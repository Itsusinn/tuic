use std::{
	collections::HashMap,
	net::{SocketAddr, TcpListener as StdTcpListener},
	sync::{Arc, Mutex, atomic::Ordering},
	time::{Duration, Instant},
};

use bytes::Bytes;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
	io,
	io::AsyncWriteExt,
	net::{TcpListener, UdpSocket},
};
use tracing::{debug, error, info, warn};
use tuic_core::Address as TuicAddress;

use crate::{
	config::{TcpForward, UdpForward},
	error::Error,
};

// Global UDP forward session registry
pub async fn start(ctx: Arc<crate::AppContext>, tcp: Vec<TcpForward>, udp: Vec<UdpForward>) {
	for entry in tcp {
		tokio::spawn(run_tcp_forwarder(entry, ctx.clone()));
	}
	for entry in udp {
		tokio::spawn(run_udp_forwarder(entry, ctx.clone()));
	}
}

#[derive(Clone)]
pub struct ForwardUdpSession {
	socket: Arc<UdpSocket>,
	src_addr: SocketAddr,
	assoc_id: u16,
	last_activity: Arc<Mutex<Instant>>,
}

impl ForwardUdpSession {
	pub fn new(socket: Arc<UdpSocket>, src_addr: SocketAddr, assoc_id: u16) -> Self {
		Self {
			socket,
			src_addr,
			assoc_id,
			last_activity: Arc::new(Mutex::new(Instant::now())),
		}
	}

	pub fn touch(&self) {
		if let Ok(mut last) = self.last_activity.lock() {
			*last = Instant::now();
		}
	}

	pub fn idle_for(&self) -> Duration {
		self.last_activity.lock().ok().map(|last| last.elapsed()).unwrap_or_default()
	}

	pub async fn send(&self, pkt: Bytes) -> Result<(), Error> {
		if let Err(err) = self.socket.send_to(&pkt, self.src_addr).await {
			warn!(
				"[forward-udp] [{assoc:#06x}] failed sending packet to {dst}: {err}",
				assoc = self.assoc_id,
				dst = self.src_addr,
			);
			return Err(Error::Io(err));
		}
		self.touch();
		Ok(())
	}
}

async fn run_tcp_forwarder(entry: TcpForward, ctx: Arc<crate::AppContext>) {
	match create_tcp_listener(entry.listen) {
		Ok(listener) => {
			warn!(
				"[forward-tcp] listening on {listen} -> {remote:?}",
				listen = listener.local_addr().unwrap(),
				remote = entry.remote
			);
			loop {
				match listener.accept().await {
					Ok((mut inbound, peer)) => {
						let remote = entry.remote.clone();
						let ctx = ctx.clone();
						tokio::spawn(async move {
							info!("[forward-tcp] [{peer}] connected", peer = peer);
							let fut = async {
								let conn = ctx.get_conn().await?;
								let remote_addr = TuicAddress::DomainAddress(remote.0, remote.1);
								let mut relay = conn.connect(remote_addr).await?;
								match io::copy_bidirectional(&mut inbound, &mut relay).await {
									Ok((_lr, _rl)) => {
										let _ = relay.shutdown().await;
									}
									Err(err) => {
										warn!("[forward-tcp] [{peer}] relay error: {err}");
									}
								}
								Ok::<(), Error>(())
							};
							if let Err(err) = fut.await {
								warn!("[forward-tcp] [{peer}] error: {err}");
							}
							debug!("[forward-tcp] [{peer}] closed");
						});
					}
					Err(err) => warn!("[forward-tcp] accept error: {err}"),
				}
			}
		}
		Err(err) => warn!("[forward-tcp] failed to bind listener: {err}"),
	}
}

fn create_tcp_listener(addr: SocketAddr) -> Result<TcpListener, Error> {
	let domain = match addr {
		SocketAddr::V4(_) => Domain::IPV4,
		SocketAddr::V6(_) => Domain::IPV6,
	};
	let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
		.map_err(|err| Error::Socket("failed to create tcp forward socket", err))?;
	socket
		.set_reuse_address(true)
		.map_err(|err| Error::Socket("failed to set tcp forward socket reuse_address", err))?;
	socket
		.set_nonblocking(true)
		.map_err(|err| Error::Socket("failed setting tcp forward socket as non-blocking", err))?;
	socket
		.bind(&SockAddr::from(addr))
		.map_err(|err| Error::Socket("failed to bind tcp forward socket", err))?;
	socket
		.listen(i32::MAX)
		.map_err(|err| Error::Socket("failed to listen on tcp forward socket", err))?;
	TcpListener::from_std(StdTcpListener::from(socket)).map_err(|err| Error::Socket("failed to create tcp forward socket", err))
}

async fn run_udp_forwarder(entry: UdpForward, ctx: Arc<crate::AppContext>) {
	let socket = match UdpSocket::bind(entry.listen).await {
		Ok(s) => s,
		Err(err) => {
			error!(
				"[forward-udp] failed to bind {addr}: {err}; forwarder will not start",
				addr = entry.listen
			);
			return;
		}
	};
	let socket = Arc::new(socket);
	warn!(
		"[forward-udp] listening on {listen} -> {remote:?} timeout={timeout:?}",
		listen = entry.listen,
		remote = entry.remote,
		timeout = entry.timeout
	);

	let mut buf = vec![0u8; 65535];
	// Per-forwarder reverse map from client src addr to assoc_id.
	// Shared with idle_watcher tasks so expiry can clean both sides atomically
	// (cache slot + reverse map entry), preventing stale entries from routing
	// future packets onto a dissociated relay session.
	let src_map: Arc<Mutex<HashMap<SocketAddr, u16>>> = Arc::new(Mutex::new(HashMap::new()));

	let mut consecutive_recv_errors: u32 = 0;
	const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 64;

	loop {
		match socket.recv_from(&mut buf).await {
			Ok((n, src_addr)) => {
				consecutive_recv_errors = 0;
				let pkt = Bytes::copy_from_slice(&buf[..n]);

				let assoc_id = {
					let existing = src_map.lock().unwrap().get(&src_addr).copied();
					match existing {
						// Reuse path: refresh activity if the session is still live; if it was
						// already evicted, drop the stale reverse-map entry and fall through to
						// allocating a fresh assoc_id.
						Some(id) => match ctx.fwd_udp_sessions.get(&id).await {
							Some(session) => {
								session.touch();
								id
							}
							None => {
								src_map.lock().unwrap().remove(&src_addr);
								allocate_fwd_session(&ctx, &socket, &src_map, src_addr, entry.timeout).await
							}
						},
						None => allocate_fwd_session(&ctx, &socket, &src_map, src_addr, entry.timeout).await,
					}
				};

				let remote = entry.remote.clone();
				let ctx = ctx.clone();
				tokio::spawn(async move {
					match ctx.get_conn().await {
						Ok(conn) => {
							let remote_addr = TuicAddress::DomainAddress(remote.0, remote.1);
							if let Err(err) = conn.packet(pkt, remote_addr, assoc_id).await {
								warn!("[forward-udp] [{assoc:#06x}] send packet error: {err}", assoc = assoc_id);
							}
						}
						Err(err) => warn!("[forward-udp] failed to get relay connection: {err}"),
					}
				});
			}
			Err(err) => {
				// recv_from on a bound UDP socket should normally not error per-packet;
				// when it does (resource exhaustion, ICMP unreachable on Windows, etc.)
				// log it, but also count to avoid a hot-spinning loop on a permanently
				// broken socket (e.g. EBADF after the socket is somehow closed).
				consecutive_recv_errors += 1;
				warn!(
					"[forward-udp] recv_from error ({consecutive_recv_errors}/{MAX_CONSECUTIVE_RECV_ERRORS}) on {listen}: \
					 {err}",
					listen = entry.listen
				);
				if consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
					error!(
						"[forward-udp] socket on {listen} appears unrecoverable after {consecutive_recv_errors} consecutive \
						 errors; shutting down this forwarder",
						listen = entry.listen
					);
					return;
				}
				// Brief backoff so a transient error storm doesn't pin a CPU core.
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}
	}
}

/// Allocate a fresh assoc_id in the forwarder half of the 16-bit space
/// (`0x8000..=0xFFFF`), register the session, and arm an idle watcher.
async fn allocate_fwd_session(
	ctx: &Arc<crate::AppContext>,
	socket: &Arc<UdpSocket>,
	src_map: &Arc<Mutex<HashMap<SocketAddr, u16>>>,
	src_addr: SocketAddr,
	timeout: Duration,
) -> u16 {
	let id = 0x8000 | (ctx.next_fwd_assoc_id.fetch_add(1, Ordering::Relaxed) & 0x7fff);
	let session = ForwardUdpSession::new(socket.clone(), src_addr, id);
	ctx.fwd_udp_sessions.insert(id, session).await;
	src_map.lock().unwrap().insert(src_addr, id);
	tokio::spawn(idle_watcher(id, src_addr, timeout, ctx.clone(), src_map.clone()));
	id
}

/// Remove `src_addr` from `src_map` **only** if it still points at `assoc_id`.
///
/// This is the successor-safety guard the idle watcher needs: between the
/// watcher waking up and acquiring the lock, the same `src_addr` may have been
/// reassigned to a brand-new session (typical when the client falls silent,
/// the watcher expires it, and the next packet arrives before the watcher
/// returns). We must not clobber that successor's entry. Returns true if the
/// entry was removed.
fn drop_src_map_if_matches(src_map: &Mutex<HashMap<SocketAddr, u16>>, src_addr: SocketAddr, assoc_id: u16) -> bool {
	let mut map = src_map.lock().unwrap();
	match map.get(&src_addr).copied() {
		Some(existing) if existing == assoc_id => {
			map.remove(&src_addr);
			true
		}
		_ => false,
	}
}

/// Idle-based session reaper. Sleeps until the session's `last_activity`
/// indicates it has been quiet for `timeout`, then removes the session from
/// both the cache and the per-forwarder reverse map and dissociates from the
/// relay. Either map being mutated under us is fine — we re-check on each
/// wake-up rather than assuming the deadline is fixed at spawn time.
async fn idle_watcher(
	assoc_id: u16,
	src_addr: SocketAddr,
	timeout: Duration,
	ctx: Arc<crate::AppContext>,
	src_map: Arc<Mutex<HashMap<SocketAddr, u16>>>,
) {
	if timeout.is_zero() {
		return;
	}
	loop {
		let session = match ctx.fwd_udp_sessions.get(&assoc_id).await {
			Some(s) => s,
			None => {
				// Already evicted (cache TTI or other path); also drop reverse-map entry
				// only if it still points at *this* id to avoid clobbering a successor.
				drop_src_map_if_matches(&src_map, src_addr, assoc_id);
				return;
			}
		};
		let idle = session.idle_for();
		drop(session);

		if idle >= timeout {
			if ctx.fwd_udp_sessions.remove(&assoc_id).await.is_some() {
				debug!(
					"[forward-udp] [{assoc:#06x}] idle for {idle:?} (>= {timeout:?}); dissociate",
					assoc = assoc_id
				);
				if let Ok(conn) = ctx.get_conn().await
					&& let Err(err) = conn.dissociate(assoc_id).await
				{
					warn!("[forward-udp] [{assoc:#06x}] dissociate error: {err}", assoc = assoc_id);
				}
			}
			drop_src_map_if_matches(&src_map, src_addr, assoc_id);
			return;
		}

		let remaining = timeout - idle;
		tokio::time::sleep(remaining.max(Duration::from_millis(100))).await;
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::*;

	async fn bound_socket() -> Arc<UdpSocket> {
		Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind 127.0.0.1:0"))
	}

	#[tokio::test]
	async fn forward_session_idle_grows_and_touch_resets() {
		let socket = bound_socket().await;
		let session = ForwardUdpSession::new(socket, "127.0.0.1:1".parse().unwrap(), 0x8000);

		assert!(session.idle_for() < Duration::from_millis(50));
		tokio::time::sleep(Duration::from_millis(80)).await;
		assert!(session.idle_for() >= Duration::from_millis(60));

		session.touch();
		assert!(session.idle_for() < Duration::from_millis(30));
	}

	#[tokio::test]
	async fn forward_session_send_delivers_and_touches() {
		// Send-side socket bound to ephemeral; the session's "src_addr" is the
		// receive-side socket where the packet will land. We then read it back to
		// confirm delivery, and verify last_activity was bumped by the send.
		let send_socket = bound_socket().await;
		let recv_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let recv_addr = recv_socket.local_addr().unwrap();

		let session = ForwardUdpSession::new(send_socket, recv_addr, 0x8001);
		tokio::time::sleep(Duration::from_millis(80)).await;
		assert!(session.idle_for() >= Duration::from_millis(60));

		session
			.send(Bytes::from_static(b"hello"))
			.await
			.expect("send should succeed on localhost");

		let mut buf = [0u8; 16];
		let (n, _) = tokio::time::timeout(Duration::from_secs(1), recv_socket.recv_from(&mut buf))
			.await
			.expect("packet should arrive within 1s")
			.expect("recv ok");
		assert_eq!(&buf[..n], b"hello");

		// send() must have touched last_activity.
		assert!(
			session.idle_for() < Duration::from_millis(30),
			"send must reset idle, got {:?}",
			session.idle_for()
		);
	}

	#[test]
	fn src_map_cleanup_removes_only_matching_id() {
		let map: Mutex<HashMap<SocketAddr, u16>> = Mutex::new(HashMap::new());
		let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

		map.lock().unwrap().insert(addr, 0x8001);

		// Stale watcher (id 0x8000) attempts cleanup — must NOT touch the entry
		// belonging to the live successor (id 0x8001).
		assert!(!drop_src_map_if_matches(&map, addr, 0x8000));
		assert_eq!(map.lock().unwrap().get(&addr).copied(), Some(0x8001));

		// Live watcher (id 0x8001) cleans up its own entry.
		assert!(drop_src_map_if_matches(&map, addr, 0x8001));
		assert!(map.lock().unwrap().get(&addr).is_none());

		// Cleanup against an empty slot is a no-op.
		assert!(!drop_src_map_if_matches(&map, addr, 0x8001));
	}
}
