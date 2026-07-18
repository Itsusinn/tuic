use std::{
	collections::HashMap,
	net::{SocketAddr, TcpListener as StdTcpListener},
	sync::{
		Arc,
		atomic::{AtomicU16, Ordering},
	},
};

use bytes::Bytes;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};
use wind_core::{
	AbstractOutbound,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
};

use crate::{
	config::{TcpForward, UdpForward},
	error::Error,
	shared::SharedOutbound,
};

static NEXT_ASSOC_ID: AtomicU16 = AtomicU16::new(0);

fn next_assoc_id() -> u16 {
	0x8000 | (NEXT_ASSOC_ID.fetch_add(1, Ordering::Relaxed) & 0x7fff)
}

/// Spawn the configured TCP/UDP forwarders with a shared outbound handle.
///
/// Each forwarder listens until `cancel` is fired; the shared outbound is
/// used for relaying traffic through the TUIC tunnel.
pub async fn start_shared(
	tcp: Vec<TcpForward>,
	udp: Vec<UdpForward>,
	outbound: Arc<SharedOutbound>,
	cancel: CancellationToken,
) {
	for entry in tcp {
		tokio::spawn(run_tcp_forwarder(entry, cancel.child_token(), outbound.clone()));
	}
	for entry in udp {
		tokio::spawn(run_udp_forwarder(entry, cancel.child_token(), outbound.clone()));
	}
}

async fn run_tcp_forwarder(entry: TcpForward, cancel: CancellationToken, outbound: Arc<SharedOutbound>) {
	let listener = match create_tcp_listener(entry.listen) {
		Ok(l) => l,
		Err(err) => {
			warn!("[forward-tcp] failed to bind listener: {err}");
			return;
		}
	};
	info!(
		"[forward-tcp] listening on {listen} -> {remote:?}",
		listen = listener.local_addr().unwrap(),
		remote = entry.remote
	);
	loop {
		tokio::select! {
			_ = cancel.cancelled() => {
				info!("[forward-tcp] cancellation received, shutting down");
				break;
			}
			res = listener.accept() => match res {
				Ok((inbound, peer)) => {
					let remote = entry.remote.clone();
					let span = tracing::info_span!("forward_tcp", peer = %peer);
					let conn_cancel = cancel.child_token();
					let ob = outbound.clone();
					tokio::spawn(
						async move {
							tokio::select! {
								_ = conn_cancel.cancelled() => {}
								_ = handle_tcp_conn(inbound, remote, ob) => {}
							}
						}
						.instrument(span),
					);
				}
				Err(err) => warn!("[forward-tcp] accept error: {err}"),
			}
		}
	}
}

async fn handle_tcp_conn(inbound: tokio::net::TcpStream, remote: (String, u16), outbound: Arc<SharedOutbound>) {
	info!("connected");
	let result: Result<(), Error> = async {
		let adapter = outbound.get().await.map_err(|e| Error::Other(anyhow::anyhow!("{e}")))?;
		let target = TargetAddr::Domain(remote.0, remote.1);
		adapter
			.handle_tcp(target, inbound, Option::<crate::wind_adapter::TuicOutboundAdapter>::None)
			.await
			.map_err(|e| Error::Other(anyhow::anyhow!("{e}")))?;
		Ok(())
	}
	.await;
	if let Err(err) = result {
		warn!(error = %err, "error");
	}
	debug!("closed");
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

/// Per-`src_addr` UDP forwarder session.
struct UdpForwardSession {
	assoc_id: u16,
	tx_to_out: tokio::sync::mpsc::Sender<UdpPacket>,
	last_seen: std::time::Instant,
}

async fn run_udp_forwarder(entry: UdpForward, cancel: CancellationToken, outbound: Arc<SharedOutbound>) {
	let socket = match UdpSocket::bind(entry.listen).await {
		Ok(s) => s,
		Err(err) => {
			warn!("[forward-udp] failed to bind {addr}: {err}", addr = entry.listen);
			return;
		}
	};
	let socket = Arc::new(socket);
	info!(
		"[forward-udp] listening on {listen} -> {remote:?} timeout={timeout:?}",
		listen = entry.listen,
		remote = entry.remote,
		timeout = entry.timeout
	);

	let mut buf = vec![0u8; 65535];
	let mut sessions: HashMap<SocketAddr, UdpForwardSession> = HashMap::new();
	let mut gc_interval = tokio::time::interval(entry.timeout / 4);
	gc_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

	loop {
		tokio::select! {
			_ = cancel.cancelled() => {
				info!("[forward-udp] cancellation received, shutting down");
				break;
			}
			recv = socket.recv_from(&mut buf) => match recv {
				Ok((n, src_addr)) => {
					let pkt = Bytes::copy_from_slice(&buf[..n]);
					let target = TargetAddr::Domain(entry.remote.0.clone(), entry.remote.1);

					let session = sessions.entry(src_addr).or_insert_with(|| {
						let assoc_id = next_assoc_id();
						let socket_for_reply = socket.clone();
						let (tx_to_out, rx_from_local) = tokio::sync::mpsc::channel::<UdpPacket>(64);
						let (tx_to_local, mut rx_from_out) = tokio::sync::mpsc::channel::<UdpPacket>(64);
						let udp_stream = UdpStream { tx: tx_to_local, rx: rx_from_local };

						// Reply bridge
						tokio::spawn(async move {
							while let Some(reply_pkt) = rx_from_out.recv().await {
								if let Err(err) = socket_for_reply.send_to(&reply_pkt.payload, src_addr).await {
									warn!("[forward-udp] [{assoc_id:#06x}] reply send error: {err}");
								}
							}
						}.instrument(tracing::info_span!("forward_udp_reply", peer = %src_addr, assoc_id)));

						let ob = outbound.clone();
						tokio::spawn(async move {
							let adapter = match ob.get().await {
								Ok(a) => a,
								Err(e) => {
									warn!("[forward-udp] [{assoc_id:#06x}] outbound error: {e}");
									return;
								}
							};
							if let Err(err) = adapter
								.handle_udp(udp_stream, Option::<crate::wind_adapter::TuicOutboundAdapter>::None)
								.await
							{
								warn!("[forward-udp] [{assoc_id:#06x}] relay error: {err}");
							}
						}.instrument(tracing::info_span!("forward_udp_relay", peer = %src_addr, assoc_id)));

						UdpForwardSession {
							assoc_id,
							tx_to_out,
							last_seen: std::time::Instant::now(),
						}
					});

					session.last_seen = std::time::Instant::now();
					let assoc_id = session.assoc_id;

					match session.tx_to_out.try_send(UdpPacket {
						source: None,
						target,
						payload: pkt,
					}) {
						Ok(()) => {}
						Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
							debug!("[forward-udp] [{assoc_id:#06x}] outbound queue full; dropping packet from {src_addr}");
						}
						Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
							debug!("[forward-udp] [{assoc_id:#06x}] outbound closed; removing session for {src_addr}");
							sessions.remove(&src_addr);
						}
					}
				}
				Err(err) => warn!("[forward-udp] recv_from error: {err}"),
			},
			_ = gc_interval.tick() => {
				let now = std::time::Instant::now();
				sessions.retain(|src_addr, s| {
					if now.duration_since(s.last_seen) >= entry.timeout {
						debug!(
							"[forward-udp] [{assoc:#06x}] idle timeout; dropping session for {src_addr}",
							assoc = s.assoc_id
						);
						false
					} else {
						true
					}
				});
			}
		}
	}
}
