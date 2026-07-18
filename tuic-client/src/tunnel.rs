//! Tunnel inbounds: TCP/UDP port forwarders as wind-core inbounds.
//!
//! Each tunnel listens on a local address and relays all traffic to a fixed
//! remote target through the dispatcher — same path as the SOCKS5 inbound.
//!
//! Reference: mihomo tunnel-type inbound pattern.

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
	AbstractInbound, InboundCallback,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
};



static NEXT_ASSOC_ID: AtomicU16 = AtomicU16::new(0);

fn next_assoc_id() -> u16 {
	0x8000 | (NEXT_ASSOC_ID.fetch_add(1, Ordering::Relaxed) & 0x7fff)
}

// ── TCP tunnel ─────────────────────────────────────────────────────────────

/// TCP port forwarder as a wind-core inbound.
///
/// Each accepted connection is handed to the dispatcher via
/// [`InboundCallback::handle_tcpstream`] with the configured remote target.
pub struct TunnelTcpInbound {
	listen: SocketAddr,
	remote: (String, u16),
	cancel: CancellationToken,
}

impl TunnelTcpInbound {
	pub fn new(listen: SocketAddr, remote: (String, u16), cancel: CancellationToken) -> Self {
		Self { listen, remote, cancel }
	}
}

impl AbstractInbound for TunnelTcpInbound {
	async fn listen(&self, cb: &impl InboundCallback) -> eyre::Result<()> {
		let listener = create_tcp_listener(self.listen)?;
		info!(
			"[tunnel-tcp] listening on {listen} -> {remote:?}",
			listen = self.listen,
			remote = self.remote
		);

		let conn_tasks = tokio_util::task::TaskTracker::new();
		loop {
			tokio::select! {
				_ = self.cancel.cancelled() => {
					info!("[tunnel-tcp] cancellation received, shutting down");
					break;
				}
				res = listener.accept() => match res {
					Ok((stream, peer)) => {
						let cb = cb.clone();
						let target = TargetAddr::Domain(self.remote.0.clone(), self.remote.1);
						let conn_cancel = self.cancel.child_token();
						conn_tasks.spawn(
							async move {
								tokio::select! {
									_ = conn_cancel.cancelled() => {}
									res = cb.handle_tcpstream(target, stream) => {
										if let Err(e) = res {
											warn!("[tunnel-tcp] [{peer}] error: {e}");
										}
									}
								}
							}
							.in_current_span(),
						);
					}
					Err(err) => warn!("[tunnel-tcp] accept error: {err}"),
				}
			}
		}
		conn_tasks.close();
		conn_tasks.wait().await;
		Ok(())
	}
}

// ── UDP tunnel ─────────────────────────────────────────────────────────────

/// Per-source-address UDP tunnel session.
struct UdpTunnelSession {
	assoc_id: u16,
	tx_to_out: tokio::sync::mpsc::Sender<UdpPacket>,
	last_seen: std::time::Instant,
}

/// UDP port forwarder as a wind-core inbound.
///
/// Packets from different source addresses get separate UDP relay sessions.
/// Each session is routed through the dispatcher via
/// [`InboundCallback::handle_udpstream`].
pub struct TunnelUdpInbound {
	socket: Arc<UdpSocket>,
	remote: (String, u16),
	timeout: std::time::Duration,
	cancel: CancellationToken,
}

impl TunnelUdpInbound {
	pub fn new(
		listen: SocketAddr,
		remote: (String, u16),
		timeout: std::time::Duration,
		cancel: CancellationToken,
	) -> std::io::Result<Self> {
		let socket = std::net::UdpSocket::bind(listen)?;
		socket.set_nonblocking(true)?;
		let socket = UdpSocket::from_std(socket)?;
		Ok(Self {
			socket: Arc::new(socket),
			remote,
			timeout,
			cancel,
		})
	}
}

impl AbstractInbound for TunnelUdpInbound {
	async fn listen(&self, cb: &impl InboundCallback) -> eyre::Result<()> {
		info!(
			"[tunnel-udp] listening on {listen} -> {remote:?} timeout={timeout:?}",
			listen = self.socket.local_addr()?,
			remote = self.remote,
			timeout = self.timeout
		);

		let mut buf = vec![0u8; 65535];
		let mut sessions: HashMap<SocketAddr, UdpTunnelSession> = HashMap::new();
		let mut gc_interval = tokio::time::interval(self.timeout / 4);
		gc_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		loop {
			tokio::select! {
				_ = self.cancel.cancelled() => {
					info!("[tunnel-udp] cancellation received, shutting down");
					break;
				}
				recv = self.socket.recv_from(&mut buf) => match recv {
					Ok((n, src_addr)) => {
						let pkt = Bytes::copy_from_slice(&buf[..n]);
						let target = TargetAddr::Domain(self.remote.0.clone(), self.remote.1);

						let session = sessions.entry(src_addr).or_insert_with(|| {
							let assoc_id = next_assoc_id();
							let socket_for_reply = self.socket.clone();
							let (tx_to_out, rx_from_local) = tokio::sync::mpsc::channel::<UdpPacket>(64);
							let (tx_to_local, mut rx_from_out) = tokio::sync::mpsc::channel::<UdpPacket>(64);
							let udp_stream = UdpStream { tx: tx_to_local, rx: rx_from_local };

							// Reply bridge: packets from remote → local socket.
							tokio::spawn(async move {
								while let Some(reply_pkt) = rx_from_out.recv().await {
									if let Err(err) = socket_for_reply.send_to(&reply_pkt.payload, src_addr).await {
										warn!("[tunnel-udp] [{assoc_id:#06x}] reply send error: {err}");
									}
								}
							}.in_current_span());

							// Relay through dispatcher
							let cb = cb.clone();
							tokio::spawn(async move {
								if let Err(e) = cb.handle_udpstream(udp_stream).await {
									warn!("[tunnel-udp] [{assoc_id:#06x}] relay error: {e}");
								}
							}.in_current_span());

							UdpTunnelSession {
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
								debug!("[tunnel-udp] [{assoc_id:#06x}] outbound queue full; dropping packet from {src_addr}");
							}
							Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
								debug!("[tunnel-udp] [{assoc_id:#06x}] outbound closed; removing session for {src_addr}");
								sessions.remove(&src_addr);
							}
						}
					}
					Err(err) => warn!("[tunnel-udp] recv_from error: {err}"),
				},
				_ = gc_interval.tick() => {
					let now = std::time::Instant::now();
					sessions.retain(|src_addr, s| {
						if now.duration_since(s.last_seen) >= self.timeout {
							debug!(
								"[tunnel-udp] [{assoc:#06x}] idle timeout; dropping session for {src_addr}",
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
		Ok(())
	}
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn create_tcp_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
	let domain = match addr {
		SocketAddr::V4(_) => Domain::IPV4,
		SocketAddr::V6(_) => Domain::IPV6,
	};
	let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
	socket.set_reuse_address(true)?;
	socket.set_nonblocking(true)?;
	socket.bind(&SockAddr::from(addr))?;
	socket.listen(i32::MAX)?;
	TcpListener::from_std(StdTcpListener::from(socket))
}
