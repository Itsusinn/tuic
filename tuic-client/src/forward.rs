use std::{
	collections::HashMap,
	net::{SocketAddr, TcpListener as StdTcpListener},
	sync::{Arc, atomic::Ordering},
	time::Duration,
};

use bytes::Bytes;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
	io,
	io::AsyncWriteExt,
	net::{TcpListener, UdpSocket},
};
use tracing::{debug, info, warn};
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
	socket:   Arc<UdpSocket>,
	src_addr: SocketAddr,
	assoc_id: u16,
}

impl ForwardUdpSession {
	pub fn new(socket: Arc<UdpSocket>, src_addr: SocketAddr, assoc_id: u16) -> Self {
		Self {
			socket,
			src_addr,
			assoc_id,
		}
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
			warn!("[forward-udp] failed to bind {addr}: {err}", addr = entry.listen);
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
	// Map from client src addr to assoc_id for this forwarder instance
	let mut src_map: HashMap<SocketAddr, u16> = HashMap::new();

	loop {
		match socket.recv_from(&mut buf).await {
			Ok((n, src_addr)) => {
				let pkt = Bytes::copy_from_slice(&buf[..n]);
				let assoc_id = match src_map.get(&src_addr).cloned() {
					Some(id) => id,
					None => {
						let id = 0x8000 | (ctx.next_fwd_assoc_id.fetch_add(1, Ordering::Relaxed) & 0x7fff);
						// register session
						let session = ForwardUdpSession::new(socket.clone(), src_addr, id);
						ctx.fwd_udp_sessions.insert(id, session).await;
						src_map.insert(src_addr, id);
						// Spawn timeout watcher
						tokio::spawn(expire_after(id, entry.timeout, ctx.clone()));
						id
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
			Err(err) => warn!("[forward-udp] recv_from error: {err}"),
		}
	}
}

async fn expire_after(assoc_id: u16, timeout: Duration, ctx: Arc<crate::AppContext>) {
	tokio::time::sleep(timeout).await;
	if ctx.fwd_udp_sessions.remove(&assoc_id).await.is_some() {
		debug!("[forward-udp] [{assoc:#06x}] timeout; dissociate", assoc = assoc_id);
		if let Ok(conn) = ctx.get_conn().await {
			if let Err(err) = conn.dissociate(assoc_id).await {
				warn!("[forward-udp] [{assoc:#06x}] dissociate error: {err}", assoc = assoc_id);
			}
		}
	}
}
