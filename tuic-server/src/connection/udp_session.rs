use std::{
	io::Error as IoError,
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
	sync::Arc,
};

use bytes::Bytes;
use moka::future::Cache;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
	net::UdpSocket,
	sync::{RwLock as AsyncRwLock, oneshot},
};
use tracing::{Instrument, Span, warn};
use tuic_core::Address;

use super::Connection;
use crate::{AppContext, error::Error, utils::FutResultExt};

pub struct UdpSession {
	ctx:          Arc<AppContext>,
	assoc_id:     u16,
	udp_sessions: Cache<u16, Arc<UdpSession>>,
	socket_v4:    UdpSocket,
	socket_v6:    Option<UdpSocket>,
	close:        AsyncRwLock<Option<oneshot::Sender<()>>>,
}

impl UdpSession {
	/// Spawn a listen task for the UDP session and return an `Arc<Self>`.
	///
	/// The listen task is the session's real owner; when it ends the session
	/// is dropped. `conn` is consumed and moved into the listen task for
	/// outgoing packet relay (`relay_packet`).
	pub fn new(
		ctx: Arc<AppContext>,
		conn: Connection,
		assoc_id: u16,
		udp_sessions: Cache<u16, Arc<UdpSession>>,
	) -> Result<Arc<Self>, Error> {
		let socket_v4 = {
			let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
				.map_err(|err| Error::Socket("failed to create UDP associate IPv4 socket", err))?;

			socket
				.set_nonblocking(true)
				.map_err(|err| Error::Socket("failed setting UDP associate IPv4 socket as non-blocking", err))?;

			socket
				.bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))))
				.map_err(|err| Error::Socket("failed to bind UDP associate IPv4 socket", err))?;

			UdpSocket::from_std(StdUdpSocket::from(socket))?
		};

		let socket_v6 = if ctx.cfg.udp_relay_ipv6 {
			let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
				.map_err(|err| Error::Socket("failed to create UDP associate IPv6 socket", err))?;

			socket
				.set_nonblocking(true)
				.map_err(|err| Error::Socket("failed setting UDP associate IPv6 socket as non-blocking", err))?;

			socket
				.set_only_v6(true)
				.map_err(|err| Error::Socket("failed setting UDP associate IPv6 socket as IPv6-only", err))?;

			socket
				.bind(&SockAddr::from(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))))
				.map_err(|err| Error::Socket("failed to bind UDP associate IPv6 socket", err))?;

			Some(UdpSocket::from_std(StdUdpSocket::from(socket))?)
		} else {
			None
		};

		let (tx, rx) = oneshot::channel();

		let ctx_listening = ctx.clone();
		let session = Arc::new(Self {
			ctx,
			assoc_id,
			udp_sessions,
			socket_v4,
			socket_v6,
			close: AsyncRwLock::new(Some(tx)),
		});

		let session_listening = session.clone();
		let conn_listening = conn; // moved here, used by listen task for relay
		let listen_span = Span::current();
		let listen = async move {
			let span = Span::current();
			let mut rx = rx;
			let mut timeout = tokio::time::interval(ctx_listening.cfg.stream_timeout);
			timeout.reset();

			loop {
				let next;
				tokio::select! {
					recv = session_listening.recv() => next = recv,
					// Avoid client didn't send `UDP-DROP` properly
					_ = timeout.tick() => {
						session_listening.close().await;
						warn!("[packet] [{assoc_id:#06x}] UDP session timeout", assoc_id = session_listening.assoc_id);
						continue;
					},
					// `UDP-DROP`
					_ = &mut rx => break
				}
				timeout.reset();
				let (pkt, addr) = match next {
					Ok(v) => v,
					Err(err) => {
						warn!(
							"[packet] [{assoc_id:#06x}] outbound listening error: {err}",
							assoc_id = session_listening.assoc_id
						);
						continue;
					}
				};

				tokio::spawn(
					conn_listening
						.clone()
						.relay_packet(pkt, Address::SocketAddress(addr), session_listening.assoc_id)
						.log_err()
						.instrument(span.clone()),
				);
			}
			session_listening.udp_sessions.invalidate(&assoc_id).await;
		};

		tokio::spawn(listen.instrument(listen_span));
		Ok(session)
	}

	pub async fn send(&self, pkt: Bytes, mut addr: SocketAddr) -> Result<(), Error> {
		if let SocketAddr::V6(v6) = addr {
			if let Some(v4) = v6.ip().to_ipv4_mapped() {
				addr = SocketAddr::new(IpAddr::V4(v4), v6.port());
			}
		}

		let socket = match addr {
			SocketAddr::V4(_) => &self.socket_v4,
			SocketAddr::V6(_) => self.socket_v6.as_ref().ok_or_else(|| Error::UdpRelayIpv6Disabled(addr))?,
		};

		socket.send_to(&pkt, addr).await?;
		Ok(())
	}

	async fn recv(&self) -> Result<(Bytes, SocketAddr), IoError> {
		let recv = async |socket: &UdpSocket| -> Result<(Bytes, SocketAddr), IoError> {
			let mut buf = vec![0u8; self.ctx.cfg.max_external_packet_size];
			let (n, mut addr) = socket.recv_from(&mut buf).await?;
			if let SocketAddr::V6(v6) = addr {
				if let Some(v4) = v6.ip().to_ipv4_mapped() {
					addr = SocketAddr::new(IpAddr::V4(v4), v6.port());
				}
			}
			buf.truncate(n);
			Ok((Bytes::from(buf), addr))
		};

		if let Some(socket_v6) = &self.socket_v6 {
			tokio::select! {
				res = recv(&self.socket_v4) => res,
				res = recv(socket_v6) => res,
			}
		} else {
			recv(&self.socket_v4).await
		}
	}

	pub async fn close(&self) {
		if let Some(v) = self.close.write().await.take() {
			_ = v.send(());
		}
	}
}
