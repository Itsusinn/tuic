use std::{
	io::Error as IoError,
	net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
	sync::{Arc, Weak},
};

use bytes::Bytes;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
	net::UdpSocket,
	sync::{RwLock as AsyncRwLock, oneshot},
};
use tracing::warn;
use tuic_core::Address;

use super::Connection;
use crate::{AppContext, error::Error, utils::FutResultExt};

pub struct UdpSession {
	ctx:       Arc<AppContext>,
	assoc_id:  u16,
	conn:      Connection,
	socket_v4: UdpSocket,
	socket_v6: Option<UdpSocket>,
	close:     AsyncRwLock<Option<oneshot::Sender<()>>>,
}

impl UdpSession {
	// spawn a task which actually owns itself, then return its wake reference.
	pub fn new(ctx: Arc<AppContext>, conn: Connection, assoc_id: u16) -> Result<Weak<Self>, Error> {
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

		let session = Arc::new(Self {
			ctx: ctx.clone(),
			conn,
			assoc_id,
			socket_v4,
			socket_v6,
			close: AsyncRwLock::new(Some(tx)),
		});

		let session_listening = session.clone();
		// UdpSession's real owner.
		let listen = async move {
			let mut rx = rx;
			let mut timeout = tokio::time::interval(ctx.cfg.stream_timeout);
			timeout.reset();

			loop {
				let next;
				tokio::select! {
					recv = session_listening.recv() => next = recv,
					// Avoid client didn't send `UDP-DROP` properly
					_ = timeout.tick() => {
						session_listening.close().await;
						warn!(
							"[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] UDP session timeout",
							id = session_listening.conn.id(),
							addr = session_listening.conn.inner.remote_address(),
							user = session_listening.conn.auth,
						);
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
							"[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] outbound listening error: {err}",
							id = session_listening.conn.id(),
							addr = session_listening.conn.inner.remote_address(),
							user = session_listening.conn.auth,
						);
						continue;
					}
				};

				tokio::spawn(
					session_listening
						.conn
						.clone()
						.relay_packet(pkt, Address::SocketAddress(addr), session_listening.assoc_id)
						.log_err(),
				);
			}
			session_listening.conn.udp_sessions.write().await.remove(&assoc_id);
		};

		tokio::spawn(listen);
		Ok(Arc::downgrade(&session))
	}

	pub async fn send(&self, pkt: Bytes, addr: SocketAddr) -> Result<(), Error> {
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
			let (n, addr) = socket.recv_from(&mut buf).await?;
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
