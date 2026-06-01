use std::{
	io::Error as IoError,
	net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket},
	sync::{Arc, Mutex},
	time::Instant,
};

use bytes::Bytes;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socks5_proto::Address;
use socks5_server::AssociatedUdpSocket;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::error::Error;

#[derive(Clone)]
pub struct UdpSession {
	socket: Arc<AssociatedUdpSocket>,
	assoc_id: u16,
	ctrl_addr: SocketAddr,
	last_activity: Arc<Mutex<Instant>>,
}

impl UdpSession {
	pub fn new(
		assoc_id: u16,
		ctrl_addr: SocketAddr,
		local_ip: IpAddr,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
	) -> Result<Self, Error> {
		info!(
			"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] creating UDP session, local_ip: {local_ip}, family: {:?}",
			local_ip
		);

		let domain = match local_ip {
			IpAddr::V4(_) => {
				info!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] using IPv4 domain");
				Domain::IPV4
			}
			IpAddr::V6(_) => {
				info!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] using IPv6 domain");
				Domain::IPV6
			}
		};

		let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|err| {
			warn!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] failed to create socket: {err}");
			Error::Socket("failed to create socks5 server UDP associate socket", err)
		})?;

		debug!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] socket created successfully");

		// Only set IPV6_V6ONLY option for IPv6 sockets
		if let (Some(dual_stack), IpAddr::V6(_)) = (dual_stack, local_ip) {
			socket.set_only_v6(!dual_stack).map_err(|err| {
				warn!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] failed to set dual-stack: {err}");
				Error::Socket("socks5 server UDP associate dual-stack socket setting error", err)
			})?;
			debug!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] dual-stack set to: {dual_stack}");
		}

		socket.set_nonblocking(true).map_err(|err| {
			warn!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] failed to set non-blocking: {err}");
			Error::Socket("failed setting socks5 server UDP associate socket as non-blocking", err)
		})?;

		let bind_addr = SocketAddr::from((local_ip, 0));
		info!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] binding to {bind_addr}");

		socket.bind(&SockAddr::from(bind_addr)).map_err(|err| {
			warn!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] failed to bind to {bind_addr}: {err}");
			Error::Socket("failed to bind socks5 server UDP associate socket", err)
		})?;

		info!(
			"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] socket bound successfully to {:?}",
			bind_addr
		);

		let socket = UdpSocket::from_std(StdUdpSocket::from(socket)).map_err(|err| {
			warn!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] failed to convert to tokio UdpSocket: {err}");
			Error::Socket("failed to create socks5 server UDP associate socket", err)
		})?;

		let local_addr = socket.local_addr().unwrap();
		info!("[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] tokio socket local address is {local_addr}");

		Ok(Self {
			socket: Arc::new(AssociatedUdpSocket::from((socket, max_pkt_size))),
			assoc_id,
			ctrl_addr,
			last_activity: Arc::new(Mutex::new(Instant::now())),
		})
	}

	pub fn touch(&self) {
		if let Ok(mut last) = self.last_activity.lock() {
			*last = Instant::now();
		}
	}

	pub fn idle_for(&self) -> std::time::Duration {
		self.last_activity.lock().ok().map(|last| last.elapsed()).unwrap_or_default()
	}

	pub async fn send(&self, pkt: Bytes, mut src_addr: Address) -> Result<(), Error> {
		if let Address::SocketAddress(SocketAddr::V6(v6)) = src_addr {
			if let Some(v4) = v6.ip().to_ipv4_mapped() {
				src_addr = Address::SocketAddress(SocketAddr::new(IpAddr::V4(v4), v6.port()));
			}
		}

		let src_addr_display = src_addr.to_string();

		debug!(
			"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] send packet from {src_addr_display} to {dst_addr}",
			ctrl_addr = self.ctrl_addr,
			assoc_id = self.assoc_id,
			dst_addr = self.socket.peer_addr().unwrap(),
		);

		if let Err(err) = self.socket.send(pkt, 0, src_addr).await {
			warn!(
				"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] send packet from {src_addr_display} to {dst_addr} \
				 error: {err}",
				ctrl_addr = self.ctrl_addr,
				assoc_id = self.assoc_id,
				dst_addr = self.socket.peer_addr().unwrap(),
			);

			return Err(Error::Io(err));
		}

		self.touch();
		Ok(())
	}

	pub async fn recv(&self) -> Result<(Bytes, Address), Error> {
		let (pkt, frag, mut dst_addr, src_addr) = self.socket.recv_from().await?;

		if let Address::SocketAddress(SocketAddr::V6(v6)) = dst_addr {
			if let Some(v4) = v6.ip().to_ipv4_mapped() {
				dst_addr = Address::SocketAddress(SocketAddr::new(IpAddr::V4(v4), v6.port()));
			}
		}

		if let Ok(connected_addr) = self.socket.peer_addr() {
			let connected_addr = match connected_addr {
				SocketAddr::V4(addr) => {
					if let SocketAddr::V6(_) = src_addr {
						SocketAddr::new(addr.ip().to_ipv6_mapped().into(), addr.port())
					} else {
						connected_addr
					}
				}
				SocketAddr::V6(addr) => {
					if let SocketAddr::V4(_) = src_addr {
						if let Some(ip) = addr.ip().to_ipv4_mapped() {
							SocketAddr::new(IpAddr::V4(ip), addr.port())
						} else {
							connected_addr
						}
					} else {
						connected_addr
					}
				}
			};
			if src_addr != connected_addr {
				Err(IoError::other(format!("invalid source address: {src_addr}")))?;
			}
		} else {
			self.socket.connect(src_addr).await?;
		}

		if frag != 0 {
			Err(IoError::other("fragmented packet is not supported"))?;
		}

		debug!(
			"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] receive packet from {src_addr} to {dst_addr}",
			ctrl_addr = self.ctrl_addr,
			assoc_id = self.assoc_id
		);

		self.touch();
		Ok((pkt, dst_addr))
	}

	pub fn local_addr(&self) -> Result<SocketAddr, IoError> {
		self.socket.local_addr()
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::*;

	fn make_session() -> UdpSession {
		UdpSession::new(
			0x1234,
			"127.0.0.1:9999".parse().unwrap(),
			"127.0.0.1".parse().unwrap(),
			None,
			1500,
		)
		.expect("binding 127.0.0.1:0 must succeed in tests")
	}

	#[tokio::test]
	async fn idle_grows_over_time() {
		let session = make_session();
		// A fresh session should be roughly zero-idle.
		assert!(session.idle_for() < Duration::from_millis(50));

		tokio::time::sleep(Duration::from_millis(80)).await;
		let idle = session.idle_for();
		assert!(idle >= Duration::from_millis(60), "idle should grow to ~80ms, got {idle:?}");
	}

	#[tokio::test]
	async fn touch_resets_idle() {
		let session = make_session();
		tokio::time::sleep(Duration::from_millis(80)).await;
		assert!(session.idle_for() >= Duration::from_millis(60));

		session.touch();
		let after_touch = session.idle_for();
		assert!(
			after_touch < Duration::from_millis(30),
			"touch should reset idle to near-zero, got {after_touch:?}"
		);
	}

	#[tokio::test]
	async fn touch_is_shared_across_clones() {
		// Sessions are cloned into recv loop, idle watcher, and the inbound packet
		// handler — touches from one clone must be visible to all readers.
		let a = make_session();
		let b = a.clone();

		tokio::time::sleep(Duration::from_millis(80)).await;
		assert!(b.idle_for() >= Duration::from_millis(60));

		a.touch();
		assert!(
			b.idle_for() < Duration::from_millis(30),
			"touch on one clone must propagate to the other"
		);
	}
}
