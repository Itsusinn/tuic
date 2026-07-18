use std::{
	io::Error as IoError,
	net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket},
};

use bytes::Bytes;
use fast_socks5::{new_udp_header, parse_udp_request, util::target_addr::TargetAddr as SocksTargetAddr};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use tracing::{debug, warn};
use wind_core::{types::TargetAddr, udp::UdpPacket};

use crate::error::Error;

/// A SOCKS5 UDP-associate relay socket.
///
/// The socket is `connect()`-latched to the first client that sends a datagram
/// whose source IP matches the controlling TCP connection's peer (RFC 1928 §6),
/// after which the kernel drops datagrams from any other source. SOCKS5 UDP
/// framing (RFC 1928 §7) is handled with `fast_socks5`'s `parse_udp_request` /
/// `new_udp_header` helpers.
pub struct UdpSession {
	socket: UdpSocket,
	assoc_id: u16,
	ctrl_addr: SocketAddr,
	max_pkt_size: usize,
}

impl UdpSession {
	pub fn new(
		assoc_id: u16,
		ctrl_addr: SocketAddr,
		local_ip: IpAddr,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
	) -> Result<Self, Error> {
		let domain = match local_ip {
			IpAddr::V4(_) => Domain::IPV4,
			IpAddr::V6(_) => Domain::IPV6,
		};

		let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
			.map_err(|err| Error::Socket("failed to create socks5 server UDP associate socket", err))?;

		// `IPV6_V6ONLY` only exists on IPv6 sockets. Setting it on an IPv4 socket
		// fails with ENOPROTOOPT ("Protocol not available"), which broke every
		// UDP ASSOCIATE on an IPv4 SOCKS5 listener. Mirror `Server::new`: only
		// apply the dual-stack option when this socket is actually IPv6.
		if local_ip.is_ipv6()
			&& let Some(dual_stack) = dual_stack
		{
			socket
				.set_only_v6(!dual_stack)
				.map_err(|err| Error::Socket("socks5 server UDP associate dual-stack socket setting error", err))?;
		}

		socket
			.set_nonblocking(true)
			.map_err(|err| Error::Socket("failed setting socks5 server UDP associate socket as non-blocking", err))?;

		socket
			.bind(&SockAddr::from(SocketAddr::from((local_ip, 0))))
			.map_err(|err| Error::Socket("failed to bind socks5 server UDP associate socket", err))?;

		let socket = UdpSocket::from_std(StdUdpSocket::from(socket))
			.map_err(|err| Error::Socket("failed to create socks5 server UDP associate socket", err))?;

		Ok(Self {
			socket,
			assoc_id,
			ctrl_addr,
			max_pkt_size,
		})
	}

	/// Receive one SOCKS5 UDP datagram and return its payload and target.
	///
	/// On the first packet the source IP is checked against the control
	/// connection's peer IP; a mismatch yields [`Error::WrongPacketSource`] and
	/// the socket is left unlatched so a legitimate client can still connect.
	pub async fn recv(&self) -> Result<(Bytes, SocksTargetAddr), Error> {
		let mut buf = vec![0u8; self.max_pkt_size];
		let (len, src_addr) = self.socket.recv_from(&mut buf).await?;

		// First-packet race hardening: before latching the association onto a
		// peer, require its source IP to match the TCP control connection's peer
		// IP. Without this an off-path attacker racing the legitimate client
		// could permanently own the association.
		if self.socket.peer_addr().is_err() {
			if unmap_v4_mapped(src_addr.ip()) != unmap_v4_mapped(self.ctrl_addr.ip()) {
				warn!(
					"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] dropping initial UDP packet from unexpected source \
					 {src_addr} (expected client IP {ctrl_ip})",
					ctrl_addr = self.ctrl_addr,
					assoc_id = self.assoc_id,
					ctrl_ip = self.ctrl_addr.ip(),
				);
				return Err(Error::WrongPacketSource);
			}
			self.socket.connect(src_addr).await?;
		}

		let (frag, target_addr, payload) = parse_udp_request(&buf[..len])
			.await
			.map_err(|err| Error::Socks5(err.to_string()))?;

		if frag != 0 {
			return Err(Error::Socks5("fragmented packet is not supported".to_string()));
		}

		debug!(
			"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] receive packet from {src_addr} to {target_addr}",
			ctrl_addr = self.ctrl_addr,
			assoc_id = self.assoc_id
		);

		Ok((Bytes::copy_from_slice(payload), target_addr))
	}

	/// Send a payload back to the latched client, prefixed with a SOCKS5 UDP
	/// header whose address identifies the remote origin. No-op until a client
	/// has latched in (nothing to reply to yet).
	pub async fn send(&self, payload: &[u8], src_addr: SocketAddr) -> Result<(), Error> {
		if self.socket.peer_addr().is_err() {
			debug!(
				"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] dropping reply, no client latched yet",
				ctrl_addr = self.ctrl_addr,
				assoc_id = self.assoc_id,
			);
			return Ok(());
		}

		let mut packet = new_udp_header(src_addr).map_err(|err| Error::Socks5(err.to_string()))?;
		packet.extend_from_slice(payload);

		self.socket.send(&packet).await?;
		Ok(())
	}

	pub fn local_addr(&self) -> Result<SocketAddr, IoError> {
		self.socket.local_addr()
	}
}

/// Convert a `fast_socks5` target address into wind's [`TargetAddr`].
pub fn convert_target_addr(addr: &SocksTargetAddr) -> TargetAddr {
	match addr {
		SocksTargetAddr::Ip(SocketAddr::V4(addr)) => TargetAddr::IPv4(*addr.ip(), addr.port()),
		SocksTargetAddr::Ip(SocketAddr::V6(addr)) => TargetAddr::IPv6(*addr.ip(), addr.port()),
		SocksTargetAddr::Domain(domain, port) => TargetAddr::Domain(domain.clone(), *port),
	}
}

/// Best-effort origin address for a reply's SOCKS5 UDP header (RFC 1928 §7:
/// ATYP/DST identify the remote host). Prefers the packet's recorded source,
/// falling back to its target. Domains have no RFC codepoint here, so they are
/// reported as `0.0.0.0:port`.
pub fn reply_origin_socket(pkt: &UdpPacket) -> SocketAddr {
	let origin = pkt.source.as_ref().unwrap_or(&pkt.target);
	match origin {
		TargetAddr::IPv4(ip, port) => SocketAddr::new((*ip).into(), *port),
		TargetAddr::IPv6(ip, port) => SocketAddr::new((*ip).into(), *port),
		TargetAddr::Domain(_, port) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), *port),
	}
}

/// Unwrap an IPv4-mapped IPv6 address (`::ffff:V4`) back to IPv4 so dual-stack
/// relay sockets compare source IPs on equal footing with IPv4 expectations.
fn unmap_v4_mapped(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
			Some(v4) => IpAddr::V4(v4),
			None => IpAddr::V6(v6),
		},
		v4 => v4,
	}
}

#[cfg(test)]
mod tests {
	use std::net::{Ipv4Addr, SocketAddr};

	use tokio::{net::UdpSocket as TokioUdpSocket, time::Duration};

	use super::*;

	/// Build a minimal SOCKS5 UDP request frame:
	/// `RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT payload`.
	fn make_socks_udp_pkt(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
		let mut buf = vec![0x00, 0x00, 0x00, 0x01];
		match target {
			SocketAddr::V4(v4) => {
				buf.extend_from_slice(&v4.ip().octets());
				buf.extend_from_slice(&v4.port().to_be_bytes());
			}
			SocketAddr::V6(_) => unreachable!("v4 only in this helper"),
		}
		buf.extend_from_slice(payload);
		buf
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn first_packet_from_mismatched_ip_is_rejected() {
		// Control connection claims the legitimate client lives on TEST-NET-1.
		// The packet we will actually send comes from 127.0.0.1 — the IP check
		// MUST refuse to latch the association onto the wrong peer.
		let session = UdpSession::new(
			0,
			SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9999)),
			IpAddr::V4(Ipv4Addr::LOCALHOST),
			None,
			65535,
		)
		.expect("create session");
		let relay_addr = session.local_addr().unwrap();

		// Off-path "attacker": binds to 127.0.0.1, races to send the first UDP
		// datagram before the legitimate (TEST-NET-1) client can.
		let attacker = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
		let frame = make_socks_udp_pkt(SocketAddr::from(([1, 1, 1, 1], 53)), b"hijack");
		attacker.send_to(&frame, relay_addr).await.unwrap();

		let res = tokio::time::timeout(Duration::from_millis(500), session.recv()).await;
		let err = res
			.expect("recv must return before timeout")
			.expect_err("first-packet hijack must be rejected");
		match err {
			Error::WrongPacketSource => {}
			other => panic!("expected WrongPacketSource, got {other:?}"),
		}
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn first_packet_from_matching_ip_latches_in() {
		// ctrl_addr.ip() == sender IP == 127.0.0.1 → must succeed and the
		// session socket becomes `connect()`-bound to the sender.
		let session = UdpSession::new(
			0,
			SocketAddr::from((Ipv4Addr::LOCALHOST, 9999)),
			IpAddr::V4(Ipv4Addr::LOCALHOST),
			None,
			65535,
		)
		.expect("create session");
		let relay_addr = session.local_addr().unwrap();

		let sender = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
		let frame = make_socks_udp_pkt(SocketAddr::from(([1, 1, 1, 1], 53)), b"ok");
		sender.send_to(&frame, relay_addr).await.unwrap();

		let (_pkt, addr) = tokio::time::timeout(Duration::from_millis(500), session.recv())
			.await
			.expect("recv must return before timeout")
			.expect("matching-IP packet must be accepted");

		match addr {
			SocksTargetAddr::Ip(SocketAddr::V4(v4)) => {
				assert_eq!(*v4.ip(), Ipv4Addr::new(1, 1, 1, 1));
				assert_eq!(v4.port(), 53);
			}
			other => panic!("unexpected dst addr {other:?}"),
		}
	}
}
