use std::{
	io::{self, IoSliceMut},
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use quinn::{
	AsyncUdpSocket, UdpSender,
	udp::{RecvMeta, Transmit},
};
use tokio::{io::ReadBuf, net::UdpSocket};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct Socks5UdpSocket {
	socket:      Arc<UdpSocket>,
	relay_addr:  SocketAddr,
	buffer_size: usize,
	is_ipv6:     bool,
}

impl Socks5UdpSocket {
	pub fn new(socket: UdpSocket, relay_addr: SocketAddr, buffer_size: usize) -> Self {
		// Ensure minimum buffer size of 1522 bytes (1500 MTU + 22 SOCKS5 header)
		let buffer_size = buffer_size.max(1522);
		let is_ipv6 = socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
		Self {
			socket: Arc::new(socket),
			relay_addr,
			buffer_size,
			is_ipv6,
		}
	}
}

#[derive(Debug)]
struct Socks5UdpSender(Arc<Socks5UdpSocket>);

impl UdpSender for Socks5UdpSender {
	fn poll_send(self: Pin<&mut Self>, transmit: &Transmit<'_>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let mut buf = Vec::with_capacity(22 + transmit.contents.len());
		buf.extend_from_slice(&[0, 0, 0]); // RSV, FRAG
		match transmit.destination {
			SocketAddr::V4(addr) => {
				buf.push(1);
				buf.extend_from_slice(&addr.ip().octets());
				buf.extend_from_slice(&addr.port().to_be_bytes());
			}
			SocketAddr::V6(addr) => {
				if let Some(ipv4) = addr.ip().to_ipv4_mapped() {
					buf.push(1);
					buf.extend_from_slice(&ipv4.octets());
				} else {
					buf.push(4);
					buf.extend_from_slice(&addr.ip().octets());
				}
				buf.extend_from_slice(&addr.port().to_be_bytes());
			}
		}
		buf.extend_from_slice(transmit.contents);

		match self.0.socket.try_send_to(&buf, self.0.relay_addr) {
			Ok(_) => Poll::Ready(Ok(())),
			Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => self.0.socket.poll_send_ready(cx),
			Err(e) => Poll::Ready(Err(e)),
		}
	}
}

impl AsyncUdpSocket for Socks5UdpSocket {
	fn create_sender(&self) -> Pin<Box<dyn quinn::UdpSender>> {
		Box::pin(Socks5UdpSender(Arc::new(self.clone())))
	}

	fn poll_recv(
		&mut self,
		cx: &mut Context<'_>,
		bufs: &mut [IoSliceMut<'_>],
		meta: &mut [RecvMeta],
	) -> Poll<io::Result<usize>> {
		let mut buf = vec![0u8; self.buffer_size];
		let mut read_buf = ReadBuf::new(&mut buf);

		match self.socket.poll_recv_from(cx, &mut read_buf) {
			Poll::Ready(Ok(from_addr)) => {
				if from_addr != self.relay_addr {
					debug!("[socks5] dropped UDP packet from unexpected source: {:?}", from_addr);
					return Poll::Pending;
				}
				let data = read_buf.filled();
				if let Some((mut src_addr, quic_data)) = unwrap_socks5_udp(data) {
					if self.is_ipv6 {
						if let SocketAddr::V4(v4) = src_addr {
							src_addr = SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port());
						}
					} else if let SocketAddr::V6(v6) = src_addr {
						if let Some(v4) = v6.ip().to_ipv4_mapped() {
							src_addr = SocketAddr::new(IpAddr::V4(v4), v6.port());
						}
					}

					let len = quic_data.len();
					if bufs.is_empty() {
						Poll::Ready(Err(io::Error::other("no buffers provided")))
					} else if len > bufs[0].len() {
						Poll::Ready(Err(io::Error::other("buffer too small")))
					} else {
						bufs[0][..len].copy_from_slice(quic_data);
						let mut recv_meta = RecvMeta::default();
						recv_meta.addr = src_addr;
						recv_meta.len = len;
						recv_meta.stride = len;
						meta[0] = recv_meta;
						Poll::Ready(Ok(1))
					}
				} else {
					// Invalid SOCKS5 UDP packet; drop it and wait for the next readable event.
					debug!("[socks5] dropped invalid SOCKS5 UDP packet from {:?}", from_addr);
					Poll::Pending
				}
			}
			Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
			Poll::Pending => Poll::Pending,
		}
	}

	fn local_addr(&self) -> io::Result<SocketAddr> {
		self.socket.local_addr()
	}
}

fn unwrap_socks5_udp(data: &[u8]) -> Option<(SocketAddr, &[u8])> {
	if data.len() < 4 {
		return None;
	}
	if data[0..3] != [0, 0, 0] {
		return None;
	}
	let atyp = data[3];
	match atyp {
		1 => {
			if data.len() < 10 {
				return None;
			}
			let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
			let port = u16::from_be_bytes([data[8], data[9]]);
			Some((SocketAddr::new(IpAddr::V4(ip), port), &data[10..]))
		}
		4 => {
			if data.len() < 22 {
				return None;
			}
			let mut octets = [0u8; 16];
			octets.copy_from_slice(&data[4..20]);
			let ip = Ipv6Addr::from(octets);
			let port = u16::from_be_bytes([data[20], data[21]]);
			Some((SocketAddr::new(IpAddr::V6(ip), port), &data[22..]))
		}
		_ => None,
	}
}
