use std::{
	io::{self, IoSliceMut},
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use quinn::{
	AsyncUdpSocket, UdpPoller,
	udp::{RecvMeta, Transmit},
};
use tokio::{io::ReadBuf, net::UdpSocket};

#[derive(Debug)]
pub struct Socks5UdpSocket {
	socket:     UdpSocket,
	relay_addr: SocketAddr,
}

impl Socks5UdpSocket {
	pub fn new(socket: UdpSocket, relay_addr: SocketAddr) -> Self {
		Self { socket, relay_addr }
	}
}

#[derive(Debug)]
struct Socks5UdpPoller(Arc<Socks5UdpSocket>);

impl UdpPoller for Socks5UdpPoller {
	fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
		self.0.socket.poll_send_ready(cx)
	}
}

impl AsyncUdpSocket for Socks5UdpSocket {
	fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
		Box::pin(Socks5UdpPoller(self))
	}

	fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
		let mut buf = Vec::with_capacity(22 + transmit.contents.len());
		buf.extend_from_slice(&[0, 0, 0]); // RSV, FRAG
		match transmit.destination {
			SocketAddr::V4(addr) => {
				buf.push(1);
				buf.extend_from_slice(&addr.ip().octets());
				buf.extend_from_slice(&addr.port().to_be_bytes());
			}
			SocketAddr::V6(addr) => {
				buf.push(4);
				buf.extend_from_slice(&addr.ip().octets());
				buf.extend_from_slice(&addr.port().to_be_bytes());
			}
		}
		buf.extend_from_slice(transmit.contents);

		match self.socket.try_send_to(&buf, self.relay_addr) {
			Ok(_) => Ok(()),
			Err(e) => Err(e),
		}
	}

	fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
		let mut buf = [0u8; 2048];
		let mut read_buf = ReadBuf::new(&mut buf);

		match self.socket.poll_recv_from(cx, &mut read_buf) {
			Poll::Ready(Ok(_from_addr)) => {
				let data = read_buf.filled();
				if let Some((src_addr, quic_data)) = unwrap_socks5_udp(data) {
					let len = quic_data.len();
					if !bufs.is_empty() && len <= bufs[0].len() {
						bufs[0][..len].copy_from_slice(quic_data);
						meta[0] = RecvMeta {
							addr: src_addr,
							len,
							stride: len,
							ecn: None,
							dst_ip: None,
						};
						Poll::Ready(Ok(1))
					} else {
						Poll::Ready(Err(io::Error::other("buffer too small or multiple buffers not supported")))
					}
				} else {
					cx.waker().wake_by_ref();
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
