//! One small TCP and UDP exchange through a real client/server pair.

use std::{net::SocketAddr, time::Duration};

use eyre::{Context, Result};
use fast_socks5::client::{Config, Socks5Datagram, Socks5Stream};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{TcpListener, TcpStream, UdpSocket},
	time::{Instant, timeout, timeout_at},
};
use tuic_tests::{Backend, TestPair};

const DEADLINE: Duration = Duration::from_secs(20);
const PAYLOAD: &[u8] = b"tuic relay\0\xff";

async fn echo_udp(socket: &UdpSocket) -> Result<()> {
	let mut buffer = [0; 128];
	loop {
		let (len, source) = socket.recv_from(&mut buffer).await?;
		socket.send_to(&buffer[..len], source).await?;
	}
}

pub async fn exercise(server: Backend, client: Backend, zero_rtt: bool) -> Result<()> {
	let pair = timeout(DEADLINE, TestPair::start_with_client(server, client, zero_rtt))
		.await
		.wrap_err("starting relay pair")?;
	let result = timeout(DEADLINE, exchange(&pair.socks5_addr())).await;
	pair.shutdown().await;
	result.wrap_err("TCP/UDP relay deadline exceeded")?
}

async fn exchange(socks: &str) -> Result<()> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let target = listener.local_addr()?;
	let peer = async {
		let (mut stream, _) = listener.accept().await?;
		let mut received = vec![0; PAYLOAD.len()];
		stream.read_exact(&mut received).await?;
		assert_eq!(received, PAYLOAD);
		stream.write_all(&received).await?;
		Ok::<_, eyre::Report>(())
	};
	let client = async {
		let mut stream = Socks5Stream::connect(socks, target.ip().to_string(), target.port(), Config::default()).await?;
		stream.write_all(PAYLOAD).await?;
		let mut received = vec![0; PAYLOAD.len()];
		stream.read_exact(&mut received).await?;
		assert_eq!(received, PAYLOAD);
		Ok::<_, eyre::Report>(())
	};
	tokio::try_join!(peer, client)?;

	let echo = UdpSocket::bind("127.0.0.1:0").await?;
	let target = echo.local_addr()?;
	let peer = echo_udp(&echo);
	let client = async {
		let control = TcpStream::connect(socks).await?;
		let association = Socks5Datagram::bind(control, SocketAddr::from(([127, 0, 0, 1], 0))).await?;
		let deadline = Instant::now() + Duration::from_secs(5);
		let mut buffer = [0; 128];
		loop {
			eyre::ensure!(Instant::now() < deadline, "UDP echo did not answer");
			association.send_to(PAYLOAD, (target.ip(), target.port())).await?;
			let attempt = deadline.min(Instant::now() + Duration::from_millis(250));
			if let Ok(received) = timeout_at(attempt, association.recv_from(&mut buffer)).await {
				let (len, source) = received?;
				assert_eq!(&buffer[..len], PAYLOAD);
				assert_eq!(source.to_string(), target.to_string());
				return Ok::<_, eyre::Report>(());
			}
		}
	};
	// Both futures are scoped: completion, failure and timeout drop the sockets.
	tokio::select! {
		result = client => result,
		result = peer => { result?; eyre::bail!("UDP echo stopped") },
	}
}
