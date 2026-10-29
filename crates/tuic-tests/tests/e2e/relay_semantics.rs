//! Relay semantics over loopback across client/server backend combinations.
//! No external DNS, fixed ports, persistent credentials, or detached echo tasks.

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

async fn tcp_half_close(socks: &str) -> Result<()> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let target = listener.local_addr()?;
	let request: Vec<u8> = (0..65_537).map(|i| (i % 251) as u8).collect();
	let response: Vec<u8> = request.iter().rev().copied().collect();
	let peer = async {
		let (mut socket, _) = listener.accept().await?;
		let mut received = Vec::new();
		(&mut socket)
			.take(request.len() as u64 + 1)
			.read_to_end(&mut received)
			.await?;
		assert_eq!(received, request, "the target must receive all bytes before EOF");
		// Deliberately answer only after EOF: dropping the reverse direction on
		// the client's FIN would lose this entire response.
		socket.write_all(&response).await?;
		socket.shutdown().await?;
		Ok::<_, eyre::Report>(())
	};
	let client = async {
		let mut stream = Socks5Stream::connect(socks, target.ip().to_string(), target.port(), Config::default()).await?;
		for chunk in request.chunks(997) {
			stream.write_all(chunk).await?;
		}
		stream.shutdown().await?;
		let mut received = Vec::new();
		stream.take(response.len() as u64 + 1).read_to_end(&mut received).await?;
		assert_eq!(
			received, response,
			"the response after half-close must arrive intact and end with EOF"
		);
		Ok::<_, eyre::Report>(())
	};
	tokio::try_join!(peer, client)?;
	Ok(())
}

async fn tcp_server_first(socks: &str) -> Result<()> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let target = listener.local_addr()?;
	let peer = async {
		let (mut socket, _) = listener.accept().await?;
		socket.write_all(b"ready\0\xff").await?;
		let mut reply = [0; 3];
		socket.read_exact(&mut reply).await?;
		assert_eq!(&reply, b"ack");
		socket.shutdown().await?;
		Ok::<_, eyre::Report>(())
	};
	let client = async {
		let mut stream = Socks5Stream::connect(socks, target.ip().to_string(), target.port(), Config::default()).await?;
		let mut banner = [0; 7];
		// A server-first protocol must progress without a client payload.
		stream.read_exact(&mut banner).await?;
		assert_eq!(&banner, b"ready\0\xff");
		stream.write_all(b"ack").await?;
		assert_eq!(stream.read(&mut banner).await?, 0, "target EOF must reach SOCKS5");
		Ok::<_, eyre::Report>(())
	};
	tokio::try_join!(peer, client)?;
	Ok(())
}

async fn echo_udp(socket: &UdpSocket) -> Result<()> {
	let mut buffer = [0; 2048];
	loop {
		let (len, source) = socket.recv_from(&mut buffer).await?;
		socket.send_to(&buffer[..len], source).await?;
	}
}

async fn udp_target_switch(socks: &str) -> Result<()> {
	let first = UdpSocket::bind("127.0.0.1:0").await?;
	let second = UdpSocket::bind("127.0.0.1:0").await?;
	let targets = [first.local_addr()?, second.local_addr()?, first.local_addr()?];
	let client = async {
		let backing = TcpStream::connect(socks).await?;
		let bind = SocketAddr::from(([127, 0, 0, 1], 0));
		let association = Socks5Datagram::bind(backing, bind).await?;
		for (index, target) in targets.into_iter().enumerate() {
			let payload = vec![index as u8; [1, 64, 1200][index]];
			let deadline = Instant::now() + Duration::from_secs(5);
			let mut buffer = [0; 2048];
			loop {
				eyre::ensure!(Instant::now() < deadline, "UDP target {index} did not answer");
				association.send_to(&payload, (target.ip(), target.port())).await?;
				let attempt = deadline.min(Instant::now() + Duration::from_millis(250));
				if let Ok(received) = timeout_at(attempt, association.recv_from(&mut buffer)).await {
					let (len, source) = received?;
					// Ignore delayed duplicates from the preceding target, but
					// require both the current payload and source address.
					if buffer[..len] == payload {
						assert_eq!(
							source.to_string(),
							target.to_string(),
							"UDP reply source must follow the target"
						);
						break;
					}
				}
			}
		}
		Ok::<_, eyre::Report>(())
	};
	// The echo futures are owned by this scope and dropped on every exit path.
	tokio::select! {
		result = client => result,
		result = echo_udp(&first) => { result?; eyre::bail!("first UDP echo stopped") },
		result = echo_udp(&second) => { result?; eyre::bail!("second UDP echo stopped") },
	}
}

#[derive(Clone, Copy)]
enum Scenario {
	HalfClose,
	ServerFirst,
	UdpTargetSwitch,
}

async fn relay_case(server: Backend, client: Backend, scenario: Scenario) -> Result<()> {
	let pair = timeout(DEADLINE, TestPair::start_with_client(server, client, false))
		.await
		.wrap_err("starting relay pair")?;
	let socks = pair.socks5_addr();
	let result = timeout(DEADLINE, async {
		match scenario {
			Scenario::HalfClose => tcp_half_close(&socks).await,
			Scenario::ServerFirst => tcp_server_first(&socks).await,
			Scenario::UdpTargetSwitch => udp_target_switch(&socks).await,
		}
	})
	.await;
	pair.shutdown().await;
	result.wrap_err("relay deadline exceeded")?
}

macro_rules! backend_cases {
	($name:ident, $server:ident, $client:ident) => {
		mod $name {
			use super::*;

			#[tokio::test]
			async fn tcp_half_close_response() -> Result<()> {
				relay_case(Backend::$server, Backend::$client, Scenario::HalfClose).await
			}

			#[tokio::test]
			async fn tcp_server_first_banner() -> Result<()> {
				relay_case(Backend::$server, Backend::$client, Scenario::ServerFirst).await
			}

			#[tokio::test]
			async fn udp_switches_target_on_one_association() -> Result<()> {
				relay_case(Backend::$server, Backend::$client, Scenario::UdpTargetSwitch).await
			}
		}
	};
}

backend_cases!(quinn_quinn, Quinn, Quinn);

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
mod quiche {
	use super::*;
	backend_cases!(quiche_quinn, Quiche, Quinn);
	backend_cases!(quinn_quiche, Quinn, Quiche);
	backend_cases!(quiche_quiche, Quiche, Quiche);
}
