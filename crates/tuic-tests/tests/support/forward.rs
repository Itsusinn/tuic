//! Exercise the real client configuration path, not standalone tunnel inbounds.

use std::{net::SocketAddr, time::Duration};

use eyre::{Context, Result};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{TcpListener, TcpStream, UdpSocket},
	time::{Instant, sleep, timeout, timeout_at},
};
use tuic_client::{
	Config,
	config::{TcpForward, UdpForward},
};

const LIMIT: Duration = Duration::from_secs(15);
const UDP_IDLE: Duration = Duration::from_millis(200);

async fn start(
	mut config: Config,
	tcp_targets: [SocketAddr; 2],
	udp_targets: [SocketAddr; 2],
) -> Result<(tuic_client::ClientGuard, [SocketAddr; 2], [SocketAddr; 2])> {
	config.local.server = "127.0.0.1:0".parse()?;
	// ClientGuard currently reports only the SOCKS5 address. Reserve dynamic
	// ports together, release them immediately before startup, and retry only
	// an actual bind collision; relay/auth/config failures must remain failures.
	for _ in 0..5 {
		let tcp_reservations = [
			std::net::TcpListener::bind("127.0.0.1:0")?,
			std::net::TcpListener::bind("127.0.0.1:0")?,
		];
		let udp_reservations = [
			std::net::UdpSocket::bind("127.0.0.1:0")?,
			std::net::UdpSocket::bind("127.0.0.1:0")?,
		];
		let tcp = [tcp_reservations[0].local_addr()?, tcp_reservations[1].local_addr()?];
		let udp = [udp_reservations[0].local_addr()?, udp_reservations[1].local_addr()?];
		config.local.tcp_forward = tcp
			.into_iter()
			.zip(tcp_targets)
			.map(|(listen, target)| TcpForward {
				listen,
				remote: (target.ip().to_string(), target.port()),
			})
			.collect();
		config.local.udp_forward = udp
			.into_iter()
			.zip(udp_targets)
			.map(|(listen, target)| UdpForward {
				listen,
				remote: (target.ip().to_string(), target.port()),
				timeout: UDP_IDLE,
			})
			.collect();
		drop(tcp_reservations);
		drop(udp_reservations);
		match timeout(LIMIT, tuic_client::run(config.clone()))
			.await
			.wrap_err("forward client startup timed out")?
		{
			Ok(client) => return Ok((client, tcp, udp)),
			Err(error)
				if error.chain().any(|cause| {
					cause
						.downcast_ref::<std::io::Error>()
						.is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse)
				}) =>
			{
				continue;
			}
			Err(error) => return Err(error),
		}
	}
	eyre::bail!("could not bind dynamic forward ports after five attempts")
}

async fn tcp_roundtrip(target: &TcpListener, forward: SocketAddr, tag: u8) -> Result<()> {
	let payload: Vec<u8> = (0..16_385).map(|i| (i % 251) as u8).collect();
	let peer = async {
		let (mut stream, _) = target.accept().await?;
		// Identifies the configured target and exercises a server-first protocol.
		stream.write_all(&[tag]).await?;
		let mut received = Vec::new();
		(&mut stream)
			.take(payload.len() as u64 + 1)
			.read_to_end(&mut received)
			.await?;
		assert_eq!(received, payload, "TCP forward lost request bytes or EOF");
		stream.write_all(&received).await?;
		stream.shutdown().await?;
		Ok::<_, eyre::Report>(())
	};
	let client = async {
		let mut stream = TcpStream::connect(forward).await?;
		assert_eq!(
			stream.read_u8().await?,
			tag,
			"TCP forward reached the wrong configured target"
		);
		for chunk in payload.chunks(997) {
			stream.write_all(chunk).await?;
		}
		stream.shutdown().await?;
		let mut received = Vec::new();
		stream.take(payload.len() as u64 + 1).read_to_end(&mut received).await?;
		assert_eq!(received, payload, "TCP forward lost response bytes after half-close");
		Ok::<_, eyre::Report>(())
	};
	tokio::try_join!(peer, client)?;
	Ok(())
}

async fn udp_echo(target: &UdpSocket, tag: u8) -> Result<()> {
	let mut buffer = [0; 2048];
	loop {
		let (len, source) = target.recv_from(&mut buffer[1..]).await?;
		buffer[0] = tag;
		target.send_to(&buffer[..len + 1], source).await?;
	}
}

async fn udp_roundtrip(client: &UdpSocket, forward: SocketAddr, tag: u8, source_id: u8, round: u8) -> Result<()> {
	let mut payload = vec![0xa5; [3, 1200, 64][usize::from(round)]];
	payload[0] = source_id;
	payload[1] = round;
	let deadline = Instant::now() + Duration::from_secs(5);
	let mut buffer = [0; 2048];
	loop {
		eyre::ensure!(
			Instant::now() < deadline,
			"UDP forward did not reply to source {source_id}, round {round}"
		);
		client.send_to(&payload, forward).await?;
		let attempt = deadline.min(Instant::now() + Duration::from_millis(250));
		if let Ok(received) = timeout_at(attempt, client.recv_from(&mut buffer)).await {
			let (len, source) = received?;
			assert_eq!(source, forward, "UDP reply must come from the forward listener");
			eyre::ensure!(len >= 3, "truncated UDP reply");
			assert_eq!(buffer[0], tag, "UDP forward reached the wrong configured target");
			assert_eq!(buffer[1], source_id, "UDP reply leaked between client source ports");
			if buffer[2] < round {
				continue;
			} // Delayed duplicate of a previous round.
			assert_eq!(&buffer[1..len], payload, "UDP forward changed the payload");
			return Ok(());
		}
	}
}

async fn udp_sources(forward: SocketAddr, tag: u8) -> Result<()> {
	let first = UdpSocket::bind("127.0.0.1:0").await?;
	let second = UdpSocket::bind("127.0.0.1:0").await?;
	for round in 0..3 {
		if round == 2 {
			// Keep the same source sockets across an idle period longer than the
			// configured session timeout and its GC interval.
			sleep(UDP_IDLE * 4).await;
		}
		tokio::try_join!(
			udp_roundtrip(&first, forward, tag, 1, round),
			udp_roundtrip(&second, forward, tag, 2, round),
		)?;
	}
	Ok(())
}

pub async fn exercise(config: Config) -> Result<()> {
	let tcp_targets = [
		TcpListener::bind("127.0.0.1:0").await?,
		TcpListener::bind("127.0.0.1:0").await?,
	];
	let udp_targets = [UdpSocket::bind("127.0.0.1:0").await?, UdpSocket::bind("127.0.0.1:0").await?];
	let (client, tcp, udp) = start(
		config,
		[tcp_targets[0].local_addr()?, tcp_targets[1].local_addr()?],
		[udp_targets[0].local_addr()?, udp_targets[1].local_addr()?],
	)
	.await?;
	let result = timeout(LIMIT, async {
		let traffic = async {
			let tcp_traffic = async {
				for _ in 0..2 {
					tokio::try_join!(
						tcp_roundtrip(&tcp_targets[0], tcp[0], 10),
						tcp_roundtrip(&tcp_targets[1], tcp[1], 20)
					)?;
				}
				Ok::<_, eyre::Report>(())
			};
			tokio::try_join!(tcp_traffic, udp_sources(udp[0], 30), udp_sources(udp[1], 40))?;
			Ok::<_, eyre::Report>(())
		};
		// All echo futures are scoped here; no detached tasks on any exit path.
		tokio::select! {
			result = traffic => result,
			result = udp_echo(&udp_targets[0], 30) => { result?; eyre::bail!("first UDP echo stopped") },
			result = udp_echo(&udp_targets[1], 40) => { result?; eyre::bail!("second UDP echo stopped") },
		}
	})
	.await;
	client.shutdown().await;
	result.wrap_err("TCP/UDP forward deadline exceeded")??;
	// Real listeners must be released after shutdown, including UDP sessions
	// which were still active when cancellation started.
	for address in tcp {
		let _rebound = TcpListener::bind(address).await.wrap_err("TCP forward listener leaked")?;
	}
	for address in udp {
		let _rebound = UdpSocket::bind(address).await.wrap_err("UDP forward listener leaked")?;
	}
	Ok(())
}
