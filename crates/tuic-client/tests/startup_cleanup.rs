use std::{net::SocketAddr, time::Duration};

use tokio_util::sync::CancellationToken;
use tuic_client::{Config, config::UdpForward};

fn free_udp_address() -> eyre::Result<SocketAddr> {
	let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
	Ok(socket.local_addr()?)
}

fn config(socks: SocketAddr, udp: SocketAddr) -> Config {
	let mut cfg = Config::default();
	cfg.local.server = socks;
	cfg.local.udp_forward.push(UdpForward {
		listen: udp,
		remote: ("127.0.0.1".into(), 9),
		timeout: Duration::from_secs(60),
	});
	cfg
}

#[tokio::test]
async fn socks_bind_failure_releases_already_bound_udp_forwarder() -> eyre::Result<()> {
	let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let udp = free_udp_address()?;
	let cancel = CancellationToken::new();
	let result = tokio::time::timeout(
		Duration::from_secs(5),
		tuic_client::run_with_cancel(config(blocker.local_addr()?, udp), cancel.clone()),
	)
	.await?;
	assert!(result.is_err());
	assert!(!cancel.is_cancelled(), "failed startup must preserve the caller's token");
	let _rebound = std::net::UdpSocket::bind(udp)?;
	Ok(())
}

#[tokio::test]
async fn second_forwarder_build_failure_releases_the_first_socket() -> eyre::Result<()> {
	let blocker = std::net::UdpSocket::bind("127.0.0.1:0")?;
	let udp = free_udp_address()?;
	let mut cfg = config(SocketAddr::from(([127, 0, 0, 1], 0)), udp);
	cfg.local.udp_forward.push(UdpForward {
		listen: blocker.local_addr()?,
		remote: ("127.0.0.1".into(), 9),
		timeout: Duration::from_secs(60),
	});
	let cancel = CancellationToken::new();
	let result = tokio::time::timeout(Duration::from_secs(5), tuic_client::run_with_cancel(cfg, cancel.clone())).await?;
	assert!(result.is_err());
	assert!(!cancel.is_cancelled());
	let _rebound = std::net::UdpSocket::bind(udp)?;
	Ok(())
}

#[tokio::test]
async fn shutdown_releases_client_sockets_and_cancels_caller() -> eyre::Result<()> {
	let udp = free_udp_address()?;
	let cancel = CancellationToken::new();
	let client = tokio::time::timeout(
		Duration::from_secs(5),
		tuic_client::run_with_cancel(config(SocketAddr::from(([127, 0, 0, 1], 0)), udp), cancel.clone()),
	)
	.await??;
	let socks = client.socks5_addr;
	client.shutdown().await;
	assert!(cancel.is_cancelled());
	let _udp = std::net::UdpSocket::bind(udp)?;
	let _socks = std::net::TcpListener::bind(socks)?;
	Ok(())
}

#[tokio::test]
async fn drop_releases_client_sockets_and_cancels_caller() -> eyre::Result<()> {
	let udp = free_udp_address()?;
	let cancel = CancellationToken::new();
	let client = tokio::time::timeout(
		Duration::from_secs(5),
		tuic_client::run_with_cancel(config(SocketAddr::from(([127, 0, 0, 1], 0)), udp), cancel.clone()),
	)
	.await??;
	let socks = client.socks5_addr;
	drop(client);
	assert!(cancel.is_cancelled());
	tokio::time::timeout(Duration::from_secs(5), async {
		loop {
			if std::net::UdpSocket::bind(udp).is_ok() && std::net::TcpListener::bind(socks).is_ok() {
				break;
			}
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await?;
	Ok(())
}
