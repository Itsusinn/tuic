//! TCP forward listeners must be part of the client's startup transaction.

use std::{net::SocketAddr, time::Duration};

use tuic_client::{
	Config, TuicClientPlugin,
	config::{TcpForward, UdpForward},
};
use wind_core::App;

fn free_tcp_address() -> eyre::Result<SocketAddr> {
	let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
	Ok(listener.local_addr()?)
}

fn config(listen: SocketAddr) -> Config {
	let mut cfg = Config::default();
	cfg.local.server = SocketAddr::from(([127, 0, 0, 1], 0));
	cfg.local.tcp_forward.push(TcpForward {
		listen,
		remote: ("127.0.0.1".into(), 9),
	});
	cfg
}

#[tokio::test]
async fn taken_tcp_forward_port_aborts_startup() -> eyre::Result<()> {
	let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let listen = blocker.local_addr()?;
	let result = tokio::time::timeout(Duration::from_secs(5), tuic_client::run(config(listen))).await?;
	let error = result
		.err()
		.ok_or_else(|| eyre::eyre!("startup accepted a taken TCP forward port"))?;
	assert!(error.to_string().contains("TCP forward listener"));
	assert!(error.to_string().contains(&listen.to_string()));
	Ok(())
}

#[tokio::test]
async fn forward_bind_failure_precedes_eager_relay_setup() -> eyre::Result<()> {
	let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let mut cfg = config(blocker.local_addr()?);
	cfg.relay.lazy = false;
	cfg.relay.certificates = vec!["no-such-ca-certificate.pem".into()];
	let result = tokio::time::timeout(Duration::from_secs(5), tuic_client::run(cfg)).await?;
	let error = result
		.err()
		.ok_or_else(|| eyre::eyre!("startup accepted a taken TCP forward port"))?;
	assert!(error.to_string().contains("TCP forward listener"));
	Ok(())
}

#[tokio::test]
async fn second_tcp_bind_failure_releases_the_first_listener() -> eyre::Result<()> {
	let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let listen = free_tcp_address()?;
	let mut cfg = config(listen);
	cfg.local.tcp_forward.push(TcpForward {
		listen: blocker.local_addr()?,
		remote: ("127.0.0.1".into(), 9),
	});
	assert!(
		tokio::time::timeout(Duration::from_secs(5), tuic_client::run(cfg))
			.await?
			.is_err()
	);
	let _rebound = std::net::TcpListener::bind(listen)?;
	Ok(())
}

#[tokio::test]
async fn udp_bind_failure_releases_the_tcp_listener() -> eyre::Result<()> {
	let blocker = std::net::UdpSocket::bind("127.0.0.1:0")?;
	let listen = free_tcp_address()?;
	let mut cfg = config(listen);
	cfg.local.udp_forward.push(UdpForward {
		listen: blocker.local_addr()?,
		remote: ("127.0.0.1".into(), 9),
		timeout: Duration::from_secs(60),
	});
	assert!(
		tokio::time::timeout(Duration::from_secs(5), tuic_client::run(cfg))
			.await?
			.is_err()
	);
	let _rebound = std::net::TcpListener::bind(listen)?;
	Ok(())
}

#[tokio::test]
async fn tcp_listener_is_reserved_from_build_until_app_drop() -> eyre::Result<()> {
	let listen = free_tcp_address()?;
	let app = tokio::time::timeout(
		Duration::from_secs(5),
		App::new().add_plugin(TuicClientPlugin::new(config(listen))),
	)
	.await??;
	assert!(
		std::net::TcpListener::bind(listen).is_err(),
		"build must keep the TCP port reserved"
	);
	drop(app);
	let _rebound = std::net::TcpListener::bind(listen)?;
	Ok(())
}

#[tokio::test]
async fn socks_bind_failure_releases_the_tcp_listener() -> eyre::Result<()> {
	let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let listen = free_tcp_address()?;
	let mut cfg = config(listen);
	cfg.local.server = blocker.local_addr()?;
	assert!(
		tokio::time::timeout(Duration::from_secs(5), tuic_client::run(cfg))
			.await?
			.is_err()
	);
	let _rebound = std::net::TcpListener::bind(listen)?;
	Ok(())
}

#[tokio::test]
async fn tcp_listener_stays_bound_until_client_shutdown() -> eyre::Result<()> {
	let listen = free_tcp_address()?;
	let client = tokio::time::timeout(Duration::from_secs(5), tuic_client::run(config(listen))).await??;
	assert!(std::net::TcpListener::bind(listen).is_err());
	client.shutdown().await;
	let _rebound = std::net::TcpListener::bind(listen)?;
	Ok(())
}
