use std::{net::SocketAddr, time::Duration};

use tokio_util::sync::CancellationToken;
use tuic_server::Config;

fn config(server: SocketAddr, restful: SocketAddr) -> Config {
	#[cfg(feature = "aws-lc-rs")]
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	#[cfg(feature = "ring")]
	let _ = rustls::crypto::ring::default_provider().install_default();
	let mut cfg = Config {
		server,
		..Default::default()
	};
	cfg.tls.self_sign = true;
	cfg.tls.hostname = "localhost".into();
	cfg.restful.enabled = true;
	cfg.restful.addr = restful;
	cfg
}

#[tokio::test]
async fn restful_bind_failure_releases_tuic_listener() -> eyre::Result<()> {
	let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let probe = std::net::UdpSocket::bind("127.0.0.1:0")?;
	let server = probe.local_addr()?;
	drop(probe);
	let cancel = CancellationToken::new();
	let result = tokio::time::timeout(
		Duration::from_secs(5),
		tuic_server::run_with_cancel(config(server, blocker.local_addr()?), cancel.clone()),
	)
	.await?;
	assert!(result.is_err());
	assert!(!cancel.is_cancelled(), "failed startup must preserve the caller's token");
	let _rebound = std::net::UdpSocket::bind(server)?;
	Ok(())
}

#[tokio::test]
async fn tuic_bind_failure_releases_restful_task_started_during_build() -> eyre::Result<()> {
	let blocker = std::net::UdpSocket::bind("127.0.0.1:0")?;
	let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
	let restful = probe.local_addr()?;
	drop(probe);
	let cancel = CancellationToken::new();
	let result = tokio::time::timeout(
		Duration::from_secs(5),
		tuic_server::run_with_cancel(config(blocker.local_addr()?, restful), cancel.clone()),
	)
	.await?;
	assert!(result.is_err());
	assert!(!cancel.is_cancelled());
	let _rebound = std::net::TcpListener::bind(restful)?;
	Ok(())
}

#[tokio::test]
async fn shutdown_releases_server_sockets_and_cancels_caller() -> eyre::Result<()> {
	let cancel = CancellationToken::new();
	let any = SocketAddr::from(([127, 0, 0, 1], 0));
	let server = tokio::time::timeout(
		Duration::from_secs(5),
		tuic_server::run_with_cancel(config(any, any), cancel.clone()),
	)
	.await??;
	let quic = server.local_addr;
	let restful = server.restful_addr.ok_or_else(|| eyre::eyre!("missing RESTful address"))?;
	server.shutdown().await;
	assert!(cancel.is_cancelled());
	let _quic = std::net::UdpSocket::bind(quic)?;
	let _restful = std::net::TcpListener::bind(restful)?;
	Ok(())
}
