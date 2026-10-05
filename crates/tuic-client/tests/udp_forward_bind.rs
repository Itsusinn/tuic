//! Startup behaviour of `[[local.udp_forward]]`.
//!
//! A listen port that is already taken must abort startup with an error that
//! names the forwarder. It must not panic inside the run task, and it must not
//! leave the client running without the configured forwarder. Conversely, a
//! free port must stay bound for the whole lifetime of the client.

use std::time::Duration;

use tuic_client::{Config, config::UdpForward};

/// Address of a loopback UDP port that was free a moment ago.
///
/// The port is read back from a `:0` bind and the probe socket is released
/// immediately; this mirrors the existing tunnel tests and is only used to give
/// the client a concrete (non-zero) port to bind.
fn free_udp_addr() -> std::net::SocketAddr {
	let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback UDP socket");
	let addr = probe.local_addr().expect("read the bound address");
	drop(probe);
	addr
}

/// A config whose relay connection stays lazy, so startup only touches the
/// local inbounds.
fn config_with_udp_forward(listen: std::net::SocketAddr) -> Config {
	let mut cfg = Config::default();
	cfg.local.server = "127.0.0.1:0".parse().expect("parse the SOCKS5 listen address");
	cfg.local.udp_forward.push(UdpForward {
		listen,
		remote: ("127.0.0.1".to_string(), 9),
		timeout: Duration::from_secs(60),
	});
	cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn taken_udp_forward_port_aborts_startup() {
	let occupied = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback UDP socket");
	let listen = occupied.local_addr().expect("read the bound address");

	let result = tokio::time::timeout(Duration::from_secs(10), tuic_client::run(config_with_udp_forward(listen)))
		.await
		.expect("startup must not hang while the UDP forward port is taken");

	let err = result.err().expect("startup must fail while the UDP forward port is taken");
	let message = err.to_string();
	assert!(
		message.contains("UDP forward listener"),
		"the failure must name the UDP forward listener, got: {message}"
	);
	assert!(
		message.contains(&listen.to_string()),
		"the failure must name the conflicting address {listen}, got: {message}"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_forward_port_stays_bound_while_the_client_runs() {
	let listen = free_udp_addr();

	let client = tokio::time::timeout(Duration::from_secs(10), tuic_client::run(config_with_udp_forward(listen)))
		.await
		.expect("startup must not hang")
		.expect("the client must start when the UDP forward port is free");

	// The forwarder socket is bound during startup and held by the inbound, so
	// nothing else can claim the port while the client runs.
	let taken = std::net::UdpSocket::bind(listen);
	assert!(
		taken.is_err(),
		"the UDP forward port {listen} must stay bound while the client runs"
	);

	client.shutdown().await;
}
