//! IPv6 end-to-end integration test.
//!
//! In its own test binary (separate process) because it runs
//! `tuic_client::run`, which sets process-global connection/SOCKS state that
//! cannot be re-set by a second client in the same process.

#![allow(unused_imports)]

use std::{
	net::{IpAddr, Ipv4Addr, Ipv6Addr},
	time::Duration,
};

use serial_test::serial;
use tokio::time::timeout;
use tracing::{error, info};
use tuic_server::config::ExperimentalConfig;
use tuic_tests::{
	run_socks5_server, run_tcp_echo_server, run_udp_echo_server, test_tcp_through_socks5, test_udp_through_socks5,
};
use uuid::Uuid;

// - Server listening on [::1]:8444 (IPv6 localhost)
// - Client connecting to [::1]:8444
// - SOCKS5 proxy on [::1]:1081
// - TCP relay through IPv6
// - UDP relay through IPv6 (native mode)
//
// This addresses the error that occurs when using IPv6 addresses like
// "[::1]:443"
#[tokio::test]
#[serial]
#[tracing_test::traced_test]
async fn test_ipv6_server_client_integration() -> eyre::Result<()> {
	use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
	#[cfg(feature = "aws-lc-rs")]
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	#[cfg(feature = "ring")]
	let _ = rustls::crypto::ring::default_provider().install_default();

	info!("\n[IPv6 Test] ========================================");
	info!("[IPv6 Test] Starting IPv6 Integration Test");
	info!("[IPv6 Test] ========================================\n");

	// Skip (rather than silently pass) when the environment has no IPv6
	// loopback -- common on constrained CI runners. If [::1] is available we
	// require the relay to actually work below.
	if tokio::net::TcpListener::bind("[::1]:0").await.is_err() {
		info!("[IPv6 Test] no IPv6 loopback available; skipping");
		return Ok(());
	}

	let server_config = tuic_server::Config {
		log_level: tuic_server::config::LogLevel::Debug,
		server: "[::1]:8444".parse::<SocketAddr>()?,
		users: {
			let mut users = HashMap::new();
			users.insert(
				Uuid::parse_str("00000000-0000-0000-0000-000000000000")?,
				"test_password".to_string(),
			);
			users
		},
		tls: tuic_server::config::TlsConfig {
			self_sign: true,
			certificate: PathBuf::from("./test_cert_ipv6.pem"),
			private_key: PathBuf::from("./test_key_ipv6.pem"),
			alpn: vec!["h3".to_string()],
			hostname: "localhost".to_string(),
			auto_ssl: false,
			acme_email: "admin@example.com".to_string(),
			acme_staging: false,
		},
		data_dir: std::env::temp_dir(),
		backend: tuic_server::config::BackendConfig::default(),
		udp_relay_ipv6: true,
		zero_rtt_handshake: false,
		dual_stack: false,
		auth_timeout: Duration::from_secs(3),
		task_negotiation_timeout: Duration::from_secs(3),
		gc_interval: Duration::from_secs(10),
		gc_lifetime: Duration::from_secs(30),
		max_external_packet_size: 1500,
		stream_timeout: Duration::from_secs(60),
		outbound: tuic_server::config::OutboundConfig::default(),
		// The echo target is `[::1]` (loopback), so the loopback guard must be
		// off or the relay is rejected before it reaches the outbound. The IPv4
		// test sets this too; the IPv6 test previously relied on the default
		// (guard on) and silently passed only because it made no assertions.
		experimental: ExperimentalConfig {
			drop_loopback: false,
			..Default::default()
		},
		// Allow localhost connections for testing
		acl: vec![tuic_server::legacy::AclRule {
			outbound: "allow".to_string(),
			addr: tuic_server::legacy::AclAddress::Localhost,
			ports: None,
			hijack: None,
		}],
		..Default::default()
	};

	info!("[IPv6 Test] Starting TUIC server on [::1]:8444...");
	let server_handle = tokio::spawn(async move {
		// Must outlast the whole test body; a 10s cap could kill it mid-test.
		match timeout(Duration::from_secs(30), tuic_server::run(server_config)).await {
			Ok(Ok(())) => info!("[IPv6 Test] Server completed successfully"),
			Ok(Err(e)) => error!("[IPv6 Test] Server error: {}", e),
			Err(_) => info!("[IPv6 Test] Server timed out (expected at test end)"),
		}
	});

	info!("[IPv6 Test] Waiting for server to initialize...");
	tokio::time::sleep(Duration::from_secs(1)).await;
	info!("[IPv6 Test] Server should be ready now");

	let client_config = tuic_client::Config {
		relay: tuic_client::config::Relay {
			server: ("[::1]".to_string(), 8444),
			uuid: Uuid::parse_str("00000000-0000-0000-0000-000000000000")?,
			password: std::sync::Arc::from(b"test_password".to_vec().into_boxed_slice()),
			ip: None,
			ipstack_prefer: tuic_client::utils::StackPrefer::V6first,
			certificates: Vec::new(),
			udp_relay_mode: tuic_client::utils::UdpRelayMode::Native,
			congestion_control: tuic_client::utils::CongestionControl::Cubic,
			alpn: vec![b"h3".to_vec()],
			zero_rtt_handshake: false,
			disable_sni: true,
			sni: None,
			timeout: Duration::from_secs(8),
			heartbeat: Duration::from_secs(3),
			disable_native_certs: true,
			send_window: 8 * 1024 * 1024 * 2,
			receive_window: 8 * 1024 * 1024,
			initial_mtu: 1200,
			min_mtu: 1200,
			gso: false,
			pmtu: false,
			gc_interval: Duration::from_secs(3),
			gc_lifetime: Duration::from_secs(15),
			skip_cert_verify: true,
			proxy: None,
			reconnect: true,
			reconnect_initial_backoff: Duration::from_millis(500),
			reconnect_max_backoff: Duration::from_secs(30),
		},
		local: tuic_client::config::Local {
			server: "[::1]:1081".parse()?,
			username: None,
			password: None,
			dual_stack: Some(false),
			max_packet_size: 1500,
			tcp_forward: Vec::new(),
			udp_forward: Vec::new(),
		},
		log_level: "debug".to_string(),
	};

	info!("[IPv6 Test] Starting TUIC client with SOCKS5 server on [::1]:1081...");
	let client_handle = tokio::spawn(async move {
		match timeout(Duration::from_secs(10), tuic_client::run(client_config)).await {
			Ok(Ok(())) => info!("[IPv6 Test] Client completed successfully"),
			Ok(Err(e)) => error!("[IPv6 Test] Client error: {}", e),
			Err(_) => error!("[IPv6 Test] Client timeout"),
		}
	});

	info!("[IPv6 Test] Waiting for client to connect and start SOCKS5 server...");
	tokio::time::sleep(Duration::from_secs(2)).await;
	info!("[IPv6 Test] SOCKS5 proxy should be ready now\n");

	use tokio::net::TcpStream;
	info!("[IPv6 Test] Testing SOCKS5 proxy connectivity on IPv6...");
	match TcpStream::connect("[::1]:1081").await {
		Ok(stream) => {
			info!("[IPv6 Test] ✓ Successfully connected to SOCKS5 proxy at [::1]:1081");
			info!("[IPv6 Test] Local: {:?}, Peer: {:?}", stream.local_addr(), stream.peer_addr());
			drop(stream);
		}
		Err(e) => {
			error!("[IPv6 Test] ✗ Failed to connect to SOCKS5 proxy: {}", e);
			error!("[IPv6 Test] This suggests the TUIC client may not have started properly on IPv6");
		}
	}

	let tcp_test = async {
		info!("[IPv6 TCP Test] Starting TCP relay test on IPv6...");

		let (echo_task, echo_addr) = run_tcp_echo_server("[::1]:0", "IPv6 TCP Test").await;

		tokio::time::sleep(Duration::from_millis(200)).await;

		let test_data = b"Hello IPv6 TUIC!";
		let ok = test_tcp_through_socks5("[::1]:1081", echo_addr, test_data, "IPv6 TCP Test").await;

		echo_task.abort();
		info!("[IPv6 TCP Test] TCP test completed\n");
		ok
	};

	let tcp_ok = timeout(Duration::from_secs(6), tcp_test)
		.await
		.expect("IPv6 TCP relay test timed out");
	assert!(tcp_ok, "IPv6 TCP relay through SOCKS5/TUIC failed");

	let udp_test = async {
		use std::net::{IpAddr, Ipv6Addr};

		info!("[IPv6 UDP Test] Starting UDP relay test on IPv6...");

		let (echo_task, echo_addr, _echo_server) = run_udp_echo_server("[::1]:0", "IPv6 UDP Test").await;

		tokio::time::sleep(Duration::from_millis(100)).await;

		let test_data = b"Hello, IPv6 UDP through TUIC!";
		let client_bind_addr = std::net::SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
		let ok = test_udp_through_socks5("[::1]:1081", echo_addr, test_data, "IPv6 UDP Test", client_bind_addr).await;

		echo_task.abort();
		info!("[IPv6 UDP Test] UDP test completed\n");
		ok
	};

	let udp_ok = timeout(Duration::from_secs(3), udp_test)
		.await
		.expect("IPv6 UDP relay test timed out");
	assert!(udp_ok, "IPv6 UDP relay through SOCKS5/TUIC failed");

	client_handle.abort();
	server_handle.abort();

	tokio::time::sleep(Duration::from_millis(100)).await;

	info!("[IPv6 Test] ========================================");
	info!("[IPv6 Test] IPv6 Integration Test Completed");
	info!("[IPv6 Test] ========================================\n");

	Ok(())
}
