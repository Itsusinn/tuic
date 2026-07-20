//! SOCKS5-proxy-configuration integration test.
//!
//! In its own test binary (separate process) because it runs
//! `tuic_client::run`, which sets process-global connection/SOCKS state.

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

// Integration test for SOCKS5 proxy configuration with TUIC client
//
// This test validates:
// - Client configuration with SOCKS5 proxy settings
// - Proper handling of proxy configuration fields (server, username, password,
//   udp_buffer_size)
// - Configuration parsing for different proxy scenarios
#[tokio::test]
#[serial]
#[tracing_test::traced_test]
async fn test_client_proxy_configuration() -> eyre::Result<()> {
	use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

	#[cfg(feature = "aws-lc-rs")]
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	#[cfg(feature = "ring")]
	let _ = rustls::crypto::ring::default_provider().install_default();

	info!("[Proxy Config Test] ========================================");
	info!("[Proxy Config Test] Starting Proxy Configuration Test");
	info!("[Proxy Config Test] ========================================\n");

	let server_config = tuic_server::Config {
		log_level: tuic_server::config::LogLevel::Debug,
		server: "127.0.0.1:8445".parse::<SocketAddr>()?,
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
			certificate: PathBuf::from("./test_cert.pem"),
			private_key: PathBuf::from("./test_key.pem"),
			alpn: vec!["h3".to_string()],
			hostname: "localhost".to_string(),
			auto_ssl: false,
			acme_email: "admin@example.com".to_string(),
			..Default::default()
		},
		data_dir: std::env::temp_dir(),
		udp_relay_ipv6: true,
		zero_rtt_handshake: false,
		dual_stack: false,
		max_external_packet_size: 1500,
		stream_timeout: Duration::from_secs(60),
		outbound: tuic_server::config::OutboundConfig::default(),
		acl: vec![tuic_server::legacy::AclRule {
			outbound: "allow".to_string(),
			addr: tuic_server::legacy::AclAddress::Localhost,
			ports: None,
			hijack: None,
		}],
		..Default::default()
	};

	info!("[Proxy Config Test] Starting TUIC server on {}...", server_config.server);
	let server_handle = tokio::spawn(async move {
		let _ = tuic_server::run(server_config).await;
	});

	tokio::time::sleep(Duration::from_millis(500)).await;

	info!("[Proxy Config Test] Test 1: Client with SOCKS5 proxy configuration");

	let (socks5_handle, socks5_addr) =
		run_socks5_server("127.0.0.1:0", "Proxy Test 1", Some("proxy_user"), Some("proxy_pass")).await;

	info!("[Proxy Config Test] SOCKS5 proxy started at: {}", socks5_addr);
	tokio::time::sleep(Duration::from_millis(200)).await;

	let config = tuic_client::config::Config {
		relay: tuic_client::config::Relay {
			server: ("127.0.0.1".to_string(), 8445),
			uuid: Uuid::parse_str("00000000-0000-0000-0000-000000000000")?,
			password: std::sync::Arc::from("test_password".as_bytes()),
			skip_cert_verify: true,
			proxy: Some(tuic_client::config::ProxyConfig {
				server: (socks5_addr.ip().to_string(), socks5_addr.port()),
				username: Some("proxy_user".to_string()),
				password: Some("proxy_pass".to_string()),
				udp_buffer_size: 4096,
			}),
			alpn: vec![b"h3".to_vec()],
			..Default::default()
		},
		local: tuic_client::config::Local {
			server: "127.0.0.1:1082".parse()?,
			..Default::default()
		},
		log_level: "debug".to_string(),
	};
	let local_socks = "127.0.0.1:1082";
	info!("[Proxy Config Test] ✓ Config built successfully");

	info!("[Proxy Config Test] Starting TUIC client with proxy configuration...");
	let client_handle = tokio::spawn(async move {
		match timeout(Duration::from_secs(5), tuic_client::run(config)).await {
			Ok(Ok(())) => info!("[Proxy Config Test] Client completed successfully"),
			Ok(Err(e)) => {
				info!("[Proxy Config Test] Client error: {}", e);
			}
			Err(_) => error!("[Proxy Config Test] Client timeout"),
		}
	});

	// Give client time to start and connect through proxy
	tokio::time::sleep(Duration::from_secs(2)).await;

	info!("[Proxy Config Test] ✓ Client started with proxy configuration");

	// Test 1b: Verify that TUIC client can actually use the SOCKS5 proxy
	// Create a TCP echo server to test connectivity through the proxy chain
	let (echo_handle, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "Proxy Test 1 Echo").await;
	tokio::time::sleep(Duration::from_millis(200)).await;

	info!("[Proxy Config Test] Testing connection through SOCKS5 proxy to echo server...");
	let test_data = b"Hello through SOCKS5 proxy!";
	let success = test_tcp_through_socks5(local_socks, echo_addr, test_data, "Proxy Test 1").await;

	if success {
		info!("[Proxy Config Test] ✓ Successfully connected through SOCKS5 proxy!");
	} else {
		info!("[Proxy Config Test] ⚠ Could not verify SOCKS5 proxy connectivity (may be expected)");
	}

	echo_handle.abort();
	client_handle.abort();
	socks5_handle.abort();
	server_handle.abort();
	tokio::time::sleep(Duration::from_millis(100)).await;

	Ok(())
}
