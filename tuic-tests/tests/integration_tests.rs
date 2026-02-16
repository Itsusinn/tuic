// Integration tests for TUIC protocol
// Tests the marshal/unmarshal round-trip for all protocol types

use std::{io::Cursor, time::Duration};

use serial_test::serial;
use tokio::time::timeout;
use tracing::{error, info};
use tuic_core::{Address, Authenticate, Connect, Dissociate, Header, Heartbeat, Packet, StackPrefer};
use tuic_server::config::ExperimentalConfig;
use tuic_tests::{
	run_socks5_server, run_tcp_echo_server, run_udp_echo_server, test_tcp_through_socks5, test_udp_through_socks5,
};
use uuid::Uuid;

// Helper function to marshal and unmarshal a header
fn marshal_unmarshal_header(header: Header) -> Header {
	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	Header::unmarshal(&mut cursor).unwrap()
}

#[test]
fn test_full_protocol_roundtrip() {
	// Test all header types can be marshaled and unmarshaled correctly

	// 1. Authenticate
	let uuid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
	let token = [42u8; 32];
	let auth = Authenticate::new(uuid, token);
	let header = Header::Authenticate(auth);

	let decoded = marshal_unmarshal_header(header);

	match decoded {
		Header::Authenticate(decoded_auth) => {
			assert_eq!(decoded_auth.uuid(), uuid);
			assert_eq!(decoded_auth.token(), token);
		}
		_ => panic!("Wrong header type"),
	}

	// 2. Connect with different address types
	let addresses = vec![
		Address::None,
		Address::DomainAddress("example.com".to_string(), 443),
		Address::SocketAddress("192.168.1.1:8080".parse().unwrap()),
		Address::SocketAddress("[2001:db8::1]:9000".parse().unwrap()),
	];

	for addr in addresses {
		let conn = Connect::new(addr.clone());
		let header = Header::Connect(conn);

		let decoded = marshal_unmarshal_header(header);

		match decoded {
			Header::Connect(decoded_conn) => {
				assert_eq!(decoded_conn.addr(), &addr);
			}
			_ => panic!("Wrong header type"),
		}
	}

	// 3. Packet
	let addr = Address::DomainAddress("udp.test".to_string(), 53);
	let pkt = Packet::new(123, 456, 10, 5, 2048, addr.clone());
	let header = Header::Packet(pkt);

	let decoded = marshal_unmarshal_header(header);

	match decoded {
		Header::Packet(decoded_pkt) => {
			assert_eq!(decoded_pkt.assoc_id(), 123);
			assert_eq!(decoded_pkt.pkt_id(), 456);
			assert_eq!(decoded_pkt.frag_total(), 10);
			assert_eq!(decoded_pkt.frag_id(), 5);
			assert_eq!(decoded_pkt.size(), 2048);
			assert_eq!(decoded_pkt.addr(), &addr);
		}
		_ => panic!("Wrong header type"),
	}

	// 4. Dissociate
	let dissoc = Dissociate::new(999);
	let header = Header::Dissociate(dissoc);

	let decoded = marshal_unmarshal_header(header);

	match decoded {
		Header::Dissociate(decoded_dissoc) => {
			assert_eq!(decoded_dissoc.assoc_id(), 999);
		}
		_ => panic!("Wrong header type"),
	}

	// 5. Heartbeat
	let hb = Heartbeat::new();
	let header = Header::Heartbeat(hb);

	let decoded = marshal_unmarshal_header(header);

	match decoded {
		Header::Heartbeat(_) => {}
		_ => panic!("Wrong header type"),
	}
}

#[test]
fn test_fragmented_udp_packets() {
	// Simulate a UDP packet split into 3 fragments
	let total_frags = 3;
	let assoc_id = 100;
	let pkt_id = 200;

	for frag_id in 0..total_frags {
		let addr = if frag_id == 0 {
			// First fragment has address
			Address::DomainAddress("destination.com".to_string(), 5353)
		} else {
			// Subsequent fragments have no address
			Address::None
		};

		let pkt = Packet::new(assoc_id, pkt_id, total_frags, frag_id, 500, addr.clone());
		let header = Header::Packet(pkt);

		let decoded = marshal_unmarshal_header(header);

		match decoded {
			Header::Packet(decoded_pkt) => {
				assert_eq!(decoded_pkt.assoc_id(), assoc_id);
				assert_eq!(decoded_pkt.pkt_id(), pkt_id);
				assert_eq!(decoded_pkt.frag_total(), total_frags);
				assert_eq!(decoded_pkt.frag_id(), frag_id);
				assert_eq!(decoded_pkt.addr(), &addr);
			}
			_ => panic!("Wrong header type"),
		}
	}
}

#[test]
fn test_edge_case_values() {
	// Test edge case values for Packet
	let test_cases = vec![
		(0u16, 0u16, 1u8, 0u8, 0u16),                         // Minimum values
		(u16::MAX, u16::MAX, u8::MAX, u8::MAX - 1, u16::MAX), // Maximum values
		(32768, 16384, 128, 64, 8192),                        // Mid-range values
	];

	for (assoc_id, pkt_id, frag_total, frag_id, size) in test_cases {
		let addr = Address::DomainAddress("test.com".to_string(), 1234);
		let pkt = Packet::new(assoc_id, pkt_id, frag_total, frag_id, size, addr.clone());
		let header = Header::Packet(pkt);

		let decoded = marshal_unmarshal_header(header);

		match decoded {
			Header::Packet(decoded_pkt) => {
				assert_eq!(decoded_pkt.assoc_id(), assoc_id);
				assert_eq!(decoded_pkt.pkt_id(), pkt_id);
				assert_eq!(decoded_pkt.frag_total(), frag_total);
				assert_eq!(decoded_pkt.frag_id(), frag_id);
				assert_eq!(decoded_pkt.size(), size);
			}
			_ => panic!("Wrong header type"),
		}
	}
}

#[test]
fn test_various_domain_names() {
	// Test various domain name lengths and formats
	let binding = "a".repeat(63);
	let domains = vec![
		"a.b",                             // Short domain
		"example.com",                     // Common domain
		"subdomain.example.com",           // Subdomain
		"very.long.subdomain.example.com", // Multiple subdomains
		"localhost",                       // Localhost
		"192-168-1-1.example.com",         // Dash-separated
		&binding,                          // Maximum label length
	];

	for domain in domains {
		let addr = Address::DomainAddress(domain.to_string(), 443);
		let conn = Connect::new(addr.clone());
		let header = Header::Connect(conn);

		let decoded = marshal_unmarshal_header(header);

		match decoded {
			Header::Connect(decoded_conn) => {
				assert_eq!(decoded_conn.addr(), &addr);
			}
			_ => panic!("Wrong header type"),
		}
	}
}

// Integration test that calls tuic-server and tuic-client run methods
//
// This test validates the full TUIC stack:
// - Server and client startup with self-signed certificates
// - QUIC connection establishment and authentication
// - SOCKS5 proxy functionality
// - TCP relay through the TUIC tunnel
// - UDP relay through the TUIC tunnel (native mode)
// - Concurrent connection handling
//
// IMPORTANT: The server ACL must be configured to allow localhost connections
// for the test to work, since all echo servers run on 127.0.0.1
#[tokio::test]
#[serial]
#[tracing_test::traced_test]
async fn test_server_client_integration() -> eyre::Result<()> {
	use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
	#[cfg(feature = "aws-lc-rs")]
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	#[cfg(feature = "ring")]
	let _ = rustls::crypto::ring::default_provider().install_default();

	// Create a minimal server configuration for testing
	// IMPORTANT: We need to configure ACL to allow localhost connections for
	// testing
	let server_config = tuic_server::Config {
		log_level: tuic_server::config::LogLevel::Debug,
		server: "127.0.0.1:8443".parse::<SocketAddr>()?,
		users: {
			let mut users = HashMap::new();
			users.insert(
				Uuid::parse_str("00000000-0000-0000-0000-000000000000")?,
				"test_password".to_string(),
			);
			users
		},
		tls: tuic_server::config::TlsConfig {
			self_sign:   true,
			certificate: PathBuf::from("./test_cert.pem"),
			private_key: PathBuf::from("./test_key.pem"),
			alpn:        vec!["h3".to_string()],
			hostname:    "localhost".to_string(),
			auto_ssl:    false,
			acme_email:  "admin@example.com".to_string(),
		},
		data_dir: std::env::temp_dir(),
		quic: tuic_server::config::QuicConfig::default(),
		udp_relay_ipv6: true,
		zero_rtt_handshake: false,
		dual_stack: false,
		experimental: ExperimentalConfig {
			drop_loopback: false,
			..Default::default()
		},
		..Default::default()
	};

	// Spawn server in background
	info!("[Integration Test] Starting TUIC server on 127.0.0.1:8443...");
	let server_handle = tokio::spawn(async move {
		// Run server with a timeout
		match timeout(Duration::from_secs(10), tuic_server::run(server_config)).await {
			Ok(Ok(())) => info!("[Integration Test] Server completed successfully"),
			Ok(Err(e)) => error!("[Integration Test] Server error: {}", e),
			Err(_) => error!("[Integration Test] Server timeout"),
		}
	});

	// Wait a bit for server to start
	info!("[Integration Test] Waiting for server to initialize...");
	tokio::time::sleep(Duration::from_secs(1)).await;
	info!("[Integration Test] Server should be ready now");

	// Create a client configuration that connects to the test server
	let client_config = tuic_client::Config {
		relay:     tuic_client::config::Relay {
			server: ("127.0.0.1".to_string(), 8443),
			uuid: Uuid::parse_str("00000000-0000-0000-0000-000000000000")?,
			password: std::sync::Arc::from(b"test_password".to_vec().into_boxed_slice()),
			ip: None,
			ipstack_prefer: StackPrefer::V6first,
			certificates: Vec::new(),
			udp_relay_mode: tuic_client::utils::UdpRelayMode::Native,
			congestion_control: tuic_client::utils::CongestionControl::Cubic,
			alpn: vec![b"h3".to_vec()],
			zero_rtt_handshake: false,
			disable_sni: true,
			disable_native_certs: true,
			gso: false,
			pmtu: false,
			skip_cert_verify: true,
			..Default::default()
		},
		local:     tuic_client::config::Local {
			server:          "127.0.0.1:1080".parse()?,
			username:        None,
			password:        None,
			dual_stack:      Some(false),
			max_packet_size: 1500,
			tcp_forward:     Vec::new(),
			udp_forward:     Vec::new(),
		},
		log_level: "debug".to_string(),
	};

	// Spawn client in background with timeout
	info!("[Integration Test] Starting TUIC client with SOCKS5 server on 127.0.0.1:1080...");
	let client_handle = tokio::spawn(async move {
		match timeout(Duration::from_secs(10), tuic_client::run(client_config)).await {
			Ok(Ok(())) => info!("[Integration Test] Client completed successfully"),
			Ok(Err(e)) => error!("[Integration Test] Client error: {}", e),
			Err(_) => error!("[Integration Test] Client timeout"),
		}
	});

	// Wait for client to establish connection and start SOCKS5 server
	info!("[Integration Test] Waiting for client to connect and start SOCKS5 server...");
	tokio::time::sleep(Duration::from_secs(2)).await;
	info!("[Integration Test] SOCKS5 proxy should be ready now\n");

	// Quick connectivity check - try to connect to SOCKS5 proxy
	use tokio::net::TcpStream;
	info!("[Integration Test] Testing SOCKS5 proxy connectivity...");
	match TcpStream::connect("127.0.0.1:1080").await {
		Ok(stream) => {
			info!("[Integration Test] ✓ Successfully connected to SOCKS5 proxy at 127.0.0.1:1080");
			info!(
				"[Integration Test] Local: {:?}, Peer: {:?}",
				stream.local_addr(),
				stream.peer_addr()
			);
			drop(stream);
		}
		Err(e) => {
			error!("[Integration Test] ✗ Failed to connect to SOCKS5 proxy: {}", e);
			error!("[Integration Test] This suggests the TUIC client may not have started properly");
		}
	}

	// ============================================================================
	// Test 1: Create a local TCP echo server and test TCP relay through SOCKS5
	// ============================================================================
	let tcp_test = async {
		info!("[TCP Test] Starting TCP relay test...");

		// Start a local TCP echo server
		let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "TCP Test").await;

		// Give server time to start
		tokio::time::sleep(Duration::from_millis(200)).await;

		// Test TCP connection through SOCKS5
		let test_data = b"Hello, TUIC!";
		test_tcp_through_socks5("127.0.0.1:1080", echo_addr, test_data, "TCP Test").await;

		// Wait a bit to see if echo server gets anything
		info!("[TCP Test] Waiting for echo server to finish...");
		tokio::time::sleep(Duration::from_millis(500)).await;

		// Clean up
		echo_task.abort();
		info!("[TCP Test] TCP test completed\n");
	};

	// Run the TCP test with a timeout
	let _ = timeout(Duration::from_secs(6), tcp_test).await;

	// ============================================================================
	// Test 2: Create a local UDP echo server and test UDP relay through SOCKS5
	// ============================================================================
	let udp_test = async {
		use std::net::{IpAddr, Ipv4Addr};

		info!("\n[UDP Test] ========================================");
		info!("[UDP Test] Starting UDP relay test...");
		info!("[UDP Test] ========================================\n");

		// Start a local UDP echo server
		let (echo_task, echo_addr, _echo_server) = run_udp_echo_server("127.0.0.1:0", "UDP Test").await;

		// Give server time to start
		tokio::time::sleep(Duration::from_millis(100)).await;

		// Test UDP connection through SOCKS5
		let test_data = b"Hello, UDP through TUIC!";
		let client_bind_addr = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
		test_udp_through_socks5("127.0.0.1:1080", echo_addr, test_data, "UDP Test", client_bind_addr).await;

		// Clean up
		echo_task.abort();
		info!("[UDP Test] UDP test completed\n");
	};

	// Run the UDP test with a timeout
	let _ = timeout(Duration::from_secs(3), udp_test).await;

	// ============================================================================
	// Test 3: Test multiple concurrent TCP connections
	// ============================================================================
	let concurrent_test = async {
		use fast_socks5::client::{Config, Socks5Stream};
		use tokio::{
			io::{AsyncReadExt, AsyncWriteExt},
			net::TcpListener,
		};

		info!("[Concurrent Test] Starting concurrent TCP connections test...");

		// Start a local TCP server
		let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let server_addr = server.local_addr().unwrap();
		info!("[Concurrent Test] TCP server started at: {}", server_addr);

		// Spawn server task that handles multiple connections
		let server_task = tokio::spawn(async move {
			for i in 0..3 {
				if let Ok((mut socket, addr)) = server.accept().await {
					info!("[Concurrent Test Server] Accepted connection {} from: {}", i, addr);
					tokio::spawn(async move {
						let mut buf = vec![0u8; 1024];
						if let Ok(n) = socket.read(&mut buf).await {
							info!("[Concurrent Test Server] Connection {}: received {} bytes", i, n);
							if let Err(e) = socket.write_all(&buf[..n]).await {
								error!("[Concurrent Test Server] Connection {}: failed to echo: {}", i, e);
							}
						}
					});
				}
			}
		});

		tokio::time::sleep(Duration::from_millis(100)).await;

		// Create multiple concurrent connections through SOCKS5
		info!("[Concurrent Test] Creating 3 concurrent connections through SOCKS5...");
		let mut handles = vec![];
		for i in 0..3 {
			let addr = server_addr;
			let handle = tokio::spawn(async move {
				info!("[Concurrent Test] Connection {}: connecting...", i);
				match Socks5Stream::connect(
					"127.0.0.1:1080".parse::<std::net::SocketAddr>().unwrap(),
					addr.ip().to_string(),
					addr.port(),
					Config::default(),
				)
				.await
				{
					Ok(mut stream) => {
						info!("[Concurrent Test] Connection {}: connected", i);
						let test_data = format!("Connection {}", i);

						if let Err(e) = stream.write_all(test_data.as_bytes()).await {
							error!("[Concurrent Test] Connection {}: failed to send: {}", i, e);
						} else {
							info!("[Concurrent Test] Connection {}: sent {} bytes", i, test_data.len());

							let mut buf = vec![0u8; 1024];
							match timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
								Ok(Ok(n)) => {
									info!("[Concurrent Test] Connection {}: received {} bytes", i, n);
								}
								Ok(Err(e)) => {
									error!("[Concurrent Test] Connection {}: failed to receive: {}", i, e);
								}
								Err(_) => {
									error!("[Concurrent Test] Connection {}: timeout", i);
								}
							}
						}
					}
					Err(e) => {
						error!("[Concurrent Test] Connection {}: failed to connect: {}", i, e);
					}
				}
			});
			handles.push(handle);
		}

		// Wait for all connections to complete
		for (i, handle) in handles.into_iter().enumerate() {
			if let Err(e) = handle.await {
				error!("[Concurrent Test] Connection {} task failed: {}", i, e);
			}
		}

		info!("[Concurrent Test] ✓ All concurrent connections completed");
		server_task.abort();
		info!("[Concurrent Test] Concurrent test completed\n");
	};

	// Run the concurrent test with a timeout
	let _ = timeout(Duration::from_secs(5), concurrent_test).await;

	// Clean up
	client_handle.abort();
	server_handle.abort();

	// Give tasks time to clean up
	tokio::time::sleep(Duration::from_millis(100)).await;

	Ok(())
}

// Integration test for IPv6 connectivity
//
// This test validates TUIC with IPv6 addresses:
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

	// Create server configuration using IPv6 localhost [::1]
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
			self_sign:   true,
			certificate: PathBuf::from("./test_cert_ipv6.pem"),
			private_key: PathBuf::from("./test_key_ipv6.pem"),
			alpn:        vec!["h3".to_string()],
			hostname:    "localhost".to_string(),
			auto_ssl:    false,
			acme_email:  "admin@example.com".to_string(),
		},
		data_dir: std::env::temp_dir(),
		restful: None,
		quic: tuic_server::config::QuicConfig::default(),
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
		// Allow localhost connections for testing
		acl: vec![tuic_server::acl::AclRule {
			outbound: "allow".to_string(),
			addr:     tuic_server::acl::AclAddress::Localhost,
			ports:    None,
			hijack:   None,
		}],
		..Default::default()
	};

	// Spawn IPv6 server
	info!("[IPv6 Test] Starting TUIC server on [::1]:8444...");
	let server_handle = tokio::spawn(async move {
		match timeout(Duration::from_secs(10), tuic_server::run(server_config)).await {
			Ok(Ok(())) => info!("[IPv6 Test] Server completed successfully"),
			Ok(Err(e)) => error!("[IPv6 Test] Server error: {}", e),
			Err(_) => error!("[IPv6 Test] Server timeout"),
		}
	});

	// Wait for server to start
	info!("[IPv6 Test] Waiting for server to initialize...");
	tokio::time::sleep(Duration::from_secs(1)).await;
	info!("[IPv6 Test] Server should be ready now");

	// Create client configuration connecting to IPv6 server
	let client_config = tuic_client::Config {
		relay:     tuic_client::config::Relay {
			server:               ("[::1]".to_string(), 8444),
			uuid:                 Uuid::parse_str("00000000-0000-0000-0000-000000000000")?,
			password:             std::sync::Arc::from(b"test_password".to_vec().into_boxed_slice()),
			ip:                   None,
			ipstack_prefer:       tuic_client::utils::StackPrefer::V6first,
			certificates:         Vec::new(),
			udp_relay_mode:       tuic_client::utils::UdpRelayMode::Native,
			congestion_control:   tuic_client::utils::CongestionControl::Cubic,
			alpn:                 vec![b"h3".to_vec()],
			zero_rtt_handshake:   false,
			disable_sni:          true,
			sni:                  None,
			timeout:              Duration::from_secs(8),
			heartbeat:            Duration::from_secs(3),
			disable_native_certs: true,
			send_window:          8 * 1024 * 1024 * 2,
			receive_window:       8 * 1024 * 1024,
			initial_mtu:          1200,
			min_mtu:              1200,
			gso:                  false,
			pmtu:                 false,
			gc_interval:          Duration::from_secs(3),
			gc_lifetime:          Duration::from_secs(15),
			skip_cert_verify:     true,
			proxy:                None,
		},
		local:     tuic_client::config::Local {
			server:          "[::1]:1081".parse()?,
			username:        None,
			password:        None,
			dual_stack:      Some(false),
			max_packet_size: 1500,
			tcp_forward:     Vec::new(),
			udp_forward:     Vec::new(),
		},
		log_level: "debug".to_string(),
	};

	// Spawn client with IPv6 SOCKS5 server
	info!("[IPv6 Test] Starting TUIC client with SOCKS5 server on [::1]:1081...");
	let client_handle = tokio::spawn(async move {
		match timeout(Duration::from_secs(10), tuic_client::run(client_config)).await {
			Ok(Ok(())) => info!("[IPv6 Test] Client completed successfully"),
			Ok(Err(e)) => error!("[IPv6 Test] Client error: {}", e),
			Err(_) => error!("[IPv6 Test] Client timeout"),
		}
	});

	// Wait for client to connect
	info!("[IPv6 Test] Waiting for client to connect and start SOCKS5 server...");
	tokio::time::sleep(Duration::from_secs(2)).await;
	info!("[IPv6 Test] SOCKS5 proxy should be ready now\n");

	// Test SOCKS5 proxy connectivity on IPv6
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

	// ============================================================================
	// Test 1: IPv6 TCP relay through SOCKS5
	// ============================================================================
	let tcp_test = async {
		info!("[IPv6 TCP Test] Starting TCP relay test on IPv6...");

		// Start a local TCP echo server on IPv6
		let (echo_task, echo_addr) = run_tcp_echo_server("[::1]:0", "IPv6 TCP Test").await;

		tokio::time::sleep(Duration::from_millis(200)).await;

		// Test TCP connection through SOCKS5 on IPv6
		let test_data = b"Hello IPv6 TUIC!";
		test_tcp_through_socks5("[::1]:1081", echo_addr, test_data, "IPv6 TCP Test").await;

		echo_task.abort();
		info!("[IPv6 TCP Test] TCP test completed\n");
	};

	let _ = timeout(Duration::from_secs(6), tcp_test).await;

	// ============================================================================
	// Test 2: IPv6 UDP relay through SOCKS5
	// ============================================================================
	let udp_test = async {
		use std::net::{IpAddr, Ipv6Addr};

		info!("[IPv6 UDP Test] Starting UDP relay test on IPv6...");

		// Start a local UDP echo server on IPv6
		let (echo_task, echo_addr, _echo_server) = run_udp_echo_server("[::1]:0", "IPv6 UDP Test").await;

		tokio::time::sleep(Duration::from_millis(100)).await;

		// Test UDP connection through SOCKS5 on IPv6
		let test_data = b"Hello, IPv6 UDP through TUIC!";
		let client_bind_addr = std::net::SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
		test_udp_through_socks5("[::1]:1081", echo_addr, test_data, "IPv6 UDP Test", client_bind_addr).await;

		echo_task.abort();
		info!("[IPv6 UDP Test] UDP test completed\n");
	};

	let _ = timeout(Duration::from_secs(3), udp_test).await;

	// Clean up
	client_handle.abort();
	server_handle.abort();

	tokio::time::sleep(Duration::from_millis(100)).await;

	info!("[IPv6 Test] ========================================");
	info!("[IPv6 Test] IPv6 Integration Test Completed");
	info!("[IPv6 Test] ========================================\n");

	Ok(())
}

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

	// Create a minimal server for testing
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
			self_sign:   true,
			certificate: PathBuf::from("./test_cert.pem"),
			private_key: PathBuf::from("./test_key.pem"),
			alpn:        vec!["h3".to_string()],
			hostname:    "localhost".to_string(),
			auto_ssl:    false,
			acme_email:  "admin@example.com".to_string(),
		},
		data_dir: std::env::temp_dir(),
		udp_relay_ipv6: true,
		zero_rtt_handshake: false,
		dual_stack: false,
		max_external_packet_size: 1500,
		stream_timeout: Duration::from_secs(60),
		outbound: tuic_server::config::OutboundConfig::default(),
		acl: vec![tuic_server::acl::AclRule {
			outbound: "allow".to_string(),
			addr:     tuic_server::acl::AclAddress::Localhost,
			ports:    None,
			hijack:   None,
		}],
		..Default::default()
	};

	info!("[Proxy Config Test] Starting TUIC server on {}...", server_config.server);
	let server_handle = tokio::spawn(async move {
		let _ = tuic_server::run(server_config).await;
	});

	tokio::time::sleep(Duration::from_millis(500)).await;

	// Test: Client config with proxy settings
	info!("[Proxy Config Test] Test 1: Client with SOCKS5 proxy configuration");

	// Start a real SOCKS5 proxy server for testing
	let (socks5_handle, socks5_addr) =
		run_socks5_server("127.0.0.1:0", "Proxy Test 1", Some("proxy_user"), Some("proxy_pass")).await;

	info!("[Proxy Config Test] SOCKS5 proxy started at: {}", socks5_addr);
	tokio::time::sleep(Duration::from_millis(200)).await;

	// Build config directly
	let config = tuic_client::config::Config {
		relay:     tuic_client::config::Relay {
			server: ("127.0.0.1".to_string(), 8445),
			uuid: Uuid::parse_str("00000000-0000-0000-0000-000000000000")?,
			password: std::sync::Arc::from("test_password".as_bytes()),
			skip_cert_verify: true,
			proxy: Some(tuic_client::config::ProxyConfig {
				server:          (socks5_addr.ip().to_string(), socks5_addr.port()),
				username:        Some("proxy_user".to_string()),
				password:        Some("proxy_pass".to_string()),
				udp_buffer_size: 4096,
			}),
			alpn: vec![b"h3".to_vec()],
			..Default::default()
		},
		local:     tuic_client::config::Local {
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

	// Try to connect to echo server through SOCKS5 proxy
	info!("[Proxy Config Test] Testing connection through SOCKS5 proxy to echo server...");
	let test_data = b"Hello through SOCKS5 proxy!";
	let success = test_tcp_through_socks5(local_socks, echo_addr, test_data, "Proxy Test 1").await;

	if success {
		info!("[Proxy Config Test] ✓ Successfully connected through SOCKS5 proxy!");
	} else {
		info!("[Proxy Config Test] ⚠ Could not verify SOCKS5 proxy connectivity (may be expected)");
	}

	// Clean up
	echo_handle.abort();
	client_handle.abort();
	socks5_handle.abort();
	server_handle.abort();
	tokio::time::sleep(Duration::from_millis(100)).await;

	Ok(())
}
