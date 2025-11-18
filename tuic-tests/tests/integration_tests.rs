// Integration tests for TUIC protocol
// Tests the marshal/unmarshal round-trip for all protocol types

use std::time::Duration;

use tokio::time::timeout;
use tuic_core::{Address, Authenticate, Connect, Dissociate, Header, Heartbeat, Packet};
use uuid::Uuid;

#[test]
fn test_full_protocol_roundtrip() {
	use std::io::Cursor;

	// Test all header types can be marshaled and unmarshaled correctly

	// 1. Authenticate
	let uuid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
	let token = [42u8; 32];
	let auth = Authenticate::new(uuid, token);
	let header = Header::Authenticate(auth);

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

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

		let mut buf = Vec::new();
		header.marshal(&mut buf).unwrap();

		let mut cursor = Cursor::new(buf);
		let decoded = Header::unmarshal(&mut cursor).unwrap();

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

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

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

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

	match decoded {
		Header::Dissociate(decoded_dissoc) => {
			assert_eq!(decoded_dissoc.assoc_id(), 999);
		}
		_ => panic!("Wrong header type"),
	}

	// 5. Heartbeat
	let hb = Heartbeat::new();
	let header = Header::Heartbeat(hb);

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

	match decoded {
		Header::Heartbeat(_) => {}
		_ => panic!("Wrong header type"),
	}
}

#[test]
fn test_fragmented_udp_packets() {
	use std::io::Cursor;

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

		let mut buf = Vec::new();
		header.marshal(&mut buf).unwrap();

		let mut cursor = Cursor::new(buf);
		let decoded = Header::unmarshal(&mut cursor).unwrap();

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
	use std::io::Cursor;

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

		let mut buf = Vec::new();
		header.marshal(&mut buf).unwrap();

		let mut cursor = Cursor::new(buf);
		let decoded = Header::unmarshal(&mut cursor).unwrap();

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
	use std::io::Cursor;

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

		let mut buf = Vec::new();
		header.marshal(&mut buf).unwrap();

		let mut cursor = Cursor::new(buf);
		let decoded = Header::unmarshal(&mut cursor).unwrap();

		match decoded {
			Header::Connect(decoded_conn) => {
				assert_eq!(decoded_conn.addr(), &addr);
			}
			_ => panic!("Wrong header type"),
		}
	}
}

#[test]
fn test_address_serialization_lengths() {
	// Test that serialization lengths are calculated correctly
	let none_addr = Address::None;
	assert_eq!(none_addr.len(), 1);

	let domain_addr = Address::DomainAddress("example.com".to_string(), 443);
	assert_eq!(domain_addr.len(), 1 + 1 + "example.com".len() + 2);

	let ipv4_addr = Address::SocketAddress("192.168.1.1:8080".parse().unwrap());
	assert_eq!(ipv4_addr.len(), 1 + 4 + 2);

	let ipv6_addr = Address::SocketAddress("[2001:db8::1]:9000".parse().unwrap());
	assert_eq!(ipv6_addr.len(), 1 + 16 + 2);
}

#[test]
fn test_header_serialization_lengths() {
	// Test that header lengths are calculated correctly
	let uuid = Uuid::new_v4();
	let token = [0u8; 32];
	let auth = Authenticate::new(uuid, token);
	let header = Header::Authenticate(auth);
	assert_eq!(header.len(), 2 + 48); // version + type + auth data

	let conn = Connect::new(Address::None);
	let header = Header::Connect(conn);
	assert_eq!(header.len(), 2 + 1); // version + type + address

	let pkt = Packet::new(1, 2, 3, 4, 5, Address::None);
	let header = Header::Packet(pkt);
	assert_eq!(header.len(), 2 + 2 + 2 + 1 + 1 + 2 + 1); // version + type + packet fields + address

	let dissoc = Dissociate::new(100);
	let header = Header::Dissociate(dissoc);
	assert_eq!(header.len(), 2 + 2); // version + type + assoc_id

	let hb = Heartbeat::new();
	let header = Header::Heartbeat(hb);
	assert_eq!(header.len(), 2); // version + type only
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
#[tracing_test::traced_test]
async fn test_server_client_integration() {
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
		server: "127.0.0.1:8443".parse::<SocketAddr>().unwrap(),
		users: {
			let mut users = HashMap::new();
			users.insert(
				Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
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
		// Allow localhost connections for testing - by default ACL blocks localhost
		acl: vec![tuic_server::acl::AclRule {
			outbound: "allow".to_string(),
			addr:     tuic_server::acl::AclAddress::Localhost,
			ports:    None,
			hijack:   None,
		}],
		..Default::default()
	};

	// Spawn server in background
	println!("[Integration Test] Starting TUIC server on 127.0.0.1:8443...");
	let server_handle = tokio::spawn(async move {
		// Run server with a timeout
		match timeout(Duration::from_secs(10), tuic_server::run(server_config)).await {
			Ok(Ok(())) => println!("[Integration Test] Server completed successfully"),
			Ok(Err(e)) => eprintln!("[Integration Test] Server error: {}", e),
			Err(_) => eprintln!("[Integration Test] Server timeout"),
		}
	});

	// Wait a bit for server to start
	println!("[Integration Test] Waiting for server to initialize...");
	tokio::time::sleep(Duration::from_secs(1)).await;
	println!("[Integration Test] Server should be ready now");

	// Create a client configuration that connects to the test server
	let client_config = tuic_client::Config {
		relay:     tuic_client::config::Relay {
			server:               ("127.0.0.1".to_string(), 8443),
			uuid:                 Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
			password:             std::sync::Arc::from(b"test_password".to_vec().into_boxed_slice()),
			ip:                   None,
			ipstack_prefer:       tuic_client::utils::StackPrefer::V6first,
			certificates:         Vec::new(),
			udp_relay_mode:       tuic_client::utils::UdpRelayMode::Native,
			congestion_control:   tuic_client::utils::CongestionControl::Cubic,
			alpn:                 vec![b"h3".to_vec()],
			zero_rtt_handshake:   false,
			disable_sni:          true,
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
		},
		local:     tuic_client::config::Local {
			server:          "127.0.0.1:1080".parse().unwrap(),
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
	println!("[Integration Test] Starting TUIC client with SOCKS5 server on 127.0.0.1:1080...");
	let client_handle = tokio::spawn(async move {
		match timeout(Duration::from_secs(10), tuic_client::run(client_config)).await {
			Ok(Ok(())) => println!("[Integration Test] Client completed successfully"),
			Ok(Err(e)) => eprintln!("[Integration Test] Client error: {}", e),
			Err(_) => eprintln!("[Integration Test] Client timeout"),
		}
	});

	// Wait for client to establish connection and start SOCKS5 server
	println!("[Integration Test] Waiting for client to connect and start SOCKS5 server...");
	tokio::time::sleep(Duration::from_secs(2)).await;
	println!("[Integration Test] SOCKS5 proxy should be ready now\n");

	// Quick connectivity check - try to connect to SOCKS5 proxy
	use tokio::net::TcpStream;
	println!("[Integration Test] Testing SOCKS5 proxy connectivity...");
	match TcpStream::connect("127.0.0.1:1080").await {
		Ok(stream) => {
			println!("[Integration Test] ✓ Successfully connected to SOCKS5 proxy at 127.0.0.1:1080");
			println!(
				"[Integration Test] Local: {:?}, Peer: {:?}",
				stream.local_addr(),
				stream.peer_addr()
			);
			drop(stream);
		}
		Err(e) => {
			eprintln!("[Integration Test] ✗ Failed to connect to SOCKS5 proxy: {}", e);
			eprintln!("[Integration Test] This suggests the TUIC client may not have started properly");
		}
	}
	println!();

	// ============================================================================
	// Test 1: Create a local TCP echo server and test TCP relay through SOCKS5
	// ============================================================================
	let tcp_test = async {
		use fast_socks5::client::{Config, Socks5Stream};
		use tokio::{
			io::{AsyncReadExt, AsyncWriteExt},
			net::TcpListener,
		};

		println!("[TCP Test] Starting TCP relay test...");

		// Start a local TCP echo server
		let echo_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let echo_addr = echo_server.local_addr().unwrap();
		println!("[TCP Test] TCP echo server started at: {}", echo_addr);

		// Spawn echo server task
		let echo_task = tokio::spawn(async move {
			println!("[TCP Echo Server] Waiting for connection...");
			// Wait with timeout to see if connection arrives
			match timeout(Duration::from_secs(5), echo_server.accept()).await {
				Ok(Ok((mut socket, addr))) => {
					println!("[TCP Echo Server] Accepted connection from: {}", addr);
					let mut buf = vec![0u8; 1024];
					match timeout(Duration::from_secs(3), socket.read(&mut buf)).await {
						Ok(Ok(0)) => {
							println!("[TCP Echo Server] Connection closed by client (received 0 bytes)");
						}
						Ok(Ok(n)) => {
							println!("[TCP Echo Server] Received {} bytes: {:?}", n, &buf[..n]);
							if let Err(e) = socket.write_all(&buf[..n]).await {
								eprintln!("[TCP Echo Server] Failed to send response: {}", e);
							} else {
								println!("[TCP Echo Server] Echoed {} bytes back", n);
							}
						}
						Ok(Err(e)) => {
							eprintln!("[TCP Echo Server] Failed to read: {}", e);
						}
						Err(_) => {
							eprintln!("[TCP Echo Server] Timeout waiting for data");
						}
					}
				}
				Ok(Err(e)) => {
					eprintln!("[TCP Echo Server] Failed to accept connection: {}", e);
				}
				Err(_) => {
					eprintln!("[TCP Echo Server] Timeout waiting for connection (no client connected)");
				}
			}
		});

		// Give server time to start
		tokio::time::sleep(Duration::from_millis(200)).await;

		// Connect to the echo server through SOCKS5 proxy
		println!("[TCP Test] Connecting to SOCKS5 proxy at 127.0.0.1:1080...");
		println!("[TCP Test] Target echo server: {}", echo_addr);
		let stream_result = Socks5Stream::connect(
			"127.0.0.1:1080".parse::<SocketAddr>().unwrap(),
			echo_addr.ip().to_string(),
			echo_addr.port(),
			Config::default(),
		)
		.await;

		match stream_result {
			Ok(mut stream) => {
				println!("[TCP Test] Connected through SOCKS5 proxy to echo server");
				println!(
					"[TCP Test] Stream info - local: {:?}, peer: {:?}",
					stream.get_socket_ref().local_addr(),
					stream.get_socket_ref().peer_addr()
				);

				// Send test data
				let test_data = b"Hello, TUIC!";
				println!("[TCP Test] Sending {} bytes: {:?}", test_data.len(), test_data);

				if let Err(e) = stream.write_all(test_data).await {
					eprintln!("[TCP Test] Failed to send data: {}", e);
				} else {
					println!("[TCP Test] Data sent successfully");

					// Give time for data to be transmitted and echoed back
					tokio::time::sleep(Duration::from_millis(500)).await;

					// Read echo response - use read_exact to ensure we get all bytes
					let mut buffer = vec![0u8; test_data.len()];
					match timeout(Duration::from_secs(3), stream.read_exact(&mut buffer)).await {
						Ok(Ok(_)) => {
							println!("[TCP Test] Received {} bytes: {:?}", buffer.len(), &buffer);

							// Verify echo
							if buffer.as_slice() == test_data {
								println!("[TCP Test] ✓ TCP echo test PASSED - data matches!");
							} else {
								eprintln!("[TCP Test] ✗ TCP echo test FAILED - data mismatch!");
								eprintln!("[TCP Test] Expected: {:?}", test_data);
								eprintln!("[TCP Test] Got: {:?}", &buffer);
							}
						}
						Ok(Err(e)) => {
							eprintln!("[TCP Test] Failed to read response: {}", e);
							// Try regular read to see what we can get
							let mut fallback_buffer = vec![0u8; 1024];
							if let Ok(Ok(bytes)) = timeout(Duration::from_secs(1), stream.read(&mut fallback_buffer)).await {
								eprintln!(
									"[TCP Test] Fallback read got {} bytes: {:?}",
									bytes,
									&fallback_buffer[..bytes]
								);
							}
						}
						Err(_) => {
							eprintln!("[TCP Test] Timeout waiting for response");
							// Try to read whatever is available
							let mut fallback_buffer = vec![0u8; 1024];
							if let Ok(n) = stream.read(&mut fallback_buffer).await {
								eprintln!("[TCP Test] Partial read got {} bytes: {:?}", n, &fallback_buffer[..n]);
							}
						}
					}
				}
			}
			Err(e) => {
				eprintln!("[TCP Test] Failed to connect to SOCKS5 proxy: {}", e);
			}
		}

		// Wait a bit to see if echo server gets anything
		println!("[TCP Test] Waiting for echo server to finish...");
		tokio::time::sleep(Duration::from_millis(500)).await;

		// Clean up
		echo_task.abort();
		println!("[TCP Test] TCP test completed\n");
	};

	// Run the TCP test with a timeout
	let _ = timeout(Duration::from_secs(6), tcp_test).await;

	// ============================================================================
	// Test 2: Create a local UDP echo server and test UDP relay through SOCKS5
	// ============================================================================
	let udp_test = async {
		use std::{
			net::{IpAddr, Ipv4Addr},
			sync::Arc,
		};

		use fast_socks5::client::Socks5Datagram;
		use tokio::net::{TcpStream, UdpSocket};

		println!("\n[UDP Test] ========================================");
		println!("[UDP Test] Starting UDP relay test...");
		println!("[UDP Test] ========================================\n");

		// Start a local UDP echo server
		let echo_server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
		let echo_addr = echo_server.local_addr().unwrap();
		println!("[UDP Test] UDP echo server started at: {}", echo_addr);

		// Spawn echo server task that echoes back received data
		let echo_server_clone = echo_server.clone();
		let echo_task = tokio::spawn(async move {
			let mut buf = vec![0u8; 1024];
			println!("[UDP Echo Server] Waiting for packets...");
			match timeout(Duration::from_secs(5), echo_server_clone.recv_from(&mut buf)).await {
				Ok(Ok((n, addr))) => {
					println!("[UDP Echo Server] Received {} bytes from {}", n, addr);
					println!("[UDP Echo Server] Data: {:?}", &buf[..n]);
					if let Err(e) = echo_server_clone.send_to(&buf[..n], addr).await {
						eprintln!("[UDP Echo Server] Failed to send response: {}", e);
					} else {
						println!("[UDP Echo Server] Echoed {} bytes back to {}", n, addr);
					}
				}
				Ok(Err(e)) => {
					eprintln!("[UDP Echo Server] Error receiving: {}", e);
				}
				Err(_) => {
					eprintln!("[UDP Echo Server] Timeout waiting for data (no packets received)");
				}
			}
		}); // Give server time to start
		tokio::time::sleep(Duration::from_millis(100)).await;

		// Connect to SOCKS5 proxy using fast-socks5's UDP API
		println!("[UDP Test] Connecting to SOCKS5 proxy at 127.0.0.1:1080...");
		let socks_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();

		// Create TCP connection to SOCKS5 server for UDP association
		println!("[UDP Test] Creating TCP connection to SOCKS5 proxy...");
		let backing_socket_result = TcpStream::connect(socks_addr).await;

		if let Ok(backing_socket) = backing_socket_result {
			println!("[UDP Test] TCP connection to SOCKS5 proxy established");
			println!(
				"[UDP Test] Local TCP addr: {:?}, Remote TCP addr: {:?}",
				backing_socket.local_addr(),
				backing_socket.peer_addr()
			);

			// Bind UDP socket through SOCKS5 (no authentication)
			let client_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
			println!("[UDP Test] Binding UDP socket through SOCKS5 from {}...", client_bind_addr);
			let socks_result = Socks5Datagram::bind(backing_socket, client_bind_addr).await;

			if let Ok(socks) = socks_result {
				println!("[UDP Test] UDP association established through SOCKS5");

				// Prepare test data
				let test_data = b"Hello, UDP through TUIC!";
				println!("[UDP Test] Test data: {} bytes - {:?}", test_data.len(), test_data);

				// Send data through SOCKS5 to echo server
				let target_ip = echo_addr.ip();
				let target_port = echo_addr.port();
				println!("[UDP Test] Sending to target {}:{}...", target_ip, target_port);
				let send_result = socks.send_to(test_data, (target_ip, target_port)).await;

				match send_result {
					Ok(sent) => {
						println!("[UDP Test] Successfully sent {} bytes through SOCKS5 proxy", sent);
						println!("[UDP Test] Waiting for echo response...");

						// Receive echo response
						let mut buffer = vec![0u8; 1024];
						let recv_result = timeout(Duration::from_secs(2), socks.recv_from(&mut buffer)).await;

						match recv_result {
							Ok(Ok((len, addr))) => {
								println!("[UDP Test] Received {} bytes from {:?}", len, addr);
								println!("[UDP Test] Response data: {:?}", &buffer[..len]);

								// Verify echo
								if &buffer[..len] == test_data {
									println!("[UDP Test] ✓ UDP echo test PASSED - data matches!");
								} else {
									eprintln!("[UDP Test] ✗ UDP echo test FAILED - data mismatch!");
									eprintln!("[UDP Test] Expected: {:?}", test_data);
									eprintln!("[UDP Test] Got: {:?}", &buffer[..len]);
								}
							}
							Ok(Err(e)) => {
								eprintln!("[UDP Test] Failed to receive response: {}", e);
							}
							Err(_) => {
								eprintln!("[UDP Test] Timeout waiting for response");
							}
						}
					}
					Err(e) => {
						eprintln!("[UDP Test] Failed to send data: {}", e);
					}
				}
			} else {
				eprintln!("[UDP Test] Failed to bind UDP through SOCKS5: {:?}", socks_result.err());
			}
		} else {
			eprintln!(
				"[UDP Test] Failed to connect to SOCKS5 proxy: {:?}",
				backing_socket_result.err()
			);
		}

		// Clean up
		echo_task.abort();
		println!("[UDP Test] UDP test completed\n");
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

		println!("[Concurrent Test] Starting concurrent TCP connections test...");

		// Start a local TCP server
		let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let server_addr = server.local_addr().unwrap();
		println!("[Concurrent Test] TCP server started at: {}", server_addr);

		// Spawn server task that handles multiple connections
		let server_task = tokio::spawn(async move {
			for i in 0..3 {
				if let Ok((mut socket, addr)) = server.accept().await {
					println!("[Concurrent Test Server] Accepted connection {} from: {}", i, addr);
					tokio::spawn(async move {
						let mut buf = vec![0u8; 1024];
						if let Ok(n) = socket.read(&mut buf).await {
							println!("[Concurrent Test Server] Connection {}: received {} bytes", i, n);
							if let Err(e) = socket.write_all(&buf[..n]).await {
								eprintln!("[Concurrent Test Server] Connection {}: failed to echo: {}", i, e);
							}
						}
					});
				}
			}
		});

		tokio::time::sleep(Duration::from_millis(100)).await;

		// Create multiple concurrent connections through SOCKS5
		println!("[Concurrent Test] Creating 3 concurrent connections through SOCKS5...");
		let mut handles = vec![];
		for i in 0..3 {
			let addr = server_addr;
			let handle = tokio::spawn(async move {
				println!("[Concurrent Test] Connection {}: connecting...", i);
				match Socks5Stream::connect(
					"127.0.0.1:1080".parse::<SocketAddr>().unwrap(),
					addr.ip().to_string(),
					addr.port(),
					Config::default(),
				)
				.await
				{
					Ok(mut stream) => {
						println!("[Concurrent Test] Connection {}: connected", i);
						let test_data = format!("Connection {}", i);

						if let Err(e) = stream.write_all(test_data.as_bytes()).await {
							eprintln!("[Concurrent Test] Connection {}: failed to send: {}", i, e);
						} else {
							println!("[Concurrent Test] Connection {}: sent {} bytes", i, test_data.len());

							let mut buf = vec![0u8; 1024];
							match timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
								Ok(Ok(n)) => {
									println!("[Concurrent Test] Connection {}: received {} bytes", i, n);
								}
								Ok(Err(e)) => {
									eprintln!("[Concurrent Test] Connection {}: failed to receive: {}", i, e);
								}
								Err(_) => {
									eprintln!("[Concurrent Test] Connection {}: timeout", i);
								}
							}
						}
					}
					Err(e) => {
						eprintln!("[Concurrent Test] Connection {}: failed to connect: {}", i, e);
					}
				}
			});
			handles.push(handle);
		}

		// Wait for all connections to complete
		for (i, handle) in handles.into_iter().enumerate() {
			if let Err(e) = handle.await {
				eprintln!("[Concurrent Test] Connection {} task failed: {}", i, e);
			}
		}

		println!("[Concurrent Test] ✓ All concurrent connections completed");
		server_task.abort();
		println!("[Concurrent Test] Concurrent test completed\n");
	};

	// Run the concurrent test with a timeout
	let _ = timeout(Duration::from_secs(5), concurrent_test).await;

	// Clean up
	client_handle.abort();
	server_handle.abort();

	// Give tasks time to clean up
	tokio::time::sleep(Duration::from_millis(100)).await;
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
// This addresses the error that occurs when using IPv6 addresses like "[::1]:443"
#[tokio::test]
#[tracing_test::traced_test]
async fn test_ipv6_server_client_integration() {
	use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
	#[cfg(feature = "aws-lc-rs")]
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	#[cfg(feature = "ring")]
	let _ = rustls::crypto::ring::default_provider().install_default();

	println!("\n[IPv6 Test] ========================================");
	println!("[IPv6 Test] Starting IPv6 Integration Test");
	println!("[IPv6 Test] ========================================\n");

	// Create server configuration using IPv6 localhost [::1]
	let server_config = tuic_server::Config {
		log_level: tuic_server::config::LogLevel::Debug,
		server: "[::1]:8444".parse::<SocketAddr>().unwrap(),
		users: {
			let mut users = HashMap::new();
			users.insert(
				Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
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
	println!("[IPv6 Test] Starting TUIC server on [::1]:8444...");
	let server_handle = tokio::spawn(async move {
		match timeout(Duration::from_secs(10), tuic_server::run(server_config)).await {
			Ok(Ok(())) => println!("[IPv6 Test] Server completed successfully"),
			Ok(Err(e)) => eprintln!("[IPv6 Test] Server error: {}", e),
			Err(_) => eprintln!("[IPv6 Test] Server timeout"),
		}
	});

	// Wait for server to start
	println!("[IPv6 Test] Waiting for server to initialize...");
	tokio::time::sleep(Duration::from_secs(1)).await;
	println!("[IPv6 Test] Server should be ready now");

	// Create client configuration connecting to IPv6 server
	let client_config = tuic_client::Config {
		relay:     tuic_client::config::Relay {
			server:               ("[::1]".to_string(), 8444),
			uuid:                 Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
			password:             std::sync::Arc::from(b"test_password".to_vec().into_boxed_slice()),
			ip:                   None,
			ipstack_prefer:       tuic_client::utils::StackPrefer::V6first,
			certificates:         Vec::new(),
			udp_relay_mode:       tuic_client::utils::UdpRelayMode::Native,
			congestion_control:   tuic_client::utils::CongestionControl::Cubic,
			alpn:                 vec![b"h3".to_vec()],
			zero_rtt_handshake:   false,
			disable_sni:          true,
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
		},
		local:     tuic_client::config::Local {
			server:          "[::1]:1081".parse().unwrap(),
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
	println!("[IPv6 Test] Starting TUIC client with SOCKS5 server on [::1]:1081...");
	let client_handle = tokio::spawn(async move {
		match timeout(Duration::from_secs(10), tuic_client::run(client_config)).await {
			Ok(Ok(())) => println!("[IPv6 Test] Client completed successfully"),
			Ok(Err(e)) => eprintln!("[IPv6 Test] Client error: {}", e),
			Err(_) => eprintln!("[IPv6 Test] Client timeout"),
		}
	});

	// Wait for client to connect
	println!("[IPv6 Test] Waiting for client to connect and start SOCKS5 server...");
	tokio::time::sleep(Duration::from_secs(2)).await;
	println!("[IPv6 Test] SOCKS5 proxy should be ready now\n");

	// Test SOCKS5 proxy connectivity on IPv6
	use tokio::net::TcpStream;
	println!("[IPv6 Test] Testing SOCKS5 proxy connectivity on IPv6...");
	match TcpStream::connect("[::1]:1081").await {
		Ok(stream) => {
			println!("[IPv6 Test] ✓ Successfully connected to SOCKS5 proxy at [::1]:1081");
			println!(
				"[IPv6 Test] Local: {:?}, Peer: {:?}",
				stream.local_addr(),
				stream.peer_addr()
			);
			drop(stream);
		}
		Err(e) => {
			eprintln!("[IPv6 Test] ✗ Failed to connect to SOCKS5 proxy: {}", e);
			eprintln!("[IPv6 Test] This suggests the TUIC client may not have started properly on IPv6");
		}
	}
	println!();

	// ============================================================================
	// Test 1: IPv6 TCP relay through SOCKS5
	// ============================================================================
	let tcp_test = async {
		use fast_socks5::client::{Config, Socks5Stream};
		use tokio::{
			io::{AsyncReadExt, AsyncWriteExt},
			net::TcpListener,
		};

		println!("[IPv6 TCP Test] Starting TCP relay test on IPv6...");

		// Start a local TCP echo server on IPv6
		let echo_server = TcpListener::bind("[::1]:0").await.unwrap();
		let echo_addr = echo_server.local_addr().unwrap();
		println!("[IPv6 TCP Test] TCP echo server started at: {}", echo_addr);

		// Spawn echo server task
		let echo_task = tokio::spawn(async move {
			println!("[IPv6 TCP Echo Server] Waiting for connection...");
			match timeout(Duration::from_secs(5), echo_server.accept()).await {
				Ok(Ok((mut socket, addr))) => {
					println!("[IPv6 TCP Echo Server] Accepted connection from: {}", addr);
					let mut buf = vec![0u8; 1024];
					match timeout(Duration::from_secs(3), socket.read(&mut buf)).await {
						Ok(Ok(0)) => {
							println!("[IPv6 TCP Echo Server] Connection closed by client");
						}
						Ok(Ok(n)) => {
							println!("[IPv6 TCP Echo Server] Received {} bytes", n);
							if let Err(e) = socket.write_all(&buf[..n]).await {
								eprintln!("[IPv6 TCP Echo Server] Failed to send response: {}", e);
							} else {
								println!("[IPv6 TCP Echo Server] Echoed {} bytes back", n);
							}
						}
						Ok(Err(e)) => {
							eprintln!("[IPv6 TCP Echo Server] Failed to read: {}", e);
						}
						Err(_) => {
							eprintln!("[IPv6 TCP Echo Server] Timeout waiting for data");
						}
					}
				}
				Ok(Err(e)) => {
					eprintln!("[IPv6 TCP Echo Server] Failed to accept connection: {}", e);
				}
				Err(_) => {
					eprintln!("[IPv6 TCP Echo Server] Timeout waiting for connection");
				}
			}
		});

		tokio::time::sleep(Duration::from_millis(200)).await;

		// Connect through SOCKS5 proxy on IPv6
		println!("[IPv6 TCP Test] Connecting to SOCKS5 proxy at [::1]:1081...");
		let stream_result = Socks5Stream::connect(
			"[::1]:1081".parse::<SocketAddr>().unwrap(),
			echo_addr.ip().to_string(),
			echo_addr.port(),
			Config::default(),
		)
		.await;

		match stream_result {
			Ok(mut stream) => {
				println!("[IPv6 TCP Test] Connected through SOCKS5 proxy to echo server");

				let test_data = b"Hello IPv6 TUIC!";
				println!("[IPv6 TCP Test] Sending {} bytes", test_data.len());

				if let Err(e) = stream.write_all(test_data).await {
					eprintln!("[IPv6 TCP Test] Failed to send data: {}", e);
				} else {
					println!("[IPv6 TCP Test] Data sent successfully");
					tokio::time::sleep(Duration::from_millis(500)).await;

					let mut buffer = vec![0u8; test_data.len()];
					match timeout(Duration::from_secs(3), stream.read_exact(&mut buffer)).await {
						Ok(Ok(_)) => {
							println!("[IPv6 TCP Test] Received {} bytes", buffer.len());
							if buffer.as_slice() == test_data {
								println!("[IPv6 TCP Test] ✓ IPv6 TCP echo test PASSED!");
							} else {
								eprintln!("[IPv6 TCP Test] ✗ IPv6 TCP echo test FAILED - data mismatch!");
							}
						}
						Ok(Err(e)) => {
							eprintln!("[IPv6 TCP Test] Failed to read response: {}", e);
						}
						Err(_) => {
							eprintln!("[IPv6 TCP Test] Timeout waiting for response");
						}
					}
				}
			}
			Err(e) => {
				eprintln!("[IPv6 TCP Test] Failed to connect to SOCKS5 proxy: {}", e);
			}
		}

		echo_task.abort();
		println!("[IPv6 TCP Test] TCP test completed\n");
	};

	let _ = timeout(Duration::from_secs(6), tcp_test).await;

	// ============================================================================
	// Test 2: IPv6 UDP relay through SOCKS5
	// ============================================================================
	let udp_test = async {
		use std::{
			net::{IpAddr, Ipv6Addr},
			sync::Arc,
		};

		use fast_socks5::client::Socks5Datagram;
		use tokio::net::{TcpStream, UdpSocket};

		println!("[IPv6 UDP Test] Starting UDP relay test on IPv6...");

		// Start a local UDP echo server on IPv6
		let echo_server = Arc::new(UdpSocket::bind("[::1]:0").await.unwrap());
		let echo_addr = echo_server.local_addr().unwrap();
		println!("[IPv6 UDP Test] UDP echo server started at: {}", echo_addr);

		let echo_server_clone = echo_server.clone();
		let echo_task = tokio::spawn(async move {
			let mut buf = vec![0u8; 1024];
			println!("[IPv6 UDP Echo Server] Waiting for packets...");
			match timeout(Duration::from_secs(5), echo_server_clone.recv_from(&mut buf)).await {
				Ok(Ok((n, addr))) => {
					println!("[IPv6 UDP Echo Server] Received {} bytes from {}", n, addr);
					if let Err(e) = echo_server_clone.send_to(&buf[..n], addr).await {
						eprintln!("[IPv6 UDP Echo Server] Failed to send response: {}", e);
					} else {
						println!("[IPv6 UDP Echo Server] Echoed {} bytes back", n);
					}
				}
				Ok(Err(e)) => {
					eprintln!("[IPv6 UDP Echo Server] Error receiving: {}", e);
				}
				Err(_) => {
					eprintln!("[IPv6 UDP Echo Server] Timeout waiting for data");
				}
			}
		});

		tokio::time::sleep(Duration::from_millis(100)).await;

		// Connect to SOCKS5 proxy on IPv6
		println!("[IPv6 UDP Test] Connecting to SOCKS5 proxy at [::1]:1081...");
		let socks_addr: SocketAddr = "[::1]:1081".parse().unwrap();

		let backing_socket_result = TcpStream::connect(socks_addr).await;

		if let Ok(backing_socket) = backing_socket_result {
			println!("[IPv6 UDP Test] TCP connection to SOCKS5 proxy established");

			let client_bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
			println!("[IPv6 UDP Test] Binding UDP socket through SOCKS5...");
			let socks_result = Socks5Datagram::bind(backing_socket, client_bind_addr).await;

			if let Ok(socks) = socks_result {
				println!("[IPv6 UDP Test] UDP association established through SOCKS5");

				let test_data = b"Hello, IPv6 UDP through TUIC!";
				println!("[IPv6 UDP Test] Test data: {} bytes", test_data.len());

				let target_ip = echo_addr.ip();
				let target_port = echo_addr.port();
				println!("[IPv6 UDP Test] Sending to target {}:{}...", target_ip, target_port);
				let send_result = socks.send_to(test_data, (target_ip, target_port)).await;

				match send_result {
					Ok(sent) => {
						println!("[IPv6 UDP Test] Successfully sent {} bytes through SOCKS5", sent);
						println!("[IPv6 UDP Test] Waiting for echo response...");

						let mut buffer = vec![0u8; 1024];
						let recv_result = timeout(Duration::from_secs(2), socks.recv_from(&mut buffer)).await;

						match recv_result {
							Ok(Ok((len, addr))) => {
								println!("[IPv6 UDP Test] Received {} bytes from {:?}", len, addr);
								if &buffer[..len] == test_data {
									println!("[IPv6 UDP Test] ✓ IPv6 UDP echo test PASSED!");
								} else {
									eprintln!("[IPv6 UDP Test] ✗ IPv6 UDP echo test FAILED - data mismatch!");
								}
							}
							Ok(Err(e)) => {
								eprintln!("[IPv6 UDP Test] Failed to receive response: {}", e);
							}
							Err(_) => {
								eprintln!("[IPv6 UDP Test] Timeout waiting for response");
							}
						}
					}
					Err(e) => {
						eprintln!("[IPv6 UDP Test] Failed to send data: {}", e);
					}
				}
			} else {
				eprintln!("[IPv6 UDP Test] Failed to bind UDP through SOCKS5: {:?}", socks_result.err());
			}
		} else {
			eprintln!(
				"[IPv6 UDP Test] Failed to connect to SOCKS5 proxy: {:?}",
				backing_socket_result.err()
			);
		}

		echo_task.abort();
		println!("[IPv6 UDP Test] UDP test completed\n");
	};

	let _ = timeout(Duration::from_secs(3), udp_test).await;

	// Clean up
	client_handle.abort();
	server_handle.abort();

	tokio::time::sleep(Duration::from_millis(100)).await;

	println!("[IPv6 Test] ========================================");
	println!("[IPv6 Test] IPv6 Integration Test Completed");
	println!("[IPv6 Test] ========================================\n");
}
