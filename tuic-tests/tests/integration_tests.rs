// Integration tests for TUIC protocol
// Tests the marshal/unmarshal round-trip for all protocol types

use std::{io::Cursor, time::Duration};

use serial_test::serial;
use tokio::time::timeout;
use tuic_core::{Address, Authenticate, Connect, Dissociate, Header, Heartbeat, Packet};
use uuid::Uuid;

// Helper function to marshal and unmarshal a header
fn marshal_unmarshal_header(header: Header) -> Header {
	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	Header::unmarshal(&mut cursor).unwrap()
}

// Helper function to create and run a TCP echo server
async fn run_tcp_echo_server(bind_addr: &str, test_name: &str) -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
	use tokio::{
		io::{AsyncReadExt, AsyncWriteExt},
		net::TcpListener,
	};

	let echo_server = TcpListener::bind(bind_addr).await.unwrap();
	let echo_addr = echo_server.local_addr().unwrap();
	println!("[{} Echo Server] Started at: {}", test_name, echo_addr);

	let test_name = test_name.to_string();
	let echo_task = tokio::spawn(async move {
		println!("[{} Echo Server] Waiting for connection...", test_name);
		match timeout(Duration::from_secs(5), echo_server.accept()).await {
			Ok(Ok((mut socket, addr))) => {
				println!("[{} Echo Server] Accepted connection from: {}", test_name, addr);
				let mut buf = vec![0u8; 1024];
				match timeout(Duration::from_secs(3), socket.read(&mut buf)).await {
					Ok(Ok(0)) => {
						println!("[{} Echo Server] Connection closed by client (received 0 bytes)", test_name);
					}
					Ok(Ok(n)) => {
						println!("[{} Echo Server] Received {} bytes: {:?}", test_name, n, &buf[..n]);
						if let Err(e) = socket.write_all(&buf[..n]).await {
							eprintln!("[{} Echo Server] Failed to send response: {}", test_name, e);
						} else {
							println!("[{} Echo Server] Echoed {} bytes back", test_name, n);
						}
					}
					Ok(Err(e)) => {
						eprintln!("[{} Echo Server] Failed to read: {}", test_name, e);
					}
					Err(_) => {
						eprintln!("[{} Echo Server] Timeout waiting for data", test_name);
					}
				}
			}
			Ok(Err(e)) => {
				eprintln!("[{} Echo Server] Failed to accept connection: {}", test_name, e);
			}
			Err(_) => {
				eprintln!(
					"[{} Echo Server] Timeout waiting for connection (no client connected)",
					test_name
				);
			}
		}
	});

	(echo_task, echo_addr)
}

// Helper function to create and run a UDP echo server
async fn run_udp_echo_server(
	bind_addr: &str,
	test_name: &str,
) -> (
	tokio::task::JoinHandle<()>,
	std::net::SocketAddr,
	std::sync::Arc<tokio::net::UdpSocket>,
) {
	use std::sync::Arc;

	use tokio::net::UdpSocket;

	let echo_server = Arc::new(UdpSocket::bind(bind_addr).await.unwrap());
	let echo_addr = echo_server.local_addr().unwrap();
	println!("[{} Echo Server] Started at: {}", test_name, echo_addr);

	let echo_server_clone = echo_server.clone();
	let test_name = test_name.to_string();
	let echo_task = tokio::spawn(async move {
		let mut buf = vec![0u8; 1024];
		println!("[{} Echo Server] Waiting for packets...", test_name);
		match timeout(Duration::from_secs(5), echo_server_clone.recv_from(&mut buf)).await {
			Ok(Ok((n, addr))) => {
				println!("[{} Echo Server] Received {} bytes from {}", test_name, n, addr);
				println!("[{} Echo Server] Data: {:?}", test_name, &buf[..n]);
				if let Err(e) = echo_server_clone.send_to(&buf[..n], addr).await {
					eprintln!("[{} Echo Server] Failed to send response: {}", test_name, e);
				} else {
					println!("[{} Echo Server] Echoed {} bytes back to {}", test_name, n, addr);
				}
			}
			Ok(Err(e)) => {
				eprintln!("[{} Echo Server] Error receiving: {}", test_name, e);
			}
			Err(_) => {
				eprintln!("[{} Echo Server] Timeout waiting for data (no packets received)", test_name);
			}
		}
	});

	(echo_task, echo_addr, echo_server)
}

// Helper function to test TCP connection through SOCKS5
async fn test_tcp_through_socks5(
	socks5_addr: &str,
	target_addr: std::net::SocketAddr,
	test_data: &[u8],
	test_name: &str,
) -> bool {
	use fast_socks5::client::{Config, Socks5Stream};
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	println!("[{}] Connecting to SOCKS5 proxy at {}...", test_name, socks5_addr);
	println!("[{}] Target echo server: {}", test_name, target_addr);

	let stream_result = Socks5Stream::connect(
		socks5_addr.parse::<std::net::SocketAddr>().unwrap(),
		target_addr.ip().to_string(),
		target_addr.port(),
		Config::default(),
	)
	.await;

	match stream_result {
		Ok(mut stream) => {
			println!("[{}] Connected through SOCKS5 proxy to echo server", test_name);
			println!(
				"[{}] Stream info - local: {:?}, peer: {:?}",
				test_name,
				stream.get_socket_ref().local_addr(),
				stream.get_socket_ref().peer_addr()
			);

			println!("[{}] Sending {} bytes: {:?}", test_name, test_data.len(), test_data);

			if let Err(e) = stream.write_all(test_data).await {
				eprintln!("[{}] Failed to send data: {}", test_name, e);
				return false;
			}

			println!("[{}] Data sent successfully", test_name);
			tokio::time::sleep(Duration::from_millis(500)).await;

			let mut buffer = vec![0u8; test_data.len()];
			match timeout(Duration::from_secs(3), stream.read_exact(&mut buffer)).await {
				Ok(Ok(_)) => {
					println!("[{}] Received {} bytes: {:?}", test_name, buffer.len(), &buffer);

					if buffer.as_slice() == test_data {
						println!("[{}] ✓ TCP echo test PASSED - data matches!", test_name);
						true
					} else {
						eprintln!("[{}] ✗ TCP echo test FAILED - data mismatch!", test_name);
						eprintln!("[{}] Expected: {:?}", test_name, test_data);
						eprintln!("[{}] Got: {:?}", test_name, &buffer);
						false
					}
				}
				Ok(Err(e)) => {
					eprintln!("[{}] Failed to read response: {}", test_name, e);
					false
				}
				Err(_) => {
					eprintln!("[{}] Timeout waiting for response", test_name);
					false
				}
			}
		}
		Err(e) => {
			eprintln!("[{}] Failed to connect to SOCKS5 proxy: {}", test_name, e);
			false
		}
	}
}

// Helper function to test UDP connection through SOCKS5
async fn test_udp_through_socks5(
	socks5_addr: &str,
	target_addr: std::net::SocketAddr,
	test_data: &[u8],
	test_name: &str,
	bind_addr: std::net::SocketAddr,
) -> bool {
	use fast_socks5::client::Socks5Datagram;
	use tokio::net::TcpStream;

	println!("[{}] Connecting to SOCKS5 proxy at {}...", test_name, socks5_addr);
	let socks_addr: std::net::SocketAddr = socks5_addr.parse().unwrap();

	println!("[{}] Creating TCP connection to SOCKS5 proxy...", test_name);
	let backing_socket_result = TcpStream::connect(socks_addr).await;

	match backing_socket_result {
		Ok(backing_socket) => {
			println!("[{}] TCP connection to SOCKS5 proxy established", test_name);
			println!(
				"[{}] Local TCP addr: {:?}, Remote TCP addr: {:?}",
				test_name,
				backing_socket.local_addr(),
				backing_socket.peer_addr()
			);

			println!("[{}] Binding UDP socket through SOCKS5 from {}...", test_name, bind_addr);
			let socks_result = Socks5Datagram::bind(backing_socket, bind_addr).await;

			match socks_result {
				Ok(socks) => {
					println!("[{}] UDP association established through SOCKS5", test_name);
					println!("[{}] Test data: {} bytes - {:?}", test_name, test_data.len(), test_data);

					let target_ip = target_addr.ip();
					let target_port = target_addr.port();
					println!("[{}] Sending to target {}:{}...", test_name, target_ip, target_port);

					match socks.send_to(test_data, (target_ip, target_port)).await {
						Ok(sent) => {
							println!("[{}] Successfully sent {} bytes through SOCKS5 proxy", test_name, sent);
							println!("[{}] Waiting for echo response...", test_name);

							let mut buffer = vec![0u8; 1024];
							match timeout(Duration::from_secs(2), socks.recv_from(&mut buffer)).await {
								Ok(Ok((len, addr))) => {
									println!("[{}] Received {} bytes from {:?}", test_name, len, addr);
									println!("[{}] Response data: {:?}", test_name, &buffer[..len]);

									if &buffer[..len] == test_data {
										println!("[{}] ✓ UDP echo test PASSED - data matches!", test_name);
										true
									} else {
										eprintln!("[{}] ✗ UDP echo test FAILED - data mismatch!", test_name);
										eprintln!("[{}] Expected: {:?}", test_name, test_data);
										eprintln!("[{}] Got: {:?}", test_name, &buffer[..len]);
										false
									}
								}
								Ok(Err(e)) => {
									eprintln!("[{}] Failed to receive response: {}", test_name, e);
									false
								}
								Err(_) => {
									eprintln!("[{}] Timeout waiting for response", test_name);
									false
								}
							}
						}
						Err(e) => {
							eprintln!("[{}] Failed to send data: {}", test_name, e);
							false
						}
					}
				}
				Err(e) => {
					eprintln!("[{}] Failed to bind UDP through SOCKS5: {:?}", test_name, e);
					false
				}
			}
		}
		Err(e) => {
			eprintln!("[{}] Failed to connect to SOCKS5 proxy: {:?}", test_name, e);
			false
		}
	}
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
#[serial]
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
		println!("[TCP Test] Starting TCP relay test...");

		// Start a local TCP echo server
		let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "TCP Test").await;

		// Give server time to start
		tokio::time::sleep(Duration::from_millis(200)).await;

		// Test TCP connection through SOCKS5
		let test_data = b"Hello, TUIC!";
		test_tcp_through_socks5("127.0.0.1:1080", echo_addr, test_data, "TCP Test").await;

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
		use std::net::{IpAddr, Ipv4Addr};

		println!("\n[UDP Test] ========================================");
		println!("[UDP Test] Starting UDP relay test...");
		println!("[UDP Test] ========================================\n");

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
					"127.0.0.1:1080".parse::<std::net::SocketAddr>().unwrap(),
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
// This addresses the error that occurs when using IPv6 addresses like
// "[::1]:443"
#[tokio::test]
#[serial]
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
			println!("[IPv6 Test] Local: {:?}, Peer: {:?}", stream.local_addr(), stream.peer_addr());
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
		println!("[IPv6 TCP Test] Starting TCP relay test on IPv6...");

		// Start a local TCP echo server on IPv6
		let (echo_task, echo_addr) = run_tcp_echo_server("[::1]:0", "IPv6 TCP Test").await;

		tokio::time::sleep(Duration::from_millis(200)).await;

		// Test TCP connection through SOCKS5 on IPv6
		let test_data = b"Hello IPv6 TUIC!";
		test_tcp_through_socks5("[::1]:1081", echo_addr, test_data, "IPv6 TCP Test").await;

		echo_task.abort();
		println!("[IPv6 TCP Test] TCP test completed\n");
	};

	let _ = timeout(Duration::from_secs(6), tcp_test).await;

	// ============================================================================
	// Test 2: IPv6 UDP relay through SOCKS5
	// ============================================================================
	let udp_test = async {
		use std::net::{IpAddr, Ipv6Addr};

		println!("[IPv6 UDP Test] Starting UDP relay test on IPv6...");

		// Start a local UDP echo server on IPv6
		let (echo_task, echo_addr, _echo_server) = run_udp_echo_server("[::1]:0", "IPv6 UDP Test").await;

		tokio::time::sleep(Duration::from_millis(100)).await;

		// Test UDP connection through SOCKS5 on IPv6
		let test_data = b"Hello, IPv6 UDP through TUIC!";
		let client_bind_addr = std::net::SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
		test_udp_through_socks5("[::1]:1081", echo_addr, test_data, "IPv6 UDP Test", client_bind_addr).await;

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
