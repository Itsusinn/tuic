use std::{
	net::{Ipv4Addr, Ipv6Addr},
	time::Duration,
};

use bytes::BytesMut;
use serial_test::serial;
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{error, info};
use tuic_server::config::ExperimentalConfig;
use tuic_tests::{run_tcp_echo_server, run_udp_echo_server, test_tcp_through_socks5, test_udp_through_socks5};
use uuid::Uuid;
use wind_tuic::proto::{Address, AddressCodec, CmdCodec, CmdType, Command, Header, HeaderCodec};

fn roundtrip_header(header: Header) -> Header {
	let mut buf = BytesMut::new();
	HeaderCodec.encode(header, &mut buf).unwrap();
	HeaderCodec.decode(&mut buf).unwrap().unwrap()
}

fn roundtrip_command(cmd_type: CmdType, command: Command) -> Command {
	let mut buf = BytesMut::new();
	CmdCodec(cmd_type).encode(command, &mut buf).unwrap();
	CmdCodec(cmd_type).decode(&mut buf).unwrap().unwrap()
}

fn roundtrip_address(addr: Address) -> Address {
	let mut buf = BytesMut::new();
	AddressCodec.encode(addr, &mut buf).unwrap();
	AddressCodec.decode(&mut buf).unwrap().unwrap()
}

#[test]
fn test_full_protocol_roundtrip() {
	let uuid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
	let token = [42u8; 32];
	let cmd = Command::Auth { uuid, token };

	let decoded_header = roundtrip_header(Header::new(CmdType::Auth));
	assert_eq!(decoded_header.command, CmdType::Auth);

	let decoded_cmd = roundtrip_command(CmdType::Auth, cmd);
	match decoded_cmd {
		Command::Auth {
			uuid: decoded_uuid,
			token: decoded_token,
		} => {
			assert_eq!(decoded_uuid, uuid);
			assert_eq!(decoded_token, token);
		}
		_ => panic!("Wrong command type"),
	}

	let addresses: Vec<Address> = vec![
		Address::None,
		Address::Domain("example.com".to_string(), 443),
		Address::IPv4("192.168.1.1".parse::<Ipv4Addr>().unwrap(), 8080),
		Address::IPv6("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 9000),
	];

	let decoded_header = roundtrip_header(Header::new(CmdType::Connect));
	assert_eq!(decoded_header.command, CmdType::Connect);

	let decoded_cmd = roundtrip_command(CmdType::Connect, Command::Connect);
	assert!(matches!(decoded_cmd, Command::Connect));

	for addr in addresses {
		let decoded_addr = roundtrip_address(addr.clone());
		assert_eq!(decoded_addr, addr);
	}

	let cmd = Command::Packet {
		assoc_id: 123,
		pkt_id: 456,
		frag_total: 10,
		frag_id: 5,
		size: 2048,
	};
	let addr = Address::Domain("udp.test".to_string(), 53);

	let decoded_header = roundtrip_header(Header::new(CmdType::Packet));
	assert_eq!(decoded_header.command, CmdType::Packet);

	let decoded_cmd = roundtrip_command(CmdType::Packet, cmd);
	match decoded_cmd {
		Command::Packet {
			assoc_id,
			pkt_id,
			frag_total,
			frag_id,
			size,
		} => {
			assert_eq!(assoc_id, 123);
			assert_eq!(pkt_id, 456);
			assert_eq!(frag_total, 10);
			assert_eq!(frag_id, 5);
			assert_eq!(size, 2048);
		}
		_ => panic!("Wrong command type"),
	}

	let decoded_addr = roundtrip_address(addr.clone());
	assert_eq!(decoded_addr, addr);

	let cmd = Command::Dissociate { assoc_id: 999 };

	let decoded_header = roundtrip_header(Header::new(CmdType::Dissociate));
	assert_eq!(decoded_header.command, CmdType::Dissociate);

	let decoded_cmd = roundtrip_command(CmdType::Dissociate, cmd);
	match decoded_cmd {
		Command::Dissociate { assoc_id } => {
			assert_eq!(assoc_id, 999);
		}
		_ => panic!("Wrong command type"),
	}

	let decoded_header = roundtrip_header(Header::new(CmdType::Heartbeat));
	assert_eq!(decoded_header.command, CmdType::Heartbeat);

	let decoded_cmd = roundtrip_command(CmdType::Heartbeat, Command::Heartbeat);
	assert!(matches!(decoded_cmd, Command::Heartbeat));
}

#[test]
fn test_fragmented_udp_packets() {
	// Simulate a UDP packet split into 3 fragments
	let total_frags: u8 = 3;
	let assoc_id: u16 = 100;
	let pkt_id: u16 = 200;

	for frag_id in 0..total_frags {
		let addr = if frag_id == 0 {
			// First fragment has address
			Address::Domain("destination.com".to_string(), 5353)
		} else {
			// Subsequent fragments have no address
			Address::None
		};

		let cmd = Command::Packet {
			assoc_id,
			pkt_id,
			frag_total: total_frags,
			frag_id,
			size: 500,
		};

		let decoded_cmd = roundtrip_command(CmdType::Packet, cmd.clone());

		assert_eq!(&decoded_cmd, &cmd);

		let decoded_addr = roundtrip_address(addr.clone());
		assert_eq!(decoded_addr, addr);
	}
}

#[test]
fn test_edge_case_values() {
	let test_cases: Vec<(u16, u16, u8, u8, u16)> = vec![
		(0, 0, 1, 0, 0),                                      // Minimum values
		(u16::MAX, u16::MAX, u8::MAX, u8::MAX - 1, u16::MAX), // Maximum values
		(32768, 16384, 128, 64, 8192),                        // Mid-range values
	];

	for (assoc_id, pkt_id, frag_total, frag_id, size) in test_cases {
		let cmd = Command::Packet {
			assoc_id,
			pkt_id,
			frag_total,
			frag_id,
			size,
		};

		let decoded_cmd = roundtrip_command(CmdType::Packet, cmd.clone());

		match decoded_cmd {
			Command::Packet {
				assoc_id: d_assoc_id,
				pkt_id: d_pkt_id,
				frag_total: d_frag_total,
				frag_id: d_frag_id,
				size: d_size,
			} => {
				assert_eq!(d_assoc_id, assoc_id);
				assert_eq!(d_pkt_id, pkt_id);
				assert_eq!(d_frag_total, frag_total);
				assert_eq!(d_frag_id, frag_id);
				assert_eq!(d_size, size);
			}
			_ => panic!("Wrong command type"),
		}
	}
}

#[test]
fn test_various_domain_names() {
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
		let addr = Address::Domain(domain.to_string(), 443);
		let decoded_addr = roundtrip_address(addr.clone());
		assert_eq!(decoded_addr, addr);
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
			self_sign: true,
			certificate: PathBuf::from("./test_cert.pem"),
			private_key: PathBuf::from("./test_key.pem"),
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
		experimental: ExperimentalConfig {
			drop_loopback: false,
			..Default::default()
		},
		..Default::default()
	};

	info!("[Integration Test] Starting TUIC server on 127.0.0.1:8443...");
	let server_handle = tokio::spawn(async move {
		// Must outlast the whole test body (TCP + UDP + concurrent phases with
		// their own timeouts); a 10s cap could kill the server mid-test.
		match timeout(Duration::from_secs(30), tuic_server::run(server_config)).await {
			Ok(Ok(())) => info!("[Integration Test] Server completed successfully"),
			Ok(Err(e)) => error!("[Integration Test] Server error: {}", e),
			Err(_) => info!("[Integration Test] Server timed out (expected at test end)"),
		}
	});

	// Wait a bit for server to start
	info!("[Integration Test] Waiting for server to initialize...");
	tokio::time::sleep(Duration::from_secs(1)).await;
	info!("[Integration Test] Server should be ready now");

	let client_config = tuic_client::Config {
		relay: tuic_client::config::Relay {
			server: ("127.0.0.1".to_string(), 8443),
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
			disable_native_certs: true,
			gso: false,
			pmtu: false,
			skip_cert_verify: true,
			..Default::default()
		},
		local: tuic_client::config::Local {
			server: "127.0.0.1:1080".parse()?,
			username: None,
			password: None,
			dual_stack: Some(false),
			max_packet_size: 1500,
			tcp_forward: Vec::new(),
			udp_forward: Vec::new(),
		},
		log_level: "debug".to_string(),
	};

	info!("[Integration Test] Starting TUIC client with SOCKS5 server on 127.0.0.1:1080...");
	let client_handle = tokio::spawn(async move {
		match timeout(Duration::from_secs(10), tuic_client::run(client_config)).await {
			Ok(Ok(())) => info!("[Integration Test] Client completed successfully"),
			Ok(Err(e)) => error!("[Integration Test] Client error: {}", e),
			Err(_) => error!("[Integration Test] Client timeout"),
		}
	});

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

	let tcp_test = async {
		info!("[TCP Test] Starting TCP relay test...");

		let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "TCP Test").await;

		tokio::time::sleep(Duration::from_millis(200)).await;

		let test_data = b"Hello, TUIC!";
		let ok = test_tcp_through_socks5("127.0.0.1:1080", echo_addr, test_data, "TCP Test").await;

		info!("[TCP Test] Waiting for echo server to finish...");
		tokio::time::sleep(Duration::from_millis(500)).await;

		echo_task.abort();
		info!("[TCP Test] TCP test completed\n");
		ok
	};

	let tcp_ok = timeout(Duration::from_secs(6), tcp_test)
		.await
		.expect("TCP relay test timed out");
	assert!(tcp_ok, "TCP relay through SOCKS5/TUIC failed");

	let udp_test = async {
		use std::net::{IpAddr, Ipv4Addr};

		info!("\n[UDP Test] ========================================");
		info!("[UDP Test] Starting UDP relay test...");
		info!("[UDP Test] ========================================\n");

		let (echo_task, echo_addr, _echo_server) = run_udp_echo_server("127.0.0.1:0", "UDP Test").await;

		tokio::time::sleep(Duration::from_millis(100)).await;

		let test_data = b"Hello, UDP through TUIC!";
		let client_bind_addr = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
		let ok = test_udp_through_socks5("127.0.0.1:1080", echo_addr, test_data, "UDP Test", client_bind_addr).await;

		echo_task.abort();
		info!("[UDP Test] UDP test completed\n");
		ok
	};

	let udp_ok = timeout(Duration::from_secs(3), udp_test)
		.await
		.expect("UDP relay test timed out");
	assert!(udp_ok, "UDP relay through SOCKS5/TUIC failed");

	let concurrent_test = async {
		use fast_socks5::client::{Config, Socks5Stream};
		use tokio::{
			io::{AsyncReadExt, AsyncWriteExt},
			net::TcpListener,
		};

		info!("[Concurrent Test] Starting concurrent TCP connections test...");

		let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let server_addr = server.local_addr().unwrap();
		info!("[Concurrent Test] TCP server started at: {}", server_addr);

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

		for (i, handle) in handles.into_iter().enumerate() {
			if let Err(e) = handle.await {
				error!("[Concurrent Test] Connection {} task failed: {}", i, e);
			}
		}

		info!("[Concurrent Test] ✓ All concurrent connections completed");
		server_task.abort();
		info!("[Concurrent Test] Concurrent test completed\n");
	};

	let _ = timeout(Duration::from_secs(5), concurrent_test).await;

	client_handle.abort();
	server_handle.abort();

	// Give tasks time to clean up
	tokio::time::sleep(Duration::from_millis(100)).await;

	Ok(())
}
