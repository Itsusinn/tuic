use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use tokio::time::timeout;
use tracing::{error, info};
use uuid::Uuid;

/// Install the rustls crypto provider (idempotent; safe to call repeatedly).
pub fn install_crypto_provider() {
	#[cfg(feature = "aws-lc-rs")]
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	#[cfg(feature = "ring")]
	let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a `tuic-server` config that uses the tokio-quiche backend with a
/// self-signed certificate.
pub fn quiche_server_config(
	server: SocketAddr,
	data_dir: PathBuf,
	uuid: Uuid,
	password: &str,
	zero_rtt: bool,
) -> tuic_server::Config {
	let mut cfg = tuic_server::Config {
		log_level: tuic_server::config::LogLevel::Debug,
		server,
		users: {
			let mut users = HashMap::new();
			users.insert(uuid, password.to_string());
			users
		},
		tls: tuic_server::config::TlsConfig {
			self_sign: true,
			hostname: "localhost".to_string(),
			..Default::default()
		},
		data_dir,
		zero_rtt_handshake: zero_rtt,
		experimental: tuic_server::config::ExperimentalConfig {
			// Echo servers run on 127.0.0.1, so loopback must be allowed.
			drop_loopback: false,
			drop_private: false,
		},
		..Default::default()
	};
	cfg.backend.mode = tuic_server::config::BackendMode::Quiche;
	cfg.backend.quiche.zero_rtt = zero_rtt;
	cfg
}

/// Build a `tuic-server` config that uses the default quinn backend
/// (`wind-tuic`) with a self-signed certificate.
pub fn quinn_server_config(
	server: SocketAddr,
	data_dir: PathBuf,
	uuid: Uuid,
	password: &str,
	zero_rtt: bool,
) -> tuic_server::Config {
	// Default `BackendMode` is `Quinn`, so leave `backend.mode` untouched. On the
	// quinn backend `zero_rtt_handshake` flows into the inbound's
	// `max_early_data_size`/`into_0rtt()` accept path (see wind-tuic
	// quinn::inbound).
	tuic_server::Config {
		log_level: tuic_server::config::LogLevel::Debug,
		server,
		users: {
			let mut users = HashMap::new();
			users.insert(uuid, password.to_string());
			users
		},
		tls: tuic_server::config::TlsConfig {
			self_sign: true,
			hostname: "localhost".to_string(),
			// The quinn backend passes `tls.alpn` straight through to the QUIC
			// server config (unlike the quiche backend, which forces `h3`), so it
			// must be set explicitly or ALPN negotiation fails against the client's
			// `h3`.
			alpn: vec!["h3".to_string()],
			..Default::default()
		},
		data_dir,
		zero_rtt_handshake: zero_rtt,
		experimental: tuic_server::config::ExperimentalConfig {
			// Echo servers run on 127.0.0.1, so loopback must be allowed.
			drop_loopback: false,
			drop_private: false,
		},
		..Default::default()
	}
}

/// Build a `tuic-client` config (quinn) pointing at a local server.
///
/// The client is always quinn-based regardless of the *server's* backend, so
/// this builder is shared by both [`start_quiche_pair`] and
/// [`start_quinn_pair`].
pub fn tuic_client_config(
	server_port: u16,
	socks_port: u16,
	uuid: Uuid,
	password: &str,
	zero_rtt: bool,
) -> tuic_client::Config {
	tuic_client::Config {
		relay: tuic_client::config::Relay {
			server: ("127.0.0.1".to_string(), server_port),
			uuid,
			password: Arc::from(password.as_bytes().to_vec().into_boxed_slice()),
			ip: None,
			ipstack_prefer: tuic_client::utils::StackPrefer::V4first,
			certificates: Vec::new(),
			udp_relay_mode: tuic_client::utils::UdpRelayMode::Native,
			congestion_control: tuic_client::utils::CongestionControl::Cubic,
			alpn: vec![b"h3".to_vec()],
			zero_rtt_handshake: zero_rtt,
			disable_sni: true,
			disable_native_certs: true,
			gso: false,
			pmtu: false,
			skip_cert_verify: true,
			..Default::default()
		},
		local: tuic_client::config::Local {
			server: format!("127.0.0.1:{socks_port}").parse().unwrap(),
			username: None,
			password: None,
			// `None` (not `Some(false)`): with `Some(false)` the SOCKS5 UDP-associate
			// socket calls `set_only_v6(true)`, which fails with ENOPROTOOPT on the
			// IPv4 associate socket used here (notably on CI runners without IPv6).
			// `None` skips the dual-stack setsockopt entirely.
			dual_stack: None,
			max_packet_size: 1500,
			tcp_forward: Vec::new(),
			udp_forward: Vec::new(),
		},
		log_level: "debug".to_string(),
	}
}

/// Start a quiche-backed `tuic-server` plus a `tuic-client`, waiting for the
/// client's SOCKS5 proxy to come up. Returns the SOCKS5 address.
///
/// NOTE: `tuic_client::run` installs a **process-global** connection
/// (`OnceCell`), so at most one client may run per test process — keep to one
/// client-starting test per `tests/*.rs` file.
pub async fn start_quiche_pair(server_port: u16, socks_port: u16, zero_rtt: bool) -> String {
	install_crypto_provider();

	let uuid = Uuid::new_v4();
	let password = "test_password";
	let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
	let data_dir = std::env::temp_dir().join(format!("wind-tuiche-test-{server_port}"));

	let scfg = quiche_server_config(server_addr, data_dir, uuid, password, zero_rtt);
	tokio::spawn(async move {
		match timeout(Duration::from_secs(20), tuic_server::run(scfg)).await {
			Ok(Ok(())) => info!("[quiche test] server exited ok"),
			Ok(Err(e)) => error!("[quiche test] server error: {e}"),
			Err(_) => info!("[quiche test] server timed out (expected at test end)"),
		}
	});
	tokio::time::sleep(Duration::from_secs(1)).await;

	let ccfg = tuic_client_config(server_port, socks_port, uuid, password, zero_rtt);
	tokio::spawn(async move {
		match timeout(Duration::from_secs(20), tuic_client::run(ccfg)).await {
			Ok(Ok(())) => info!("[quiche test] client exited ok"),
			Ok(Err(e)) => error!("[quiche test] client error: {e}"),
			Err(_) => info!("[quiche test] client timed out (expected at test end)"),
		}
	});
	tokio::time::sleep(Duration::from_secs(2)).await;

	format!("127.0.0.1:{socks_port}")
}

/// Start a quinn-backed `tuic-server` plus a `tuic-client`, waiting for the
/// client's SOCKS5 proxy to come up. Returns the SOCKS5 address. Mirrors
/// [`start_quiche_pair`] but exercises the default quinn backend.
///
/// NOTE: `tuic_client::run` installs a **process-global** connection
/// (`OnceCell`), so at most one client may run per test process — keep to one
/// client-starting test per `tests/*.rs` file.
pub async fn start_quinn_pair(server_port: u16, socks_port: u16, zero_rtt: bool) -> String {
	install_crypto_provider();

	let uuid = Uuid::new_v4();
	let password = "test_password";
	let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
	let data_dir = std::env::temp_dir().join(format!("wind-tuic-quinn-test-{server_port}"));

	let scfg = quinn_server_config(server_addr, data_dir, uuid, password, zero_rtt);
	tokio::spawn(async move {
		match timeout(Duration::from_secs(20), tuic_server::run(scfg)).await {
			Ok(Ok(())) => info!("[quinn test] server exited ok"),
			Ok(Err(e)) => error!("[quinn test] server error: {e}"),
			Err(_) => info!("[quinn test] server timed out (expected at test end)"),
		}
	});
	tokio::time::sleep(Duration::from_secs(1)).await;

	let ccfg = tuic_client_config(server_port, socks_port, uuid, password, zero_rtt);
	tokio::spawn(async move {
		match timeout(Duration::from_secs(20), tuic_client::run(ccfg)).await {
			Ok(Ok(())) => info!("[quinn test] client exited ok"),
			Ok(Err(e)) => error!("[quinn test] client error: {e}"),
			Err(_) => info!("[quinn test] client timed out (expected at test end)"),
		}
	});
	tokio::time::sleep(Duration::from_secs(2)).await;

	format!("127.0.0.1:{socks_port}")
}

pub async fn run_tcp_echo_server(bind_addr: &str, test_name: &str) -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
	use tokio::{
		io::{AsyncReadExt, AsyncWriteExt},
		net::TcpListener,
	};

	let echo_server = TcpListener::bind(bind_addr).await.unwrap();
	let echo_addr = echo_server.local_addr().unwrap();
	info!("[{} Echo Server] Started at: {}", test_name, echo_addr);

	let test_name = test_name.to_string();
	let echo_task = tokio::spawn(async move {
		info!("[{} Echo Server] Waiting for connection...", test_name);
		match timeout(Duration::from_secs(5), echo_server.accept()).await {
			Ok(Ok((mut socket, addr))) => {
				info!("[{} Echo Server] Accepted connection from: {}", test_name, addr);
				let mut buf = vec![0u8; 1024];
				match timeout(Duration::from_secs(3), socket.read(&mut buf)).await {
					Ok(Ok(0)) => {
						info!("[{} Echo Server] Connection closed by client (received 0 bytes)", test_name);
					}
					Ok(Ok(n)) => {
						info!("[{} Echo Server] Received {} bytes: {:?}", test_name, n, &buf[..n]);
						if let Err(e) = socket.write_all(&buf[..n]).await {
							error!("[{} Echo Server] Failed to send response: {}", test_name, e);
						} else {
							info!("[{} Echo Server] Echoed {} bytes back", test_name, n);
						}
					}
					Ok(Err(e)) => {
						error!("[{} Echo Server] Failed to read: {}", test_name, e);
					}
					Err(_) => {
						error!("[{} Echo Server] Timeout waiting for data", test_name);
					}
				}
			}
			Ok(Err(e)) => {
				error!("[{} Echo Server] Failed to accept connection: {}", test_name, e);
			}
			Err(_) => {
				error!(
					"[{} Echo Server] Timeout waiting for connection (no client connected)",
					test_name
				);
			}
		}
	});

	(echo_task, echo_addr)
}

pub async fn run_udp_echo_server(
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
	info!("[{} Echo Server] Started at: {}", test_name, echo_addr);

	let echo_server_clone = echo_server.clone();
	let test_name = test_name.to_string();
	let echo_task = tokio::spawn(async move {
		let mut buf = vec![0u8; 1024];
		info!("[{} Echo Server] Waiting for packets...", test_name);
		match timeout(Duration::from_secs(5), echo_server_clone.recv_from(&mut buf)).await {
			Ok(Ok((n, addr))) => {
				info!("[{} Echo Server] Received {} bytes from {}", test_name, n, addr);
				info!("[{} Echo Server] Data: {:?}", test_name, &buf[..n]);
				if let Err(e) = echo_server_clone.send_to(&buf[..n], addr).await {
					error!("[{} Echo Server] Failed to send response: {}", test_name, e);
				} else {
					info!("[{} Echo Server] Echoed {} bytes back to {}", test_name, n, addr);
				}
			}
			Ok(Err(e)) => {
				error!("[{} Echo Server] Error receiving: {}", test_name, e);
			}
			Err(_) => {
				error!("[{} Echo Server] Timeout waiting for data (no packets received)", test_name);
			}
		}
	});

	(echo_task, echo_addr, echo_server)
}

pub async fn test_tcp_through_socks5(
	socks5_addr: &str,
	target_addr: std::net::SocketAddr,
	test_data: &[u8],
	test_name: &str,
) -> bool {
	use fast_socks5::client::{Config, Socks5Stream};
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	info!("[{}] Connecting to SOCKS5 proxy at {}...", test_name, socks5_addr);
	info!("[{}] Target echo server: {}", test_name, target_addr);

	let stream_result = Socks5Stream::connect(
		socks5_addr.parse::<std::net::SocketAddr>().unwrap(),
		target_addr.ip().to_string(),
		target_addr.port(),
		Config::default(),
	)
	.await;

	match stream_result {
		Ok(mut stream) => {
			info!("[{}] Connected through SOCKS5 proxy to echo server", test_name);
			info!(
				"[{}] Stream info - local: {:?}, peer: {:?}",
				test_name,
				stream.get_socket_ref().local_addr(),
				stream.get_socket_ref().peer_addr()
			);

			info!("[{}] Sending {} bytes: {:?}", test_name, test_data.len(), test_data);

			if let Err(e) = stream.write_all(test_data).await {
				error!("[{}] Failed to send data: {}", test_name, e);
				return false;
			}

			info!("[{}] Data sent successfully", test_name);
			tokio::time::sleep(Duration::from_millis(500)).await;

			let mut buffer = vec![0u8; test_data.len()];
			match timeout(Duration::from_secs(3), stream.read_exact(&mut buffer)).await {
				Ok(Ok(_)) => {
					info!("[{}] Received {} bytes: {:?}", test_name, buffer.len(), &buffer);

					if buffer.as_slice() == test_data {
						info!("[{}] ✓ TCP echo test PASSED - data matches!", test_name);
						true
					} else {
						error!("[{}] ✗ TCP echo test FAILED - data mismatch!", test_name);
						error!("[{}] Expected: {:?}", test_name, test_data);
						error!("[{}] Got: {:?}", test_name, &buffer);
						false
					}
				}
				Ok(Err(e)) => {
					error!("[{}] Failed to read response: {}", test_name, e);
					false
				}
				Err(_) => {
					error!("[{}] Timeout waiting for response", test_name);
					false
				}
			}
		}
		Err(e) => {
			error!("[{}] Failed to connect to SOCKS5 proxy: {}", test_name, e);
			false
		}
	}
}

pub async fn test_udp_through_socks5(
	socks5_addr: &str,
	target_addr: std::net::SocketAddr,
	test_data: &[u8],
	test_name: &str,
	bind_addr: std::net::SocketAddr,
) -> bool {
	use fast_socks5::client::Socks5Datagram;
	use tokio::net::TcpStream;

	info!("[{}] Connecting to SOCKS5 proxy at {}...", test_name, socks5_addr);
	let socks_addr: std::net::SocketAddr = socks5_addr.parse().unwrap();

	info!("[{}] Creating TCP connection to SOCKS5 proxy...", test_name);
	let backing_socket_result = TcpStream::connect(socks_addr).await;

	match backing_socket_result {
		Ok(backing_socket) => {
			info!("[{}] TCP connection to SOCKS5 proxy established", test_name);
			info!(
				"[{}] Local TCP addr: {:?}, Remote TCP addr: {:?}",
				test_name,
				backing_socket.local_addr(),
				backing_socket.peer_addr()
			);

			info!("[{}] Binding UDP socket through SOCKS5 from {}...", test_name, bind_addr);
			let socks_result = Socks5Datagram::bind(backing_socket, bind_addr).await;

			match socks_result {
				Ok(socks) => {
					info!("[{}] UDP association established through SOCKS5", test_name);
					info!("[{}] Test data: {} bytes - {:?}", test_name, test_data.len(), test_data);

					let target_ip = target_addr.ip();
					let target_port = target_addr.port();
					info!("[{}] Sending to target {}:{}...", test_name, target_ip, target_port);

					match socks.send_to(test_data, (target_ip, target_port)).await {
						Ok(sent) => {
							info!("[{}] Successfully sent {} bytes through SOCKS5 proxy", test_name, sent);
							info!("[{}] Waiting for echo response...", test_name);

							let mut buffer = vec![0u8; 1024];
							match timeout(Duration::from_secs(5), socks.recv_from(&mut buffer)).await {
								Ok(Ok((len, addr))) => {
									info!("[{}] Received {} bytes from {:?}", test_name, len, addr);
									info!("[{}] Response data: {:?}", test_name, &buffer[..len]);

									if &buffer[..len] == test_data {
										info!("[{}] ✓ UDP echo test PASSED - data matches!", test_name);
										true
									} else {
										error!("[{}] ✗ UDP echo test FAILED - data mismatch!", test_name);
										error!("[{}] Expected: {:?}", test_name, test_data);
										error!("[{}] Got: {:?}", test_name, &buffer[..len]);
										false
									}
								}
								Ok(Err(e)) => {
									error!("[{}] Failed to receive response: {}", test_name, e);
									false
								}
								Err(_) => {
									error!("[{}] Timeout waiting for response", test_name);
									false
								}
							}
						}
						Err(e) => {
							error!("[{}] Failed to send data: {}", test_name, e);
							false
						}
					}
				}
				Err(e) => {
					error!("[{}] Failed to bind UDP through SOCKS5: {:?}", test_name, e);
					false
				}
			}
		}
		Err(e) => {
			error!("[{}] Failed to connect to SOCKS5 proxy: {:?}", test_name, e);
			false
		}
	}
}

// This server can be used as a proxy for testing TUIC client proxy
// configuration
pub async fn run_socks5_server(
	bind_addr: &str,
	test_name: &str,
	username: Option<&str>,
	password: Option<&str>,
) -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
	use fast_socks5::{
		ReplyError, Socks5Command,
		server::{Socks5ServerProtocol, run_tcp_proxy, run_udp_proxy},
	};
	use tokio::net::TcpListener;

	let listener = TcpListener::bind(bind_addr).await.unwrap();
	let server_addr = listener.local_addr().unwrap();
	info!("[{} SOCKS5 Server] Started at: {}", test_name, server_addr);

	let test_name = test_name.to_string();
	let auth_username = username.map(|s| s.to_string());
	let auth_password = password.map(|s| s.to_string());

	let server_task = tokio::spawn(async move {
		info!("[{} SOCKS5 Server] Waiting for connections...", test_name);

		loop {
			match listener.accept().await {
				Ok((socket, client_addr)) => {
					info!("[{} SOCKS5 Server] Accepted connection from: {}", test_name, client_addr);

					let test_name_clone = test_name.clone();
					let username = auth_username.clone();
					let password = auth_password.clone();

					tokio::spawn(async move {
						// Handle authentication and read command based on configuration
						let result = match (username, password) {
							(Some(u), Some(p)) => {
								info!("[{} SOCKS5 Server] Using password authentication", test_name_clone);
								match Socks5ServerProtocol::accept_password_auth(socket, move |user, pass| {
									user == u && pass == p
								})
								.await
								{
									Ok((proto, _creds)) => proto.read_command().await,
									Err(e) => Err(e),
								}
							}
							_ => {
								info!("[{} SOCKS5 Server] Using no authentication", test_name_clone);
								match Socks5ServerProtocol::accept_no_auth(socket).await {
									Ok(proto) => proto.read_command().await,
									Err(e) => Err(e),
								}
							}
						};

						match result {
							Ok((proto, cmd, target_addr)) => {
								info!(
									"[{} SOCKS5 Server] Command: {:?}, Target: {:?}",
									test_name_clone, cmd, target_addr
								);

								match cmd {
									Socks5Command::TCPConnect => {
										info!("[{} SOCKS5 Server] Handling TCP CONNECT", test_name_clone);
										if let Err(e) = run_tcp_proxy(proto, &target_addr, Duration::from_secs(10), false).await
										{
											error!("[{} SOCKS5 Server] TCP proxy error: {:?}", test_name_clone, e);
										} else {
											info!("[{} SOCKS5 Server] TCP connection completed", test_name_clone);
										}
									}
									Socks5Command::UDPAssociate => {
										info!("[{} SOCKS5 Server] Handling UDP ASSOCIATE request", test_name_clone);

										// Use 127.0.0.1 as the reply address for UDP ASSOCIATE
										let reply_ip = "127.0.0.1".parse().unwrap();
										if let Err(e) = run_udp_proxy(proto, &target_addr, None, reply_ip, None).await {
											error!("[{} SOCKS5 Server] UDP proxy error: {:?}", test_name_clone, e);
										} else {
											info!("[{} SOCKS5 Server] UDP proxy completed", test_name_clone);
										}
									}
									Socks5Command::TCPBind => {
										info!("[{} SOCKS5 Server] TCP BIND not supported", test_name_clone);
										if let Err(e) = proto.reply_error(&ReplyError::CommandNotSupported).await {
											error!("[{} SOCKS5 Server] Failed to send error reply: {:?}", test_name_clone, e);
										}
									}
								}
							}
							Err(e) => {
								error!("[{} SOCKS5 Server] Protocol error: {:?}", test_name_clone, e);
							}
						}
					});
				}
				Err(e) => {
					error!("[{} SOCKS5 Server] Failed to accept connection: {}", test_name, e);
				}
			}
		}
	});

	(server_task, server_addr)
}
