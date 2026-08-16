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

/// Which `tuic-server` backend the pair exercises.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Backend {
	Quinn,
	Quiche,
}

impl Backend {
	fn label(self) -> &'static str {
		match self {
			Backend::Quinn => "quinn",
			Backend::Quiche => "quiche",
		}
	}
}

/// A running `tuic-server` + `tuic-client` pair for integration tests.
///
/// Both processes bind to port `0` — the OS assigns a free port atomically, so
/// there is no bind/unbind race — and report their actually-bound addresses
/// back through the returned guards. `shutdown` cancels both tokens and waits
/// (bounded) for the processes to drain, with a `Drop` guard as a last resort.
pub struct TestPair {
	server: tuic_server::ServerGuard,
	client: tuic_client::ClientGuard,
}

impl TestPair {
	/// Start a `tuic-server` + `tuic-client` pair on OS-assigned loopback
	/// ports.
	pub async fn start(backend: Backend, zero_rtt: bool) -> Self {
		install_crypto_provider();

		let uuid = Uuid::new_v4();
		let password = "test_password";
		// Unique per-test data dir: the server binds to `:0`, so its actual port
		// isn't known until startup returns.
		let data_dir = std::env::temp_dir().join(format!("wind-tuic-test-{}", Uuid::new_v4()));

		let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
		let label = backend.label();
		let scfg = match backend {
			Backend::Quinn => quinn_server_config(server_addr, data_dir, uuid, password, zero_rtt),
			Backend::Quiche => quiche_server_config(server_addr, data_dir, uuid, password, zero_rtt),
		};

		let server = tuic_server::run(scfg)
			.await
			.unwrap_or_else(|e| panic!("[{label} test] tuic-server failed to start: {e:#}"));

		let ccfg = tuic_client_config(server.local_addr.port(), 0, uuid, password, zero_rtt);
		let client = tuic_client::run(ccfg)
			.await
			.unwrap_or_else(|e| panic!("[{label} test] tuic-client failed to start: {e:#}"));

		TestPair { server, client }
	}

	/// The server's actually-bound QUIC address.
	pub fn server_addr(&self) -> SocketAddr {
		self.server.local_addr
	}

	/// The client's SOCKS5 address as `"host:port"` — the format the relay
	/// helpers expect.
	pub fn socks5_addr(&self) -> String {
		self.client.socks5_addr.to_string()
	}

	/// Cancel both processes and wait (bounded) for them to drain.
	pub async fn shutdown(self) {
		self.client.shutdown().await;
		self.server.shutdown().await;
	}
}

/// Start a quiche-backed pair. See [`TestPair::start`].
pub async fn start_quiche_pair(zero_rtt: bool) -> TestPair {
	TestPair::start(Backend::Quiche, zero_rtt).await
}

/// Start a quinn-backed pair. See [`TestPair::start`].
pub async fn start_quinn_pair(zero_rtt: bool) -> TestPair {
	TestPair::start(Backend::Quinn, zero_rtt).await
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
	run_udp_echo_server_sized(bind_addr, test_name, 1024).await
}

/// `run_udp_echo_server` with a caller-sized receive buffer (for >MTU UDP
/// fragmentation tests).
pub async fn run_udp_echo_server_sized(
	bind_addr: &str,
	test_name: &str,
	buf_size: usize,
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
		let mut buf = vec![0u8; buf_size];
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
	test_udp_through_socks5_sized(socks5_addr, target_addr, test_data, test_name, bind_addr, 1024).await
}

/// `test_udp_through_socks5` with a caller-sized receive buffer (for >MTU UDP
/// fragmentation tests).
pub async fn test_udp_through_socks5_sized(
	socks5_addr: &str,
	target_addr: std::net::SocketAddr,
	test_data: &[u8],
	test_name: &str,
	bind_addr: std::net::SocketAddr,
	buf_size: usize,
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

							let mut buffer = vec![0u8; buf_size];
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

// ---------------------------------------------------------------------------
// Low-level helpers for negative / handshake tests.
//
// These bypass the SOCKS5 inbound entirely and drive a `TuicOutbound` directly
// (mirroring `tests/graceful_shutdown.rs`), so a single test binary can
// exercise several distinct failure modes against both backends without the
// "one `tuic_client::run` per process" constraint.
// ---------------------------------------------------------------------------

/// Build low-level `TuicOutboundOpts` against a local server, with the knobs
/// the negative tests need to tweak (TLS verification, ALPN, auth).
pub fn low_level_outbound_opts(
	server_port: u16,
	uuid: Uuid,
	password: &str,
	skip_cert_verify: bool,
	alpn: &[&str],
) -> wind_tuic::quinn::outbound::TuicOutboundOpts {
	use wind_tuic::quinn::outbound::{ReconnectConfig, TuicOutboundOpts};

	let password_bytes: Arc<[u8]> = Arc::from(password.as_bytes());
	TuicOutboundOpts {
		peer_addr: SocketAddr::from(([127, 0, 0, 1], server_port)),
		sni: "localhost".to_string(),
		auth: (uuid, password_bytes),
		zero_rtt_handshake: false,
		heartbeat: Duration::from_secs(30),
		gc_interval: Duration::from_secs(10),
		gc_lifetime: Duration::from_secs(30),
		skip_cert_verify,
		alpn: alpn.iter().map(|s| s.to_string()).collect(),
		// Reconnect is irrelevant here (the supervisor is only started by
		// `start_poll`, which these tests never call); disable it explicitly so
		// a failed handshake cannot accidentally spawn a retry loop.
		reconnect: ReconnectConfig {
			enabled: false,
			..Default::default()
		},
	}
}

/// Drive a single TCP echo round-trip through a low-level `TuicOutbound`
/// (bypassing SOCKS5). Returns `true` iff the echoed bytes match `test_data`
/// within `timeout_dur`; returns `false` on timeout, EOF, or mismatch — the
/// failure signal the negative tests assert on.
pub async fn low_level_tcp_echo(
	outbound: Arc<wind_tuic::quinn::outbound::TuicOutbound>,
	echo_addr: SocketAddr,
	test_data: &[u8],
	timeout_dur: Duration,
) -> bool {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use wind_core::{FlowContext, Outbound, hooks::Protocol, rule::NetworkType, types::TargetAddr};

	let (local, remote) = tokio::io::duplex(8192);
	let target = TargetAddr::IPv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
	let ctx = FlowContext {
		target,
		network: NetworkType::Tcp,
		source: None,
		inbound_tag: "tuic-test".into(),
		protocol: Protocol::Tuic,
		user: None,
		inbound_port: None,
		inbound_type: None,
	};

	let tunnel = tokio::spawn(async move {
		let _ = outbound.handle_tcp(ctx, Box::new(remote)).await;
	});

	let (mut reader, mut writer) = tokio::io::split(local);
	if writer.write_all(test_data).await.is_err() {
		tunnel.abort();
		return false;
	}
	let mut buf = vec![0u8; test_data.len()];
	let echoed = matches!(
		tokio::time::timeout(timeout_dur, reader.read_exact(&mut buf)).await,
		Ok(Ok(_))
	) && buf.as_slice() == test_data;
	tunnel.abort();
	echoed
}

// ---------------------------------------------------------------------------
// Full-stack (SOCKS5) e2e case helpers — used by thin per-backend test files.
// ---------------------------------------------------------------------------

/// Minimal HTTP/1.1 client over a raw TCP stream, enough for the local
/// RESTful API (`/kick`, `/traffic`). Returns the response body (asserts HTTP
/// 200).
pub async fn restful_request(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> String {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	let mut stream = timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
		.await
		.expect("connect to restful api")
		.expect("tcp connect");
	let mut request =
		format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAccept: application/json\r\nConnection: close\r\n");
	if let Some(b) = body {
		request.push_str("Content-Type: application/json\r\n");
		request.push_str(&format!("Content-Length: {}\r\n", b.len()));
	}
	request.push_str("\r\n");
	if let Some(b) = body {
		request.push_str(b);
	}
	stream.write_all(request.as_bytes()).await.expect("write request");
	let mut buf = Vec::new();
	stream.read_to_end(&mut buf).await.expect("read response");
	let response = String::from_utf8_lossy(&buf);
	assert!(
		response.starts_with("HTTP/1.1 200"),
		"unexpected status in response: {response}"
	);
	response.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&response).trim().to_string()
}

/// Full-stack reconnect E2E: server (RESTful enabled) + client with
/// `reconnect` on. Prove a TCP echo works, kick the user to drop the live
/// connection, then poll until a fresh echo succeeds — proving the client
/// supervisor re-established the QUIC connection and resumed relaying.
pub async fn reconnect_case(backend: Backend) {
	install_crypto_provider();

	let uuid = Uuid::new_v4();
	let password = "test_password";
	let data_dir = std::env::temp_dir().join(format!("wind-tuic-reconnect-{}", Uuid::new_v4()));

	let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
	let mut scfg = match backend {
		Backend::Quinn => quinn_server_config(server_addr, data_dir, uuid, password, false),
		Backend::Quiche => quiche_server_config(server_addr, data_dir, uuid, password, false),
	};
	scfg.restful.enabled = true;
	scfg.restful.addr = "127.0.0.1:0".parse().unwrap();
	scfg.restful.secret = String::new();

	let server = tuic_server::run(scfg).await.expect("reconnect test server failed to start");
	let restful_addr = server.restful_addr.expect("RESTful API should report its bound address");

	let mut ccfg = tuic_client_config(server.local_addr.port(), 0, uuid, password, false);
	ccfg.relay.reconnect = true;
	ccfg.relay.reconnect_initial_backoff = Duration::from_millis(100);
	ccfg.relay.reconnect_max_backoff = Duration::from_millis(500);
	let client = tuic_client::run(ccfg).await.expect("reconnect test client failed to start");
	let socks5 = client.socks5_addr.to_string();

	// 1. Initial echo proves the connection + auth work.
	let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "reconnect-before").await;
	tokio::time::sleep(Duration::from_millis(200)).await;
	let ok = test_tcp_through_socks5(&socks5, echo_addr, b"before-kick", "reconnect-before").await;
	assert!(ok, "initial TCP echo must succeed before the kick");
	echo_task.abort();

	// 2. Kick the user to drop the live QUIC connection.
	let kick_body = restful_request(restful_addr, "POST", "/kick", Some(&format!("[\"{uuid}\"]"))).await;
	let kicked: serde_json::Value = serde_json::from_str(&kick_body).expect("valid kick JSON");
	assert!(kicked["kicked"].as_u64().unwrap_or(0) > 0, "kick must hit the live connection, got: {kick_body}");

	// 3. Poll a fresh echo until the supervisor reconnects and relay recovers.
	let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
	loop {
		let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "reconnect-after").await;
		tokio::time::sleep(Duration::from_millis(200)).await;
		let ok = test_tcp_through_socks5(&socks5, echo_addr, b"after-kick", "reconnect-after").await;
		echo_task.abort();
		if ok {
			break;
		}
		assert!(
			tokio::time::Instant::now() < deadline,
			"client must auto-reconnect and relay data after the connection was kicked"
		);
		tokio::time::sleep(Duration::from_millis(200)).await;
	}

	client.shutdown().await;
	server.shutdown().await;
}

/// Full-stack >MTU UDP fragmentation/reassembly E2E: send a UDP payload larger
/// than the QUIC max datagram size through the SOCKS5 proxy, forcing the
/// client to fragment it (`UdpStream::send_fragmented_packet`) and the server
/// to reassemble it (`FragmentReassemblyBuffer`), and the reverse on the echo
/// return path. The echoed payload must round-trip intact.
pub async fn udp_fragmentation_case(backend: Backend) {
	install_crypto_provider();

	let uuid = Uuid::new_v4();
	let password = "test_password";
	let data_dir = std::env::temp_dir().join(format!("wind-tuic-udpfrag-{}", Uuid::new_v4()));

	let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
	let scfg = match backend {
		Backend::Quinn => quinn_server_config(server_addr, data_dir, uuid, password, false),
		Backend::Quiche => quiche_server_config(server_addr, data_dir, uuid, password, false),
	};
	let server = tuic_server::run(scfg)
		.await
		.expect("udp fragmentation test server failed to start");

	let ccfg = tuic_client_config(server.local_addr.port(), 0, uuid, password, false);
	let client = tuic_client::run(ccfg)
		.await
		.expect("udp fragmentation test client failed to start");
	let socks5 = client.socks5_addr.to_string();

	// 4000 bytes comfortably exceeds the QUIC max datagram size (~1200 B), so
	// the client must fragment and the server must reassemble.
	let payload: Vec<u8> = (0..4000).map(|i| (i % 251) as u8).collect();
	let (echo_task, echo_addr, _echo_server) = run_udp_echo_server_sized("127.0.0.1:0", "udp-frag", 65536).await;
	tokio::time::sleep(Duration::from_millis(200)).await;

	let bind_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
	let ok = timeout(
		Duration::from_secs(15),
		test_udp_through_socks5_sized(&socks5, echo_addr, &payload, "udp-frag", bind_addr, 65536),
	)
	.await
	.unwrap_or(false);

	echo_task.abort();
	assert!(ok, ">MTU UDP payload must round-trip through fragmentation/reassembly");

	client.shutdown().await;
	server.shutdown().await;
}
