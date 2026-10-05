use std::{
	collections::HashMap,
	net::SocketAddr,
	path::{Path, PathBuf},
	sync::Arc,
	time::Duration,
};

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
	// Default `BackendMode` is `Quinn`, so leave `backend.mode` untouched. On
	// the quinn backend `zero_rtt_handshake` flows into the inbound's
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

/// Build a `tuic-client` config pointing at a local server.
///
/// `client_backend` selects the client's QUIC implementation independently of
/// the server's, so the pair can mix backends (e.g. quinn server + quiche
/// client).
pub fn tuic_client_config(
	server_port: u16,
	socks_port: u16,
	uuid: Uuid,
	password: &str,
	zero_rtt: bool,
	client_backend: Backend,
) -> tuic_client::Config {
	let mut cfg = tuic_client::Config {
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
	};

	cfg.relay.backend_mode = match client_backend {
		Backend::Quinn => tuic_client::config::BackendMode::Quinn,
		Backend::Quiche => tuic_client::config::BackendMode::Quiche,
	};
	cfg.relay.quiche.zero_rtt = zero_rtt;

	cfg
}

/// Which QUIC backend a `tuic-server` / `tuic-client` in the pair exercises.
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

/// A per-test server data directory that creates itself and removes itself when
/// dropped.
///
/// Every integration case writes a freshly minted self-signed certificate into
/// the server's `data_dir`, so the directory has to be unique per case. The
/// same property means it must also be cleaned up: without an owner that
/// deletes it, every run leaves one directory behind per case, forever.
///
/// The guard owns both ends of the lifecycle. `tuic_server::run` takes a
/// `Config` and never calls `parse_config`, so the only thing that would
/// otherwise create the directory is the server itself, and nothing at all
/// removes it. Creating it here also makes the leak checkable by looking at the
/// filesystem instead of trusting an implementation detail.
///
/// Removal happens on `Drop`, which every exit path reaches — including the
/// panics used as assertion failures, because the tests are compiled with
/// unwinding. A caller that wants the directory gone before the guard's scope
/// ends can call [`TempDataDir::cleanup`]. Removal is best-effort: a failure is
/// logged rather than raised, since panicking from `Drop` during an unwinding
/// test would abort the whole binary and hide the original failure.
pub struct TempDataDir {
	path: PathBuf,
}

impl TempDataDir {
	/// Create a unique directory under the system temp dir, named
	/// `<prefix>-<uuid>`, and return a guard that owns it.
	pub fn new(prefix: &str) -> Self {
		Self::with_base(&std::env::temp_dir(), prefix)
	}

	/// Create a unique directory under `base`, named `<prefix>-<uuid>`.
	///
	/// Tests that assert on the on-disk lifecycle pass their own empty `base`
	/// directory, so the assertion cannot observe artifacts left by cases
	/// running in parallel threads or by earlier runs.
	pub fn with_base(base: &Path, prefix: &str) -> Self {
		let path = base.join(format!("{prefix}-{}", Uuid::new_v4()));
		if let Err(e) = std::fs::create_dir_all(&path) {
			panic!("failed to create test data dir {}: {e}", path.display());
		}
		Self { path }
	}

	/// The directory path, for handing to a server config.
	pub fn path(&self) -> &Path {
		&self.path
	}

	/// Remove the directory now. Removing an already-removed or never-created
	/// directory is not an error.
	pub fn cleanup(&self) {
		if let Err(e) = std::fs::remove_dir_all(&self.path) {
			if e.kind() != std::io::ErrorKind::NotFound {
				error!("failed to remove test data dir {}: {e}", self.path.display());
			}
		}
	}
}

impl Drop for TempDataDir {
	fn drop(&mut self) {
		self.cleanup();
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
	/// Declared last so it outlives both guards and removes the directory only
	/// after the two processes driving it have been torn down.
	temp_data_dir: TempDataDir,
}

impl TestPair {
	/// Start a `tuic-server` + `tuic-client` pair on OS-assigned loopback
	/// ports. The client uses the quinn backend.
	pub async fn start(backend: Backend, zero_rtt: bool) -> Self {
		Self::start_with_client(backend, Backend::Quinn, zero_rtt).await
	}

	/// Start a pair with independently selected server and client backends.
	pub async fn start_with_client(server_backend: Backend, client_backend: Backend, zero_rtt: bool) -> Self {
		install_crypto_provider();

		let uuid = Uuid::new_v4();
		let password = "test_password";
		// Unique per-test data dir: the server binds to `:0`, so its actual
		// port isn't known until startup returns. The guard also removes the
		// directory, so it must be declared before the guards whose processes
		// still need the certificate files.
		let data_dir = TempDataDir::new("wind-tuic-test");

		let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
		let label = format!("{}+{}", server_backend.label(), client_backend.label());
		let scfg = match server_backend {
			Backend::Quinn => quinn_server_config(server_addr, data_dir.path().to_path_buf(), uuid, password, zero_rtt),
			Backend::Quiche => quiche_server_config(server_addr, data_dir.path().to_path_buf(), uuid, password, zero_rtt),
		};

		let server = tuic_server::run(scfg)
			.await
			.unwrap_or_else(|e| panic!("[{label} test] tuic-server failed to start: {e:#}"));

		let ccfg = tuic_client_config(server.local_addr.port(), 0, uuid, password, zero_rtt, client_backend);
		let client = tuic_client::run(ccfg)
			.await
			.unwrap_or_else(|e| panic!("[{label} test] tuic-client failed to start: {e:#}"));

		TestPair {
			server,
			client,
			temp_data_dir: data_dir,
		}
	}

	/// The server's actually-bound QUIC address.
	pub fn server_addr(&self) -> SocketAddr {
		self.server.local_addr
	}

	/// The per-test server data directory, kept alive for the pair's lifetime.
	pub fn data_dir(&self) -> &Path {
		self.temp_data_dir.path()
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

/// Start a quinn-server + quiche-client pair, exercising the quiche client.
pub async fn start_quiche_client_pair(zero_rtt: bool) -> TestPair {
	TestPair::start_with_client(Backend::Quinn, Backend::Quiche, zero_rtt).await
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
				// Echo every chunk until the peer half-closes or the read
				// deadline elapses. A single `read` would truncate any payload
				// that does not fit in one buffer or arrives split across TCP
				// segments, so the caller's `read_exact` would only ever see a
				// prefix of what it sent.
				let deadline = std::time::Instant::now() + Duration::from_secs(3);
				loop {
					let remaining = deadline.saturating_duration_since(std::time::Instant::now());
					if remaining.is_zero() {
						error!("[{} Echo Server] Timeout waiting for data", test_name);
						break;
					}
					match timeout(remaining, socket.read(&mut buf)).await {
						Ok(Ok(0)) => {
							info!("[{} Echo Server] Connection closed by client", test_name);
							break;
						}
						Ok(Ok(n)) => {
							info!("[{} Echo Server] Received {} bytes: {:?}", test_name, n, &buf[..n]);
							if let Err(e) = socket.write_all(&buf[..n]).await {
								error!("[{} Echo Server] Failed to send response: {}", test_name, e);
								break;
							}
							info!("[{} Echo Server] Echoed {} bytes back", test_name, n);
						}
						Ok(Err(e)) => {
							error!("[{} Echo Server] Failed to read: {}", test_name, e);
							break;
						}
						Err(_) => {
							error!("[{} Echo Server] Timeout waiting for data", test_name);
							break;
						}
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
		// Answer every datagram the tests send, not just the first one: the
		// SOCKS5 helper retransmits when a datagram is lost before the relay
		// association can carry it, and a one-shot server cannot serve a retry.
		// Callers abort this task once the case is done.
		loop {
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
					break;
				}
				Err(_) => {
					error!("[{} Echo Server] Timeout waiting for data (no packets received)", test_name);
					break;
				}
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

			// Await the echo under the deadline below instead of sleeping
			// first: `read_exact` already waits for the payload to
			// arrive (or fails on timeout), so a fixed pre-read
			// sleep only added that delay to every successful case
			// without making a slow response any more likely to
			// arrive in time.
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

/// Window the UDP relay helper allows for the echoed payload to arrive,
/// retransmitting the request within it.
///
/// A caller that wraps the helper in an outer `timeout` must give it a
/// **strictly larger** deadline, plus room for whatever it does before calling
/// the helper. A tighter outer deadline aborts the relay while the helper is
/// still retransmitting, so a slow relay is reported as an opaque outer
/// timeout instead of the helper's own diagnostic.
pub const UDP_RELAY_RESPONSE_DEADLINE: Duration = Duration::from_secs(5);

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

					// UDP carries no delivery guarantee: a datagram can be lost
					// before the relay association (and the QUIC session behind
					// it) can carry it. Retransmit within one response deadline
					// instead of failing on a single lost datagram; the
					// assertion is unchanged - a payload-identical echo must
					// arrive before the deadline. The echo servers answer every
					// datagram, so the retries can be served.
					const RETRANSMIT_INTERVAL: Duration = Duration::from_millis(500);
					let deadline = tokio::time::Instant::now() + UDP_RELAY_RESPONSE_DEADLINE;
					let mut buffer = vec![0u8; buf_size];
					info!("[{}] Waiting for echo response...", test_name);

					loop {
						if tokio::time::Instant::now() >= deadline {
							error!("[{}] Timeout waiting for response", test_name);
							break false;
						}

						match socks.send_to(test_data, (target_ip, target_port)).await {
							Ok(sent) => {
								info!("[{}] Successfully sent {} bytes through SOCKS5 proxy", test_name, sent);
							}
							Err(e) => {
								error!("[{}] Failed to send data: {}", test_name, e);
								break false;
							}
						}

						let attempt_deadline = deadline.min(tokio::time::Instant::now() + RETRANSMIT_INTERVAL);

						let verdict = match tokio::time::timeout_at(attempt_deadline, socks.recv_from(&mut buffer)).await {
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
								// A lost datagram: retransmit until the
								// deadline.
								continue;
							}
						};
						break verdict;
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
						// Handle authentication and read command based on
						// configuration
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

										// Use 127.0.0.1 as the reply address
										// for UDP ASSOCIATE
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
		peer_resolver: None,
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
		client_config: None,
		congestion_control: wind_tuic::quinn::CongestionControl::Bbr,
		max_concurrent_bi_streams: None,
		max_concurrent_uni_streams: None,
		send_window: None,
		stream_receive_window: None,
		max_idle_time: None,
		udp_relay_mode: wind_tuic::quinn::UdpRelayMode::Native,
		socket_factory: None,
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
	let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAccept: application/json\r\nConnection: close\r\n");
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
	response
		.split_once("\r\n\r\n")
		.map(|(_, b)| b)
		.unwrap_or(&response)
		.trim()
		.to_string()
}

/// Full-stack reconnect E2E: server (RESTful enabled) + client with
/// `reconnect` on. Prove a TCP echo works, kick the user to drop the live
/// connection, then poll until a fresh echo succeeds — proving the client
/// supervisor re-established the QUIC connection and resumed relaying.
pub async fn reconnect_case(backend: Backend) {
	install_crypto_provider();

	let uuid = Uuid::new_v4();
	let password = "test_password";
	// Declared before the server guard so it drops after it: the guard removes
	// the directory only once the server holding the certificate has stopped.
	let data_dir = TempDataDir::new("wind-tuic-reconnect");

	let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
	let mut scfg = match backend {
		Backend::Quinn => quinn_server_config(server_addr, data_dir.path().to_path_buf(), uuid, password, false),
		Backend::Quiche => quiche_server_config(server_addr, data_dir.path().to_path_buf(), uuid, password, false),
	};
	scfg.restful.enabled = true;
	scfg.restful.addr = "127.0.0.1:0".parse().unwrap();
	scfg.restful.secret = String::new();

	let server = tuic_server::run(scfg).await.expect("reconnect test server failed to start");
	let restful_addr = server.restful_addr.expect("RESTful API should report its bound address");

	let mut ccfg = tuic_client_config(server.local_addr.port(), 0, uuid, password, false, Backend::Quinn);
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
	assert!(
		kicked["kicked"].as_u64().unwrap_or(0) > 0,
		"kick must hit the live connection, got: {kick_body}"
	);

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
	// Declared before the server guard so it drops after it: the guard removes
	// the directory only once the server holding the certificate has stopped.
	let data_dir = TempDataDir::new("wind-tuic-udpfrag");

	let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
	let scfg = match backend {
		Backend::Quinn => quinn_server_config(server_addr, data_dir.path().to_path_buf(), uuid, password, false),
		Backend::Quiche => quiche_server_config(server_addr, data_dir.path().to_path_buf(), uuid, password, false),
	};
	let server = tuic_server::run(scfg)
		.await
		.expect("udp fragmentation test server failed to start");

	let ccfg = tuic_client_config(server.local_addr.port(), 0, uuid, password, false, Backend::Quinn);
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

#[cfg(test)]
mod tests {
	use std::{path::Path, time::Duration};

	use tokio::{
		io::{AsyncReadExt, AsyncWriteExt},
		time::timeout,
	};

	use super::{Backend, TempDataDir, TestPair, run_tcp_echo_server};

	/// Count the entries of a directory. Used to prove that a data directory
	/// comes and goes, so the caller passes a directory it owns exclusively.
	fn count_entries(dir: &Path) -> usize {
		std::fs::read_dir(dir).expect("the directory must be readable").count()
	}

	/// Write a file into `dir` so it cannot be mistaken for an empty directory.
	fn seed(dir: &Path) {
		std::fs::write(dir.join("seed.txt"), b"seed").expect("writing into the data dir must succeed");
	}

	/// The echo helper must hand back every byte it received, even when the
	/// payload is bigger than one receive buffer and arrives in several TCP
	/// segments. It used to issue exactly one 1024-byte `read` followed by one
	/// echo, so the peer saw a truncated reply and then EOF.
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn tcp_echo_server_returns_a_payload_larger_than_one_read() {
		let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "split-echo").await;

		// 3000 bytes is roughly three times the helper's receive buffer; each
		// 1500-byte write is itself split by the send/receive boundary so a
		// single read can never observe the whole payload.
		let payload: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
		let mut stream = tokio::net::TcpStream::connect(echo_addr).await.unwrap();
		for chunk in payload.chunks(1500) {
			stream.write_all(chunk).await.unwrap();
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		// Half-close so the echo server observes EOF instead of waiting for its
		// read deadline to expire.
		stream.shutdown().await.unwrap();

		let mut echoed = Vec::new();
		let read = timeout(Duration::from_secs(5), stream.read_to_end(&mut echoed)).await;
		echo_task.abort();

		read.expect("the echo must complete before the deadline")
			.expect("reading the echo must succeed");
		assert_eq!(echoed, payload, "the echo server must return every byte it received");
	}

	/// The per-case server data directory has to be removed again, in both the
	/// normal `Drop` path and after an explicit `cleanup`. It used to be a bare
	/// `PathBuf` under the system temp dir with nothing owning its removal, so
	/// every case leaked one directory (with a generated self-signed
	/// certificate in it) on every run.
	///
	/// Each half of the test runs under its own empty parent directory, so the
	/// assertion cannot observe a data directory created by another case in a
	/// parallel thread or left behind by an earlier run.
	#[test]
	fn a_temp_data_dir_is_deleted_when_its_guard_is_dropped() {
		let base = TempDataDir::new("wind-tuic-test-guard-base");
		let base_path = base.path().to_path_buf();

		{
			let guard = TempDataDir::with_base(&base_path, "case");
			let path = guard.path().to_path_buf();
			seed(&path);
			assert!(path.is_dir(), "{} must exist while the guard is alive", path.display());
			assert_eq!(count_entries(&base_path), 1, "the guard must own exactly one directory");
			drop(guard);
			assert!(!path.exists(), "{} must be gone once the guard is dropped", path.display());
			assert_eq!(count_entries(&base_path), 0, "dropping the guard must remove its directory");
		}

		{
			let guard = TempDataDir::with_base(&base_path, "case");
			let path = guard.path().to_path_buf();
			seed(&path);
			guard.cleanup();
			assert!(
				!path.exists(),
				"{} must be gone right after an explicit cleanup",
				path.display()
			);
			drop(guard);
			assert!(!path.exists(), "{} must stay gone after cleanup", path.display());
			assert_eq!(count_entries(&base_path), 0, "an explicit cleanup must remove it");
		}
	}

	/// End-to-end shape of the same bug: a whole pair's data directory exists
	/// while the pair runs and is gone once the pair has been shut down.
	/// `shutdown` consumes the pair, so its remaining field is released there
	/// rather than at the end of a scope.
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn a_started_pair_leaves_no_data_dir_behind() {
		let pair = TestPair::start(Backend::Quinn, false).await;
		let data_dir = pair.data_dir().to_path_buf();
		seed(&data_dir);
		assert!(data_dir.is_dir(), "{} must exist while the pair runs", data_dir.display());
		pair.shutdown().await;
		assert!(!data_dir.exists(), "{} must be gone after shutdown", data_dir.display());
	}
}
