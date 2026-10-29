//! Observe actual QUIC traffic at the upstream SOCKS5 UDP association.

use std::{
	net::SocketAddr,
	sync::{
		Arc,
		atomic::{AtomicUsize, Ordering},
	},
	time::Duration,
};

use fast_socks5::{Socks5Command, server::Socks5ServerProtocol, util::target_addr::TargetAddr};
use tokio::{
	io::AsyncReadExt,
	net::{TcpListener, UdpSocket},
	sync::{Mutex, Notify},
	task::JoinHandle,
};
use tokio_util::{
	sync::{CancellationToken, DropGuard},
	task::TaskTracker,
};
use tuic_client::config::{ProxyConfig, Relay};
use tuic_tests::{install_crypto_provider, quinn_server_config};


pub const LIMIT: Duration = Duration::from_secs(10);
type SessionTask = JoinHandle<eyre::Result<()>>;
pub struct Proxy {
	addr: SocketAddr,
	pub associations: Arc<AtomicUsize>,
	pub packets: Arc<AtomicUsize>,
	pub replies: Arc<AtomicUsize>,
	pub unreachable_errors: Arc<AtomicUsize>,
	pub disconnect: Arc<Notify>,
	_guard: DropGuard,
	tasks: TaskTracker,
	accept: SessionTask,
	sessions: Arc<Mutex<Vec<SessionTask>>>,
}

impl Proxy {
	pub async fn start(target: SocketAddr, reject: bool) -> eyre::Result<Self> {
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		let associations = Arc::new(AtomicUsize::new(0));
		let packets = Arc::new(AtomicUsize::new(0));
		let replies = Arc::new(AtomicUsize::new(0));
		let unreachable_errors = Arc::new(AtomicUsize::new(0));
		let disconnect = Arc::new(Notify::new());
		let tasks = TaskTracker::new();
		let token = CancellationToken::new();
		let _guard = token.clone().drop_guard();
		let sessions = Arc::new(Mutex::new(Vec::new()));
		let accept = tasks.spawn({
			let tasks = tasks.clone();
			let token = token.clone();
			let associations = associations.clone();
			let packets = packets.clone();
			let replies = replies.clone();
			let unreachable_errors = unreachable_errors.clone();
			let disconnect = disconnect.clone();
			let sessions = sessions.clone();
			async move {
				loop {
					let accepted = tokio::select! {
						_ = token.cancelled() => return eyre::Ok(()),
						result = listener.accept() => result,
					};
					let (stream, _) = accepted?;
					let token = token.clone();
					let associations = associations.clone();
					let packets = packets.clone();
					let replies = replies.clone();
					let unreachable_errors = unreachable_errors.clone();
					let disconnect = disconnect.clone();
					let task = tasks.spawn(async move {
						tokio::select! {
							_ = token.cancelled() => eyre::Ok(()),
							result = async move {
								let result = async {
									let (proto, _) = Socks5ServerProtocol::accept_password_auth(stream, move |user, pass| !reject && user == "proxy-test-user" && pass == "proxy-test-password").await?;
									let (proto, command, _) = proto.read_command().await?;
									assert_eq!(command, Socks5Command::UDPAssociate);
									let relay = UdpSocket::bind("127.0.0.1:0").await?;
									let upstream = UdpSocket::bind("127.0.0.1:0").await?;
									upstream.connect(target).await?;
									let reply = SocketAddr::from(([0, 0, 0, 0], relay.local_addr()?.port()));
									let mut control = proto.reply_success(reply).await?;
									associations.fetch_add(1, Ordering::SeqCst);
									let mut request = vec![0; 65536];
									let mut response = vec![0; 65536];
									let mut peer = None;
									loop {
										tokio::select! {
											_ = disconnect.notified() => return eyre::Ok(()),
											_ = control.read_u8() => return Ok(()),
											packet = relay.recv_from(&mut request) => {
												let (len, source) = packet?;
												let (frag, destination, payload) = fast_socks5::parse_udp_request(&request[..len]).await?;
												assert_eq!(frag, 0);
												assert!(destination == TargetAddr::Ip(target)
													|| destination == TargetAddr::Domain("relay-test.invalid".into(), target.port()));
												peer = Some(source);
												match upstream.send(payload).await {
													Ok(_) => {},
													// A pending ICMP error can also surface on send.
													Err(error) if upstream_port_unreachable(&error) => {
														unreachable_errors.fetch_add(1, Ordering::SeqCst);
														continue;
													},
													Err(error) => return Err(error.into()),
												}
												packets.fetch_add(1, Ordering::SeqCst);
											},
											packet = upstream.recv(&mut response) => {
												let len = match packet {
													Ok(len) => len,
													// A server restart can produce ICMP port-unreachable:
													// ConnectionRefused on Linux, ConnectionReset on Windows.
													Err(error) if upstream_port_unreachable(&error) => {
														unreachable_errors.fetch_add(1, Ordering::SeqCst);
														continue;
													},
													Err(error) => return Err(error.into()),
												};
												if let Some(peer) = peer {
													let mut packet = fast_socks5::new_udp_header(target)?;
													packet.extend_from_slice(&response[..len]);
													relay.send_to(&packet, peer).await?;
													replies.fetch_add(1, Ordering::SeqCst);
												}
											},
										}
									}
								}.await;
								// Rejection is intentional; unexpected errors must fail the test.
								if reject { Ok(()) } else { result }
							} => result,
						}
					});
					sessions.lock().await.push(task);
				}
			}
		});
		Ok(Self {
			addr,
			associations,
			packets,
			replies,
			unreachable_errors,
			disconnect,
			_guard,
			tasks,
			accept,
			sessions,
		})
	}

	pub fn config(&self) -> ProxyConfig {
		ProxyConfig {
			server: (self.addr.ip().to_string(), self.addr.port()),
			username: Some("proxy-test-user".into()),
			password: Some("proxy-test-password".into()),
			udp_buffer_size: 1,
		}
	}

	pub async fn shutdown(self) -> eyre::Result<()> {
		self._guard.disarm().cancel();
		self.tasks.close();
		tokio::time::timeout(LIMIT, self.tasks.wait()).await?;
		self.accept.await??;
		for session in std::mem::take(&mut *self.sessions.lock().await) {
			// Propagate both returned errors and background panics into this
			// test.
			session.await??;
		}
		Ok(())
	}
}

fn upstream_port_unreachable(error: &std::io::Error) -> bool {
	matches!(
		error.kind(),
		std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
	)
}

pub async fn server() -> eyre::Result<(tuic_server::ServerGuard, tuic_server::Config, tempfile::TempDir)> {
	install_crypto_provider();
	let dir = tempfile::tempdir()?;
	let cfg = quinn_server_config(
		"127.0.0.1:0".parse()?,
		dir.path().into(),
		uuid::Uuid::new_v4(),
		"tuic-test-password",
		false,
	);
	#[cfg(all(
		target_pointer_width = "64",
		not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
	))]
	let cfg = {
		let mut cfg = cfg;
		let cert = rcgen::generate_simple_self_signed(vec!["relay-test.invalid".into()])?;
		let certificate = dir.path().join("cert.pem");
		let private_key = dir.path().join("key.pem");
		std::fs::write(&certificate, cert.cert.pem())?;
		std::fs::write(&private_key, cert.signing_key.serialize_pem())?;
		cfg.tls.self_sign = false;
		cfg.tls.certificate = certificate;
		cfg.tls.private_key = private_key;
		cfg
	};
	let saved = serde_json::to_value(&cfg)?;
	let server = tokio::time::timeout(LIMIT, tuic_server::run(cfg)).await??;
	let mut cfg: tuic_server::Config = serde_json::from_value(saved)?;
	cfg.server = server.local_addr;
	Ok((server, cfg, dir))
}

pub fn relay_for(cfg: &tuic_server::Config, proxy: ProxyConfig) -> eyre::Result<Relay> {
	let uuid = *cfg.users.keys().next().ok_or_else(|| eyre::eyre!("missing test user"))?;
	Ok(Relay {
		server: ("relay-test.invalid".into(), cfg.server.port()),
		ip: Some(cfg.server.ip()),
		uuid,
		password: Arc::from(b"tuic-test-password".as_slice()),
		certificates: if cfg!(all(
			target_pointer_width = "64",
			not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
		)) {
			vec![cfg.tls.certificate.clone()]
		} else {
			Vec::new()
		},
		skip_cert_verify: !cfg!(all(
			target_pointer_width = "64",
			not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
		)),
		disable_native_certs: true,
		alpn: vec![b"h3".to_vec()],
		proxy: Some(proxy),
		heartbeat: Duration::from_millis(100),
		timeout: Duration::from_secs(2),
		reconnect_initial_backoff: Duration::from_millis(20),
		reconnect_max_backoff: Duration::from_millis(100),
		..Default::default()
	})
}
