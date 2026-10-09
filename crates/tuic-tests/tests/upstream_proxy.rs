//! Observe actual QUIC traffic at the upstream SOCKS5 UDP association.

#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]

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
	io::{AsyncReadExt, AsyncWriteExt},
	net::{TcpListener, UdpSocket},
	sync::{Mutex, Notify},
	task::JoinHandle,
};
use tokio_util::{
	sync::{CancellationToken, DropGuard},
	task::TaskTracker,
};
use tuic_client::{
	config::{ProxyConfig, Relay},
	plugin::build_quinn_outbound,
};
use tuic_tests::{install_crypto_provider, quinn_server_config};
use wind_core::{AppContext, FlowContext, Outbound, hooks::Protocol, rule::NetworkType};

const LIMIT: Duration = Duration::from_secs(10);
type SessionTask = JoinHandle<eyre::Result<()>>;

struct Proxy {
	addr: SocketAddr,
	associations: Arc<AtomicUsize>,
	packets: Arc<AtomicUsize>,
	replies: Arc<AtomicUsize>,
	disconnect: Arc<Notify>,
	_guard: DropGuard,
	tasks: TaskTracker,
	accept: SessionTask,
	sessions: Arc<Mutex<Vec<SessionTask>>>,
}

impl Proxy {
	async fn start(target: SocketAddr, reject: bool) -> eyre::Result<Self> {
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		let associations = Arc::new(AtomicUsize::new(0));
		let packets = Arc::new(AtomicUsize::new(0));
		let replies = Arc::new(AtomicUsize::new(0));
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
												assert_eq!(destination, TargetAddr::Ip(target));
												peer = Some(source);
												upstream.send(payload).await?;
												packets.fetch_add(1, Ordering::SeqCst);
											},
											packet = upstream.recv(&mut response) => {
												let len = match packet {
													Ok(len) => len,
													// Windows reports ICMP from the brief server restart gap.
													Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => continue,
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
			disconnect,
			_guard,
			tasks,
			accept,
			sessions,
		})
	}

	fn config(&self) -> ProxyConfig {
		ProxyConfig {
			server: (self.addr.ip().to_string(), self.addr.port()),
			username: Some("proxy-test-user".into()),
			password: Some("proxy-test-password".into()),
			udp_buffer_size: 1,
		}
	}

	async fn shutdown(self) -> eyre::Result<()> {
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

async fn server() -> eyre::Result<(tuic_server::ServerGuard, tuic_server::Config, tempfile::TempDir)> {
	install_crypto_provider();
	let dir = tempfile::tempdir()?;
	let cert = rcgen::generate_simple_self_signed(vec!["relay-test.invalid".into()])?;
	let certificate = dir.path().join("cert.pem");
	let private_key = dir.path().join("key.pem");
	std::fs::write(&certificate, cert.cert.pem())?;
	std::fs::write(&private_key, cert.signing_key.serialize_pem())?;
	let mut cfg = quinn_server_config(
		"127.0.0.1:0".parse()?,
		dir.path().into(),
		uuid::Uuid::new_v4(),
		"tuic-test-password",
		false,
	);
	cfg.tls.self_sign = false;
	cfg.tls.certificate = certificate;
	cfg.tls.private_key = private_key;
	let saved = serde_json::to_value(&cfg)?;
	let server = tokio::time::timeout(LIMIT, tuic_server::run(cfg)).await??;
	let mut cfg: tuic_server::Config = serde_json::from_value(saved)?;
	cfg.server = server.local_addr;
	Ok((server, cfg, dir))
}

fn relay_for(cfg: &tuic_server::Config, proxy: ProxyConfig) -> eyre::Result<Relay> {
	let uuid = *cfg.users.keys().next().ok_or_else(|| eyre::eyre!("missing test user"))?;
	Ok(Relay {
		server: ("relay-test.invalid".into(), cfg.server.port()),
		ip: Some(cfg.server.ip()),
		uuid,
		password: Arc::from(b"tuic-test-password".as_slice()),
		certificates: vec![cfg.tls.certificate.clone()],
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

async fn transfer(outbound: Arc<dyn Outbound>) -> eyre::Result<()> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let target = listener.local_addr()?;
	let (mut client, inbound) = tokio::io::duplex(4096);
	let ctx = FlowContext {
		target: target.into(),
		network: NetworkType::Tcp,
		source: None,
		inbound_tag: Arc::from("test"),
		protocol: Protocol::Tunnel,
		user: None,
		inbound_port: None,
		inbound_type: None,
	};
	let forward = outbound.handle_tcp(ctx, Box::new(inbound));
	let echo = async {
		let (mut stream, _) = listener.accept().await?;
		let (mut read, mut write) = stream.split();
		tokio::io::copy(&mut read, &mut write).await?;
		eyre::Ok(())
	};
	let data = async {
		let bytes = vec![0x63; 16384];
		client.write_all(&bytes).await?;
		let mut reply = vec![0; bytes.len()];
		client.read_exact(&mut reply).await?;
		assert_eq!(reply, bytes);
		client.shutdown().await?;
		eyre::Ok(())
	};
	tokio::time::timeout(Duration::from_secs(2), async {
		tokio::try_join!(forward, echo, data).map(|_| ())
	})
	.await??;
	Ok(())
}

#[tokio::test]
async fn authenticated_proxy_carries_quic_and_recovers_association_and_connection() -> eyre::Result<()> {
	let (server, cfg, _dir) = server().await?;
	let proxy = Proxy::start(server.local_addr, false).await?;
	let ctx = Arc::new(AppContext::default());
	let outbound = tokio::time::timeout(LIMIT, build_quinn_outbound(ctx.clone(), relay_for(&cfg, proxy.config())?)).await??;
	transfer(outbound.clone()).await?;
	assert_eq!(proxy.associations.load(Ordering::SeqCst), 1);
	assert!(proxy.packets.load(Ordering::SeqCst) > 0 && proxy.replies.load(Ordering::SeqCst) > 0);

	proxy.disconnect.notify_waiters();
	tokio::time::timeout(LIMIT, async {
		while proxy.associations.load(Ordering::SeqCst) < 2 {
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	})
	.await?;
	// Association recovery must carry traffic, not merely finish a TCP
	// handshake.
	tokio::time::timeout(LIMIT, async {
		while transfer(outbound.clone()).await.is_err() {
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	})
	.await?;

	server.shutdown().await;
	let restarted = tokio::time::timeout(LIMIT, tuic_server::run(cfg)).await??;
	// A fresh server cannot use the old QUIC connection: this requires the
	// TUIC supervisor to authenticate a new one through the recovered proxy.
	tokio::time::timeout(LIMIT, async {
		while transfer(outbound.clone()).await.is_err() {
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	})
	.await?;

	drop(outbound);
	ctx.tasks.close();
	tokio::time::timeout(LIMIT, ctx.tasks.wait()).await?;
	assert!(
		!ctx.token.is_cancelled(),
		"outbound drop must leave the parent context usable"
	);
	proxy.shutdown().await?;
	restarted.shutdown().await;
	Ok(())
}

#[tokio::test]
async fn proxy_rejection_and_disconnect_do_not_fall_back_to_direct_quic() -> eyre::Result<()> {
	// A bound UDP socket observes any accidental direct QUIC dial, without
	// requiring the relay to complete its handshake.
	let target = UdpSocket::bind("127.0.0.1:0").await?;
	let proxy = Proxy::start(target.local_addr()?, true).await?;
	let ctx = Arc::new(AppContext::default());
	let relay = Relay {
		server: (target.local_addr()?.ip().to_string(), target.local_addr()?.port()),
		sni: Some("relay-test.invalid".into()),
		skip_cert_verify: true,
		disable_native_certs: true,
		proxy: Some(proxy.config()),
		alpn: vec![b"h3".to_vec()],
		timeout: Duration::from_millis(100),
		..Default::default()
	};
	assert!(
		tokio::time::timeout(LIMIT, build_quinn_outbound(ctx.clone(), relay))
			.await?
			.is_err()
	);
	let mut packet = [0; 2048];
	assert!(
		tokio::time::timeout(Duration::from_millis(100), target.recv_from(&mut packet))
			.await
			.is_err()
	);
	ctx.tasks.close();
	tokio::time::timeout(LIMIT, ctx.tasks.wait()).await?;
	proxy.shutdown().await?;

	let (server, cfg, _dir) = server().await?;
	let proxy = Proxy::start(server.local_addr, false).await?;
	let ctx = Arc::new(AppContext::default());
	let outbound = build_quinn_outbound(ctx.clone(), relay_for(&cfg, proxy.config())?).await?;
	transfer(outbound.clone()).await?;
	proxy.shutdown().await?;
	// With the association gone, a reachable relay must not make direct
	// traffic succeed while the bridge keeps trying to reconnect.
	assert!(transfer(outbound.clone()).await.is_err());
	assert!(transfer(outbound.clone()).await.is_err());
	drop(outbound);
	ctx.tasks.close();
	tokio::time::timeout(LIMIT, ctx.tasks.wait()).await?;
	server.shutdown().await;
	Ok(())
}

#[tokio::test]
async fn quiche_proxy_is_rejected_even_for_lazy_startup() -> eyre::Result<()> {
	let mut cfg = tuic_client::Config::default();
	cfg.relay.proxy = Some(ProxyConfig::default());
	cfg.relay.backend_mode = tuic_client::config::BackendMode::Quiche;
	assert!(cfg.relay.lazy);
	let error = tuic_client::run(cfg)
		.await
		.err()
		.ok_or_else(|| eyre::eyre!("ignored unsupported proxy"))?;
	assert!(error.to_string().contains("SOCKS5 proxy requires"));
	Ok(())
}
