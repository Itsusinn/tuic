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
struct EchoTask(JoinHandle<()>);
impl Drop for EchoTask {
	fn drop(&mut self) {
		self.0.abort();
	}
}

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
												assert!(destination == TargetAddr::Ip(target)
													|| destination == TargetAddr::Domain("relay-test.invalid".into(), target.port()));
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
async fn proxy_startup_is_lazy_for_both_backends() -> eyre::Result<()> {
	for mode in [
		tuic_client::config::BackendMode::Quinn,
		tuic_client::config::BackendMode::Quiche,
	] {
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		let mut cfg = tuic_client::Config::default();
		cfg.local.server = "127.0.0.1:0".parse()?;
		cfg.relay.proxy = Some(ProxyConfig {
			server: (addr.ip().to_string(), addr.port()),
			..Default::default()
		});
		cfg.relay.backend_mode = mode;
		let client = tuic_client::run(cfg).await?;
		assert!(
			tokio::time::timeout(Duration::from_millis(50), listener.accept())
				.await
				.is_err()
		);
		client.shutdown().await;
	}
	Ok(())
}

#[derive(Debug)]
struct RecordingCertificate {
	key: Arc<rustls::sign::CertifiedKey>,
	names: tokio::sync::mpsc::UnboundedSender<Option<String>>,
}

impl rustls::server::ResolvesServerCert for RecordingCertificate {
	fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
		let _ = self.names.send(hello.server_name().map(str::to_owned));
		Some(self.key.clone())
	}
}

#[tokio::test]
async fn proxy_preserves_original_sni_and_alpn_in_both_backends() -> eyre::Result<()> {
	install_crypto_provider();
	for mode in [
		tuic_client::config::BackendMode::Quinn,
		tuic_client::config::BackendMode::Quiche,
	] {
		let cert = rcgen::generate_simple_self_signed(vec!["relay-test.invalid".into()])?;
		let provider = rustls::crypto::CryptoProvider::get_default().ok_or_else(|| eyre::eyre!("missing provider"))?;
		let key = provider
			.key_provider
			.load_private_key(rustls::pki_types::PrivateKeyDer::Pkcs8(
				cert.signing_key.serialize_der().into(),
			))?;
		let (names, mut received) = tokio::sync::mpsc::unbounded_channel();
		let mut tls = rustls::ServerConfig::builder()
			.with_no_client_auth()
			.with_cert_resolver(Arc::new(RecordingCertificate {
				key: Arc::new(rustls::sign::CertifiedKey::new(vec![cert.cert.der().clone()], key)),
				names,
			}));
		tls.alpn_protocols = vec![b"h3".to_vec()];
		let endpoint = quinn::Endpoint::server(
			quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls)?)),
			"127.0.0.1:0".parse()?,
		)?;
		let proxy = Proxy::start(endpoint.local_addr()?, false).await?;
		let mut cfg = tuic_client::Config::default();
		cfg.local.server = "127.0.0.1:0".parse()?;
		cfg.relay.server = ("relay-test.invalid".into(), endpoint.local_addr()?.port());
		cfg.relay.proxy = Some(proxy.config());
		cfg.relay.backend_mode = mode;
		cfg.relay.lazy = false;
		cfg.relay.reconnect = false;
		cfg.relay.skip_cert_verify = true;
		cfg.relay.alpn = vec![b"h3".to_vec()];
		cfg.relay.timeout = Duration::from_secs(2);
		let handshake = async {
			let incoming = endpoint.accept().await.ok_or_else(|| eyre::eyre!("recorder closed"))?;
			let connection = incoming.await?;
			let name = received.recv().await.ok_or_else(|| eyre::eyre!("missing ClientHello"))?;
			assert_eq!(name.as_deref(), Some("relay-test.invalid"));
			let handshake = connection
				.handshake_data()
				.ok_or_else(|| eyre::eyre!("missing handshake data"))?;
			let handshake = handshake
				.downcast::<quinn::crypto::rustls::HandshakeData>()
				.map_err(|_| eyre::eyre!("unexpected TLS backend"))?;
			assert_eq!(handshake.protocol.as_deref(), Some(b"h3".as_slice()));
			eyre::Ok(connection)
		};
		let (client, handshake) = tokio::time::timeout(LIMIT, async { tokio::join!(tuic_client::run(cfg), handshake) }).await?;
		// This endpoint records TLS but does not implement TUIC authentication.
		if let Ok(client) = client {
			client.shutdown().await;
		}
		let connection = handshake?;
		connection.close(0u32.into(), b"recorded");
		endpoint.close(0u32.into(), b"recorded");
		proxy.shutdown().await?;
	}
	Ok(())
}

async fn recover_client(client: &tuic_client::ClientGuard) -> eyre::Result<()> {
	tokio::time::timeout(LIMIT, async {
		loop {
			// The shared echo helper accepts one connection, so every retry
			// needs its own server instead of reusing the completed first one.
			let (task, addr) = tuic_tests::run_tcp_echo_server("127.0.0.1:0", "chain reconnect").await;
			let _echo = EchoTask(task);
			if tuic_tests::test_tcp_through_socks5(&client.socks5_addr.to_string(), addr, b"reconnected", "chain reconnect")
				.await
			{
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	})
	.await?;
	Ok(())
}

async fn full_client(mode: tuic_client::config::BackendMode, lazy: bool) -> eyre::Result<()> {
	let (server, cfg, _dir) = server().await?;
	let proxy = Proxy::start(server.local_addr, false).await?;
	let mut relay = relay_for(&cfg, proxy.config())?;
	relay.ip = None; // Only our proxy knows relay-test.invalid; local DNS must never run.
	relay.backend_mode = mode;
	relay.lazy = lazy;
	if mode == tuic_client::config::BackendMode::Quiche {
		relay.skip_cert_verify = true; // Quiche cannot load the temporary custom CA.
		relay.certificates.clear();
		relay.disable_native_certs = false;
	}
	let mut client_cfg = tuic_client::Config {
		relay,
		..Default::default()
	};
	client_cfg.local.server = "127.0.0.1:0".parse()?;
	let client = tokio::time::timeout(LIMIT, tuic_client::run(client_cfg)).await??;
	let (echo, addr) = tuic_tests::run_tcp_echo_server("127.0.0.1:0", "chained TCP").await;
	assert!(
		tokio::time::timeout(
			LIMIT,
			tuic_tests::test_tcp_through_socks5(&client.socks5_addr.to_string(), addr, b"through chain", "chain")
		)
		.await?
	);
	echo.abort();
	let (echo, addr, _guard) = tuic_tests::run_udp_echo_server("127.0.0.1:0", "chained UDP").await;
	assert!(
		tokio::time::timeout(
			LIMIT,
			tuic_tests::test_udp_through_socks5(
				&client.socks5_addr.to_string(),
				addr,
				b"through UDP chain",
				"chain",
				"127.0.0.1:0".parse()?
			)
		)
		.await?
	);
	echo.abort();
	assert!(proxy.packets.load(Ordering::SeqCst) > 0 && proxy.replies.load(Ordering::SeqCst) > 0);
	proxy.disconnect.notify_waiters();
	tokio::time::timeout(LIMIT, async {
		while proxy.associations.load(Ordering::SeqCst) < 2 {
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	})
	.await?;
	// Wait for UDP traffic to migrate to the new proxy association before
	// restarting the server, so its close notification reaches the client.
	recover_client(&client).await?;
	server.shutdown().await;
	let server = tokio::time::timeout(LIMIT, tuic_server::run(cfg)).await??;
	recover_client(&client).await?;
	client.shutdown().await;
	proxy.shutdown().await?;
	server.shutdown().await;
	Ok(())
}

#[tokio::test]
async fn quinn_chain_uses_remote_dns_for_eager_and_lazy_tcp_and_udp() -> eyre::Result<()> {
	for lazy in [false, true] {
		full_client(tuic_client::config::BackendMode::Quinn, lazy).await?;
	}
	Ok(())
}

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
#[tokio::test]
async fn quiche_chain_uses_remote_dns_for_eager_and_lazy_tcp_and_udp() -> eyre::Result<()> {
	for lazy in [false, true] {
		full_client(tuic_client::config::BackendMode::Quiche, lazy).await?;
	}
	Ok(())
}

#[tokio::test]
async fn rejected_proxy_never_dials_the_relay_in_either_backend() -> eyre::Result<()> {
	for mode in [
		tuic_client::config::BackendMode::Quinn,
		tuic_client::config::BackendMode::Quiche,
	] {
		let target = UdpSocket::bind("127.0.0.1:0").await?;
		let proxy = Proxy::start(target.local_addr()?, true).await?;
		let mut cfg = tuic_client::Config::default();
		cfg.local.server = "127.0.0.1:0".parse()?;
		cfg.relay.server = ("relay-test.invalid".into(), target.local_addr()?.port());
		cfg.relay.ip = Some(target.local_addr()?.ip());
		cfg.relay.proxy = Some(proxy.config());
		cfg.relay.backend_mode = mode;
		cfg.relay.lazy = false;
		cfg.relay.timeout = Duration::from_millis(100);
		assert!(tokio::time::timeout(LIMIT, tuic_client::run(cfg)).await?.is_err());
		let mut packet = [0; 2048];
		assert!(
			tokio::time::timeout(Duration::from_millis(100), target.recv_from(&mut packet))
				.await
				.is_err()
		);
		proxy.shutdown().await?;
	}
	Ok(())
}
