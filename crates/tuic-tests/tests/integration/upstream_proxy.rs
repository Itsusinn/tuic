//! Proxy/outbound lifecycle, startup, rejection and TLS integration checks.

use std::{
	sync::{Arc, atomic::Ordering},
	time::Duration,
};

use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{TcpListener, UdpSocket},
};
use tuic_client::{config::ProxyConfig, plugin::build_quinn_outbound};
#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
use tuic_tests::install_crypto_provider;
use wind_core::{AppContext, FlowContext, Outbound, hooks::Protocol, rule::NetworkType};

use super::proxy_fixture::{LIMIT, Proxy, relay_for, server};

#[cfg(target_os = "linux")]
#[tokio::test]
async fn proxy_association_survives_upstream_port_unreachable() -> eyre::Result<()> {
	tokio::time::timeout(LIMIT, async {
		let upstream = UdpSocket::bind("127.0.0.1:0").await?;
		let target = upstream.local_addr()?;
		let proxy = Proxy::start(target, false).await?;
		let config = proxy.config();
		let control = tokio::net::TcpStream::connect((config.server.0.as_str(), config.server.1)).await?;
		let association = fast_socks5::client::Socks5Datagram::bind_with_password(
			control,
			"127.0.0.1:0",
			"proxy-test-user",
			"proxy-test-password",
		)
		.await?;
		drop(upstream);
		association.send_to(b"while stopped", target).await?;
		// Wait for an actual ICMP error, rather than relying on a restart delay.
		while proxy.unreachable_errors.load(Ordering::SeqCst) == 0 {
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
		let upstream = UdpSocket::bind(target).await?;
		association.send_to(b"after restart", target).await?;
		let mut buffer = [0; 128];
		let (len, peer) = upstream.recv_from(&mut buffer).await?;
		assert_eq!(&buffer[..len], b"after restart");
		upstream.send_to(&buffer[..len], peer).await?;
		let (len, _) = association.recv_from(&mut buffer).await?;
		assert_eq!(&buffer[..len], b"after restart");
		assert_eq!(proxy.associations.load(Ordering::SeqCst), 1);
		drop(association);
		proxy.shutdown().await
	})
	.await?
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
async fn dropping_proxy_outbound_drains_tasks_without_cancelling_parent() -> eyre::Result<()> {
	let (server, cfg, _dir) = server().await?;
	let proxy = Proxy::start(server.local_addr, false).await?;
	let ctx = Arc::new(AppContext::default());
	let outbound = tokio::time::timeout(LIMIT, build_quinn_outbound(ctx.clone(), relay_for(&cfg, proxy.config())?)).await??;
	transfer(outbound.clone()).await?;
	assert_eq!(proxy.associations.load(Ordering::SeqCst), 1);
	assert!(proxy.packets.load(Ordering::SeqCst) > 0 && proxy.replies.load(Ordering::SeqCst) > 0);

	drop(outbound);
	ctx.tasks.close();
	tokio::time::timeout(LIMIT, ctx.tasks.wait()).await?;
	assert!(
		!ctx.token.is_cancelled(),
		"outbound drop must leave the parent context usable"
	);
	proxy.shutdown().await?;
	server.shutdown().await;
	Ok(())
}

#[tokio::test]
async fn proxy_disconnect_does_not_fall_back_to_direct_quic() -> eyre::Result<()> {
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
async fn proxy_startup_is_lazy_for_supported_backends() -> eyre::Result<()> {
	for mode in [
		tuic_client::config::BackendMode::Quinn,
		#[cfg(all(
			target_pointer_width = "64",
			not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
		))]
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

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
#[derive(Debug)]
struct RecordingCertificate {
	key: Arc<rustls::sign::CertifiedKey>,
	names: tokio::sync::mpsc::UnboundedSender<Option<String>>,
}

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
impl rustls::server::ResolvesServerCert for RecordingCertificate {
	fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
		let _ = self.names.send(hello.server_name().map(str::to_owned));
		Some(self.key.clone())
	}
}

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
#[tokio::test]
async fn proxy_preserves_original_sni_and_alpn_in_both_backends() -> eyre::Result<()> {
	install_crypto_provider();
	for mode in [
		tuic_client::config::BackendMode::Quinn,
		#[cfg(all(
			target_pointer_width = "64",
			not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
		))]
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

#[tokio::test]
async fn rejected_proxy_never_dials_the_relay_in_supported_backends() -> eyre::Result<()> {
	for mode in [
		tuic_client::config::BackendMode::Quinn,
		#[cfg(all(
			target_pointer_width = "64",
			not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
		))]
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
