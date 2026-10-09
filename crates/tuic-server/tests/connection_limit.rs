//! Exercise the configured admission limit through real TUIC authentication.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use quinn::{Connection, Endpoint};
use tokio::{io::AsyncReadExt, time::timeout};
use tuic_server::ServerGuard;
use uuid::Uuid;

const TIMEOUT: Duration = Duration::from_secs(5);

struct Harness {
	server: ServerGuard,
	endpoint: Endpoint,
	user: Uuid,
	password: String,
	_cert_dir: tempfile::TempDir,
}

impl Harness {
	async fn new(maximum: usize, restful: bool) -> eyre::Result<Self> {
		#[cfg(feature = "aws-lc-rs")]
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		#[cfg(feature = "ring")]
		let _ = rustls::crypto::ring::default_provider().install_default();
		let cert_dir = tempfile::tempdir()?;
		let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
		let certificate = cert_dir.path().join("cert.pem");
		let private_key = cert_dir.path().join("key.pem");
		std::fs::write(&certificate, cert.cert.pem())?;
		std::fs::write(&private_key, cert.signing_key.serialize_pem())?;
		let user = Uuid::new_v4();
		let password = Uuid::new_v4().to_string();
		let mut cfg = tuic_server::Config {
			server: SocketAddr::from(([127, 0, 0, 1], 0)),
			users: HashMap::from([(user, password.clone())]),
			..Default::default()
		};
		cfg.tls.certificate = certificate;
		cfg.tls.private_key = private_key;
		cfg.tls.alpn = vec!["h3".into()];
		cfg.restful.enabled = restful;
		cfg.restful.addr = SocketAddr::from(([127, 0, 0, 1], 0));
		cfg.restful.maximum_clients_per_user = maximum;
		cfg.experimental.drop_loopback = false;
		cfg.experimental.drop_private = false;
		let mut roots = rustls::RootCertStore::empty();
		roots.add(rustls::pki_types::CertificateDer::from(cert.cert))?;
		let mut tls = rustls::ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		tls.alpn_protocols = vec![b"h3".to_vec()];
		let endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))?;
		endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
			quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
		)));
		let server = timeout(TIMEOUT, tuic_server::run(cfg)).await??;
		Ok(Self {
			server,
			endpoint,
			user,
			password,
			_cert_dir: cert_dir,
		})
	}

	async fn authenticate(&self) -> eyre::Result<Connection> {
		let connection = timeout(TIMEOUT, self.endpoint.connect(self.server.local_addr, "localhost")?).await??;
		let mut token = [0; 32];
		connection
			.export_keying_material(&mut token, self.user.as_bytes(), self.password.as_bytes())
			.map_err(|e| eyre::eyre!("export authentication token: {e:?}"))?;
		let mut frame = vec![wind_tuic::proto::VER, wind_tuic::proto::CmdType::Auth.into()];
		frame.extend_from_slice(self.user.as_bytes());
		frame.extend_from_slice(&token);
		let mut stream = timeout(TIMEOUT, connection.open_uni()).await??;
		timeout(TIMEOUT, stream.write_all(&frame)).await??;
		stream.finish()?;
		Ok(connection)
	}

	async fn wait_online(&self, expected: u64) -> eyre::Result<()> {
		let api = self.server.restful_addr.ok_or_else(|| eyre::eyre!("missing RESTful API"))?;
		let client = reqwest::Client::new();
		timeout(TIMEOUT, async {
			loop {
				let body = client.get(format!("http://{api}/online")).send().await?.text().await?;
				let body: serde_json::Value = serde_json::from_str(&body)?;
				if body[self.user.to_string()].as_u64().unwrap_or(0) == expected {
					return Ok::<_, eyre::Report>(());
				}
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await?
	}
}

impl Drop for Harness {
	fn drop(&mut self) {
		self.endpoint.close(0u32.into(), b"test finished");
		self.server.cancel.cancel();
	}
}

/// TCP round trip acknowledges that the server has actually admitted auth.
async fn assert_admitted(connection: &Connection) -> eyre::Result<()> {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let port = listener.local_addr()?.port();
	let forward = async {
		let (mut send, mut recv) = connection.open_bi().await?;
		let mut frame = vec![
			wind_tuic::proto::VER,
			wind_tuic::proto::CmdType::Connect.into(),
			wind_tuic::proto::AddressType::IPv4.into(),
			127,
			0,
			0,
			1,
		];
		frame.extend_from_slice(&port.to_be_bytes());
		frame.push(42);
		send.write_all(&frame).await?;
		let mut marker = [0];
		recv.read_exact(&mut marker).await?;
		send.finish()?;
		assert_eq!(marker, [42]);
		Ok::<_, eyre::Report>(())
	};
	let echo = async {
		let (mut stream, _) = listener.accept().await?;
		let marker = stream.read_u8().await?;
		tokio::io::AsyncWriteExt::write_all(&mut stream, &[marker]).await?;
		Ok::<_, eyre::Report>(())
	};
	timeout(TIMEOUT, async { tokio::try_join!(forward, echo) }).await??;
	Ok(())
}

#[tokio::test]
async fn configured_connection_limit_rejects_excess_and_releases_on_disconnect() -> eyre::Result<()> {
	let harness = Harness::new(1, true).await?;
	let first = harness.authenticate().await?;
	assert_admitted(&first).await?;
	harness.wait_online(1).await?;
	let rejected = harness.authenticate().await?;
	let error = timeout(TIMEOUT, rejected.closed()).await?;
	assert!(matches!(error, quinn::ConnectionError::ApplicationClosed(ref close) if close.reason == b"rejected"[..]));
	harness.wait_online(1).await?;
	first.close(0u32.into(), b"release slot");
	harness.wait_online(0).await?;
	let replacement = harness.authenticate().await?;
	assert_admitted(&replacement).await?;
	harness.wait_online(1).await?;
	Ok(())
}

#[tokio::test]
async fn configured_connection_limit_works_without_restful_listener() -> eyre::Result<()> {
	let harness = Harness::new(1, false).await?;
	assert!(harness.server.restful_addr.is_none());
	let first = harness.authenticate().await?;
	assert_admitted(&first).await?;
	let rejected = harness.authenticate().await?;
	let error = timeout(TIMEOUT, rejected.closed()).await?;
	assert!(matches!(error, quinn::ConnectionError::ApplicationClosed(ref close) if close.reason == b"rejected"[..]));
	assert_admitted(&first).await?;
	Ok(())
}

#[tokio::test]
async fn configured_zero_connection_limit_admits_multiple_connections() -> eyre::Result<()> {
	let harness = Harness::new(0, true).await?;
	let first = harness.authenticate().await?;
	let second = harness.authenticate().await?;
	assert_admitted(&first).await?;
	assert_admitted(&second).await?;
	harness.wait_online(2).await?;
	Ok(())
}
