//! End-to-end test for the HTTP/3 masquerade, using **reqwest's HTTP/3 client**
//! as the "prober".
//!
//! A real HTTP/3 GET against the (quinn) `tuic-server` must come back as the
//! reverse-proxied upstream response — proving a non-TUIC client is served like
//! a genuine web server rather than reset. Exercises the whole path: QUIC
//! handshake, first-byte classification (`0x05` vs not), the `h3::quic`
//! adapter, the `h3` server, and the reqwest reverse proxy to the upstream.
//!
//! Opt-in (pulls reqwest's experimental HTTP/3 stack; the `--cfg
//! reqwest_unstable` flag it needs is set by the workspace
//! `.cargo/config.toml`):   cargo test -p tuic-tests --features
//! h3-masquerade-test
#![cfg(all(feature = "h3-masquerade-test", reqwest_unstable, target_pointer_width = "64"))]

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use tokio::{
	io::{AsyncReadExt as _, AsyncWriteExt as _},
	net::TcpListener,
	time::timeout,
};
use tuic_tests::install_crypto_provider;
use uuid::Uuid;

const UPSTREAM_BODY: &str = "wind masquerade upstream OK";

/// A trivial HTTP/1.1 upstream: answers every request with a fixed 200 body.
/// This is what the masquerade reverse-proxies to.
async fn start_upstream() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut sock, _)) = listener.accept().await {
			tokio::spawn(async move {
				// A probe GET has no body, so a single read drains the request line
				// + headers; we don't need to parse it.
				let mut buf = [0u8; 8192];
				let _ = sock.read(&mut buf).await;
				let resp = format!(
					"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
					UPSTREAM_BODY.len(),
					UPSTREAM_BODY
				);
				let _ = sock.write_all(resp.as_bytes()).await;
				let _ = sock.shutdown().await;
			});
		}
	});
	addr
}

#[tokio::test(flavor = "multi_thread")]
async fn masquerade_reverse_proxies_http3_probes() -> eyre::Result<()> {
	install_crypto_provider();

	let upstream = start_upstream().await;

	// Fixed port (matches the repo's other e2e tests) so we can form the client
	// URL before the server reports its address.
	let server_addr: SocketAddr = "127.0.0.1:8471".parse().unwrap();
	let uuid = Uuid::new_v4();

	let cfg = tuic_server::Config {
		log_level: tuic_server::config::LogLevel::Debug,
		server: server_addr,
		users: {
			let mut users = HashMap::new();
			users.insert(uuid, "pw".to_string());
			users
		},
		tls: tuic_server::config::TlsConfig {
			self_sign: true,
			hostname: "localhost".to_string(),
			// The server must advertise the `h3` ALPN for an HTTP/3 client to
			// negotiate at all — this is also what TUIC uses to disguise itself.
			alpn: vec!["h3".to_string()],
			..Default::default()
		},
		masquerade: tuic_server::config::MasqueradeConfig {
			enabled: true,
			upstream: format!("http://{upstream}"),
		},
		data_dir: std::env::temp_dir().join("wind-masquerade-test"),
		experimental: tuic_server::config::ExperimentalConfig {
			drop_loopback: false,
			drop_private: false,
		},
		..Default::default()
	};

	// `run` blocks forever on success; bound it so a hung server can't wedge the
	// test runner, and treat the safety-timeout as "still serving".
	let mut server = tokio::spawn(async move {
		match timeout(Duration::from_secs(20), tuic_server::run(cfg)).await {
			Ok(res) => res,
			Err(_) => Ok(()),
		}
	});

	// Wait for the server to bind. If it instead exits early (e.g. the fixed port
	// is already in use), surface that real error now rather than letting the
	// HTTP/3 request below fail with an opaque 10s timeout.
	tokio::select! {
		joined = &mut server => match joined {
			Ok(Ok(())) => eyre::bail!("tuic-server exited before serving any request"),
			Ok(Err(e)) => eyre::bail!("tuic-server failed to start: {e:?}"),
			Err(e) => eyre::bail!("tuic-server task panicked: {e}"),
		},
		_ = tokio::time::sleep(Duration::from_secs(1)) => {}
	}

	// reqwest as a real HTTP/3 prober. `danger_accept_invalid_certs` because the
	// server uses a self-signed cert; `http3_prior_knowledge` forces h3.
	let client = reqwest::Client::builder()
		.danger_accept_invalid_certs(true)
		.http3_prior_knowledge()
		.build()?;

	let url = format!("https://{server_addr}/some/secret/path?probe=1");
	let res = timeout(
		Duration::from_secs(10),
		client.get(&url).version(http::Version::HTTP_3).send(),
	)
	.await
	.map_err(|_| eyre::eyre!("HTTP/3 request to the masquerade timed out"))??;

	assert_eq!(res.version(), http::Version::HTTP_3, "response must be HTTP/3");
	assert_eq!(res.status(), 200, "masquerade should return the upstream's 200");
	let body = res.text().await?;
	assert_eq!(body, UPSTREAM_BODY, "masquerade must relay the upstream body");

	Ok(())
}
