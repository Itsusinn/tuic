//! End-to-end regression test for issue #117: HTTP/3 camouflage path must
//! stream responses larger than the previously-hard-coded 64 MiB cap without
//! terminating the QUIC stream.
//!
//! Topology:
//!   h3 client (this test)  --QUIC/h3-->  tuic-server (camouflage)
//!                                            |
//!                                            v
//!                                         HTTP/1.1 backend (this test, 80 MiB body)
//!
//! NOTE: tuic-server depends on a forked quinn 0.12, but h3-quinn 0.0.10 only
//! works with crates.io quinn 0.11. The two crates are imported separately
//! (the latter aliased as `quinn_stock` in Cargo.toml) — they're distinct Rust
//! types but interoperate over the QUIC wire.

use std::{
	collections::HashMap,
	net::{Ipv4Addr, SocketAddr},
	path::PathBuf,
	sync::Arc,
	time::Duration,
};

use bytes::Buf;
use eyre::Context;
use http::Request;
use quinn_stock as quinn;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{TcpListener, UdpSocket},
	time::timeout,
};
use tracing::{error, info};
use tuic_server::config::{CamouflageConfig, ExperimentalConfig, TlsConfig};

/// 80 MiB — comfortably past the 64 MiB cap that issue #117 reports.
const PAYLOAD_SIZE: usize = 80 * 1024 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_camouflage_streams_more_than_64mb() -> eyre::Result<()> {
	#[cfg(feature = "aws-lc-rs")]
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	#[cfg(feature = "ring")]
	let _ = rustls::crypto::ring::default_provider().install_default();

	let _ = tracing_subscriber::fmt()
		.with_max_level(tracing::Level::INFO)
		.with_test_writer()
		.try_init();

	// --- 1. backend -------------------------------------------------------
	let backend_port = spawn_http_backend().await?;
	info!("backend listening on 127.0.0.1:{backend_port}");

	// --- 2. tuic-server with camouflage -----------------------------------
	let server_port = pick_unused_udp_port().await?;
	let cfg = tuic_server::Config {
		log_level: tuic_server::config::LogLevel::Info,
		server: format!("127.0.0.1:{server_port}").parse().unwrap(),
		users: HashMap::new(),
		tls: TlsConfig {
			self_sign:   true,
			certificate: PathBuf::new(),
			private_key: PathBuf::new(),
			alpn:        vec!["h3".to_string()],
			hostname:    "localhost".to_string(),
			auto_ssl:    false,
			acme_email:  String::new(),
		},
		camouflage: Some(CamouflageConfig {
			enabled:                 true,
			reverse_proxy_url:       format!("http://127.0.0.1:{backend_port}"),
			reverse_proxy_hostname:  None,
			request_timeout:         Duration::from_secs(60),
			skip_backend_tls_verify: true,
		}),
		data_dir: std::env::temp_dir(),
		quic: tuic_server::config::QuicConfig::default(),
		udp_relay_ipv6: false,
		zero_rtt_handshake: false,
		dual_stack: false,
		experimental: ExperimentalConfig::default(),
		..Default::default()
	};

	tokio::spawn(async move {
		if let Err(e) = tuic_server::run(cfg).await {
			error!("tuic-server exited: {e}");
		}
	});

	// Poll until the server's UDP port answers, with a hard ceiling.
	wait_for_quic_port(server_port).await?;

	// --- 3. h3 client -----------------------------------------------------
	let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();

	let mut client_crypto = rustls::ClientConfig::builder()
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(SkipVerify::new()))
		.with_no_client_auth();
	client_crypto.alpn_protocols = vec![b"h3".to_vec()];

	let client_config = quinn::ClientConfig::new(Arc::new(
		quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).context("quic client config")?,
	));
	let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
	endpoint.set_default_client_config(client_config);

	let conn = endpoint.connect(server_addr, "localhost")?.await?;
	info!("QUIC connected to {server_addr}");

	let h3_conn = h3_quinn::Connection::new(conn);
	let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;
	let drive_handle = tokio::spawn(async move {
		let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
	});

	let req = Request::get("https://localhost/big").body(())?;
	let mut stream = send_request.send_request(req).await?;
	stream.finish().await?;

	let resp = stream.recv_response().await?;
	info!("h3 response status: {}", resp.status());
	assert_eq!(resp.status(), 200, "expected 200 from camouflage proxy");

	// --- 4. drain body and verify size ------------------------------------
	let mut total = 0usize;
	let read = async {
		while let Some(mut chunk) = stream.recv_data().await? {
			let n = chunk.remaining();
			total += n;
			chunk.advance(n);
		}
		Ok::<_, eyre::Report>(())
	};
	timeout(Duration::from_secs(120), read)
		.await
		.context("h3 body recv timed out")??;

	info!("received {total} bytes (expected {PAYLOAD_SIZE})");
	assert_eq!(
		total, PAYLOAD_SIZE,
		"camouflage truncated body before backend EOF — issue #117 regression"
	);

	drop(send_request);
	drive_handle.abort();
	endpoint.close(0u32.into(), b"done");
	Ok(())
}

/// Trivial single-shot HTTP/1.1 server: drains the request, then writes
/// an 80 MiB body in 64 KiB chunks of a deterministic byte pattern.
async fn spawn_http_backend() -> eyre::Result<u16> {
	let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0u16)).await?;
	let port = listener.local_addr()?.port();
	tokio::spawn(async move {
		loop {
			let Ok((mut sock, _)) = listener.accept().await else {
				return;
			};
			tokio::spawn(async move {
				// Drain headers (read until \r\n\r\n or 64 KiB).
				let mut buf = vec![0u8; 8192];
				let mut acc = Vec::with_capacity(4096);
				loop {
					match sock.read(&mut buf).await {
						Ok(0) => return,
						Ok(n) => {
							acc.extend_from_slice(&buf[..n]);
							if acc.windows(4).any(|w| w == b"\r\n\r\n") || acc.len() > 64 * 1024 {
								break;
							}
						}
						Err(_) => return,
					}
				}

				let header = format!(
					"HTTP/1.1 200 OK\r\nContent-Length: {PAYLOAD_SIZE}\r\nContent-Type: \
					 application/octet-stream\r\nConnection: close\r\n\r\n"
				);
				if sock.write_all(header.as_bytes()).await.is_err() {
					return;
				}
				let chunk = vec![0xA5u8; 64 * 1024];
				let mut sent = 0usize;
				while sent < PAYLOAD_SIZE {
					let n = (PAYLOAD_SIZE - sent).min(chunk.len());
					if sock.write_all(&chunk[..n]).await.is_err() {
						return;
					}
					sent += n;
				}
				let _ = sock.shutdown().await;
			});
		}
	});
	Ok(port)
}

async fn pick_unused_udp_port() -> eyre::Result<u16> {
	let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await?;
	Ok(s.local_addr()?.port())
}

/// Give the spawned tuic-server task time to bind its UDP socket. tuic-server
/// initializes synchronously inside `run()` then blocks on `accept()`, so a
/// short fixed wait is enough — the QUIC handshake itself will retry if the
/// first datagram races the bind.
async fn wait_for_quic_port(_port: u16) -> eyre::Result<()> {
	tokio::time::sleep(Duration::from_millis(750)).await;
	Ok(())
}

// ---- skip-verify cert verifier ----------------------------------------------
#[derive(Debug)]
struct SkipVerify {
	provider: Arc<rustls::crypto::CryptoProvider>,
}
impl SkipVerify {
	fn new() -> Self {
		Self {
			provider: rustls::crypto::CryptoProvider::get_default()
				.cloned()
				.unwrap_or_else(|| {
					#[cfg(feature = "aws-lc-rs")]
					{
						Arc::new(rustls::crypto::aws_lc_rs::default_provider())
					}
					#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
					{
						Arc::new(rustls::crypto::ring::default_provider())
					}
				}),
		}
	}
}
impl rustls::client::danger::ServerCertVerifier for SkipVerify {
	fn verify_server_cert(
		&self,
		_: &rustls::pki_types::CertificateDer<'_>,
		_: &[rustls::pki_types::CertificateDer<'_>],
		_: &rustls::pki_types::ServerName<'_>,
		_: &[u8],
		_: rustls::pki_types::UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		_: &[u8],
		_: &rustls::pki_types::CertificateDer<'_>,
		_: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}

	fn verify_tls13_signature(
		&self,
		_: &[u8],
		_: &rustls::pki_types::CertificateDer<'_>,
		_: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		self.provider.signature_verification_algorithms.supported_schemes()
	}
}
