//! Certificate hot-reload test for the tokio-quiche (`wind-tuiche`) backend.
//!
//! A `TuicheInbound` is started with a self-signed certificate A. A raw quinn
//! client completes the QUIC/TLS handshake and reads the served leaf
//! certificate via `Connection::peer_identity()`. We then push a *different*
//! certificate B through `CertStore::update` and reconnect: the newly served
//! certificate must change — proving the `ConnectionHook` +
//! `select_certificate` callback path hot-reloads certs into the running
//! listener with no restart.

// These e2e tests drive real QUIC sockets; only *run* them on 64-bit hosts
// (cross-emulated 32-bit test execution is unreliable for networking). The
// quiche backend itself now builds on 32-bit too (see patches/tokio-quiche).
#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]

use std::{
	net::SocketAddr,
	sync::Arc,
	time::{Duration, Instant},
};

use quinn::Endpoint;
use rustls::{
	DigitallySignedStruct, SignatureScheme,
	client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
	pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::time::timeout;
use wind_core::{
	AbstractInbound, Dispatcher, FlowContext, Outbound, RouteAction, Router, tcp::AbstractTcpStream, udp::UdpStream,
};
use wind_tuic::quiche::TuicheInboundBuilder;

/// How long the listener may take to serve the rotated certificate. The swap
/// itself is an in-process atomic store, so this only has to cover the time to
/// observe a handshake — it is a failure budget, not an expected wait.
const RELOAD_DEADLINE: Duration = Duration::from_secs(5);

/// Pause between two observation attempts, so a failed probe cannot spin.
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

// ---- a no-op outbound handler (TLS handshake is all we need) --------------

struct NoopOutbound;

#[async_trait::async_trait]
impl Outbound for NoopOutbound {
	async fn handle_tcp(&self, _ctx: FlowContext, _stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
		Ok(())
	}

	async fn handle_udp(&self, _ctx: FlowContext, _udp_stream: UdpStream) -> eyre::Result<()> {
		Ok(())
	}
}

/// Router that forwards everything to the `"default"` outbound handler.
struct ForwardRouter;

impl Router for ForwardRouter {
	#[allow(clippy::manual_async_fn)]
	fn route(&self, _ctx: &FlowContext) -> impl std::future::Future<Output = eyre::Result<RouteAction>> + Send {
		async { Ok(RouteAction::Forward("default".to_string())) }
	}
}

// ---- an accept-all server-cert verifier that exposes nothing --------------

#[derive(Debug)]
struct SkipVerify;

impl ServerCertVerifier for SkipVerify {
	fn verify_server_cert(
		&self,
		_end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		_message: &[u8],
		_cert: &CertificateDer<'_>,
		_dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		Ok(HandshakeSignatureValid::assertion())
	}

	fn verify_tls13_signature(
		&self,
		_message: &[u8],
		_cert: &CertificateDer<'_>,
		_dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		Ok(HandshakeSignatureValid::assertion())
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		vec![
			SignatureScheme::ECDSA_NISTP256_SHA256,
			SignatureScheme::ECDSA_NISTP384_SHA384,
			SignatureScheme::ED25519,
			SignatureScheme::RSA_PSS_SHA256,
			SignatureScheme::RSA_PSS_SHA384,
			SignatureScheme::RSA_PSS_SHA512,
		]
	}
}

/// Generate a fresh self-signed cert for `localhost`, returning `(cert_pem,
/// key_pem)`.
fn self_signed() -> (String, String) {
	let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
	(c.cert.pem(), c.signing_key.serialize_pem())
}

/// The leaf certificate of a PEM bundle, in DER — the same encoding
/// `peer_identity()` hands back, so a served certificate can be compared
/// against the exact cert that was pushed into the store.
fn leaf_der(cert_pem: &str) -> Vec<u8> {
	rustls_pemfile::certs(&mut cert_pem.as_bytes())
		.next()
		.expect("certificate PEM must contain at least one certificate")
		.expect("certificate PEM must parse")
		.as_ref()
		.to_vec()
}

/// Connect to `addr`, complete the handshake, and return the served leaf
/// certificate (DER).
async fn fetch_served_cert(endpoint: &Endpoint, addr: SocketAddr) -> eyre::Result<Vec<u8>> {
	let conn = endpoint.connect(addr, "localhost").expect("connect config").await?;
	let identity = conn.peer_identity().expect("peer identity present");
	let chain = identity
		.downcast::<Vec<CertificateDer<'static>>>()
		.expect("peer identity is a cert chain");
	let leaf = chain.first().expect("non-empty chain").as_ref().to_vec();
	conn.close(0u32.into(), b"done");
	Ok(leaf)
}

#[tokio::test]
async fn quiche_certificate_hot_reload() -> eyre::Result<()> {
	tuic_tests::install_crypto_provider();

	let dir = std::env::temp_dir().join("wind-tuiche-cert-reload");
	std::fs::create_dir_all(&dir)?;
	let cert_path = dir.join("cert.pem");
	let key_path = dir.join("key.pem");

	// Initial certificate A.
	let (cert_a, key_a) = self_signed();
	std::fs::write(&cert_path, &cert_a)?;
	std::fs::write(&key_path, &key_a)?;

	let (addr_tx, mut addr_rx) = tokio::sync::watch::channel(None::<SocketAddr>);
	let inbound = TuicheInboundBuilder::new()
		.listen_addr("127.0.0.1:0".parse().unwrap())
		.bound_addr(addr_tx)
		.certificate_path(cert_path.to_string_lossy().into_owned())
		.private_key_path(key_path.to_string_lossy().into_owned())
		.build()
		.await?;
	let store = inbound.cert_store();

	let mut dispatcher = Dispatcher::new(ForwardRouter);
	dispatcher.add_handler("default", Arc::new(NoopOutbound));
	tokio::spawn(async move {
		let _ = inbound.listen(&dispatcher).await;
	});

	// Wait for the listener to bind and report its OS-assigned address.
	let listen = addr_rx
		.wait_for(|a| a.is_some())
		.await
		.expect("listener exited before reporting its bound address")
		.expect("wait_for predicate guarantees Some");

	// quinn client that accepts any cert (we only want to read what is served).
	let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
	let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
		.with_protocol_versions(&[&rustls::version::TLS13])?
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(SkipVerify))
		.with_no_client_auth();
	crypto.alpn_protocols = vec![b"h3".to_vec()];
	let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
	let endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
	endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(qcc)));

	// 1) Served cert before rotation.
	let served_a = fetch_served_cert(&endpoint, listen).await?;

	// 2) Rotate to a different certificate B and reconnect.
	let (cert_b, key_b) = self_signed();
	let expected_b = leaf_der(&cert_b);
	assert_ne!(
		served_a, expected_b,
		"the two generated certificates must differ, otherwise this test proves nothing"
	);
	store.update(cert_b.as_bytes(), key_b.as_bytes())?;

	// The swap is an in-process `ArcSwap::store`, so it is visible to the very
	// next handshake. Poll instead of sleeping a fixed slice: a probe may fail
	// transiently, and only the rotated leaf arriving within the budget proves
	// the running listener picked the rotation up with no restart. A listener
	// that keeps serving the old leaf exhausts the budget and fails.
	let deadline = Instant::now() + RELOAD_DEADLINE;
	let mut served_b = None;
	while served_b.is_none() {
		let remaining = deadline.saturating_duration_since(Instant::now());
		if remaining.is_zero() {
			break;
		}
		match timeout(remaining, fetch_served_cert(&endpoint, listen)).await {
			Ok(Ok(leaf)) if leaf == expected_b => served_b = Some(leaf),
			Ok(Ok(_)) => tokio::time::sleep(RETRY_INTERVAL).await,
			Ok(Err(err)) => {
				tracing::debug!("cert reload probe failed, retrying: {err}");
				tokio::time::sleep(RETRY_INTERVAL).await;
			}
			Err(_) => break,
		}
	}
	let served_b = served_b.ok_or_else(|| {
		eyre::eyre!(
			"the served certificate did not become the rotated leaf within {RELOAD_DEADLINE:?} of CertStore::update — hot \
			 reload failed"
		)
	})?;

	// Redundant with the poll's exit condition, but kept as the explicit
	// contract of this test: the listener must serve exactly the rotated leaf.
	assert_eq!(
		served_b, expected_b,
		"the certificate served after CertStore::update is not the rotated leaf"
	);

	endpoint.wait_idle().await;
	Ok(())
}
