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
#![cfg(target_pointer_width = "64")]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::Endpoint;
use rustls::{
	DigitallySignedStruct, SignatureScheme,
	client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
	pki_types::{CertificateDer, ServerName, UnixTime},
};
use wind_core::{AbstractInbound, InboundCallback, tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream};
use wind_tuic::quiche::TuicheInboundBuilder;

// ---- a no-op inbound callback (TLS handshake is all we need) --------------

#[derive(Clone)]
struct NoopCallback;

impl InboundCallback for NoopCallback {
	async fn handle_tcpstream(&self, _addr: TargetAddr, _stream: impl AbstractTcpStream + 'static) -> eyre::Result<()> {
		Ok(())
	}

	async fn handle_udpstream(&self, _udp_stream: UdpStream) -> eyre::Result<()> {
		Ok(())
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

/// Connect to `addr`, complete the handshake, and return the served leaf
/// certificate (DER).
async fn fetch_served_cert(endpoint: &Endpoint, addr: SocketAddr) -> Vec<u8> {
	let conn = endpoint
		.connect(addr, "localhost")
		.expect("connect config")
		.await
		.expect("handshake");
	let identity = conn.peer_identity().expect("peer identity present");
	let chain = identity
		.downcast::<Vec<CertificateDer<'static>>>()
		.expect("peer identity is a cert chain");
	let leaf = chain.first().expect("non-empty chain").as_ref().to_vec();
	conn.close(0u32.into(), b"done");
	leaf
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

	let listen: SocketAddr = "127.0.0.1:8468".parse()?;
	let inbound = TuicheInboundBuilder::new()
		.listen_addr(listen)
		.certificate_path(cert_path.to_string_lossy().into_owned())
		.private_key_path(key_path.to_string_lossy().into_owned())
		.build()
		.await?;
	let store = inbound.cert_store();

	tokio::spawn(async move {
		let _ = inbound.listen(&NoopCallback).await;
	});
	tokio::time::sleep(Duration::from_secs(1)).await;

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
	let served_a = fetch_served_cert(&endpoint, listen).await;

	// 2) Rotate to a different certificate B and reconnect.
	let (cert_b, key_b) = self_signed();
	store.update(cert_b.as_bytes(), key_b.as_bytes())?;
	// Small settle so the next handshake observes the swap.
	tokio::time::sleep(Duration::from_millis(200)).await;
	let served_b = fetch_served_cert(&endpoint, listen).await;

	assert_ne!(
		served_a, served_b,
		"served certificate did not change after CertStore::update — hot reload failed"
	);

	endpoint.wait_idle().await;
	Ok(())
}
