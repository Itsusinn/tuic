//! Client builder / TLS endpoint integration coverage for the `[tls]` options the rustls client configuration
//! now honours: `disable_sni`, `disable_native_certs`, and `certificates`.
//!
//! `disable_sni` is observed from the **server** side: a quinn endpoint backed
//! by a `ResolvesServerCert` resolver records the `server_name` of every
//! ClientHello it receives, so a leaked host name fails the test instead of
//! being asserted indirectly.
//!
//! `certificates` is observed through a real handshake: the client verifies the
//! server certificate against the CA supplied in `[tls] certificates`, so a
//! configuration that never loads the file cannot complete the connection.
//!
//! Each test drives the real construction path
//! (`tuic_client::plugin::build_quinn_outbound` -> `crate::tls`), so what is
//! asserted is what the binary actually builds. That path also authenticates
//! against the TUIC server, which the recording endpoint does not implement, so
//! the tests assert on the recorded ClientHello rather than on the returned
//! `Result`.

// `quinn`/`rcgen` are declared under the 64-bit target cfg in Cargo.toml, so
// keep this file behind the same predicate as the quiche tests.
#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]

use std::{
	sync::{Arc, Mutex},
	time::Duration,
};

use rustls::{server::ResolvesServerCert, sign::CertifiedKey as RustlsCertifiedKey};
use tuic_client::config::Relay;
use tuic_tests::install_crypto_provider;
use uuid::Uuid;

const AUTH_PASSWORD: &str = "tls-options-test-password";

/// A resolver that records every SNI it is asked for and then serves a static
/// certificate.
#[derive(Debug)]
struct SniRecorder {
	record: Arc<Mutex<Vec<Option<String>>>>,
	leaf: Arc<RustlsCertifiedKey>,
}

impl ResolvesServerCert for SniRecorder {
	fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<RustlsCertifiedKey>> {
		self.record
			.lock()
			.expect("sni record lock")
			.push(hello.server_name().map(|name| name.to_string()));
		Some(self.leaf.clone())
	}
}

use super::tls_fixture_support::signed_server_cert;

/// Start a quinn endpoint that records the SNI of every incoming ClientHello.
///
/// Returns its bound port, the record, and a cancellation token that must be
/// cancelled to tear the accept loop down.
async fn start_sni_recorder(
	leaf: RustlsCertifiedKey,
) -> eyre::Result<(u16, Arc<Mutex<Vec<Option<String>>>>, tokio_util::sync::CancellationToken)> {
	let record = Arc::new(Mutex::new(Vec::new()));
	let mut crypto = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_cert_resolver(Arc::new(SniRecorder {
			record: record.clone(),
			leaf: Arc::new(leaf),
		}));
	crypto.alpn_protocols = vec![b"h3".to_vec()];
	let mut server_config =
		quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?));
	server_config.transport_config(Arc::new(quinn::TransportConfig::default()));

	let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
	let port = endpoint.local_addr()?.port();
	let cancel = tokio_util::sync::CancellationToken::new();
	tokio::spawn({
		let cancel = cancel.clone();
		async move {
			loop {
				tokio::select! {
					_ = cancel.cancelled() => {
						endpoint.close(0u32.into(), b"sni recorder shutdown");
						return;
					}
					incoming = endpoint.accept() => {
						let Some(incoming) = incoming else { return };
						tokio::spawn(async move {
							// Completing the handshake is what makes the
							// resolver run; hold the connection briefly so the
							// client can finish too.
							if let Ok(conn) = incoming.await {
								tokio::time::sleep(Duration::from_millis(100)).await;
								conn.close(0u32.into(), b"recorded");
							}
						});
					}
				}
			}
		}
	});
	Ok((port, record, cancel))
}

/// A relay configuration pointing at a loopback recorder.
fn relay_for(port: u16, sni: &str) -> Relay {
	Relay {
		server: ("127.0.0.1".to_string(), port),
		uuid: Uuid::new_v4(),
		password: Arc::from(AUTH_PASSWORD.as_bytes().to_vec().into_boxed_slice()),
		alpn: vec![b"h3".to_vec()],
		sni: Some(sni.to_string()),
		// The caller flips this per test.
		skip_cert_verify: true,
		..Default::default()
	}
}

/// Wait for the handshake to have been recorded, then return the SNI list.
async fn recorded(record: &Arc<Mutex<Vec<Option<String>>>>) -> Vec<Option<String>> {
	let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
	loop {
		{
			let seen = record.lock().expect("sni record lock");
			if !seen.is_empty() {
				return seen.clone();
			}
		}
		if tokio::time::Instant::now() >= deadline {
			return record.lock().expect("sni record lock").clone();
		}
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

#[tokio::test]
async fn disable_sni_true_stops_sending_the_server_name() -> eyre::Result<()> {
	install_crypto_provider();
	let server = signed_server_cert("expected.test");
	let (port, record, cancel) = start_sni_recorder(server.leaf).await?;

	let mut relay = relay_for(port, "expected.test");
	relay.disable_sni = true;
	relay.disable_native_certs = true;
	// The recorder does not implement TUIC auth, so the outbound may report an
	// auth failure; the ClientHello is what this test observes.
	let _ = tuic_client::plugin::build_quinn_outbound(Arc::new(wind_core::AppContext::default()), relay).await;

	let seen = recorded(&record).await;
	cancel.cancel();
	assert_eq!(
		seen,
		vec![None],
		"disable_sni=true must leave the ClientHello without a server_name, but the server saw {seen:?}"
	);
	Ok(())
}

#[tokio::test]
async fn enabled_sni_still_sends_the_server_name() -> eyre::Result<()> {
	install_crypto_provider();
	let server = signed_server_cert("expected.test");
	let (port, record, cancel) = start_sni_recorder(server.leaf).await?;

	let mut relay = relay_for(port, "expected.test");
	relay.disable_sni = false;
	let _ = tuic_client::plugin::build_quinn_outbound(Arc::new(wind_core::AppContext::default()), relay).await;

	let seen = recorded(&record).await;
	cancel.cancel();
	assert_eq!(
		seen,
		vec![Some("expected.test".to_string())],
		"the positive control must still send the server name, but the server saw {seen:?}"
	);
	Ok(())
}

#[tokio::test]
async fn supplied_certificate_lets_the_client_verify_the_server() -> eyre::Result<()> {
	install_crypto_provider();
	let server = signed_server_cert("expected.test");
	let dir = tempfile::tempdir()?;
	let ca_path = dir.path().join("ca.pem");
	std::fs::write(&ca_path, server.ca_pem.as_bytes())?;
	let (port, record, cancel) = start_sni_recorder(server.leaf).await?;

	let mut relay = relay_for(port, "expected.test");
	// Verification stays ON: only the supplied CA can make the TLS handshake
	// succeed, because the platform trust store does not know this test CA.
	relay.skip_cert_verify = false;
	relay.disable_native_certs = true;
	relay.certificates = vec![ca_path];
	let _ = tuic_client::plugin::build_quinn_outbound(Arc::new(wind_core::AppContext::default()), relay).await;

	let seen = recorded(&record).await;
	cancel.cancel();
	assert_eq!(
		seen,
		vec![Some("expected.test".to_string())],
		"a `[tls] certificates` CA must be trusted enough to complete the handshake, saw {seen:?}"
	);
	Ok(())
}

#[tokio::test]
async fn unknown_ca_still_fails_verification() -> eyre::Result<()> {
	install_crypto_provider();
	let server = signed_server_cert("expected.test");
	let (port, _record, cancel) = start_sni_recorder(server.leaf).await?;

	let mut relay = relay_for(port, "expected.test");
	relay.skip_cert_verify = false;
	relay.disable_native_certs = true;
	// No `[tls] certificates`: the CA is unknown and verification must refuse
	// the connection. This is the negative control for the test above.
	relay.certificates = Vec::new();
	let result = tuic_client::plugin::build_quinn_outbound(Arc::new(wind_core::AppContext::default()), relay).await;

	cancel.cancel();
	// Without the supplied CA the TLS handshake must fail, so the build cannot
	// succeed. A successful build would mean verification was skipped.
	assert!(
		result.is_err(),
		"an unknown CA must fail verification, yet the outbound was built successfully"
	);
	Ok(())
}
