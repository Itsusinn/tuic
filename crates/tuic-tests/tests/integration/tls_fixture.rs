#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
use tuic_client::config::Relay;
use tuic_tests::install_crypto_provider;

use super::tls_fixture_support::signed_server_cert;

/// The CA PEM used by the tests must be a loadable certificate file.
#[test]
fn ca_pem_is_a_usable_certificate_file() {
	install_crypto_provider();
	let server = signed_server_cert("expected.test");
	assert!(!server.leaf.cert.is_empty());
	assert!(server.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
	assert_eq!(
		rustls_pemfile::certs(&mut server.ca_pem.as_bytes())
			.collect::<Result<Vec<_>, _>>()
			.expect("pem parse")
			.len(),
		1
	);
}

#[tokio::test]
async fn missing_certificate_file_fails_before_dialing() -> eyre::Result<()> {
	install_crypto_provider();
	let relay = Relay {
		skip_cert_verify: false,
		certificates: vec!["definitely-missing-ca.pem".into()],
		server: ("127.0.0.1".into(), 1),
		sni: Some("expected.test".into()),
		..Default::default()
	};
	let result = tuic_client::plugin::build_quinn_outbound(std::sync::Arc::new(wind_core::AppContext::default()), relay).await;
	match result {
		Ok(_) => eyre::bail!("a missing `[tls] certificates` file must fail the outbound build"),
		Err(err) => {
			let message = format!("{err:#}");
			assert!(
				message.contains("certificates") || message.contains("missing-ca.pem"),
				"the error must name the certificate problem, got: {message}"
			);
		}
	}
	Ok(())
}
