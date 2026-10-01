//! Client-side rustls configuration for the quinn backend.
//!
//! `tuic-client` builds the whole `rustls::ClientConfig` itself and hands it to
//! wind through [`TuicOutboundOpts::client_config`], which wind uses verbatim
//! instead of its built-in configuration. That is the only way `[tls]
//! disable_sni`, `[tls] disable_native_certs`, and `[tls] certificates` can
//! take effect: the built-in configuration has no knob for any of them, so they
//! used to be accepted, serialized, and then silently ignored.
//!
//! Because the supplied configuration wins outright, the ALPN fallback, the
//! 0-RTT flag, and the skip-verify branch are reproduced here (they mirror
//! `wind-tuic`'s `quinn::tls::tls_config`, which is bypassed whenever
//! `client_config` is `Some`). The unit tests below pin that contract.
//!
//! [`TuicOutboundOpts::client_config`]: wind_tuic::quinn::outbound::TuicOutboundOpts::client_config

use std::{path::Path, sync::Arc};

use rustls::{
	crypto::CryptoProvider,
	pki_types::{CertificateDer, ServerName, UnixTime},
};
use thiserror::Error;
use tracing::{debug, warn};

use crate::config::Relay;

/// Failure to assemble the rustls client configuration.
#[derive(Debug, Error)]
pub enum TlsConfigError {
	#[error("failed to read certificate file {path}: {source}")]
	CertificateIo {
		path: String,
		#[source]
		source: std::io::Error,
	},

	#[error("certificate file {path} contains no usable PEM certificate")]
	NoCertificate { path: String },

	#[error("certificate file {path} contains no usable PEM certificate ({rejected} rejected)")]
	NoUsableCertificate { path: String, rejected: usize },

	#[error("rustls rejected {rejected} of {total} built-in webpki root certificates")]
	WebpkiRootsRejected { total: usize, rejected: usize },

	#[error("no usable root certificate: {unusable} of {total} candidate certificate(s) were rejected")]
	NoUsableRoot { total: usize, unusable: usize },

	#[error("no rustls crypto provider is installed (call `rustls::crypto::*::default_provider().install_default()`)")]
	NoCryptoProvider,
}

/// Build the rustls configuration for the quinn TUIC outbound.
///
/// Mirrors the semantics of `[tls]`:
/// * `skip_cert_verify` disables verification entirely (the trust store is not
///   even loaded).
/// * `disable_native_certs` replaces the platform trust store with the built-in
///   webpki/Mozilla root set instead of switching verification off.
/// * `certificates` adds extra PEM CA roots to whichever trust store is used,
///   which is how a privately signed relay certificate becomes trusted.
/// * `disable_sni` stops advertising the server name in the ClientHello while
///   certificate verification still uses it.
pub fn build_client_config(relay: &Relay) -> Result<rustls::ClientConfig, TlsConfigError> {
	let mut config = if relay.skip_cert_verify {
		warn!(
			target: "tls",
			"skip_cert_verify=true: server certificate verification is DISABLED. \
			 This is insecure and allows trivial MITM of the upstream relay."
		);
		rustls::ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(SkipServerVerification::new()?)
			.with_no_client_auth()
	} else {
		let roots = build_root_store(relay)?;
		rustls::ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth()
	};

	// Honour the caller-supplied ALPN list. An empty list falls back to "h3",
	// matching wind's built-in configuration (and the behaviour this
	// configuration now replaces).
	let mut alpn: Vec<Vec<u8>> = relay.alpn.clone();
	if alpn.is_empty() {
		alpn.push(b"h3".to_vec());
	}
	config.alpn_protocols = alpn;

	// Without `enable_early_data` on the rustls client configuration quinn
	// never attempts early data even when the server accepts it.
	config.enable_early_data = relay.zero_rtt_handshake;

	// `enable_sni = false` suppresses the SNI extension; rustls still verifies
	// the chain against the configured server name, which matches the
	// documented TUIC behaviour for `disable_sni`.
	config.enable_sni = !relay.disable_sni;
	if relay.disable_sni {
		warn!(
			target: "tls",
			"disable_sni=true: the relay's host name is no longer sent in the ClientHello; its certificate is still \
			 verified against it"
		);
	}

	debug!(
		target: "tls",
		"built rustls client config: alpn={:?} enable_sni={} enable_early_data={}",
		config
			.alpn_protocols
			.iter()
			.map(|p| String::from_utf8_lossy(p).into_owned())
			.collect::<Vec<_>>(),
		config.enable_sni,
		config.enable_early_data,
	);

	Ok(config)
}

/// Assemble the trust store: the platform roots unless
/// `disable_native_certs`, plus every `[tls] certificates` entry.
pub(crate) fn build_root_store(relay: &Relay) -> Result<rustls::RootCertStore, TlsConfigError> {
	let mut supplied: Vec<CertificateDer<'static>> = Vec::new();
	for path in &relay.certificates {
		supplied.extend(load_certificate_file(path)?);
	}

	let mut roots = rustls::RootCertStore::empty();
	if relay.disable_native_certs {
		// "Native certificates" are the platform trust store; the built-in
		// webpki/Mozilla set is the explicit replacement rather than a fallback
		// that keeps the platform store in play.
		let built_in = webpki_roots::TLS_SERVER_ROOTS.to_vec();
		let total = built_in.len();
		// `TLS_SERVER_ROOTS` already holds parsed `TrustAnchor`s, so they go in
		// directly (`add_parsable_certificates` only accepts DER).
		roots.extend(built_in);
		if roots.roots.len() != total {
			return Err(TlsConfigError::WebpkiRootsRejected {
				total,
				rejected: total - roots.roots.len(),
			});
		}
		warn!(
			target: "tls",
			"disable_native_certs=true: the platform trust store is disabled; using the {} built-in webpki roots{}",
			total,
			if supplied.is_empty() {
				String::new()
			} else {
				format!(" plus {} supplied certificate(s)", supplied.len())
			}
		);
	} else {
		let native = rustls_native_certs::load_native_certs();
		if !native.errors.is_empty() {
			warn!(
				target: "tls",
				"failed to load {} platform certificate store(s); continuing with the {} that did load",
				native.errors.len(),
				native.certs.len()
			);
		}
		let native_total = native.certs.len();
		let (native_added, native_rejected) = roots.add_parsable_certificates(native.certs);
		if native_rejected > 0 {
			warn!(
				target: "tls",
				"rustls rejected {native_rejected} of {native_total} platform certificates"
			);
		}
		if native_total > 0 && native_added == 0 && relay.certificates.is_empty() {
			return Err(TlsConfigError::NoUsableRoot {
				total: native_total,
				unusable: native_rejected,
			});
		}
	}

	let supplied_total = supplied.len();
	let (supplied_added, supplied_rejected) = roots.add_parsable_certificates(supplied);
	if supplied_rejected > 0 {
		// A `[tls] certificates` entry rustls cannot build a trust anchor from
		// must not be silently ignored: the operator expects it to be trusted.
		return Err(TlsConfigError::NoUsableCertificate {
			path: relay
				.certificates
				.iter()
				.map(|p| p.display().to_string())
				.collect::<Vec<_>>()
				.join(", "),
			rejected: supplied_rejected,
		});
	}
	if supplied_total > 0 && supplied_added == 0 {
		return Err(TlsConfigError::NoUsableCertificate {
			path: relay
				.certificates
				.iter()
				.map(|p| p.display().to_string())
				.collect::<Vec<_>>()
				.join(", "),
			rejected: supplied_total,
		});
	}
	if roots.is_empty() {
		return Err(TlsConfigError::NoUsableRoot {
			total: supplied_total,
			unusable: supplied_total,
		});
	}

	Ok(roots)
}

/// Read every PEM certificate from one `[tls] certificates` entry.
///
/// A file that yields no certificate at all is an error: silently trusting
/// nothing would turn a typo into a hard-to-diagnose handshake failure.
fn load_certificate_file(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
	let display = path.display().to_string();
	let file = std::fs::File::open(path).map_err(|source| TlsConfigError::CertificateIo {
		path: display.clone(),
		source,
	})?;
	let mut reader = std::io::BufReader::new(file);
	let certs = rustls_pemfile::certs(&mut reader)
		.collect::<Result<Vec<_>, _>>()
		.map_err(|source| TlsConfigError::CertificateIo {
			path: display.clone(),
			source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
		})?;
	if certs.is_empty() {
		return Err(TlsConfigError::NoCertificate { path: display });
	}
	Ok(certs)
}

/// Certificate verifier that accepts any certificate, used only when
/// `[tls] skip_cert_verify = true`.
#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
	fn new() -> Result<Arc<Self>, TlsConfigError> {
		Ok(Arc::new(Self(
			CryptoProvider::get_default().ok_or(TlsConfigError::NoCryptoProvider)?.clone(),
		)))
	}
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
	fn verify_server_cert(
		&self,
		_end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp: &[u8],
		_now: UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		self.0.signature_verification_algorithms.supported_schemes()
	}
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;

	use super::*;

	fn install_provider() {
		// Idempotent: `install_default` returns Err once the global is set.
		#[cfg(feature = "aws-lc-rs")]
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		#[cfg(feature = "ring")]
		let _ = rustls::crypto::ring::default_provider().install_default();
	}

	fn relay_with(alpn: Vec<Vec<u8>>, certificates: Vec<PathBuf>) -> Relay {
		Relay {
			server: ("relay.example".to_string(), 8443),
			// Skip verification so the ALPN/SNI tests never depend on a
			// reachable platform trust store; the trust-store tests below flip
			// it off.
			skip_cert_verify: true,
			alpn,
			certificates,
			..Default::default()
		}
	}

	/// Write a self-signed certificate for `name` into `dir` and return its PEM
	/// path.
	fn write_self_signed(name: &str, dir: &tempfile::TempDir) -> PathBuf {
		let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).expect("rcgen");
		let path = dir.path().join(format!("{name}.pem"));
		std::fs::write(&path, cert.cert.pem()).expect("write pem");
		path
	}

	#[test]
	fn empty_alpn_falls_back_to_h3() {
		install_provider();
		let config = build_client_config(&relay_with(Vec::new(), Vec::new())).expect("config");
		assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
	}

	#[test]
	fn caller_alpn_is_used_verbatim() {
		install_provider();
		let config = build_client_config(&relay_with(vec![b"tuic".to_vec()], Vec::new())).expect("config");
		assert_eq!(config.alpn_protocols, vec![b"tuic".to_vec()]);
	}

	#[test]
	fn sni_and_early_data_follow_the_config() {
		install_provider();

		let mut relay = relay_with(Vec::new(), Vec::new());
		relay.disable_sni = true;
		relay.zero_rtt_handshake = true;
		let config = build_client_config(&relay).expect("config");
		assert!(!config.enable_sni, "disable_sni=true must stop sending the SNI extension");
		assert!(config.enable_early_data, "zero_rtt_handshake=true must enable early data");

		let mut relay = relay_with(Vec::new(), Vec::new());
		relay.disable_sni = false;
		relay.zero_rtt_handshake = false;
		let config = build_client_config(&relay).expect("config");
		assert!(config.enable_sni, "the default must keep sending SNI");
		assert!(!config.enable_early_data, "the default must keep 0-RTT off");
	}

	#[test]
	fn disable_native_certs_keeps_the_builtin_roots() {
		install_provider();
		let mut relay = relay_with(Vec::new(), Vec::new());
		relay.skip_cert_verify = false;
		relay.disable_native_certs = true;
		let roots = build_root_store(&relay).expect("trust store");
		// No platform certificate may be mixed in when the platform store is
		// disabled.
		assert_eq!(
			roots.roots.len(),
			webpki_roots::TLS_SERVER_ROOTS.len(),
			"disable_native_certs=true must use exactly the built-in roots"
		);
	}

	#[test]
	fn supplied_certificate_is_added_on_top_of_the_native_store() {
		install_provider();
		let dir = tempfile::tempdir().expect("tempdir");
		let ca = write_self_signed("relay.internal", &dir);

		let mut relay = relay_with(Vec::new(), vec![ca]);
		relay.skip_cert_verify = false;
		relay.disable_native_certs = false;
		let roots = build_root_store(&relay).expect("trust store");
		assert!(
			!roots.is_empty(),
			"a supplied CA must be trusted even when the platform store is in use"
		);
	}

	#[test]
	fn supplied_certificate_is_added_to_the_builtin_store_too() {
		install_provider();
		let dir = tempfile::tempdir().expect("tempdir");
		let ca = write_self_signed("relay.internal", &dir);

		let mut relay = relay_with(Vec::new(), vec![ca]);
		relay.skip_cert_verify = false;
		relay.disable_native_certs = true;
		let roots = build_root_store(&relay).expect("trust store");
		assert_eq!(
			roots.roots.len(),
			webpki_roots::TLS_SERVER_ROOTS.len() + 1,
			"the supplied CA must be appended to the built-in roots"
		);
	}

	#[test]
	fn missing_certificate_file_is_a_config_error() {
		install_provider();
		let mut relay = relay_with(Vec::new(), vec![PathBuf::from("C:/definitely/missing.pem")]);
		relay.skip_cert_verify = false;
		let err = build_client_config(&relay).expect_err("a missing certificate file must fail");
		assert!(
			matches!(err, TlsConfigError::CertificateIo { .. }),
			"unexpected error: {err:?}"
		);
	}

	#[test]
	fn certificate_file_without_pem_is_a_config_error() {
		install_provider();
		let dir = tempfile::tempdir().expect("tempdir");
		let path = dir.path().join("empty.pem");
		std::fs::write(&path, b"not a certificate\n").expect("write");

		let mut relay = relay_with(Vec::new(), vec![path]);
		relay.skip_cert_verify = false;
		let err = build_client_config(&relay).expect_err("an empty certificate file must fail");
		assert!(
			matches!(err, TlsConfigError::NoCertificate { .. }),
			"unexpected error: {err:?}"
		);
	}
}
