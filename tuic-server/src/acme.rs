use std::{
	path::Path,
	sync::Arc,
	time::SystemTime,
};

use axum::Router;
use eyre::{Context, Result};
use rustls::server::ResolvesServerCert;
use rustls_acme::{AcmeConfig, UseChallenge::Http01, caches::DirCache};
use tokio::fs;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

// ---------------------------------------------------------------------------
// Domain validation
// ---------------------------------------------------------------------------

/// Check if a domain name is valid for ACME certificate issuance.
pub fn is_valid_domain(hostname: &str) -> bool {
	if hostname.is_empty() || hostname.len() > 253 {
		return false;
	}

	hostname.split('.').all(|label| {
		!label.is_empty()
			&& label.len() <= 63
			&& label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
			&& !label.starts_with('-')
			&& !label.ends_with('-')
	}) && hostname.contains('.')
		&& !hostname.starts_with('.')
		&& !hostname.ends_with('.')
}

// ---------------------------------------------------------------------------
// Certificate validation helpers
// ---------------------------------------------------------------------------

/// Check if a certificate file is valid (exists, readable, and not expired).
pub async fn is_certificate_valid(cert_path: &Path) -> bool {
	let cert_data = match fs::read(cert_path).await {
		Ok(data) => data,
		Err(_) => {
			warn!("Cannot read certificate file at {}", cert_path.display());
			return false;
		}
	};

	let (rem, pem) = match parse_x509_pem(&cert_data) {
		Ok(res) => res,
		Err(e) => {
			warn!("PEM parsing failed: {:?}", e);
			return false;
		}
	};

	if !rem.is_empty() {
		warn!("Extra data after certificate");
	}
	if pem.label != "CERTIFICATE" {
		warn!("Invalid PEM label: {:?}", pem.label);
	}

	let (_, parsed_cert) = match parse_x509_certificate(&pem.contents) {
		Ok(res) => res,
		Err(e) => {
			warn!("Failed to parse X.509 certificate: {:?}", e);
			return false;
		}
	};

	// Reject self-signed certificates (except during tests).
	if parsed_cert.tbs_certificate.issuer == parsed_cert.tbs_certificate.subject {
		warn!("Certificate is self-signed");
		#[cfg(not(test))]
		return false;
	}

	let validity = &parsed_cert.tbs_certificate.validity;
	let now = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.expect("SystemTime before UNIX EPOCH")
		.as_secs() as i64;

	let not_before = validity.not_before.timestamp();
	let not_after = validity.not_after.timestamp();

	if now < not_before {
		warn!("Certificate is not yet valid");
		return false;
	}
	if now > not_after {
		warn!("Certificate has expired");
		return false;
	}

	true
}

/// Check if a certificate is about to expire (within the specified days).
pub async fn is_certificate_expiring(cert_path: &Path, days_threshold: u64) -> Result<bool> {
	let cert_data = fs::read(cert_path).await.context("Failed to read certificate file")?;

	let (rem, pem) = parse_x509_pem(&cert_data).map_err(|e| eyre::eyre!("Failed to parse PEM certificate: {:?}", e))?;

	if !rem.is_empty() {
		warn!("Extra data after certificate");
	}
	if pem.label != "CERTIFICATE" {
		warn!("Invalid PEM label: {:?}", pem.label);
	}

	let (_, parsed_cert) =
		parse_x509_certificate(&pem.contents).map_err(|e| eyre::eyre!("Failed to parse X.509 certificate: {:?}", e))?;

	let now = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.context("Failed to get current time")?
		.as_secs();

	let not_after = parsed_cert.tbs_certificate.validity.not_after.timestamp() as u64;
	let threshold_time = now + (days_threshold * 24 * 60 * 60);

	Ok(not_after <= threshold_time)
}

// ---------------------------------------------------------------------------
// ACME certificate management via rustls-acme
// ---------------------------------------------------------------------------

/// Start automatic ACME certificate management.
///
/// Uses `rustls-acme` to automatically provision and renew certificates from
/// Let's Encrypt via HTTP-01 challenges. An HTTP challenge server is started
/// on port 80.
///
/// Returns a certificate resolver that can be used with a `rustls::ServerConfig`.
pub async fn start_acme(
	hostname: &str,
	acme_email: &str,
	cache_dir: &Path,
) -> Result<Arc<dyn ResolvesServerCert>> {
	if !is_valid_domain(hostname) {
		return Err(eyre::eyre!("Invalid domain name: {hostname}"));
	}

	let contact = if !acme_email.is_empty() {
		format!("mailto:{acme_email}")
	} else {
		format!("mailto:admin@{hostname}")
	};

	info!("Starting ACME certificate management for domain: {hostname}");

	tokio::fs::create_dir_all(cache_dir)
		.await
		.context("Failed to create ACME cache directory")?;

	let mut state = AcmeConfig::new(vec![hostname.to_string()])
		.contact(vec![contact])
		.cache(DirCache::new(cache_dir.to_path_buf()))
		.directory_lets_encrypt(true)
		.challenge_type(Http01)
		.state();

	let default_config = state.default_rustls_config();
	let resolver = default_config.cert_resolver.clone();
	let http01_service = state.http01_challenge_tower_service();

	// Start HTTP-01 challenge server on port 80
	let app = Router::new().route_service("/.well-known/acme-challenge/{challenge_token}", http01_service);
	let listener = tokio::net::TcpListener::bind("[::]:80")
		.await
		.context("Failed to bind to port 80 for ACME HTTP-01 challenges")?;
	info!("Started ACME HTTP-01 challenge server on port 80");

	tokio::spawn(async move {
		if let Err(e) = axum::serve(listener, app).await {
			error!("ACME HTTP-01 challenge server error: {}", e);
		}
	});

	// Drive the ACME state machine in background
	tokio::spawn(async move {
		loop {
			match state.next().await {
				Some(Ok(event)) => info!("ACME event: {:?}", event),
				Some(Err(e)) => error!("ACME error: {:?}", e),
				None => break,
			}
		}
	});

	Ok(resolver)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use rcgen::CertificateParams;
	use tempfile::NamedTempFile;
	use time::OffsetDateTime;

	use super::*;

	// -- Domain validation --

	#[test]
	fn test_domain_validation() {
		assert!(is_valid_domain("example.com"));
		assert!(is_valid_domain("sub.domain.co.uk"));
		assert!(is_valid_domain("a-b.c-d.com"));
		assert!(is_valid_domain("xn--eckwd4c7c.xn--zckzah.jp"));

		assert!(!is_valid_domain(".leading.dot"));
		assert!(!is_valid_domain("trailing.dot."));
		assert!(!is_valid_domain("double..dot"));
		assert!(!is_valid_domain("-leading-hyphen.com"));
		assert!(!is_valid_domain("trailing-hyphen-.com"));
		assert!(!is_valid_domain("space in.domain"));
		assert!(!is_valid_domain(""));
		assert!(!is_valid_domain(&"a".repeat(254)));
		assert!(!is_valid_domain("no-tld"));
	}

	// -- Certificate validation --

	#[tokio::test]
	async fn test_certificate_validation() -> eyre::Result<()> {
		let key_pair = rcgen::KeyPair::generate()?;

		let params = CertificateParams::new(vec!["test.com".to_string()])?;
		let cert = params.self_signed(&key_pair)?;
		let valid_file = NamedTempFile::new().unwrap();
		tokio::fs::write(valid_file.path(), &cert.pem()).await.unwrap();
		assert!(is_certificate_valid(valid_file.path()).await);

		let mut params = CertificateParams::new(vec!["test.com".to_string()])?;
		params.not_before = OffsetDateTime::now_utc() - chrono::Duration::days(365).to_std().unwrap();
		params.not_after = OffsetDateTime::now_utc() - chrono::Duration::days(1).to_std().unwrap();
		let expired_cert = params.self_signed(&key_pair)?;
		let expired_file = NamedTempFile::new().unwrap();
		tokio::fs::write(expired_file.path(), &expired_cert.pem()).await.unwrap();
		assert!(!is_certificate_valid(expired_file.path()).await);

		let invalid_file = NamedTempFile::new().unwrap();
		tokio::fs::write(invalid_file.path(), "invalid data").await.unwrap();
		assert!(!is_certificate_valid(invalid_file.path()).await);

		Ok(())
	}

	#[tokio::test]
	async fn test_certificate_expiration_check() -> eyre::Result<()> {
		let key_pair = rcgen::KeyPair::generate()?;

		let mut params = CertificateParams::new(vec!["test.com".to_string()])?;
		params.not_before = OffsetDateTime::now_utc() - chrono::Duration::days(1).to_std().unwrap();
		params.not_after = OffsetDateTime::now_utc() + chrono::Duration::days(2).to_std().unwrap();
		let cert = params.self_signed(&key_pair)?;
		let file = NamedTempFile::new().unwrap();
		tokio::fs::write(file.path(), &cert.pem()).await.unwrap();

		assert!(is_certificate_expiring(file.path(), 3).await.unwrap());
		assert!(!is_certificate_expiring(file.path(), 1).await.unwrap());
		Ok(())
	}
}
