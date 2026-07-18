use std::{
	ops::Deref,
	path::{Path, PathBuf},
	sync::Arc,
	time::Duration,
};

use arc_swap::ArcSwap;
use eyre::{Context, Result};
use rustls::{
	pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
	server::{ClientHello, ResolvesServerCert},
	sign::CertifiedKey,
};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio_util::sync::CancellationToken;
use tracing::warn;

#[derive(Debug)]
pub struct CertResolver {
	cert_path: PathBuf,
	key_path: PathBuf,
	cert_key: ArcSwap<CertifiedKey>,
	hash: ArcSwap<[u8; 32]>,
}
impl CertResolver {
	pub async fn new(cert_path: &Path, key_path: &Path, interval: Duration, cancel: CancellationToken) -> Result<Arc<Self>> {
		let cert_key = load_cert_key(cert_path, key_path).await?;
		let hash = Self::calc_hash(cert_path, key_path).await?;
		let resolver = Arc::new(Self {
			cert_path: cert_path.to_owned(),
			key_path: key_path.to_owned(),
			cert_key: ArcSwap::new(cert_key),
			hash: ArcSwap::new(Arc::new(hash)),
		});
		// Start file watcher in background; exits on `cancel` so the task does
		// not outlive the server when used as a library.
		let resolver_clone = resolver.clone();
		tokio::spawn(async move {
			if let Err(e) = resolver_clone.start_watch(interval, cancel).await {
				warn!("Certificate watcher exited with error: {e}");
			}
		});
		Ok(resolver)
	}

	async fn start_watch(&self, interval: Duration, cancel: CancellationToken) -> Result<()> {
		let mut interval = tokio::time::interval(interval);
		loop {
			tokio::select! {
				_ = cancel.cancelled() => return Ok(()),
				_ = interval.tick() => {}
			}

			// Treat I/O errors here as transient (the cert file may be in the
			// middle of an ACME-driven `rename`, the directory may be missing
			// permission briefly during a system update, etc.). Previously
			// `?` propagated the error out of the spawned watcher task and the
			// watcher silently died — hot-reload then permanently stopped
			// working until the process was restarted.
			let new_hash = match Self::calc_hash(&self.cert_path, &self.key_path).await {
				Ok(h) => h,
				Err(e) => {
					warn!("Certificate watcher: failed to hash cert/key (will retry on next tick): {e}");
					continue;
				}
			};

			// Compare against the currently committed hash WITHOUT swapping
			// first. The previous code did `swap(new_hash)` even when the
			// reload subsequently failed; the next tick then saw an unchanged
			// hash and never retried, leaving the old (possibly expired)
			// certificate served forever with no further warnings.
			if self.hash.load().deref().as_ref() == &new_hash {
				continue;
			}

			match self.reload_cert_key().await {
				Ok(_) => {
					// Only commit the new hash on a successful reload, so a
					// failed reload keeps retrying on subsequent ticks.
					self.hash.store(Arc::new(new_hash));
					warn!("Successfully reloaded TLS certificate and key");
				}
				Err(e) => {
					warn!("Failed to reload TLS certificate and key (will retry on next tick): {e}");
				}
			}
		}
	}

	async fn reload_cert_key(&self) -> Result<()> {
		let new_cert_key = load_cert_key(&self.cert_path, &self.key_path).await?;
		self.cert_key.store(new_cert_key);
		Ok(())
	}

	async fn calc_hash(cert_path: &Path, key_path: &Path) -> Result<[u8; 32]> {
		let mut hasher = Sha256::new();
		hasher.update(fs::read(cert_path).await?);
		hasher.update(fs::read(key_path).await?);
		let result: [u8; 32] = hasher.finalize().into();
		Ok(result)
	}
}
impl ResolvesServerCert for CertResolver {
	fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		Some(self.cert_key.load_full())
	}
}

async fn load_cert_key(cert_path: &Path, key_path: &Path) -> eyre::Result<Arc<CertifiedKey>> {
	let cert_chain = load_cert_chain(cert_path).await?;
	let der = load_priv_key(key_path).await?;
	#[cfg(feature = "aws-lc-rs")]
	let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&der).context("Unsupported private key type")?;
	#[cfg(feature = "ring")]
	let key = rustls::crypto::ring::sign::any_supported_type(&der).context("Unsupported private key type")?;

	Ok(Arc::new(CertifiedKey::new(cert_chain, key)))
}

async fn load_cert_chain(cert_path: &Path) -> eyre::Result<Vec<CertificateDer<'static>>> {
	let data = tokio::fs::read(cert_path).await.context("Failed to read certificate chain")?;

	let pem_result = rustls_pemfile::certs(&mut data.as_slice())
		.collect::<Result<Vec<_>, _>>()
		.context("Invalid PEM certificate(s)");

	match pem_result {
		Ok(certs) if !certs.is_empty() => Ok(certs),
		_ => {
			if data.is_empty() {
				return Err(eyre::eyre!("Empty certificate file"));
			}
			Ok(vec![CertificateDer::from(data)])
		}
	}
}

async fn load_priv_key(key_path: &Path) -> eyre::Result<PrivateKeyDer<'static>> {
	let data = tokio::fs::read(key_path).await.context("Failed to read private key")?;

	if data.is_empty() {
		return Err(eyre::eyre!("Empty private key file: {}", key_path.display()));
	}

	// 1. Prefer PEM — `rustls_pemfile::private_key` dispatches between PKCS1
	//    (-----BEGIN RSA PRIVATE KEY-----), SEC1 (-----BEGIN EC PRIVATE KEY-----)
	//    and PKCS8 (-----BEGIN PRIVATE KEY-----).
	if let Some(key) = rustls_pemfile::private_key(&mut data.as_slice()).context("Malformed PEM private key")? {
		return Ok(key);
	}

	// 2. Not PEM. Previously the loader unconditionally wrapped any non-empty blob
	//    as PKCS8 DER, so a random/binary file produced an opaque rustls error far
	//    from the point of failure. Now we do a structural check first: every
	//    accepted DER key encoding (PKCS8 PrivateKeyInfo, PKCS1 RSAPrivateKey, SEC1
	//    ECPrivateKey) starts with an ASN.1 SEQUENCE (tag 0x30) whose declared
	//    length covers the rest of the file. That rejects text/garbage/truncated
	//    files cheaply while letting any valid DER through to rustls for real
	//    parsing later.
	if !looks_like_der_sequence(&data) {
		return Err(eyre::eyre!(
			"Private key at {} is neither a recognized PEM (PKCS1/SEC1/PKCS8) key nor a valid DER ASN.1 SEQUENCE — refusing \
			 to load arbitrary bytes as a PKCS8 key",
			key_path.display()
		));
	}

	Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(data)))
}

/// Cheap structural check: does `data` start with an ASN.1 SEQUENCE whose
/// declared length is consistent with the buffer size? Accepts DER inputs that
/// have at most a few trailing bytes (some keystores append a newline).
fn looks_like_der_sequence(data: &[u8]) -> bool {
	if data.len() < 2 || data[0] != 0x30 {
		return false;
	}
	let (declared_len, header_len) = match data[1] {
		// Short form: length fits in the low 7 bits.
		b @ 0..=0x7f => (b as usize, 2),
		// Long form: low 7 bits of byte 1 give the number of length octets.
		0x81 if data.len() >= 3 => (data[2] as usize, 3),
		0x82 if data.len() >= 4 => (u16::from_be_bytes([data[2], data[3]]) as usize, 4),
		0x83 if data.len() >= 5 => {
			let len = ((data[2] as usize) << 16) | ((data[3] as usize) << 8) | data[4] as usize;
			(len, 5)
		}
		0x84 if data.len() >= 6 => {
			let len = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
			(len, 6)
		}
		_ => return false,
	};
	let body = data.len().saturating_sub(header_len);
	// Allow up to 8 trailing bytes of slack (newline, NUL padding).
	declared_len <= body && body.saturating_sub(declared_len) <= 8
}

/// Check if a domain name is valid for ACME certificate issuance
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

#[cfg(test)]
mod tests {
	use std::io::Write;

	use rcgen::{CertificateParams, DnType, KeyPair, SanType, string::Ia5String};
	use tempfile::{NamedTempFile, tempdir};

	use super::*;

	fn generate_test_cert() -> eyre::Result<(String, String)> {
		let mut params = CertificateParams::default();

		let mut distinguished_name = rcgen::DistinguishedName::new();
		distinguished_name.push(DnType::CommonName, "localhost");
		distinguished_name.push(DnType::OrganizationName, "My Company");
		distinguished_name.push(DnType::CountryName, "US");
		params.distinguished_name = distinguished_name;

		params.subject_alt_names = vec![
			SanType::DnsName(Ia5String::try_from("localhost".to_string())?),
			SanType::IpAddress("127.0.0.1".parse()?),
		];
		let key_pair = KeyPair::generate()?;

		let cert = params.self_signed(&key_pair)?;

		let private_key_pem = key_pair.serialize_pem();
		let cert_pem = cert.pem();

		Ok((cert_pem, private_key_pem))
	}

	fn generate_test_cert_der() -> eyre::Result<(Vec<u8>, Vec<u8>)> {
		let mut params = CertificateParams::default();

		let mut distinguished_name = rcgen::DistinguishedName::new();
		distinguished_name.push(DnType::CommonName, "localhost");
		distinguished_name.push(DnType::OrganizationName, "My Company");
		distinguished_name.push(DnType::CountryName, "US");
		params.distinguished_name = distinguished_name;

		params.subject_alt_names = vec![
			SanType::DnsName(Ia5String::try_from("localhost".to_string())?),
			SanType::IpAddress("127.0.0.1".parse()?),
		];
		let key_pair = KeyPair::generate()?;
		let cert = params.self_signed(&key_pair)?;
		let private_key_der = key_pair.serialize_der();
		let cert_der = cert.der();

		Ok((cert_der.to_vec(), private_key_der))
	}

	async fn create_temp_cert_file(cert_data: &[u8], key_data: &[u8]) -> (NamedTempFile, NamedTempFile) {
		let mut cert_file = NamedTempFile::new().unwrap();
		cert_file.write_all(cert_data).unwrap();
		cert_file.as_file().sync_all().unwrap();

		let mut key_file = NamedTempFile::new().unwrap();
		key_file.write_all(key_data).unwrap();
		key_file.as_file().sync_all().unwrap();
		(cert_file, key_file)
	}

	#[tokio::test]
	async fn test_load_cert_chain_pem() -> Result<()> {
		let (cert_pem, _) = generate_test_cert()?;
		let (cert_file, _) = create_temp_cert_file(cert_pem.as_bytes(), b"").await;

		let result = load_cert_chain(cert_file.path()).await;
		assert!(result.is_ok());
		assert_eq!(result.unwrap().len(), 1);
		Ok(())
	}

	#[tokio::test]
	async fn test_load_cert_chain_der() -> Result<()> {
		let (cert_der, _) = generate_test_cert_der()?;
		let (cert_file, _) = create_temp_cert_file(&cert_der, b"").await;

		let result = load_cert_chain(cert_file.path()).await?;
		assert_eq!(result.len(), 1);
		Ok(())
	}

	#[tokio::test]
	async fn test_load_priv_key_pem() -> Result<()> {
		let (_, key_pem) = generate_test_cert()?;
		let (_, key_file) = create_temp_cert_file(b"", key_pem.as_bytes()).await;

		let result = load_priv_key(key_file.path()).await;
		assert!(result.is_ok());
		Ok(())
	}

	#[tokio::test]
	async fn test_load_priv_key_der() -> Result<()> {
		let (_, key_der) = generate_test_cert_der()?;
		let (_, key_file) = create_temp_cert_file(b"", &key_der).await;

		let result = load_priv_key(key_file.path()).await;
		assert!(result.is_ok());
		Ok(())
	}

	#[tokio::test]
	async fn test_cert_resolver_initial_load() -> Result<()> {
		let (cert_der, key_der) = generate_test_cert_der()?;
		let (cert_file, key_file) = create_temp_cert_file(&cert_der, &key_der).await;

		let resolver = CertResolver::new(
			cert_file.path(),
			key_file.path(),
			Duration::from_secs(10),
			CancellationToken::new(),
		)
		.await
		.unwrap();

		let certified_key = resolver.cert_key.load_full();
		assert!(!certified_key.cert.is_empty());
		Ok(())
	}

	#[tokio::test]
	async fn test_cert_resolver_reload() -> Result<()> {
		let temp_dir = tempdir().unwrap();
		let cert_path = temp_dir.path().join("cert.pem");
		let key_path = temp_dir.path().join("key.pem");

		let (cert_pem, key_pem) = generate_test_cert()?;
		tokio::fs::write(&cert_path, &cert_pem.as_bytes()).await.unwrap();
		tokio::fs::write(&key_path, &key_pem.as_bytes()).await.unwrap();

		let resolver = CertResolver::new(&cert_path, &key_path, Duration::from_micros(100), CancellationToken::new())
			.await
			.unwrap();

		let initial_fingerprint = {
			let key = resolver.cert_key.load_full();
			key.cert[0].as_ref().to_vec()
		};

		let (new_cert_pem, new_key_pem) = generate_test_cert()?;
		tokio::fs::write(&cert_path, &new_cert_pem).await.unwrap();
		tokio::fs::write(&key_path, &new_key_pem).await.unwrap();

		tokio::time::sleep(Duration::from_secs(5)).await;

		let updated_fingerprint = {
			let key = resolver.cert_key.load_full();
			key.cert[0].as_ref().to_vec()
		};
		assert_ne!(cert_pem, new_cert_pem);
		assert_ne!(initial_fingerprint, updated_fingerprint);
		Ok(())
	}

	#[tokio::test]
	async fn test_invalid_cert_handling() {
		let (cert_file, key_file) = create_temp_cert_file(b"invalid", b"invalid").await;

		let load_result = load_cert_key(cert_file.path(), key_file.path()).await;
		assert!(load_result.is_err());

		let resolver_result = CertResolver::new(
			cert_file.path(),
			key_file.path(),
			Duration::from_secs(10),
			CancellationToken::new(),
		)
		.await;
		assert!(resolver_result.is_err());
	}

	// --- PR1: private-key loader hardening regression tests ----------------

	#[tokio::test]
	async fn test_load_priv_key_rejects_empty_file() {
		let (_, key_file) = create_temp_cert_file(b"", b"").await;
		let err = load_priv_key(key_file.path()).await.expect_err("empty file must error");
		let msg = format!("{err:#}");
		assert!(
			msg.contains("Empty private key"),
			"expected explicit empty-file error, got: {msg}"
		);
	}

	#[tokio::test]
	async fn test_load_priv_key_rejects_random_bytes() {
		// 256 bytes of non-DER, non-PEM nonsense (first byte = 0xFF, not 0x30
		// SEQUENCE). Previously this was silently wrapped as PKCS8 and failed later
		// inside rustls with an opaque error far from the load site.
		let mut garbage = vec![0u8; 256];
		for (i, b) in garbage.iter_mut().enumerate() {
			*b = (i as u8).wrapping_mul(31).wrapping_add(0x80);
		}
		let (_, key_file) = create_temp_cert_file(b"", &garbage).await;
		let err = load_priv_key(key_file.path())
			.await
			.expect_err("random bytes must be rejected");
		let msg = format!("{err:#}");
		assert!(
			msg.contains("neither a recognized PEM"),
			"expected structural-rejection error, got: {msg}"
		);
	}

	#[tokio::test]
	async fn test_load_priv_key_rejects_text() {
		// Looks like HTML / a log file / etc. — must NOT be wrapped as PKCS8.
		let html = b"<html><body>not a private key, just an HTTP error page</body></html>";
		let (_, key_file) = create_temp_cert_file(b"", html).await;
		let err = load_priv_key(key_file.path())
			.await
			.expect_err("HTML content must be rejected");
		let msg = format!("{err:#}");
		assert!(
			msg.contains("neither a recognized PEM"),
			"expected structural-rejection error, got: {msg}"
		);
	}

	#[tokio::test]
	async fn test_load_priv_key_rejects_der_with_bogus_length() {
		// Starts with 0x30 (SEQUENCE) but the declared long-form length far
		// exceeds the buffer size: byte 1 = 0x82 means "next 2 bytes are the
		// length", followed by 0xFF 0xFF (= 65535) but only ~10 bytes follow.
		let bogus = vec![0x30, 0x82, 0xff, 0xff, 0x02, 0x01, 0x00, 0x03, 0x04, 0x05, 0x06];
		let (_, key_file) = create_temp_cert_file(b"", &bogus).await;
		let err = load_priv_key(key_file.path())
			.await
			.expect_err("DER with bogus length must be rejected");
		let msg = format!("{err:#}");
		assert!(
			msg.contains("neither a recognized PEM"),
			"expected structural-rejection error, got: {msg}"
		);
	}

	#[test]
	fn test_looks_like_der_sequence() {
		// Too short.
		assert!(!looks_like_der_sequence(&[]));
		assert!(!looks_like_der_sequence(&[0x30]));
		// Wrong tag.
		assert!(!looks_like_der_sequence(&[0xff, 0x00]));
		// Short-form, correct length.
		assert!(looks_like_der_sequence(&[0x30, 0x03, 0x01, 0x02, 0x03]));
		// Short-form, body smaller than declared.
		assert!(!looks_like_der_sequence(&[0x30, 0x10, 0x01, 0x02]));
		// Long-form 0x82, two-byte length.
		let mut buf = vec![0x30, 0x82, 0x00, 0x05];
		buf.extend_from_slice(&[1, 2, 3, 4, 5]);
		assert!(looks_like_der_sequence(&buf));
		// Long-form 0x82, declared length massively larger than buffer.
		assert!(!looks_like_der_sequence(&[0x30, 0x82, 0xff, 0xff, 0x01]));
		// Tolerate one trailing newline byte (some keystores append \n).
		assert!(looks_like_der_sequence(&[0x30, 0x03, 0x01, 0x02, 0x03, b'\n']));
	}

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
}
