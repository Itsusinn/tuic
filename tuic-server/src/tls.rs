use std::{
    collections::HashMap,
    net::TcpListener,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use arc_swap::ArcSwap;
use axum::{Router, extract::Path as AxumPath, http::StatusCode, routing::get};
use eyre::{Context, Result};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use sha2::{Digest, Sha256};
use tokio::{fs, sync::RwLock as TokioRwLock};
use tracing::{error, info, warn};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

#[derive(Debug)]
pub struct CertResolver {
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_key: RwLock<Arc<CertifiedKey>>,
    hash: ArcSwap<[u8; 32]>,
}
impl CertResolver {
    pub async fn new(cert_path: &Path, key_path: &Path, interval: Duration) -> Result<Arc<Self>> {
        let cert_key = load_cert_key(cert_path, key_path).await?;
        let hash = Self::calc_hash(cert_path, key_path).await?;
        let resolver = Arc::new(Self {
            cert_path: cert_path.to_owned(),
            key_path: key_path.to_owned(),
            cert_key: RwLock::new(cert_key),
            hash: ArcSwap::new(Arc::new(hash)),
        });
        // Start file watcher in background
        let resolver_clone = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = resolver_clone.start_watch(interval).await {
                warn!("Certificate watcher exited with error: {e}");
            }
        });
        Ok(resolver)
    }

    async fn start_watch(&self, interval: Duration) -> Result<()> {
        let mut interval = tokio::time::interval(interval);
        loop {
            interval.tick().await;
            let hash = Self::calc_hash(&self.cert_path, &self.key_path).await?;
            if &hash != self.hash.swap(hash.into()).deref() {
                match self.reload_cert_key().await {
                    Ok(_) => warn!("Successfully reloaded TLS certificate and key"),
                    Err(e) => warn!("Failed to reload TLS certificate and key: {e}"),
                }
            }
        }
    }

    async fn reload_cert_key(&self) -> Result<()> {
        let new_cert_key = load_cert_key(&self.cert_path, &self.key_path).await?;
        let mut guard = self
            .cert_key
            .write()
            .map_err(|_| eyre::eyre!("Certificate lock poisoned"))?;
        *guard = new_cert_key;
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
        self.cert_key.read().map(|guard| guard.deref().clone()).ok()
    }
}

async fn load_cert_key(cert_path: &Path, key_path: &Path) -> eyre::Result<Arc<CertifiedKey>> {
    let cert_chain = load_cert_chain(cert_path).await?;
    let der = load_priv_key(key_path).await?;
    #[cfg(feature = "aws-lc-rs")]
    let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&der)
        .context("Unsupported private key type")?;
    #[cfg(feature = "ring")]
    let key = rustls::crypto::ring::sign::any_supported_type(&der)
        .context("Unsupported private key type")?;

    Ok(Arc::new(CertifiedKey::new(cert_chain, key)))
}

async fn load_cert_chain(cert_path: &Path) -> eyre::Result<Vec<CertificateDer<'static>>> {
    let data = tokio::fs::read(cert_path)
        .await
        .context("Failed to read certificate chain")?;

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
    let data = tokio::fs::read(key_path)
        .await
        .context("Failed to read private key")?;

    if let Ok(Some(key)) =
        rustls_pemfile::private_key(&mut data.as_slice()).context("Malformed PEM private key")
    {
        return Ok(key);
    }

    if data.is_empty() {
        return Err(eyre::eyre!("Empty private key file"));
    }

    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(data)))
}

/// Check if port 80 is available for HTTP challenge server
pub fn is_port_80_available() -> bool {
    match TcpListener::bind("[::]:80") {
        Ok(listener) => {
            // Explicitly drop the TcpListener to release the port
            drop(listener);
            info!("Port 80 is available for HTTP challenge server");
            true
        }
        Err(e) => {
            warn!("Port 80 is not available: {}", e);
            false
        }
    }
}

/// HTTP challenge server state
#[derive(Clone)]
pub struct ChallengeServer {
    challenges: Arc<TokioRwLock<HashMap<String, String>>>,
}

impl ChallengeServer {
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(TokioRwLock::new(HashMap::new())),
        }
    }

    pub async fn add_challenge(&self, token: String, key_auth: String) {
        let mut challenges = self.challenges.write().await;
        challenges.insert(token, key_auth);
    }

    pub async fn remove_challenge(&self, token: &str) {
        let mut challenges = self.challenges.write().await;
        challenges.remove(token);
    }

    pub async fn get_challenge(&self, token: &str) -> Option<String> {
        let challenges = self.challenges.read().await;
        challenges.get(token).cloned()
    }
}

/// Start HTTP challenge server on port 80
pub async fn start_challenge_server(challenge_server: ChallengeServer) -> Result<()> {
    let app = Router::new()
        .route("/.well-known/acme-challenge/{token}", get(handle_challenge))
        .with_state(challenge_server);

    let listener = tokio::net::TcpListener::bind("[::]:80")
        .await
        .context("Failed to bind to port 80")?;

    info!("Starting HTTP challenge server on port 80");

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            error!("HTTP challenge server error: {}", e);
        }
    });

    Ok(())
}

/// Handle ACME challenge requests
async fn handle_challenge(
    AxumPath(token): AxumPath<String>,
    axum::extract::State(challenge_server): axum::extract::State<ChallengeServer>,
) -> Result<String, StatusCode> {
    info!("Received challenge request for token: {}", token);

    match challenge_server.get_challenge(&token).await {
        Some(key_auth) => {
            info!("Serving challenge response for token: {}", token);
            Ok(key_auth)
        }
        None => {
            warn!("Challenge token not found: {}", token);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Check if a domain name is valid for ACME certificate issuance
pub fn is_valid_domain(hostname: &str) -> bool {
    // Basic domain validation
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    // Check for valid characters and structure
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

/// Provision a certificate using ACME (Let's Encrypt)
pub async fn provision_acme_certificate(
    hostname: &str,
    cert_path: &Path,
    key_path: &Path,
    max_retries: u32,
) -> Result<()> {
    if !is_valid_domain(hostname) {
        return Err(eyre::eyre!("Invalid domain name: {hostname}"));
    }

    info!("Starting ACME certificate provisioning for domain: {hostname}");

    for attempt in 1..=max_retries {
        match provision_certificate_attempt(hostname, cert_path, key_path).await {
            Ok(()) => {
                info!("Successfully provisioned ACME certificate for {hostname}");
                return Ok(());
            }
            Err(e) => {
                warn!(
                    "ACME attempt {}/{} failed for {}: {}",
                    attempt, max_retries, hostname, e
                );
                if attempt < max_retries {
                    tokio::time::sleep(Duration::from_secs(5 * attempt as u64)).await;
                }
            }
        }
    }

    Err(eyre::eyre!(
        "Failed to provision ACME certificate after {} attempts",
        max_retries
    ))
}

async fn provision_certificate_attempt(
    hostname: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<()> {
    info!(
        "Starting ACME certificate provisioning for domain: {}",
        hostname
    );

    // Create a new ACME account
    let (account, _credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[&format!("mailto:admin@{hostname}")],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            LetsEncrypt::Production.url().to_owned(),
            None,
        )
        .await
        .context("Failed to create ACME account")?;

    info!("Created ACME account successfully");

    // Create the ACME order for the domain
    let identifiers = vec![Identifier::Dns(hostname.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("Failed to create ACME order")?;

    let state = order.state();
    info!("ACME order state: {:?}", state.status);

    if !matches!(state.status, OrderStatus::Pending) {
        return Err(eyre::eyre!("Unexpected order status: {:?}", state.status));
    }

    // Process authorizations
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.context("Failed to get authorization")?;

        match authz.status {
            AuthorizationStatus::Pending => {
                info!("Processing authorization for: {}", authz.identifier());

                // Check what challenge types are available
                let has_http01 = authz
                    .challenges
                    .iter()
                    .any(|c| c.r#type == ChallengeType::Http01);
                let has_dns01 = authz
                    .challenges
                    .iter()
                    .any(|c| c.r#type == ChallengeType::Dns01);

                if has_http01 && is_port_80_available() {
                    let mut challenge = authz
                        .challenge(ChallengeType::Http01)
                        .ok_or_else(|| eyre::eyre!("HTTP-01 challenge not found"))?;

                    info!("Using HTTP-01 challenge for {}", challenge.identifier());

                    // For HTTP-01 challenge, we need to serve the key authorization at:
                    // http://{domain}/.well-known/acme-challenge/{token}
                    let token = challenge.token.clone();
                    let key_auth = challenge.key_authorization();

                    info!("Setting up HTTP challenge server for token: {}", token);
                    info!(
                        "Challenge URL: http://{}/.well-known/acme-challenge/{}",
                        hostname, token
                    );

                    // Create and start the challenge server
                    let challenge_server = ChallengeServer::new();
                    challenge_server
                        .add_challenge(token.clone(), key_auth.as_str().to_string())
                        .await;

                    // Start the HTTP server
                    start_challenge_server(challenge_server.clone())
                        .await
                        .context("Failed to start HTTP challenge server")?;

                    // Give the server a moment to start
                    tokio::time::sleep(Duration::from_millis(500)).await;

                    // Set the challenge as ready
                    challenge
                        .set_ready()
                        .await
                        .context("Failed to set challenge as ready")?;

                    info!("HTTP-01 challenge set as ready for {}", hostname);

                    // Wait a bit for the challenge to be validated
                    tokio::time::sleep(Duration::from_secs(5)).await;

                    // Clean up the challenge token
                    challenge_server.remove_challenge(&token).await;
                } else if has_http01 {
                    // HTTP-01 is available but port 80 is not accessible
                    let challenge = authz
                        .challenge(ChallengeType::Http01)
                        .ok_or_else(|| eyre::eyre!("HTTP-01 challenge not found"))?;

                    warn!("HTTP-01 challenge is available but port 80 is not accessible");
                    warn!(
                        "URL: http://{}/.well-known/acme-challenge/{}",
                        hostname, challenge.token
                    );
                    warn!("Content: {}", challenge.key_authorization().as_str());
                    warn!("Please ensure port 80 is available or manually serve this content");

                    return Err(eyre::eyre!(
                        "HTTP-01 challenge requires port 80 to be available"
                    ));
                } else if has_dns01 {
                    let challenge = authz
                        .challenge(ChallengeType::Dns01)
                        .ok_or_else(|| eyre::eyre!("DNS-01 challenge not found"))?;

                    info!("Using DNS-01 challenge for {}", challenge.identifier());

                    let dns_value = challenge.key_authorization().dns_value();
                    warn!("DNS-01 challenge requires setting the following DNS record:");
                    warn!("_acme-challenge.{} IN TXT {}", hostname, dns_value);
                    warn!("Please set this DNS record and ensure it propagates before continuing.");

                    // For automated deployment, we can't wait for manual DNS setup
                    return Err(eyre::eyre!(
                        "DNS-01 challenge requires manual DNS record setup"
                    ));
                } else {
                    return Err(eyre::eyre!("No supported challenge type found"));
                }
            }
            AuthorizationStatus::Valid => {
                info!("Authorization already valid for: {}", authz.identifier());
                continue;
            }
            _ => {
                return Err(eyre::eyre!(
                    "Authorization failed with status: {:?}",
                    authz.status
                ));
            }
        }
    }

    // Poll for order to become ready
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .context("Failed to poll order status")?;

    if status != OrderStatus::Ready {
        return Err(eyre::eyre!("Order not ready, status: {:?}", status));
    }

    // Finalize the order
    let private_key_pem = order.finalize().await.context("Failed to finalize order")?;

    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("Failed to get certificate")?;

    // Save certificate and private key to files
    fs::write(cert_path, &cert_chain_pem)
        .await
        .context("Failed to write certificate file")?;

    fs::write(key_path, &private_key_pem)
        .await
        .context("Failed to write private key file")?;

    info!(
        "Successfully provisioned and saved ACME certificate for {}",
        hostname
    );
    info!("Certificate saved to: {}", cert_path.display());
    info!("Private key saved to: {}", key_path.display());

    Ok(())
}

/// Check if a certificate file is valid (exists, readable, and not expired)
pub async fn is_certificate_valid(cert_path: &Path) -> bool {
    // Try to read and parse the certificate
    match fs::read(cert_path).await {
        Ok(cert_data) => {
            let res = parse_x509_pem(&cert_data);
            match res {
                Ok((rem, pem)) => {
                    if !rem.is_empty() {
                        warn!("Extra data after certificate");
                    }
                    if pem.label != "CERTIFICATE" {
                        warn!("Invalid PEM label: {:?}", pem.label);
                    }
                    let res_x509 = parse_x509_certificate(&pem.contents);
                    match res_x509 {
                        Ok((_, parsed_cert)) => {
                            // Check if self-signed
                            if parsed_cert.tbs_certificate.issuer
                                == parsed_cert.tbs_certificate.subject
                            {
                                warn!("Certificate is self-signed");
                                return false;
                            }

                            // Check expiration
                            let now = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();

                            if now
                                < parsed_cert.tbs_certificate.validity.not_before.timestamp() as u64
                            {
                                warn!("Certificate is not yet valid");
                                return false;
                            }

                            if now
                                > parsed_cert.tbs_certificate.validity.not_after.timestamp() as u64
                            {
                                warn!("Certificate has expired");
                                return false;
                            }
                            true
                        }
                        Err(e) => {
                            warn!("Failed to parse X.509 certificate: {:?}", e);
                            false
                        }
                    }
                }
                _ => {
                    warn!("PEM parsing failed: {:?}", res);
                    false
                }
            }
        }
        Err(_) => {
            warn!("Cannot read certificate file at {}", cert_path.display());
            false
        }
    }
}

/// Check if a certificate is about to expire (within the specified days)
pub async fn is_certificate_expiring(cert_path: &Path, days_threshold: u64) -> Result<bool> {
    let cert_data = fs::read(cert_path)
        .await
        .context("Failed to read certificate file")?;

    // Parse the certificate using x509-parser
    let res = parse_x509_pem(&cert_data);
    match res {
        Ok((rem, pem)) => {
            if !rem.is_empty() {
                warn!("Extra data after certificate");
            }
            if pem.label != "CERTIFICATE" {
                warn!("Invalid PEM label: {:?}", pem.label);
            }
            let res_x509 = parse_x509_certificate(&pem.contents);
            match res_x509 {
                Ok((_, parsed_cert)) => {
                    // Get current time as seconds since Unix epoch
                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .context("Failed to get current time")?
                        .as_secs();

                    // Get certificate expiration time
                    let not_after =
                        parsed_cert.tbs_certificate.validity.not_after.timestamp() as u64;

                    // Calculate threshold time (current time + days_threshold)
                    let threshold_time = now + (days_threshold * 24 * 60 * 60);

                    // Certificate is expiring if the expiration time is before our threshold
                    Ok(not_after <= threshold_time)
                }
                Err(e) => Err(eyre::eyre!("Failed to parse X.509 certificate: {:?}", e)),
            }
        }
        Err(e) => Err(eyre::eyre!("Failed to parse PEM certificate: {:?}", e)),
    }
}

/// Start the certificate renewal background task
pub async fn start_certificate_renewal_task(
    hostname: String,
    cert_path: PathBuf,
    key_path: PathBuf,
) {
    tokio::spawn(async move {
        // check cert expiration every 12 hours
        let mut interval = tokio::time::interval(Duration::from_secs(12 * 60 * 60));

        loop {
            interval.tick().await;

            match is_certificate_expiring(&cert_path, 3).await {
                Ok(true) => {
                    info!(
                        "Certificate for {} is expiring soon, attempting renewal",
                        hostname
                    );

                    match provision_acme_certificate(&hostname, &cert_path, &key_path, 3).await {
                        Ok(()) => {
                            info!("Successfully renewed certificate for {}", hostname);
                        }
                        Err(e) => {
                            error!("Failed to renew certificate for {}: {}", hostname, e);
                        }
                    }
                }
                Ok(false) => {
                    info!("{} certificate check: still valid", hostname);
                }
                Err(e) => {
                    warn!(
                        "Failed to check certificate expiration for {}: {}",
                        hostname, e
                    );
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use rcgen::{CertificateParams, DnType, Ia5String, KeyPair, SanType};
    use tempfile::{NamedTempFile, tempdir};
    use tokio::time::Duration;

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
        key_pair.serialize_der();

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

    async fn create_temp_cert_file(
        cert_data: &[u8],
        key_data: &[u8],
    ) -> (NamedTempFile, NamedTempFile) {
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

        let resolver =
            CertResolver::new(cert_file.path(), key_file.path(), Duration::from_secs(10))
                .await
                .unwrap();

        let certified_key = resolver.cert_key.read().unwrap();
        assert!(!certified_key.cert.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_cert_resolver_reload() -> Result<()> {
        let temp_dir = tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let (cert_pem, key_pem) = generate_test_cert()?;
        tokio::fs::write(&cert_path, &cert_pem.as_bytes())
            .await
            .unwrap();
        tokio::fs::write(&key_path, &key_pem.as_bytes())
            .await
            .unwrap();

        let resolver = CertResolver::new(&cert_path, &key_path, Duration::from_micros(100))
            .await
            .unwrap();

        let initial_fingerprint = {
            let key = resolver.cert_key.read().unwrap();
            key.cert[0].as_ref().to_vec()
        };

        let (new_cert_pem, new_key_pem) = generate_test_cert()?;
        tokio::fs::write(&cert_path, &new_cert_pem).await.unwrap();
        tokio::fs::write(&key_path, &new_key_pem).await.unwrap();

        tokio::time::sleep(Duration::from_secs(5)).await;

        let updated_fingerprint = {
            let key = resolver.cert_key.read().unwrap();
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

        let resolver_result =
            CertResolver::new(cert_file.path(), key_file.path(), Duration::from_secs(10)).await;
        assert!(resolver_result.is_err());
    }
}
