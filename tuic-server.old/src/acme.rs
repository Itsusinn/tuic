use std::{path::Path, sync::Arc};

use arc_swap::ArcSwapOption;
use axum::Router;
use eyre::{Context, Result};
use rustls::server::ResolvesServerCert;
use rustls_acme::{AcmeConfig, UseChallenge::Http01, caches::DirCache};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::AppContext;

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

/// ACME certificate management via rustls-acme
pub async fn start_acme(
	ctx: Arc<AppContext>,
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

	let axum_cancel: ArcSwapOption<CancellationToken> = None.into();

	// Drive the ACME state machine in background
	tokio::spawn(async move {
		loop {
			match state.next().await {
				Some(Ok(event)) => match event {
					// Requesting certificate for the first time or renewing an existing one
					rustls_acme::EventOk::AccountCacheStore => {
						info!("ACME event: AccountCacheStore");
						let cancel = Arc::new(ctx.cancel.child_token());
						axum_cancel.swap(Some(cancel.clone())).inspect(|v| v.cancel());
						let http01_service = state.http01_challenge_tower_service();
						let axum_app =
							Router::new().route_service("/.well-known/acme-challenge/{challenge_token}", http01_service);
						if let Err(e) = spawn_axum(cancel.child_token(), axum_app).await {
							error!("Failed to start ACME HTTP-01 challenge server: {:?}", e);
						}
					}
					rustls_acme::EventOk::DeployedNewCert => {
						info!("ACME event: DeployedNewCert");
						axum_cancel.swap(None).inspect(|v| v.cancel());
					}
					_ => info!("ACME event: {:?}", event),
				},
				Some(Err(e)) => error!("ACME error: {:?}", e),
				None => break,
			}
		}
	});

	Ok(resolver)
}

async fn spawn_axum(cancel: CancellationToken, router: Router) -> eyre::Result<()> {
	let listener = tokio::net::TcpListener::bind("[::]:80")
		.await
		.context("Failed to bind to port 80 for ACME HTTP-01 challenges")?;
	info!("Started ACME HTTP-01 challenge server on port 80");
	tokio::spawn(async move {
		tokio::select! {
			Err(e) = axum::serve(listener, router) => {
				error!("ACME HTTP-01 challenge server error: {:?}", e);
			}
			_ = cancel.cancelled() => {
				info!("ACME HTTP-01 challenge server cancellation requested");
			}
		}
		info!("ACME certificate deployed, shutting down HTTP-01 challenge server");
	});
	Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
}
