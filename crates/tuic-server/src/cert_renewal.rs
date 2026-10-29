use std::{future::Future, time::Duration};

use tokio_util::sync::CancellationToken;

pub(crate) async fn reload(
	store: &wind_tuic::quiche::CertStore,
	cert: &std::path::Path,
	key: &std::path::Path,
) -> eyre::Result<()> {
	let cert_pem = tokio::fs::read(cert).await?;
	let key_pem = tokio::fs::read(key).await?;
	store.update(&cert_pem, &key_pem)
}

/// Retry renewal failures without replacing a previously valid certificate.
/// The first check is delayed because startup already provisioned the certificate.
pub(crate) async fn run<F, Fut>(cancel: CancellationToken, interval: Duration, mut renew: F)
where
	F: FnMut() -> Fut,
	Fut: Future<Output = eyre::Result<()>>,
{
	loop {
		tokio::select! {
			biased;
			_ = cancel.cancelled() => return,
			_ = tokio::time::sleep(interval) => {},
		}
		tokio::select! {
			biased;
			_ = cancel.cancelled() => return,
			result = renew() => if let Err(error) = result {
				tracing::warn!("[acme] certificate renewal failed; retaining current certificate: {error:#}");
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn retries_failures_and_stops_on_cancellation() -> eyre::Result<()> {
		let token = CancellationToken::new();
		let mut calls = 0;
		tokio::time::timeout(
			Duration::from_secs(2),
			run(token.clone(), Duration::from_millis(1), || {
				calls += 1;
				if calls == 2 {
					token.cancel();
				}
				async { eyre::bail!("simulated renewal failure") }
			}),
		)
		.await?;
		assert_eq!(calls, 2);
		Ok(())
	}

	#[tokio::test]
	async fn cancellation_interrupts_pending_renewal() -> eyre::Result<()> {
		let token = CancellationToken::new();
		let signal = token.clone();
		tokio::time::timeout(
			Duration::from_secs(2),
			run(token, Duration::from_millis(1), move || {
				signal.cancel();
				std::future::pending::<eyre::Result<()>>()
			}),
		)
		.await?;
		Ok(())
	}
}
