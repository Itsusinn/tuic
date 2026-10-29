//! Configuration-driven TCP/UDP forwards through a real TUIC client/server.

use std::time::Duration;

use eyre::Result;
use tuic_tests::{Backend, install_crypto_provider, quinn_server_config, tuic_client_config};

use super::forward;

async fn forwards(backend: Backend, lazy: bool) -> Result<()> {
	install_crypto_provider();
	let directory = tempfile::tempdir()?;
	let uuid = uuid::Uuid::new_v4();
	let password = uuid::Uuid::new_v4().to_string();
	let server = tokio::time::timeout(
		Duration::from_secs(10),
		tuic_server::run(quinn_server_config(
			"127.0.0.1:0".parse()?,
			directory.path().into(),
			uuid,
			&password,
			false,
		)),
	)
	.await??;
	let mut config = tuic_client_config(server.local_addr.port(), 0, uuid, &password, false, backend);
	config.relay.lazy = lazy;
	let result = forward::exercise(config).await;
	server.shutdown().await;
	result
}

#[tokio::test]
async fn quinn_eager_tcp_udp_forward() -> Result<()> {
	forwards(Backend::Quinn, false).await
}

#[tokio::test]
async fn quinn_lazy_tcp_udp_forward() -> Result<()> {
	forwards(Backend::Quinn, true).await
}

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
mod quiche {
	use super::*;
	#[tokio::test]
	async fn quiche_eager_tcp_udp_forward() -> Result<()> {
		forwards(Backend::Quiche, false).await
	}
	#[tokio::test]
	async fn quiche_lazy_tcp_udp_forward() -> Result<()> {
		forwards(Backend::Quiche, true).await
	}
}
