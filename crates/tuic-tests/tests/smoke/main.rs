//! Fast availability checks: startup, authentication, one TCP and UDP echo.

#[path = "../support/relay.rs"]
mod relay;

use tuic_tests::Backend;

#[tokio::test]
async fn quinn_server_quinn_client() -> eyre::Result<()> {
	relay::exercise(Backend::Quinn, Backend::Quinn, false).await
}

mod quiche {
	use super::*;

	#[tokio::test]
	async fn quiche_server_quinn_client() -> eyre::Result<()> {
		relay::exercise(Backend::Quiche, Backend::Quinn, false).await
	}

	#[tokio::test]
	async fn quinn_server_quiche_client() -> eyre::Result<()> {
		relay::exercise(Backend::Quinn, Backend::Quiche, false).await
	}

	#[tokio::test]
	async fn quiche_server_quiche_client() -> eyre::Result<()> {
		relay::exercise(Backend::Quiche, Backend::Quiche, false).await
	}
}
