//! Fresh connections with 0-RTT enabled. Actual early-data acceptance is
//! covered separately by the backend-specific zero_rtt_resumption modules.

#[path = "../support/relay.rs"]
mod relay;

use tuic_tests::Backend;

#[tokio::test]
async fn quinn_zero_rtt_config_tcp_and_udp_relay() -> eyre::Result<()> {
	relay::exercise(Backend::Quinn, Backend::Quinn, true).await
}

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
#[tokio::test]
async fn quiche_zero_rtt_config_tcp_and_udp_relay() -> eyre::Result<()> {
	relay::exercise(Backend::Quiche, Backend::Quinn, true).await
}
