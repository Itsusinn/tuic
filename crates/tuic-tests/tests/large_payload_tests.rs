//! Payload-size stress tests for TUIC TCP relay.
//!
//! Uses the library's proven echo helpers to verify TCP relay works for
//! various payload sizes through the TUIC proxy.

use std::time::Duration;

use serial_test::serial;
use tokio::time::timeout;
use tracing::info;
use tracing_test::traced_test;
use tuic_tests::{install_crypto_provider, run_tcp_echo_server, start_quinn_pair, test_tcp_through_socks5};

fn make_test_data(size: usize) -> Vec<u8> {
	(0..size).map(|i| (i % 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[traced_test]
async fn test_tcp_512b_payload() -> eyre::Result<()> {
	install_crypto_provider();

	let socks5 = start_quinn_pair(21500, 21501, false).await;
	let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "8k").await;
	tokio::time::sleep(Duration::from_millis(200)).await;

	let data = make_test_data(512);
	info!("[512b] testing {} byte payload", data.len());

	let ok = timeout(
		Duration::from_secs(15),
		test_tcp_through_socks5(&socks5, echo_addr, &data, "512b"),
	)
	.await
	.unwrap_or(false);

	echo_task.abort();
	assert!(ok, "512B TCP echo through TUIC relay must succeed");

	Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[traced_test]
async fn test_tcp_varied_payloads() -> eyre::Result<()> {
	install_crypto_provider();

	let socks5 = start_quinn_pair(21510, 21511, false).await;

	let sizes: &[usize] = &[1, 32, 256, 512, 768, 1024];
	for &size in sizes {
		let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", &format!("tcp_{size}b")).await;
		tokio::time::sleep(Duration::from_millis(100)).await;

		let data = make_test_data(size);
		let label = format!("tcp_{size}b");

		let ok = timeout(
			Duration::from_secs(10),
			test_tcp_through_socks5(&socks5, echo_addr, &data, &label),
		)
		.await
		.unwrap_or(false);

		echo_task.abort();
		assert!(ok, "{size}-byte TCP echo through TUIC relay must succeed");
	}

	Ok(())
}
