//! Bounded concurrent-stream E2E tests.
//!
//! Spawns multiple simultaneous TCP connections through the TUIC proxy to
//! verify that the multiplexed QUIC transport handles concurrent streams
//! correctly.

use std::{net::SocketAddr, time::Duration};

use fast_socks5::client::{Config, Socks5Stream};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	time::timeout,
};
use tracing::info;
use tracing_test::traced_test;
use tuic_tests::start_quinn_pair;

/// Upper bound for a single SOCKS5 connect attempt: the TCP handshake plus the
/// proxy's own connect to the echo server address.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for one request/echo round trip once the stream is established.
const ECHO_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for collecting the spawned connection tasks, so a wedged task
/// cannot hang the whole suite.
const JOIN_TIMEOUT: Duration = Duration::from_secs(30);
#[tokio::test(flavor = "multi_thread")]
#[traced_test]
async fn test_concurrent_5_tcp_connections() -> eyre::Result<()> {
	let pair = start_quinn_pair(false).await;
	let socks5 = pair.socks5_addr();
	let (echo_task, echo_addr) = run_multi_echo("127.0.0.1:0", 5).await;
	tokio::time::sleep(Duration::from_millis(200)).await;

	let mut handles = Vec::with_capacity(5);
	for i in 0..5 {
		let socks = socks5.clone();
		let target = echo_addr;
		handles.push(tokio::spawn(async move {
			let label = format!("concur_{i}");
			let connected = timeout(
				CONNECT_TIMEOUT,
				Socks5Stream::connect(
					socks.parse::<SocketAddr>().unwrap(),
					target.ip().to_string(),
					target.port(),
					Config::default(),
				),
			)
			.await;
			let mut stream = match connected {
				Ok(Ok(stream)) => stream,
				Ok(Err(e)) => {
					info!("[{label}] SOCKS5 connect failed: {e}");
					return false;
				}
				Err(_) => {
					info!("[{label}] SOCKS5 connect timed out after {CONNECT_TIMEOUT:?}");
					return false;
				}
			};

			let data = format!("hello {i}").into_bytes();
			let exchange = async {
				stream.write_all(&data).await.ok()?;
				let mut buf = vec![0u8; data.len()];
				stream.read_exact(&mut buf).await.ok()?;
				Some(buf == data)
			};
			match timeout(ECHO_TIMEOUT, exchange).await {
				Ok(Some(echoed)) => echoed,
				Ok(None) => {
					info!("[{label}] the echo exchange failed before it completed");
					false
				}
				Err(_) => {
					info!("[{label}] the echo exchange timed out after {ECHO_TIMEOUT:?}");
					false
				}
			}
		}));
	}

	let mut ok = 0;
	for mut h in handles {
		match timeout(JOIN_TIMEOUT, &mut h).await {
			Ok(Ok(true)) => ok += 1,
			Ok(Ok(false)) => {}
			Ok(Err(e)) => info!("[concur] connection task failed: {e}"),
			Err(_) => {
				info!("[concur] connection task did not finish within {JOIN_TIMEOUT:?}");
				h.abort();
			}
		}
	}
	echo_task.abort();
	assert_eq!(ok, 5, "5 concurrent TCP echoes must all succeed (got {ok})");

	pair.shutdown().await;
	Ok(())
}


#[path = "../support/echo.rs"]
mod echo;
use echo::run_multi_echo;
