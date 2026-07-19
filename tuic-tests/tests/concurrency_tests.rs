//! Concurrent-connection stress tests.
//!
//! Spawns multiple simultaneous TCP connections through the TUIC proxy to verify
//! that the multiplexed QUIC transport handles concurrent streams correctly.
//!
//! NOTE: `tuic_client::run` installs a process-global connection handle
//! (`OnceCell`), so at most one client may run per test process. Each `#[test]`
//! in this file launches its own server + client pair; use `#[serial]` to avoid
//! collisions.

use std::{net::SocketAddr, time::Duration};

use fast_socks5::client::{Config, Socks5Stream};
use serial_test::serial;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpListener,
};
use tracing::info;
use tracing_test::traced_test;
use tuic_tests::{install_crypto_provider, start_quinn_pair};

/// Start a multi-connection TCP echo server that handles `count` concurrent
/// connections, each in its own spawned task.
async fn run_multi_echo(addr: &str, count: usize) -> (tokio::task::JoinHandle<()>, SocketAddr) {
	let listener = TcpListener::bind(addr).await.unwrap();
	let server_addr = listener.local_addr().unwrap();
	info!("[multi-echo] listening on {server_addr}, expecting {count} connections");

	let handle = tokio::spawn(async move {
		let mut accepted = 0;
		while accepted < count {
			match listener.accept().await {
				Ok((mut socket, peer)) => {
					accepted += 1;
					info!("[multi-echo] connection {accepted}/{count} from {peer}");
					tokio::spawn(async move {
						let mut buf = vec![0u8; 65536];
						if let Ok(n) = socket.read(&mut buf).await {
							if n > 0 {
								let _ = socket.write_all(&buf[..n]).await;
							}
						}
					});
				}
				Err(e) => {
					info!("[multi-echo] accept error: {e}");
					break;
				}
			}
		}
		info!("[multi-echo] all {accepted} connections handled");
	});

	(handle, server_addr)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[traced_test]
async fn test_concurrent_5_tcp_connections() -> eyre::Result<()> {
	install_crypto_provider();

	let socks5 = start_quinn_pair(21100, 21101, false).await;
	let (echo_task, echo_addr) = run_multi_echo("127.0.0.1:0", 5).await;
	tokio::time::sleep(Duration::from_millis(200)).await;

	let mut handles = Vec::with_capacity(5);
	for i in 0..5 {
		let socks = socks5.clone();
		let target = echo_addr;
		handles.push(tokio::spawn(async move {
			let label = format!("concur_{i}");
			match Socks5Stream::connect(
				socks.parse::<SocketAddr>().unwrap(),
				target.ip().to_string(),
				target.port(),
				Config::default(),
			)
			.await
			{
				Ok(mut stream) => {
					let data = format!("hello {i}").into_bytes();
					if stream.write_all(&data).await.is_err() {
						return false;
					}
					let mut buf = vec![0u8; data.len()];
					stream.read_exact(&mut buf).await.is_ok() && buf == data
				}
				Err(e) => {
					info!("[{label}] SOCKS5 connect failed: {e}");
					false
				}
			}
		}));
	}

	let mut ok = 0;
	for h in handles {
		if h.await.unwrap_or(false) {
			ok += 1;
		}
	}
	echo_task.abort();
	assert_eq!(ok, 5, "5 concurrent TCP echoes must all succeed (got {ok})");

	Ok(())
}
