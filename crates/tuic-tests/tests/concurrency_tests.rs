//! Concurrent-connection stress tests.
//!
//! Spawns multiple simultaneous TCP connections through the TUIC proxy to
//! verify that the multiplexed QUIC transport handles concurrent streams
//! correctly.

use std::{net::SocketAddr, time::Duration};

use fast_socks5::client::{Config, Socks5Stream};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpListener,
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
/// Upper bound for one echoed connection: the peer may connect and then go
/// silent, and the per-connection task must not stay alive forever.
const ECHO_DEADLINE: Duration = Duration::from_secs(3);

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
						// Echo every chunk until the peer half-closes or the
						// deadline elapses: one `read` + `write_all` truncates
						// payloads that arrive split across TCP segments,
						// because the socket closes right after that echo.
						let deadline = std::time::Instant::now() + ECHO_DEADLINE;
						loop {
							let remaining = deadline.saturating_duration_since(std::time::Instant::now());
							match timeout(remaining, socket.read(&mut buf)).await {
								Ok(Ok(0)) => break,
								Ok(Ok(n)) => {
									if let Err(e) = socket.write_all(&buf[..n]).await {
										info!("[multi-echo] failed to echo {n} bytes back: {e}");
										break;
									}
								}
								Ok(Err(e)) => {
									info!("[multi-echo] read error: {e}");
									break;
								}
								Err(_) => {
									info!("[multi-echo] connection idle past the echo deadline");
									break;
								}
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

/// The multi-echo helper must hand back every byte a peer sent, even when the
/// payload arrives in more than one TCP segment. It used to issue a single
/// `read` followed by a single echo and then drop the socket, so a peer that
/// wrote twice only ever saw the first chunk come back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_echo_returns_a_payload_split_across_reads() {
	let (echo_task, echo_addr) = run_multi_echo("127.0.0.1:0", 1).await;

	// Two writes separated by more than a loopback round trip: the first
	// `read` can never observe the second chunk, and the second write must not
	// race a socket that the helper closes after echoing only the first one.
	let payload: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
	let mut stream = tokio::net::TcpStream::connect(echo_addr).await.unwrap();
	for chunk in payload.chunks(1500) {
		stream.write_all(chunk).await.unwrap();
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	// Half-close so the echo handler observes EOF instead of waiting for its
	// own read deadline to expire.
	stream.shutdown().await.unwrap();

	let mut echoed = Vec::new();
	let read = timeout(Duration::from_secs(5), stream.read_to_end(&mut echoed)).await;
	echo_task.abort();

	read.expect("the echo must complete before the deadline")
		.expect("reading the echo must succeed");
	assert_eq!(echoed, payload, "the multi-echo server must return every byte it received");
}
