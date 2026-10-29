#[path = "../support/echo.rs"]
mod fixture;
use std::time::Duration;

use fixture::run_multi_echo;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	time::timeout,
};

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
