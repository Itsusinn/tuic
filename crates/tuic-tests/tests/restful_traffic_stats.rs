//! End-to-end regression test: the RESTful `/traffic` endpoint must reflect
//! traffic that actually flowed through the TUIC inbound.
//!
//! The server plugin owns the `StatsCollector` it hands to the REST API, but
//! the inbound writes into the collector that `App::run` builds from the hooks
//! bundle. When the plugin never injects its collector into the `App`, the
//! inbound has no collector to write into (`InboundHooks.stats == None`), so
//! `/traffic` reports an empty object even after real traffic. This test fails
//! in that state and passes once the plugin wires the collector through
//! `App::set_stats_collector`.
//!
//! NOTE: `tuic_client::run` installs a process-global connection (`OnceCell`),
//! so at most one client-starting test may live per `tests/*.rs` file — keep
//! this file to a single `#[serial]` test.

use std::{net::SocketAddr, time::Duration};

use serial_test::serial;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpStream,
	time::timeout,
};
use tracing::{error, info};
use tuic_tests::{run_tcp_echo_server, test_tcp_through_socks5};
use uuid::Uuid;

/// Fixed ports for this test, following the repo's other e2e tests (each file
/// owns a distinct range and runs `#[serial]`).
const SERVER_PORT: u16 = 21801;
const SOCKS_PORT: u16 = 21802;
const RESTFUL_PORT: u16 = 21800;

/// Minimal HTTP/1.1 client over a raw TCP stream — enough for the local
/// RESTful API and avoids pulling an HTTP client into the test crate. Returns
/// the response body.
async fn http_request(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> String {
	let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(addr))
		.await
		.expect("connect to restful api")
		.expect("tcp connect");
	let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAccept: application/json\r\nConnection: close\r\n");
	if let Some(b) = body {
		request.push_str("Content-Type: application/json\r\n");
		request.push_str(&format!("Content-Length: {}\r\n", b.len()));
	}
	request.push_str("\r\n");
	if let Some(b) = body {
		request.push_str(b);
	}
	stream.write_all(request.as_bytes()).await.expect("write request");
	let mut buf = Vec::new();
	stream.read_to_end(&mut buf).await.expect("read response");
	let response = String::from_utf8_lossy(&buf);
	assert!(
		response.starts_with("HTTP/1.1 200"),
		"unexpected status in response: {response}"
	);
	// Split headers from the body on the first empty line.
	let body = response.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&response);
	body.trim().to_string()
}

/// Start a quinn-backed `tuic-server` with the RESTful API enabled plus a
/// `tuic-client`, mirroring `tuic_tests::start_quinn_pair`. Returns the
/// client's SOCKS5 address and the test user's UUID (needed to read its
/// traffic from the API).
async fn start_pair_with_restful() -> (String, Uuid) {
	tuic_tests::install_crypto_provider();

	let uuid = Uuid::new_v4();
	let password = "test_password";
	let server_addr: SocketAddr = format!("127.0.0.1:{SERVER_PORT}").parse().unwrap();
	let data_dir = std::env::temp_dir().join("wind-tuic-restful-stats-test");

	let mut scfg = tuic_tests::quinn_server_config(server_addr, data_dir, uuid, password, false);
	scfg.restful.enabled = true;
	scfg.restful.addr = format!("127.0.0.1:{RESTFUL_PORT}").parse().unwrap();
	scfg.restful.secret = String::new(); // no auth needed for the test
	tokio::spawn(async move {
		match timeout(Duration::from_secs(20), tuic_server::run(scfg)).await {
			Ok(Ok(())) => info!("[restful stats test] server exited ok"),
			Ok(Err(e)) => error!("[restful stats test] server error: {e}"),
			Err(_) => info!("[restful stats test] server timed out (expected at test end)"),
		}
	});
	tokio::time::sleep(Duration::from_secs(1)).await;

	let ccfg = tuic_tests::tuic_client_config(SERVER_PORT, SOCKS_PORT, uuid, password, false);
	tokio::spawn(async move {
		match timeout(Duration::from_secs(20), tuic_client::run(ccfg)).await {
			Ok(Ok(())) => info!("[restful stats test] client exited ok"),
			Ok(Err(e)) => error!("[restful stats test] client error: {e}"),
			Err(_) => info!("[restful stats test] client timed out (expected at test end)"),
		}
	});
	tokio::time::sleep(Duration::from_secs(2)).await;

	(format!("127.0.0.1:{SOCKS_PORT}"), uuid)
}

#[tokio::test]
#[serial]
async fn restful_traffic_reflects_inbound_stats() {
	let (socks5, uuid) = start_pair_with_restful().await;

	// 1. Push real traffic through the TUIC tunnel.
	let (_echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "restful-stats").await;
	let test_data = b"hello-restful-traffic";
	assert!(
		test_tcp_through_socks5(&socks5, echo_addr, test_data, "restful-stats").await,
		"TCP echo through the SOCKS5 proxy must succeed"
	);

	// 2. Kick the user so the server closes the live connection: the TUIC traffic
	//    sampler only records bytes on its (default 60s) tick or on close, so
	//    closing the connection triggers the final sample that bills the echoed
	//    bytes.
	let restful_addr: SocketAddr = format!("127.0.0.1:{RESTFUL_PORT}").parse().unwrap();
	let kick_body = http_request(restful_addr, "POST", "/kick", Some(&format!("[\"{uuid}\"]"))).await;
	let kicked: serde_json::Value = serde_json::from_str(&kick_body).expect("valid kick JSON");
	assert!(
		kicked["kicked"].as_u64().unwrap_or(0) > 0,
		"kick must hit the live connection, got: {kick_body}"
	);
	// Let the final sample land in the collector.
	tokio::time::sleep(Duration::from_millis(1000)).await;

	// 3. Ask the RESTful API for the cumulative per-user traffic.
	let body = http_request(restful_addr, "GET", "/traffic", None).await;
	info!("[restful stats test] /traffic response: {body}");

	// 4. The response must contain this user with non-zero tx/rx. Before the fix,
	//    the plugin never injects its collector into the App, so the inbound has no
	//    collector to write into and the API returns `{}` — failing this assertion.
	let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON body");
	let user_entry = parsed
		.get(uuid.to_string())
		.unwrap_or_else(|| panic!("expected per-user entry for {uuid} in /traffic, got: {body}"));
	let tx = user_entry["tx"].as_u64().unwrap_or(0);
	let rx = user_entry["rx"].as_u64().unwrap_or(0);
	assert!(tx > 0, "upload must be recorded, got: {body}");
	assert!(rx > 0, "download must be recorded, got: {body}");
}
