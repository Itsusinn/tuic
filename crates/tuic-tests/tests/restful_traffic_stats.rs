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

use std::time::Duration;

use tracing::info;
use tuic_tests::{restful_request, run_tcp_echo_server, test_tcp_through_socks5};
use uuid::Uuid;

/// A quinn-backed `tuic-server` with the RESTful API enabled plus a
/// `tuic-client`, all bound to OS-assigned ports (no bind/unbind race).
struct RestfulPair {
	server: tuic_server::ServerGuard,
	client: tuic_client::ClientGuard,
	uuid: Uuid,
}

impl RestfulPair {
	async fn shutdown(self) {
		self.client.shutdown().await;
		self.server.shutdown().await;
	}
}

async fn start_pair_with_restful() -> RestfulPair {
	tuic_tests::install_crypto_provider();

	let uuid = Uuid::new_v4();
	let password = "test_password";
	let data_dir = std::env::temp_dir().join("wind-tuic-restful-stats-test");

	let mut scfg = tuic_tests::quinn_server_config("127.0.0.1:0".parse().unwrap(), data_dir, uuid, password, false);
	scfg.restful.enabled = true;
	scfg.restful.addr = "127.0.0.1:0".parse().unwrap();
	scfg.restful.secret = String::new(); // no auth needed for the test

	let server = tuic_server::run(scfg)
		.await
		.expect("restful stats test: server failed to start");

	let ccfg = tuic_tests::tuic_client_config(server.local_addr.port(), 0, uuid, password, false, tuic_tests::Backend::Quinn);
	let client = tuic_client::run(ccfg)
		.await
		.expect("restful stats test: client failed to start");

	RestfulPair { server, client, uuid }
}

#[tokio::test]
async fn restful_traffic_reflects_inbound_stats() {
	let pair = start_pair_with_restful().await;
	let socks5 = pair.client.socks5_addr.to_string();
	let restful_addr = pair.server.restful_addr.expect("RESTful API should report its bound address");

	// 1. Push real traffic through the TUIC tunnel.
	let (_echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "restful-stats").await;
	let test_data = b"hello-restful-traffic";
	assert!(
		test_tcp_through_socks5(&socks5, echo_addr, test_data, "restful-stats").await,
		"TCP echo through the SOCKS5 proxy must succeed"
	);

	// 2. Kick the user so the server closes the live connection: the TUIC
	//    traffic sampler only records bytes on its (default 60s) tick or on
	//    close, so closing the connection triggers the final sample that bills
	//    the echoed bytes.
	let kick_body = restful_request(restful_addr, "POST", "/kick", Some(&format!("[\"{}\"]", pair.uuid))).await;
	let kicked: serde_json::Value = serde_json::from_str(&kick_body).expect("valid kick JSON");
	assert!(
		kicked["kicked"].as_u64().unwrap_or(0) > 0,
		"kick must hit the live connection, got: {kick_body}"
	);
	// 3. Poll the RESTful API for the cumulative per-user traffic until the
	//    final sample lands in the collector or the deadline passes. Polling
	//    instead of a fixed sleep is faster on the happy path and robust to
	//    scheduling jitter.
	let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
	let body = loop {
		let body = restful_request(restful_addr, "GET", "/traffic", None).await;
		info!("[restful stats test] /traffic response: {body}");
		let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON body");
		if let Some(entry) = parsed.get(pair.uuid.to_string()) {
			if entry["tx"].as_u64().unwrap_or(0) > 0 && entry["rx"].as_u64().unwrap_or(0) > 0 {
				break body;
			}
		}
		assert!(
			tokio::time::Instant::now() < deadline,
			"timed out waiting for traffic to appear in /traffic, last response: {body}"
		);
		tokio::time::sleep(Duration::from_millis(50)).await;
	};

	// 4. The response must contain this user with non-zero tx/rx. Before the
	//    fix, the plugin never injects its collector into the App, so the
	//    inbound has no collector to write into and the API returns `{}` —
	//    failing this assertion.
	let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON body");
	let user_entry = parsed
		.get(pair.uuid.to_string())
		.unwrap_or_else(|| panic!("expected per-user entry for {} in /traffic, got: {body}", pair.uuid));
	let tx = user_entry["tx"].as_u64().unwrap_or(0);
	let rx = user_entry["rx"].as_u64().unwrap_or(0);
	assert!(tx > 0, "upload must be recorded, got: {body}");
	assert!(rx > 0, "download must be recorded, got: {body}");

	pair.shutdown().await;
}
