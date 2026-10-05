//! The management API is part of the server contract: when `restful.enabled`
//! is set, `run_with_cancel` must not report a healthy startup unless the API
//! has actually bound its socket.
//!
//! Before this was enforced, a failed bind only produced a warning inside the
//! detached RESTful task, the address channel was dropped without a value, and
//! `run_with_cancel` silently returned `Ok` with `restful_addr == None` — the
//! server came up without the control plane an operator asked for.

use std::{
	collections::HashMap,
	net::{IpAddr, Ipv4Addr, SocketAddr},
	time::Duration,
};

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Loopback server with the RESTful API enabled and a self-signed certificate,
/// no external certificate or geodata files required.
fn server_config(server: SocketAddr, restful: SocketAddr) -> tuic_server::Config {
	let uuid = Uuid::new_v4();
	let mut cfg = tuic_server::Config {
		server,
		users: HashMap::from([(uuid, "test_password".to_string())]),
		..Default::default()
	};
	cfg.tls.self_sign = true;
	cfg.tls.hostname = "localhost".to_string();
	cfg.restful.enabled = true;
	cfg.restful.addr = restful;
	cfg
}

fn install_crypto_provider() {
	#[cfg(feature = "aws-lc-rs")]
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	#[cfg(feature = "ring")]
	let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Read `GET /online` from a RESTful API, if one is listening there.
///
/// Returns `None` while the API is not answering yet (or at all), so callers
/// can poll for it without a bind/unbind race. The whole exchange is bounded so
/// a socket that accepts but never replies cannot hang the test. The endpoint
/// needs no auth header (the server is configured with an empty secret).
async fn read_restful_state(addr: SocketAddr) -> Option<serde_json::Value> {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	let exchange = async {
		let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
		let request = format!("GET /online HTTP/1.1\r\nHost: {addr}\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
		stream.write_all(request.as_bytes()).await.ok()?;
		let mut raw = Vec::new();
		stream.read_to_end(&mut raw).await.ok()?;
		let response = String::from_utf8_lossy(&raw);
		let body = response.split_once("\r\n\r\n")?.1.trim().to_string();
		serde_json::from_str(&body).ok()
	};

	tokio::time::timeout(Duration::from_millis(500), exchange)
		.await
		.ok()
		.flatten()
}

#[tokio::test]
async fn restful_bind_conflict_fails_startup() {
	install_crypto_provider();

	// A dynamic loopback port held for the whole test: the RESTful API cannot
	// bind it, while the TUIC inbound uses its own OS-assigned port.
	let blocker = tokio::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
		.await
		.expect("blocker listener must bind");
	let restful_addr = blocker.local_addr().expect("blocker must have a local address");

	let cfg = server_config("127.0.0.1:0".parse().expect("valid server address"), restful_addr);
	let mut startup = tokio::spawn(tuic_server::run(cfg));

	// Wait (bounded) for the management API to report that it cannot listen.
	// The startup handshake deliberately waits for that same event, so a
	// regression that swallows it leaves the server parked here instead.
	let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
	while tokio::time::Instant::now() < deadline {
		match read_restful_state(restful_addr).await {
			Some(state) => panic!("a RESTful API that failed to bind must not serve requests, got: {state}"),
			None if startup.is_finished() => break,
			None => tokio::time::sleep(Duration::from_millis(20)).await,
		}
	}

	// With the management API enabled but not listening, startup must not
	// report success: the caller gets the reason instead of a server that is
	// quietly missing its control plane.
	match tokio::time::timeout(Duration::from_secs(10), &mut startup).await {
		Ok(Ok(Err(err))) => {
			let message = format!("{err:#}");
			assert!(
				message.contains("failed to bind RESTful API"),
				"startup error must name the RESTful bind failure, got: {message}"
			);
		}
		Ok(Ok(Ok(guard))) => {
			let restful = guard.restful_addr;
			guard.shutdown().await;
			panic!("startup must fail when the RESTful API cannot bind {restful_addr}, got restful_addr {restful:?}");
		}
		Ok(Err(join_err)) => panic!("startup task failed: {join_err}"),
		Err(_) => panic!("startup must not hang when the RESTful API cannot bind {restful_addr}"),
	}
}

#[tokio::test]
async fn restful_bind_success_still_reports_its_address() {
	install_crypto_provider();

	let cfg = server_config(
		"127.0.0.1:0".parse().expect("valid server address"),
		"127.0.0.1:0".parse().expect("valid restful address"),
	);
	let guard = tuic_server::run(cfg).await.expect("a free port must start the server");
	let restful_addr = guard
		.restful_addr
		.expect("an enabled and successfully bound RESTful API must report its address");
	assert_ne!(
		restful_addr.port(),
		0,
		"the OS-assigned port must be reported, got {restful_addr}"
	);
	assert!(restful_addr.ip().is_loopback(), "unexpected bind address {restful_addr}");
	guard.shutdown().await;
}

#[tokio::test]
async fn disabled_restful_api_keeps_reporting_no_address() {
	install_crypto_provider();

	let mut cfg = server_config(
		"127.0.0.1:0".parse().expect("valid server address"),
		"127.0.0.1:0".parse().expect("valid restful address"),
	);
	cfg.restful.enabled = false;

	let guard = tuic_server::run(cfg)
		.await
		.expect("the server must start without the RESTful API");
	assert!(
		guard.restful_addr.is_none(),
		"a disabled RESTful API must not report an address, got {:?}",
		guard.restful_addr
	);
	guard.shutdown().await;
}

#[tokio::test]
async fn cancellation_before_the_restful_bind_is_not_a_startup_failure() {
	install_crypto_provider();

	// The reported address is not expected here: the point is that an early
	// cancel must not be turned into a bogus bind error, and that the guard
	// (when it is produced) shuts down without hanging.
	let cfg = server_config(
		"127.0.0.1:0".parse().expect("valid server address"),
		"127.0.0.1:0".parse().expect("valid restful address"),
	);
	let cancel = CancellationToken::new();
	let result = tokio::time::timeout(Duration::from_secs(10), tuic_server::run_with_cancel(cfg, cancel.clone()))
		.await
		.expect("startup must not hang");

	match result {
		Ok(guard) => {
			cancel.cancel();
			guard.shutdown().await;
		}
		Err(err) => {
			let message = format!("{err:#}");
			assert!(
				!message.contains("failed to bind RESTful API"),
				"an early cancel must not be reported as a bind failure: {message}"
			);
		}
	}
}
