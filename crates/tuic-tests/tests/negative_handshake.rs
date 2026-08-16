//! Negative end-to-end tests for connection-establishment, authentication, and
//! routing failure modes.
//!
//! These are driven at the low-level `TuicOutbound` layer (no SOCKS5 inbound),
//! mirroring `graceful_shutdown.rs`, so a single test binary can exercise both
//! QUIC backends without the "one `tuic_client::run` per process" constraint.
//!
//! Failure-mode coverage:
//! * self-signed certificate with verification enabled (TLS handshake fails),
//! * ALPN mismatch (client `h2` vs server `h3`),
//! * wrong password (handshake sends; the auth failure surfaces on the first
//!   bidirectional stream),
//! * unknown UUID (same),
//! * ACL reject of the relay target.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::time::timeout;
use tuic_server::legacy::{AclAddress, AclRule};
use tuic_tests::{
	Backend, install_crypto_provider, low_level_outbound_opts, low_level_tcp_echo, quiche_server_config,
	quinn_server_config, run_tcp_echo_server,
};
use uuid::Uuid;
use wind_core::AppContext;
use wind_tuic::quinn::outbound::TuicOutbound;

/// Start a `tuic-server` (quinn or quiche) with the given auth/ALPN/ACL knobs.
async fn start_server(
	backend: Backend,
	uuid: Uuid,
	password: &str,
	alpn: Vec<String>,
	acl: Vec<AclRule>,
	auth_timeout: Duration,
) -> tuic_server::ServerGuard {
	let data_dir = std::env::temp_dir().join(format!("wind-tuic-neg-{}", Uuid::new_v4()));
	let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
	let mut cfg = match backend {
		Backend::Quinn => quinn_server_config(addr, data_dir, uuid, password, false),
		Backend::Quiche => quiche_server_config(addr, data_dir, uuid, password, false),
	};
	cfg.tls.alpn = alpn;
	cfg.auth_timeout = auth_timeout;
	cfg.acl = acl;
	// The relay targets are loopback echo servers, so the loopback/private
	// guards must stay off or they would reject the target before the ACL is
	// consulted (confusing the rejection source in the ACL test).
	cfg.experimental.drop_loopback = false;
	cfg.experimental.drop_private = false;
	tuic_server::run(cfg).await.expect("negative test server failed to start")
}

/// Build and connect a low-level TUIC outbound. `Ok` means the QUIC + TUIC auth
/// handshake completed; `Err` means the handshake itself failed.
async fn try_connect(
	server_port: u16,
	uuid: Uuid,
	password: &str,
	skip_cert_verify: bool,
	alpn: &[&str],
) -> eyre::Result<TuicOutbound> {
	let opts = low_level_outbound_opts(server_port, uuid, password, skip_cert_verify, alpn);
	let ctx = Arc::new(AppContext::default());
	let connect = TuicOutbound::new(ctx, opts);
	match timeout(Duration::from_secs(10), connect).await {
		Ok(res) => res,
		Err(_) => Err(eyre::eyre!("outbound connect timed out")),
	}
}

/// Run all five negative scenarios against one backend.
async fn run_cases(backend: Backend) {
	install_crypto_provider();

	// 1. Certificate verification failure: self-signed server + verification on.
	{
		let uuid = Uuid::new_v4();
		let server = start_server(backend, uuid, "correct", vec!["h3".into()], vec![], Duration::from_secs(3)).await;
		let res = try_connect(server.local_addr.port(), uuid, "correct", false, &["h3"]).await;
		assert!(
			res.is_err(),
			"self-signed certificate must fail verification when skip_cert_verify=false"
		);
		server.shutdown().await;
	}

	// 2. ALPN mismatch: server advertises `h3`, client asks for `h2`.
	{
		let uuid = Uuid::new_v4();
		let server = start_server(backend, uuid, "correct", vec!["h3".into()], vec![], Duration::from_secs(3)).await;
		let res = try_connect(server.local_addr.port(), uuid, "correct", true, &["h2"]).await;
		assert!(res.is_err(), "ALPN mismatch must fail the handshake");
		server.shutdown().await;
	}

	// 3. Wrong password: the QUIC handshake completes, but the relay must not
	//    carry data (the auth failure surfaces on the first bi stream).
	{
		let uuid = Uuid::new_v4();
		let server = start_server(backend, uuid, "correct", vec!["h3".into()], vec![], Duration::from_secs(1)).await;
		let outbound = try_connect(server.local_addr.port(), uuid, "wrong", true, &["h3"])
			.await
			.expect("wrong password still completes the QUIC handshake");
		let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "neg-wrong-password").await;
		let relayed = low_level_tcp_echo(Arc::new(outbound), echo_addr, b"should-not-relay", Duration::from_secs(4)).await;
		assert!(!relayed, "wrong password must not relay data");
		echo_task.abort();
		server.shutdown().await;
	}

	// 4. Unknown UUID: same shape as the wrong-password case.
	{
		let uuid = Uuid::new_v4();
		let server = start_server(backend, uuid, "correct", vec!["h3".into()], vec![], Duration::from_secs(1)).await;
		let stranger = Uuid::new_v4();
		let outbound = try_connect(server.local_addr.port(), stranger, "correct", true, &["h3"])
			.await
			.expect("unknown UUID still completes the QUIC handshake");
		let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "neg-unknown-uuid").await;
		let relayed = low_level_tcp_echo(Arc::new(outbound), echo_addr, b"should-not-relay", Duration::from_secs(4)).await;
		assert!(!relayed, "unknown UUID must not relay data");
		echo_task.abort();
		server.shutdown().await;
	}

	// 5. ACL reject: valid credentials, but the target is denied by the ACL.
	{
		let uuid = Uuid::new_v4();
		let acl = vec![AclRule {
			outbound: "reject".to_string(),
			addr: AclAddress::Localhost,
			ports: None,
			hijack: None,
		}];
		let server = start_server(backend, uuid, "correct", vec!["h3".into()], acl, Duration::from_secs(3)).await;
		let outbound = try_connect(server.local_addr.port(), uuid, "correct", true, &["h3"])
			.await
			.expect("ACL reject applies post-auth; the handshake must still succeed");
		let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "neg-acl-reject").await;
		let relayed = low_level_tcp_echo(Arc::new(outbound), echo_addr, b"should-not-relay", Duration::from_secs(4)).await;
		assert!(!relayed, "ACL-rejected target must not relay data");
		echo_task.abort();
		server.shutdown().await;
	}
}

#[tokio::test]
#[tracing_test::traced_test]
async fn negative_handshake_quinn() {
	run_cases(Backend::Quinn).await;
}

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
#[tokio::test]
#[tracing_test::traced_test]
async fn negative_handshake_quiche() {
	run_cases(Backend::Quiche).await;
}
