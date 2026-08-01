//! Graceful-shutdown integration tests at the `App::run()` level.
//!
//! These verify that the full TUIC server (Plugin → Router → Inbound → REST
//! API) stops cleanly within a bounded time when its root `CancellationToken`
//! is cancelled — without relying on OS signals (SIGTERM / Ctrl-C).  This is
//! the path `docker stop` triggers, and it must complete before the container
//! runtime's own SIGKILL deadline.
//!
//! The tests complement the lower-level cancellation tests in `wind-test`
//! (which verify `TuicInbound::listen` in isolation) and `tuic-client` (which
//! verify individual tunnel inbounds).

use std::{
	collections::HashMap,
	net::{Ipv4Addr, SocketAddr},
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
	time::Duration,
};

use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpListener,
	time::timeout,
};
use tuic_server::{Config, TuicServerPlugin};
use wind_core::{AbstractOutbound, App, types::TargetAddr};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Obtain a free UDP port without holding the socket, so the server can bind
/// it immediately afterwards.
fn free_udp_addr() -> SocketAddr {
	let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind free port");
	let a = s.local_addr().expect("local addr");
	drop(s);
	a
}

/// Minimal server config suitable for a cancel-only test — self-signed TLS,
/// empty user list (no client can authenticate, but the inbound starts and
/// enters its accept loop), and a direct default outbound.
fn build_minimal_server_config(server_addr: SocketAddr) -> Config {
	Config {
		server: server_addr,
		users: HashMap::new(),
		tls: tuic_server::config::TlsConfig {
			self_sign: true,
			hostname: "localhost".to_string(),
			alpn: vec!["h3".to_string()],
			..Default::default()
		},
		data_dir: std::env::temp_dir().join("tuic-graceful-shutdown-test"),
		..Default::default()
	}
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// An idle server whose token is cancelled must return `Ok(())` from
/// `App::run()` within a bounded time — no hanging, no timeout-then-SIGKILL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_server_exits_on_cancel() {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

	let addr = free_udp_addr();
	let cfg = build_minimal_server_config(addr);

	let app = App::new().add_plugin(TuicServerPlugin::new(cfg)).await.expect("plugin build");

	let ctx = app.context().clone();
	let handle = tokio::spawn(async move { app.run().await });

	// Give the server a moment to bind and start accepting.
	tokio::time::sleep(Duration::from_millis(300)).await;

	// Trigger graceful shutdown via the cancel token (no OS signal).
	ctx.token.cancel();

	let result = timeout(Duration::from_secs(5), handle)
		.await
		.expect("App::run did not exit within 5s of cancellation")
		.expect("App::run task panicked");

	match result {
		Ok(()) => {} // clean exit
		Err(e) => panic!("App::run returned an error after cancellation: {e}"),
	}
}

/// When a client connects before the token is cancelled, the server must still
/// drain all per-connection handlers and the accept loop within a bounded time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_connection_drains_on_cancel() {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

	let addr = free_udp_addr();

	// Build a config *with* a known user so a client can authenticate.
	let uuid = uuid::Uuid::new_v4();
	let password = "test-password";
	let mut users = HashMap::new();
	users.insert(uuid, password.to_string());

	let cfg = Config {
		server: addr,
		users,
		tls: tuic_server::config::TlsConfig {
			self_sign: true,
			hostname: "localhost".to_string(),
			alpn: vec!["h3".to_string()],
			..Default::default()
		},
		data_dir: std::env::temp_dir().join("tuic-graceful-shutdown-active"),
		..Default::default()
	};

	let app = App::new().add_plugin(TuicServerPlugin::new(cfg)).await.expect("plugin build");

	let ctx = app.context().clone();
	let handle = tokio::spawn(async move { app.run().await });

	// Let the server bind.
	tokio::time::sleep(Duration::from_millis(300)).await;

	// Connect a TUIC client to ensure the server spawns a per-connection
	// handler tracked in ctx.tasks.
	let client_ctx = Arc::new(wind_core::AppContext::default());
	let password_bytes: Arc<[u8]> = Arc::from(password.as_bytes());
	let client_opts = wind_tuic::quinn::outbound::TuicOutboundOpts {
		peer_addr: addr,
		sni: "localhost".to_string(),
		auth: (uuid, password_bytes),
		alpn: vec!["h3".to_string()],
		skip_cert_verify: true,
		zero_rtt_handshake: false,
		heartbeat: Duration::from_secs(30),
		gc_interval: Duration::from_secs(10),
		gc_lifetime: Duration::from_secs(30),
		reconnect: Default::default(),
	};
	let _client = wind_tuic::quinn::outbound::TuicOutbound::new(client_ctx, client_opts).await;
	// Give the server a moment to register the connection handler.
	tokio::time::sleep(Duration::from_millis(200)).await;

	// Cancel — the entire chain from accept loop through per-connection
	// handlers must unwind.
	ctx.token.cancel();

	let result = timeout(Duration::from_secs(10), handle)
		.await
		.expect("App::run did not exit within 10s of cancellation with active client")
		.expect("App::run task panicked");

	match result {
		Ok(()) => {}
		Err(e) => panic!("App::run returned an error after cancellation: {e}"),
	}
}

// ---------------------------------------------------------------------------
// helpers for traffic tests
// ---------------------------------------------------------------------------

/// Build a server config with a known user (for client authentication).
fn build_server_config_with_user(addr: SocketAddr, uuid: uuid::Uuid, password: &str) -> Config {
	let mut users = HashMap::new();
	users.insert(uuid, password.to_string());
	Config {
		server: addr,
		users,
		tls: tuic_server::config::TlsConfig {
			self_sign: true,
			hostname: "localhost".to_string(),
			alpn: vec!["h3".to_string()],
			..Default::default()
		},
		data_dir: std::env::temp_dir().join("tuic-graceful-shutdown-traffic"),
		..Default::default()
	}
}

/// Connect a TUIC client to the given server address / credentials.
async fn connect_tuic_client(
	addr: SocketAddr,
	uuid: uuid::Uuid,
	password: &str,
) -> Arc<wind_tuic::quinn::outbound::TuicOutbound> {
	let ctx = Arc::new(wind_core::AppContext::default());
	let password_bytes: Arc<[u8]> = Arc::from(password.as_bytes());
	let opts = wind_tuic::quinn::outbound::TuicOutboundOpts {
		peer_addr: addr,
		sni: "localhost".to_string(),
		auth: (uuid, password_bytes),
		alpn: vec!["h3".to_string()],
		skip_cert_verify: true,
		zero_rtt_handshake: false,
		heartbeat: Duration::from_secs(30),
		gc_interval: Duration::from_secs(10),
		gc_lifetime: Duration::from_secs(30),
		reconnect: Default::default(),
	};
	let client = wind_tuic::quinn::outbound::TuicOutbound::new(ctx, opts)
		.await
		.expect("connect tuic client");
	Arc::new(client)
}

/// Start a TCP echo server on a random local port. Returns the server task
/// handle and the bound address. The server echoes every byte it receives.
async fn start_tcp_echo_server() -> (tokio::task::JoinHandle<()>, SocketAddr) {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp echo");
	let addr = listener.local_addr().expect("echo addr");
	let handle = tokio::spawn(async move {
		while let Ok((mut stream, _)) = listener.accept().await {
			tokio::spawn(async move {
				let mut buf = vec![0u8; 4096];
				loop {
					match stream.read(&mut buf).await {
						Ok(0) | Err(_) => break,
						Ok(n) => {
							let _ = stream.write_all(&buf[..n]).await;
						}
					}
				}
			});
		}
	});
	(handle, addr)
}

// ---------------------------------------------------------------------------
// long-lived traffic test
// ---------------------------------------------------------------------------

/// When a TUIC client has active, long-lived TCP traffic flowing through the
/// tunnel, cancelling the server's root token must still drain all connection
/// handlers and the accept loop within a bounded time — the traffic must not
/// keep the server alive indefinitely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drains_while_active_traffic_flows() {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

	// 1. Start a local TCP echo server.
	let (_echo_task, echo_addr) = start_tcp_echo_server().await;

	// 2. Build and start the TUIC server.
	let server_addr = free_udp_addr();
	let uuid = uuid::Uuid::new_v4();
	let password = "test-pass";
	let cfg = build_server_config_with_user(server_addr, uuid, password);

	let app = App::new().add_plugin(TuicServerPlugin::new(cfg)).await.expect("plugin build");

	let ctx = app.context().clone();
	let app_handle = tokio::spawn(async move { app.run().await });
	tokio::time::sleep(Duration::from_millis(300)).await;

	// 3. Connect a TUIC client.
	let client = connect_tuic_client(server_addr, uuid, password).await;
	tokio::time::sleep(Duration::from_millis(200)).await;

	// 4. Open a TCP tunnel through TUIC to the echo server and start continuous
	//    traffic in a background task.
	let (local, remote) = tokio::io::duplex(8192);
	let target = TargetAddr::IPv4(Ipv4Addr::LOCALHOST, echo_addr.port());

	let c = client.clone();
	let _tunnel_handle = tokio::spawn(async move {
		let _ = c
			.handle_tcp(target, remote, Option::<wind_tuic::quinn::outbound::TuicOutbound>::None)
			.await;
	});

	// 5. Pump traffic through the tunnel: send a ping, expect the echo back. Run in
	//    a loop to keep the connection busy.
	let traffic_done = Arc::new(AtomicBool::new(false));
	let td = traffic_done.clone();
	let traffic_handle = tokio::spawn(async move {
		let (mut reader, mut writer) = tokio::io::split(local);
		let ping = b"hello-from-tuic-keepalive";
		let mut buf = vec![0u8; ping.len()];
		loop {
			if td.load(Ordering::SeqCst) {
				break;
			}
			if writer.write_all(ping).await.is_err() {
				break;
			}
			match reader.read_exact(&mut buf).await {
				Ok(_) if buf == ping => {} // echo OK
				_ => break,                // connection broken (expected after cancel)
			}
		}
	});

	// Let the traffic loop run for a few round-trips.
	tokio::time::sleep(Duration::from_millis(500)).await;

	// 6. Cancel — traffic is still flowing.
	ctx.token.cancel();
	traffic_done.store(true, Ordering::SeqCst);

	// 7. App::run must exit within 10s.
	let result = timeout(Duration::from_secs(10), app_handle)
		.await
		.expect("App::run did not exit within 10s while traffic was active")
		.expect("App::run task panicked");

	match result {
		Ok(()) => {}
		Err(e) => panic!("App::run returned an error while draining active traffic: {e}"),
	}

	// Clean up: the traffic loop should have exited by now (connection broke).
	let _ = timeout(Duration::from_secs(2), traffic_handle).await;
}
