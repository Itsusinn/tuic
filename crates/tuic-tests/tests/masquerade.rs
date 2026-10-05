//! End-to-end test for the HTTP/3 masquerade, using **reqwest's HTTP/3 client**
//! as the "prober".
//!
//! A real HTTP/3 GET against the (quinn) `tuic-server` must come back as the
//! reverse-proxied upstream response — proving a non-TUIC client is served like
//! a genuine web server rather than reset. Exercises the whole path: QUIC
//! handshake, first-byte classification (`0x05` vs not), the `h3::quic`
//! adapter, the `h3` server, and the reqwest reverse proxy to the upstream.
//!
//! Runs with the default build; reqwest's experimental HTTP/3 stack needs the
//! `--cfg reqwest_unstable` flag, which the workspace `.cargo/config.toml`
//! sets.
#![cfg(all(reqwest_unstable, target_pointer_width = "64"))]

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use tokio::{
	io::{AsyncReadExt as _, AsyncWriteExt as _},
	net::{TcpListener, TcpStream},
	task::{JoinHandle, JoinSet},
	time::timeout,
};
use tokio_util::sync::CancellationToken;
use tuic_tests::install_crypto_provider;
use uuid::Uuid;

const UPSTREAM_BODY: &str = "wind masquerade upstream OK";

/// How long the upstream may take to stop once its cancellation token fires.
/// Cancelling it settles the accept loop and shuts its connection handlers
/// down, so the only way to exceed this is a loop that cannot be stopped.
const UPSTREAM_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

/// A trivial HTTP/1.1 upstream: answers every request with a fixed 200 body.
/// This is what the masquerade reverse-proxies to.
///
/// The listener and every connection handler it accepts belong to this value,
/// so the test can ask the upstream to stop and observe that it did, instead of
/// leaving a detached task whose only teardown is the runtime being dropped.
struct Upstream {
	addr: SocketAddr,
	/// Stops the accept loop; ending the loop also ends its connection
	/// handlers.
	cancel: CancellationToken,
	task: JoinHandle<()>,
}

impl Upstream {
	/// Binds `127.0.0.1:0` and starts serving on the address the OS assigned.
	async fn start() -> eyre::Result<Self> {
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		let cancel = CancellationToken::new();
		let task = tokio::spawn(accept_upstream_requests(listener, cancel.clone()));
		Ok(Self { addr, cancel, task })
	}

	/// Cancels the accept loop and waits for it under a deadline, so an
	/// upstream that ignores cancellation fails the caller instead of
	/// silently outliving it.
	async fn shutdown(mut self) -> eyre::Result<()> {
		self.cancel.cancel();
		match timeout(UPSTREAM_SHUTDOWN_DEADLINE, &mut self.task).await {
			Ok(Ok(())) => Ok(()),
			Ok(Err(err)) => eyre::bail!("the upstream task panicked instead of shutting down cleanly: {err}"),
			Err(_) => {
				self.task.abort();
				eyre::bail!(
					"the upstream was still serving requests {UPSTREAM_SHUTDOWN_DEADLINE:?} after its cancellation token fired"
				)
			}
		}
	}
}

impl Drop for Upstream {
	fn drop(&mut self) {
		// Only reached when the test left through an early return: `shutdown`
		// has already joined the task by then, and aborting a finished task is
		// a no-op.
		self.cancel.cancel();
		self.task.abort();
	}
}

/// Accepts probe requests until `cancel` fires, then stops.
async fn accept_upstream_requests(listener: TcpListener, cancel: CancellationToken) {
	let mut connections = JoinSet::new();
	loop {
		tokio::select! {
			biased;
			() = cancel.cancelled() => break,
			// Reap finished handlers so the set cannot grow without bound.
			Some(_) = connections.join_next(), if !connections.is_empty() => {}
			accepted = listener.accept() => match accepted {
				Ok((sock, _)) => {
					connections.spawn(answer_probe(sock));
				}
				Err(_) => break,
			},
		}
	}
	// Aborts whatever is still mid-request and waits for it: an upstream that
	// has stopped must not leave connection handlers behind.
	connections.shutdown().await;
}

/// Reads one request and answers it with the fixed 200 body.
///
/// A probe GET has no body, so a single read drains the request line and the
/// headers; the request itself is never parsed.
async fn answer_probe(mut sock: TcpStream) {
	let mut buf = [0u8; 8192];
	let _ = sock.read(&mut buf).await;
	let resp = format!(
		"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
		UPSTREAM_BODY.len(),
		UPSTREAM_BODY
	);
	let _ = sock.write_all(resp.as_bytes()).await;
	let _ = sock.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn masquerade_reverse_proxies_http3_probes() -> eyre::Result<()> {
	install_crypto_provider();

	let upstream = Upstream::start().await?;

	// Bind to `:0` so the OS assigns a free port atomically.
	let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
	let uuid = Uuid::new_v4();

	let cfg = tuic_server::Config {
		log_level: tuic_server::config::LogLevel::Debug,
		server: server_addr,
		users: {
			let mut users = HashMap::new();
			users.insert(uuid, "pw".to_string());
			users
		},
		tls: tuic_server::config::TlsConfig {
			self_sign: true,
			hostname: "localhost".to_string(),
			// The server must advertise the `h3` ALPN for an HTTP/3 client to
			// negotiate at all — this is also what TUIC uses to disguise itself.
			alpn: vec!["h3".to_string()],
			..Default::default()
		},
		masquerade: tuic_server::config::MasqueradeConfig {
			enabled: true,
			upstream: format!("http://{}", upstream.addr),
		},
		data_dir: std::env::temp_dir().join("wind-masquerade-test"),
		experimental: tuic_server::config::ExperimentalConfig {
			drop_loopback: false,
			drop_private: false,
		},
		..Default::default()
	};

	// `run` returns once the inbound has bound and reported its address; a
	// failure to start surfaces as an error here.
	let server = tuic_server::run(cfg).await?;

	// reqwest as a real HTTP/3 prober. `danger_accept_invalid_certs` because
	// the server uses a self-signed cert; `http3_prior_knowledge` forces h3.
	let client = reqwest::Client::builder()
		.danger_accept_invalid_certs(true)
		.http3_prior_knowledge()
		.build()?;

	let url = format!("https://{}/some/secret/path?probe=1", server.local_addr);
	let res = timeout(
		Duration::from_secs(10),
		client.get(&url).version(http::Version::HTTP_3).send(),
	)
	.await
	.map_err(|_| eyre::eyre!("HTTP/3 request to the masquerade timed out"))??;

	assert_eq!(res.version(), http::Version::HTTP_3, "response must be HTTP/3");
	assert_eq!(res.status(), 200, "masquerade should return the upstream's 200");
	let body = res.text().await?;
	assert_eq!(body, UPSTREAM_BODY, "masquerade must relay the upstream body");

	server.shutdown().await;

	// The upstream must stop because it was asked to, not because the test
	// runtime is going away. This used to be a bare `tokio::spawn` whose handle
	// was dropped, so an accept loop that never noticed a stop request could
	// not fail this test.
	upstream.shutdown().await?;

	Ok(())
}
