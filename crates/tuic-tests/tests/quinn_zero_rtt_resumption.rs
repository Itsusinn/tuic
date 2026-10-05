//! 0-RTT *resumption* test for the quinn backend.
//!
//! Unlike `quinn_zero_rtt.rs` — which only proves the 0-RTT-enabled config
//! path still relays over a fresh 1-RTT connection — this test drives the full
//! resumption flow and asserts that early data is actually *accepted*:
//!
//! 1. connect once (full 1-RTT handshake; the server sends a TLS 1.3 session
//!    ticket which the client caches in memory);
//! 2. reconnect on the **same** client endpoint/config (so the ticket is still
//!    there) and convert the handshake via `Connecting::into_0rtt()`;
//! 3. open a stream and write before the handshake completes, then assert on
//!    the server side that the received stream `is_0rtt()` — i.e. the server
//!    *accepted* the client's early data rather than rejecting it.
//!
//! The client is `wind-quic`'s `QuinnClient` (the stack the `wind-tuic` quinn
//! outbound builds on) with 0-RTT enabled. The server is a raw quinn endpoint
//! because the vendored quinn fork drops upstream's `ZeroRttAccepted` future
//! and `wind-quic`'s acceptor awaits the handshake before yielding the
//! connection — both of which would hide the accept/reject verdict. Accepting
//! the resumed connection via `Connecting::into_0rtt()` (0.5-RTT) and reading
//! the stream while the handshake is still in flight is the decisive
//! observation: a rejected 0-RTT stream is never surfaced to the server at
//! all.
//!
//! `quinn`/`rcgen` are declared under the 64-bit target cfg in Cargo.toml, so
//! keep this file behind the same predicate as the quiche tests.

#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]

use std::{
	net::SocketAddr,
	sync::{
		Arc,
		atomic::{AtomicUsize, Ordering},
	},
	time::{Duration, Instant},
};

use quinn::crypto::rustls::QuicClientConfig;
use rcgen::generate_simple_self_signed;
use rustls::{
	client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue},
	pki_types::{PrivateKeyDer, ServerName},
};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tuic_tests::install_crypto_provider;
use wind_quic::config::ClientTlsConfig;

/// How long the first connection may take to leave a usable resumption ticket
/// in the client's TLS session cache before the test gives up on it.
const TICKET_DEADLINE: Duration = Duration::from_secs(5);
/// Polling granularity while waiting for that ticket.
const TICKET_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[tokio::test]
#[tracing_test::traced_test]
async fn quinn_zero_rtt_resumption_accepts_early_data() -> eyre::Result<()> {
	install_crypto_provider();

	let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

	// Self-signed certificate for the test server (the client skips
	// verification, so no trust store is needed).
	let certified = generate_simple_self_signed(vec!["localhost".to_string()])?;
	let mut server_crypto =
		rustls::ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(vec![certified.cert.der().clone()], {
				let der = certified.signing_key.serialize_der();
				PrivateKeyDer::Pkcs8(der.into())
			})?;
	server_crypto.alpn_protocols = vec![b"h3".to_vec()];
	// Accepting 0-RTT requires the server to advertise a non-zero early-data
	// size (QUIC mandates exactly `u32::MAX`); this mirrors what `wind-quic`
	// does when `TransportConfig::enable_0rtt` is set (i.e. the TUIC server's
	// `zero_rtt_handshake`).
	server_crypto.max_early_data_size = u32::MAX;

	let server_endpoint = quinn::Endpoint::server(
		quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?)),
		server_addr,
	)?;
	let server_addr = server_endpoint.local_addr()?;

	let (result_tx, result_rx) = tokio::sync::oneshot::channel();
	let cancel = CancellationToken::new();
	let mut server = tokio::spawn({
		let cancel = cancel.clone();
		async move {
			// `conn2` must outlive the outcome block (dropping it aborts the
			// second connection while the client is still confirming the
			// handshake), so stash it here until the task ends.
			let mut conn2_holder: Option<quinn::Connection> = None;
			let outcome = async {
				// First connection: complete the handshake (1-RTT) and close.
				let incoming = server_endpoint
					.accept()
					.await
					.ok_or_else(|| eyre::eyre!("server: no first connection"))?;
				let conn1 = incoming.accept()?.await?;
				conn1.close(0u32.into(), b"server done with first connection");

				// Second (resumed) connection: accept as 0.5-RTT immediately so
				// we can observe the stream *before* the handshake
				// finishes. If the server accepted the client's early data,
				// the stream is visible here and reports `is_0rtt() ==
				// true`.
				let incoming = server_endpoint
					.accept()
					.await
					.ok_or_else(|| eyre::eyre!("server: no second connection"))?;
				let conn2 = incoming
					.accept()?
					.into_0rtt()
					.map_err(|_| eyre::eyre!("server: into_0rtt failed (unexpected on the server side)"))?;
				let (mut send, mut recv) = conn2.accept_bi().await?;
				let mut buf = [0u8; 32];
				let n = timeout(Duration::from_secs(5), recv.read(&mut buf))
					.await
					.map_err(|_| eyre::eyre!("server: timeout reading early data"))??
					.ok_or_else(|| eyre::eyre!("server: unexpected EOF on early-data stream"))?;
				let is_0rtt = recv.is_0rtt();
				// Echo back so the client can confirm the round trip.
				send.write_all(&buf[..n]).await?;
				conn2_holder = Some(conn2);
				Ok::<_, eyre::Report>((n, is_0rtt))
			}
			.await;
			let _ = result_tx.send(outcome);
			// Keep the endpoint and `conn2` alive until the test signals
			// teardown.
			cancel.cancelled().await;
			drop(conn2_holder);
		}
	});

	// A *persistent* client endpoint/config so the session ticket obtained by
	// the first connection survives into the second one. The config is mapped
	// from the same `wind-quic` `ClientTlsConfig` the real client uses, but
	// with a session store the test can observe: `into_0rtt()` only succeeds
	// once rustls has actually cached a TLS 1.3 ticket, and quinn reports the
	// first handshake as complete *before* that ticket arrives.
	let client_tls = ClientTlsConfig {
		server_name: "localhost".to_string(),
		verify_certificate: false,
		alpn: vec![b"h3".to_vec()],
		enable_early_data: true,
	};
	let tickets = TicketStore::new();
	let client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
	client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(
		client_crypto(&client_tls, tickets.clone())?,
	)?)));

	// 1) First connection: full 1-RTT handshake; server sends a session ticket.
	let conn1 = client_endpoint.connect(server_addr, "localhost")?.await?;
	// The NewSessionTicket is a post-handshake message, so it is processed
	// after `connect()` reports the handshake as complete; wait (bounded) until
	// rustls has cached it instead of guessing a settle time.
	let wait_started = Instant::now();
	while tickets.cached() == 0 {
		if wait_started.elapsed() >= TICKET_DEADLINE {
			return Err(eyre::eyre!(
				"client did not cache a TLS 1.3 resumption ticket within {TICKET_DEADLINE:?} of the first connection"
			));
		}
		tokio::time::sleep(TICKET_POLL_INTERVAL).await;
	}
	conn1.close(0u32.into(), b"first connection done");

	// 2) Second connection must attempt 0-RTT (resumable session cached).
	let connecting = client_endpoint.connect(server_addr, "localhost")?;
	let conn2 = connecting.into_0rtt().map_err(|_| {
		eyre::eyre!(
			"client did not attempt 0-RTT on reconnect: no resumable session ticket was cached from the first connection"
		)
	})?;

	// Send application data on a fresh stream before the handshake completes —
	// at the QUIC layer this is the early data.
	let (mut send, mut recv) = conn2.open_bi().await?;
	send.write_all(b"early data").await?;

	// 3) Server-side verdict: it must have accepted the early data (the stream
	// it received was opened during the 0-RTT phase) and echoed it.
	let (n, is_0rtt) = timeout(Duration::from_secs(10), result_rx)
		.await
		.map_err(|_| eyre::eyre!("server task did not report in time"))?
		.map_err(|_| eyre::eyre!("server task panicked before reporting"))??;
	assert!(
		is_0rtt,
		"server rejected the client's 0-RTT early data on the resumed handshake"
	);

	let mut echoed = vec![0u8; n];
	// Wait for the handshake to be fully confirmed before touching the 0-RTT
	// stream: quinn only marks early data accepted after processing the
	// server's EncryptedExtensions (and rejects it otherwise).
	timeout(Duration::from_secs(10), conn2.authenticated())
		.await
		.map_err(|_| eyre::eyre!("client: handshake never confirmed"))??;
	timeout(Duration::from_secs(5), recv.read_exact(&mut echoed))
		.await
		.map_err(|_| eyre::eyre!("client: timeout reading echoed data"))??;
	assert_eq!(&echoed, b"early data", "echoed early data mismatch");

	conn2.close(0u32.into(), b"second connection done");
	cancel.cancel();
	let _ = timeout(Duration::from_secs(10), &mut server).await;
	Ok(())
}

/// A rustls session store that additionally reports how many TLS 1.3 tickets
/// it holds, so the test can wait for the resumption precondition instead of
/// sleeping.
///
/// Note the capacity: `ClientSessionMemoryCache` derives its server-slot count
/// from this number, and a value of 8 or less collapses to a single slot that
/// is evicted by the very insertion that fills it.
#[derive(Debug)]
struct TicketStore {
	cache: rustls::client::ClientSessionMemoryCache,
	tickets: AtomicUsize,
}

impl TicketStore {
	fn new() -> Arc<Self> {
		Arc::new(Self {
			cache: rustls::client::ClientSessionMemoryCache::new(64),
			tickets: AtomicUsize::new(0),
		})
	}

	fn cached(&self) -> usize {
		self.tickets.load(Ordering::SeqCst)
	}
}

impl ClientSessionStore for TicketStore {
	fn set_kx_hint(&self, server_name: ServerName<'static>, group: rustls::NamedGroup) {
		ClientSessionStore::set_kx_hint(&self.cache, server_name, group);
	}

	fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<rustls::NamedGroup> {
		ClientSessionStore::kx_hint(&self.cache, server_name)
	}

	fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
		ClientSessionStore::set_tls12_session(&self.cache, server_name, value);
	}

	fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
		ClientSessionStore::tls12_session(&self.cache, server_name)
	}

	fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
		ClientSessionStore::remove_tls12_session(&self.cache, server_name);
	}

	fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue) {
		self.tickets.fetch_add(1, Ordering::SeqCst);
		ClientSessionStore::insert_tls13_ticket(&self.cache, server_name, value);
	}

	fn take_tls13_ticket(&self, server_name: &ServerName<'_>) -> Option<Tls13ClientSessionValue> {
		// The concrete cache insists on a `'static` name, so hand it an owned
		// copy (this runs once per connection attempt).
		let owned: ServerName<'static> = server_name.to_owned();
		ClientSessionStore::take_tls13_ticket(&self.cache, &owned)
	}
}

/// Builds the client `rustls::ClientConfig` the way `wind-quic` does for
/// `verify_certificate = false`, with the observable session store attached.
/// Only the tests build their own client config; production code keeps using
/// `wind_quic`'s `QuinnClient`.
fn client_crypto(cfg: &ClientTlsConfig, tickets: Arc<TicketStore>) -> eyre::Result<rustls::ClientConfig> {
	let provider = rustls::crypto::CryptoProvider::get_default()
		.ok_or_else(|| eyre::eyre!("no default crypto provider installed"))?
		.clone();
	let mut crypto = rustls::ClientConfig::builder()
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
		.with_no_client_auth();
	crypto.alpn_protocols = cfg.alpn.clone();
	crypto.enable_early_data = cfg.enable_early_data;
	crypto.resumption = rustls::client::Resumption::store(tickets);
	Ok(crypto)
}

/// Accepts any server certificate. The test server uses a throwaway
/// self-signed certificate, which is why `ClientTlsConfig` is built with
/// `verify_certificate = false` here.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
	fn verify_server_cert(
		&self,
		_end_entity: &rustls::pki_types::CertificateDer<'_>,
		_intermediates: &[rustls::pki_types::CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp: &[u8],
		_now: rustls::pki_types::UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &rustls::pki_types::CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &rustls::pki_types::CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		self.0.signature_verification_algorithms.supported_schemes()
	}
}
