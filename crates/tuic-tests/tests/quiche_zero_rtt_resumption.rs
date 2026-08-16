//! 0-RTT *resumption* test for the quiche backend.
//!
//! Unlike `quiche_zero_rtt.rs` — which only proves the 0-RTT-enabled config
//! path still relays over a fresh 1-RTT connection — this test drives the full
//! resumption flow and asserts that early data is actually *accepted*:
//!
//! 1. connect once through a `wind-quic` quiche server (full 1-RTT handshake)
//!    and read back the TLS session ticket from the client handle;
//! 2. reconnect with that session via `quiche::connect_with_session`;
//! 3. assert the completed handshake reports
//!    `SSL_early_data_reason == SSL_EARLY_DATA_ACCEPTED (2)` — i.e. the
//!    server accepted the client's early data, not merely the connection.
//!
//! The server here is `wind-quic`'s quiche endpoint with
//! `TransportConfig::enable_0rtt`, the same stack the TUIC server's quiche
//! backend wires `zero_rtt_handshake` into.
//!
//! `rcgen`/quiche are declared under the 64-bit target cfg in Cargo.toml, so
//! keep this file behind the same predicate as the other quiche tests.

#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]

use std::{net::SocketAddr, time::Duration};

use rcgen::generate_simple_self_signed;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tuic_tests::install_crypto_provider;
use wind_quic::{
	QuicConnection as _,
	config::{ClientTlsConfig, ServerTlsConfig, TransportConfig},
	quiche,
};

/// BoringSSL `SSL_early_data_reason_t::ssl_early_data_accepted`.
const SSL_EARLY_DATA_ACCEPTED: u32 = 2;

#[tokio::test]
#[tracing_test::traced_test]
async fn quiche_zero_rtt_resumption_accepts_early_data() -> eyre::Result<()> {
	install_crypto_provider();

	let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
	let data_dir = std::env::temp_dir().join("wind-quiche-resumption-test");
	std::fs::create_dir_all(&data_dir)?;

	// The quiche backend loads credentials from PEM file paths; materialize a
	// self-signed cert (the client skips verification).
	let certified = generate_simple_self_signed(vec!["localhost".to_string()])?;
	let cert_path = data_dir.join("cert.pem");
	let key_path = data_dir.join("key.pem");
	std::fs::write(&cert_path, certified.cert.pem())?;
	std::fs::write(&key_path, certified.signing_key.serialize_pem())?;

	let server_tls = ServerTlsConfig::from_pem_paths(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
	let server_transport = TransportConfig {
		enable_0rtt: true, // mirrors tuic-server `zero_rtt_handshake`
		..Default::default()
	};

	let mut acceptor = quiche::bind_server(server_addr, &server_tls, &server_transport, None).await?;
	let server_addr = acceptor.local_addr();
	let cancel = CancellationToken::new();
	let mut server = tokio::spawn({
		let cancel = cancel.clone();
		async move {
			// First connection (1-RTT): the client closes it once it has the
			// ticket, so just accept and drop.
			let _ = acceptor.accept().await;
			// Second (resumed) connection: hold it open until the test ends.
			let _ = acceptor.accept().await;
			cancel.cancelled().await;
		}
	});

	let client_tls = ClientTlsConfig {
		server_name: "localhost".to_string(),
		verify_certificate: false,
		alpn: vec![b"h3".to_vec()],
		enable_early_data: true,
	};
	// 0-RTT must be enabled on the client's transport too: `enable_early_data`
	// on the TLS config plus `enable_0rtt` on the transport is what quiche
	// needs to attempt early data on a resumed handshake.
	let client_transport = TransportConfig {
		enable_0rtt: true,
		..Default::default()
	};

	// 1) First connection: full 1-RTT handshake; capture the session ticket.
	let conn1 = quiche::connect(server_addr, &client_tls, &client_transport).await?;
	// The ticket arrives right after the handshake (NewSessionTicket), so poll
	// until the driver has received and processed it.
	let session = timeout(Duration::from_secs(5), async {
		loop {
			if let Some(s) = conn1.session().await {
				break s;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	})
	.await
	.map_err(|_| eyre::eyre!("quiche client never received a session ticket from the first handshake"))?;
	conn1.close(0, b"first connection done");
	tokio::time::sleep(Duration::from_millis(200)).await;

	// 2) Second connection resuming that session.
	let conn2 = quiche::connect_with_session(server_addr, &client_tls, &client_transport, Some(session)).await?;

	// 3) The decisive assertion: the server must have *accepted* the early
	// data (`SSL_EARLY_DATA_ACCEPTED == 2`). Anything else — not sent,
	// rejected, session not resumed — means no 0-RTT happened.
	let reason = conn2.early_data_reason();
	assert_eq!(
		reason, SSL_EARLY_DATA_ACCEPTED,
		"quiche server did not accept 0-RTT early data on the resumed handshake (SSL_early_data_reason={reason}, \
		 expected 2 = SSL_EARLY_DATA_ACCEPTED)"
	);

	// Let the second connection close cleanly before tearing the server down.
	conn2.close(0, b"second connection done");
	tokio::time::sleep(Duration::from_millis(100)).await;
	cancel.cancel();
	let _ = timeout(Duration::from_secs(10), &mut server).await;
	Ok(())
}
