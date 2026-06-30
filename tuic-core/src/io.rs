//! Bidirectional relay copy with a half-close idle reaper.
//!
//! [`copy_bidirectional`] behaves like [`tokio::io::copy_bidirectional`] but
//! additionally protects against the *idle half-closed relay* leak: when one
//! peer half-closes (sends FIN) while the other keeps its half of the stream
//! open and idle, a plain bidirectional copy waits forever for the second EOF.
//! The still-open socket then lingers in `CLOSE_WAIT` for the entire lifetime
//! of the parent QUIC connection, accumulating until the process is restarted.

use std::{future::pending, time::Duration};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BUFFER_SIZE: usize = 16 * 1024;

/// Default idle window before a half-closed relay is reaped.
///
/// Used by callers that don't expose a configurable idle timeout. The server
/// overrides this with its `stream_timeout` setting.
pub const RELAY_HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Copy data in both directions between `a` and `b`.
///
/// Returns once *both* directions reach EOF, an IO error occurs, or — only
/// after the relay becomes *half-closed* (exactly one direction has reached
/// EOF) — no bytes move for `half_close_timeout`.
///
/// The idle reaper arms only while the relay is half-open and is reset by any
/// byte transferred, so a slow-but-steady half-open transfer is preserved while
/// a truly idle one is reaped promptly. A fully-open idle tunnel (neither side
/// has sent FIN, e.g. a keep-alive connection) is never reaped, matching
/// [`tokio::io::copy_bidirectional`]. A `half_close_timeout` of zero disables
/// the reaper entirely.
///
/// Returns `(a_to_b_bytes, b_to_a_bytes, last_error)`.
pub async fn copy_bidirectional<A, B>(
	a: &mut A,
	b: &mut B,
	half_close_timeout: Duration,
) -> (usize, usize, Option<std::io::Error>)
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	let mut a2b = BytesMut::with_capacity(BUFFER_SIZE);
	let mut b2a = BytesMut::with_capacity(BUFFER_SIZE);

	let mut a2b_num = 0;
	let mut b2a_num = 0;

	let mut a_eof = false;
	let mut b_eof = false;

	let mut last_err = None;

	let reaper_enabled = !half_close_timeout.is_zero();

	loop {
		// Arm an idle reaper only while the relay is half-closed. The future is
		// rebuilt every iteration, so any byte transferred restarts the countdown.
		// While fully open, it resolves to `pending` and never fires.
		let half_closed = a_eof ^ b_eof;
		let reaper = async {
			if reaper_enabled && half_closed {
				tokio::time::sleep(half_close_timeout).await;
			} else {
				pending::<()>().await;
			}
		};

		tokio::select! {
			a2b_res = a.read_buf(&mut a2b), if !a_eof => match a2b_res {
				Ok(0) => {
					a_eof = true;
					if let Err(err) = b.shutdown().await {
						last_err = Some(err);
					}
					if b_eof {
						break;
					}
				}
				Ok(num) => {
					a2b_num += num;
					if let Err(err) = b.write_all(&a2b[..num]).await {
						last_err = Some(err);
						break;
					}
					a2b.clear();
				}
				Err(err) => {
					last_err = Some(err);
					break;
				}
			},
			b2a_res = b.read_buf(&mut b2a), if !b_eof => match b2a_res {
				Ok(0) => {
					b_eof = true;
					if let Err(err) = a.shutdown().await {
						last_err = Some(err);
					}
					if a_eof {
						break;
					}
				}
				Ok(num) => {
					b2a_num += num;
					if let Err(err) = a.write_all(&b2a[..num]).await {
						last_err = Some(err);
						break;
					}
					b2a.clear();
				}
				Err(err) => {
					last_err = Some(err);
					break;
				}
			},
			// Half-open and idle past the timeout: stop waiting for the peer that
			// will never close so the still-open socket is released instead of
			// lingering in CLOSE_WAIT for the lifetime of the parent connection.
			() = reaper => break,
		}
	}

	(a2b_num, b2a_num, last_err)
}

#[cfg(test)]
mod tests {
	use tokio::io::duplex;

	use super::*;

	#[tokio::test]
	async fn test_copy_bidirectional() {
		let (mut client, mut server_side) = duplex(1024);
		let (mut remote, mut remote_side) = duplex(1024);

		let data_to_remote = b"hello from client";
		let data_to_client = b"hello from remote";

		// Spawn writer tasks that write and then shut down
		let client_writer = tokio::spawn(async move {
			client.write_all(data_to_remote).await.unwrap();
			client.shutdown().await.unwrap();
			// Read response
			let mut buf = Vec::new();
			client.read_to_end(&mut buf).await.unwrap();
			buf
		});

		let remote_writer = tokio::spawn(async move {
			remote_side.write_all(data_to_client).await.unwrap();
			remote_side.shutdown().await.unwrap();
			let mut buf = Vec::new();
			remote_side.read_to_end(&mut buf).await.unwrap();
			buf
		});

		let (a2b, b2a, err) = copy_bidirectional(&mut server_side, &mut remote, RELAY_HALF_CLOSE_TIMEOUT).await;

		assert_eq!(a2b, data_to_remote.len());
		assert_eq!(b2a, data_to_client.len());
		assert!(err.is_none());

		let client_received = client_writer.await.unwrap();
		let remote_received = remote_writer.await.unwrap();
		assert_eq!(client_received, data_to_client);
		assert_eq!(remote_received, data_to_remote);
	}

	#[tokio::test]
	async fn test_copy_empty_streams() {
		let (mut client, mut server_side) = duplex(1024);
		let (mut remote, mut remote_side) = duplex(1024);

		// Close both sides immediately
		tokio::spawn(async move {
			client.shutdown().await.unwrap();
		});
		tokio::spawn(async move {
			remote_side.shutdown().await.unwrap();
		});

		let (a2b, b2a, _err) = copy_bidirectional(&mut server_side, &mut remote, RELAY_HALF_CLOSE_TIMEOUT).await;

		assert_eq!(a2b, 0);
		assert_eq!(b2a, 0);
	}

	#[tokio::test]
	async fn test_copy_one_direction_only() {
		let (mut client, mut server_side) = duplex(1024);
		let (mut remote, mut remote_side) = duplex(1024);

		let data = b"one way only";

		tokio::spawn(async move {
			client.write_all(data).await.unwrap();
			client.shutdown().await.unwrap();
			// Drain incoming
			let mut buf = Vec::new();
			let _ = client.read_to_end(&mut buf).await;
		});

		tokio::spawn(async move {
			// Only read, don't write
			remote_side.shutdown().await.unwrap();
			let mut buf = Vec::new();
			let _ = remote_side.read_to_end(&mut buf).await;
		});

		let (a2b, b2a, _err) = copy_bidirectional(&mut server_side, &mut remote, RELAY_HALF_CLOSE_TIMEOUT).await;

		assert_eq!(a2b, data.len());
		assert_eq!(b2a, 0);
	}

	#[tokio::test]
	async fn test_copy_large_data() {
		let (mut client, mut server_side) = duplex(64 * 1024);
		let (mut remote, mut remote_side) = duplex(64 * 1024);

		let data = vec![0xAB; 100_000];
		let data_clone = data.clone();

		tokio::spawn(async move {
			client.write_all(&data_clone).await.unwrap();
			client.shutdown().await.unwrap();
			let mut buf = Vec::new();
			let _ = client.read_to_end(&mut buf).await;
		});

		tokio::spawn(async move {
			// Echo!
			remote_side.shutdown().await.unwrap();
			let mut buf = Vec::new();
			let _ = remote_side.read_to_end(&mut buf).await;
		});

		let (a2b, b2a, _err) = copy_bidirectional(&mut server_side, &mut remote, RELAY_HALF_CLOSE_TIMEOUT).await;

		assert_eq!(a2b, 100_000);
		assert_eq!(b2a, 0);
	}

	/// The core fix: the remote half-closes after responding while the client
	/// keeps its upload open and idle. The reaper must terminate the relay
	/// instead of hanging forever (which would leak the remote socket).
	#[tokio::test(start_paused = true)]
	async fn test_half_open_is_reaped() {
		let (client, mut server_side) = duplex(1024);
		let (mut remote, mut remote_side) = duplex(1024);

		// Remote sends a response then half-closes (FIN).
		let data_to_client = b"hello from remote";
		remote_side.write_all(data_to_client).await.unwrap();
		remote_side.shutdown().await.unwrap();

		// Hold both peers open: `client` keeps a's read pending forever, and
		// keeping `remote_side` alive preserves b's write half. Dropping either
		// would close the stream and defeat the test.
		let _hold_client = client;
		let _hold_remote_side = remote_side;

		let (a2b, b2a, err) = copy_bidirectional(&mut server_side, &mut remote, Duration::from_secs(30)).await;

		assert_eq!(a2b, 0, "client sent nothing");
		assert_eq!(b2a, data_to_client.len(), "remote response is relayed before reaping");
		assert!(err.is_none(), "reaping is a clean shutdown, not an error");
	}

	/// A fully-open idle tunnel (keep-alive) must never be reaped.
	#[tokio::test(start_paused = true)]
	async fn test_full_open_idle_not_reaped() {
		let (client, mut server_side) = duplex(1024);
		let (mut remote, remote_side) = duplex(1024);

		let _hold_client = client;
		let _hold_remote_side = remote_side;

		// A large half_close_timeout ensures the outer guard fires first even if
		// the reaper were (incorrectly) armed.
		let res = tokio::time::timeout(
			Duration::from_secs(10),
			copy_bidirectional(&mut server_side, &mut remote, Duration::from_secs(100)),
		)
		.await;

		assert!(res.is_err(), "fully-open idle tunnel must not be reaped");
	}

	/// A `half_close_timeout` of zero disables the reaper, restoring the
	/// "wait for both directions to EOF" behaviour.
	#[tokio::test(start_paused = true)]
	async fn test_reaper_disabled_waits_for_both_eof() {
		let (client, mut server_side) = duplex(1024);
		let (mut remote, mut remote_side) = duplex(1024);

		remote_side.write_all(b"data").await.unwrap();
		remote_side.shutdown().await.unwrap();
		let _hold_client = client;
		let _hold_remote_side = remote_side;

		let res = tokio::time::timeout(
			Duration::from_secs(120),
			copy_bidirectional(&mut server_side, &mut remote, Duration::ZERO),
		)
		.await;

		assert!(
			res.is_err(),
			"with the reaper disabled, a half-open relay must not self-terminate"
		);
	}

	/// Traffic on the still-open direction resets the reaper, so a slow but
	/// steady half-open transfer is preserved; only true idleness reaps it.
	#[tokio::test(start_paused = true)]
	async fn test_activity_resets_reaper() {
		let (mut client, mut server_side) = duplex(1024);
		let (mut remote, mut remote_side) = duplex(1024);

		// Remote half-closes up front.
		remote_side.shutdown().await.unwrap();
		let _hold_remote_side = remote_side;

		// Client dribbles bytes with gaps shorter than the 30s reaper window,
		// then goes idle. Each byte must reset the reaper; only the final gap
		// reaps. If a reset were missing, the relay would end early and drop
		// bytes, so the asserted count would not match.
		let n_bytes = 3usize;
		let writer = tokio::spawn(async move {
			for _ in 0..n_bytes {
				tokio::time::sleep(Duration::from_secs(20)).await;
				client.write_all(b"x").await.unwrap();
			}
			// Hold the upload open and idle so the reaper (not EOF) ends it.
			pending::<()>().await;
		});

		let (a2b, b2a, err) = copy_bidirectional(&mut server_side, &mut remote, Duration::from_secs(30)).await;

		assert_eq!(a2b, n_bytes, "every dribbled byte is relayed before the reaper fires");
		assert_eq!(b2a, 0);
		assert!(err.is_none());

		writer.abort();
	}
}
