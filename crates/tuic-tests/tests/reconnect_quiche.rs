//! Full-stack reconnect E2E (quiche backend).
//!
//! `tuic_client::run` installs a process-global connection, so each backend
//! lives in its own test binary; both call the shared
//! [`tuic_tests::reconnect_case`].

// These e2e tests drive real QUIC sockets; only *run* them on 64-bit hosts
// (cross-emulated 32-bit test execution is unreliable for networking). The
// quiche backend itself now builds on 32-bit too (see patches/tokio-quiche).
#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]

use serial_test::serial;
use tuic_tests::{Backend, reconnect_case};

#[tokio::test]
#[serial]
#[tracing_test::traced_test]
async fn reconnect_quiche() {
	reconnect_case(Backend::Quiche).await;
}
