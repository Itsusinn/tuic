//! Full-stack reconnect E2E (quiche backend).
//!
//! The backend-specific cases call the shared
//! [`tuic_tests::reconnect_case`].

// These e2e tests drive real QUIC sockets; only *run* them on 64-bit hosts
// (cross-emulated 32-bit test execution is unreliable for networking). The
// quiche backend itself now builds on 32-bit too (see patches/tokio-quiche).

use tuic_tests::{Backend, reconnect_case};

#[tokio::test]
#[tracing_test::traced_test]
async fn reconnect_quiche() {
	reconnect_case(Backend::Quiche).await;
}
