//! Full-stack >MTU UDP fragmentation/reassembly E2E (quiche backend).
//!
//! Each backend lives in its own test binary; both call the shared
//! [`tuic_tests::udp_fragmentation_case`].

// These e2e tests drive real QUIC sockets; only *run* them on 64-bit hosts
// (cross-emulated 32-bit test execution is unreliable for networking). The
// quiche backend itself now builds on 32-bit too (see patches/tokio-quiche).
#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]

use tuic_tests::{Backend, udp_fragmentation_case};

#[tokio::test]
#[tracing_test::traced_test]
async fn udp_fragmentation_quiche() {
	udp_fragmentation_case(Backend::Quiche).await;
}
