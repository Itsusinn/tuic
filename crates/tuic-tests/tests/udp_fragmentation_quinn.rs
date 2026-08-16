//! Full-stack >MTU UDP fragmentation/reassembly E2E (quinn backend).
//!
//! Each backend lives in its own test binary; both call the shared
//! [`tuic_tests::udp_fragmentation_case`].

use tuic_tests::{Backend, udp_fragmentation_case};

#[tokio::test]
#[tracing_test::traced_test]
async fn udp_fragmentation_quinn() {
	udp_fragmentation_case(Backend::Quinn).await;
}
