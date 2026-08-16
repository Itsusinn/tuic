//! Full-stack >MTU UDP fragmentation/reassembly E2E (quinn backend).
//!
//! `tuic_client::run` installs a process-global connection, so each backend
//! lives in its own test binary; both call the shared
//! [`tuic_tests::udp_fragmentation_case`].

use serial_test::serial;
use tuic_tests::{Backend, udp_fragmentation_case};

#[tokio::test]
#[serial]
#[tracing_test::traced_test]
async fn udp_fragmentation_quinn() {
	udp_fragmentation_case(Backend::Quinn).await;
}
