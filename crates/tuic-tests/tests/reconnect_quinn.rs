//! Full-stack reconnect E2E (quinn backend).
//!
//! `tuic_client::run` installs a process-global connection, so each backend
//! lives in its own test binary; both call the shared
//! [`tuic_tests::reconnect_case`].

use serial_test::serial;
use tuic_tests::{Backend, reconnect_case};

#[tokio::test]
#[serial]
#[tracing_test::traced_test]
async fn reconnect_quinn() {
	reconnect_case(Backend::Quinn).await;
}
