//! Full-stack reconnect E2E (quinn backend).
//!
//! The backend-specific cases call the shared
//! [`tuic_tests::reconnect_case`].

use tuic_tests::{Backend, reconnect_case};

#[tokio::test]
#[tracing_test::traced_test]
async fn reconnect_quinn() {
	reconnect_case(Backend::Quinn).await;
}
