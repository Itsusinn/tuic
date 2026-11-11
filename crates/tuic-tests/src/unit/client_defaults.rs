mod backend {
	use tuic_client::config::{BackendMode, Relay};
	/// Keep the backend selection explicit: these tests only make sense on quinn.
	#[test]
	fn relay_defaults_to_the_quinn_backend() {
		let relay = Relay::default();
		assert_eq!(relay.backend_mode, BackendMode::Quinn);
	}
}
