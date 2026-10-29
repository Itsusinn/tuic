#[path = "../../tests/support/deadlines.rs"]
mod deadlines;
use deadlines::UDP_RELAY_TIMEOUT;

/// The outer UDP deadline must stay strictly above the relay helper's own
/// response window: the helper retransmits a lost datagram for that whole
/// window, so an outer deadline inside it can only abort a relay that is still
/// making progress.
#[test]
fn the_udp_relay_deadline_outlives_the_helper_response_window() {
	assert!(
		UDP_RELAY_TIMEOUT > crate::UDP_RELAY_RESPONSE_DEADLINE,
		"outer UDP deadline {UDP_RELAY_TIMEOUT:?} must exceed the relay helper's response window {:?}",
		crate::UDP_RELAY_RESPONSE_DEADLINE
	);
}

// The module header is audited by the `port_audit` test in this directory,
// which fails if this file ever documents a fixed loopback port again.

/// A crate-level allowance for unused imports would let a removed call site
/// leave a dead `use` behind with no diagnostic at all, which is how the
/// imports in this file previously drifted out of date; the compiler only keeps
/// reporting them while such an allowance is absent. The audit is textual
/// because no build of this file can observe an attribute that would silence
/// it.
#[test]
fn the_file_does_not_mute_unused_import_warnings() {
	const SOURCE: &str = include_str!("../../tests/e2e/ipv6.rs");
	const FORBIDDEN: &str = concat!("allow", "(unused_imports)");
	assert!(
		!SOURCE.contains(FORBIDDEN),
		"e2e/ipv6.rs must drop its dead imports instead of muting the warnings about them"
	);
}
