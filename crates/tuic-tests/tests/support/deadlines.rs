use std::time::Duration;

/// Outer deadline for the UDP relay half.
///
/// It has to outlive what the UDP relay helper does on its own: a 100 ms settle
/// before the relay starts plus its [`tuic_tests::UDP_RELAY_RESPONSE_DEADLINE`]
/// window, inside which it retransmits a lost datagram. A tighter outer
/// deadline aborts the relay while the helper is still retransmitting, so a
/// slow relay surfaces as this test's opaque "timed out" panic instead of the
/// helper's own diagnostic. Twice the helper's window also leaves room for the
/// SOCKS5 UDP association setup.
pub const UDP_RELAY_TIMEOUT: Duration = Duration::from_secs(10);
