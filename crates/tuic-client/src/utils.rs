pub use wind_core::StackPrefer;
pub use wind_tuic::quinn::{CongestionControl, UdpRelayMode};

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ipstack_prefer_values_distinct() {
		assert_ne!(StackPrefer::V4only, StackPrefer::V6only, "prefer values must be distinct");
	}
}
