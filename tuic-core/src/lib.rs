pub extern crate quinn as quinn_crate;

mod protocol;

pub use self::protocol::{Address, Authenticate, Connect, Dissociate, Header, Heartbeat, Packet, VERSION};

#[cfg(any(feature = "async_marshal", feature = "marshal"))]
mod marshal;

#[cfg(any(feature = "async_marshal", feature = "marshal"))]
mod unmarshal;

#[cfg(any(feature = "async_marshal", feature = "marshal"))]
pub use self::unmarshal::UnmarshalError;

#[cfg(feature = "model")]
pub mod model;

#[cfg(test)]
mod tests;

// Quinn integration module
mod quinn_impl;
pub mod quinn {
	pub use super::quinn_impl::*;
}

// Utility types
mod utils;
pub use self::utils::{CongestionControl, StackPrefer, UdpRelayMode, is_private_ip, sniff_from_stream};
