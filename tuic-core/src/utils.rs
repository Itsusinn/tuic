use std::{
	fmt::{Display, Formatter, Result as FmtResult},
	net::IpAddr,
	str::FromStr,
};

use serde::{Deserialize, Serialize};

/// UDP relay mode for TUIC protocol
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UdpRelayMode {
	Native,
	Quic,
}

impl Display for UdpRelayMode {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match self {
			Self::Native => write!(f, "native"),
			Self::Quic => write!(f, "quic"),
		}
	}
}

impl FromStr for UdpRelayMode {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.eq_ignore_ascii_case("native") {
			Ok(Self::Native)
		} else if s.eq_ignore_ascii_case("quic") {
			Ok(Self::Quic)
		} else {
			Err("invalid UDP relay mode")
		}
	}
}

/// Congestion control algorithm for QUIC
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CongestionControl {
	#[default]
	Bbr,
	Cubic,
	NewReno,
}

impl FromStr for CongestionControl {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.eq_ignore_ascii_case("cubic") {
			Ok(Self::Cubic)
		} else if s.eq_ignore_ascii_case("new_reno") || s.eq_ignore_ascii_case("newreno") {
			Ok(Self::NewReno)
		} else if s.eq_ignore_ascii_case("bbr") {
			Ok(Self::Bbr)
		} else {
			Err("invalid congestion control")
		}
	}
}

/// IP stack preference for address resolution.
///
/// Determines which IP version to prefer when resolving domain names.
///
/// # Variants
///
/// - `V4only`: Use only IPv4 addresses (alias: "v4", "only_v4")
/// - `V6only`: Use only IPv6 addresses (alias: "v6", "only_v6")
/// - `V4first`: Prefer IPv4, fallback to IPv6 (alias: "v4v6", "prefer_v4")
/// - `V6first`: Prefer IPv6, fallback to IPv4 (alias: "v6v4", "prefer_v6")
///
/// # Examples
///
/// ```
/// use tuic_core::StackPrefer;
///
/// // Serializes to "v4first"
/// let prefer = StackPrefer::V4first;
///
/// // Can deserialize from legacy aliases
/// let json = r#""prefer_v4""#;
/// let prefer: StackPrefer = serde_json::from_str(json).unwrap();
/// assert_eq!(prefer, StackPrefer::V4first);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StackPrefer {
	/// Use only IPv4 addresses
	#[serde(alias = "v4", alias = "only_v4")]
	#[default]
	V4only,
	/// Use only IPv6 addresses
	#[serde(alias = "v6", alias = "only_v6")]
	V6only,
	/// Prefer IPv4, fallback to IPv6
	#[serde(alias = "v4v6", alias = "prefer_v4", alias = "auto")]
	V4first,
	/// Prefer IPv6, fallback to IPv4
	#[serde(alias = "v6v4", alias = "prefer_v6")]
	V6first,
}

impl FromStr for StackPrefer {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_ascii_lowercase().as_str() {
			"v4" | "v4only" | "only_v4" => Ok(StackPrefer::V4only),
			"v6" | "v6only" | "only_v6" => Ok(StackPrefer::V6only),
			"v4v6" | "v4first" | "prefer_v4" | "auto" => Ok(StackPrefer::V4first),
			"v6v4" | "v6first" | "prefer_v6" => Ok(StackPrefer::V6first),
			_ => Err("invalid stack preference"),
		}
	}
}

/// Check if an IP address is private (LAN address)
///
/// Returns `true` for:
/// - IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
///   (Link-local)
/// - IPv6: fc00::/7 (Unique Local Address), fe80::/10 (Link-local)
#[inline]
pub fn is_private_ip(ip: &IpAddr) -> bool {
	match ip {
		IpAddr::V4(ipv4) => {
			// 10.0.0.0/8
			ipv4.octets()[0] == 10
				// 172.16.0.0/12
				|| (ipv4.octets()[0] == 172 && (ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31))
				// 192.168.0.0/16
				|| (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168)
				// 169.254.0.0/16 (Link-local)
				|| (ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254)
		}
		IpAddr::V6(ipv6) => {
			// fc00::/7 (Unique Local Address)
			ipv6.octets()[0] & 0xfe == 0xfc
				// fe80::/10 (Link-local)
				|| (ipv6.octets()[0] == 0xfe && (ipv6.octets()[1] & 0xc0) == 0x80)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_udp_relay_mode_from_str() {
		assert_eq!(UdpRelayMode::from_str("native").unwrap(), UdpRelayMode::Native);
		assert_eq!(UdpRelayMode::from_str("NATIVE").unwrap(), UdpRelayMode::Native);
		assert_eq!(UdpRelayMode::from_str("quic").unwrap(), UdpRelayMode::Quic);
		assert_eq!(UdpRelayMode::from_str("QUIC").unwrap(), UdpRelayMode::Quic);
		assert!(UdpRelayMode::from_str("invalid").is_err());
	}

	#[test]
	fn test_udp_relay_mode_serde() {
		let native = UdpRelayMode::Native;
		let json = serde_json::to_string(&native).unwrap();
		assert_eq!(json, "\"native\"");

		let quic = UdpRelayMode::Quic;
		let json = serde_json::to_string(&quic).unwrap();
		assert_eq!(json, "\"quic\"");

		let native: UdpRelayMode = serde_json::from_str("\"native\"").unwrap();
		assert_eq!(native, UdpRelayMode::Native);

		let quic: UdpRelayMode = serde_json::from_str("\"quic\"").unwrap();
		assert_eq!(quic, UdpRelayMode::Quic);
	}

	#[test]
	fn test_udp_relay_mode_display() {
		assert_eq!(UdpRelayMode::Native.to_string(), "native");
		assert_eq!(UdpRelayMode::Quic.to_string(), "quic");
	}

	#[test]
	fn test_congestion_control_from_str() {
		assert_eq!(CongestionControl::from_str("cubic").unwrap(), CongestionControl::Cubic);
		assert_eq!(CongestionControl::from_str("CUBIC").unwrap(), CongestionControl::Cubic);
		assert_eq!(CongestionControl::from_str("new_reno").unwrap(), CongestionControl::NewReno);
		assert_eq!(CongestionControl::from_str("newreno").unwrap(), CongestionControl::NewReno);
		assert_eq!(CongestionControl::from_str("NEWRENO").unwrap(), CongestionControl::NewReno);
		assert_eq!(CongestionControl::from_str("bbr").unwrap(), CongestionControl::Bbr);
		assert_eq!(CongestionControl::from_str("BBR").unwrap(), CongestionControl::Bbr);
		assert!(CongestionControl::from_str("invalid").is_err());
	}

	#[test]
	fn test_congestion_control_serde() {
		let cubic = CongestionControl::Cubic;
		let json = serde_json::to_string(&cubic).unwrap();
		assert_eq!(json, "\"cubic\"");

		let newreno = CongestionControl::NewReno;
		let json = serde_json::to_string(&newreno).unwrap();
		assert_eq!(json, "\"newreno\"");

		let bbr = CongestionControl::Bbr;
		let json = serde_json::to_string(&bbr).unwrap();
		assert_eq!(json, "\"bbr\"");

		let cubic: CongestionControl = serde_json::from_str("\"cubic\"").unwrap();
		assert_eq!(cubic, CongestionControl::Cubic);

		let newreno: CongestionControl = serde_json::from_str("\"newreno\"").unwrap();
		assert_eq!(newreno, CongestionControl::NewReno);

		let bbr: CongestionControl = serde_json::from_str("\"bbr\"").unwrap();
		assert_eq!(bbr, CongestionControl::Bbr);
	}

	#[test]
	fn test_congestion_control_default() {
		let default = CongestionControl::default();
		assert_eq!(default, CongestionControl::Bbr);
	}

	#[test]
	fn test_stack_prefer_from_str() {
		assert_eq!(StackPrefer::from_str("v4").unwrap(), StackPrefer::V4only);
		assert_eq!(StackPrefer::from_str("V4").unwrap(), StackPrefer::V4only);
		assert_eq!(StackPrefer::from_str("v4only").unwrap(), StackPrefer::V4only);
		assert_eq!(StackPrefer::from_str("only_v4").unwrap(), StackPrefer::V4only);
		assert_eq!(StackPrefer::from_str("ONLY_V4").unwrap(), StackPrefer::V4only);
		assert_eq!(StackPrefer::from_str("v6").unwrap(), StackPrefer::V6only);
		assert_eq!(StackPrefer::from_str("V6").unwrap(), StackPrefer::V6only);
		assert_eq!(StackPrefer::from_str("v6only").unwrap(), StackPrefer::V6only);
		assert_eq!(StackPrefer::from_str("only_v6").unwrap(), StackPrefer::V6only);
		assert_eq!(StackPrefer::from_str("ONLY_V6").unwrap(), StackPrefer::V6only);
		assert_eq!(StackPrefer::from_str("v4v6").unwrap(), StackPrefer::V4first);
		assert_eq!(StackPrefer::from_str("V4V6").unwrap(), StackPrefer::V4first);
		assert_eq!(StackPrefer::from_str("v4first").unwrap(), StackPrefer::V4first);
		assert_eq!(StackPrefer::from_str("prefer_v4").unwrap(), StackPrefer::V4first);
		assert_eq!(StackPrefer::from_str("PREFER_V4").unwrap(), StackPrefer::V4first);
		assert_eq!(StackPrefer::from_str("v6v4").unwrap(), StackPrefer::V6first);
		assert_eq!(StackPrefer::from_str("V6V4").unwrap(), StackPrefer::V6first);
		assert_eq!(StackPrefer::from_str("v6first").unwrap(), StackPrefer::V6first);
		assert_eq!(StackPrefer::from_str("prefer_v6").unwrap(), StackPrefer::V6first);
		assert_eq!(StackPrefer::from_str("PREFER_V6").unwrap(), StackPrefer::V6first);
		assert!(StackPrefer::from_str("invalid").is_err());
	}

	#[test]
	fn test_stack_prefer_serde() {
		let v4only = StackPrefer::V4only;
		let json = serde_json::to_string(&v4only).unwrap();
		assert_eq!(json, "\"v4only\"");

		let v6only = StackPrefer::V6only;
		let json = serde_json::to_string(&v6only).unwrap();
		assert_eq!(json, "\"v6only\"");

		let v4first = StackPrefer::V4first;
		let json = serde_json::to_string(&v4first).unwrap();
		assert_eq!(json, "\"v4first\"");

		let v6first = StackPrefer::V6first;
		let json = serde_json::to_string(&v6first).unwrap();
		assert_eq!(json, "\"v6first\"");

		// Test deserialization with original aliases
		let v4only: StackPrefer = serde_json::from_str("\"v4\"").unwrap();
		assert_eq!(v4only, StackPrefer::V4only);

		let v6only: StackPrefer = serde_json::from_str("\"v6\"").unwrap();
		assert_eq!(v6only, StackPrefer::V6only);

		let v4first: StackPrefer = serde_json::from_str("\"v4v6\"").unwrap();
		assert_eq!(v4first, StackPrefer::V4first);

		let v6first: StackPrefer = serde_json::from_str("\"v6v4\"").unwrap();
		assert_eq!(v6first, StackPrefer::V6first);

		// Test deserialization with new aliases
		let v4only: StackPrefer = serde_json::from_str("\"only_v4\"").unwrap();
		assert_eq!(v4only, StackPrefer::V4only);

		let v6only: StackPrefer = serde_json::from_str("\"only_v6\"").unwrap();
		assert_eq!(v6only, StackPrefer::V6only);

		let v4first: StackPrefer = serde_json::from_str("\"prefer_v4\"").unwrap();
		assert_eq!(v4first, StackPrefer::V4first);

		let v6first: StackPrefer = serde_json::from_str("\"prefer_v6\"").unwrap();
		assert_eq!(v6first, StackPrefer::V6first);
	}
}
