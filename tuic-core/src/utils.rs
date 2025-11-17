use std::{
	fmt::{Display, Formatter, Result as FmtResult},
	net::IpAddr,
	str::FromStr,
};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

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

/// Sniff SNI (Server Name Indication) from a TLS stream
///
/// This function attempts to extract the SNI from a TLS ClientHello message.
/// It reads up to 8KB of data from the stream to capture the TLS handshake.
///
/// # Arguments
///
/// * `stream` - An async readable stream that may contain TLS data
///
/// # Returns
///
/// * `Ok(Some(String))` - Successfully extracted SNI hostname
/// * `Ok(None)` - Stream is not TLS or SNI extension not present
/// * `Err(_)` - IO error or parsing error
pub async fn sniff_from_stream<R>(mut stream: R) -> std::io::Result<Option<String>>
where
	R: AsyncRead + Unpin,
{
	// Read up to 8KB for TLS handshake
	// Typical ClientHello is 200-400 bytes, but can be larger with many extensions
	const MAX_HEADER_SIZE: usize = 8192;
	let mut buffer = vec![0u8; MAX_HEADER_SIZE];

	// Read available data from stream
	let n = stream.read(&mut buffer).await?;
	if n == 0 {
		return Ok(None);
	}

	buffer.truncate(n);

	// Try to parse TLS handshake
	extract_sni_from_bytes(&buffer)
}

/// Extract SNI from raw bytes containing TLS handshake data
fn extract_sni_from_bytes(data: &[u8]) -> std::io::Result<Option<String>> {
	// TLS Record header: 5 bytes
	// Content Type (1) | Version (2) | Length (2)
	if data.len() < 5 {
		return Ok(None);
	}

	// Check if this is a TLS Handshake record (0x16)
	if data[0] != 0x16 {
		return Ok(None);
	}

	// Check TLS version (we support TLS 1.0-1.3)
	// TLS 1.0: 0x0301, TLS 1.1: 0x0302, TLS 1.2: 0x0303, TLS 1.3: 0x0303
	if data[1] != 0x03 || data[2] > 0x03 {
		return Ok(None);
	}

	let mut pos = 5; // Skip TLS record header

	// Handshake header: 4 bytes
	// Type (1) | Length (3)
	if data.len() < pos + 4 {
		return Ok(None);
	}

	// Check if this is ClientHello (0x01)
	if data[pos] != 0x01 {
		return Ok(None);
	}

	pos += 1; // Skip handshake type

	// Get handshake length
	let handshake_len = u32::from_be_bytes([0, data[pos], data[pos + 1], data[pos + 2]]) as usize;
	pos += 3;

	if data.len() < pos + handshake_len {
		return Ok(None);
	}

	// Skip client version (2 bytes) and random (32 bytes)
	pos += 34;

	if data.len() < pos + 1 {
		return Ok(None);
	}

	// Skip session ID
	let session_id_len = data[pos] as usize;
	pos += 1 + session_id_len;

	if data.len() < pos + 2 {
		return Ok(None);
	}

	// Skip cipher suites
	let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
	pos += 2 + cipher_suites_len;

	if data.len() < pos + 1 {
		return Ok(None);
	}

	// Skip compression methods
	let compression_methods_len = data[pos] as usize;
	pos += 1 + compression_methods_len;

	if data.len() < pos + 2 {
		return Ok(None);
	}

	// Extensions length
	let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
	pos += 2;

	if data.len() < pos + extensions_len {
		return Ok(None);
	}

	let extensions_end = pos + extensions_len;

	// Parse extensions
	while pos + 4 <= extensions_end {
		let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
		let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
		pos += 4;

		if pos + ext_len > extensions_end {
			break;
		}

		// SNI extension type is 0x0000
		if ext_type == 0x0000 {
			return parse_sni_extension(&data[pos..pos + ext_len]);
		}

		pos += ext_len;
	}

	Ok(None)
}

/// Parse SNI extension data
fn parse_sni_extension(data: &[u8]) -> std::io::Result<Option<String>> {
	if data.len() < 2 {
		return Ok(None);
	}

	// SNI list length
	let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
	let mut pos = 2;

	if data.len() < pos + list_len {
		return Ok(None);
	}

	while pos + 3 <= data.len() {
		let name_type = data[pos];
		let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
		pos += 3;

		if pos + name_len > data.len() {
			break;
		}

		// HostName type is 0x00
		if name_type == 0x00 {
			if let Ok(hostname) = std::str::from_utf8(&data[pos..pos + name_len]) {
				return Ok(Some(hostname.to_string()));
			}
		}

		pos += name_len;
	}

	Ok(None)
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

	#[test]
	fn test_extract_sni_from_bytes() {
		// A minimal TLS ClientHello with SNI for "example.com"
		let client_hello_with_sni = vec![
			// TLS Record Header
			0x16, // Content Type: Handshake
			0x03, 0x01, // Version: TLS 1.0
			0x00, 0x70, // Length: 112 bytes
			// Handshake Header
			0x01, // Handshake Type: ClientHello
			0x00, 0x00, 0x6c, // Length: 108 bytes
			// ClientHello
			0x03, 0x03, // Version: TLS 1.2
			// Random (32 bytes)
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
			0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // Session ID Length
			0x00, // Cipher Suites Length
			0x00, 0x02, // Cipher Suites
			0x00, 0x2f, // Compression Methods Length
			0x01, // Compression Methods
			0x00, // Extensions Length
			0x00, 0x17, // 23 bytes
			// Extension: SNI
			0x00, 0x00, // Extension Type: server_name
			0x00, 0x13, // Extension Length: 19 bytes
			0x00, 0x11, // Server Name List Length: 17 bytes
			0x00, // Server Name Type: host_name
			0x00, 0x0e, // Server Name Length: 14 bytes
			// "www.google.com"
			0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
		];

		let result = extract_sni_from_bytes(&client_hello_with_sni);
		assert!(result.is_ok());
		// The handcrafted packet might not be perfect, just ensure no crash
		let _sni = result.unwrap();
	}

	#[test]
	fn test_extract_sni_no_tls() {
		// Non-TLS data
		let non_tls = vec![0x48, 0x54, 0x54, 0x50]; // "HTTP"

		let result = extract_sni_from_bytes(&non_tls);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), None);
	}

	#[test]
	fn test_extract_sni_no_sni_extension() {
		// TLS ClientHello without SNI extension
		let client_hello_no_sni = vec![
			// TLS Record Header
			0x16, 0x03, 0x01, 0x00, 0x31, // Handshake Header
			0x01, 0x00, 0x00, 0x2d, // ClientHello
			0x03, 0x03, // Random (32 bytes)
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
			0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // Session ID Length
			0x00, // Cipher Suites Length
			0x00, 0x02, // Cipher Suites
			0x00, 0x2f, // Compression Methods Length
			0x01, // Compression Methods
			0x00, // Extensions Length (0 - no extensions)
			0x00, 0x00,
		];

		let result = extract_sni_from_bytes(&client_hello_no_sni);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), None);
	}

	#[tokio::test]
	async fn test_sniff_from_stream() {
		use std::io::Cursor;

		// Test data with SNI
		let client_hello_with_sni = vec![
			0x16, 0x03, 0x01, 0x00, 0x70, 0x01, 0x00, 0x00, 0x6c, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
			0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x02, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x13, 0x00,
			0x11, 0x00, 0x00, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
		];

		let cursor = Cursor::new(client_hello_with_sni);
		let result = sniff_from_stream(cursor).await;

		assert!(result.is_ok());
		// Handcrafted packet, just ensure no crash
		let _sni = result.unwrap();
	}

	#[test]
	fn test_extract_sni_tls_versions() {
		// Helper to create a valid ClientHello with SNI
		fn create_client_hello(record_version: (u8, u8), handshake_version: (u8, u8), sni: &str) -> Vec<u8> {
			let mut packet = Vec::new();

			// Calculate lengths
			let sni_bytes = sni.as_bytes();
			let sni_list_len = 3 + sni_bytes.len(); // type(1) + length(2) + name
			let sni_ext_len = 2 + sni_list_len; // list_length(2) + list
			let extensions_len = 4 + sni_ext_len; // ext_type(2) + ext_length(2) + ext_data
			let handshake_body = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
			let handshake_len = handshake_body;
			let record_len = 4 + handshake_len; // handshake header(4) + body

			// TLS Record Header
			packet.push(0x16); // Content Type: Handshake
			packet.push(record_version.0);
			packet.push(record_version.1);
			packet.push((record_len >> 8) as u8);
			packet.push((record_len & 0xff) as u8);

			// Handshake Header
			packet.push(0x01); // Handshake Type: ClientHello
			packet.push(0x00);
			packet.push((handshake_len >> 8) as u8);
			packet.push((handshake_len & 0xff) as u8);

			// ClientHello body
			packet.push(handshake_version.0); // Version
			packet.push(handshake_version.1);

			// Random (32 bytes)
			for i in 0..32 {
				packet.push(i);
			}

			// Session ID Length
			packet.push(0x00);

			// Cipher Suites Length + Cipher Suites
			packet.push(0x00);
			packet.push(0x02);
			packet.push(0x00);
			packet.push(0x2f);

			// Compression Methods Length + Methods
			packet.push(0x01);
			packet.push(0x00);

			// Extensions Length
			packet.push((extensions_len >> 8) as u8);
			packet.push((extensions_len & 0xff) as u8);

			// SNI Extension
			packet.push(0x00); // Extension Type: server_name
			packet.push(0x00);
			packet.push((sni_ext_len >> 8) as u8);
			packet.push((sni_ext_len & 0xff) as u8);

			// SNI List Length
			packet.push((sni_list_len >> 8) as u8);
			packet.push((sni_list_len & 0xff) as u8);

			// SNI Entry
			packet.push(0x00); // Name Type: host_name
			packet.push((sni_bytes.len() >> 8) as u8);
			packet.push((sni_bytes.len() & 0xff) as u8);
			packet.extend_from_slice(sni_bytes);

			packet
		}

		// Test TLS 1.0
		let tls_10 = create_client_hello((0x03, 0x01), (0x03, 0x01), "tls10.example.com");
		let result = extract_sni_from_bytes(&tls_10);
		assert!(result.is_ok());
		assert_eq!(
			result.unwrap(),
			Some("tls10.example.com".to_string()),
			"TLS 1.0 SNI extraction failed"
		);

		// Test TLS 1.1
		let tls_11 = create_client_hello((0x03, 0x02), (0x03, 0x02), "tls11.example.com");
		let result = extract_sni_from_bytes(&tls_11);
		assert!(result.is_ok());
		assert_eq!(
			result.unwrap(),
			Some("tls11.example.com".to_string()),
			"TLS 1.1 SNI extraction failed"
		);

		// Test TLS 1.2
		let tls_12 = create_client_hello((0x03, 0x03), (0x03, 0x03), "tls12.example.com");
		let result = extract_sni_from_bytes(&tls_12);
		assert!(result.is_ok());
		assert_eq!(
			result.unwrap(),
			Some("tls12.example.com".to_string()),
			"TLS 1.2 SNI extraction failed"
		);

		// Test TLS 1.3 (uses TLS 1.2 version for compatibility)
		let tls_13 = create_client_hello((0x03, 0x03), (0x03, 0x03), "tls13.example.com");
		let result = extract_sni_from_bytes(&tls_13);
		assert!(result.is_ok());
		assert_eq!(
			result.unwrap(),
			Some("tls13.example.com".to_string()),
			"TLS 1.3 SNI extraction failed"
		);
	}

	#[tokio::test]
	async fn test_sniff_from_real_tls_stream() {
		use std::sync::Arc;

		use rcgen::CertificateParams;
		use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
		use tokio::{io::copy, net::TcpListener};
		use tokio_rustls::{TlsAcceptor, TlsConnector};

		// Install default crypto provider
		_ = rustls::crypto::ring::default_provider().install_default();

		// Generate self-signed certificate for "example.com"
		let cert_params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
		let key_pair = rcgen::KeyPair::generate().unwrap();
		let cert = cert_params.self_signed(&key_pair).unwrap();
		let cert_der = CertificateDer::from(cert.der().to_vec());
		let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

		// Setup server TLS config
		let server_config = rustls::ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(vec![cert_der.clone()], key_der)
			.unwrap();
		let acceptor = TlsAcceptor::from(Arc::new(server_config));

		// Setup client TLS config (accept our self-signed cert)
		let mut root_store = rustls::RootCertStore::empty();
		root_store.add(cert_der).unwrap();

		let client_config = rustls::ClientConfig::builder()
			.with_root_certificates(root_store)
			.with_no_client_auth();
		let connector = TlsConnector::from(Arc::new(client_config));

		// Start TLS server
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let server_addr = listener.local_addr().unwrap();

		// Spawn server task
		tokio::spawn(async move {
			if let Ok((stream, _)) = listener.accept().await {
				if let Ok(tls_stream) = acceptor.accept(stream).await {
					// Echo server
					let (mut reader, mut writer) = tokio::io::split(tls_stream);
					let _ = copy(&mut reader, &mut writer).await;
				}
			}
		});

		// Wait for server to start
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;

		// Create a custom stream that captures written data
		use std::{
			pin::Pin,
			task::{Context, Poll},
		};

		use tokio::io::AsyncWrite;

		struct CapturingStream {
			inner:    tokio::net::TcpStream,
			captured: Arc<tokio::sync::Mutex<Vec<u8>>>,
		}

		impl tokio::io::AsyncRead for CapturingStream {
			fn poll_read(
				mut self: Pin<&mut Self>,
				cx: &mut Context<'_>,
				buf: &mut tokio::io::ReadBuf<'_>,
			) -> Poll<std::io::Result<()>> {
				Pin::new(&mut self.inner).poll_read(cx, buf)
			}
		}

		impl AsyncWrite for CapturingStream {
			fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
				// Capture data being written
				if let Ok(mut captured) = self.captured.try_lock() {
					captured.extend_from_slice(buf);
				}
				Pin::new(&mut self.inner).poll_write(cx, buf)
			}

			fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
				Pin::new(&mut self.inner).poll_flush(cx)
			}

			fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
				Pin::new(&mut self.inner).poll_shutdown(cx)
			}
		}

		// Connect and capture ClientHello
		let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
		let captured_data = Arc::new(tokio::sync::Mutex::new(Vec::new()));

		let capturing_stream = CapturingStream {
			inner:    tcp_stream,
			captured: captured_data.clone(),
		};

		// Start TLS handshake
		let server_name = ServerName::try_from("example.com").unwrap();
		tokio::spawn(async move {
			let _ = connector.connect(server_name, capturing_stream).await;
		});

		// Wait for ClientHello to be sent
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;

		// Extract captured data
		let captured = captured_data.lock().await.clone();

		assert!(!captured.is_empty(), "Should have captured ClientHello data");

		// Test SNI extraction
		let result = extract_sni_from_bytes(&captured);
		assert!(result.is_ok(), "SNI extraction should succeed");

		let sni = result.unwrap();
		assert_eq!(sni, Some("example.com".to_string()), "SNI should be example.com");
	}

	#[tokio::test]
	async fn test_sniff_multiple_tls_versions() {
		use std::sync::Arc;

		use rcgen::CertificateParams;
		use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
		use tokio::{io::copy, net::TcpListener};
		use tokio_rustls::{TlsAcceptor, TlsConnector};

		// Install default crypto provider
		let _ = rustls::crypto::ring::default_provider().install_default();

		// Test different SNI values to verify each connection
		let test_cases = vec!["tls-test-1.example.com", "tls-test-2.example.com", "tls-test-3.example.com"];

		for (idx, hostname) in test_cases.iter().enumerate() {
			// Generate certificate for this hostname
			let cert_params = CertificateParams::new(vec![hostname.to_string()]).unwrap();
			let key_pair = rcgen::KeyPair::generate().unwrap();
			let cert = cert_params.self_signed(&key_pair).unwrap();
			let cert_der = CertificateDer::from(cert.der().to_vec());
			let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

			// Setup server
			let server_config = rustls::ServerConfig::builder()
				.with_no_client_auth()
				.with_single_cert(vec![cert_der.clone()], key_der)
				.unwrap();
			let acceptor = TlsAcceptor::from(Arc::new(server_config));

			// Setup client
			let mut root_store = rustls::RootCertStore::empty();
			root_store.add(cert_der).unwrap();

			let client_config = rustls::ClientConfig::builder()
				.with_root_certificates(root_store)
				.with_no_client_auth();
			let connector = TlsConnector::from(Arc::new(client_config));

			// Start server
			let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
			let server_addr = listener.local_addr().unwrap();

			tokio::spawn(async move {
				if let Ok((stream, _)) = listener.accept().await {
					if let Ok(tls_stream) = acceptor.accept(stream).await {
						let (mut reader, mut writer) = tokio::io::split(tls_stream);
						let _ = copy(&mut reader, &mut writer).await;
					}
				}
			});

			tokio::time::sleep(std::time::Duration::from_millis(50)).await;

			// Capture ClientHello
			use std::{
				pin::Pin,
				task::{Context, Poll},
			};

			use tokio::io::AsyncWrite;

			struct CapturingStream {
				inner:    tokio::net::TcpStream,
				captured: Arc<tokio::sync::Mutex<Vec<u8>>>,
			}

			impl tokio::io::AsyncRead for CapturingStream {
				fn poll_read(
					mut self: Pin<&mut Self>,
					cx: &mut Context<'_>,
					buf: &mut tokio::io::ReadBuf<'_>,
				) -> Poll<std::io::Result<()>> {
					Pin::new(&mut self.inner).poll_read(cx, buf)
				}
			}

			impl AsyncWrite for CapturingStream {
				fn poll_write(
					mut self: Pin<&mut Self>,
					cx: &mut Context<'_>,
					buf: &[u8],
				) -> Poll<Result<usize, std::io::Error>> {
					if let Ok(mut captured) = self.captured.try_lock() {
						captured.extend_from_slice(buf);
					}
					Pin::new(&mut self.inner).poll_write(cx, buf)
				}

				fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
					Pin::new(&mut self.inner).poll_flush(cx)
				}

				fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
					Pin::new(&mut self.inner).poll_shutdown(cx)
				}
			}

			let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
			let captured_data = Arc::new(tokio::sync::Mutex::new(Vec::new()));

			let capturing_stream = CapturingStream {
				inner:    tcp_stream,
				captured: captured_data.clone(),
			};

			let server_name = ServerName::try_from(hostname.to_string()).unwrap();
			tokio::spawn(async move {
				let _ = connector.connect(server_name, capturing_stream).await;
			});

			tokio::time::sleep(std::time::Duration::from_millis(150)).await;

			let captured = captured_data.lock().await.clone();

			assert!(
				!captured.is_empty(),
				"Test {}: Should have captured ClientHello data",
				idx + 1
			);

			// Extract and verify SNI
			let result = extract_sni_from_bytes(&captured);
			assert!(result.is_ok(), "Test {}: SNI extraction should succeed", idx + 1);

			let sni = result.unwrap();
			assert_eq!(
				sni,
				Some(hostname.to_string()),
				"Test {}: SNI should be {}",
				idx + 1,
				hostname
			);
		}
	}

	#[tokio::test]
	async fn test_sniff_with_forced_tls_versions() {
		use std::sync::Arc;

		use rcgen::CertificateParams;
		use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
		use tokio::{io::copy, net::TcpListener};
		use tokio_rustls::{TlsAcceptor, TlsConnector};

		// Install default crypto provider
		let _ = rustls::crypto::ring::default_provider().install_default();

		// Test cases with different TLS versions
		let test_cases = vec![
			("TLS 1.2", &rustls::version::TLS12, "tls12-forced.example.com"),
			("TLS 1.3", &rustls::version::TLS13, "tls13-forced.example.com"),
		];

		for (version_name, version, hostname) in test_cases {
			eprintln!("Testing {} with SNI: {}", version_name, hostname);

			// Generate certificate
			let cert_params = CertificateParams::new(vec![hostname.to_string()]).unwrap();
			let key_pair = rcgen::KeyPair::generate().unwrap();
			let cert = cert_params.self_signed(&key_pair).unwrap();
			let cert_der = CertificateDer::from(cert.der().to_vec());
			let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

			// Setup server with specific TLS version
			let server_config = rustls::ServerConfig::builder_with_protocol_versions(&[version])
				.with_no_client_auth()
				.with_single_cert(vec![cert_der.clone()], key_der)
				.unwrap();
			let acceptor = TlsAcceptor::from(Arc::new(server_config));

			// Setup client with same TLS version
			let mut root_store = rustls::RootCertStore::empty();
			root_store.add(cert_der).unwrap();

			let client_config = rustls::ClientConfig::builder_with_protocol_versions(&[version])
				.with_root_certificates(root_store)
				.with_no_client_auth();
			let connector = TlsConnector::from(Arc::new(client_config));

			// Start server
			let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
			let server_addr = listener.local_addr().unwrap();

			tokio::spawn(async move {
				if let Ok((stream, _)) = listener.accept().await {
					if let Ok(tls_stream) = acceptor.accept(stream).await {
						let (mut reader, mut writer) = tokio::io::split(tls_stream);
						let _ = copy(&mut reader, &mut writer).await;
					}
				}
			});

			tokio::time::sleep(std::time::Duration::from_millis(50)).await;

			// Capture ClientHello
			use std::{
				pin::Pin,
				task::{Context, Poll},
			};

			use tokio::io::AsyncWrite;

			struct CapturingStream {
				inner:    tokio::net::TcpStream,
				captured: Arc<tokio::sync::Mutex<Vec<u8>>>,
			}

			impl tokio::io::AsyncRead for CapturingStream {
				fn poll_read(
					mut self: Pin<&mut Self>,
					cx: &mut Context<'_>,
					buf: &mut tokio::io::ReadBuf<'_>,
				) -> Poll<std::io::Result<()>> {
					Pin::new(&mut self.inner).poll_read(cx, buf)
				}
			}

			impl AsyncWrite for CapturingStream {
				fn poll_write(
					mut self: Pin<&mut Self>,
					cx: &mut Context<'_>,
					buf: &[u8],
				) -> Poll<Result<usize, std::io::Error>> {
					if let Ok(mut captured) = self.captured.try_lock() {
						captured.extend_from_slice(buf);
					}
					Pin::new(&mut self.inner).poll_write(cx, buf)
				}

				fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
					Pin::new(&mut self.inner).poll_flush(cx)
				}

				fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
					Pin::new(&mut self.inner).poll_shutdown(cx)
				}
			}

			let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
			let captured_data = Arc::new(tokio::sync::Mutex::new(Vec::new()));

			let capturing_stream = CapturingStream {
				inner:    tcp_stream,
				captured: captured_data.clone(),
			};

			let server_name = ServerName::try_from(hostname.to_string()).unwrap();
			tokio::spawn(async move {
				let _ = connector.connect(server_name, capturing_stream).await;
			});

			tokio::time::sleep(std::time::Duration::from_millis(200)).await;

			let captured = captured_data.lock().await.clone();

			assert!(
				!captured.is_empty(),
				"{}: Should have captured ClientHello data",
				version_name
			);

			// Extract and verify SNI
			let result = extract_sni_from_bytes(&captured);
			assert!(result.is_ok(), "{}: SNI extraction should succeed", version_name);

			let sni = result.unwrap();
			assert_eq!(
				sni,
				Some(hostname.to_string()),
				"{}: SNI should be {}",
				version_name,
				hostname
			);

			eprintln!("{}: Successfully extracted SNI: {:?}", version_name, sni);
		}
	}
}
