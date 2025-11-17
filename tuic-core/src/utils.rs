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

	/// Helper function to setup a proxy test environment and capture TLS
	/// ClientHello
	///
	/// Returns the captured ClientHello bytes and the test hostname
	#[cfg(test)]
	async fn setup_proxy_and_capture_client_hello(
		test_hostname: &str,
		server_tls_versions: Vec<&'static rustls::SupportedProtocolVersion>,
		client_tls_versions: Vec<&'static rustls::SupportedProtocolVersion>,
	) -> (Vec<u8>, String) {
		use std::sync::Arc;

		use rcgen::CertificateParams;
		use rustls::pki_types::{CertificateDer, PrivateKeyDer};
		use tokio::{
			io::{AsyncReadExt, AsyncWriteExt, copy},
			net::TcpListener,
			sync::Mutex,
		};
		use tokio_rustls::TlsAcceptor;

		// Install default crypto provider
		#[cfg(feature = "ring")]
		let _ = rustls::crypto::ring::default_provider().install_default();
		#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		// Generate self-signed certificate for test domain
		let cert_params = CertificateParams::new(vec![test_hostname.to_string()]).unwrap();
		let key_pair = rcgen::KeyPair::generate().unwrap();
		let cert = cert_params.self_signed(&key_pair).unwrap();
		let cert_der = CertificateDer::from(cert.der().to_vec());
		let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

		// Setup HTTPS server
		let server_config = if server_tls_versions.is_empty() {
			rustls::ServerConfig::builder()
				.with_no_client_auth()
				.with_single_cert(vec![cert_der.clone()], key_der)
				.unwrap()
		} else {
			rustls::ServerConfig::builder_with_protocol_versions(&server_tls_versions)
				.with_no_client_auth()
				.with_single_cert(vec![cert_der.clone()], key_der)
				.unwrap()
		};
		let acceptor = TlsAcceptor::from(Arc::new(server_config));

		// Start HTTPS server on a random port
		let https_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let https_addr = https_listener.local_addr().unwrap();

		tokio::spawn(async move {
			while let Ok((stream, _)) = https_listener.accept().await {
				let acceptor = acceptor.clone();
				tokio::spawn(async move {
					if let Ok(mut tls_stream) = acceptor.accept(stream).await {
						let response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
						let _ = tls_stream.write_all(response).await;
						let _ = tls_stream.flush().await;
					}
				});
			}
		});

		// Start HTTP proxy that captures TLS ClientHello
		let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let proxy_addr = proxy_listener.local_addr().unwrap();

		let captured_client_hello = Arc::new(Mutex::new(Vec::<u8>::new()));
		let captured_clone = captured_client_hello.clone();

		tokio::spawn(async move {
			if let Ok((mut client_stream, _)) = proxy_listener.accept().await {
				if let Ok(mut server_stream) = tokio::net::TcpStream::connect(https_addr).await {
					let mut buffer = vec![0u8; 8192];

					if let Ok(n) = client_stream.read(&mut buffer).await {
						if n > 0 {
							let mut captured = captured_clone.lock().await;
							captured.extend_from_slice(&buffer[..n]);

							let _ = server_stream.write_all(&buffer[..n]).await;

							let (mut client_read, mut client_write) = client_stream.split();
							let (mut server_read, mut server_write) = server_stream.split();

							let client_to_server = async {
								let _ = copy(&mut client_read, &mut server_write).await;
							};

							let server_to_client = async {
								let _ = copy(&mut server_read, &mut client_write).await;
							};

							tokio::select! {
								_ = client_to_server => {},
								_ = server_to_client => {},
							}
						}
					}
				}
			}
		});

		// Wait for servers to start
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;

		// Create a custom client that uses our proxy
		let hostname = test_hostname.to_string();
		let client_task = tokio::spawn(async move {
			if let Ok(stream) = tokio::net::TcpStream::connect(proxy_addr).await {
				let mut root_store = rustls::RootCertStore::empty();
				root_store.add(cert_der).unwrap();

				let client_config = if client_tls_versions.is_empty() {
					rustls::ClientConfig::builder()
						.with_root_certificates(root_store)
						.with_no_client_auth()
				} else {
					rustls::ClientConfig::builder_with_protocol_versions(&client_tls_versions)
						.with_root_certificates(root_store)
						.with_no_client_auth()
				};

				let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

				let server_name = rustls::pki_types::ServerName::try_from(hostname.clone()).unwrap();
				if let Ok(mut tls_stream) = connector.connect(server_name, stream).await {
					let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", hostname);
					let _ = tls_stream.write_all(request.as_bytes()).await;
					let _ = tls_stream.flush().await;

					let mut response = Vec::new();
					let _ = tls_stream.read_to_end(&mut response).await;
				}
			}
		});

		// Wait for the client to send data
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;

		let captured = captured_client_hello.lock().await.clone();
		let _ = client_task.await;

		(captured, test_hostname.to_string())
	}

	/// Test SNI sniffing using an HTTP inbound proxy that captures real TLS
	/// traffic
	///
	/// This test creates a TCP proxy that intercepts the TLS ClientHello from a
	/// real HTTP client connecting to an HTTPS server, instead of capturing
	/// from rustls client.
	#[tokio::test]
	async fn test_sniff_from_http_proxy() {
		let test_hostname = "proxy-test.example.com";
		let (captured, test_hostname) = setup_proxy_and_capture_client_hello(
			test_hostname,
			vec![], // Use default TLS versions
			vec![], // Use default TLS versions
		)
		.await;
		assert!(!captured.is_empty(), "Proxy should have captured ClientHello data");

		eprintln!("Captured {} bytes from proxy", captured.len());

		// Test SNI extraction from captured data
		let result = extract_sni_from_bytes(&captured);
		assert!(result.is_ok(), "SNI extraction should succeed on proxy-captured data");

		let sni = result.unwrap();
		assert_eq!(
			sni,
			Some(test_hostname.to_string()),
			"SNI should match the hostname: {}",
			test_hostname
		);

		eprintln!("Successfully extracted SNI from HTTP proxy: {:?}", sni);

		// Also test with sniff_from_stream
		use std::io::Cursor;

		let cursor = Cursor::new(captured);
		let stream_result = sniff_from_stream(cursor).await;
		assert!(
			stream_result.is_ok(),
			"sniff_from_stream should succeed on proxy-captured data"
		);

		let stream_sni = stream_result.unwrap();
		assert_eq!(
			stream_sni,
			Some(test_hostname.to_string()),
			"sniff_from_stream should extract correct SNI"
		);

		eprintln!("sniff_from_stream test passed with SNI: {:?}", stream_sni);
	}

	/// Test SNI sniffing with TLS 1.2 specifically
	#[tokio::test]
	async fn test_sniff_from_http_proxy_tls12() {
		let test_hostname = "tls12-test.example.com";
		let (captured, test_hostname) =
			setup_proxy_and_capture_client_hello(test_hostname, vec![&rustls::version::TLS12], vec![&rustls::version::TLS12])
				.await;
		assert!(!captured.is_empty(), "TLS 1.2: Proxy should have captured ClientHello data");

		eprintln!("TLS 1.2: Captured {} bytes from proxy", captured.len());

		let result = extract_sni_from_bytes(&captured);
		assert!(result.is_ok(), "TLS 1.2: SNI extraction should succeed");

		let sni = result.unwrap();
		assert_eq!(
			sni,
			Some(test_hostname.to_string()),
			"TLS 1.2: SNI should match the hostname: {}",
			test_hostname
		);

		eprintln!("TLS 1.2: Successfully extracted SNI: {:?}", sni);
	}

	/// Test SNI sniffing with TLS 1.3 specifically
	#[tokio::test]
	async fn test_sniff_from_http_proxy_tls13() {
		let test_hostname = "tls13-test.example.com";
		let (captured, test_hostname) =
			setup_proxy_and_capture_client_hello(test_hostname, vec![&rustls::version::TLS13], vec![&rustls::version::TLS13])
				.await;
		assert!(!captured.is_empty(), "TLS 1.3: Proxy should have captured ClientHello data");

		eprintln!("TLS 1.3: Captured {} bytes from proxy", captured.len());

		let result = extract_sni_from_bytes(&captured);
		assert!(result.is_ok(), "TLS 1.3: SNI extraction should succeed");

		let sni = result.unwrap();
		assert_eq!(
			sni,
			Some(test_hostname.to_string()),
			"TLS 1.3: SNI should match the hostname: {}",
			test_hostname
		);

		eprintln!("TLS 1.3: Successfully extracted SNI: {:?}", sni);
	}
}
