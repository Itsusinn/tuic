use std::{
	fmt::Display,
	io::Error as IoError,
	net::{IpAddr, SocketAddr},
	path::PathBuf,
	str::FromStr,
	sync::Arc,
	time::Duration,
};

use clap::Parser;
use educe::Educe;
use figment::{
	Figment,
	providers::{Format, Serialized, Toml, Yaml},
};
use figment_json5::Json5;
use humantime::Duration as HumanDuration;
use json5::Error as Json5Error;
use serde::{Deserialize, Deserializer, de::Error as DeError};
use thiserror::Error;
use uuid::Uuid;

use crate::utils::{CongestionControl, StackPrefer, UdpRelayMode};

/// Environment state for configuration parsing
#[derive(Debug, Clone, Default)]
pub struct EnvState {
	pub tuic_force_toml:    bool,
	pub tuic_config_format: Option<String>,
}

impl EnvState {
	/// Create EnvState from system environment variables
	pub fn from_system() -> Self {
		Self {
			tuic_force_toml:    std::env::var("TUIC_FORCE_TOML").is_ok(),
			tuic_config_format: std::env::var("TUIC_CONFIG_FORMAT").ok().map(|v| v.to_lowercase()),
		}
	}
}

/// Control flow results for CLI parsing
#[derive(Debug)]
pub struct Control(&'static str);

impl std::fmt::Display for Control {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::error::Error for Control {}

/// TUIC Client - A minimalistic TUIC client implementation
#[derive(Parser, Debug)]
#[command(name = "tuic-client")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
	/// Path to the config file
	#[arg(short, long, value_name = "PATH")]
	pub config: Option<PathBuf>,
}

#[derive(Debug, Deserialize, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
	pub relay: Relay,

	pub local: Local,

	#[educe(Default = "info")]
	pub log_level: String,
}

#[derive(Debug, Deserialize, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields, default)]
pub struct Relay {
	#[serde(deserialize_with = "deserialize_server")]
	pub server: (String, u16),

	#[educe(Default(expression = Uuid::nil()))]
	pub uuid: Uuid,

	#[serde(deserialize_with = "deserialize_password", serialize_with = "serialize_password")]
	#[educe(Default(expression = Arc::from([])))]
	pub password: Arc<[u8]>,

	#[educe(Default = None)]
	pub ip: Option<IpAddr>,

	#[educe(Default(expression = StackPrefer::V4first))]
	pub ipstack_prefer: StackPrefer,

	#[educe(Default(expression = Vec::new()))]
	pub certificates: Vec<PathBuf>,

	#[educe(Default(expression = UdpRelayMode::Native))]
	pub udp_relay_mode: UdpRelayMode,

	#[educe(Default(expression = CongestionControl::Bbr))]
	pub congestion_control: CongestionControl,

	#[educe(Default(expression = Vec::new()))]
	#[serde(deserialize_with = "deserialize_alpn")]
	pub alpn: Vec<Vec<u8>>,

	#[educe(Default = false)]
	pub zero_rtt_handshake: bool,

	#[educe(Default = false)]
	pub disable_sni: bool,

	#[educe(Default = None)]
	pub sni: Option<String>,

	#[educe(Default(expression = Duration::from_secs(8)))]
	#[serde(with = "humantime_serde")]
	pub timeout: Duration,

	#[educe(Default(expression = Duration::from_secs(3)))]
	#[serde(with = "humantime_serde")]
	pub heartbeat: Duration,

	#[educe(Default = false)]
	pub disable_native_certs: bool,

	#[educe(Default = 16777216)]
	pub send_window: u64,

	#[educe(Default = 8388608)]
	pub receive_window: u32,

	#[educe(Default = 1200)]
	pub initial_mtu: u16,

	#[educe(Default = 1200)]
	pub min_mtu: u16,

	#[educe(Default = true)]
	pub gso: bool,

	#[educe(Default = true)]
	pub pmtu: bool,

	#[educe(Default(expression = Duration::from_secs(3)))]
	#[serde(with = "humantime_serde")]
	pub gc_interval: Duration,

	#[educe(Default(expression = Duration::from_secs(15)))]
	#[serde(with = "humantime_serde")]
	pub gc_lifetime: Duration,

	#[educe(Default = false)]
	pub skip_cert_verify: bool,

	#[educe(Default = None)]
	pub proxy: Option<ProxyConfig>,
}

#[derive(Debug, Deserialize, serde::Serialize, Educe, Clone, PartialEq, Eq)]
#[educe(Default)]
#[serde(deny_unknown_fields, default)]
pub struct ProxyConfig {
	#[serde(deserialize_with = "deserialize_server")]
	#[educe(Default(expression = ("".to_string(), 0)))]
	pub server: (String, u16),

	#[educe(Default = None)]
	pub username: Option<String>,

	#[educe(Default = None)]
	pub password: Option<String>,
}

#[derive(Debug, Deserialize, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields, default)]
pub struct Local {
	#[educe(Default(expression = "127.0.0.1:1080".parse().unwrap()))]
	pub server: SocketAddr,

	#[educe(Default = None)]
	#[serde(deserialize_with = "deserialize_optional_bytes")]
	pub username: Option<Vec<u8>>,

	#[educe(Default = None)]
	#[serde(deserialize_with = "deserialize_optional_bytes")]
	pub password: Option<Vec<u8>>,

	#[educe(Default = None)]
	pub dual_stack: Option<bool>,

	#[educe(Default = 1500)]
	pub max_packet_size: usize,

	#[educe(Default(expression = Vec::new()))]
	pub tcp_forward: Vec<TcpForward>,

	#[educe(Default(expression = Vec::new()))]
	pub udp_forward: Vec<UdpForward>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct TcpForward {
	pub listen: SocketAddr,
	#[serde(deserialize_with = "deserialize_server")]
	pub remote: (String, u16),
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpForward {
	pub listen:  SocketAddr,
	#[serde(deserialize_with = "deserialize_server")]
	pub remote:  (String, u16),
	#[serde(default = "default_udp_timeout", deserialize_with = "deserialize_duration")]
	pub timeout: Duration,
}

fn default_udp_timeout() -> Duration {
	Duration::from_secs(60)
}

impl Config {
	pub fn parse(cli: Cli, env_state: EnvState) -> eyre::Result<Self> {
		// Require config file
		let path = cli.config.ok_or(ConfigError::NoConfig)?;

		// Check if config file exists
		if !path.exists() {
			return Err(ConfigError::ConfigNotFound(path))?;
		}

		let figmet = Figment::from(Serialized::defaults(Config::default()));
		let format;

		// Priority: TUIC_FORCE_TOML > TUIC_CONFIG_FORMAT > file extension > content
		// inference
		if env_state.tuic_force_toml {
			format = ConfigFormat::Toml;
		} else if let Some(ref env_format) = env_state.tuic_config_format {
			// TUIC_CONFIG_FORMAT has higher priority than file extension
			match env_format.to_lowercase().as_str() {
				"json" | "json5" => format = ConfigFormat::Json,
				"yaml" | "yml" => format = ConfigFormat::Yaml,
				"toml" => format = ConfigFormat::Toml,
				_ => format = ConfigFormat::Unknown,
			}
		} else {
			// Fall back to file extension
			match path
				.extension()
				.and_then(|v| v.to_str())
				.unwrap_or_default()
				.to_lowercase()
				.as_str()
			{
				"json" | "json5" => format = ConfigFormat::Json,
				"yaml" | "yml" => format = ConfigFormat::Yaml,
				"toml" => format = ConfigFormat::Toml,
				_ => format = ConfigFormat::Unknown,
			}
		}

		let figmet = match format {
			ConfigFormat::Json => figmet.merge(Json5::file(&path)),
			ConfigFormat::Toml => figmet.merge(Toml::file(&path)),
			ConfigFormat::Yaml => figmet.merge(Yaml::file(&path)),
			ConfigFormat::Unknown => {
				// Try to infer format from file content
				let content = std::fs::read_to_string(&path)?;
				let inferred_format = infer_config_format(&content);

				match inferred_format {
					ConfigFormat::Json => figmet.merge(Json5::string(&content)),
					ConfigFormat::Toml => figmet.merge(Toml::string(&content)),
					ConfigFormat::Yaml => figmet.merge(Yaml::string(&content)),
					ConfigFormat::Unknown => {
						return Err(ConfigError::UnknownFormat)?;
					}
				}
			}
		};

		let config: Config = figmet.extract().map_err(ConfigError::Figment)?;

		Ok(config)
	}
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ConfigFormat {
	Json,
	Toml,
	Yaml,
	Unknown,
}

fn infer_config_format(content: &str) -> ConfigFormat {
	let trimmed = content.trim();

	// Check for YAML indicators
	if trimmed.lines().any(|line| {
		let line = line.trim();
		// YAML typically has keys followed by colons (not in quotes)
		// and doesn't use brackets for top-level structure
		line.contains(':')
			&& !line.starts_with('{')
			&& !line.starts_with('[')
			&& !line.starts_with('"')
			&& !line.starts_with('\'')
	}) && !trimmed.starts_with('{')
		&& !trimmed.starts_with('[')
	{
		return ConfigFormat::Yaml;
	}

	// Check for TOML indicators (section headers)
	if trimmed.lines().any(|line| {
		let line = line.trim();
		line.starts_with('[') && line.ends_with(']') && !line.contains('{')
	}) {
		return ConfigFormat::Toml;
	}

	// Check for JSON/JSON5 indicators
	if trimmed.starts_with('{') || trimmed.starts_with('[') {
		return ConfigFormat::Json;
	}

	ConfigFormat::Unknown
}

pub fn deserialize_from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
	T: FromStr,
	<T as FromStr>::Err: Display,
	D: Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	T::from_str(&s).map_err(DeError::custom)
}

pub fn deserialize_server<'de, D>(deserializer: D) -> Result<(String, u16), D::Error>
where
	D: Deserializer<'de>,
{
	let mut s = String::deserialize(deserializer)?;

	let (domain, port) = s.rsplit_once(':').ok_or(DeError::custom("invalid server address"))?;

	let port = port.parse().map_err(DeError::custom)?;
	s.truncate(domain.len());

	// Strip brackets from IPv6 addresses (e.g., "[::1]" -> "::1")
	if s.starts_with('[') && s.ends_with(']') {
		s = s[1..s.len() - 1].to_string();
	}

	Ok((s, port))
}

pub fn deserialize_password<'de, D>(deserializer: D) -> Result<Arc<[u8]>, D::Error>
where
	D: Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	Ok(Arc::from(s.into_bytes().into_boxed_slice()))
}

pub fn serialize_password<S>(password: &Arc<[u8]>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	use serde::Serialize;
	let s = String::from_utf8_lossy(password);
	s.serialize(serializer)
}

pub fn deserialize_alpn<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
	D: Deserializer<'de>,
{
	let s = Vec::<String>::deserialize(deserializer)?;
	Ok(s.into_iter().map(|alpn| alpn.into_bytes()).collect())
}

pub fn deserialize_optional_bytes<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
	D: Deserializer<'de>,
{
	Ok(Option::<String>::deserialize(deserializer)?.map(|s| s.into_bytes()))
}

pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
	D: Deserializer<'de>,
{
	String::deserialize(deserializer)?
		.parse::<HumanDuration>()
		.map(|d| *d)
		.map_err(DeError::custom)
}

#[derive(Debug, Error)]
pub enum ConfigError {
	#[error("no config file specified")]
	NoConfig,
	#[error("config file not found: {0}")]
	ConfigNotFound(PathBuf),
	#[error("cannot infer config format from file extension or content")]
	UnknownFormat,
	#[error(transparent)]
	Io(#[from] IoError),
	#[error(transparent)]
	Json5(#[from] Json5Error),
	#[error("TOML parse error: {0}")]
	Toml(String),
	#[error("configuration error: {0}")]
	Figment(#[from] figment::Error),
}

impl From<toml::de::Error> for ConfigError {
	fn from(err: toml::de::Error) -> Self {
		ConfigError::Toml(err.to_string())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// Helper function for testing config file parsing
	fn test_parse_config(config_content: &str, extension: &str) -> eyre::Result<Config> {
		test_parse_config_with_env(config_content, extension, EnvState::default())
	}

	// Helper function for testing config file parsing with custom environment state
	fn test_parse_config_with_env(config_content: &str, extension: &str, env_state: EnvState) -> eyre::Result<Config> {
		use std::fs;

		use tempfile::tempdir;

		let temp_dir = tempdir().unwrap();

		let config_path = temp_dir.path().join(format!("config{}", extension));

		fs::write(&config_path, config_content).unwrap();

		// Temporarily set command line arguments for clap to parse
		let os_args = vec![
			"test_binary".to_owned(),
			"--config".to_owned(),
			config_path.to_string_lossy().into_owned(),
		];

		// Parse CLI with test arguments
		let cli = Cli::try_parse_from(os_args).map_err(|e| ConfigError::Figment(figment::Error::from(e.to_string())))?;

		// Call parse with the CLI and env_state
		Config::parse(cli, env_state)
	}
	#[test]
	fn test_backward_compatibility_standard_json() {
		// Test backward compatibility with standard JSON format
		let json_config = include_str!("../tests/config/backward_compatibility_standard_json.json");

		let config = test_parse_config(json_config, ".json5");
		assert!(config.is_ok(), "Standard JSON should be parseable by JSON5");

		let config = config.unwrap();
		assert_eq!(config.log_level, "info");
		assert_eq!(config.relay.server.0, "example.com");
		assert_eq!(config.relay.server.1, 8443);
	}

	#[test]
	fn test_json5_comments() {
		// Test JSON5 comment support (single-line and multi-line)
		let json5_config = include_str!("../tests/config/json5_comments.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with comments should be parseable");
	}

	#[test]
	fn test_json5_trailing_commas() {
		// Test JSON5 trailing comma support
		let json5_config = include_str!("../tests/config/json5_trailing_commas.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with trailing commas should be parseable");
	}

	#[test]
	fn test_json5_unquoted_keys() {
		// Test JSON5 unquoted object keys
		let json5_config = include_str!("../tests/config/json5_unquoted_keys.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with unquoted keys should be parseable");
	}

	#[test]
	fn test_json5_single_quotes() {
		// Test JSON5 single-quoted strings
		let json5_config = include_str!("../tests/config/json5_single_quotes.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with single quotes should be parseable");
	}

	#[test]
	fn test_json5_multiline_strings() {
		// Test JSON5 multiline strings with escaped newlines
		let json5_config = include_str!("../tests/config/json5_multiline_strings.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with multiline strings should be parseable");
	}

	#[test]
	fn test_json5_mixed_features() {
		// Test multiple JSON5 features combined
		let json5_config = include_str!("../tests/config/json5_mixed_features.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with mixed features should be parseable");

		let config = config.unwrap();
		assert_eq!(config.log_level, "info");
	}

	#[test]
	fn test_complex_config_with_all_fields() {
		// Test a more complete configuration with various optional fields
		let json5_config = include_str!("../tests/config/complex_config_with_all_fields.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "Complex JSON5 config should be parseable");

		let config = config.unwrap();
		assert_eq!(config.log_level, "debug");
		assert!(config.relay.zero_rtt_handshake);
	}

	#[test]
	fn test_default_values() {
		let json5_config = include_str!("../tests/config/default_values.json5");

		let config = test_parse_config(json5_config, ".json5").unwrap();

		// Check default values
		assert_eq!(config.log_level, "info");
		assert_eq!(config.relay.ipstack_prefer, StackPrefer::V4first);
		assert_eq!(config.relay.udp_relay_mode, UdpRelayMode::Native);
		assert_eq!(config.relay.congestion_control, CongestionControl::Bbr);
		assert!(!config.relay.zero_rtt_handshake);
		assert!(!config.relay.disable_sni);
		assert_eq!(config.relay.timeout, Duration::from_secs(8));
		assert_eq!(config.relay.heartbeat, Duration::from_secs(3));
		assert!(!config.relay.disable_native_certs);
		assert_eq!(config.relay.send_window, 16 * 1024 * 1024);
		assert_eq!(config.relay.receive_window, 8 * 1024 * 1024);
		assert_eq!(config.relay.initial_mtu, 1200);
		assert_eq!(config.relay.min_mtu, 1200);
		assert!(config.relay.gso);
		assert!(config.relay.pmtu);
		assert_eq!(config.relay.gc_interval, Duration::from_secs(3));
		assert_eq!(config.relay.gc_lifetime, Duration::from_secs(15));
		assert!(!config.relay.skip_cert_verify);
		assert_eq!(config.local.max_packet_size, 1500);
	}
	#[test]
	fn test_tcp_udp_forward() {
		let json5_config = include_str!("../tests/config/tcp_udp_forward.json5");

		let config = test_parse_config(json5_config, ".json5").unwrap();

		assert_eq!(config.local.tcp_forward.len(), 2);
		assert_eq!(config.local.tcp_forward[0].listen.to_string(), "127.0.0.1:8080");
		assert_eq!(config.local.tcp_forward[0].remote.0, "google.com");
		assert_eq!(config.local.tcp_forward[0].remote.1, 80);

		assert_eq!(config.local.udp_forward.len(), 1);
		assert_eq!(config.local.udp_forward[0].listen.to_string(), "127.0.0.1:5353");
		assert_eq!(config.local.udp_forward[0].remote.0, "8.8.8.8");
		assert_eq!(config.local.udp_forward[0].remote.1, 53);
		assert_eq!(config.local.udp_forward[0].timeout, Duration::from_secs(10));
	}

	#[test]
	fn test_invalid_uuid() {
		let json5_config = include_str!("../tests/config/invalid_uuid.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_err());
	}

	#[test]
	fn test_invalid_socket_addr() {
		let json5_config = include_str!("../tests/config/invalid_socket_addr.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_err());
	}

	#[test]
	fn test_alpn_configuration() {
		let json5_config = include_str!("../tests/config/alpn_configuration.json5");

		let config = test_parse_config(json5_config, ".json5").unwrap();
		assert_eq!(config.relay.alpn.len(), 3);
		assert_eq!(config.relay.alpn[0], b"h3".to_vec());
		assert_eq!(config.relay.alpn[1], b"h2".to_vec());
		assert_eq!(config.relay.alpn[2], b"http/1.1".to_vec());
	}

	#[test]
	fn test_proxy_config() {
		let toml_config = r#"
[relay]
server = "example.com:443"
uuid = "00000000-0000-0000-0000-000000000000"
password = "pass"
[relay.proxy]
server = "127.0.0.1:1080"
username = "user"
password = "pwd"

[local]
server = "127.0.0.1:1081"
"#;
		let config = test_parse_config(toml_config, ".toml").unwrap();
		let proxy = config.relay.proxy.unwrap();
		assert_eq!(proxy.server.0, "127.0.0.1");
		assert_eq!(proxy.server.1, 1080);
		assert_eq!(proxy.username.unwrap(), "user");
		assert_eq!(proxy.password.unwrap(), "pwd");
	}

	#[test]
	fn test_ipv6_server_address() {
		let json5_config = include_str!("../tests/config/ipv6_server_address.json5");

		let config = test_parse_config(json5_config, ".json5").unwrap();
		assert!(config.local.server.is_ipv6());
		assert_eq!(config.local.server.to_string(), "[::1]:1080");
	}

	#[test]
	fn test_socks5_authentication() {
		let json5_config = include_str!("../tests/config/socks5_authentication.json5");

		let config = test_parse_config(json5_config, ".json5").unwrap();
		assert!(config.local.username.is_some());
		assert!(config.local.password.is_some());
		assert_eq!(config.local.username.as_ref().unwrap(), b"socks_user");
		assert_eq!(config.local.password.as_ref().unwrap(), b"socks_pass");
	}

	#[test]
	fn test_toml_basic_config() {
		let toml_config = include_str!("../tests/config/toml_basic_config.toml");

		let config = test_parse_config(toml_config, ".toml").unwrap();

		assert_eq!(config.log_level, "info");
		assert_eq!(config.relay.server.0, "example.com");
		assert_eq!(config.relay.server.1, 443);
		assert_eq!(config.local.server.to_string(), "127.0.0.1:1080");
	}

	#[test]
	fn test_toml_with_defaults() {
		let toml_config = include_str!("../tests/config/toml_with_defaults.toml");

		let config = test_parse_config(toml_config, ".toml").unwrap();

		// Test default values
		assert_eq!(config.log_level, "info");
		assert_eq!(config.relay.congestion_control, CongestionControl::Bbr);
		assert_eq!(config.relay.udp_relay_mode, UdpRelayMode::Native);
		assert_eq!(config.relay.timeout, Duration::from_secs(8));
		assert_eq!(config.relay.heartbeat, Duration::from_secs(3));
		assert_eq!(config.relay.initial_mtu, 1200);
		assert_eq!(config.relay.min_mtu, 1200);
		assert!(config.relay.gso);
		assert!(config.relay.pmtu);
		assert!(!config.relay.zero_rtt_handshake);
		assert!(!config.relay.disable_sni);
	}

	#[test]
	fn test_toml_full_config() {
		let toml_config = include_str!("../tests/config/toml_full_config.toml");

		let config = test_parse_config(toml_config, ".toml").unwrap();

		assert_eq!(config.log_level, "debug");
		assert_eq!(config.relay.server.0, "example.com");
		assert_eq!(config.relay.server.1, 8443);
		assert_eq!(config.relay.ipstack_prefer, StackPrefer::V6first);
		assert_eq!(config.relay.udp_relay_mode, UdpRelayMode::Quic);
		assert_eq!(config.relay.congestion_control, CongestionControl::Bbr);
		assert_eq!(config.relay.alpn.len(), 2);
		assert_eq!(config.relay.alpn[0], b"h3".to_vec());
		assert_eq!(config.relay.alpn[1], b"h2".to_vec());
		assert!(config.relay.zero_rtt_handshake);
		assert!(config.relay.disable_sni);
		assert_eq!(config.relay.timeout, Duration::from_secs(10));
		assert_eq!(config.relay.heartbeat, Duration::from_secs(5));
		assert_eq!(config.relay.send_window, 32777216);
		assert_eq!(config.relay.receive_window, 16388608);
		assert_eq!(config.relay.initial_mtu, 1400);
		assert_eq!(config.relay.min_mtu, 1300);
		assert!(!config.relay.gso);
		assert!(!config.relay.pmtu);
		assert_eq!(config.relay.gc_interval, Duration::from_secs(5));
		assert_eq!(config.relay.gc_lifetime, Duration::from_secs(20));
		assert_eq!(config.local.server.to_string(), "[::1]:1080");
		assert_eq!(config.local.dual_stack, Some(false));
		assert_eq!(config.local.max_packet_size, 2000);
	}

	#[test]
	fn test_toml_with_forwarding() {
		let toml_config = include_str!("../tests/config/toml_with_forwarding.toml");

		let config = test_parse_config(toml_config, ".toml").unwrap();

		assert_eq!(config.local.tcp_forward.len(), 1);
		assert_eq!(config.local.tcp_forward[0].listen.to_string(), "127.0.0.1:8080");
		assert_eq!(config.local.tcp_forward[0].remote.0, "example.com");
		assert_eq!(config.local.tcp_forward[0].remote.1, 80);

		assert_eq!(config.local.udp_forward.len(), 1);
		assert_eq!(config.local.udp_forward[0].listen.to_string(), "127.0.0.1:5353");
		assert_eq!(config.local.udp_forward[0].remote.0, "8.8.8.8");
		assert_eq!(config.local.udp_forward[0].remote.1, 53);
		assert_eq!(config.local.udp_forward[0].timeout, Duration::from_secs(30));
	}

	#[test]
	fn test_parse_json5_file() {
		let config_content = include_str!("../tests/config/basic.json5");

		let config = test_parse_config(config_content, ".json5").unwrap();
		assert_eq!(config.log_level, "debug");
		assert_eq!(config.relay.server.0, "example.com");
		assert_eq!(config.relay.server.1, 8443);
	}

	#[test]
	fn test_parse_toml_file() {
		let config_content = include_str!("../tests/config/basic.toml");

		let config = test_parse_config(config_content, ".toml").unwrap();
		assert_eq!(config.log_level, "warn");
		assert_eq!(config.relay.server.0, "test.example.com");
		assert_eq!(config.relay.server.1, 9443);
		assert_eq!(config.relay.udp_relay_mode, UdpRelayMode::Quic);
		assert!(config.relay.zero_rtt_handshake);
	}

	#[test]
	fn test_parse_yaml_file() {
		let config_content = include_str!("../tests/config/basic.yaml");

		let config = test_parse_config(config_content, ".yaml").unwrap();
		assert_eq!(config.log_level, "info");
		assert_eq!(config.relay.server.0, "yaml.example.com");
		assert_eq!(config.relay.server.1, 8443);
	}

	#[test]
	fn test_format_inference_json() {
		let config_content = include_str!("../tests/config/inference_json.txt");

		// Use .txt extension to force format inference
		let config = test_parse_config(config_content, ".txt").unwrap();
		assert_eq!(config.relay.server.0, "inferred.example.com");
	}

	#[test]
	fn test_format_inference_toml() {
		let config_content = include_str!("../tests/config/inference_toml.config");

		// Use .config extension to force format inference
		let config = test_parse_config(config_content, ".config").unwrap();
		assert_eq!(config.relay.server.0, "inferred.example.com");
	}

	#[test]
	fn test_format_inference_yaml() {
		let config_content = include_str!("../tests/config/inference_yaml.config");

		let config = test_parse_config(config_content, ".config").unwrap();
		assert_eq!(config.relay.server.0, "inferred.example.com");
	}

	#[test]
	fn test_env_var_force_toml() {
		let config_content = include_str!("../tests/config/env_var_force_toml.toml");

		// Create EnvState with force_toml enabled
		let env_state = EnvState {
			tuic_force_toml:    true,
			tuic_config_format: None,
		};

		// Even with .json extension, should parse as TOML
		let config = test_parse_config_with_env(config_content, ".json", env_state).unwrap();
		assert_eq!(config.relay.server.0, "forced.example.com");
	}

	#[test]
	fn test_env_var_config_format() {
		let config_content = include_str!("../tests/config/env_yaml.toml");

		// Create EnvState with config_format set to YAML
		let env_state = EnvState {
			tuic_force_toml:    false,
			tuic_config_format: Some("yaml".to_string()),
		};

		// Even with .toml extension, should parse as YAML
		let config = test_parse_config_with_env(config_content, ".toml", env_state).unwrap();
		assert_eq!(config.relay.server.0, "env.example.com");
		assert_eq!(config.log_level, "error");
	}

	#[test]
	fn test_config_not_found() {
		let cli = Cli {
			config: Some(PathBuf::from("/nonexistent/path/config.json")),
		};

		let result = Config::parse(cli, EnvState::default());
		assert!(result.is_err());
		let err = result.unwrap_err();
		let config_err = err.downcast_ref::<ConfigError>().unwrap();
		assert!(matches!(config_err, ConfigError::ConfigNotFound(_)));
	}

	#[test]
	fn test_no_config_specified() {
		let cli = Cli { config: None };

		let result = Config::parse(cli, EnvState::default());
		assert!(result.is_err());
		let err = result.unwrap_err();
		let config_err = err.downcast_ref::<ConfigError>().unwrap();
		assert!(matches!(config_err, ConfigError::NoConfig));
	}

	#[test]
	fn test_backward_compat_json_to_toml() {
		// Test that configs can be converted from JSON5 to TOML
		let json5_content = include_str!("../tests/config/compat_json.json5");

		let json_config = test_parse_config(json5_content, ".json5").unwrap();

		// Verify the config is parsed correctly
		assert_eq!(json_config.relay.server.0, "compat.example.com");
		assert_eq!(json_config.relay.server.1, 8443);
		assert_eq!(json_config.log_level, "warn");
	}

	#[test]
	fn test_all_relay_options_toml() {
		let config_content = include_str!("../tests/config/all_relay_options_toml.toml");

		let config = test_parse_config(config_content, ".toml").unwrap();

		assert_eq!(config.log_level, "trace");
		assert_eq!(config.relay.server.0, "full.example.com");
		assert_eq!(config.relay.server.1, 8443);
		assert_eq!(config.relay.ip, Some("192.168.1.100".parse().unwrap()));
		assert_eq!(config.relay.ipstack_prefer, StackPrefer::V4only);
		assert_eq!(config.relay.certificates.len(), 2);
		assert_eq!(config.relay.udp_relay_mode, UdpRelayMode::Quic);
		assert_eq!(config.relay.congestion_control, CongestionControl::Cubic);
		assert_eq!(config.relay.alpn.len(), 1);
		assert!(config.relay.zero_rtt_handshake);
		assert!(config.relay.disable_sni);
		assert_eq!(config.relay.timeout, Duration::from_secs(20));
		assert_eq!(config.relay.heartbeat, Duration::from_secs(10));
		assert!(config.relay.disable_native_certs);
		assert_eq!(config.relay.send_window, 20000000);
		assert_eq!(config.relay.receive_window, 10000000);
		assert_eq!(config.relay.initial_mtu, 1500);
		assert_eq!(config.relay.min_mtu, 1280);
		assert!(!config.relay.gso);
		assert!(!config.relay.pmtu);
		assert_eq!(config.relay.gc_interval, Duration::from_secs(10));
		assert_eq!(config.relay.gc_lifetime, Duration::from_secs(60));
		assert!(config.relay.skip_cert_verify);

		assert_eq!(config.local.server.to_string(), "[::1]:9999");
		assert_eq!(config.local.username, Some(b"user123".to_vec()));
		assert_eq!(config.local.password, Some(b"pass456".to_vec()));
		assert_eq!(config.local.dual_stack, Some(true));
		assert_eq!(config.local.max_packet_size, 2000);
	}

	#[test]
	fn test_forwarding_yaml() {
		let config_content = include_str!("../tests/config/forwarding.yaml");

		let config = test_parse_config(config_content, ".yaml").unwrap();

		assert_eq!(config.local.tcp_forward.len(), 1);
		assert_eq!(config.local.tcp_forward[0].listen.to_string(), "127.0.0.1:8080");
		assert_eq!(config.local.tcp_forward[0].remote.0, "example.com");
		assert_eq!(config.local.tcp_forward[0].remote.1, 80);

		assert_eq!(config.local.udp_forward.len(), 1);
		assert_eq!(config.local.udp_forward[0].listen.to_string(), "127.0.0.1:5353");
		assert_eq!(config.local.udp_forward[0].remote.0, "8.8.8.8");
		assert_eq!(config.local.udp_forward[0].timeout, Duration::from_secs(30));
	}
}
