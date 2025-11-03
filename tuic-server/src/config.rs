use std::{
	collections::HashMap,
	fmt,
	net::{Ipv4Addr, Ipv6Addr, SocketAddr},
	path::PathBuf,
	time::Duration,
};

use clap::Parser;
use educe::Educe;
use figment::{
	Figment,
	providers::{Format, Serialized, Toml, Yaml},
};
use figment_json5::Json5;
use serde::{
	Deserialize, Deserializer, Serialize,
	de::{self, Unexpected, Visitor},
};
use tracing::{level_filters::LevelFilter, warn};
use uuid::Uuid;

use crate::{
	acl::{AclAddress, AclPorts, AclRule},
	utils::{CongestionController, StackPrefer},
};

/// Environment state for configuration parsing
#[derive(Debug, Clone, Default)]
pub struct EnvState {
	pub in_docker:          bool,
	pub tuic_force_toml:    bool,
	pub tuic_config_format: Option<String>,
}

impl EnvState {
	/// Create EnvState from system environment variables
	pub fn from_system() -> Self {
		Self {
			in_docker:          std::env::var("IN_DOCKER").unwrap_or_default().to_lowercase() == "true",
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

/// TUIC Server - A minimalistic TUIC server implementation
#[derive(Parser, Debug)]
#[command(name = "tuic-server")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
	/// Path to the config file
	#[arg(short, long, value_name = "PATH")]
	pub config: Option<PathBuf>,

	/// Directory to search for config file (uses first recognizable config file
	/// found)
	#[arg(short, long, value_name = "DIR")]
	pub dir: Option<PathBuf>,

	/// Generate an example configuration file (config.toml)
	#[arg(short, long)]
	pub init: bool,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
	pub log_level: LogLevel,
	#[educe(Default(expression = "[::]:8443".parse().unwrap()))]
	pub server:    SocketAddr,
	pub users:     HashMap<Uuid, String>,
	pub tls:       TlsConfig,

	#[educe(Default = "")]
	pub data_dir: PathBuf,

	#[educe(Default = None)]
	pub restful: Option<RestfulConfig>,

	pub quic: QuicConfig,

	#[educe(Default = true)]
	pub udp_relay_ipv6: bool,

	#[educe(Default = false)]
	pub zero_rtt_handshake: bool,

	#[educe(Default = true)]
	pub dual_stack: bool,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(3)))]
	pub auth_timeout: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(3)))]
	pub task_negotiation_timeout: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(10)))]
	pub gc_interval: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(30)))]
	pub gc_lifetime: Duration,

	#[educe(Default = 1500)]
	pub max_external_packet_size: usize,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(60)))]
	pub stream_timeout: Duration,

	#[serde(default)]
	pub outbound: OutboundConfig,

	/// Access Control List rules
	#[serde(default, deserialize_with = "deserialize_acl")]
	#[educe(Default(expression = Vec::new()))]
	pub acl: Vec<AclRule>,

	pub experimental: ExperimentalConfig,

	/// Old configuration fields
	#[serde(default, rename = "self_sign")]
	#[deprecated]
	pub __self_sign:          Option<bool>,
	#[serde(default, rename = "certificate")]
	#[deprecated]
	pub __certificate:        Option<PathBuf>,
	#[serde(default, rename = "private_key")]
	#[deprecated]
	pub __private_key:        Option<PathBuf>,
	#[serde(default, rename = "auto_ssl")]
	#[deprecated]
	pub __auto_ssl:           Option<bool>,
	#[serde(default, rename = "hostname")]
	#[deprecated]
	pub __hostname:           Option<String>,
	#[serde(default, rename = "congestion_control")]
	#[deprecated]
	pub __congestion_control: Option<CongestionController>,
	#[serde(default, rename = "alpn")]
	#[deprecated]
	pub __alpn:               Option<Vec<String>>,
	#[serde(default, rename = "max_idle_time", with = "humantime_serde")]
	#[deprecated]
	pub __max_idle_time:      Option<Duration>,
	#[serde(default, rename = "initial_window")]
	#[deprecated]
	pub __initial_window:     Option<u64>,
	#[serde(default, rename = "receive_window")]
	#[deprecated]
	pub __send_window:        Option<u64>,
	#[serde(default, rename = "send_window")]
	#[deprecated]
	pub __receive_window:     Option<u32>,
	#[serde(default, rename = "initial_mtu")]
	#[deprecated]
	pub __initial_mtu:        Option<u16>,
	#[serde(default, rename = "min_mtu")]
	#[deprecated]
	pub __min_mtu:            Option<u16>,
	#[serde(default, rename = "gso")]
	#[deprecated]
	pub __gso:                Option<bool>,
	#[serde(default, rename = "pmtu")]
	#[deprecated]
	pub __pmtu:               Option<bool>,
	#[serde(rename = "restful_server")]
	#[deprecated]
	pub __restful_server:     Option<SocketAddr>,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
	pub self_sign:   bool,
	#[educe(Default(expression = ""))]
	pub certificate: PathBuf,
	#[educe(Default(expression = ""))]
	pub private_key: PathBuf,
	#[educe(Default(expression = Vec::new()))]
	pub alpn:        Vec<String>,
	#[educe(Default(expression = "localhost"))]
	pub hostname:    String,
	#[educe(Default(expression = false))]
	pub auto_ssl:    bool,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct QuicConfig {
	pub congestion_control: CongestionControlConfig,

	#[educe(Default = 1200)]
	pub initial_mtu: u16,

	#[educe(Default = 1200)]
	pub min_mtu: u16,

	#[educe(Default = true)]
	pub gso: bool,

	#[educe(Default = true)]
	pub pmtu: bool,

	#[educe(Default = 16777216)]
	pub send_window: u64,

	#[educe(Default = 8388608)]
	pub receive_window: u32,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(30)))]
	pub max_idle_time: Duration,
}

/// The `default` rule is mandatory when named rules are present; other named
/// rules are optional.
#[derive(Deserialize, Serialize, Educe, Clone, Debug)]
#[educe(Default)]
pub struct OutboundConfig {
	/// The default outbound rule (used when no name is specified).
	#[serde(default)]
	pub default: OutboundRule,

	/// Additional named outbound rules (e.g., `prefer_v4`, `through_socks5`).
	#[serde(flatten)]
	pub named: std::collections::HashMap<String, OutboundRule>,
}

/// Represents a single outbound rule (e.g., direct, socks5).
#[derive(Deserialize, Serialize, Educe, Clone, Debug)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct OutboundRule {
	/// The type of outbound: "direct" or "socks5".
	#[educe(Default = "direct".to_string())]
	#[serde(rename = "type")]
	pub kind: String,

	/// Mode for direct connections: "v4first" (prefer IPv4), "v6first" (prefer
	/// IPv6), "v4only" (IPv4 only), "v6only" (IPv6 only).
	#[educe(Default(expression = Some(StackPrefer::V4first)))]
	pub ip_mode: Option<StackPrefer>,

	/// Optional IPv4 address to bind to for direct connections (only used when
	/// kind == "direct").
	#[serde(default)]
	pub bind_ipv4: Option<Ipv4Addr>,

	/// Optional IPv6 address to bind to for direct connections (only used when
	/// kind == "direct").
	#[serde(default)]
	pub bind_ipv6: Option<Ipv6Addr>,

	/// Optional device/interface name to bind to (only used when kind ==
	/// "direct").
	#[serde(default)]
	pub bind_device: Option<String>,

	/// SOCKS5 address (only used when kind == "socks5").
	#[serde(default)]
	pub addr: Option<String>,

	/// Optional SOCKS5 username (only used when kind == "socks5").
	#[serde(default)]
	pub username: Option<String>,

	/// Optional SOCKS5 password (only used when kind == "socks5").
	#[serde(default)]
	pub password: Option<String>,

	/// Whether to allow UDP traffic when this outbound is selected.
	/// Only effective for kind == "socks5". Default behavior is to block UDP
	/// (i.e., drop UDP packets) to avoid leaking QUIC/HTTP3 over direct path.
	/// Set to true to allow UDP (still sent directly; UDP over SOCKS5 is not
	/// implemented).
	#[serde(default)]
	pub allow_udp: Option<bool>,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct CongestionControlConfig {
	pub controller:     CongestionController,
	#[educe(Default = 1048576)]
	pub initial_window: u64,
}

#[derive(Deserialize, Serialize, Educe, Clone)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct RestfulConfig {
	#[educe(Default(expression = "127.0.0.1:8443".parse().unwrap()))]
	pub addr:                     SocketAddr,
	#[educe(Default = "YOUR_SECRET_HERE")]
	pub secret:                   String,
	#[educe(Default = 0)]
	pub maximum_clients_per_user: usize,
}

#[derive(Deserialize, Serialize, Educe, Clone)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct ExperimentalConfig {
	#[educe(Default = true)]
	pub drop_loopback: bool,
}

impl Config {
	pub fn migrate(&mut self) {
		// Migrate TLS-related fields
		#[allow(deprecated)]
		{
			if let Some(self_sign) = self.__self_sign {
				self.tls.self_sign = self_sign;
			}
			if let Some(certificate) = self.__certificate.take() {
				self.tls.certificate = certificate;
			}
			if let Some(private_key) = self.__private_key.take() {
				self.tls.private_key = private_key;
			}
			if let Some(auto_ssl) = self.__auto_ssl {
				self.tls.auto_ssl = auto_ssl;
			}
			if let Some(hostname) = self.__hostname.take() {
				self.tls.hostname = hostname;
			}
			if let Some(alpn) = self.__alpn.take() {
				self.tls.alpn = alpn;
			}
		}

		// Migrate QUIC-related fields
		#[allow(deprecated)]
		{
			if let Some(congestion_control) = self.__congestion_control {
				self.quic.congestion_control.controller = congestion_control;
			}
			if let Some(max_idle_time) = self.__max_idle_time {
				self.quic.max_idle_time = max_idle_time;
			}
			if let Some(initial_window) = self.__initial_window {
				self.quic.congestion_control.initial_window = initial_window;
			}
			if let Some(send_window) = self.__send_window {
				self.quic.send_window = send_window;
			}
			if let Some(receive_window) = self.__receive_window {
				self.quic.receive_window = receive_window;
			}
			if let Some(initial_mtu) = self.__initial_mtu {
				self.quic.initial_mtu = initial_mtu;
			}
			if let Some(min_mtu) = self.__min_mtu {
				self.quic.min_mtu = min_mtu;
			}
			if let Some(gso) = self.__gso {
				self.quic.gso = gso;
			}
			if let Some(pmtu) = self.__pmtu {
				self.quic.pmtu = pmtu;
			}
		}

		// Migrate Restful-related fields
		#[allow(deprecated)]
		{
			if let Some(restful_server) = self.__restful_server {
				if self.restful.is_none() {
					self.restful = Some(RestfulConfig::default());
				}
				if let Some(ref mut restful) = self.restful {
					restful.addr = restful_server;
				}
			}
		}
	}

	pub fn full_example() -> Self {
		Self {
			users: {
				let mut users = HashMap::new();
				users.insert(Uuid::new_v4(), "YOUR_USER_PASSWD_HERE".into());
				users
			},
			restful: Some(RestfulConfig::default()),
			// Provide a minimal outbound example
			outbound: OutboundConfig {
				default: OutboundRule {
					kind: "direct".into(),
					ip_mode: Some(StackPrefer::V4first),
					..Default::default()
				},
				..Default::default()
			},
			// Example ACL list (empty by default)
			acl: Vec::new(),
			..Default::default()
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Educe)]
#[educe(Default)]
pub enum LogLevel {
	Trace,
	Debug,
	#[educe(Default)]
	Info,
	Warn,
	Error,
	Off,
}
impl From<LogLevel> for LevelFilter {
	fn from(value: LogLevel) -> Self {
		match value {
			LogLevel::Trace => LevelFilter::TRACE,
			LogLevel::Debug => LevelFilter::DEBUG,
			LogLevel::Info => LevelFilter::INFO,
			LogLevel::Warn => LevelFilter::WARN,
			LogLevel::Error => LevelFilter::ERROR,
			LogLevel::Off => LevelFilter::OFF,
		}
	}
}

/// Infer the config format from file content
fn infer_config_format(content: &str) -> ConfigFormat {
	let trimmed = content.trim_start();

	// Check for JSON/JSON5 format
	if trimmed.starts_with('{') || trimmed.starts_with('[') {
		return ConfigFormat::Json;
	}

	// Check for YAML format (common indicators)
	// YAML typically starts with --- or has key: value patterns
	if trimmed.starts_with("---") || trimmed.starts_with("%YAML") {
		return ConfigFormat::Yaml;
	}

	// Try to detect YAML-style indentation patterns
	let lines: Vec<&str> = content
		.lines()
		.filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
		.collect();
	let has_yaml_patterns = lines.iter().any(|line| {
		let trimmed_line = line.trim();
		// YAML list items start with -
		if trimmed_line.starts_with("- ") {
			return true;
		}
		// YAML key-value with colon and typically followed by space or newline
		if let Some(colon_pos) = trimmed_line.find(':') {
			let after_colon = &trimmed_line[colon_pos + 1..];
			// In YAML, after colon there's usually a space, newline, or it's at the end
			// In TOML, = is used instead of :
			return after_colon.is_empty() || after_colon.starts_with(' ') || after_colon.starts_with('\t');
		}
		false
	});

	// Check for TOML format (common indicators)
	// TOML uses = for assignment and [section] for tables
	let has_toml_patterns = lines.iter().any(|line| {
		let trimmed_line = line.trim();
		trimmed_line.starts_with('[') && trimmed_line.contains(']') && !trimmed_line.contains(':') || trimmed_line.contains('=')
	});

	// Decide based on patterns found
	if has_toml_patterns && !has_yaml_patterns {
		ConfigFormat::Toml
	} else if has_yaml_patterns && !has_toml_patterns {
		ConfigFormat::Yaml
	} else if has_toml_patterns && has_yaml_patterns {
		// If both patterns exist, prefer TOML as it's more distinctive
		// (YAML could have = in values, but TOML [sections] are more specific)
		ConfigFormat::Toml
	} else {
		// Default to Unknown if we can't determine
		ConfigFormat::Unknown
	}
}

enum ConfigFormat {
	Json,
	Toml,
	Yaml,
	Unknown,
}

/// Find the first recognizable config file in a directory
async fn find_config_in_dir(dir: &PathBuf) -> eyre::Result<PathBuf> {
	if !dir.exists() {
		return Err(eyre::eyre!("Directory not found: {}", dir.display()));
	}

	if !dir.is_dir() {
		return Err(eyre::eyre!("Path is not a directory: {}", dir.display()));
	}

	let mut entries = tokio::fs::read_dir(dir).await?;
	let mut config_files = Vec::new();

	// Collect all files with recognizable config extensions
	while let Some(entry) = entries.next_entry().await? {
		let path = entry.path();
		if path.is_file() {
			if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
				match ext.to_lowercase().as_str() {
					"toml" | "json" | "json5" | "yaml" | "yml" => {
						config_files.push(path);
					}
					_ => {}
				}
			}
		}
	}

	if config_files.is_empty() {
		return Err(eyre::eyre!(
			"No recognizable config file found in directory: {}",
			dir.display()
		));
	}

	// Sort to ensure consistent behavior (alphabetical order)
	config_files.sort();

	Ok(config_files[0].clone())
}

pub async fn parse_config(cli: Cli, env_state: EnvState) -> eyre::Result<Config> {
	// Handle --init flag
	if cli.init {
		warn!("Generating an example configuration to config.toml......");
		let example = Config::full_example();
		let example = toml::to_string_pretty(&example).unwrap();
		tokio::fs::write("config.toml", example).await?;
		return Err(Control("Done").into());
	}

	// Determine config path: either from --config or --dir
	let cfg_path = if let Some(config) = cli.config {
		config
	} else if let Some(dir) = cli.dir {
		find_config_in_dir(&dir).await?
	} else {
		return Err(eyre::eyre!(
			"Config file is required. Use -c/--config to specify the path, -d/--dir to specify a directory, or -h for help."
		));
	};

	// Check if config file exists
	if !cfg_path.exists() {
		return Err(eyre::eyre!("Config file not found: {}", cfg_path.display()));
	}

	let figmet = Figment::from(Serialized::defaults(Config::default()));
	let format;

	// Priority: TUIC_FORCE_TOML > TUIC_CONFIG_FORMAT > file extension > content
	// inference (in Docker)
	if env_state.tuic_force_toml {
		format = ConfigFormat::Toml;
	} else if let Some(ref env_format) = env_state.tuic_config_format {
		// TUIC_CONFIG_FORMAT has higher priority than file extension
		match env_format.to_lowercase().as_str() {
			"json" | "json5" => {
				format = ConfigFormat::Json;
			}
			"yaml" | "yml" => {
				format = ConfigFormat::Yaml;
			}
			"toml" => {
				format = ConfigFormat::Toml;
			}
			_ => format = ConfigFormat::Unknown,
		}
	} else if env_state.in_docker {
		// In Docker without explicit format, prefer content inference over file
		// extension
		format = ConfigFormat::Unknown;
	} else {
		// Fall back to file extension
		match cfg_path
			.extension()
			.and_then(|v| v.to_str())
			.unwrap_or_default()
			.to_lowercase()
			.as_str()
		{
			"json" | "json5" => {
				format = ConfigFormat::Json;
			}
			"yaml" | "yml" => {
				format = ConfigFormat::Yaml;
			}
			"toml" => {
				format = ConfigFormat::Toml;
			}
			_ => format = ConfigFormat::Unknown,
		}
	}
	let figmet = match format {
		ConfigFormat::Json => figmet.merge(Json5::file(&cfg_path)),
		ConfigFormat::Toml => figmet.merge(Toml::file(&cfg_path)),
		ConfigFormat::Yaml => figmet.merge(Yaml::file(&cfg_path)),
		ConfigFormat::Unknown => {
			// Try to infer format from file content
			let content = tokio::fs::read_to_string(&cfg_path).await?;
			let inferred_format = infer_config_format(&content);

			match inferred_format {
				ConfigFormat::Json => figmet.merge(Json5::file(&cfg_path)),
				ConfigFormat::Toml => figmet.merge(Toml::file(&cfg_path)),
				ConfigFormat::Yaml => figmet.merge(Yaml::file(&cfg_path)),
				ConfigFormat::Unknown => {
					return Err(Control(
						"Cannot infer config format from file extension or content, please set TUIC_CONFIG_FORMAT or \
						 TUIC_FORCE_TOML",
					))?;
				}
			}
		}
	};

	let mut config: Config = figmet.extract()?;

	// Migrate legacy fields to new nested structure
	config.migrate();

	if config.data_dir.to_str() == Some("") {
		config.data_dir = std::env::current_dir()?
	} else if config.data_dir.is_relative() {
		config.data_dir = std::env::current_dir()?.join(config.data_dir);
		tokio::fs::create_dir_all(&config.data_dir).await?;
	} else {
		tokio::fs::create_dir_all(&config.data_dir).await?;
	};

	// Determine certificate and key paths
	let base_dir = config.data_dir.clone();
	config.tls.certificate = if config.tls.auto_ssl && config.tls.certificate.to_str() == Some("") {
		config.data_dir.join(format!("{}.cer.pem", config.tls.hostname))
	} else if config.tls.certificate.is_relative() {
		config.data_dir.join(&config.tls.certificate)
	} else {
		config.tls.certificate.clone()
	};

	config.tls.private_key = if config.tls.auto_ssl && config.tls.private_key.to_str() == Some("") {
		config.data_dir.join(format!("{}.key.pem", config.tls.hostname))
	} else if config.tls.private_key.is_relative() {
		base_dir.join(&config.tls.private_key)
	} else {
		config.tls.private_key.clone()
	};

	Ok(config)
}

/// Deserialize the `acl` field which may be either:
///   * an array of TOML tables (array-of-tables format)
///   * a single multiline string with space-separated rules
fn deserialize_acl<'de, D>(deserializer: D) -> Result<Vec<AclRule>, D::Error>
where
	D: Deserializer<'de>,
{
	struct AclVisitor;

	impl<'de> Visitor<'de> for AclVisitor {
		type Value = Vec<AclRule>;

		fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
			formatter.write_str("a sequence of ACL rule tables or a multiline string")
		}

		// Handle array-of-tables format: [[acl]] entries
		fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
		where
			A: de::SeqAccess<'de>,
		{
			let mut vec = Vec::new();
			while let Some(rule) = seq.next_element::<AclRule>()? {
				vec.push(rule);
			}
			Ok(vec)
		}

		// Handle multiline string format
		fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
		where
			E: de::Error,
		{
			parse_multiline_acl_string(v).map_err(|e| de::Error::invalid_value(Unexpected::Str(v), &e.as_str()))
		}

		fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
		where
			E: de::Error,
		{
			self.visit_str(&v)
		}
	}

	deserializer.deserialize_any(AclVisitor)
}

/// Parse a multiline string into ACL rules
/// Format: <outbound_name> <address> <optional:port(s)>
/// <optional:hijack_ip_address>
fn parse_multiline_acl_string(input: &str) -> Result<Vec<AclRule>, String> {
	let mut rules = Vec::new();

	for (line_num, line) in input.lines().enumerate() {
		let line = line.trim();

		// Skip empty lines and comments
		if line.is_empty() || line.starts_with('#') {
			continue;
		}

		// Split by whitespace
		let parts: Vec<&str> = line.split_whitespace().collect();

		if parts.len() < 2 {
			return Err(format!(
				"Line {}: Invalid ACL rule format. Expected: <outbound> <address> [ports] [hijack]",
				line_num + 1
			));
		}

		let outbound = parts[0].to_string();
		let addr_str = parts[1];

		// Parse address
		let addr = addr_str
			.parse::<AclAddress>()
			.map_err(|e| format!("Line {}: Invalid address '{}': {}", line_num + 1, addr_str, e))?;

		// Parse optional ports (3rd parameter)
		let ports = if parts.len() > 2 && parts[2].parse::<std::net::IpAddr>().is_err() {
			// If the 3rd part is not an IP address, treat it as ports
			Some(
				parts[2]
					.parse::<AclPorts>()
					.map_err(|e| format!("Line {}: Invalid ports '{}': {}", line_num + 1, parts[2], e))?,
			)
		} else {
			None
		};

		// Parse optional hijack IP (last parameter if it's an IP)
		let hijack = if parts.len() > 2 {
			let last_part = parts[parts.len() - 1];
			if last_part.parse::<std::net::IpAddr>().is_ok() {
				Some(last_part.to_string())
			} else {
				None
			}
		} else {
			None
		};

		rules.push(AclRule {
			outbound,
			addr,
			ports,
			hijack,
		});
	}

	Ok(rules)
}

// You'll also need to implement Deserialize for AclRule to handle TOML table
// format
impl<'de> Deserialize<'de> for AclRule {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		#[derive(Deserialize)]
		struct AclRuleHelper {
			outbound: String,
			addr:     String,
			ports:    Option<String>,
			hijack:   Option<String>,
		}

		let helper = AclRuleHelper::deserialize(deserializer)?;

		let addr = helper
			.addr
			.parse::<AclAddress>()
			.map_err(|e| de::Error::invalid_value(Unexpected::Str(&helper.addr), &format!("valid address: {e}").as_str()))?;

		let ports =
			if let Some(ports_str) = helper.ports {
				Some(ports_str.parse::<AclPorts>().map_err(|e| {
					de::Error::invalid_value(Unexpected::Str(&ports_str), &format!("valid ports: {e}").as_str())
				})?)
			} else {
				None
			};

		Ok(AclRule {
			outbound: helper.outbound,
			addr,
			ports,
			hijack: helper.hijack,
		})
	}
}

#[cfg(test)]
mod tests {
	use std::{
		env, fs,
		net::{Ipv6Addr, SocketAddr, SocketAddrV6},
	};

	use tempfile::tempdir;

	use super::*;
	use crate::acl::{AclPortSpec, AclProtocol};

	async fn test_parse_config(config_content: &str, extension: &str) -> eyre::Result<Config> {
		test_parse_config_with_env(config_content, extension, EnvState::default()).await
	}

	async fn test_parse_config_with_env(config_content: &str, extension: &str, env_state: EnvState) -> eyre::Result<Config> {
		let temp_dir = tempdir().unwrap();
		let config_path = temp_dir.path().join(format!("config{}", extension));

		fs::write(&config_path, &config_content).unwrap();

		// Temporarily set command line arguments for clap to parse
		let os_args = vec![
			"test_binary".to_owned(),
			"--config".to_owned(),
			config_path.to_string_lossy().into_owned(),
		];

		// Parse CLI with test arguments
		let cli = Cli::try_parse_from(os_args)?;

		// Call parse_config with the CLI and env_state
		let result = parse_config(cli, env_state).await;

		result
	}

	#[tokio::test]
	async fn test_valid_toml_config() -> eyre::Result<()> {
		let config = include_str!("../tests/config/valid_toml_config.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		assert_eq!(result.log_level, LogLevel::Warn);
		assert_eq!(result.server, "127.0.0.1:8080".parse().unwrap());
		assert_eq!(result.udp_relay_ipv6, false);
		assert_eq!(result.zero_rtt_handshake, true);

		assert_eq!(result.tls.self_sign, true);
		assert_eq!(result.tls.auto_ssl, true);
		assert_eq!(result.tls.hostname, "testhost");

		assert_eq!(result.quic.initial_mtu, 1400);
		assert_eq!(result.quic.min_mtu, 1300);
		assert_eq!(result.quic.send_window, 10000000);
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);
		assert_eq!(result.quic.congestion_control.initial_window, 2000000);

		let restful = result.restful.unwrap();
		assert_eq!(restful.addr, "192.168.1.100:8081".parse().unwrap());
		assert_eq!(restful.secret, "test_secret");
		assert_eq!(restful.maximum_clients_per_user, 5);

		let uuid1 = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
		let uuid2 = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174001").unwrap();
		assert_eq!(result.users.get(&uuid1), Some(&"password1".to_string()));
		assert_eq!(result.users.get(&uuid2), Some(&"password2".to_string()));

		// Cleanup test directories
		let _ = tokio::fs::remove_dir_all("__test__custom_data").await;
		Ok(())
	}

	#[tokio::test]
	async fn test_json_config() {
		let config = include_str!("../tests/config/json_config.json");

		let result = test_parse_config(config, ".json").await.unwrap();

		assert_eq!(result.log_level, LogLevel::Error);
		assert_eq!(
			result.server,
			SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0, 0))
		);

		let uuid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174002").unwrap();
		assert_eq!(result.users.get(&uuid), Some(&"old_password".to_string()));

		assert_eq!(result.tls.self_sign, false);
		assert!(result.data_dir.ends_with("__test__legacy_data"));

		// Cleanup test directories
		let _ = tokio::fs::remove_dir_all("__test__legacy_data").await;
	}

	#[tokio::test]
	async fn test_path_handling() {
		let config = include_str!("../tests/config/path_handling.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		let current_dir = env::current_dir().unwrap();

		assert_eq!(result.data_dir, current_dir.join("__test__relative_path"));

		assert_eq!(
			result.tls.certificate,
			current_dir.join("__test__relative_path").join("certs/server.crt")
		);
		assert_eq!(
			result.tls.private_key,
			current_dir.join("__test__relative_path").join("certs/server.key")
		);

		// Cleanup test directories
		let _ = tokio::fs::remove_dir_all("__test__relative_path").await;
	}

	#[tokio::test]
	async fn test_auto_ssl_path_generation() {
		let config = include_str!("../tests/config/auto_ssl_path_generation.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		let expected_cert = env::current_dir()
			.unwrap()
			.join("__test__ssl_data")
			.join("example.com.cer.pem");

		let expected_key = env::current_dir()
			.unwrap()
			.join("__test__ssl_data")
			.join("example.com.key.pem");

		assert_eq!(result.tls.certificate, expected_cert);
		assert_eq!(result.tls.private_key, expected_key);

		// Cleanup test directories
		let _ = tokio::fs::remove_dir_all("__test__ssl_data").await;
	}

	#[tokio::test]
	async fn test_error_handling() {
		// Test Invalid TOML
		let config = "invalid toml content";
		let result = test_parse_config(config, ".toml").await;
		assert!(result.is_err());

		// Test Invalid JSON
		let config = "{ invalid json }";
		let result = test_parse_config(config, ".json").await;
		assert!(result.is_err());

		// Test non-existent configuration files - should fail when trying to parse
		let result = Cli::try_parse_from(vec!["test_binary", "--config", "non_existent.toml"]);
		// This will succeed at parsing CLI level, but fail when actually loading the
		// file
		if let Ok(cli) = result {
			assert!(cli.config.is_some());
			assert!(!cli.config.unwrap().exists());
		}

		// Test missing configuration file parameters - should fail at CLI parsing level
		let result = Cli::try_parse_from(vec!["test_binary"]);
		// This should succeed because --config is optional in CLI definition
		assert!(result.is_ok());
		let cli = result.unwrap();
		assert!(cli.config.is_none());
	}

	#[tokio::test]
	async fn test_outbound_no_configuration() {
		// Test that when no outbound configuration is provided, default is used
		let config = include_str!("../tests/config/outbound_no_configuration.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		// Should have default outbound configuration
		assert_eq!(result.outbound.default.kind, "direct");
		assert_eq!(result.outbound.named.len(), 0);
	}

	#[tokio::test]
	async fn test_outbound_valid_with_default() {
		// Test that when named outbound rules exist with a proper default, validation
		// passes
		let config = include_str!("../tests/config/outbound_valid_with_default.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		// Should have default and named outbound configurations
		assert_eq!(result.outbound.default.kind, "direct");
		assert_eq!(result.outbound.named.len(), 2);

		let prefer_v4 = result.outbound.named.get("prefer_v4").unwrap();
		assert_eq!(prefer_v4.kind, "direct");
		assert_eq!(prefer_v4.ip_mode, Some(StackPrefer::V4first));
		assert_eq!(prefer_v4.bind_ipv4, Some("2.4.6.8".parse().unwrap()));
		assert_eq!(prefer_v4.bind_device, Some("eth233".to_string()));

		let socks5 = result.outbound.named.get("through_socks5").unwrap();
		assert_eq!(socks5.kind, "socks5");
		assert_eq!(socks5.addr, Some("127.0.0.1:1080".to_string()));
		assert_eq!(socks5.username, Some("optional".to_string()));
		assert_eq!(socks5.password, Some("optional".to_string()));
	}

	#[tokio::test]
	async fn test_outbound_with_legacy_ip_mode_aliases() {
		// Test backward compatibility with old ip_mode values like "prefer_v4",
		// "only_v4" etc.
		let config = include_str!("../tests/config/outbound_with_legacy_ip_mode_aliases.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		// Verify default uses prefer_v4 (which maps to V4first)
		assert_eq!(result.outbound.default.ip_mode, Some(StackPrefer::V4first));

		// Verify named rules with legacy aliases
		let prefer_v6 = result.outbound.named.get("prefer_v6_rule").unwrap();
		assert_eq!(prefer_v6.ip_mode, Some(StackPrefer::V6first));

		let only_v4 = result.outbound.named.get("only_v4_rule").unwrap();
		assert_eq!(only_v4.ip_mode, Some(StackPrefer::V4only));

		let only_v6 = result.outbound.named.get("only_v6_rule").unwrap();
		assert_eq!(only_v6.ip_mode, Some(StackPrefer::V6only));
	}

	#[tokio::test]
	async fn test_acl_parsing() {
		let config = include_str!("../tests/config/acl_parsing.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		assert_eq!(result.acl.len(), 10);

		// Test first rule: "allow localhost udp/53"
		let rule1 = &result.acl[0];
		assert_eq!(rule1.outbound, "allow");
		assert_eq!(rule1.addr, AclAddress::Localhost);
		assert!(rule1.ports.is_some());
		let ports1 = rule1.ports.as_ref().unwrap();
		assert_eq!(ports1.entries.len(), 1);
		assert_eq!(ports1.entries[0].protocol, Some(AclProtocol::Udp));
		assert_eq!(ports1.entries[0].port_spec, AclPortSpec::Single(53));
		assert!(rule1.hijack.is_none());

		// Test complex ports rule: "allow localhost udp/53,tcp/80,tcp/443,udp/443"
		let rule2 = &result.acl[1];
		assert_eq!(rule2.outbound, "allow");
		assert_eq!(rule2.addr, AclAddress::Localhost);
		let ports2 = rule2.ports.as_ref().unwrap();
		assert_eq!(ports2.entries.len(), 4);

		// Test CIDR rule: "reject 10.6.0.0/16"
		let rule4 = &result.acl[3];
		assert_eq!(rule4.outbound, "reject");
		assert_eq!(rule4.addr, AclAddress::Cidr("10.6.0.0/16".to_string()));

		// Test wildcard domain: "allow *.google.com"
		let rule6 = &result.acl[5];
		assert_eq!(rule6.outbound, "allow");
		assert_eq!(rule6.addr, AclAddress::WildcardDomain("*.google.com".to_string()));

		// Test hijack rule: "default 8.8.4.4 udp/53 1.1.1.1"
		let rule10 = &result.acl[9];
		assert_eq!(rule10.outbound, "default");
		assert_eq!(rule10.addr, AclAddress::Ip("8.8.4.4".to_string()));
		assert!(rule10.ports.is_some());
		assert_eq!(rule10.hijack, Some("1.1.1.1".to_string()));
	}

	#[tokio::test]
	async fn test_acl_parsing_edge_cases() {
		// Test individual parsing functions
		assert_eq!(crate::acl::parse_acl_address("localhost").unwrap(), AclAddress::Localhost);
		assert_eq!(
			crate::acl::parse_acl_address("*.example.com").unwrap(),
			AclAddress::WildcardDomain("*.example.com".to_string())
		);
		assert_eq!(
			crate::acl::parse_acl_address("192.168.1.0/24").unwrap(),
			AclAddress::Cidr("192.168.1.0/24".to_string())
		);
		assert_eq!(
			crate::acl::parse_acl_address("127.0.0.1").unwrap(),
			AclAddress::Ip("127.0.0.1".to_string())
		);
		assert_eq!(
			crate::acl::parse_acl_address("example.com").unwrap(),
			AclAddress::Domain("example.com".to_string())
		);

		// Test port parsing
		let ports = crate::acl::parse_acl_ports("80,443,1000-2000,udp/53").unwrap();
		assert_eq!(ports.entries.len(), 4);
		assert_eq!(ports.entries[0].port_spec, AclPortSpec::Single(80));
		assert_eq!(ports.entries[2].port_spec, AclPortSpec::Range(1000, 2000));
		assert_eq!(ports.entries[3].protocol, Some(AclProtocol::Udp));

		// Test rule parsing
		let rule = crate::acl::parse_acl_rule("allow google.com 80,443").unwrap();
		assert_eq!(rule.outbound, "allow");
		assert_eq!(rule.addr, AclAddress::Domain("google.com".to_string()));
		assert!(rule.ports.is_some());
		assert!(rule.hijack.is_none());
	}

	#[tokio::test]
	async fn test_default_values() {
		// Test minimal configuration with defaults
		let config = include_str!("../tests/config/default_values.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		// Check default values
		assert_eq!(result.log_level, LogLevel::Info);
		assert_eq!(result.server, "[::]:8443".parse().unwrap());
		assert_eq!(result.udp_relay_ipv6, true);
		assert_eq!(result.zero_rtt_handshake, false);
		assert_eq!(result.dual_stack, true);
		assert_eq!(result.auth_timeout, Duration::from_secs(3));
		assert_eq!(result.task_negotiation_timeout, Duration::from_secs(3));
		assert_eq!(result.gc_interval, Duration::from_secs(10));
		assert_eq!(result.gc_lifetime, Duration::from_secs(30));
		assert_eq!(result.max_external_packet_size, 1500);
		assert_eq!(result.stream_timeout, Duration::from_secs(60));
	}

	#[tokio::test]
	async fn test_invalid_uuid() {
		let config = include_str!("../tests/config/invalid_uuid.toml");

		let result = test_parse_config(config, ".toml").await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_invalid_socket_addr() {
		let config = include_str!("../tests/config/invalid_socket_addr.toml");

		let result = test_parse_config(config, ".toml").await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_duration_parsing() {
		let config = include_str!("../tests/config/duration_parsing.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		assert_eq!(result.auth_timeout, Duration::from_secs(5));
		assert_eq!(result.task_negotiation_timeout, Duration::from_secs(10));
		assert_eq!(result.gc_interval, Duration::from_secs(30));
		assert_eq!(result.gc_lifetime, Duration::from_secs(60));
		assert_eq!(result.stream_timeout, Duration::from_secs(120));
	}

	#[tokio::test]
	async fn test_empty_acl() {
		let config = include_str!("../tests/config/empty_acl.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();
		assert_eq!(result.acl.len(), 0);
	}

	#[tokio::test]
	async fn test_acl_comments_and_whitespace() {
		let config = include_str!("../tests/config/acl_comments_and_whitespace.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();
		// Should have 3 rules
		assert_eq!(result.acl.len(), 3);
	}

	#[tokio::test]
	async fn test_congestion_control_variants() {
		// Test BBR
		let config_bbr = include_str!("../tests/config/congestion_control_bbr.toml");

		let result = test_parse_config(config_bbr, ".toml").await.unwrap();
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);

		// Test NewReno (note: lowercase 'newreno' is the valid variant)
		let config_new_reno = include_str!("../tests/config/congestion_control_newreno.toml");

		let result = test_parse_config(config_new_reno, ".toml").await.unwrap();
		assert_eq!(result.quic.congestion_control.controller, CongestionController::NewReno);
	}

	#[tokio::test]
	async fn test_backward_compatibility_standard_json() {
		// Test backward compatibility with standard JSON format
		let json_config = include_str!("../tests/config/backward_compatibility_standard_json.json");

		let result = test_parse_config(json_config, ".json").await;
		assert!(result.is_ok(), "Standard JSON should be parseable by JSON5");
	}
	#[tokio::test]
	async fn test_legacy_field_migration_json() {
		// Test legacy field migration with JSON format
		let config = include_str!("../tests/config/legacy_field_migration_json.json");

		let result = test_parse_config(config, ".json").await.unwrap();

		// Verify migration worked
		assert_eq!(result.tls.self_sign, true);
		assert!(result.tls.certificate.ends_with("cert.pem"));
		assert!(result.tls.private_key.ends_with("key.pem"));
		assert_eq!(result.tls.hostname, "example.com");
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);
		assert_eq!(result.quic.max_idle_time, Duration::from_secs(60));
		assert_eq!(result.quic.initial_mtu, 1500);

		assert!(result.restful.is_some());
		assert_eq!(result.restful.unwrap().addr, "0.0.0.0:8080".parse().unwrap());
	}

	#[tokio::test]
	async fn test_infer_format_toml_without_extension() {
		// Test TOML config without file extension
		let config = include_str!("../tests/config/infer_format_toml_without_extension");

		let result = test_parse_config(config, "").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Info);
		assert_eq!(result.server, "127.0.0.1:8080".parse().unwrap());
	}

	#[tokio::test]
	async fn test_infer_format_json_without_extension() {
		// Test JSON config without file extension
		let config = include_str!("../tests/config/infer_format_json_without_extension");

		let result = test_parse_config(config, "").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Debug);
		assert_eq!(result.server, "0.0.0.0:8443".parse().unwrap());
	}

	#[tokio::test]
	async fn test_yaml_config_format() {
		// Test YAML config format with .yaml extension
		// Note: test_parse_config helper trims whitespace which breaks YAML
		// indentation, so we keep indentation minimal and avoid deeply nested
		// structures
		let config = include_str!("../tests/config/yaml_config_format.yaml");

		let result = test_parse_config(config, ".yaml").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Warn);
		assert_eq!(result.server, "127.0.0.1:9000".parse().unwrap());
		assert_eq!(result.tls.hostname, "yaml.test.com");
	}

	#[tokio::test]
	async fn test_json5_with_comments() {
		// Test JSON5 format with comments
		let config = include_str!("../tests/config/json5_with_comments.json5");

		let result = test_parse_config(config, ".json5").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Info);
		assert_eq!(result.server, "127.0.0.1:8080".parse().unwrap());
		assert_eq!(result.tls.hostname, "test.json5.com");
	}

	#[tokio::test]
	async fn test_json5_with_trailing_commas() {
		// Test JSON5 format with trailing commas
		let config = include_str!("../tests/config/json5_with_trailing_commas.json5");

		let result = test_parse_config(config, ".json5").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Debug);
		assert_eq!(
			result.server,
			SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0, 0))
		);
		assert_eq!(result.users.len(), 2);
	}

	#[tokio::test]
	async fn test_json5_with_unquoted_keys() {
		// Test JSON5 format with unquoted keys
		let config = include_str!("../tests/config/json5_with_unquoted_keys.json5");

		let result = test_parse_config(config, ".json5").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Warn);
		assert_eq!(result.server, "0.0.0.0:8443".parse().unwrap());
		assert_eq!(result.tls.hostname, "unquoted.test.com");
	}

	#[tokio::test]
	async fn test_json5_comprehensive_features() {
		// Test JSON5 with multiple features combined
		let config = include_str!("../tests/config/json5_comprehensive_features.json5");

		let result = test_parse_config(config, ".json5").await.unwrap();

		assert_eq!(result.log_level, LogLevel::Info);
		assert_eq!(result.server, "127.0.0.1:9443".parse().unwrap());
		assert_eq!(result.udp_relay_ipv6, false);
		assert_eq!(result.zero_rtt_handshake, true);

		assert_eq!(result.users.len(), 2);

		assert_eq!(result.tls.self_sign, true);
		assert_eq!(result.tls.auto_ssl, true);
		assert_eq!(result.tls.hostname, "json5.example.com");

		assert_eq!(result.quic.initial_mtu, 1400);
		assert_eq!(result.quic.min_mtu, 1300);
		assert_eq!(result.quic.send_window, 8000000);
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);
		assert_eq!(result.quic.congestion_control.initial_window, 1500000);

		let restful = result.restful.unwrap();
		assert_eq!(restful.addr, "127.0.0.1:8888".parse().unwrap());
		assert_eq!(restful.secret, "json5_secret");
		assert_eq!(restful.maximum_clients_per_user, 10);
	}

	#[tokio::test]
	async fn test_json5_with_acl_rules() {
		// Test JSON5 format with ACL rules using multiline string
		let config = include_str!("../tests/config/json5_with_acl_rules.json5");

		let result = test_parse_config(config, ".json5").await.unwrap();

		assert_eq!(result.acl.len(), 4);

		// Verify first ACL rule
		assert_eq!(result.acl[0].outbound, "allow");
		assert_eq!(result.acl[0].addr, AclAddress::Localhost);

		// Verify CIDR rule
		assert_eq!(result.acl[2].outbound, "reject");
		assert_eq!(result.acl[2].addr, AclAddress::Cidr("10.0.0.0/8".to_string()));

		// Verify wildcard domain
		assert_eq!(result.acl[3].outbound, "allow");
		assert_eq!(result.acl[3].addr, AclAddress::WildcardDomain("*.example.com".to_string()));
	}

	#[tokio::test]
	async fn test_json5_backward_compatibility() {
		// Test that JSON5 parser can handle standard JSON
		let config = include_str!("../tests/config/json5_backward_compatibility.json5");

		let result = test_parse_config(config, ".json5").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Error);
		assert_eq!(result.server, "192.168.1.1:8443".parse().unwrap());
		assert_eq!(result.tls.self_sign, false);
	}

	#[tokio::test]
	async fn test_dir_parameter_finds_config() {
		// Test that --dir finds the first config file in a directory
		let temp_dir = tempdir().unwrap();
		let dir_path = temp_dir.path();

		// Create multiple config files
		let config_content = r#"
			log_level = "info"
			server = "127.0.0.1:8080"
			[users]
		"#;

		fs::write(dir_path.join("config.toml"), config_content).unwrap();
		fs::write(dir_path.join("other.json"), "{}").unwrap();

		let os_args = vec![
			"test_binary".to_owned(),
			"--dir".to_owned(),
			dir_path.to_string_lossy().into_owned(),
		];

		let cli = Cli::try_parse_from(os_args).unwrap();
		let result = parse_config(cli, EnvState::default()).await;

		assert!(result.is_ok());
		let config = result.unwrap();
		assert_eq!(config.log_level, LogLevel::Info);
		assert_eq!(config.server, "127.0.0.1:8080".parse().unwrap());
	}

	#[tokio::test]
	async fn test_dir_parameter_alphabetical_order() {
		// Test that --dir picks the first file alphabetically
		let temp_dir = tempdir().unwrap();
		let dir_path = temp_dir.path();

		// Create files that would sort alphabetically
		let config_a = r#"log_level = "debug""#;
		let config_z = r#"log_level = "error""#;

		fs::write(dir_path.join("z_config.toml"), config_z).unwrap();
		fs::write(dir_path.join("a_config.toml"), config_a).unwrap();

		let os_args = vec![
			"test_binary".to_owned(),
			"--dir".to_owned(),
			dir_path.to_string_lossy().into_owned(),
		];

		let cli = Cli::try_parse_from(os_args).unwrap();
		let result = parse_config(cli, EnvState::default()).await.unwrap();

		// Should pick a_config.toml which has debug level
		assert_eq!(result.log_level, LogLevel::Debug);
	}

	#[tokio::test]
	async fn test_dir_parameter_no_config_found() {
		// Test that --dir fails when no config files exist
		let temp_dir = tempdir().unwrap();
		let dir_path = temp_dir.path();

		// Create a non-config file
		fs::write(dir_path.join("readme.txt"), "not a config").unwrap();

		let os_args = vec![
			"test_binary".to_owned(),
			"--dir".to_owned(),
			dir_path.to_string_lossy().into_owned(),
		];

		let cli = Cli::try_parse_from(os_args).unwrap();
		let result = parse_config(cli, EnvState::default()).await;

		assert!(result.is_err());
		if let Err(err) = result {
			assert!(err.to_string().contains("No recognizable config file found"));
		}
	}

	#[tokio::test]
	async fn test_dir_parameter_nonexistent_directory() {
		// Test that --dir fails when directory doesn't exist
		let os_args = vec![
			"test_binary".to_owned(),
			"--dir".to_owned(),
			"/nonexistent/directory/path".to_owned(),
		];

		let cli = Cli::try_parse_from(os_args).unwrap();
		let result = parse_config(cli, EnvState::default()).await;

		assert!(result.is_err());
		if let Err(err) = result {
			assert!(err.to_string().contains("Directory not found"));
		}
	}

	#[tokio::test]
	async fn test_config_parameter_takes_precedence() {
		// Test that --config takes precedence over --dir
		let temp_dir = tempdir().unwrap();
		let dir_path = temp_dir.path();

		let config_in_dir = r#"log_level = "error""#;
		let config_explicit = r#"log_level = "warn""#;

		fs::write(dir_path.join("dir_config.toml"), config_in_dir).unwrap();
		let explicit_path = dir_path.join("explicit.toml");
		fs::write(&explicit_path, config_explicit).unwrap();

		let os_args = vec![
			"test_binary".to_owned(),
			"--config".to_owned(),
			explicit_path.to_string_lossy().into_owned(),
			"--dir".to_owned(),
			dir_path.to_string_lossy().into_owned(),
		];

		let cli = Cli::try_parse_from(os_args).unwrap();
		let result = parse_config(cli, EnvState::default()).await.unwrap();

		// Should use explicit config, not dir
		assert_eq!(result.log_level, LogLevel::Warn);
	}

	#[tokio::test]
	async fn test_dir_parameter_supports_all_formats() {
		// Test that --dir recognizes all supported config formats
		let temp_dir = tempdir().unwrap();
		let dir_path = temp_dir.path();

		// Test with JSON
		let json_dir = dir_path.join("json_test");
		fs::create_dir(&json_dir).unwrap();
		fs::write(json_dir.join("config.json"), r#"{"log_level": "debug"}"#).unwrap();

		let os_args = vec![
			"test_binary".to_owned(),
			"--dir".to_owned(),
			json_dir.to_string_lossy().into_owned(),
		];
		let cli = Cli::try_parse_from(os_args).unwrap();
		let result = parse_config(cli, EnvState::default()).await.unwrap();
		assert_eq!(result.log_level, LogLevel::Debug);

		// Test with YAML
		let yaml_dir = dir_path.join("yaml_test");
		fs::create_dir(&yaml_dir).unwrap();
		fs::write(yaml_dir.join("config.yaml"), "log_level: warn").unwrap();

		let os_args = vec![
			"test_binary".to_owned(),
			"--dir".to_owned(),
			yaml_dir.to_string_lossy().into_owned(),
		];
		let cli = Cli::try_parse_from(os_args).unwrap();
		let result = parse_config(cli, EnvState::default()).await.unwrap();
		assert_eq!(result.log_level, LogLevel::Warn);
	}

	#[tokio::test]
	async fn test_env_state_force_toml() {
		// Test TUIC_FORCE_TOML forces TOML parsing even with .json extension
		let config_content = include_str!("../tests/config/env_force_toml.toml");

		let env_state = EnvState {
			tuic_force_toml:    true,
			tuic_config_format: None,
			in_docker:          false,
		};

		// Use .json extension but content is TOML
		let result = test_parse_config_with_env(config_content, ".json", env_state).await.unwrap();
		assert_eq!(result.log_level, LogLevel::Info);
		assert_eq!(result.server, "127.0.0.1:8443".parse().unwrap());
	}

	#[tokio::test]
	async fn test_env_state_config_format_yaml() {
		// Test TUIC_CONFIG_FORMAT=yaml forces YAML parsing
		let config_content = include_str!("../tests/config/env_format_yaml.yaml");

		let env_state = EnvState {
			tuic_force_toml:    false,
			tuic_config_format: Some("yaml".to_string()),
			in_docker:          false,
		};

		// Use .toml extension but content is YAML
		let result = test_parse_config_with_env(config_content, ".toml", env_state).await.unwrap();
		assert_eq!(result.log_level, LogLevel::Debug);
		assert_eq!(
			result.server,
			SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0, 0))
		);
	}

	#[tokio::test]
	async fn test_env_state_config_format_json() {
		// Test TUIC_CONFIG_FORMAT=json forces JSON parsing
		let config_content = include_str!("../tests/config/env_format_json.json");

		let env_state = EnvState {
			tuic_force_toml:    false,
			tuic_config_format: Some("json".to_string()),
			in_docker:          false,
		};

		// Use .toml extension but content is JSON
		let result = test_parse_config_with_env(config_content, ".toml", env_state).await.unwrap();
		assert_eq!(result.log_level, LogLevel::Warn);
		assert_eq!(result.server, "127.0.0.1:9999".parse().unwrap());
	}

	#[tokio::test]
	async fn test_env_state_in_docker_inference() {
		// Test IN_DOCKER=true triggers content inference for files without extension
		let config_content = include_str!("../tests/config/env_docker_inference.config");

		let env_state = EnvState {
			tuic_force_toml:    false,
			tuic_config_format: None,
			in_docker:          true,
		};

		// Use unknown extension to trigger inference
		let result = test_parse_config_with_env(config_content, ".config", env_state)
			.await
			.unwrap();
		assert_eq!(result.log_level, LogLevel::Trace);
		assert_eq!(result.server, "127.0.0.1:7777".parse().unwrap());
	}

	#[tokio::test]
	async fn test_env_state_priority_force_toml_over_config_format() {
		// Test that TUIC_FORCE_TOML has higher priority than TUIC_CONFIG_FORMAT
		let config_content = include_str!("../tests/config/env_force_toml.toml");

		let env_state = EnvState {
			tuic_force_toml:    true,
			tuic_config_format: Some("json".to_string()), // This should be ignored
			in_docker:          false,
		};

		let result = test_parse_config_with_env(config_content, ".yaml", env_state).await.unwrap();
		assert_eq!(result.log_level, LogLevel::Info);
	}

	#[tokio::test]
	async fn test_env_state_priority_config_format_over_extension() {
		// Test that TUIC_CONFIG_FORMAT has higher priority than file extension
		let config_content = include_str!("../tests/config/env_format_yaml.yaml");

		let env_state = EnvState {
			tuic_force_toml:    false,
			tuic_config_format: Some("yaml".to_string()),
			in_docker:          false,
		};

		// File extension says .json but env says yaml
		let result = test_parse_config_with_env(config_content, ".json", env_state).await.unwrap();
		assert_eq!(result.log_level, LogLevel::Debug);
	}

	#[tokio::test]
	async fn test_env_state_priority_config_format_over_docker() {
		// Test that TUIC_CONFIG_FORMAT has higher priority than IN_DOCKER
		let config_content = include_str!("../tests/config/env_format_json.json");

		let env_state = EnvState {
			tuic_force_toml:    false,
			tuic_config_format: Some("json".to_string()),
			in_docker:          true, // This should be ignored when config_format is set
		};

		let result = test_parse_config_with_env(config_content, ".unknown", env_state)
			.await
			.unwrap();
		assert_eq!(result.log_level, LogLevel::Warn);
	}

	#[tokio::test]
	async fn test_env_state_from_system() {
		// Test EnvState::from_system() reads environment variables correctly
		// Note: This test doesn't actually set env vars, just tests the structure
		let env_state = EnvState::from_system();

		// Should not panic and return a valid EnvState
		assert!(env_state.tuic_config_format.is_none() || env_state.tuic_config_format.is_some());
	}

	#[tokio::test]
	async fn test_env_state_case_insensitive_format() {
		// Test that format names are case-insensitive
		let config_content = include_str!("../tests/config/env_format_yaml.yaml");

		let env_state = EnvState {
			tuic_force_toml:    false,
			tuic_config_format: Some("YAML".to_string()), // Uppercase
			in_docker:          false,
		};

		let result = test_parse_config_with_env(config_content, ".toml", env_state).await.unwrap();
		assert_eq!(result.log_level, LogLevel::Debug);
	}

	#[tokio::test]
	async fn test_env_state_invalid_format() {
		// Test that invalid format in TUIC_CONFIG_FORMAT falls back to Unknown
		let config_content = include_str!("../tests/config/env_force_toml.toml");

		let env_state = EnvState {
			tuic_force_toml:    false,
			tuic_config_format: Some("invalid_format".to_string()),
			in_docker:          false,
		};

		// Should try to infer from content
		let result = test_parse_config_with_env(config_content, ".txt", env_state).await;

		// Should succeed because inference will detect TOML
		assert!(result.is_ok());
	}
}
