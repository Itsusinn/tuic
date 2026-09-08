use std::{
	io::Error as IoError,
	net::{IpAddr, SocketAddr},
	path::PathBuf,
	sync::Arc,
	time::Duration,
};

use clap::Parser;
use educe::Educe;
use eyre::bail;
use figment::{
	Figment,
	providers::{Format, Serialized, Toml, Yaml},
};
use figment_json5::Json5;
use humantime::Duration as HumanDuration;
use serde::{Deserialize, Deserializer, de::Error as DeError};
use thiserror::Error;
use uuid::Uuid;

use crate::utils::{CongestionControl, StackPrefer, UdpRelayMode};

/// Environment state for configuration parsing
#[derive(Debug, Clone, Default)]
pub struct EnvState {
	pub tuic_force_toml: bool,
	pub tuic_config_format: Option<String>,
}

impl EnvState {
	/// Create EnvState from system environment variables
	pub fn from_system() -> Self {
		Self {
			tuic_force_toml: std::env::var("TUIC_FORCE_TOML").is_ok(),
			tuic_config_format: std::env::var("TUIC_CONFIG_FORMAT").ok().map(|v| v.to_lowercase()),
		}
	}
}

/// Command-line arguments for tuic-client.
#[derive(Parser, Debug)]
#[command(name = "tuic-client")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
	/// Path to the config file
	#[arg(short, long, value_name = "PATH")]
	pub config: Option<PathBuf>,
}

/// On-disk configuration, grouped like tuic-server. Runtime callers can keep
/// using Config/Relay; serialization always emits this modern layout.
#[derive(Debug, Clone, Deserialize, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
struct ConfigFile {
	#[serde(deserialize_with = "deserialize_server", serialize_with = "serialize_server")]
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

	#[educe(Default(expression = UdpRelayMode::Native))]
	pub udp_relay_mode: UdpRelayMode,

	#[educe(Default = false)]
	pub zero_rtt_handshake: bool,

	#[educe(Default(expression = Duration::from_secs(8)))]
	#[serde(with = "humantime_serde")]
	pub timeout: Duration,

	#[educe(Default(expression = Duration::from_secs(3)))]
	#[serde(with = "humantime_serde")]
	pub heartbeat: Duration,

	#[educe(Default(expression = Duration::from_secs(3)))]
	#[serde(with = "humantime_serde")]
	pub gc_interval: Duration,

	#[educe(Default(expression = Duration::from_secs(15)))]
	#[serde(with = "humantime_serde")]
	pub gc_lifetime: Duration,

	#[educe(Default = None)]
	pub proxy: Option<ProxyConfig>,

	/// Automatically reconnect to the relay after the connection drops.
	#[educe(Default = true)]
	pub reconnect: bool,

	/// Delay before the first reconnect attempt; doubled after each failure.
	#[educe(Default(expression = Duration::from_millis(500)))]
	#[serde(with = "humantime_serde")]
	pub reconnect_initial_backoff: Duration,

	/// Upper bound on the reconnect backoff delay.
	#[educe(Default(expression = Duration::from_secs(30)))]
	#[serde(with = "humantime_serde")]
	pub reconnect_max_backoff: Duration,

	/// Defer the QUIC connection establishment until the first actual
	/// traffic arrives.  When `false` (eager), the connection is
	/// established immediately at startup and the process exits on
	/// failure.  Defaults to `true` (matching v1.8.11 `startup_mode =
	/// "lazy"`).
	#[educe(Default = true)]
	#[serde(default)]
	pub lazy: bool,

	pub tls: TlsConfig,
	pub backend: BackendConfig,
	pub local: Local,
	#[educe(Default = "info")]
	pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
	#[educe(Default(expression = Vec::new()))]
	pub certificates: Vec<PathBuf>,

	#[educe(Default(expression = Vec::new()))]
	#[serde(deserialize_with = "deserialize_alpn", serialize_with = "serialize_alpn")]
	pub alpn: Vec<Vec<u8>>,

	#[educe(Default = false)]
	pub disable_sni: bool,

	#[educe(Default = None)]
	pub sni: Option<String>,

	#[educe(Default = false)]
	pub disable_native_certs: bool,

	#[educe(Default = false)]
	pub skip_cert_verify: bool,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct QuinnConfig {
	pub congestion_control: CongestionControlConfig,

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
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct CongestionControlConfig {
	#[educe(Default(expression = CongestionControl::Bbr))]
	pub controller: CongestionControl,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct BackendConfig {
	pub mode: BackendMode,
	pub quinn: QuinnConfig,
}

/// The client currently supports only the quinn backend.
#[derive(Debug, Clone, Copy, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendMode {
	#[default]
	Quinn,
}

impl From<ConfigFile> for Config {
	fn from(file: ConfigFile) -> Self {
		Self {
			local: file.local,
			log_level: file.log_level,
			relay: Relay {
				server: file.server,
				uuid: file.uuid,
				password: file.password,
				ip: file.ip,
				ipstack_prefer: file.ipstack_prefer,
				certificates: file.tls.certificates,
				udp_relay_mode: file.udp_relay_mode,
				congestion_control: file.backend.quinn.congestion_control.controller,
				alpn: file.tls.alpn,
				zero_rtt_handshake: file.zero_rtt_handshake,
				disable_sni: file.tls.disable_sni,
				sni: file.tls.sni,
				timeout: file.timeout,
				heartbeat: file.heartbeat,
				disable_native_certs: file.tls.disable_native_certs,
				send_window: file.backend.quinn.send_window,
				receive_window: file.backend.quinn.receive_window,
				initial_mtu: file.backend.quinn.initial_mtu,
				min_mtu: file.backend.quinn.min_mtu,
				gso: file.backend.quinn.gso,
				pmtu: file.backend.quinn.pmtu,
				gc_interval: file.gc_interval,
				gc_lifetime: file.gc_lifetime,
				skip_cert_verify: file.tls.skip_cert_verify,
				proxy: file.proxy,
				reconnect: file.reconnect,
				reconnect_initial_backoff: file.reconnect_initial_backoff,
				reconnect_max_backoff: file.reconnect_max_backoff,
				lazy: file.lazy,
			},
		}
	}
}

impl From<Config> for ConfigFile {
	fn from(config: Config) -> Self {
		let relay = config.relay;
		Self {
			local: config.local,
			log_level: config.log_level,
			server: relay.server,
			uuid: relay.uuid,
			password: relay.password,
			ip: relay.ip,
			ipstack_prefer: relay.ipstack_prefer,
			udp_relay_mode: relay.udp_relay_mode,
			zero_rtt_handshake: relay.zero_rtt_handshake,
			timeout: relay.timeout,
			heartbeat: relay.heartbeat,
			gc_interval: relay.gc_interval,
			gc_lifetime: relay.gc_lifetime,
			proxy: relay.proxy,
			reconnect: relay.reconnect,
			reconnect_initial_backoff: relay.reconnect_initial_backoff,
			reconnect_max_backoff: relay.reconnect_max_backoff,
			lazy: relay.lazy,
			tls: TlsConfig {
				certificates: relay.certificates,
				alpn: relay.alpn,
				disable_sni: relay.disable_sni,
				sni: relay.sni,
				disable_native_certs: relay.disable_native_certs,
				skip_cert_verify: relay.skip_cert_verify,
			},
			backend: BackendConfig {
				mode: BackendMode::Quinn,
				quinn: QuinnConfig {
					congestion_control: CongestionControlConfig {
						controller: relay.congestion_control,
					},
					send_window: relay.send_window,
					receive_window: relay.receive_window,
					initial_mtu: relay.initial_mtu,
					min_mtu: relay.min_mtu,
					gso: relay.gso,
					pmtu: relay.pmtu,
				},
			},
		}
	}
}

#[derive(Debug, Clone, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(into = "ConfigFile")]
pub struct Config {
	pub relay: Relay,

	pub local: Local,

	#[educe(Default = "info")]
	pub log_level: String,
}

impl<'de> Deserialize<'de> for Config {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let mut values = figment::value::Dict::deserialize(deserializer)?;
		migrate_relay(&mut values).map_err(D::Error::custom)?;
		Figment::from(Serialized::defaults(values))
			.extract::<ConfigFile>()
			.map(Config::from)
			.map_err(D::Error::custom)
	}
}

#[derive(Debug, Deserialize, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields, default)]
#[derive(Clone)]
pub struct Relay {
	#[serde(deserialize_with = "deserialize_server", serialize_with = "serialize_server")]
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
	#[serde(deserialize_with = "deserialize_alpn", serialize_with = "serialize_alpn")]
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

	/// Automatically reconnect to the relay after the connection drops.
	#[educe(Default = true)]
	pub reconnect: bool,

	/// Delay before the first reconnect attempt; doubled after each failure.
	#[educe(Default(expression = Duration::from_millis(500)))]
	#[serde(with = "humantime_serde")]
	pub reconnect_initial_backoff: Duration,

	/// Upper bound on the reconnect backoff delay.
	#[educe(Default(expression = Duration::from_secs(30)))]
	#[serde(with = "humantime_serde")]
	pub reconnect_max_backoff: Duration,

	/// Defer the QUIC connection establishment until the first actual
	/// traffic arrives.  When `false` (eager), the connection is
	/// established immediately at startup and the process exits on
	/// failure.  Defaults to `true` (matching v1.8.11 `startup_mode =
	/// "lazy"`).
	#[educe(Default = true)]
	#[serde(default)]
	pub lazy: bool,
}

#[derive(Debug, Deserialize, serde::Serialize, Educe, Clone, PartialEq, Eq)]
#[educe(Default)]
#[serde(deny_unknown_fields, default)]
pub struct ProxyConfig {
	#[serde(deserialize_with = "deserialize_server", serialize_with = "serialize_server")]
	#[educe(Default(expression = ("".to_string(), 0)))]
	pub server: (String, u16),

	#[educe(Default = None)]
	pub username: Option<String>,

	#[educe(Default = None)]
	pub password: Option<String>,

	#[educe(Default = 2048)]
	pub udp_buffer_size: usize,
}

#[derive(Debug, Deserialize, serde::Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields, default)]
#[derive(Clone)]
pub struct Local {
	#[educe(Default(expression = "127.0.0.1:1080".parse().unwrap()))]
	pub server: SocketAddr,

	#[educe(Default = None)]
	#[serde(
		deserialize_with = "deserialize_optional_bytes",
		serialize_with = "serialize_optional_bytes"
	)]
	pub username: Option<Vec<u8>>,

	#[educe(Default = None)]
	#[serde(
		deserialize_with = "deserialize_optional_bytes",
		serialize_with = "serialize_optional_bytes"
	)]
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
	#[serde(deserialize_with = "deserialize_server", serialize_with = "serialize_server")]
	pub remote: (String, u16),
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpForward {
	pub listen: SocketAddr,
	#[serde(deserialize_with = "deserialize_server", serialize_with = "serialize_server")]
	pub remote: (String, u16),
	#[serde(default = "default_udp_timeout", with = "humantime_serde")]
	pub timeout: Duration,
}

fn default_udp_timeout() -> Duration {
	Duration::from_secs(60)
}

impl Config {
	pub fn parse(cli: Cli, env_state: EnvState) -> eyre::Result<Self> {
		let path = cli.config.ok_or(ConfigError::NoConfig)?;

		if !path.exists() {
			bail!(ConfigError::ConfigNotFound(path));
		}

		let figmet = Figment::new();
		let format;

		if env_state.tuic_force_toml {
			format = ConfigFormat::Toml;
		} else if let Some(ref env_format) = env_state.tuic_config_format {
			match env_format.to_lowercase().as_str() {
				"json" | "json5" => format = ConfigFormat::Json,
				"yaml" | "yml" => format = ConfigFormat::Yaml,
				"toml" => format = ConfigFormat::Toml,
				_ => format = ConfigFormat::Unknown,
			}
		} else {
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
				let content = std::fs::read_to_string(&path)?;
				let inferred_format = infer_config_format(&content);

				match inferred_format {
					ConfigFormat::Json => figmet.merge(Json5::string(&content)),
					ConfigFormat::Toml => figmet.merge(Toml::string(&content)),
					ConfigFormat::Yaml => figmet.merge(Yaml::string(&content)),
					ConfigFormat::Unknown => Err(ConfigError::UnknownFormat)?,
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
	// Parse a mapping instead of guessing from ':' in host:port strings or
	// '[' in table headers. Modern minimal TOML has no section headers.
	if Figment::from(Json5::string(content))
		.extract::<figment::value::Dict>()
		.is_ok()
	{
		ConfigFormat::Json
	} else if Figment::from(Toml::string(content)).extract::<figment::value::Dict>().is_ok() {
		ConfigFormat::Toml
	} else if Figment::from(Yaml::string(content)).extract::<figment::value::Dict>().is_ok() {
		ConfigFormat::Yaml
	} else {
		ConfigFormat::Unknown
	}
}

/// Move explicitly supplied legacy fields before merging defaults, so modern
/// fields (including explicit default values) always take precedence.
fn migrate_relay(values: &mut figment::value::Dict) -> eyre::Result<()> {
	use figment::value::Value;
	let Some(legacy) = values.remove("relay") else {
		return Ok(());
	};
	let Value::Dict(_, legacy) = legacy else {
		bail!("relay must be a table");
	};
	// Validate the entire old section, including fields shadowed by modern
	// ones.
	let _: Relay = Figment::from(Serialized::defaults(legacy.clone())).extract()?;
	for (key, value) in legacy {
		let path: &[&str] = match key.as_str() {
			"certificates" | "alpn" | "disable_sni" | "sni" | "disable_native_certs" | "skip_cert_verify" => &["tls"],
			"congestion_control" => &["backend", "quinn", "congestion_control"],
			"send_window" | "receive_window" | "initial_mtu" | "min_mtu" | "gso" | "pmtu" => &["backend", "quinn"],
			_ => &[],
		};
		let mut target = &mut *values;
		for section in path {
			let entry = target
				.entry((*section).to_owned())
				.or_insert_with(|| Value::from(figment::value::Dict::new()));
			let Value::Dict(_, dict) = entry else {
				bail!("{section} must be a table");
			};
			target = dict;
		}
		let key = if key == "congestion_control" {
			"controller".to_owned()
		} else {
			key
		};
		match target.entry(key) {
			std::collections::btree_map::Entry::Vacant(entry) => {
				entry.insert(value);
			}
			std::collections::btree_map::Entry::Occupied(mut entry) => {
				// A partially migrated [proxy] inherits unspecified legacy
				// fields.
				if let (Value::Dict(_, modern), Value::Dict(_, legacy)) = (entry.get_mut(), value) {
					for (key, value) in legacy {
						modern.entry(key).or_insert(value);
					}
				}
			}
		}
	}
	tracing::warn!("The [relay] section is deprecated; use top-level connection fields, [tls] and [backend.quinn]");
	Ok(())
}

pub fn serialize_server<S: serde::Serializer>(server: &(String, u16), serializer: S) -> Result<S::Ok, S::Error> {
	let host = server.0.trim_start_matches('[').trim_end_matches(']');
	let address = if host.contains(':') {
		format!("[{host}]:{}", server.1)
	} else {
		format!("{host}:{}", server.1)
	};
	serializer.serialize_str(&address)
}

pub fn serialize_alpn<S: serde::Serializer>(alpn: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
	use serde::Serialize;
	alpn.iter()
		.map(|value| String::from_utf8_lossy(value))
		.collect::<Vec<_>>()
		.serialize(serializer)
}

pub fn serialize_optional_bytes<S: serde::Serializer>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> {
	use serde::Serialize;
	value
		.as_ref()
		.map(|bytes| String::from_utf8_lossy(bytes))
		.serialize(serializer)
}

pub fn deserialize_server<'de, D>(deserializer: D) -> Result<(String, u16), D::Error>
where
	D: Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;

	// Bracketed IPv6: "[host]:port" — the host may itself contain colons.
	if let Some(rest) = s.strip_prefix('[') {
		let (host, after) = rest
			.split_once(']')
			.ok_or_else(|| DeError::custom("unterminated '[' in IPv6 server address"))?;
		let port = after
			.strip_prefix(':')
			.ok_or_else(|| DeError::custom("expected ':port' after ']' in server address"))?;
		let port = port.parse().map_err(DeError::custom)?;
		return Ok((host.to_string(), port));
	}

	let (host, port) = s
		.rsplit_once(':')
		.ok_or_else(|| DeError::custom("server address must be 'host:port'"))?;
	// A leftover colon in the host means an unbracketed IPv6 literal, which is
	// ambiguous (`rsplit_once` would treat part of the address as the port).
	if host.contains(':') {
		return Err(DeError::custom("IPv6 server address must be bracketed as '[addr]:port'"));
	}
	let port = port.parse().map_err(DeError::custom)?;

	Ok((host.to_string(), port))
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
	#[error("configuration error: {0}")]
	Figment(#[from] figment::Error),
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn modern_and_legacy_layouts_are_equivalent() {
		let modern = test_parse_config(include_str!("../tests/config/toml_full_config.toml"), ".toml").unwrap();
		let legacy = test_parse_config(include_str!("../tests/config/legacy_full_config.toml"), ".toml").unwrap();
		assert_eq!(toml::to_string(&modern).unwrap(), toml::to_string(&legacy).unwrap());
	}

	#[test]
	fn modern_formats_and_headerless_toml_inference() {
		for content in [
			r#"server = "example.com:8443"
uuid = "00000000-0000-0000-0000-000000000000"
password = "test"
"#,
			r#"{server: "example.com:8443", password: "test", tls: {alpn: ["h3"]}, backend: {quinn: {congestion_control: {controller: "cubic"}}}}"#,
			"server: example.com:8443\npassword: test\ntls:\n  alpn: [h3]\nbackend:\n  quinn:\n    congestion_control:\n      \
			 controller: cubic\n",
		] {
			let config = test_parse_config(content, ".config").unwrap();
			assert_eq!(config.relay.server, ("example.com".into(), 8443));
			assert_eq!(&*config.relay.password, b"test");
			if !content.starts_with("server =") {
				assert_eq!(config.relay.alpn, vec![b"h3".to_vec()]);
				assert_eq!(config.relay.congestion_control, CongestionControl::Cubic);
			}
		}
	}

	#[test]
	fn modern_explicit_defaults_override_legacy_fields() {
		let config = test_parse_config(
			r#"
server = "modern.example:8443"
zero_rtt_handshake = false
[tls]
skip_cert_verify = false
alpn = []
[backend.quinn]
gso = true
[backend.quinn.congestion_control]
controller = "bbr"
[proxy]
username = "modern_user"
[relay]
server = "legacy.example:443"
zero_rtt_handshake = true
skip_cert_verify = true
alpn = ["h3"]
gso = false
congestion_control = "cubic"
heartbeat = "7s"
[relay.proxy]
server = "127.0.0.1:1080"
username = "legacy_user"
"#,
			".toml",
		)
		.unwrap();
		assert_eq!(config.relay.server.0, "modern.example");
		assert!(!config.relay.zero_rtt_handshake);
		assert!(!config.relay.skip_cert_verify);
		assert!(config.relay.alpn.is_empty());
		assert!(config.relay.gso);
		assert_eq!(config.relay.congestion_control, CongestionControl::Bbr);
		assert_eq!(config.relay.heartbeat, Duration::from_secs(7));
		let proxy = config.relay.proxy.unwrap();
		assert_eq!(proxy.server, ("127.0.0.1".into(), 1080));
		assert_eq!(proxy.username.as_deref(), Some("modern_user"));
	}

	#[test]
	fn rejects_invalid_sections_and_unknown_fields() {
		for content in [
			"typo = true",
			"[tls]\nskip_cert_verfy = true",
			"[backend]\nmode = 'quiche'",
			"[backend.quinn]\nsend_windw = 10",
			"[backend.quinn.congestion_control]\ncontroller = 'invalid'",
			"[relay]\ntypo = true",
			"relay = false",
			"tls = false\n[relay]\nalpn = ['h3']",
		] {
			assert!(test_parse_config(content, ".toml").is_err(), "accepted {content}");
		}
	}

	#[test]
	fn serialization_emits_modern_layout_and_roundtrips_values() {
		let mut config = test_parse_config(include_str!("../tests/config/all_relay_options_toml.toml"), ".toml").unwrap();
		config.relay.server = ("::1".into(), 8443);
		config.relay.proxy = Some(ProxyConfig {
			server: ("::1".into(), 1080),
			username: Some("proxy_user".into()),
			password: Some("proxy_password".into()),
			..Default::default()
		});
		config.local.tcp_forward.push(TcpForward {
			listen: "127.0.0.1:8080".parse().unwrap(),
			remote: ("::1".into(), 80),
		});
		config.local.udp_forward.push(UdpForward {
			listen: "127.0.0.1:5353".parse().unwrap(),
			remote: ("::1".into(), 53),
			timeout: Duration::from_secs(12),
		});
		let output = toml::to_string_pretty(&config).unwrap();
		assert!(!output.contains("[relay"));
		assert!(output.contains("[tls]"));
		assert!(output.contains("[backend.quinn.congestion_control]"));
		assert!(output.contains("[::1]:8443"));
		let reparsed: Config = toml::from_str(&output).unwrap();
		assert_eq!(output, toml::to_string_pretty(&reparsed).unwrap());
	}

	#[test]
	fn direct_serde_still_accepts_legacy_files() {
		let config: Config = toml::from_str(include_str!("../tests/config/legacy_full_config.toml")).unwrap();
		assert_eq!(config.relay.server.0, "example.com");
		assert_eq!(config.relay.alpn, vec![b"h3".to_vec(), b"h2".to_vec()]);
	}

	fn parse_server(s: &str) -> Result<(String, u16), serde::de::value::Error> {
		use serde::de::IntoDeserializer;
		deserialize_server(s.into_deserializer())
	}

	#[test]
	fn deserialize_server_handles_ipv6_domains_and_rejects_ambiguous() {
		assert_eq!(parse_server("example.com:443").unwrap(), ("example.com".to_string(), 443));
		assert_eq!(parse_server("1.2.3.4:8443").unwrap(), ("1.2.3.4".to_string(), 8443));
		assert_eq!(parse_server("[2001:db8::1]:443").unwrap(), ("2001:db8::1".to_string(), 443));
		assert_eq!(parse_server("[::1]:8443").unwrap(), ("::1".to_string(), 8443));

		// Unbracketed IPv6 is ambiguous and must be rejected rather than split
		// wrong.
		assert!(parse_server("2001:db8::1").is_err());
		assert!(parse_server("::1").is_err());
		// Missing port / malformed.
		assert!(parse_server("example.com").is_err());
		assert!(parse_server("[2001:db8::1]").is_err());
	}

	fn test_parse_config(config_content: &str, extension: &str) -> eyre::Result<Config> {
		test_parse_config_with_env(config_content, extension, EnvState::default())
	}

	fn test_parse_config_with_env(config_content: &str, extension: &str, env_state: EnvState) -> eyre::Result<Config> {
		use std::fs;

		use tempfile::tempdir;

		let temp_dir = tempdir().unwrap();

		let config_path = temp_dir.path().join(format!("config{}", extension));

		fs::write(&config_path, config_content).unwrap();

		let os_args = vec![
			"test_binary".to_owned(),
			"--config".to_owned(),
			config_path.to_string_lossy().into_owned(),
		];

		let cli = Cli::try_parse_from(os_args).map_err(|e| ConfigError::Figment(figment::Error::from(e.to_string())))?;

		Config::parse(cli, env_state)
	}
	#[test]
	fn test_backward_compatibility_standard_json() {
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
		let json5_config = include_str!("../tests/config/json5_comments.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with comments should be parseable");
	}

	#[test]
	fn test_json5_trailing_commas() {
		let json5_config = include_str!("../tests/config/json5_trailing_commas.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with trailing commas should be parseable");
	}

	#[test]
	fn test_json5_unquoted_keys() {
		let json5_config = include_str!("../tests/config/json5_unquoted_keys.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with unquoted keys should be parseable");
	}

	#[test]
	fn test_json5_single_quotes() {
		let json5_config = include_str!("../tests/config/json5_single_quotes.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with single quotes should be parseable");
	}

	#[test]
	fn test_json5_multiline_strings() {
		let json5_config = include_str!("../tests/config/json5_multiline_strings.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with multiline strings should be parseable");
	}

	#[test]
	fn test_json5_mixed_features() {
		let json5_config = include_str!("../tests/config/json5_mixed_features.json5");

		let config = test_parse_config(json5_config, ".json5");
		assert!(config.is_ok(), "JSON5 with mixed features should be parseable");

		let config = config.unwrap();
		assert_eq!(config.log_level, "info");
	}

	#[test]
	fn test_complex_config_with_all_fields() {
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
		// Reconnect defaults: enabled, 500ms initial backoff capped at 30s.
		assert!(config.relay.reconnect);
		assert_eq!(config.relay.reconnect_initial_backoff, Duration::from_millis(500));
		assert_eq!(config.relay.reconnect_max_backoff, Duration::from_secs(30));
		assert_eq!(config.local.max_packet_size, 1500);
	}

	#[test]
	fn test_reconnect_can_be_disabled_and_tuned() {
		// A config omitting reconnect keeps the defaults (backward compatible).
		let default_cfg = r#"{ "relay": { "server": "example.com:8443", "uuid": "00000000-0000-0000-0000-000000000000", "password": "pw" } }"#;
		let config = test_parse_config(default_cfg, ".json5").unwrap();
		assert!(config.relay.reconnect);

		// Explicit values are honoured, including disabling reconnect and
		// humantime-formatted backoff durations.
		let tuned = r#"{
			"relay": {
				"server": "example.com:8443",
				"uuid": "00000000-0000-0000-0000-000000000000",
				"password": "pw",
				"reconnect": false,
				"reconnect_initial_backoff": "2s",
				"reconnect_max_backoff": "1m"
			}
		}"#;
		let config = test_parse_config(tuned, ".json5").unwrap();
		assert!(!config.relay.reconnect);
		assert_eq!(config.relay.reconnect_initial_backoff, Duration::from_secs(2));
		assert_eq!(config.relay.reconnect_max_backoff, Duration::from_secs(60));
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
	fn test_proxy_config_json5() {
		let json5_config = include_str!("../tests/config/proxy_json5.json5");

		let config = test_parse_config(json5_config, ".json5").unwrap();
		let proxy = config.relay.proxy.unwrap();
		assert_eq!(proxy.server.0, "127.0.0.1");
		assert_eq!(proxy.server.1, 1080);
		assert_eq!(proxy.username.unwrap(), "proxy_user");
		assert_eq!(proxy.password.unwrap(), "proxy_pass");
		assert_eq!(proxy.udp_buffer_size, 4096);
	}

	#[test]
	fn test_proxy_config_yaml() {
		let yaml_config = include_str!("../tests/config/proxy_yaml.yaml");

		let config = test_parse_config(yaml_config, ".yaml").unwrap();
		let proxy = config.relay.proxy.unwrap();
		assert_eq!(proxy.server.0, "socks5.proxy.com");
		assert_eq!(proxy.server.1, 1080);
		assert_eq!(proxy.username.unwrap(), "yaml_user");
		assert_eq!(proxy.password.unwrap(), "yaml_pass");
		assert_eq!(proxy.udp_buffer_size, 8192);
	}

	#[test]
	fn test_proxy_minimal_config() {
		let toml_config = include_str!("../tests/config/proxy_minimal.toml");

		let config = test_parse_config(toml_config, ".toml").unwrap();
		let proxy = config.relay.proxy.unwrap();
		assert_eq!(proxy.server.0, "proxy.example.com");
		assert_eq!(proxy.server.1, 1080);
		assert!(proxy.username.is_none());
		assert!(proxy.password.is_none());
		assert_eq!(proxy.udp_buffer_size, 2048);
	}

	#[test]
	fn test_proxy_defaults() {
		let json5_config = include_str!("../tests/config/proxy_defaults.json5");

		let config = test_parse_config(json5_config, ".json5").unwrap();
		let proxy = config.relay.proxy.unwrap();
		assert_eq!(proxy.server.0, "127.0.0.1");
		assert_eq!(proxy.server.1, 1080);
		assert!(proxy.username.is_none());
		assert!(proxy.password.is_none());
		assert_eq!(proxy.udp_buffer_size, 2048);
	}

	#[test]
	fn test_no_proxy_config() {
		let toml_config = include_str!("../tests/config/no_proxy.toml");

		let config = test_parse_config(toml_config, ".toml").unwrap();
		assert!(config.relay.proxy.is_none());
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

		let env_state = EnvState {
			tuic_force_toml: true,
			tuic_config_format: None,
		};

		// Even with .json extension, should parse as TOML
		let config = test_parse_config_with_env(config_content, ".json", env_state).unwrap();
		assert_eq!(config.relay.server.0, "forced.example.com");
	}

	#[test]
	fn test_env_var_config_format() {
		let config_content = include_str!("../tests/config/env_yaml.toml");

		let env_state = EnvState {
			tuic_force_toml: false,
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
		let json5_content = include_str!("../tests/config/compat_json.json5");

		let json_config = test_parse_config(json5_content, ".json5").unwrap();

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
