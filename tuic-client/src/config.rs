use std::{
	env::ArgsOs,
	fmt::Display,
	fs::File,
	io::{BufReader, Error as IoError},
	net::{IpAddr, SocketAddr},
	path::PathBuf,
	str::FromStr,
	sync::Arc,
	time::Duration,
};

use educe::Educe;
use figment::{
	Figment,
	providers::{Format, Toml},
};
use humantime::Duration as HumanDuration;
use json5::Error as Json5Error;
use lexopt::{Arg, Error as ArgumentError, Parser};
use serde::{Deserialize, Deserializer, de::Error as DeError};
use thiserror::Error;
use uuid::Uuid;

use crate::utils::{CongestionControl, StackPrefer, UdpRelayMode};

const HELP_MSG: &str = r#"
Usage tuic-client [arguments]

Arguments:
    -c, --config <path>     Path to the config file (required)
    -v, --version           Print the version
    -h, --help              Print this help message
"#;

#[derive(Deserialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
	pub relay: Relay,

	pub local: Local,

	#[educe(Default = "info")]
	pub log_level: String,
}

#[derive(Deserialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields, default)]
pub struct Relay {
	#[serde(deserialize_with = "deserialize_server")]
	pub server: (String, u16),

	#[educe(Default(expression = Uuid::nil()))]
	pub uuid: Uuid,

	#[serde(deserialize_with = "deserialize_password")]
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
}

#[derive(Deserialize, Educe)]
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

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpForward {
	pub listen: SocketAddr,
	#[serde(deserialize_with = "deserialize_server")]
	pub remote: (String, u16),
}

#[derive(Clone, Deserialize)]
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
	pub fn parse(args: ArgsOs) -> Result<Self, ConfigError> {
		let mut parser = Parser::from_iter(args);
		let mut path = None;

		while let Some(arg) = parser.next()? {
			match arg {
				Arg::Short('c') | Arg::Long("config") => {
					if path.is_none() {
						path = Some(PathBuf::from(parser.value()?));
					} else {
						return Err(ConfigError::Argument(arg.unexpected()));
					}
				}
				Arg::Short('v') | Arg::Long("version") => {
					return Err(ConfigError::Version(env!("CARGO_PKG_VERSION")));
				}
				Arg::Short('h') | Arg::Long("help") => return Err(ConfigError::Help(HELP_MSG)),
				_ => return Err(ConfigError::Argument(arg.unexpected())),
			}
		}

		if path.is_none() {
			return Err(ConfigError::NoConfig);
		}

		let path = path.unwrap();

		// Check file extension to determine format
		// TOML format: .toml extension or TUIC_FORCE_TOML env var
		// JSON format: everything else (for backward compatibility)
		let config: Config = if path.extension().is_some_and(|v| v == "toml") || std::env::var("TUIC_FORCE_TOML").is_ok() {
			// Parse as TOML using Figment
			Figment::new()
				.merge(Toml::file(&path))
				.extract()
				.map_err(|e| ConfigError::Io(IoError::other(e)))?
		} else {
			// Parse as JSON5 (legacy support)
			let file = File::open(&path)?;
			let reader = BufReader::new(file);
			let content = std::io::read_to_string(reader)?;
			json5::from_str(&content)?
		};

		Ok(config)
	}
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

	Ok((s, port))
}

pub fn deserialize_password<'de, D>(deserializer: D) -> Result<Arc<[u8]>, D::Error>
where
	D: Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	Ok(Arc::from(s.into_bytes().into_boxed_slice()))
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
	let s = String::deserialize(deserializer)?;
	Ok(Some(s.into_bytes()))
}

pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
	D: Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;

	s.parse::<HumanDuration>().map(|d| *d).map_err(DeError::custom)
}

#[derive(Debug, Error)]
pub enum ConfigError {
	#[error(transparent)]
	Argument(#[from] ArgumentError),
	#[error("no config file specified")]
	NoConfig,
	#[error("{0}")]
	Version(&'static str),
	#[error("{0}")]
	Help(&'static str),
	#[error(transparent)]
	Io(#[from] IoError),
	#[error(transparent)]
	Json5(#[from] Json5Error),
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_backward_compatibility_standard_json() {
		// Test backward compatibility with standard JSON format
		let json_config = r#"
        {
            "relay": {
                "server": "example.com:8443",
                "uuid": "00000000-0000-0000-0000-000000000000",
                "password": "test_password"
            },
            "local": {
                "server": "127.0.0.1:1080"
            },
            "log_level": "info"
        }
        "#;

		let config: Result<Config, _> = json5::from_str(json_config);
		assert!(config.is_ok(), "Standard JSON should be parseable by JSON5");

		let config = config.unwrap();
		assert_eq!(config.log_level, "info");
		assert_eq!(config.relay.server.0, "example.com");
		assert_eq!(config.relay.server.1, 8443);
	}

	#[test]
	fn test_json5_comments() {
		// Test JSON5 comment support (single-line and multi-line)
		let json5_config = r#"
        {
            // This is a single-line comment
            "relay": {
                "server": "example.com:8443",
                "uuid": "00000000-0000-0000-0000-000000000000",
                /* This is a multi-line comment
                   spanning multiple lines */
                "password": "test_password"
            },
            "local": {
                "server": "127.0.0.1:1080"
            },
            "log_level": "info" // End-of-line comment
        }
        "#;

		let config: Result<Config, _> = json5::from_str(json5_config);
		assert!(config.is_ok(), "JSON5 with comments should be parseable");
	}

	#[test]
	fn test_json5_trailing_commas() {
		// Test JSON5 trailing comma support
		let json5_config = r#"
        {
            "relay": {
                "server": "example.com:8443",
                "uuid": "00000000-0000-0000-0000-000000000000",
                "password": "test_password",
            },
            "local": {
                "server": "127.0.0.1:1080",
            },
            "log_level": "info",
        }
        "#;

		let config: Result<Config, _> = json5::from_str(json5_config);
		assert!(config.is_ok(), "JSON5 with trailing commas should be parseable");
	}

	#[test]
	fn test_json5_unquoted_keys() {
		// Test JSON5 unquoted object keys
		let json5_config = r#"
        {
            relay: {
                server: "example.com:8443",
                uuid: "00000000-0000-0000-0000-000000000000",
                password: "test_password"
            },
            local: {
                server: "127.0.0.1:1080"
            },
            log_level: "info"
        }
        "#;

		let config: Result<Config, _> = json5::from_str(json5_config);
		assert!(config.is_ok(), "JSON5 with unquoted keys should be parseable");
	}

	#[test]
	fn test_json5_single_quotes() {
		// Test JSON5 single-quoted strings
		let json5_config = r#"
        {
            'relay': {
                'server': 'example.com:8443',
                'uuid': '00000000-0000-0000-0000-000000000000',
                'password': 'test_password'
            },
            'local': {
                'server': '127.0.0.1:1080'
            },
            'log_level': 'info'
        }
        "#;

		let config: Result<Config, _> = json5::from_str(json5_config);
		assert!(config.is_ok(), "JSON5 with single quotes should be parseable");
	}

	#[test]
	fn test_json5_multiline_strings() {
		// Test JSON5 multiline strings with escaped newlines
		let json5_config = r#"
        {
            "relay": {
                "server": "example.com:8443",
                "uuid": "00000000-0000-0000-0000-000000000000",
                "password": "test_\
password"
            },
            "local": {
                "server": "127.0.0.1:1080"
            },
            "log_level": "info"
        }
        "#;

		let config: Result<Config, _> = json5::from_str(json5_config);
		assert!(config.is_ok(), "JSON5 with multiline strings should be parseable");
	}

	#[test]
	fn test_json5_mixed_features() {
		// Test multiple JSON5 features combined
		let json5_config = r#"
        {
            // Client relay configuration
            relay: {
                server: 'example.com:8443',
                uuid: '00000000-0000-0000-0000-000000000000',
                password: 'test_password',
                /* Optional settings */
                udp_relay_mode: 'native',
                congestion_control: 'cubic',
            },
            // Local server configuration
            local: {
                server: '127.0.0.1:1080',
            },
            log_level: 'info', // Set logging level
        }
        "#;

		let config: Result<Config, _> = json5::from_str(json5_config);
		assert!(config.is_ok(), "JSON5 with mixed features should be parseable");

		let config = config.unwrap();
		assert_eq!(config.log_level, "info");
	}

	#[test]
	fn test_complex_config_with_all_fields() {
		// Test a more complete configuration with various optional fields
		let json5_config = r#"
        {
            relay: {
                server: 'test.example.com:8443',
                uuid: '12345678-1234-5678-1234-567812345678',
                password: 'secure_password_123',
                udp_relay_mode: 'quic',
                congestion_control: 'bbr',
                zero_rtt_handshake: true,
                alpn: ['h3', 'h2'],
                ipstack_prefer: 'v6',
            },
            local: {
                server: '[::1]:9090',
                dual_stack: false,
            },
            log_level: 'debug',
        }
        "#;

		let config: Result<Config, _> = json5::from_str(json5_config);
		assert!(config.is_ok(), "Complex JSON5 config should be parseable");

		let config = config.unwrap();
		assert_eq!(config.log_level, "debug");
		assert_eq!(config.relay.zero_rtt_handshake, true);
	}

	#[test]
	fn test_default_values() {
		let json5_config = r#"
        {
            relay: {
                server: 'example.com:443',
                uuid: '00000000-0000-0000-0000-000000000000',
                password: 'password'
            },
            local: {
                server: '127.0.0.1:1080'
            }
        }
        "#;

		let config: Config = json5::from_str(json5_config).unwrap();

		// Check default values
		assert_eq!(config.log_level, "info");
		assert_eq!(config.relay.ipstack_prefer, StackPrefer::V4first);
		assert_eq!(config.relay.udp_relay_mode, UdpRelayMode::Native);
		assert_eq!(config.relay.congestion_control, CongestionControl::Bbr);
		assert_eq!(config.relay.zero_rtt_handshake, false);
		assert_eq!(config.relay.disable_sni, false);
		assert_eq!(config.relay.timeout, Duration::from_secs(8));
		assert_eq!(config.relay.heartbeat, Duration::from_secs(3));
		assert_eq!(config.relay.disable_native_certs, false);
		assert_eq!(config.relay.send_window, 16 * 1024 * 1024);
		assert_eq!(config.relay.receive_window, 8 * 1024 * 1024);
		assert_eq!(config.relay.initial_mtu, 1200);
		assert_eq!(config.relay.min_mtu, 1200);
		assert_eq!(config.relay.gso, true);
		assert_eq!(config.relay.pmtu, true);
		assert_eq!(config.relay.gc_interval, Duration::from_secs(3));
		assert_eq!(config.relay.gc_lifetime, Duration::from_secs(15));
		assert_eq!(config.relay.skip_cert_verify, false);
		assert_eq!(config.local.max_packet_size, 1500);
	}

	#[test]
	fn test_tcp_udp_forward() {
		let json5_config = r#"
        {
            relay: {
                server: 'example.com:443',
                uuid: '00000000-0000-0000-0000-000000000000',
                password: 'password'
            },
            local: {
                server: '127.0.0.1:1080',
                tcp_forward: [
                    { listen: '127.0.0.1:8080', remote: 'google.com:80' },
                    { listen: '127.0.0.1:8443', remote: 'example.com:443' }
                ],
                udp_forward: [
                    { listen: '127.0.0.1:5353', remote: '8.8.8.8:53', timeout: '10s' }
                ]
            }
        }
        "#;

		let config: Config = json5::from_str(json5_config).unwrap();

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
		let json5_config = r#"
        {
            relay: {
                server: 'example.com:443',
                uuid: 'not-a-valid-uuid',
                password: 'password'
            },
            local: {
                server: '127.0.0.1:1080'
            }
        }
        "#;

		let config: Result<Config, _> = json5::from_str(json5_config);
		assert!(config.is_err());
	}

	#[test]
	fn test_invalid_socket_addr() {
		let json5_config = r#"
        {
            relay: {
                server: 'example.com:443',
                uuid: '00000000-0000-0000-0000-000000000000',
                password: 'password'
            },
            local: {
                server: 'not-a-valid-address'
            }
        }
        "#;

		let config: Result<Config, _> = json5::from_str(json5_config);
		assert!(config.is_err());
	}

	#[test]
	fn test_alpn_configuration() {
		let json5_config = r#"
        {
            relay: {
                server: 'example.com:443',
                uuid: '00000000-0000-0000-0000-000000000000',
                password: 'password',
                alpn: ['h3', 'h2', 'http/1.1']
            },
            local: {
                server: '127.0.0.1:1080'
            }
        }
        "#;

		let config: Config = json5::from_str(json5_config).unwrap();
		assert_eq!(config.relay.alpn.len(), 3);
		assert_eq!(config.relay.alpn[0], b"h3".to_vec());
		assert_eq!(config.relay.alpn[1], b"h2".to_vec());
		assert_eq!(config.relay.alpn[2], b"http/1.1".to_vec());
	}

	#[test]
	fn test_ipv6_server_address() {
		let json5_config = r#"
        {
            relay: {
                server: 'example.com:443',
                uuid: '00000000-0000-0000-0000-000000000000',
                password: 'password'
            },
            local: {
                server: '[::1]:1080'
            }
        }
        "#;

		let config: Config = json5::from_str(json5_config).unwrap();
		assert!(config.local.server.is_ipv6());
		assert_eq!(config.local.server.to_string(), "[::1]:1080");
	}

	#[test]
	fn test_socks5_authentication() {
		let json5_config = r#"
        {
            relay: {
                server: 'example.com:443',
                uuid: '00000000-0000-0000-0000-000000000000',
                password: 'relay_password'
            },
            local: {
                server: '127.0.0.1:1080',
                username: 'socks_user',
                password: 'socks_pass'
            }
        }
        "#;

		let config: Config = json5::from_str(json5_config).unwrap();
		assert!(config.local.username.is_some());
		assert!(config.local.password.is_some());
		assert_eq!(config.local.username.as_ref().unwrap(), b"socks_user");
		assert_eq!(config.local.password.as_ref().unwrap(), b"socks_pass");
	}

	#[test]
	fn test_toml_basic_config() {
		let toml_config = r#"
            log_level = "info"

            [relay]
            server = "example.com:443"
            uuid = "00000000-0000-0000-0000-000000000000"
            password = "test_password"

            [local]
            server = "127.0.0.1:1080"
        "#;

		let config: Config = Figment::new().merge(Toml::string(toml_config)).extract().unwrap();

		assert_eq!(config.log_level, "info");
		assert_eq!(config.relay.server.0, "example.com");
		assert_eq!(config.relay.server.1, 443);
		assert_eq!(config.local.server.to_string(), "127.0.0.1:1080");
	}

	#[test]
	fn test_toml_with_defaults() {
		let toml_config = r#"
            [relay]
            server = "example.com:443"
            uuid = "00000000-0000-0000-0000-000000000000"
            password = "test_password"

            [local]
            server = "127.0.0.1:1080"
        "#;

		let config: Config = Figment::new().merge(Toml::string(toml_config)).extract().unwrap();

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
		let toml_config = r#"
            log_level = "debug"

            [relay]
            server = "example.com:8443"
            uuid = "12345678-1234-1234-1234-123456789012"
            password = "secure_password"
            ipstack_prefer = "v6v4"
            udp_relay_mode = "quic"
            congestion_control = "bbr"
            alpn = ["h3", "h2"]
            zero_rtt_handshake = true
            disable_sni = true
            timeout = "10s"
            heartbeat = "5s"
            send_window = 32777216
            receive_window = 16388608
            initial_mtu = 1400
            min_mtu = 1300
            gso = false
            pmtu = false
            gc_interval = "5s"
            gc_lifetime = "20s"

            [local]
            server = "[::1]:1080"
            dual_stack = false
            max_packet_size = 2000
        "#;

		let config: Config = Figment::new().merge(Toml::string(toml_config)).extract().unwrap();

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
		let toml_config = r#"
            [relay]
            server = "example.com:443"
            uuid = "00000000-0000-0000-0000-000000000000"
            password = "test_password"

            [local]
            server = "127.0.0.1:1080"

            [[local.tcp_forward]]
            listen = "127.0.0.1:8080"
            remote = "example.com:80"

            [[local.udp_forward]]
            listen = "127.0.0.1:5353"
            remote = "8.8.8.8:53"
            timeout = "30s"
        "#;

		let config: Config = Figment::new().merge(Toml::string(toml_config)).extract().unwrap();

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
}
