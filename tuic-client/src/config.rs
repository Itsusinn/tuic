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

use humantime::Duration as HumanDuration;
use lexopt::{Arg, Error as ArgumentError, Parser};
use serde::{Deserialize, Deserializer, de::Error as DeError};
use json5::Error as Json5Error;
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub relay: Relay,

    pub local: Local,

    #[serde(default = "default::log_level")]
    pub log_level: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    #[serde(deserialize_with = "deserialize_server")]
    pub server: (String, u16),

    pub uuid: Uuid,

    #[serde(deserialize_with = "deserialize_password")]
    pub password: Arc<[u8]>,

    pub ip: Option<IpAddr>,

    #[serde(
        default = "default::relay::ipstack_prefer",
        deserialize_with = "deserialize_from_str"
    )]
    pub ipstack_prefer: StackPrefer,

    #[serde(default = "default::relay::certificates")]
    pub certificates: Vec<PathBuf>,

    #[serde(
        default = "default::relay::udp_relay_mode",
        deserialize_with = "deserialize_from_str"
    )]
    pub udp_relay_mode: UdpRelayMode,

    #[serde(
        default = "default::relay::congestion_control",
        deserialize_with = "deserialize_from_str"
    )]
    pub congestion_control: CongestionControl,

    #[serde(
        default = "default::relay::alpn",
        deserialize_with = "deserialize_alpn"
    )]
    pub alpn: Vec<Vec<u8>>,

    #[serde(default = "default::relay::zero_rtt_handshake")]
    pub zero_rtt_handshake: bool,

    #[serde(default = "default::relay::disable_sni")]
    pub disable_sni: bool,

    #[serde(
        default = "default::relay::timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub timeout: Duration,

    #[serde(
        default = "default::relay::heartbeat",
        deserialize_with = "deserialize_duration"
    )]
    pub heartbeat: Duration,

    #[serde(default = "default::relay::disable_native_certs")]
    pub disable_native_certs: bool,

    #[serde(default = "default::relay::send_window")]
    pub send_window: u64,

    #[serde(default = "default::relay::receive_window")]
    pub receive_window: u32,

    #[serde(default = "default::relay::initial_mtu")]
    pub initial_mtu: u16,

    #[serde(default = "default::relay::min_mtu")]
    pub min_mtu: u16,

    #[serde(default = "default::relay::gso")]
    pub gso: bool,

    #[serde(default = "default::relay::pmtu")]
    pub pmtu: bool,

    #[serde(
        default = "default::relay::gc_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_interval: Duration,

    #[serde(
        default = "default::relay::gc_lifetime",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_lifetime: Duration,

    #[serde(default = "default::relay::skip_cert_verify")]
    pub skip_cert_verify: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Local {
    pub server: SocketAddr,

    #[serde(deserialize_with = "deserialize_optional_bytes", default)]
    pub username: Option<Vec<u8>>,

    #[serde(deserialize_with = "deserialize_optional_bytes", default)]
    pub password: Option<Vec<u8>>,

    pub dual_stack: Option<bool>,

    #[serde(default = "default::local::max_packet_size")]
    pub max_packet_size: usize,

    #[serde(default)]
    pub tcp_forward: Vec<TcpForward>,

    #[serde(default)]
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
    pub listen: SocketAddr,
    #[serde(deserialize_with = "deserialize_server")]
    pub remote: (String, u16),
    #[serde(
        default = "default::forward::udp_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub timeout: Duration,
}

impl Config {
    pub fn parse(args: ArgsOs) -> Result<Self, ConfigError> {
        let mut parser = Parser::from_iter(args);
        let mut path = None;

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('c') | Arg::Long("config") => {
                    if path.is_none() {
                        path = Some(parser.value()?);
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

        let file = File::open(path.unwrap())?;
        let reader = BufReader::new(file);
        let content = std::io::read_to_string(reader)?;
        Ok(json5::from_str(&content)?)
    }
}

mod default {

    pub mod relay {
        use std::{path::PathBuf, time::Duration};

        use crate::utils::{CongestionControl, StackPrefer, UdpRelayMode};
        pub fn ipstack_prefer() -> StackPrefer {
            StackPrefer::V4first
        }

        pub fn certificates() -> Vec<PathBuf> {
            Vec::new()
        }

        pub fn udp_relay_mode() -> UdpRelayMode {
            UdpRelayMode::Native
        }

        pub fn congestion_control() -> CongestionControl {
            CongestionControl::Cubic
        }

        pub fn alpn() -> Vec<Vec<u8>> {
            Vec::new()
        }

        pub fn zero_rtt_handshake() -> bool {
            false
        }

        pub fn disable_sni() -> bool {
            false
        }

        pub fn timeout() -> Duration {
            Duration::from_secs(8)
        }

        pub fn heartbeat() -> Duration {
            Duration::from_secs(3)
        }

        pub fn disable_native_certs() -> bool {
            false
        }

        pub fn send_window() -> u64 {
            8 * 1024 * 1024 * 2
        }

        pub fn receive_window() -> u32 {
            8 * 1024 * 1024
        }

        // struct.TransportConfig#method.initial_mtu
        pub fn initial_mtu() -> u16 {
            1200
        }

        // struct.TransportConfig#method.min_mtu
        pub fn min_mtu() -> u16 {
            1200
        }

        // struct.TransportConfig#method.enable_segmentation_offload
        // aka. Generic Segmentation Offload
        pub fn gso() -> bool {
            true
        }

        // struct.TransportConfig#method.mtu_discovery_config
        // if not pmtu() -> mtu_discovery_config(None)
        pub fn pmtu() -> bool {
            true
        }

        pub fn gc_interval() -> Duration {
            Duration::from_secs(3)
        }

        pub fn gc_lifetime() -> Duration {
            Duration::from_secs(15)
        }

        pub fn skip_cert_verify() -> bool {
            false
        }
    }

    pub mod local {
        pub fn max_packet_size() -> usize {
            1500
        }
    }

    pub mod forward {
        use std::time::Duration;
        pub fn udp_timeout() -> Duration {
            Duration::from_secs(60)
        }
    }

    pub fn log_level() -> String {
        "info".into()
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

    let (domain, port) = s
        .rsplit_once(':')
        .ok_or(DeError::custom("invalid server address"))?;

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

    s.parse::<HumanDuration>()
        .map(|d| *d)
        .map_err(DeError::custom)
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
}
