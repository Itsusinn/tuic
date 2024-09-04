use std::{
    collections::HashMap,
    env::ArgsOs,
    fmt::Display,
    fs::File,
    io::{BufReader, Error as IoError},
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use humantime::Duration as HumanDuration;
use json_comments::StripComments;
use lexopt::{Arg, Error as ArgumentError, Parser};
use log::LevelFilter;
use serde::{de::Error as DeError, Deserialize, Deserializer};
use serde_json::Error as SerdeError;
use thiserror::Error;
use uuid::Uuid;

use crate::utils::CongestionControl;

const HELP_MSG: &str = r#"
Usage tuic-server [arguments]

Arguments:
    -c, --config <path>     Path to the config file (required)
    -v, --version           Print the version
    -h, --help              Print this help message
"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: SocketAddr,

    #[serde(deserialize_with = "deserialize_users")]
    pub users: HashMap<Uuid, Box<[u8]>>,

    #[serde(default = "default::self_sign")]
    pub self_sign: bool,

    #[serde(default = "default::certificate")]
    pub certificate: PathBuf,

    #[serde(default = "default::private_key")]
    pub private_key: PathBuf,

    #[serde(
        default = "default::congestion_control",
        deserialize_with = "deserialize_from_str"
    )]
    pub congestion_control: CongestionControl,

    #[serde(default = "default::alpn", deserialize_with = "deserialize_alpn")]
    pub alpn: Vec<Vec<u8>>,

    #[serde(default = "default::udp_relay_ipv6")]
    pub udp_relay_ipv6: bool,

    #[serde(default = "default::zero_rtt_handshake")]
    pub zero_rtt_handshake: bool,

    pub dual_stack: Option<bool>,

    #[serde(
        default = "default::auth_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub auth_timeout: Duration,

    #[serde(
        default = "default::task_negotiation_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub task_negotiation_timeout: Duration,

    #[serde(
        default = "default::max_idle_time",
        deserialize_with = "deserialize_duration"
    )]
    pub max_idle_time: Duration,

    #[serde(default = "default::max_external_packet_size")]
    pub max_external_packet_size: usize,

    #[serde(default = "default::initial_window")]
    pub initial_window: Option<u64>,

    #[serde(default = "default::send_window")]
    pub send_window: u64,

    #[serde(default = "default::receive_window")]
    pub receive_window: u32,

    #[serde(default = "default::initial_mtu")]
    pub initial_mtu: u16,

    #[serde(default = "default::min_mtu")]
    pub min_mtu: u16,

    #[serde(default = "default::gso")]
    pub gso: bool,

    #[serde(default = "default::pmtu")]
    pub pmtu: bool,

    #[serde(
        default = "default::gc_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_interval: Duration,

    #[serde(
        default = "default::gc_lifetime",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_lifetime: Duration,

    #[serde(default = "default::log_level")]
    pub log_level: LevelFilter,
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
        let stripped = StripComments::new(reader);
        Ok(serde_json::from_reader(stripped)?)
    }
}

mod default {
    use std::{path::PathBuf, time::Duration};

    use log::LevelFilter;

    use crate::utils::CongestionControl;

    pub fn congestion_control() -> CongestionControl {
        CongestionControl::Cubic
    }

    pub fn alpn() -> Vec<Vec<u8>> {
        Vec::new()
    }

    pub fn udp_relay_ipv6() -> bool {
        true
    }

    pub fn zero_rtt_handshake() -> bool {
        false
    }

    pub fn auth_timeout() -> Duration {
        Duration::from_secs(3)
    }

    pub fn task_negotiation_timeout() -> Duration {
        Duration::from_secs(3)
    }

    pub fn max_idle_time() -> Duration {
        Duration::from_secs(10)
    }

    pub fn max_external_packet_size() -> usize {
        1500
    }

    pub fn initial_window() -> Option<u64> {
        None
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

    pub fn log_level() -> LevelFilter {
        LevelFilter::Warn
    }

    pub fn certificate() -> PathBuf {
        PathBuf::new()
    }

    pub fn private_key() -> PathBuf {
        PathBuf::new()
    }

    pub fn self_sign() -> bool {
        false
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

pub fn deserialize_users<'de, D>(deserializer: D) -> Result<HashMap<Uuid, Box<[u8]>>, D::Error>
where
    D: Deserializer<'de>,
{
    let users = HashMap::<Uuid, String>::deserialize(deserializer)?;

    if users.is_empty() {
        return Err(DeError::custom("users cannot be empty"));
    }

    Ok(users
        .into_iter()
        .map(|(k, v)| (k, v.into_bytes().into_boxed_slice()))
        .collect())
}

pub fn deserialize_alpn<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Vec::<String>::deserialize(deserializer)?;
    Ok(s.into_iter().map(|alpn| alpn.into_bytes()).collect())
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
    Serde(#[from] SerdeError),
}
