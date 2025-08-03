use std::{
    collections::HashMap, fmt::Display, io::Error as IoError, net::SocketAddr, path::PathBuf,
    str::FromStr, time::Duration,
};

use humantime::Duration as HumanDuration;
use lexopt::Error as ArgumentError;
use serde::{Deserialize, Deserializer, de::Error as DeError};
use serde_json::Error as SerdeError;
use thiserror::Error;
use uuid::Uuid;

use crate::{config::LogLevel, utils::CongestionController};

pub const HELP_MSG: &str = r#"
Usage tuic-server [arguments]

Arguments:
    -c, --config <path>     Path to the config file (required)
    -v, --version           Print the version
    -h, --help              Print this help message
    -i, --init              Generate a example configuration (config.toml)
"#;

#[derive(Deserialize)]
pub struct OldConfig {
    pub server: SocketAddr,

    pub users: HashMap<Uuid, String>,

    #[serde(default = "default::self_sign")]
    pub self_sign: bool,

    #[serde(default = "default::certificate")]
    pub certificate: PathBuf,

    #[serde(default = "default::private_key")]
    pub private_key: PathBuf,

    #[serde(default = "default::auto_ssl")]
    pub auto_ssl: bool,

    #[serde(default = "default::hostname")]
    pub hostname: String,

    #[serde(
        default = "default::congestion_control",
        deserialize_with = "deserialize_from_str"
    )]
    pub congestion_control: CongestionController,

    #[serde(default = "default::alpn")]
    pub alpn: Vec<String>,

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

    pub log_level: Option<LogLevel>,

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

    pub restful_server: Option<SocketAddr>,
}

mod default {
    use std::{path::PathBuf, time::Duration};

    use crate::utils::CongestionController;

    pub fn congestion_control() -> CongestionController {
        CongestionController::Cubic
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

    pub fn certificate() -> PathBuf {
        PathBuf::new()
    }

    pub fn private_key() -> PathBuf {
        PathBuf::new()
    }

    pub fn auto_ssl() -> bool {
        false
    }

    pub fn hostname() -> String {
        "localhost".to_string()
    }

    pub fn self_sign() -> bool {
        false
    }

    pub fn alpn() -> Vec<String> {
        Vec::new()
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
