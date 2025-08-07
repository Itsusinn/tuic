use std::{collections::HashMap, env::ArgsOs, net::SocketAddr, path::PathBuf, time::Duration};

use educe::Educe;
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use lexopt::{Arg, Parser};
use serde::{Deserialize, Serialize};
use tracing::{level_filters::LevelFilter, warn};
use uuid::Uuid;

use crate::{
    old_config::{ConfigError, OldConfig},
    utils::CongestionController,
};

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub log_level: LogLevel,
    #[educe(Default(expression = "[::]:443".parse().unwrap()))]
    pub server: SocketAddr,
    pub users: HashMap<Uuid, String>,
    pub tls: TlsConfig,

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
    #[educe(Default(expression = Duration::from_millis(3000)))]
    pub auth_timeout: Duration,

    #[serde(with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_millis(3000)))]
    pub task_negotiation_timeout: Duration,

    #[serde(with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_millis(3000)))]
    pub gc_interval: Duration,

    #[serde(alias = "gc_lifetime", with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_millis(15000)))]
    pub gc_lifetime: Duration,

    #[educe(Default = 1500)]
    pub max_external_packet_size: usize,

    #[serde(with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_millis(60000)))]
    pub stream_timeout: Duration,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub self_sign: bool,
    #[educe(Default(expression = PathBuf::from("PATH/TO/CERT")))]
    pub certificate: PathBuf,
    #[educe(Default(expression = PathBuf::from("PATH/TO/KEY")))]
    pub private_key: PathBuf,
    #[educe(Default(expression = Vec::new()))]
    pub alpn: Vec<String>,
    #[educe(Default(expression = "localhost"))]
    pub hostname: String,
    #[educe(Default(expression = false))]
    pub auto_ssl: bool,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
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
    #[educe(Default(expression = Duration::from_millis(10000)))]
    pub max_idle_time: Duration,
}
#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct CongestionControlConfig {
    pub controller: CongestionController,
    #[educe(Default = 1048576)]
    pub initial_window: u64,
}

#[derive(Deserialize, Serialize, Educe, Clone)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct RestfulConfig {
    #[educe(Default(expression = "127.0.0.1:8443".parse().unwrap()))]
    pub addr: SocketAddr,
    #[educe(Default = "YOUR_SECRET_HERE")]
    pub secret: String,
    #[educe(Default = 0)]
    pub maximum_clients_per_user: u64,
}

impl Config {
    pub fn full_example() -> Self {
        Self {
            users: {
                let mut users = HashMap::new();
                users.insert(Uuid::new_v4(), "YOUR_USER_PASSWD_HERE".into());
                users
            },
            restful: Some(RestfulConfig::default()),
            ..Default::default()
        }
    }
}

/// TODO remove in 2.0.0
impl From<OldConfig> for Config {
    fn from(value: OldConfig) -> Self {
        Self {
            server: value.server,
            users: value.users,
            tls: TlsConfig {
                self_sign: value.self_sign,
                certificate: value.certificate,
                private_key: value.private_key,
                alpn: value.alpn,
                auto_ssl: value.auto_ssl,
                hostname: value.hostname,
            },
            udp_relay_ipv6: value.udp_relay_ipv6,
            zero_rtt_handshake: value.zero_rtt_handshake,
            dual_stack: value.dual_stack.unwrap_or(true),
            auth_timeout: value.auth_timeout,
            task_negotiation_timeout: value.task_negotiation_timeout,
            gc_interval: value.gc_interval,
            gc_lifetime: value.gc_lifetime,
            max_external_packet_size: value.max_external_packet_size,
            restful: if value.restful_server.is_some() {
                Some(RestfulConfig {
                    addr: value.restful_server.unwrap(),
                    ..Default::default()
                })
            } else {
                None
            },
            log_level: value.log_level.unwrap_or_default(),
            quic: QuicConfig {
                congestion_control: CongestionControlConfig {
                    controller: value.congestion_control,
                    initial_window: value.initial_window.unwrap_or(1048576),
                },
                initial_mtu: value.initial_mtu,
                min_mtu: value.min_mtu,
                gso: value.gso,
                pmtu: value.pmtu,
                send_window: value.send_window,
                receive_window: value.receive_window,
                max_idle_time: value.max_idle_time,
            },
            ..Default::default()
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
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

pub async fn parse_config(args: ArgsOs) -> Result<Config, ConfigError> {
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
            Arg::Short('h') | Arg::Long("help") => {
                return Err(ConfigError::Help(crate::old_config::HELP_MSG));
            }
            Arg::Short('i') | Arg::Long("init") => {
                warn!("Generating a example configuration to config.toml......");
                let example = Config::full_example();
                let example = toml::to_string_pretty(&example).unwrap();
                tokio::fs::write("config.toml", example).await?;
                return Err(ConfigError::Help("Done")); // TODO refactor
            }
            _ => return Err(ConfigError::Argument(arg.unexpected())),
        }
    }

    if path.is_none() {
        return Err(ConfigError::NoConfig);
    }
    let path_buf = path.unwrap();
    let path = path_buf.to_string_lossy().to_string();
    let mut config: Config = if path.ends_with(".toml") || std::env::var("TUIC_FORCE_TOML").is_ok()
    {
        Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file(&path))
            .extract()
            .unwrap()
    } else {
        let config_text = tokio::fs::read(&path).await?;
        let config: OldConfig = serde_json::from_slice(&config_text)?;
        config.into()
    };

    if config.data_dir.to_str() == Some("") {
        config.data_dir = PathBuf::from(&path);
    } else {
        tokio::fs::create_dir_all(&config.data_dir).await?;
    };
    Ok(config)
}
