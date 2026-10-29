use std::{
	collections::HashMap,
	net::{Ipv4Addr, SocketAddr},
};

use tuic_server::{Config, config::ExperimentalConfig};
use tuic_tests::TempDataDir;

pub fn any_loopback_addr() -> SocketAddr {
	SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

pub fn build_minimal_server_config() -> (Config, TempDataDir) {
	let data_dir = TempDataDir::new("tuic-graceful-shutdown");
	(
		Config {
			server: any_loopback_addr(),
			users: HashMap::new(),
			tls: tuic_server::config::TlsConfig {
				self_sign: true,
				hostname: "localhost".to_string(),
				alpn: vec!["h3".to_string()],
				..Default::default()
			},
			data_dir: data_dir.path().to_path_buf(),
			..Default::default()
		},
		data_dir,
	)
}

pub fn build_server_config_with_user(uuid: uuid::Uuid, password: &str) -> (Config, TempDataDir) {
	let mut users = HashMap::new();
	users.insert(uuid, password.to_string());
	let data_dir = TempDataDir::new("tuic-graceful-shutdown");
	(
		Config {
			server: any_loopback_addr(),
			users,
			tls: tuic_server::config::TlsConfig {
				self_sign: true,
				hostname: "localhost".to_string(),
				alpn: vec!["h3".to_string()],
				..Default::default()
			},
			data_dir: data_dir.path().to_path_buf(),
			// The traffic test relays to a loopback echo server, so the loopback
			// guards must be off or the relay target is rejected before it ever
			// reaches the outbound (this used to make the test pass with zero
			// traffic actually flowing).
			experimental: ExperimentalConfig {
				drop_loopback: false,
				drop_private: false,
			},
			..Default::default()
		},
		data_dir,
	)
}
