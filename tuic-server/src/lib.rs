// Library interface for tuic-server
// This allows the server to be used as a library in integration tests

use std::{
	collections::{HashMap, HashSet},
	sync::{Arc, atomic::AtomicUsize},
};

use chashmap::CHashMap;
use uuid::Uuid;

pub mod acl;
pub mod compat;
pub mod config;
pub mod connection;
pub mod error;
pub mod io;
pub mod old_config;
pub mod restful;
pub mod server;
pub mod tls;
pub mod utils;

pub use config::Config;

pub struct AppContext {
	pub cfg:            Config,
	pub online_counter: HashMap<Uuid, AtomicUsize>,
	pub online_clients: CHashMap<Uuid, HashSet<compat::QuicClient>>,
	pub traffic_stats:  HashMap<Uuid, (AtomicUsize, AtomicUsize)>,
}

/// Run the TUIC server with the given configuration
pub async fn run(cfg: Config) -> eyre::Result<()> {
	let mut online_counter = HashMap::new();
	for (user, _) in cfg.users.iter() {
		online_counter.insert(user.to_owned(), AtomicUsize::new(0));
	}

	let mut traffic_stats = HashMap::new();
	for (user, _) in cfg.users.iter() {
		traffic_stats.insert(user.to_owned(), (AtomicUsize::new(0), AtomicUsize::new(0)));
	}

	let ctx = Arc::new(AppContext {
		cfg,
		online_counter,
		online_clients: CHashMap::new(),
		traffic_stats,
	});

	match server::Server::init(ctx.clone()).await {
		Ok(server) => {
			server.start().await;
			Ok(())
		}
		Err(err) => Err(err.into()),
	}
}
