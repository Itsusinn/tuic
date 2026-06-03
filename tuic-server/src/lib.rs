// Library interface for tuic-server
// This allows the server to be used as a library in integration tests

use std::{
	collections::HashMap,
	sync::{Arc, atomic::AtomicUsize},
};

use moka::future::Cache;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub mod acl;
pub mod acme;
pub mod camouflage;
pub mod compat;
pub mod config;
pub mod connection;
pub mod error;
pub mod io;
pub mod log;
pub mod restful;
pub mod server;
pub mod tls;
pub mod utils;

pub use config::{Cli, Config, Control};

pub struct AppContext {
	pub cfg: Config,
	pub online_counter: HashMap<Uuid, AtomicUsize>,
	pub online_clients: Cache<Uuid, Arc<Cache<usize, compat::QuicClient>>>,
	pub traffic_stats: HashMap<Uuid, (AtomicUsize, AtomicUsize)>,
	pub cancel: CancellationToken,
}

pub struct ServerGuard {
	pub local_addr: std::net::SocketAddr,
	pub cancel: CancellationToken,
}

/// Run the TUIC server with the given configuration.
/// Returns a [`ServerGuard`] containing the actual bound address and
/// a cancellation token for graceful shutdown.
pub async fn run(cfg: Config) -> eyre::Result<ServerGuard> {
	let mut online_counter = HashMap::new();
	for user in cfg.users.keys() {
		online_counter.insert(user.to_owned(), AtomicUsize::new(0));
	}

	let mut traffic_stats = HashMap::new();
	for user in cfg.users.keys() {
		traffic_stats.insert(user.to_owned(), (AtomicUsize::new(0), AtomicUsize::new(0)));
	}

	let ctx = Arc::new(AppContext {
		online_counter,
		online_clients: Cache::new(cfg.users.len() as u64),
		traffic_stats,
		cfg,
		cancel: CancellationToken::new(),
	});
	let server = server::Server::init(ctx.clone()).await?;
	let local_addr = server.local_addr()?;
	let cancel = ctx.cancel.clone();
	tokio::spawn(async move {
		server.start().await;
	});
	Ok(ServerGuard { local_addr, cancel })
}
pub mod h3_quinn_compat;
