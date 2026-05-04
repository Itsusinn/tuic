// Library interface for tuic-client
// This allows the client to be used as a library in integration tests

use std::sync::{
	Arc,
	atomic::{AtomicBool, AtomicU16, Ordering},
};

use moka::future::Cache;
use tokio::{
	sync::Mutex as AsyncMutex,
	time::{Duration, sleep},
};
use tracing::{error, warn};

pub mod config;
pub mod connection;
pub mod error;
pub mod forward;
pub mod socks5;
pub mod utils;

pub use config::Config;

/// Application-level context holding all shared state.
/// Passed as `Arc<AppContext>` throughout the client; eliminates global
/// statics.
pub struct AppContext {
	/// Manages the QUIC endpoint and current connection
	pub conn_mgr:            Arc<connection::ConnectionManager>,
	/// SOCKS5 proxy server
	pub socks5:              Arc<socks5::Server>,
	/// UDP session registry for SOCKS5 UDP associate
	pub socks5_udp_sessions: Cache<u16, socks5::UdpSession>,
	/// UDP session registry for TCP/UDP port forwarding
	pub fwd_udp_sessions:    Cache<u16, forward::ForwardUdpSession>,
	/// Next association ID counter for UDP forwarding (high bit set to avoid
	/// collisions with SOCKS5 IDs)
	pub next_fwd_assoc_id:   AtomicU16,
	/// Startup connection behavior.
	pub startup_mode:        config::StartupMode,
	/// Whether the first relay connection has been established at least once.
	pub first_connected:     AtomicBool,
	/// Serializes first-connection logic under non-eager modes.
	pub first_connect_lock:  AsyncMutex<()>,
}

impl AppContext {
	/// Get or re-establish the TUIC relay connection.
	pub async fn get_conn(&self) -> Result<connection::Connection, error::Error> {
		if self.first_connected.load(Ordering::Relaxed) {
			return self
				.conn_mgr
				.get_conn(self.socks5_udp_sessions.clone(), self.fwd_udp_sessions.clone())
				.await;
		}

		let _guard = self.first_connect_lock.lock().await;
		if self.first_connected.load(Ordering::Relaxed) {
			return self
				.conn_mgr
				.get_conn(self.socks5_udp_sessions.clone(), self.fwd_udp_sessions.clone())
				.await;
		}

		match self.startup_mode {
			config::StartupMode::Eager | config::StartupMode::Lazy => {
				let conn = self
					.conn_mgr
					.get_conn(self.socks5_udp_sessions.clone(), self.fwd_udp_sessions.clone())
					.await
					.unwrap_or_else(|err| {
						error!("[relay] first on-demand connection failed: {err}");
						std::process::exit(1);
					});
				self.first_connected.store(true, Ordering::Relaxed);
				Ok(conn)
			}
			config::StartupMode::Loop => loop {
				match self
					.conn_mgr
					.get_conn(self.socks5_udp_sessions.clone(), self.fwd_udp_sessions.clone())
					.await
				{
					Ok(conn) => {
						self.first_connected.store(true, Ordering::Relaxed);
						return Ok(conn);
					}
					Err(err) => {
						warn!("[relay] first on-demand connection failed in loop mode, retrying: {err}");
						sleep(Duration::from_secs(1)).await;
					}
				}
			},
		}
	}
}

/// Run the TUIC client with the given configuration.
pub async fn run(cfg: Config) -> eyre::Result<()> {
	let startup_mode = cfg.relay.startup_mode;
	let conn_mgr = Arc::new(connection::ConnectionManager::build(cfg.relay).await?);
	let socks5 = Arc::new(socks5::Server::new(
		cfg.local.server,
		cfg.local.dual_stack,
		cfg.local.max_packet_size,
		cfg.local.username,
		cfg.local.password,
	)?);
	let ctx = Arc::new(AppContext {
		conn_mgr,
		socks5,
		socks5_udp_sessions: Cache::new(1024),
		fwd_udp_sessions: Cache::new(1024),
		next_fwd_assoc_id: AtomicU16::new(0),
		startup_mode,
		first_connected: AtomicBool::new(false),
		first_connect_lock: AsyncMutex::new(()),
	});

	// Eager mode keeps the original behavior: connect at startup and exit on
	// failure.
	if matches!(startup_mode, config::StartupMode::Eager) {
		ctx.get_conn().await?;
	}

	forward::start(ctx.clone(), cfg.local.tcp_forward, cfg.local.udp_forward).await;
	socks5::Server::start(ctx.clone()).await;
	Ok(())
}
