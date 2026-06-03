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
	pub conn_mgr: Arc<connection::ConnectionManager>,
	/// SOCKS5 proxy server
	pub socks5: Option<Arc<socks5::Server>>,
	/// UDP session registry for SOCKS5 UDP associate
	pub socks5_udp_sessions: Cache<u16, socks5::UdpSession>,
	/// UDP session registry for TCP/UDP port forwarding
	pub fwd_udp_sessions: Cache<u16, forward::ForwardUdpSession>,
	/// Next association ID counter for UDP forwarding (high bit set to avoid
	/// collisions with SOCKS5 IDs)
	pub next_fwd_assoc_id: AtomicU16,
	/// Startup connection behavior.
	pub startup_mode: config::StartupMode,
	/// Whether the first relay connection has been established at least once.
	pub first_connected: AtomicBool,
	/// Serializes first-connection logic under non-eager modes.
	pub first_connect_lock: AsyncMutex<()>,
	/// Idle timeout applied to each SOCKS5 UDP ASSOCIATE session.
	pub socks5_udp_idle_timeout: Duration,
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
	let socks5 = cfg
		.local
		.server
		.map(|addr| {
			socks5::Server::new(
				addr,
				cfg.local.dual_stack,
				cfg.local.max_packet_size,
				cfg.local.username,
				cfg.local.password,
			)
			.map(Arc::new)
		})
		.transpose()?;

	let socks5_idle = cfg.local.socks5_udp_idle_timeout;
	// Cache acts as a safety-net evictor; the per-session idle watcher does the
	// authoritative cleanup (with proper `dissociate` to the relay). The cache TTI
	// is sized larger than the watcher's interval so the watcher wins under normal
	// conditions and the cache only fires if the watcher is stuck or missing.
	let socks5_cache_tti = socks5_idle.saturating_mul(2).max(Duration::from_secs(60));
	let fwd_cache_tti = cfg
		.local
		.udp_forward
		.iter()
		.map(|f| f.timeout)
		.max()
		.unwrap_or(Duration::from_secs(60))
		.saturating_mul(2);

	let ctx = Arc::new(AppContext {
		conn_mgr,
		socks5,
		socks5_udp_sessions: Cache::builder().max_capacity(1024).time_to_idle(socks5_cache_tti).build(),
		fwd_udp_sessions: Cache::builder().max_capacity(1024).time_to_idle(fwd_cache_tti).build(),
		next_fwd_assoc_id: AtomicU16::new(0),
		startup_mode,
		first_connected: AtomicBool::new(false),
		first_connect_lock: AsyncMutex::new(()),
		socks5_udp_idle_timeout: socks5_idle,
	});

	// Eager mode keeps the original behavior: connect at startup and exit on
	// failure.
	if matches!(startup_mode, config::StartupMode::Eager) {
		ctx.get_conn().await?;
	}

	let has_forwarding = !cfg.local.tcp_forward.is_empty() || !cfg.local.udp_forward.is_empty();
	forward::start(ctx.clone(), cfg.local.tcp_forward, cfg.local.udp_forward).await;
	if ctx.socks5.is_some() {
		socks5::Server::start(ctx.clone()).await;
	} else if has_forwarding {
		// If SOCKS5 is disabled but forwarding is active, block forever to keep
		// the background tasks alive.
		std::future::pending::<()>().await;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use tokio::time::{Duration, timeout};
	use uuid::Uuid;

	use super::*;
	use crate::config::TcpForward;

	fn install_crypto() {
		#[cfg(feature = "aws-lc-rs")]
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		#[cfg(feature = "ring")]
		let _ = rustls::crypto::ring::default_provider().install_default();
	}

	#[tokio::test]
	async fn test_run_stays_alive_with_only_forwarding() {
		install_crypto();
		let mut cfg = Config::default();
		cfg.relay.server = ("127.0.0.1".to_string(), 443);
		cfg.relay.uuid = Uuid::new_v4();

		cfg.local.server = None;
		cfg.local.tcp_forward = vec![TcpForward {
			listen: "127.0.0.1:0".parse().unwrap(),
			remote: ("127.0.0.1".to_string(), 80),
		}];

		// run should block because has_forwarding is true and socks5 is None.
		// We use timeout to verify it doesn't return immediately.
		let result = timeout(Duration::from_millis(100), run(cfg)).await;

		assert!(result.is_err(), "run() should have blocked and timed out");
	}

	#[tokio::test]
	async fn test_run_exits_immediately_with_nothing() {
		install_crypto();
		let mut cfg = Config::default();
		cfg.relay.server = ("127.0.0.1".to_string(), 443);
		cfg.relay.uuid = Uuid::new_v4();

		cfg.local.server = None;
		cfg.local.tcp_forward = vec![];
		cfg.local.udp_forward = vec![];

		// run should return Ok(()) immediately.
		let result = timeout(Duration::from_millis(100), run(cfg)).await;

		assert!(result.is_ok(), "run() should have returned immediately");
		assert!(result.unwrap().is_ok());
	}
}
