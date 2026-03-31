// Library interface for tuic-client
// This allows the client to be used as a library in integration tests

use std::{
	collections::HashMap,
	sync::{Arc, atomic::AtomicU16},
};

use tokio::sync::RwLock as AsyncRwLock;

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
	pub socks5_udp_sessions: Arc<AsyncRwLock<HashMap<u16, socks5::UdpSession>>>,
	/// UDP session registry for TCP/UDP port forwarding
	pub fwd_udp_sessions:    Arc<AsyncRwLock<HashMap<u16, forward::ForwardUdpSession>>>,
	/// Next association ID counter for UDP forwarding (high bit set to avoid
	/// collisions with SOCKS5 IDs)
	pub next_fwd_assoc_id:   AtomicU16,
}

impl AppContext {
	/// Get or re-establish the TUIC relay connection.
	pub async fn get_conn(&self) -> Result<connection::Connection, error::Error> {
		self.conn_mgr
			.get_conn(self.socks5_udp_sessions.clone(), self.fwd_udp_sessions.clone())
			.await
	}
}

/// Run the TUIC client with the given configuration.
pub async fn run(cfg: Config) -> eyre::Result<()> {
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
		socks5_udp_sessions: Arc::new(AsyncRwLock::new(HashMap::new())),
		fwd_udp_sessions: Arc::new(AsyncRwLock::new(HashMap::new())),
		next_fwd_assoc_id: AtomicU16::new(0),
	});

	// Establish the initial relay connection eagerly
	ctx.get_conn().await?;

	forward::start(ctx.clone(), cfg.local.tcp_forward, cfg.local.udp_forward).await;
	socks5::Server::start(ctx.clone()).await;
	Ok(())
}
