// Library interface for tuic-client
// This allows the client to be used as a library in integration tests

pub mod config;
pub mod connection;
pub mod error;
pub mod forward;
pub mod socks5;
pub mod utils;

pub use config::Config;

/// Run the TUIC client with the given configuration
pub async fn run(cfg: Config) -> eyre::Result<()> {
	match connection::Connection::set_config(cfg.relay).await {
		Ok(()) => {
			connection::Connection::get_conn().await?;
		}
		Err(err) => {
			return Err(err.into());
		}
	}

	forward::start(cfg.local.tcp_forward.clone(), cfg.local.udp_forward.clone()).await;

	match socks5::Server::set_config(cfg.local) {
		Ok(()) => {}
		Err(err) => {
			return Err(err.into());
		}
	}

	socks5::Server::start().await;
	Ok(())
}
