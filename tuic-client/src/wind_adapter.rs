//! Wind framework adapter for tuic-client
//!
//! This module provides integration between the original tuic-client logic
//! and the wind-tuic implementation.

use std::{net::SocketAddr, sync::Arc};

use once_cell::sync::OnceCell;
use wind_core::{AbstractOutbound, AppContext, tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream};
use wind_tuic::quinn::outbound::{ReconnectConfig, TuicOutbound, TuicOutboundOpts};

use crate::config::Relay;

static WIND_CONNECTION: OnceCell<TuicOutboundAdapter> = OnceCell::new();

/// Wind-tuic outbound wrapper for tuic-client
pub struct TuicOutboundAdapter {
	pub outbound: TuicOutbound,
}

impl TuicOutboundAdapter {
	pub async fn new(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<Self> {
		let server_addr = if let Some(ip) = relay.ip {
			SocketAddr::new(ip, relay.server.1)
		} else {
			let addrs = tokio::net::lookup_host(format!("{}:{}", relay.server.0, relay.server.1)).await?;
			addrs
				.into_iter()
				.next()
				.ok_or_else(|| eyre::eyre!("Failed to resolve server address"))?
		};

		let password: Arc<[u8]> = relay.password.clone();

		// Pick the SNI to send during TLS handshake.
		//
		// Defaulting to `relay.server.0` is sensible when the server field is
		// a hostname, but if it's an IP literal we end up announcing the IP
		// in the SNI extension — most rustls/webpki verifiers reject that as
		// a non-hostname SNI, and even when they don't, the SNI value carries
		// no integrity benefit. Warn loudly so operators notice the
		// wrong configuration; require an explicit `sni` for IP-literal
		// servers and use a placeholder otherwise so the connection still
		// attempts to handshake (and rustls will surface the bad-SNI error
		// in its own message).
		let sni = match relay.sni.clone() {
			Some(s) => s,
			None => {
				// Strip any surrounding brackets so a bracketed IPv6 literal
				// (`[::1]`) is recognized as an IP literal too -- otherwise the
				// bracketed form fails `IpAddr::parse` and gets announced
				// verbatim as the SNI, which rustls rejects ("invalid server
				// name").
				let host = relay.server.0.trim_start_matches('[').trim_end_matches(']');
				if host.parse::<std::net::IpAddr>().is_ok() {
					tracing::warn!(
						"relay server `{}` is an IP literal but no `sni` was configured; TLS verification will likely fail. \
						 Set `sni = \"<hostname>\"` in the relay config to fix.",
						relay.server.0,
					);
					// rustls accepts "invalid" only if the verifier accepts it
					// — for the skip-verify path this is harmless; for the
					// real path the connection will fail with a clear error.
					"invalid.sni.placeholder".to_string()
				} else {
					relay.server.0.clone()
				}
			}
		};

		let reconnect = ReconnectConfig {
			enabled: relay.reconnect,
			initial_backoff: relay.reconnect_initial_backoff,
			max_backoff: relay.reconnect_max_backoff,
		};

		let opts = TuicOutboundOpts {
			peer_addr: server_addr,
			sni,
			auth: (relay.uuid, password),
			zero_rtt_handshake: relay.zero_rtt_handshake,
			heartbeat: relay.heartbeat,
			gc_interval: relay.gc_interval,
			gc_lifetime: relay.gc_lifetime,
			skip_cert_verify: relay.skip_cert_verify,
			alpn: relay
				.alpn
				.into_iter()
				.map(|v| String::from_utf8_lossy(&v).to_string())
				.collect(),
			reconnect,
		};

		let outbound: TuicOutbound = TuicOutbound::new(ctx, opts).await?;

		outbound.start_poll().await?;

		Ok(Self { outbound })
	}
}

impl AbstractOutbound for TuicOutboundAdapter {
	async fn handle_tcp(
		&self,
		target_addr: TargetAddr,
		stream: impl AbstractTcpStream,
		_dialer: Option<impl AbstractOutbound>,
	) -> eyre::Result<()> {
		self.outbound
			.handle_tcp(target_addr, stream, None::<TuicOutboundAdapter>)
			.await
	}

	async fn handle_udp(&self, udp_stream: UdpStream, _dialer: Option<impl AbstractOutbound>) -> eyre::Result<()> {
		self.outbound.handle_udp(udp_stream, None::<TuicOutboundAdapter>).await
	}
}

impl TuicOutboundAdapter {
	/// Get the global wind-tuic connection
	pub fn get() -> Option<&'static Self> {
		WIND_CONNECTION.get()
	}

	/// Initialize the global wind-tuic connection
	pub fn set_global(adapter: Self) -> Result<(), Box<Self>> {
		WIND_CONNECTION.set(adapter).map_err(Box::new)
	}
}

/// Create a new TUIC connection using wind-tuic and set it as global
pub async fn create_connection(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<()> {
	let adapter = TuicOutboundAdapter::new(ctx, relay).await?;
	TuicOutboundAdapter::set_global(adapter).map_err(|_| eyre::eyre!("Failed to set global wind-tuic connection"))?;
	Ok(())
}

/// Get the global wind-tuic connection
pub fn get_connection() -> Option<&'static TuicOutboundAdapter> {
	TuicOutboundAdapter::get()
}
