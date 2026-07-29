//! Wind-tuic outbound wrapper for tuic-client.
//!
//! [`TuicOutboundAdapter`] wraps a [`TuicOutbound`] and implements
//! [`wind_core::AbstractOutbound`] so it can be used as a dispatcher handler
//! (via [`OutboundAsAction`]) or directly by forwarders.

use std::{net::SocketAddr, sync::Arc};

use wind_core::{AbstractOutbound, AppContext, tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream};
use wind_tuic::quinn::outbound::{ReconnectConfig, TuicOutbound, TuicOutboundOpts};

use crate::config::Relay;

/// Wind-tuic outbound wrapper.
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

		let sni = match relay.sni.clone() {
			Some(s) => s,
			None => {
				let host = relay.server.0.trim_start_matches('[').trim_end_matches(']');
				if host.parse::<std::net::IpAddr>().is_ok() {
					tracing::warn!(
						"relay server `{}` is an IP literal but no `sni` was configured; TLS verification will likely fail. \
						 Set `sni = \"<hostname>\"` in the relay config to fix.",
						relay.server.0,
					);
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
		_via: Option<impl AbstractOutbound + Sized + Send>,
	) -> eyre::Result<()> {
		self.outbound.handle_tcp(target_addr, stream, Option::<Self>::None).await
	}

	async fn handle_udp(&self, udp_stream: UdpStream, _via: Option<impl AbstractOutbound + Sized + Send>) -> eyre::Result<()> {
		self.outbound.handle_udp(udp_stream, Option::<Self>::None).await
	}
}
