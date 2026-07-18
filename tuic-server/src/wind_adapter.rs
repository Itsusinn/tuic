//! Wind framework adapter for tuic-server
//!
//! This module provides:
//!
//! * [`TuicRouter`] – implements `wind_core::Router`.
//! * [`ServerInbound`] – QUIC listener wrapper (quinn / quiche).
//! * [`load_cert_from_files`] – TLS certificate loading.
//! * [`make_outbound_action`] – factory for named outbound handlers.

use std::{sync::Arc, time::Duration};

use tracing::Instrument;
use wind_acl::AclEngine;
use wind_base::{
	direct::{DirectOutbound, DirectOutboundOpts},
	resolve::resolve_target,
};
use wind_core::{
	OutboundAction, RouteAction, Router,
	rule::Rule,
	types::TargetAddr,
	utils::is_private_ip,
};
use wind_geodata::GeoData;
use wind_socks::action::{Socks5Action, Socks5ActionOpts};

use crate::{
	config::{ExperimentalConfig, OutboundRule},
	legacy::acl_to_rules,
};

/// Inbound QUIC listener selected by `backend.mode`.
pub enum ServerInbound {
	Tuic(wind_tuic::quinn::inbound::TuicInbound),
	#[cfg(feature = "quiche")]
	Tuiche(wind_tuic::quiche::TuicheInbound),
}

impl wind_core::AbstractInbound for ServerInbound {
	async fn listen(&self, cb: &impl wind_core::InboundCallback) -> eyre::Result<()> {
		match self {
			ServerInbound::Tuic(inbound) => inbound.listen(cb).await,
			#[cfg(feature = "quiche")]
			ServerInbound::Tuiche(inbound) => inbound.listen(cb).await,
		}
	}
}

/// Build an [`OutboundAction`] for a single configured outbound rule.
pub fn make_outbound_action(
	rule: &OutboundRule,
	resolver: Arc<dyn wind_core::Resolver>,
	stream_timeout: Duration,
) -> Arc<dyn OutboundAction> {
	match rule.kind.as_str() {
		"socks5" => Arc::new(Socks5Action::new(Socks5ActionOpts {
			addr: rule.addr.clone().unwrap_or_default(),
			username: rule.username.clone(),
			password: rule.password.clone(),
			allow_udp: rule.allow_udp,
			stream_timeout,
			tcp_keepalive: Some(wind_core::tcp::TcpKeepalive::default()),
		})),
		"direct" => Arc::new(DirectOutbound::new(
			DirectOutboundOpts {
				bind_ipv4: rule.bind_ipv4,
				bind_ipv6: rule.bind_ipv6,
				bind_device: rule.bind_device.clone(),
				stream_timeout,
				tcp_keepalive: Some(wind_core::tcp::TcpKeepalive::default()),
			},
			resolver,
		)),
		other => {
			tracing::warn!(
				outbound_type = %other,
				"unknown outbound type; falling back to DIRECT"
			);
			Arc::new(DirectOutbound::new(
				DirectOutboundOpts {
					bind_ipv4: rule.bind_ipv4,
					bind_ipv6: rule.bind_ipv6,
					bind_device: rule.bind_device.clone(),
					stream_timeout,
					tcp_keepalive: Some(wind_core::tcp::TcpKeepalive::default()),
				},
				resolver,
			))
		}
	}
}

pub struct TuicRouter {
	experimental: ExperimentalConfig,
	resolver: Arc<dyn wind_core::Resolver>,
	acl_engine: Option<AclEngine>,
}

impl TuicRouter {
	pub fn new(
		cfg: &crate::Config,
		resolver: Arc<dyn wind_core::Resolver>,
		geodata: Option<Arc<GeoData>>,
	) -> eyre::Result<Self> {
		let converted = acl_to_rules(&cfg.acl);
		let explicit: Vec<Rule> = cfg
			.rules
			.iter()
			.map(|r| Rule::parse(&r.to_string()).expect("round-trip rule parse"))
			.collect();
		let all_rules: Vec<Rule> = converted.into_iter().chain(explicit).collect();

		let acl_engine = if all_rules.is_empty() {
			None
		} else {
			if !cfg.acl.is_empty() {
				tracing::info!(
					"[router] converted {} legacy ACL rule(s) to Metacubex format",
					cfg.acl.len()
				);
			}
			let mut builder = AclEngine::builder("default").rules(all_rules);
			if let Some(gd) = geodata {
				builder = builder.geodata(gd);
			}
			Some(builder.build()?)
		};

		Ok(Self {
			experimental: cfg.experimental.clone(),
			resolver,
			acl_engine,
		})
	}
}

impl Router for TuicRouter {
	async fn route(&self, target: &TargetAddr, is_tcp: bool) -> eyre::Result<RouteAction> {
		let span = tracing::debug_span!("route", target = %target, proto = if is_tcp { "tcp" } else { "udp" });
		self.do_route(target, is_tcp).instrument(span).await
	}
}

impl TuicRouter {
	async fn do_route(&self, target: &TargetAddr, is_tcp: bool) -> eyre::Result<RouteAction> {
		let need_resolve = self.experimental.drop_loopback || self.experimental.drop_private;

		if need_resolve {
			let resolved = resolve_target(target, self.resolver.as_ref()).await?;
			if self.experimental.drop_loopback && resolved.ip().is_loopback() {
				tracing::debug!(resolved = %resolved, "dropping loopback connection");
				return Ok(RouteAction::Reject(format!("loopback address rejected: {}", resolved)));
			}
			if self.experimental.drop_private && is_private_ip(&resolved.ip()) {
				tracing::debug!(resolved = %resolved, "dropping private-range connection");
				return Ok(RouteAction::Reject(format!("private address rejected: {}", resolved)));
			}
		}

		if let Some(acl_engine) = &self.acl_engine {
			return acl_engine.route(target, is_tcp).await;
		}

		Ok(RouteAction::Forward("default".to_string()))
	}
}

/// Load TLS certificate and private key from PEM files.
pub fn load_cert_from_files(
	cert_path: &std::path::Path,
	key_path: &std::path::Path,
) -> eyre::Result<(
	Vec<rustls::pki_types::CertificateDer<'static>>,
	rustls::pki_types::PrivateKeyDer<'static>,
)> {
	let cert_data = std::fs::read(cert_path)?;
	let key_data = std::fs::read(key_path)?;
	let certs = rustls_pemfile::certs(&mut cert_data.as_slice()).collect::<Result<Vec<_>, _>>()?;
	let key = rustls_pemfile::private_key(&mut key_data.as_slice())?
		.ok_or_else(|| eyre::eyre!("No private key found"))?;
	Ok((certs, key))
}
