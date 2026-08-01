//! Wind framework adapter for tuic-server
//!
//! This module provides:
//!
//! * [`TuicRouter`] – implements `wind_core::Router`.
//! * [`ServerInbound`] – QUIC listener wrapper (quinn / quiche).
//! * [`load_cert_from_files`] – TLS certificate loading.
//! * [`make_outbound_action`] – factory for named outbound handlers.

use std::{
	net::{Ipv4Addr, Ipv6Addr},
	sync::Arc,
	time::Duration,
};

use tracing::Instrument;
use wind_acl::AclEngine;
use wind_base::{
	direct::{DirectOutbound, DirectOutboundOpts},
	load_balance::{LoadBalanceOpts, LoadBalanceOutbound, LoadBalanceStrategy},
	resolve::resolve_target,
};
use wind_core::{
	OutboundAction, RouteAction, Router, rule::Rule, types::TargetAddr,
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
///
/// When `bind_ipv4` + `bind_ipv6` together contain **more than one** address
/// (and `kind == "direct"`), the addresses are wrapped in a
/// [`LoadBalanceOutbound`] with round-robin strategy so connections are
/// distributed across the available source IPs.
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
		"direct" => build_direct_or_lb(rule, resolver, stream_timeout),
		other => {
			tracing::warn!(
				outbound_type = %other,
				"unknown outbound type; falling back to DIRECT"
			);
			build_direct_or_lb(rule, resolver, stream_timeout)
		}
	}
}

/// Build either a single [`DirectOutbound`] or a [`LoadBalanceOutbound`]
/// wrapping the cartesian product of `bind_ipv4 × bind_ipv6`.
///
/// When both families have entries, each pair `(v4, v6)` becomes one
/// `DirectOutbound` so that every outbound can bind correctly regardless of
/// the target's address family.  When only one family has entries (or none),
/// the behaviour degrades to a flat list.
fn build_direct_or_lb(
	rule: &OutboundRule,
	resolver: Arc<dyn wind_core::Resolver>,
	stream_timeout: Duration,
) -> Arc<dyn OutboundAction> {
	// Build the domain for each address family.  An empty family
	// contributes a single [None] so the cartesian product still includes
	// the other family's addresses.
	let v4_opts: Vec<Option<Ipv4Addr>> = if rule.bind_ipv4.is_empty() {
		vec![None]
	} else {
		rule.bind_ipv4.iter().copied().map(Some).collect()
	};
	let v6_opts: Vec<Option<Ipv6Addr>> = if rule.bind_ipv6.is_empty() {
		vec![None]
	} else {
		rule.bind_ipv6.iter().copied().map(Some).collect()
	};

	let total = v4_opts.len() * v6_opts.len();

	if total <= 1 {
		// Zero or one combination — single DirectOutbound (existing behaviour).
		return Arc::new(DirectOutbound::new(
			make_direct_opts(
				rule,
				stream_timeout,
				v4_opts.first().copied().flatten(),
				v6_opts.first().copied().flatten(),
			),
			resolver,
		));
	}

	// Cartesian product: each (v4, v6) pair → one DirectOutbound.
	let proxies: Vec<Arc<dyn OutboundAction>> = v4_opts
		.iter()
		.flat_map(|v4| v6_opts.iter().map(move |v6| (*v4, *v6)))
		.map(|(v4, v6)| {
			Arc::new(DirectOutbound::new(
				make_direct_opts(rule, stream_timeout, v4, v6),
				resolver.clone(),
			)) as Arc<dyn OutboundAction>
		})
		.collect();

	let lb_opts = LoadBalanceOpts {
		strategy: LoadBalanceStrategy::RoundRobin,
		url: "https://cp.cloudflare.com/".into(),
		interval: Duration::from_secs(30),
		lazy: true,
	};

	tracing::info!(
		proxy_count = proxies.len(),
		"creating load-balance outbound for multiple bind addresses"
	);

	Arc::new(LoadBalanceOutbound::new(lb_opts, proxies))
}

/// Construct [`DirectOutboundOpts`] from the shared rule fields + resolved
/// bind addresses.
fn make_direct_opts(
	rule: &OutboundRule,
	stream_timeout: Duration,
	bind_ipv4: Option<Ipv4Addr>,
	bind_ipv6: Option<Ipv6Addr>,
) -> DirectOutboundOpts {
	DirectOutboundOpts {
		bind_ipv4,
		bind_ipv6,
		bind_device: rule.bind_device.clone(),
		stream_timeout,
		tcp_keepalive: Some(wind_core::tcp::TcpKeepalive::default()),
		ip_mode: rule.ip_mode,
		routing_mark: rule.routing_mark,
		tfo: rule.tfo.unwrap_or(false),
		mptcp: false,
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
				tracing::info!("[router] converted {} legacy ACL rule(s) to Metacubex format", cfg.acl.len());
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

#[cfg(test)]
mod tests {
	use std::net::IpAddr;

	use tempfile::tempdir;
	use wind_core::utils::StackPrefer;

	use super::*;

	struct FakeResolver;
	impl wind_core::Resolver for FakeResolver {
		fn resolve<'a>(
			&'a self,
			_host: &'a str,
		) -> std::pin::Pin<Box<dyn std::future::Future<Output = eyre::Result<IpAddr>> + Send + 'a>> {
			Box::pin(async { Ok("127.0.0.1".parse().unwrap()) })
		}

		fn resolve_all<'a>(
			&'a self,
			_host: &'a str,
		) -> std::pin::Pin<Box<dyn std::future::Future<Output = eyre::Result<Vec<IpAddr>>> + Send + 'a>> {
			Box::pin(async { Ok(vec!["127.0.0.1".parse().unwrap()]) })
		}
	}

	fn default_resolver() -> Arc<dyn wind_core::Resolver> {
		Arc::new(FakeResolver)
	}

	#[test]
	fn test_make_outbound_action_socks5_does_not_panic() {
		let rule = OutboundRule {
			kind: "socks5".to_string(),
			ip_mode: None,
			addr: Some("127.0.0.1:1080".to_string()),
			username: Some("user".to_string()),
			password: Some("pass".to_string()),
			allow_udp: Some(true),
			bind_ipv4: Vec::new(),
			bind_ipv6: Vec::new(),
			bind_device: None,
			routing_mark: None,
			tfo: None,
		};
		let _action = make_outbound_action(&rule, default_resolver(), Duration::from_secs(30));
	}

	#[test]
	fn test_make_outbound_action_direct_does_not_panic() {
		let rule = OutboundRule {
			kind: "direct".to_string(),
			ip_mode: None,
			addr: None,
			username: None,
			password: None,
			allow_udp: None,
			bind_ipv4: Vec::new(),
			bind_ipv6: Vec::new(),
			bind_device: None,
			routing_mark: None,
			tfo: None,
		};
		let _action = make_outbound_action(&rule, default_resolver(), Duration::from_secs(30));
	}

	#[test]
	fn test_make_outbound_action_unknown_falls_back_to_direct() {
		let rule = OutboundRule {
			kind: "bogus".to_string(),
			ip_mode: None,
			addr: None,
			username: None,
			password: None,
			allow_udp: None,
			bind_ipv4: Vec::new(),
			bind_ipv6: Vec::new(),
			bind_device: None,
			routing_mark: None,
			tfo: None,
		};
		let _action = make_outbound_action(&rule, default_resolver(), Duration::from_secs(30));
	}

	#[test]
	fn test_make_outbound_action_socks5_with_all_options() {
		let rule = OutboundRule {
			kind: "socks5".to_string(),
			ip_mode: Some(StackPrefer::V4first),
			addr: Some("192.168.0.1:8888".to_string()),
			username: Some("admin".to_string()),
			password: Some("secret".to_string()),
			allow_udp: Some(false),
			bind_ipv4: Vec::new(),
			bind_ipv6: Vec::new(),
			bind_device: None,
			routing_mark: None,
			tfo: None,
		};
		let _action = make_outbound_action(&rule, default_resolver(), Duration::from_secs(0));
	}

	#[test]
	fn test_make_outbound_action_direct_single_ip_no_lb() {
		// Single bind address → still a DirectOutbound (no LoadBalance wrapping).
		let rule = OutboundRule {
			kind: "direct".to_string(),
			ip_mode: None,
			addr: None,
			username: None,
			password: None,
			allow_udp: None,
			bind_ipv4: vec!["10.0.0.1".parse().unwrap()],
			bind_ipv6: Vec::new(),
			bind_device: None,
			routing_mark: None,
			tfo: None,
		};
		let _action = make_outbound_action(&rule, default_resolver(), Duration::from_secs(30));
	}

	#[test]
	fn test_make_outbound_action_direct_multi_ipv4_creates_lb() {
		// Multiple IPv4 addresses → LoadBalanceOutbound with 3 children.
		let rule = OutboundRule {
			kind: "direct".to_string(),
			ip_mode: None,
			addr: None,
			username: None,
			password: None,
			allow_udp: None,
			bind_ipv4: vec![
				"10.0.0.1".parse().unwrap(),
				"10.0.0.2".parse().unwrap(),
				"10.0.0.3".parse().unwrap(),
			],
			bind_ipv6: Vec::new(),
			bind_device: None,
			routing_mark: None,
			tfo: None,
		};
		let _action = make_outbound_action(&rule, default_resolver(), Duration::from_secs(30));
	}

	#[test]
	fn test_make_outbound_action_direct_mixed_ipv4_ipv6_creates_lb() {
		// Mixed IPv4 + IPv6 (2×1 cartesian product) → 2 children.
		let rule = OutboundRule {
			kind: "direct".to_string(),
			ip_mode: None,
			addr: None,
			username: None,
			password: None,
			allow_udp: None,
			bind_ipv4: vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()],
			bind_ipv6: vec!["fd00::1".parse().unwrap()],
			bind_device: None,
			routing_mark: None,
			tfo: None,
		};
		let _action = make_outbound_action(&rule, default_resolver(), Duration::from_secs(30));
	}

	#[test]
	fn test_make_outbound_action_direct_mixed_2x2_creates_lb() {
		// Mixed IPv4 + IPv6 (2×2 cartesian product) → 4 children,
		// each with both bind_ipv4 and bind_ipv6 set.
		let rule = OutboundRule {
			kind: "direct".to_string(),
			ip_mode: None,
			addr: None,
			username: None,
			password: None,
			allow_udp: None,
			bind_ipv4: vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()],
			bind_ipv6: vec!["fd00::1".parse().unwrap(), "fd00::2".parse().unwrap()],
			bind_device: None,
			routing_mark: None,
			tfo: None,
		};
		let _action = make_outbound_action(&rule, default_resolver(), Duration::from_secs(30));
	}

	#[test]
	fn test_make_outbound_action_direct_multi_ipv6_creates_lb() {
		// Multiple IPv6 addresses → LoadBalanceOutbound with 2 children.
		let rule = OutboundRule {
			kind: "direct".to_string(),
			ip_mode: None,
			addr: None,
			username: None,
			password: None,
			allow_udp: None,
			bind_ipv4: Vec::new(),
			bind_ipv6: vec!["fd00::1".parse().unwrap(), "fd00::2".parse().unwrap()],
			bind_device: None,
			routing_mark: None,
			tfo: None,
		};
		let _action = make_outbound_action(&rule, default_resolver(), Duration::from_secs(30));
	}

	#[tokio::test]
	async fn test_load_cert_from_files_success() {
		let dir = tempdir().unwrap();
		let cert_path = dir.path().join("cert.pem");
		let key_path = dir.path().join("key.pem");

		let (cert_pem, key_pem) = {
			let mut params = rcgen::CertificateParams::default();
			params.distinguished_name.push(rcgen::DnType::CommonName, "localhost");
			params.subject_alt_names = vec![rcgen::SanType::DnsName(
				rcgen::string::Ia5String::try_from("localhost".to_string()).unwrap(),
			)];
			let key_pair = rcgen::KeyPair::generate().unwrap();
			let cert = params.self_signed(&key_pair).unwrap();
			(cert.pem(), key_pair.serialize_pem())
		};

		std::fs::write(&cert_path, &cert_pem).unwrap();
		std::fs::write(&key_path, &key_pem).unwrap();

		let (certs, _key) = load_cert_from_files(&cert_path, &key_path).unwrap();
		assert!(!certs.is_empty());
	}

	#[test]
	fn test_load_cert_from_files_missing_cert() {
		let dir = tempdir().unwrap();
		let cert_path = dir.path().join("noexist.pem");
		let key_path = dir.path().join("noexist.key");

		let result = load_cert_from_files(&cert_path, &key_path);
		assert!(result.is_err());
	}

	#[test]
	fn test_load_cert_from_files_invalid_pem() {
		let dir = tempdir().unwrap();
		let cert_path = dir.path().join("bad.pem");
		let key_path = dir.path().join("bad.key");
		std::fs::write(&cert_path, b"not a certificate").unwrap();
		std::fs::write(&key_path, b"not a key").unwrap();

		let result = load_cert_from_files(&cert_path, &key_path);
		assert!(result.is_err());
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
	let key = rustls_pemfile::private_key(&mut key_data.as_slice())?.ok_or_else(|| eyre::eyre!("No private key found"))?;
	Ok((certs, key))
}
