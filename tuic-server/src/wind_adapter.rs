//! Wind framework adapter for tuic-server
//!
//! This module wires together:
//!
//! * [`TuicRouter`] – implements `wind_core::Router`.  For every incoming
//!   connection it resolves the destination, applies experimental guards, and
//!   evaluates the ACL table to pick the right named outbound.
//! * Outbound handlers from `wind-base` ([`DirectOutbound`]) and `wind-socks`
//!   ([`Socks5Action`]) perform the actual TCP/UDP relay.
//! * [`create_inbound`] – factory that builds a `wind_core::Dispatcher` wired
//!   to a `wind_tuic::TuicInbound` and returns the pair.
//!
//! # Dispatch flow
//!
//! For every incoming TCP stream or UDP session:
//!
//! 1. **Resolve** the `TargetAddr` to a `SocketAddr` using the default
//!    outbound's ip_mode (needed for ACL matching).
//! 2. **Experimental guards** – drop loopback / private addresses if
//!    configured.
//! 3. **ACL evaluation** – first-match wins.  The rule names `"reject"`,
//!    `"block"`, `"deny"` cause rejection; `"allow"` / `"default"` map to the
//!    `"default"` handler; any other name looks up a named outbound.
//! 4. **Outbound dispatch** via the `Dispatcher` / `OutboundAction` trait.

use std::{sync::Arc, time::Duration};

// `WrapErr` is only used by the quiche cert helpers (the `quiche` feature).
#[cfg(feature = "quiche")]
use eyre::WrapErr as _;
use tracing::Instrument;
use wind_acl::AclEngine;
use wind_base::{
	direct::{DirectOutbound, DirectOutboundOpts},
	resolve::resolve_target,
};
use wind_core::{
	AppContext, Dispatcher, OutboundAction, RouteAction, Router, SystemResolver,
	resolve::Resolver,
	rule::Rule,
	types::TargetAddr,
	utils::{StackPrefer, is_private_ip},
};
use wind_geodata::GeoData;
use wind_socks::action::{Socks5Action, Socks5ActionOpts};
// The quiche backend lives behind the `quiche` cargo feature (enabled per target
// via `.github/target.toml`).
#[cfg(feature = "quiche")]
use wind_tuic::quiche::{TuicheInbound, TuicheInboundBuilder};
use wind_tuic::quinn::inbound::{TuicInbound, TuicInboundOpts};

// `CongestionController` is only referenced by the quiche backend wiring.
#[cfg(feature = "quiche")]
use crate::utils::CongestionController;
use crate::{
	AppContext as TuicAppContext,
	config::{BackendMode, OutboundRule},
	legacy::acl_to_rules,
};

/// Inbound QUIC listener selected by `backend.mode`.
pub enum ServerInbound {
	/// quinn-based backend (`wind-tuic`).
	Tuic(TuicInbound),
	/// tokio-quiche-based backend (`wind-tuiche`); requires the `quiche`
	/// feature.
	#[cfg(feature = "quiche")]
	Tuiche(TuicheInbound),
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
/// `stream_timeout` is the configured half-close idle timeout for relays; it
/// was previously hardcoded to `Duration::ZERO`, silently disabling the feature
/// and ignoring the operator's `stream_timeout` setting.
fn make_outbound_action(rule: &OutboundRule, resolver: Arc<dyn Resolver>, stream_timeout: Duration) -> Arc<dyn OutboundAction> {
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
		// An unknown outbound type (typically a typo such as "Socks5" or
		// "sock5") must NOT silently become a direct outbound: that would send
		// traffic out via the server's own IP instead of the intended tunnel.
		// Warn loudly and fall back to direct so the misconfiguration is
		// visible in logs rather than being a silent security downgrade.
		other => {
			tracing::warn!(
				outbound_type = %other,
				"unknown outbound type; falling back to DIRECT. Expected \"direct\" or \"socks5\""
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
	ctx: Arc<TuicAppContext>,
	resolver: Arc<dyn Resolver>,
	acl_engine: Option<AclEngine>,
}

impl TuicRouter {
	pub fn new(ctx: Arc<TuicAppContext>, resolver: Arc<dyn Resolver>, geodata: Option<Arc<GeoData>>) -> eyre::Result<Self> {
		let converted = acl_to_rules(&ctx.cfg.acl);

		let explicit: Vec<Rule> = ctx
			.cfg
			.rules
			.iter()
			.map(|r| Rule::parse(&r.to_string()).expect("round-trip rule parse"))
			.collect();

		let all_rules: Vec<Rule> = converted.into_iter().chain(explicit).collect();

		let acl_engine = if all_rules.is_empty() {
			None
		} else {
			if !ctx.cfg.acl.is_empty() {
				tracing::info!(
					"[router] converted {} legacy ACL rule(s) to Metacubex format",
					ctx.cfg.acl.len()
				);
			}
			// Route via wind-acl's AclEngine so GEOIP/GEOSITE rules resolve
			// against the geodata database. Guards stay in `do_route` below
			// (AclEngine's own guards are left off, so no double resolution).
			let mut builder = AclEngine::builder("default").rules(all_rules);
			if let Some(gd) = geodata {
				builder = builder.geodata(gd);
			}
			Some(builder.build()?)
		};

		Ok(Self {
			ctx,
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
		let exp = &self.ctx.cfg.experimental;
		let need_resolve = exp.drop_loopback || exp.drop_private;

		if need_resolve {
			let resolved = resolve_target(target, self.resolver.as_ref()).await?;
			if exp.drop_loopback && resolved.ip().is_loopback() {
				tracing::debug!(resolved = %resolved, "dropping loopback connection");
				return Ok(RouteAction::Reject(format!("loopback address rejected: {}", resolved)));
			}
			if exp.drop_private && is_private_ip(&resolved.ip()) {
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

/// Build the DNS resolver selected by the configuration.
fn build_resolver(cfg: &crate::Config) -> eyre::Result<Arc<dyn Resolver>> {
	let default_ip_mode = cfg.outbound.default.ip_mode.unwrap_or(StackPrefer::V4first);
	let resolver: Arc<dyn Resolver> = match wind_dns::build(&cfg.dns)? {
		Some(hickory) => {
			tracing::info!("[dns] using {:?} resolver", cfg.dns.mode);
			Arc::new(hickory)
		}
		None => {
			tracing::info!("[dns] using system resolver");
			Arc::new(SystemResolver::new(default_ip_mode))
		}
	};
	Ok(resolver)
}

/// Load the GeoIP / GeoSite database from config, compiling the v2ray `.dat`
/// files into a cache under `data_dir`. Returns `None` when geodata is not
/// configured (both files are required).
async fn load_geodata(cfg: &crate::Config) -> eyre::Result<Option<Arc<GeoData>>> {
	if !cfg.geodata.is_enabled() {
		return Ok(None);
	}
	// `is_enabled()` guarantees both are `Some`.
	let geosite_path = cfg.geodata.geosite.clone().unwrap();
	let geoip_path = cfg.geodata.geoip.clone().unwrap();

	let geosite_bytes = tokio::fs::read(&geosite_path)
		.await
		.map_err(|e| eyre::eyre!("reading geosite database {}: {e}", geosite_path.display()))?;
	let geoip_bytes = tokio::fs::read(&geoip_path)
		.await
		.map_err(|e| eyre::eyre!("reading geoip database {}: {e}", geoip_path.display()))?;

	let cache_path = cfg.data_dir.join("geodata.cache");
	// Building the cache decodes + serializes + mmaps; keep it off the async
	// runtime.
	let geo = tokio::task::spawn_blocking(move || GeoData::build_and_open(&geosite_bytes, &geoip_bytes, &cache_path))
		.await
		.map_err(|e| eyre::eyre!("geodata build task panicked: {e}"))?
		.map_err(|e| eyre::eyre!("building geodata cache: {e}"))?;

	tracing::info!(
		"[geodata] loaded geosite ({}) + geoip ({})",
		geosite_path.display(),
		geoip_path.display()
	);
	Ok(Some(Arc::new(geo)))
}

/// Assemble the routing [`Dispatcher`] (ACL router + named outbound handlers).
///
/// Backend-agnostic: the dispatcher is identical for both QUIC backends, which
/// differ only in the inbound listener paired with it.
fn build_dispatcher(
	ctx: Arc<TuicAppContext>,
	resolver: Arc<dyn Resolver>,
	geodata: Option<Arc<GeoData>>,
) -> eyre::Result<Dispatcher<TuicRouter>> {
	let cfg = &ctx.cfg;
	let router = TuicRouter::new(ctx.clone(), resolver.clone(), geodata)?;
	let mut dispatcher = Dispatcher::new(router);

	let stream_timeout = cfg.stream_timeout;
	dispatcher.add_handler(
		"default",
		make_outbound_action(&cfg.outbound.default, resolver.clone(), stream_timeout),
	);

	for (name, rule) in &cfg.outbound.named {
		dispatcher.add_handler(name.clone(), make_outbound_action(rule, resolver.clone(), stream_timeout));
	}

	Ok(dispatcher)
}

pub async fn create_inbound(ctx: Arc<TuicAppContext>) -> eyre::Result<(ServerInbound, Dispatcher<TuicRouter>)> {
	let resolver = build_resolver(&ctx.cfg)?;
	let geodata = load_geodata(&ctx.cfg).await?;
	let dispatcher = build_dispatcher(ctx.clone(), resolver, geodata)?;

	let inbound = match ctx.cfg.backend.mode {
		BackendMode::Quinn => ServerInbound::Tuic(create_quinn_inbound(&ctx).await?),
		#[cfg(feature = "quiche")]
		BackendMode::Quiche => ServerInbound::Tuiche(create_quiche_inbound(&ctx).await?),
		#[cfg(not(feature = "quiche"))]
		BackendMode::Quiche => {
			return Err(eyre::eyre!(
				"backend.mode = \"quiche\" requires this build to be compiled with the `quiche` feature; rebuild with \
				 --features quiche, or use backend.mode = \"quinn\""
			));
		}
	};

	Ok((inbound, dispatcher))
}

/// Build the quinn (`wind-tuic`) inbound, including ACME / self-signed / file
/// certificate resolution.
async fn create_quinn_inbound(ctx: &Arc<TuicAppContext>) -> eyre::Result<TuicInbound> {
	let cfg = &ctx.cfg;
	let quinn = &cfg.backend.quinn;

	let mut cert_resolver = None;
	let (certs, key) = if cfg.tls.auto_ssl && crate::tls::is_valid_domain(&cfg.tls.hostname) {
		tracing::info!(
			"auto_ssl enabled, starting ACME management for: {} (staging: {})",
			cfg.tls.hostname,
			cfg.tls.acme_staging
		);
		let cache_dir = std::path::Path::new("acme-cache");
		let resolver = wind_acme::start_acme(
			ctx.cancel.child_token(),
			&cfg.tls.hostname,
			&cfg.tls.acme_email,
			cache_dir,
			!cfg.tls.acme_staging,
		)
		.await?;
		cert_resolver = Some(resolver);
		(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into()))
	} else if cfg.tls.self_sign {
		generate_self_signed(&cfg.tls.hostname)?
	} else {
		load_cert_from_files(&cfg.tls.certificate, &cfg.tls.private_key)?
	};

	// Derive the wind-core token from the tuic-server cancel token so a single
	// `cancel()` from the binary's signal handler tears down the listen loop
	// AND every spawned inbound task (each wind_ctx.tasks-tracked task uses a
	// child of `wind_ctx.token`). Previously `wind_ctx` was an independent
	// `AppContext::default()`, so ctrl-c would return from `main` while the
	// listen loop was still alive in the background — quinn's connections
	// stayed up and log guards never flushed.
	let wind_ctx = Arc::new(AppContext {
		tasks: tokio_util::task::TaskTracker::new(),
		token: ctx.cancel.child_token(),
	});

	let opts = TuicInboundOpts {
		listen_addr: cfg.server,
		certificate: certs,
		private_key: key,
		cert_resolver,
		alpn: cfg.tls.alpn.clone(),
		users: cfg.users.clone(),
		auth_timeout: cfg.auth_timeout,
		max_idle_time: quinn.max_idle_time,
		max_concurrent_bi_streams: 512,
		max_concurrent_uni_streams: 512,
		send_window: quinn.send_window,
		receive_window: quinn.receive_window,
		zero_rtt: cfg.zero_rtt_handshake,
		initial_mtu: quinn.initial_mtu,
		min_mtu: quinn.min_mtu,
		gso: quinn.gso,
		// `CongestionController` is a type alias for `wind_tuic::quinn::CongestionControl`,
		// so the configured controller and initial window flow straight through.
		congestion_control: quinn.congestion_control.controller,
		initial_window: quinn.congestion_control.initial_window,
		masquerade: cfg.masquerade.enabled.then(|| wind_tuic::server::MasqueradeConfig {
			upstream: cfg.masquerade.upstream.clone(),
		}),
		..Default::default()
	};
	tracing::info!("Initializing quinn (wind-tuic) backend");
	Ok(TuicInbound::new(wind_ctx, opts))
}

/// Build the tokio-quiche (`wind-tuiche`) inbound from the shared config.
///
/// The quiche backend reads TLS material from *files*, so ACME-issued and
/// self-signed certificates are materialised to disk first (see
/// [`resolve_quiche_cert_files`]).
#[cfg(feature = "quiche")]
async fn create_quiche_inbound(ctx: &Arc<TuicAppContext>) -> eyre::Result<TuicheInbound> {
	let cfg = &ctx.cfg;
	let quiche = &cfg.backend.quiche;

	let (cert, key, acme_rx) = resolve_quiche_cert_files(ctx).await?;

	let congestion_control = match quiche.congestion_control.controller {
		CongestionController::Cubic => wind_tuic::quiche::CongestionControl::Cubic,
		CongestionController::Bbr | CongestionController::Bbr3 => wind_tuic::quiche::CongestionControl::Bbr,
		CongestionController::NewReno => wind_tuic::quiche::CongestionControl::Reno,
	};

	let opts = wind_tuic::quiche::ConnectionOpts {
		max_idle_timeout: quiche.max_idle_time,
		max_concurrent_bi_streams: quiche.max_concurrent_bi_streams,
		max_concurrent_uni_streams: quiche.max_concurrent_uni_streams,
		send_window: quiche.send_window,
		receive_window: quiche.receive_window,
		// This (legacy) adapter uses the single `receive_window`; the
		// per-direction overrides stay unset.
		init_stream_receive_window: None,
		max_stream_receive_window: None,
		init_conn_receive_window: None,
		max_conn_receive_window: None,
		congestion_control,
		// This (legacy) adapter does not expose per-algorithm CC tuning; keep
		// quiche's defaults.
		cc: Default::default(),
		udp_relay_mode: wind_tuic::quiche::UdpRelayMode::Datagram,
		enable_0rtt: quiche.zero_rtt,
	};

	// Wire the binary's cancel token into the inbound so ctrl-c actually stops
	// the accept loop and closes live connections (mirrors the quinn backend,
	// which derives its token from `ctx.cancel` via `wind_ctx`).
	let mut builder = TuicheInboundBuilder::new()
		.listen_addr(cfg.server)
		.connection_opts(opts)
		.certificate_path(cert.clone())
		.private_key_path(key.clone())
		.masquerade(cfg.masquerade.enabled.then(|| wind_tuic::server::MasqueradeConfig {
			upstream: cfg.masquerade.upstream.clone(),
		}))
		.cancel_token(ctx.cancel.child_token());
	for (uuid, pwd) in &cfg.users {
		builder = builder.user(*uuid, pwd.clone());
	}

	tracing::info!("Initializing tokio-quiche (wind-tuiche) backend");
	let inbound = builder.build().await?;

	// For ACME, hot-reload the renewed certificate into the running listener via
	// the inbound's cert store — no restart required.
	if let Some(rx) = acme_rx {
		spawn_quiche_cert_reload(ctx, inbound.cert_store(), rx, cert, key);
	}

	Ok(inbound)
}

/// Background task: on every ACME (re)issuance, hot-reload the certificate into
/// the running quiche listener via its
/// [`CertStore`](wind_tuic::quiche::CertStore) and refresh the on-disk PEM
/// files (so a restart also picks up the latest cert).
#[cfg(feature = "quiche")]
fn spawn_quiche_cert_reload(
	ctx: &Arc<TuicAppContext>,
	store: wind_tuic::quiche::CertStore,
	mut rx: tokio::sync::watch::Receiver<Option<wind_acme::CertPem>>,
	cert_path: String,
	key_path: String,
) {
	let cancel = ctx.cancel.child_token();
	tokio::spawn(async move {
		loop {
			tokio::select! {
				_ = cancel.cancelled() => break,
				changed = rx.changed() => {
					if changed.is_err() {
						break;
					}
					let pem = rx.borrow_and_update().clone();
					let Some(pem) = pem else { continue };
					let text = match std::str::from_utf8(&pem) {
						Ok(t) => t,
						Err(_) => {
							tracing::warn!("quiche backend: renewed ACME cert PEM is not valid UTF-8");
							continue;
						}
					};
					let (certs, key) = split_pem(text);
					if certs.is_empty() || key.is_empty() {
						tracing::warn!("quiche backend: renewed ACME cert blob missing a cert or key block");
						continue;
					}
					match store.update(certs.as_bytes(), key.as_bytes()) {
						Ok(()) => tracing::info!("quiche backend: hot-reloaded renewed certificate"),
						Err(e) => tracing::warn!("quiche backend: failed to hot-reload renewed certificate: {e}"),
					}
					// Keep the on-disk files current for the next restart.
					let _ = std::fs::write(&cert_path, &certs);
					let _ = std::fs::write(&key_path, &key);
				}
			}
		}
	});
}

/// Resolve the TLS certificate + key to on-disk PEM file paths for the quiche
/// backend, handling ACME (`auto_ssl`), self-signed (`self_sign`), and explicit
/// file paths.
///
/// Returns `(cert_path, key_path, acme_rx)` where `acme_rx` is `Some` only for
/// ACME — the caller wires it to the listener's cert store for live rotation.
#[cfg(feature = "quiche")]
type CertReceiver = tokio::sync::watch::Receiver<Option<wind_acme::CertPem>>;

#[cfg(feature = "quiche")]
async fn resolve_quiche_cert_files(ctx: &Arc<TuicAppContext>) -> eyre::Result<(String, String, Option<CertReceiver>)> {
	use std::time::Duration;

	let cfg = &ctx.cfg;

	// Directory the generated/issued PEM files are written into.
	let dir = if cfg.data_dir.as_os_str().is_empty() {
		std::env::temp_dir()
	} else {
		cfg.data_dir.clone()
	};
	let _ = std::fs::create_dir_all(&dir);
	let cert_path = dir.join("wind-tuiche.cert.pem");
	let key_path = dir.join("wind-tuiche.key.pem");

	if cfg.tls.auto_ssl && crate::tls::is_valid_domain(&cfg.tls.hostname) {
		tracing::info!(
			"auto_ssl enabled for quiche backend, starting ACME management for: {} (staging: {})",
			cfg.tls.hostname,
			cfg.tls.acme_staging
		);
		let cache_dir = std::path::Path::new("acme-cache");
		let (_resolver, mut cert_rx) = wind_acme::start_acme_with_cert(
			ctx.cancel.child_token(),
			&cfg.tls.hostname,
			&cfg.tls.acme_email,
			cache_dir,
			!cfg.tls.acme_staging,
		)
		.await?;

		// The quiche backend needs the cert on disk before it can listen, so wait
		// for the first certificate (cached or freshly issued) and write it out.
		// The `cert_rx` is handed back so the caller can hot-reload renewals into
		// the running listener via its cert store.
		let pem = wait_for_cert(&mut cert_rx, Duration::from_secs(120)).await?;
		write_split_pem(&pem, &cert_path, &key_path)?;

		return Ok((path_to_string(&cert_path)?, path_to_string(&key_path)?, Some(cert_rx)));
	}

	if cfg.tls.self_sign {
		tracing::info!(
			"self_sign enabled for quiche backend, generating certificate for {}",
			cfg.tls.hostname
		);
		let (cert_pem, key_pem) = generate_self_signed_pem(&cfg.tls.hostname)?;
		std::fs::write(&cert_path, cert_pem).wrap_err_with(|| format!("writing {}", cert_path.display()))?;
		std::fs::write(&key_path, key_pem).wrap_err_with(|| format!("writing {}", key_path.display()))?;
		return Ok((path_to_string(&cert_path)?, path_to_string(&key_path)?, None));
	}

	// Explicit certificate / key file paths.
	let cert = cfg.tls.certificate.to_string_lossy();
	let key = cfg.tls.private_key.to_string_lossy();
	if cert.is_empty() || key.is_empty() {
		return Err(eyre::eyre!(
			"backend.mode = \"quiche\" requires tls.certificate and tls.private_key paths, or tls.self_sign / tls.auto_ssl"
		));
	}
	Ok((cert.into_owned(), key.into_owned(), None))
}

/// Wait for the ACME watch channel to yield a certificate, up to `timeout`.
#[cfg(feature = "quiche")]
async fn wait_for_cert(
	rx: &mut tokio::sync::watch::Receiver<Option<wind_acme::CertPem>>,
	timeout: std::time::Duration,
) -> eyre::Result<wind_acme::CertPem> {
	let deadline = tokio::time::Instant::now() + timeout;
	loop {
		if let Some(pem) = rx.borrow_and_update().clone() {
			return Ok(pem);
		}
		let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
		if remaining.is_zero() {
			return Err(eyre::eyre!("timed out waiting for ACME certificate"));
		}
		match tokio::time::timeout(remaining, rx.changed()).await {
			Ok(Ok(())) => {}
			Ok(Err(_)) => {
				return Err(eyre::eyre!(
					"ACME certificate channel closed before a certificate was available"
				));
			}
			Err(_) => return Err(eyre::eyre!("timed out waiting for ACME certificate")),
		}
	}
}

/// Generate a self-signed certificate, returning `(cert_pem, key_pem)`.
#[cfg(feature = "quiche")]
fn generate_self_signed_pem(hostname: &str) -> eyre::Result<(String, String)> {
	let generated = rcgen::generate_simple_self_signed(vec![hostname.to_string()])?;
	Ok((generated.cert.pem(), generated.signing_key.serialize_pem()))
}

/// Split a combined PEM blob (private key + certificate chain, as produced by
/// rustls-acme) into separate cert and key files. Order-independent: every
/// `PRIVATE KEY` block goes to `key_path`, every other block to `cert_path`.
#[cfg(feature = "quiche")]
fn write_split_pem(pem: &[u8], cert_path: &std::path::Path, key_path: &std::path::Path) -> eyre::Result<()> {
	let text = std::str::from_utf8(pem).wrap_err("certificate PEM is not valid UTF-8")?;
	let (certs, key) = split_pem(text);
	if certs.is_empty() || key.is_empty() {
		return Err(eyre::eyre!(
			"certificate blob is missing a certificate or private-key PEM block"
		));
	}
	std::fs::write(cert_path, certs).wrap_err_with(|| format!("writing {}", cert_path.display()))?;
	std::fs::write(key_path, key).wrap_err_with(|| format!("writing {}", key_path.display()))?;
	Ok(())
}

/// Partition PEM blocks into (certificates, private keys) by block label.
#[cfg(feature = "quiche")]
fn split_pem(blob: &str) -> (String, String) {
	let mut certs = String::new();
	let mut key = String::new();
	let mut current = String::new();
	let mut in_block = false;
	let mut is_key = false;
	for line in blob.lines() {
		if let Some(rest) = line.strip_prefix("-----BEGIN ") {
			in_block = true;
			is_key = rest.contains("PRIVATE KEY");
			current.clear();
			current.push_str(line);
			current.push('\n');
		} else if line.starts_with("-----END ") {
			current.push_str(line);
			current.push('\n');
			if is_key {
				key.push_str(&current);
			} else {
				certs.push_str(&current);
			}
			in_block = false;
		} else if in_block {
			current.push_str(line);
			current.push('\n');
		}
	}
	(certs, key)
}

#[cfg(feature = "quiche")]
fn path_to_string(p: &std::path::Path) -> eyre::Result<String> {
	p.to_str()
		.map(str::to_owned)
		.ok_or_else(|| eyre::eyre!("non-UTF-8 path: {}", p.display()))
}

fn generate_self_signed(
	hostname: &str,
) -> eyre::Result<(
	Vec<rustls::pki_types::CertificateDer<'static>>,
	rustls::pki_types::PrivateKeyDer<'static>,
)> {
	let generated = rcgen::generate_simple_self_signed(vec![hostname.to_string()])?;
	let cert_der = rustls::pki_types::CertificateDer::from(generated.cert);
	let priv_key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
	Ok((vec![cert_der], rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key)))
}

fn load_cert_from_files(
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
