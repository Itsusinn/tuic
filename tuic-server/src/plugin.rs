//! Wind framework [`Plugin`] for the TUIC server.
//!
//! Assembles DNS resolver, geo-database, router, outbound handlers, auth,
//! connection tracking, traffic stats, and the TUIC inbound into a single
//! composable [`App`] via [`wind_core::App`].

use std::sync::Arc;

use wind_core::{
	ActiveConnections, App, AppContext, InboundHooks, Plugin, StaticTuicAuth, StatsCollector,
	utils::StackPrefer,
};
use wind_tuic::quinn::inbound::{TuicInbound, TuicInboundOpts};


use crate::{
	Config,
	restful::{self, ConnectionTracker},
	wind_adapter::{self, ServerInbound, load_cert_from_files},
};

/// Wind framework plugin that wires a TUIC server's full runtime.
pub struct TuicServerPlugin {
	cfg: Config,
}

impl TuicServerPlugin {
	pub fn new(cfg: Config) -> Self {
		Self { cfg }
	}
}

impl Plugin for TuicServerPlugin {
	fn build(self, app: App) -> App {
		let mut cfg = self.cfg;

		// ── DNS resolver ─────────────────────────────────────────────────────
		let default_ip_mode = cfg.outbound.default.ip_mode.unwrap_or(StackPrefer::V4first);
		let resolver: Arc<dyn wind_core::Resolver> = match wind_dns::build(&cfg.dns).unwrap() {
			Some(hickory) => {
				tracing::info!("[dns] using {:?} resolver", cfg.dns.mode);
				Arc::new(hickory)
			}
			None => {
				tracing::info!("[dns] using system resolver");
				Arc::new(wind_core::SystemResolver::new(default_ip_mode))
			}
		};

		// ── Geo data (blocking io: decode + mmap) ────────────────────────────
		let geodata = load_geodata_blocking(&cfg);

		// ── Router ───────────────────────────────────────────────────────────
		let router = wind_adapter::TuicRouter::new(&cfg, resolver.clone(), geodata.clone()).unwrap();
		let app = app.set_router(router);

		// ── Outbound handlers ────────────────────────────────────────────────
		let stream_timeout = cfg.stream_timeout;
		let app = app.add_outbound("default", wind_adapter::make_outbound_action(&cfg.outbound.default, resolver.clone(), stream_timeout));
		let mut app = app;
		for (name, rule) in std::mem::take(&mut cfg.outbound.named) {
			let handler = wind_adapter::make_outbound_action(&rule, resolver.clone(), stream_timeout);
			app = app.add_outbound(name, handler);
		}

		// ── TUIC auth ────────────────────────────────────────────────────────
		let app = app.set_tuic_authenticator(Arc::new(StaticTuicAuth::from_passwords(&cfg.users)));

		// ── Hooks: stats + connection tracking + active registry ─────────────
		let stats = Arc::new(StatsCollector::new());
		let active = if cfg.restful.maximum_clients_per_user > 0 || cfg.restful.enabled {
			Some(ActiveConnections::new())
		} else {
			None
		};
		let tracker = if cfg.restful.enabled {
			Some(Arc::new(ConnectionTracker::new()))
		} else {
			None
		};

		let mut app = app;
		if let Some(t) = &tracker {
			app = app.add_connection_hooks(t.clone() as Arc<dyn wind_core::ConnectionHooks>);
		}

		// Clone values for closures.
		let active_for_inbound = active.clone();
		let stats_for_restful = stats.clone();
		let tracker_for_restful = tracker.clone();
		let users_for_restful = cfg.users.clone();
		let restful_cfg = cfg.restful.clone();
		let server = cfg.server;
		let auth_timeout = cfg.auth_timeout;
		let zero_rtt = cfg.zero_rtt_handshake;

		// ── Inbound factory ──────────────────────────────────────────────────
		match cfg.backend.mode {
			crate::config::BackendMode::Quinn => {
				let quinn = cfg.backend.quinn.clone();
				let tls_self_sign = cfg.tls.self_sign;
				let hostname = cfg.tls.hostname.clone();
				let cert_path = cfg.tls.certificate.clone();
				let key_path = cfg.tls.private_key.clone();
				let alpn = cfg.tls.alpn.clone();
				let masquerade_enabled = cfg.masquerade.enabled;
				let masquerade_upstream = cfg.masquerade.upstream.clone();

				app = app.add_inbound_with(move |hooks: InboundHooks, ctx: Arc<AppContext>| {
					let (certs, key) = if tls_self_sign {
						generate_self_signed(&hostname).expect("self-signed cert generation")
					} else {
						load_cert_from_files(&cert_path, &key_path)
							.expect("loading TLS cert/key from files")
					};
					let opts = TuicInboundOpts {
						hooks,
						active: active_for_inbound,
						listen_addr: server,
						certificate: certs,
						private_key: key,
						cert_resolver: None,
						alpn,
						users: Default::default(),
						auth_timeout,
						max_idle_time: quinn.max_idle_time,
						max_concurrent_bi_streams: 512,
						max_concurrent_uni_streams: 512,
						send_window: quinn.send_window,
						receive_window: quinn.receive_window,
						zero_rtt,
						initial_mtu: quinn.initial_mtu,
						min_mtu: quinn.min_mtu,
						gso: quinn.gso,
						congestion_control: quinn.congestion_control.controller,
						initial_window: quinn.congestion_control.initial_window,
						masquerade: masquerade_enabled.then(|| wind_tuic::server::MasqueradeConfig {
							upstream: masquerade_upstream,
						}),
						..Default::default()
					};
					ServerInbound::Tuic(TuicInbound::new(ctx, opts))
				});
			}
			crate::config::BackendMode::Quiche => {
				#[cfg(not(feature = "quiche"))]
				tracing::error!("backend.mode = \"quiche\" requires the `quiche` feature");
				return app;
			}
		}

		// ── RESTful API (spawned as a background task) ───────────────────────
		if restful_cfg.enabled {
			let rf_active: Arc<dyn restful::KickConnections> = match active {
				Some(a) => Arc::new(a) as Arc<dyn restful::KickConnections>,
				None => Arc::new(restful::NoopConnections),
			};
			let rf_state = Arc::new(restful::RestfulState {
				active: rf_active,
				stats: Some(stats_for_restful.clone()),
				tracker: tracker_for_restful.clone(),
				secret: restful_cfg.secret.clone(),
				users: users_for_restful,
			});
			let rf_addr = restful_cfg.addr;
			let rf_cancel = app.context().token.child_token();
			app.context().tasks.spawn(async move {
				if let Err(e) = restful::serve(rf_state, rf_addr, rf_cancel).await {
					tracing::warn!("RESTful API server stopped: {e}");
				}
			});
		}

		app
	}
}

// ─── Geo-data loading (blocking) ─────────────────────────────────────────────

fn load_geodata_blocking(cfg: &Config) -> Option<Arc<wind_geodata::GeoData>> {
	if !cfg.geodata.is_enabled() {
		return None;
	}
	let geosite_path = cfg.geodata.geosite.as_ref().unwrap();
	let geoip_path = cfg.geodata.geoip.as_ref().unwrap();

	let geosite_bytes = std::fs::read(geosite_path).ok()?;
	let geoip_bytes = std::fs::read(geoip_path).ok()?;

	let cache_path = cfg.data_dir.join("geodata.cache");
	match wind_geodata::GeoData::build_and_open(&geosite_bytes, &geoip_bytes, &cache_path) {
		Ok(geo) => {
			tracing::info!(
				"[geodata] loaded geosite ({}) + geoip ({})",
				geosite_path.display(),
				geoip_path.display()
			);
			Some(Arc::new(geo))
		}
		Err(e) => {
			tracing::warn!("[geodata] failed to build cache: {e}");
			None
		}
	}
}

// ─── Self-signed cert generation ─────────────────────────────────────────────

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
