//! Wind framework [`Plugin`] for the TUIC server.
//!
//! Assembles DNS resolver, geo-database, router, outbound handlers, auth,
//! connection tracking, traffic stats, and the TUIC inbound into a single
//! composable [`App`] via [`wind_core::App`].

use std::sync::Arc;

use eyre::Context;
use wind_acme;
use wind_core::{ActiveConnections, App, AppContext, InboundHooks, Plugin, StaticTuicAuth, StatsCollector, utils::StackPrefer};
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
	async fn build(self, app: App) -> eyre::Result<App> {
		let mut cfg = self.cfg;

		// DNS resolver
		let default_ip_mode = cfg.outbound.default.ip_mode.unwrap_or(StackPrefer::V4first);
		let resolver: Arc<dyn wind_core::Resolver> = match wind_dns::build(&cfg.dns)? {
			Some(hickory) => {
				tracing::info!("[dns] using {:?} resolver", cfg.dns.mode);
				Arc::new(hickory)
			}
			None => {
				tracing::info!("[dns] using system resolver");
				Arc::new(wind_core::SystemResolver::new(default_ip_mode))
			}
		};

		// Geo data (blocking io: decode + mmap)
		let geodata = load_geodata_blocking(&cfg);

		// Router
		let router = wind_adapter::TuicRouter::new(&cfg, resolver.clone(), geodata.clone())?;
		let app = app.set_router(router);

		// Outbound handlers
		let stream_timeout = cfg.stream_timeout;
		let app = app.add_outbound(
			"default",
			wind_adapter::make_outbound_action(&cfg.outbound.default, resolver.clone(), stream_timeout),
		);
		let mut app = app;
		for (name, rule) in std::mem::take(&mut cfg.outbound.named) {
			let handler = wind_adapter::make_outbound_action(&rule, resolver.clone(), stream_timeout);
			app = app.add_outbound(name, handler);
		}

		// TUIC auth
		let app = app.set_tuic_authenticator(Arc::new(StaticTuicAuth::from_passwords(&cfg.users)));

		// Hooks: stats + connection tracking + active registry
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

		// Inbound factory
		match cfg.backend.mode {
			crate::config::BackendMode::Quinn => {
				let quinn = cfg.backend.quinn.clone();
				let tls_self_sign = cfg.tls.self_sign;
				let hostname = cfg.tls.hostname.clone();
				let cert_path = cfg.tls.certificate.clone();
				let key_path = cfg.tls.private_key.clone();
				let alpn = cfg.tls.alpn.clone();
				let auto_ssl = cfg.tls.auto_ssl;
				let acme_staging = cfg.tls.acme_staging;
				let acme_email = cfg.tls.acme_email.clone();
				let masquerade_enabled = cfg.masquerade.enabled;
				let masquerade_upstream = cfg.masquerade.upstream.clone();

				// ACME: obtain cert resolver outside the non-async closure so we can
				// call the async `start_acme_with_cert`.  The resolver is passed into
				// closure via `cert_resolver`; the `certificate`/`private_key` fields
				// are set to placeholders — `create_server_config` uses the resolver
				// when it is `Some`, bypassing the file-based cert path entirely.
				let cert_resolver: Option<std::sync::Arc<dyn rustls::server::ResolvesServerCert>> =
					if auto_ssl && !tls_self_sign {
						match wind_acme::start_acme_with_cert(
							app.context().token.child_token(),
							&hostname,
							&acme_email,
							&cfg.data_dir,
							!acme_staging,
						)
						.await
						{
							Ok((resolver, _cert_rx)) => {
								tracing::info!("[acme] certificate resolver ready for {hostname}");
								Some(resolver)
							}
							Err(e) => {
								tracing::error!("[acme] failed to start ACME for {hostname}: {e:#}");
								return Err(e);
							}
						}
					} else {
						None
					};

				// Build TLS provider outside the closure so we can use `?` for
				// error propagation (build now returns Result<App>).
				let tls_provider: wind_tuic::quinn::inbound::TlsProvider = if let Some(resolver) = cert_resolver {
					wind_tuic::quinn::inbound::TlsProvider::Resolver(resolver)
				} else if tls_self_sign {
					let (certs, key) = generate_self_signed(&hostname).context("self-signed cert generation")?;
					wind_tuic::quinn::inbound::TlsProvider::Files {
						certificate: certs,
						private_key: key,
					}
				} else {
					let (certs, key) = load_cert_from_files(&cert_path, &key_path).with_context(|| {
						format!("loading TLS cert/key from {} / {}", cert_path.display(), key_path.display())
					})?;
					wind_tuic::quinn::inbound::TlsProvider::Files {
						certificate: certs,
						private_key: key,
					}
				};

				app = app.add_inbound_with(move |hooks: InboundHooks, ctx: Arc<AppContext>| {
					let opts = TuicInboundOpts {
						hooks,
						active: active_for_inbound,
						listen_addr: server,
						tls: tls_provider.clone(),
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
						masquerade: masquerade_enabled.then_some(wind_tuic::server::MasqueradeConfig {
							upstream: masquerade_upstream,
						}),
						..Default::default()
					};
					ServerInbound::Tuic(TuicInbound::new(ctx, opts))
				});
			}
			crate::config::BackendMode::Quiche => {
				#[cfg(not(feature = "quiche"))]
				{
					tracing::error!("backend.mode = \"quiche\" requires the `quiche` feature");
					return Err(eyre::eyre!("backend.mode = \"quiche\" requires the `quiche` feature"));
				}
				#[cfg(feature = "quiche")]
				{
					use wind_tuic::quiche::{CertStore, CongestionControl as QuicheCC, ConnectionOpts, TuicheInbound};

					let quiche_cfg = cfg.backend.quiche.clone();
					let tls_self_sign = cfg.tls.self_sign;
					let hostname = cfg.tls.hostname.clone();
					let cert_path = cfg.tls.certificate.clone();
					let key_path = cfg.tls.private_key.clone();
					let auto_ssl = cfg.tls.auto_ssl;
					let acme_staging = cfg.tls.acme_staging;
					let acme_email = cfg.tls.acme_email.clone();
					let masquerade_enabled = cfg.masquerade.enabled;
					let masquerade_upstream = cfg.masquerade.upstream.clone();
					let users = cfg.users.clone();

					let cc = match quiche_cfg.congestion_control.controller {
						wind_tuic::quinn::CongestionControl::Cubic => QuicheCC::Cubic,
						wind_tuic::quinn::CongestionControl::Bbr | wind_tuic::quinn::CongestionControl::Bbr3 => QuicheCC::Bbr,
						wind_tuic::quinn::CongestionControl::NewReno => QuicheCC::Reno,
					};

					let opts = ConnectionOpts {
						max_idle_timeout: quiche_cfg.max_idle_time,
						max_concurrent_bi_streams: quiche_cfg.max_concurrent_bi_streams,
						max_concurrent_uni_streams: quiche_cfg.max_concurrent_uni_streams,
						send_window: quiche_cfg.send_window,
						receive_window: quiche_cfg.receive_window,
						congestion_control: cc,
						enable_0rtt: quiche_cfg.zero_rtt || zero_rtt,
						..Default::default()
					};

					// ACME: provision cert to disk via HTTP-01 so the file-based
					// quiche backend can consume it.
					if auto_ssl && !tls_self_sign {
						match wind_acme::http01::ensure_acme_cert(
							&hostname,
							if acme_email.is_empty() { None } else { Some(&acme_email) },
							&cert_path,
							&key_path,
							acme_staging,
						)
						.await
						{
							Ok(()) => {
								tracing::info!("[acme] certificate provisioned for {hostname}");
							}
							Err(e) => {
								tracing::error!("[acme] failed to provision certificate for {hostname}: {e:#}");
								return Err(e);
							}
						}
					}

					let quiche_dir = std::env::temp_dir().join("tuic-server-quiche");
					std::fs::create_dir_all(&quiche_dir)
						.with_context(|| format!("create quiche temp cert dir {}", quiche_dir.display()))?;
					let quiche_cert_path = quiche_dir.join("cert.pem");
					let quiche_key_path = quiche_dir.join("key.pem");

					if tls_self_sign {
						let generated = rcgen::generate_simple_self_signed(vec![hostname.clone()])
							.with_context(|| format!("quiche self-signed cert generation for {hostname}"))?;
						std::fs::write(&quiche_cert_path, generated.cert.pem())
							.with_context(|| format!("write quiche cert.pem to {}", quiche_cert_path.display()))?;
						std::fs::write(&quiche_key_path, generated.signing_key.serialize_pem())
							.with_context(|| format!("write quiche key.pem to {}", quiche_key_path.display()))?;
					} else {
						std::fs::copy(&cert_path, &quiche_cert_path).with_context(|| {
							format!(
								"copy quiche cert from {} to {}",
								cert_path.display(),
								quiche_cert_path.display()
							)
						})?;
						std::fs::copy(&key_path, &quiche_key_path).with_context(|| {
							format!("copy quiche key from {} to {}", key_path.display(), quiche_key_path.display())
						})?;
					}

					let cert_pem = std::fs::read(&quiche_cert_path)
						.with_context(|| format!("read quiche cert.pem {}", quiche_cert_path.display()))?;
					let key_pem = std::fs::read(&quiche_key_path)
						.with_context(|| format!("read quiche key.pem {}", quiche_key_path.display()))?;
					let cert_store =
						CertStore::from_pem(&cert_pem, &key_pem).map_err(|e| eyre::eyre!("create quiche cert store: {e}"))?;

					let quiche_cert_path_s = quiche_cert_path.to_string_lossy().into_owned();
					let quiche_key_path_s = quiche_key_path.to_string_lossy().into_owned();

					app = app.add_inbound_with(move |hooks: InboundHooks, ctx: Arc<AppContext>| {
						let cancel = ctx.token.child_token();
						ServerInbound::Tuiche(TuicheInbound::new(
							server,
							users,
							opts,
							quiche_cert_path_s,
							quiche_key_path_s,
							cert_store,
							cancel,
							masquerade_enabled.then_some(wind_tuic::server::MasqueradeConfig {
								upstream: masquerade_upstream,
							}),
							hooks,
							active_for_inbound,
						))
					});
				}
			}
		}

		// RESTful API (spawned as a background task)
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

		Ok(app)
	}
}

// Geo-data loading (blocking)

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

// Self-signed cert generation

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
