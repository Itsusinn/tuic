use std::{
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};

use eyre::Context;
use quinn::{
    Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime, TransportConfig, VarInt,
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    crypto::rustls::QuicServerConfig,
};
use rustls::{
    ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::{debug, info, warn};

use crate::{
    AppContext,
    connection::{Connection, INIT_CONCURRENT_STREAMS},
    error::Error,
    tls::{
        CertResolver, is_certificate_valid, is_valid_domain, provision_acme_certificate,
        start_certificate_renewal_task,
    },
    utils::CongestionController,
};

pub struct Server {
    ep: Endpoint,
    ctx: Arc<AppContext>,
}

/// Returns the directory of the configuration file provided as `config_path`
fn get_config_dir(config_path: &std::path::Path) -> Option<std::path::PathBuf> {
    config_path.parent().map(|dir| dir.to_path_buf())
}

impl Server {
    pub async fn init(ctx: Arc<AppContext>) -> Result<Self, Error> {
        let mut crypto: RustlsServerConfig;
        let hostname = ctx.cfg.tls.hostname.clone();
        if ctx.cfg.tls.auto_ssl && is_valid_domain(hostname.as_str()) {
            warn!(
                "Attempting automatic SSL certificate provisioning for domain: {}",
                hostname
            );
            // Determine certificate and key paths
            let cert_path = if ctx.cfg.tls.certificate.as_os_str().is_empty() {
                let base_dir = ctx
                    .config_path
                    .as_ref()
                    .and_then(|path| get_config_dir(path))
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                base_dir.join(format!("{hostname}.cer.pem"))
            } else {
                ctx.cfg.tls.certificate.clone()
            };

            let key_path = if ctx.cfg.tls.private_key.as_os_str().is_empty() {
                let base_dir = ctx
                    .config_path
                    .as_ref()
                    .and_then(|path| get_config_dir(path))
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                base_dir.join(format!("{hostname}.key.pem"))
            } else {
                ctx.cfg.tls.private_key.clone()
            };

            if is_certificate_valid(&cert_path).await {
                info!(
                    "Existing ACME certificate is valid, using it instead of provisioning new one"
                );

                // Use existing valid ACME certificate
                let cert_resolver =
                    CertResolver::new(&cert_path, &key_path, Duration::from_secs(10)).await?;

                crypto =
                    RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(cert_resolver);

                // Start certificate renewal background task for existing certificate
                start_certificate_renewal_task(
                    hostname.clone(),
                    cert_path.clone(),
                    key_path.clone(),
                )
                .await;
            } else {
                info!("No valid ACME certificate found, will provision new one");

                // Attempt ACME certificate provisioning
                match provision_acme_certificate(hostname.as_str(), &cert_path, &key_path, 2).await
                {
                    Ok(()) => {
                        warn!("Successfully provisioned ACME certificate for {}", hostname);

                        // Start certificate renewal background task
                        start_certificate_renewal_task(
                            hostname.clone(),
                            cert_path.clone(),
                            key_path.clone(),
                        )
                        .await;

                        // Use the provisioned certificate
                        let cert_resolver =
                            CertResolver::new(&cert_path, &key_path, Duration::from_secs(10))
                                .await?;

                        crypto = RustlsServerConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_no_client_auth()
                        .with_cert_resolver(cert_resolver);
                    }
                    Err(e) => {
                        warn!(
                            "ACME certificate provisioning failed after 2 attempts: {}",
                            e
                        );
                        warn!("Falling back to self-signed certificate");

                        let cert =
                            rcgen::generate_simple_self_signed(vec![hostname.clone()]).unwrap();
                        let cert_pem = cert.cert.pem();
                        let cert_der = CertificateDer::from(cert.cert);
                        let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
                        if let Err(e) = tokio::fs::write(&cert_path, cert_pem).await {
                            warn!("Failed to write certificate to disk: {}", e);
                        }
                        if let Err(e) =
                            tokio::fs::write(&key_path, cert.key_pair.serialize_pem()).await
                        {
                            warn!("Failed to write key to disk: {}", e);
                        }
                        crypto = RustlsServerConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_no_client_auth()
                        .with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(priv_key))?;
                    }
                }
            }
        } else if ctx.cfg.tls.self_sign {
            let cert =
                rcgen::generate_simple_self_signed(vec![ctx.cfg.tls.hostname.clone()]).unwrap();
            let cert_der = CertificateDer::from(cert.cert);
            let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
            crypto = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(priv_key))?;
        } else {
            let cert_resolver = CertResolver::new(
                &ctx.cfg.tls.certificate,
                &ctx.cfg.tls.private_key,
                Duration::from_secs(10),
            )
            .await?;

            crypto = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_cert_resolver(cert_resolver);
        }

        crypto.alpn_protocols = ctx
            .cfg
            .tls
            .alpn
            .iter()
            .cloned()
            .map(|alpn| alpn.into_bytes())
            .collect();
        // TODO only set when 0-RTT enabled
        crypto.max_early_data_size = u32::MAX;
        crypto.send_half_rtt_data = ctx.cfg.zero_rtt_handshake;

        let mut config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(crypto).context("no initial cipher suite found")?,
        ));
        let mut tp_cfg = TransportConfig::default();

        tp_cfg
            .max_concurrent_bidi_streams(VarInt::from(INIT_CONCURRENT_STREAMS))
            .max_concurrent_uni_streams(VarInt::from(INIT_CONCURRENT_STREAMS))
            .send_window(ctx.cfg.quic.send_window)
            .stream_receive_window(VarInt::from_u32(ctx.cfg.quic.receive_window))
            .max_idle_timeout(Some(
                IdleTimeout::try_from(ctx.cfg.quic.max_idle_time)
                    .map_err(|_| Error::InvalidMaxIdleTime)?,
            ))
            .initial_mtu(ctx.cfg.quic.initial_mtu)
            .min_mtu(ctx.cfg.quic.min_mtu)
            .enable_segmentation_offload(ctx.cfg.quic.gso)
            .mtu_discovery_config(if !ctx.cfg.quic.pmtu {
                None
            } else {
                Some(Default::default())
            });

        match ctx.cfg.quic.congestion_control.controller {
            CongestionController::Bbr => {
                let mut bbr_config = BbrConfig::default();
                bbr_config.initial_window(ctx.cfg.quic.congestion_control.initial_window);
                tp_cfg.congestion_controller_factory(Arc::new(bbr_config))
            }
            CongestionController::Cubic => {
                let mut cubic_config = CubicConfig::default();
                cubic_config.initial_window(ctx.cfg.quic.congestion_control.initial_window);
                tp_cfg.congestion_controller_factory(Arc::new(cubic_config))
            }
            CongestionController::NewReno => {
                let mut new_reno = NewRenoConfig::default();
                new_reno.initial_window(ctx.cfg.quic.congestion_control.initial_window);
                tp_cfg.congestion_controller_factory(Arc::new(new_reno))
            }
        };

        config.transport_config(Arc::new(tp_cfg));

        let socket = {
            let domain = match ctx.cfg.server {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };

            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                .context("failed to create endpoint UDP socket")?;

            if ctx.cfg.dual_stack {
                socket.set_only_v6(!ctx.cfg.dual_stack).map_err(|err| {
                    Error::Socket("endpoint dual-stack socket setting error", err)
                })?;
            }

            socket
                .bind(&SockAddr::from(ctx.cfg.server))
                .context("failed to bind endpoint UDP socket")?;

            StdUdpSocket::from(socket)
        };

        let ep = Endpoint::new(
            EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(TokioRuntime),
        )?;

        Ok(Self { ep, ctx })
    }

    pub async fn start(&self) {
        warn!(
            "server started, listening on {}",
            self.ep.local_addr().unwrap()
        );
        if self.ctx.cfg.restful.is_some() {
            tokio::spawn(crate::restful::start(self.ctx.clone()));
        }

        loop {
            match self.ep.accept().await {
                Some(conn) => match conn.accept() {
                    Ok(conn) => {
                        tokio::spawn(Connection::handle(self.ctx.clone(), conn));
                    }
                    Err(e) => {
                        debug!("[Incoming] Failed to accept connection: {e}");
                    }
                },
                None => {
                    debug!("[Incoming] the endpoint is closed");
                    return;
                }
            }
        }
    }
}
