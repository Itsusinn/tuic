use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use quinn::{
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    crypto::rustls::QuicServerConfig,
    Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime, TransportConfig, VarInt,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig as RustlsServerConfig,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use uuid::Uuid;

use crate::{
    config::Config,
    connection::{Connection, DEFAULT_CONCURRENT_STREAMS},
    error::Error,
    utils::{self, CongestionControl},
};

pub struct Server {
    ep: Endpoint,
    users: Arc<HashMap<Uuid, Box<[u8]>>>,
    udp_relay_ipv6: bool,
    zero_rtt_handshake: bool,
    auth_timeout: Duration,
    task_negotiation_timeout: Duration,
    max_external_pkt_size: usize,
    gc_interval: Duration,
    gc_lifetime: Duration,
}

impl Server {
    pub fn init(cfg: Config) -> Result<Self, Error> {
        let mut crypto: RustlsServerConfig;
        if cfg.self_sign {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert_der = CertificateDer::from(cert.cert);
            let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
            crypto = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(priv_key))?;
        } else {
            let certs = utils::load_cert_chain(&cfg.certificate)?;
            let priv_key = utils::load_priv_key(&cfg.private_key)?;
            crypto = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certs, priv_key)?;
        }

        crypto.alpn_protocols = cfg.alpn;
        // TODO only set when 0-RTT enabled
        crypto.max_early_data_size = u32::MAX;
        crypto.send_half_rtt_data = cfg.zero_rtt_handshake;

        let mut config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(crypto).context("no initial cipher suite found")?,
        ));
        let mut tp_cfg = TransportConfig::default();

        fn create_bbr_with_initial_window(initial_window: Option<u64>) -> BbrConfig {
            let mut bbr_config = BbrConfig::default();

            if let Some(window) = initial_window {
                bbr_config.initial_window(window);
            }

            bbr_config
        }

        tp_cfg
            .max_concurrent_bidi_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
            .max_concurrent_uni_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
            .send_window(cfg.send_window)
            .stream_receive_window(VarInt::from_u32(cfg.receive_window))
            .max_idle_timeout(Some(
                IdleTimeout::try_from(cfg.max_idle_time).map_err(|_| Error::InvalidMaxIdleTime)?,
            ))
            .initial_mtu(cfg.initial_mtu)
            .min_mtu(cfg.min_mtu);

        if !cfg.gso {
            tp_cfg.enable_segmentation_offload(false);
        }
        if !cfg.pmtu {
            tp_cfg.mtu_discovery_config(None);
        }

        match cfg.congestion_control {
            CongestionControl::Cubic => {
                tp_cfg.congestion_controller_factory(Arc::new(CubicConfig::default()))
            }
            CongestionControl::NewReno => {
                tp_cfg.congestion_controller_factory(Arc::new(NewRenoConfig::default()))
            }
            CongestionControl::Bbr => {
                let bbr_config = create_bbr_with_initial_window(cfg.initial_window);
                tp_cfg.congestion_controller_factory(Arc::new(bbr_config));
            }
        };

        config.transport_config(Arc::new(tp_cfg));

        let socket = {
            let domain = match cfg.server {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };

            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                .map_err(|err| Error::Socket("failed to create endpoint UDP socket", err))?;

            if let Some(dual_stack) = cfg.dual_stack {
                socket.set_only_v6(!dual_stack).map_err(|err| {
                    Error::Socket("endpoint dual-stack socket setting error", err)
                })?;
            }

            socket
                .bind(&SockAddr::from(cfg.server))
                .map_err(|err| Error::Socket("failed to bind endpoint UDP socket", err))?;

            StdUdpSocket::from(socket)
        };

        let ep = Endpoint::new(
            EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(TokioRuntime),
        )?;

        Ok(Self {
            ep,
            users: Arc::new(cfg.users),
            udp_relay_ipv6: cfg.udp_relay_ipv6,
            zero_rtt_handshake: cfg.zero_rtt_handshake,
            auth_timeout: cfg.auth_timeout,
            task_negotiation_timeout: cfg.task_negotiation_timeout,
            max_external_pkt_size: cfg.max_external_packet_size,
            gc_interval: cfg.gc_interval,
            gc_lifetime: cfg.gc_lifetime,
        })
    }

    pub async fn start(&self) {
        log::warn!(
            "server started, listening on {}",
            self.ep.local_addr().unwrap()
        );

        loop {
            match self.ep.accept().await {
                Some(conn) => match conn.accept() {
                    Ok(conn) => {
                        tokio::spawn(Connection::handle(
                            conn,
                            self.users.clone(),
                            self.udp_relay_ipv6,
                            self.zero_rtt_handshake,
                            self.auth_timeout,
                            self.task_negotiation_timeout,
                            self.max_external_pkt_size,
                            self.gc_interval,
                            self.gc_lifetime,
                        ));
                    }
                    Err(e) => {
                        log::debug!("[Incoming] Failed to accept connection: {e}");
                    }
                },
                None => {
                    log::debug!("[Incoming] ep.accept() returned None.");
                    return;
                }
            }
        }
    }
}
