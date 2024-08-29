use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use anyhow::Context;
use crossbeam_utils::atomic::AtomicCell;
use once_cell::sync::OnceCell;
use quinn::{
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
    ClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint, EndpointConfig,
    TokioRuntime, TransportConfig, VarInt, ZeroRttAccepted,
};
use register_count::Counter;
use rustls::{
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig as RustlsClientConfig,
};
use tokio::{
    sync::{OnceCell as AsyncOnceCell, RwLock as AsyncRwLock},
    time,
};
use tuic_quinn::{side, Connection as Model};
use uuid::Uuid;

use crate::{
    config::Relay,
    error::Error,
    utils::{self, CongestionControl, ServerAddr, UdpRelayMode},
};

mod handle_stream;
mod handle_task;

static ENDPOINT: OnceCell<AsyncRwLock<Endpoint>> = OnceCell::new();
static CONNECTION: AsyncOnceCell<AsyncRwLock<Connection>> = AsyncOnceCell::const_new();
static TIMEOUT: AtomicCell<Duration> = AtomicCell::new(Duration::from_secs(0));

pub const ERROR_CODE: VarInt = VarInt::from_u32(0);
const DEFAULT_CONCURRENT_STREAMS: u32 = 512;

#[derive(Clone)]
pub struct Connection {
    conn: QuinnConnection,
    model: Model<side::Client>,
    uuid: Uuid,
    password: Arc<[u8]>,
    udp_relay_mode: UdpRelayMode,
    remote_uni_stream_cnt: Counter,
    remote_bi_stream_cnt: Counter,
    max_concurrent_uni_streams: Arc<AtomicU32>,
    max_concurrent_bi_streams: Arc<AtomicU32>,
}

impl Connection {
    pub async fn set_config(cfg: Relay) -> Result<(), Error> {
        let certs = utils::load_certs(cfg.certificates, cfg.disable_native_certs)?;

        let mut crypto = if cfg.skip_cert_verify {
            #[derive(Debug)]
            struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

            impl SkipServerVerification {
                fn new() -> Arc<Self> {
                    Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
                }
            }

            impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
                fn verify_server_cert(
                    &self,
                    _end_entity: &CertificateDer<'_>,
                    _intermediates: &[CertificateDer<'_>],
                    _server_name: &ServerName<'_>,
                    _ocsp: &[u8],
                    _now: UnixTime,
                ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error>
                {
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                }

                fn verify_tls12_signature(
                    &self,
                    message: &[u8],
                    cert: &CertificateDer<'_>,
                    dss: &rustls::DigitallySignedStruct,
                ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
                {
                    rustls::crypto::verify_tls12_signature(
                        message,
                        cert,
                        dss,
                        &self.0.signature_verification_algorithms,
                    )
                }

                fn verify_tls13_signature(
                    &self,
                    message: &[u8],
                    cert: &CertificateDer<'_>,
                    dss: &rustls::DigitallySignedStruct,
                ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
                {
                    rustls::crypto::verify_tls13_signature(
                        message,
                        cert,
                        dss,
                        &self.0.signature_verification_algorithms,
                    )
                }

                fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                    self.0.signature_verification_algorithms.supported_schemes()
                }
            }
            RustlsClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new())
                .with_no_client_auth()
        } else {
            RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(certs)
                .with_no_client_auth()
        };

        crypto.alpn_protocols = cfg.alpn;
        crypto.enable_early_data = true;
        crypto.enable_sni = !cfg.disable_sni;

        let mut config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).context("no initial cipher suite found")?,
        ));
        let mut tp_cfg = TransportConfig::default();

        tp_cfg
            .max_concurrent_bidi_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
            .max_concurrent_uni_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
            .send_window(cfg.send_window)
            .stream_receive_window(VarInt::from_u32(cfg.receive_window))
            .max_idle_timeout(None)
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
                tp_cfg.congestion_controller_factory(Arc::new(BbrConfig::default()))
            }
        };

        config.transport_config(Arc::new(tp_cfg));

        let server = ServerAddr::new(cfg.server.0, cfg.server.1, cfg.ip);
        let server_ip: Option<IpAddr> = match server.resolve().await?.next() {
            Some(SocketAddr::V4(v4)) => Some(v4.ip().to_owned().into()),
            Some(SocketAddr::V6(v6)) => Some(v6.ip().to_owned().into()),
            None => None,
        };
        let server_ip = server_ip.expect("Server ip not found");
        let socket = if server_ip.is_ipv4() {
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?
        } else {
            UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))?
        };

        let mut ep = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )?;

        ep.set_default_client_config(config);

        let ep = Endpoint {
            ep,
            server,
            uuid: cfg.uuid,
            password: cfg.password,
            udp_relay_mode: cfg.udp_relay_mode,
            zero_rtt_handshake: cfg.zero_rtt_handshake,
            heartbeat: cfg.heartbeat,
            gc_interval: cfg.gc_interval,
            gc_lifetime: cfg.gc_lifetime,
        };

        ENDPOINT
            .set(AsyncRwLock::new(ep))
            .map_err(|_| "endpoint already initialized")
            .unwrap();

        TIMEOUT.store(cfg.timeout);

        Ok(())
    }

    pub async fn get_conn() -> Result<Connection, Error> {
        let try_init_conn = async {
            ENDPOINT
                .get()
                .unwrap()
                .read()
                .await
                .connect()
                .await
                .map(AsyncRwLock::new)
        };

        let try_get_conn = async {
            let mut conn = CONNECTION
                .get_or_try_init(|| try_init_conn)
                .await?
                .write()
                .await;

            if conn.is_closed() {
                let new_conn = ENDPOINT.get().unwrap().read().await.connect().await?;
                *conn = new_conn;
            }

            Ok::<_, Error>(conn.clone())
        };

        let conn = time::timeout(TIMEOUT.load(), try_get_conn)
            .await
            .map_err(|_| Error::Timeout)??;

        Ok(conn)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        conn: QuinnConnection,
        zero_rtt_accepted: Option<ZeroRttAccepted>,
        udp_relay_mode: UdpRelayMode,
        uuid: Uuid,
        password: Arc<[u8]>,
        heartbeat: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) -> Self {
        let conn = Self {
            conn: conn.clone(),
            model: Model::<side::Client>::new(conn),
            uuid,
            password,
            udp_relay_mode,
            remote_uni_stream_cnt: Counter::new(),
            remote_bi_stream_cnt: Counter::new(),
            max_concurrent_uni_streams: Arc::new(AtomicU32::new(DEFAULT_CONCURRENT_STREAMS)),
            max_concurrent_bi_streams: Arc::new(AtomicU32::new(DEFAULT_CONCURRENT_STREAMS)),
        };

        tokio::spawn(
            conn.clone()
                .init(zero_rtt_accepted, heartbeat, gc_interval, gc_lifetime),
        );

        conn
    }

    async fn init(
        self,
        zero_rtt_accepted: Option<ZeroRttAccepted>,
        heartbeat: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) {
        log::info!("[relay] connection established");

        tokio::spawn(self.clone().authenticate(zero_rtt_accepted));
        tokio::spawn(self.clone().heartbeat(heartbeat));
        tokio::spawn(self.clone().collect_garbage(gc_interval, gc_lifetime));

        let err = loop {
            tokio::select! {
                res = self.accept_uni_stream() => match res {
                    Ok((recv, reg)) => tokio::spawn(self.clone().handle_uni_stream(recv, reg)),
                    Err(err) => break err,
                },
                res = self.accept_bi_stream() => match res {
                    Ok((send, recv, reg)) => tokio::spawn(self.clone().handle_bi_stream(send, recv, reg)),
                    Err(err) => break err,
                },
                res = self.accept_datagram() => match res {
                    Ok(dg) => tokio::spawn(self.clone().handle_datagram(dg)),
                    Err(err) => break err,
                },
            };
        };

        log::warn!("[relay] connection error: {err}");
    }

    fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    async fn collect_garbage(self, gc_interval: Duration, gc_lifetime: Duration) {
        loop {
            time::sleep(gc_interval).await;

            if self.is_closed() {
                break;
            }

            log::debug!("[relay] packet fragment garbage collecting event");
            self.model.collect_garbage(gc_lifetime);
        }
    }
}

struct Endpoint {
    ep: QuinnEndpoint,
    server: ServerAddr,
    uuid: Uuid,
    password: Arc<[u8]>,
    udp_relay_mode: UdpRelayMode,
    zero_rtt_handshake: bool,
    heartbeat: Duration,
    gc_interval: Duration,
    gc_lifetime: Duration,
}

impl Endpoint {
    async fn connect(&self) -> Result<Connection, Error> {
        let mut last_err = None;

        for addr in self.server.resolve().await? {
            let connect_to = async {
                let conn = self.ep.connect(addr, self.server.server_name())?;
                let (conn, zero_rtt_accepted) = if self.zero_rtt_handshake {
                    match conn.into_0rtt() {
                        Ok((conn, zero_rtt_accepted)) => (conn, Some(zero_rtt_accepted)),
                        Err(conn) => (conn.await?, None),
                    }
                } else {
                    (conn.await?, None)
                };

                Ok((conn, zero_rtt_accepted))
            };

            match connect_to.await {
                Ok((conn, zero_rtt_accepted)) => {
                    return Ok(Connection::new(
                        conn,
                        zero_rtt_accepted,
                        self.udp_relay_mode,
                        self.uuid,
                        self.password.clone(),
                        self.heartbeat,
                        self.gc_interval,
                        self.gc_lifetime,
                    ));
                }
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or(Error::DnsResolve))
    }
}
