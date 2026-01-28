// Standard library imports for networking, synchronization, and timing
use std::{
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
	sync::{Arc, atomic::AtomicU32},
	time::Duration,
};

// Error handling and utility crates
use anyhow::Context;
use crossbeam_utils::atomic::AtomicCell;
use once_cell::sync::OnceCell;
use quinn::{
	AsyncUdpSocket, ClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint, EndpointConfig, TokioRuntime,
	TransportConfig, VarInt, ZeroRttAccepted,
	congestion::{BbrConfig, CubicConfig, NewRenoConfig},
	crypto::rustls::QuicClientConfig,
};
use register_count::Counter;
use rustls::{
	ClientConfig as RustlsClientConfig,
	pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
	sync::{OnceCell as AsyncOnceCell, RwLock as AsyncRwLock},
	time,
};
use tracing::{debug, info, warn};
// Importing custom QUIC connection model and side marker
use tuic_core::quinn::{Connection as Model, side};
use uuid::Uuid;

use crate::{
	config::{ProxyConfig, Relay},
	error::Error,
	utils::{self, CongestionControl, ServerAddr, UdpRelayMode},
};

mod handle_stream;
mod handle_task;
mod socks5;

use self::socks5::Socks5UdpSocket;

// Global state for endpoint, connection, and timeout
static ENDPOINT: OnceCell<AsyncRwLock<Endpoint>> = OnceCell::new();
static CONNECTION: AsyncOnceCell<AsyncRwLock<Connection>> = AsyncOnceCell::const_new();
static TIMEOUT: AtomicCell<Duration> = AtomicCell::new(Duration::from_secs(8));

/// Default error code for QUIC connection
pub const ERROR_CODE: VarInt = VarInt::from_u32(0);
/// Default maximum concurrent streams
const DEFAULT_CONCURRENT_STREAMS: u32 = 512;

/// Represents a client QUIC connection, including stream counters and
/// configuration
#[derive(Clone)]
pub struct Connection {
	/// Underlying QUIC connection
	conn: QuinnConnection,
	/// Model for handling protocol logic
	model: Model<side::Client>,
	/// Unique identifier for the connection
	uuid: Uuid,
	/// Password for authentication
	password: Arc<[u8]>,
	/// UDP relay mode
	udp_relay_mode: UdpRelayMode,
	/// Counter for remote unidirectional streams
	remote_uni_stream_cnt: Counter,
	/// Counter for remote bidirectional streams
	remote_bi_stream_cnt: Counter,
	/// Max concurrent unidirectional streams
	max_concurrent_uni_streams: Arc<AtomicU32>,
	/// Max concurrent bidirectional streams
	max_concurrent_bi_streams: Arc<AtomicU32>,
}

impl Connection {
	/// Initialize the global endpoint and connection configuration
	pub async fn set_config(cfg: Relay) -> Result<(), Error> {
		// Load certificates for TLS
		let certs = utils::load_certs(cfg.certificates, cfg.disable_native_certs)?;

		// Build TLS client config, optionally skipping certificate verification (for
		// development/testing)
		let mut crypto = if cfg.skip_cert_verify {
			#[derive(Debug)]
			struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

			impl SkipServerVerification {
				fn new() -> Arc<Self> {
					Arc::new(Self(
						rustls::crypto::CryptoProvider::get_default()
							.expect("Crypto not found")
							.clone(),
					))
				}
			}

			// Custom certificate verifier that skips all checks (dangerous, use only for
			// testing)
			impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
				fn verify_server_cert(
					&self,
					_end_entity: &CertificateDer<'_>,
					_intermediates: &[CertificateDer<'_>],
					_server_name: &ServerName<'_>,
					_ocsp: &[u8],
					_now: UnixTime,
				) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
					Ok(rustls::client::danger::ServerCertVerified::assertion())
				}

				fn verify_tls12_signature(
					&self,
					message: &[u8],
					cert: &CertificateDer<'_>,
					dss: &rustls::DigitallySignedStruct,
				) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
					rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
				}

				fn verify_tls13_signature(
					&self,
					message: &[u8],
					cert: &CertificateDer<'_>,
					dss: &rustls::DigitallySignedStruct,
				) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
					rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
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

		// Build QUIC client and transport configuration
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
            //.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(10))))
            .initial_mtu(cfg.initial_mtu)
            .min_mtu(cfg.min_mtu);

		if !cfg.gso {
			tp_cfg.enable_segmentation_offload(false);
		}
		if !cfg.pmtu {
			tp_cfg.mtu_discovery_config(None);
		}

		// Set congestion control algorithm
		match cfg.congestion_control {
			CongestionControl::Cubic => tp_cfg.congestion_controller_factory(Arc::new(CubicConfig::default())),
			CongestionControl::NewReno => tp_cfg.congestion_controller_factory(Arc::new(NewRenoConfig::default())),
			CongestionControl::Bbr => tp_cfg.congestion_controller_factory(Arc::new(BbrConfig::default())),
		};

		config.transport_config(Arc::new(tp_cfg));

		// Prepare server address and create the primary endpoint with IPv4 binding
		let server = ServerAddr::with_sni(cfg.server.0, cfg.server.1, cfg.ip, cfg.ipstack_prefer, cfg.sni);

		let (mut ep, socks5_ctrl) = if let Some(proxy_cfg) = cfg.proxy {
			debug!(
				"[relay] outgoing traffic is using socks5 proxy {}:{}",
				proxy_cfg.server.0.as_str(),
				proxy_cfg.server.1
			);

			let (ctrl, relay_addr) = socks5_handshake(&proxy_cfg).await?;
			let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
			socket.set_nonblocking(true)?;
			let socket = tokio::net::UdpSocket::from_std(socket)?;
			let ep = QuinnEndpoint::new_with_abstract_socket(
				EndpointConfig::default(),
				None,
				Arc::new(Socks5UdpSocket::new(socket, relay_addr)) as Arc<dyn AsyncUdpSocket>,
				Arc::new(TokioRuntime),
			)?;
			(ep, Some(ctrl))
		} else {
			let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
			let ep = QuinnEndpoint::new(EndpointConfig::default(), None, socket, Arc::new(TokioRuntime))?;
			(ep, None)
		};

		ep.set_default_client_config(config);

		// Store endpoint and configuration globally
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
			socks5_ctrl,
		};

		ENDPOINT
			.set(AsyncRwLock::new(ep))
			.map_err(|_| "endpoint already initialized")
			.unwrap();

		TIMEOUT.store(cfg.timeout);

		Ok(())
	}

	/// Get a connection, establishing a new one if needed
	pub async fn get_conn() -> Result<Connection, Error> {
		let try_init_conn = async { ENDPOINT.get().unwrap().read().await.connect().await.map(AsyncRwLock::new) };

		let try_get_conn = async {
			let mut conn = CONNECTION.get_or_try_init(|| try_init_conn).await?.write().await;

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

	/// Create a new Connection instance and spawn background tasks
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

		tokio::spawn(conn.clone().init(zero_rtt_accepted, heartbeat, gc_interval, gc_lifetime));

		conn
	}

	/// Initialize background tasks for authentication, heartbeat, and garbage
	/// collection
	async fn init(
		self,
		zero_rtt_accepted: Option<ZeroRttAccepted>,
		heartbeat: Duration,
		gc_interval: Duration,
		gc_lifetime: Duration,
	) {
		info!("[relay] connection established");

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

		warn!("[relay] connection error: {err}");
	}

	/// Check if the connection is closed
	fn is_closed(&self) -> bool {
		self.conn.close_reason().is_some()
	}

	/// Periodically collect garbage fragments from the model
	async fn collect_garbage(self, gc_interval: Duration, gc_lifetime: Duration) {
		loop {
			time::sleep(gc_interval).await;

			if self.is_closed() {
				break;
			}

			debug!("[relay] packet fragment garbage collecting event");
			self.model.collect_garbage(gc_lifetime);
		}
	}
}

/// Represents a QUIC endpoint and its configuration
struct Endpoint {
	ep:                 QuinnEndpoint,
	server:             ServerAddr,
	uuid:               Uuid,
	password:           Arc<[u8]>,
	udp_relay_mode:     UdpRelayMode,
	zero_rtt_handshake: bool,
	heartbeat:          Duration,
	gc_interval:        Duration,
	gc_lifetime:        Duration,
	socks5_ctrl:        Option<tokio::net::TcpStream>,
}

impl Endpoint {
	/// Establish a new QUIC connection to the server, rebinding if necessary
	/// for IP family
	async fn connect(&self) -> Result<Connection, Error> {
		let server_addr = self.server.resolve().await?.next().context("no resolved address")?;
		// Check if endpoint's local address IP family matches the server's resolved IP
		// family
		let mut need_rebind = false;
		if self.socks5_ctrl.is_none() && self.ep.local_addr()?.is_ipv4() && !server_addr.ip().is_ipv4() {
			need_rebind = true;
		}
		if need_rebind {
			// Log the IP family and binding action
			match server_addr.ip() {
				std::net::IpAddr::V4(_) => {
					warn!("[relay] Rebinding endpoint: Detected IPv4 server address, binding to 0.0.0.0:0");
					let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
					warn!("[relay] Successfully bound to IPv4 socket: {:?}", socket.local_addr().ok());
					self.ep.rebind(socket)?;
					warn!("[relay] Endpoint successfully rebound to IPv4 socket");
				}
				std::net::IpAddr::V6(_) => {
					warn!("[relay] Rebinding endpoint: Detected IPv6 server address, binding to [::]:0");
					let socket = UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))?;
					warn!("[relay] Successfully bound to IPv6 socket: {:?}", socket.local_addr().ok());
					self.ep.rebind(socket)?;
					warn!("[relay] Endpoint successfully rebound to IPv6 socket");
				}
			}
		}
		info!(
			"[relay] Connecting to server at {:?} using endpoint with local address: {:?}",
			server_addr,
			self.ep.local_addr().ok()
		);

		let connect_to = async {
			let conn = self.ep.connect(server_addr, self.server.server_name())?;
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
			Ok((conn, zero_rtt_accepted)) => Ok(Connection::new(
				conn,
				zero_rtt_accepted,
				self.udp_relay_mode,
				self.uuid,
				self.password.clone(),
				self.heartbeat,
				self.gc_interval,
				self.gc_lifetime,
			)),
			Err(err) => Err(err),
		}
	}
}

async fn socks5_handshake(proxy_cfg: &ProxyConfig) -> Result<(tokio::net::TcpStream, SocketAddr), Error> {
	use tokio::{
		io::{AsyncReadExt, AsyncWriteExt},
		net::TcpStream,
	};

	let mut stream = TcpStream::connect((proxy_cfg.server.0.as_str(), proxy_cfg.server.1))
		.await
		.map_err(|e| Error::Socks5(format!("failed to connect to proxy: {}", e)))?;

	// Greeting
	if proxy_cfg.username.is_some() {
		stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
	} else {
		stream.write_all(&[0x05, 0x01, 0x00]).await?;
	}

	let mut buf = [0u8; 2];
	stream.read_exact(&mut buf).await?;
	if buf[0] != 0x05 {
		return Err(Error::Socks5("invalid socks5 version".to_string()));
	}

	match buf[1] {
		0x00 => {} // No auth
		0x02 => {
			// Password auth
			let username = proxy_cfg.username.as_ref().unwrap();
			let password = proxy_cfg.password.as_ref().unwrap();
			let mut auth_buf = Vec::new();
			auth_buf.push(0x01); // Version
			auth_buf.push(username.len() as u8);
			auth_buf.extend_from_slice(username.as_bytes());
			auth_buf.push(password.len() as u8);
			auth_buf.extend_from_slice(password.as_bytes());
			stream.write_all(&auth_buf).await?;

			let mut auth_res = [0u8; 2];
			stream.read_exact(&mut auth_res).await?;
			if auth_res[1] != 0x00 {
				return Err(Error::Socks5("socks5 authentication failed".to_string()));
			}
		}
		0xFF => return Err(Error::Socks5("no acceptable authentication methods".to_string())),
		_ => return Err(Error::Socks5("unsupported authentication method".to_string())),
	}

	// UDP ASSOCIATE
	stream.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

	let mut res_buf = [0u8; 4];
	stream.read_exact(&mut res_buf).await?;
	if res_buf[0] != 0x05 || res_buf[1] != 0x00 {
		return Err(Error::Socks5(format!("UDP ASSOCIATE failed with status: {}", res_buf[1])));
	}

	let atyp = res_buf[3];
	let relay_addr = match atyp {
		0x01 => {
			let mut ip = [0u8; 4];
			stream.read_exact(&mut ip).await?;
			let mut port = [0u8; 2];
			stream.read_exact(&mut port).await?;
			SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port))
		}
		0x03 => {
			let mut len = [0u8; 1];
			stream.read_exact(&mut len).await?;
			let mut domain = vec![0u8; len[0] as usize];
			stream.read_exact(&mut domain).await?;
			let mut port = [0u8; 2];
			stream.read_exact(&mut port).await?;
			let domain = String::from_utf8_lossy(&domain);
			let port = u16::from_be_bytes(port);
			tokio::net::lookup_host(format!("{}:{}", domain, port))
				.await?
				.next()
				.ok_or_else(|| Error::Socks5("failed to resolve relay address".to_string()))?
		}
		0x04 => {
			let mut ip = [0u8; 16];
			stream.read_exact(&mut ip).await?;
			let mut port = [0u8; 2];
			stream.read_exact(&mut port).await?;
			SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), u16::from_be_bytes(port))
		}
		_ => return Err(Error::Socks5("unsupported address type".to_string())),
	};

	Ok((stream, relay_addr))
}
