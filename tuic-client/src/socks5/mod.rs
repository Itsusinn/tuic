use std::{
	net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
	sync::atomic::{AtomicU16, Ordering},
};

use fast_socks5::{ReplyError, Socks5Command, server::Socks5ServerProtocol};
use once_cell::sync::OnceCell;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use crate::{config::Local, error::Error};

mod handle_task;
mod udp_session;

static SERVER: OnceCell<Server> = OnceCell::new();

/// SOCKS5 authentication configuration derived from the client `Local` config.
enum AuthConfig {
	NoAuth,
	Password { username: String, password: String },
}

pub struct Server {
	listener: TcpListener,
	dual_stack: Option<bool>,
	max_pkt_size: usize,
	next_assoc_id: AtomicU16,
	auth: AuthConfig,
}

impl Server {
	pub fn set_config(cfg: Local) -> Result<(), Error> {
		SERVER
			.set(Self::new(
				cfg.server,
				cfg.dual_stack,
				cfg.max_packet_size,
				cfg.username,
				cfg.password,
			)?)
			// Called more than once (SERVER already initialized): return an error
			// instead of `unwrap()`-panicking the caller.
			.map_err(|_| Error::Socks5("socks5 server already initialized".to_string()))?;

		Ok(())
	}

	fn new(
		addr: SocketAddr,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
		username: Option<Vec<u8>>,
		password: Option<Vec<u8>>,
	) -> Result<Self, Error> {
		let listener = {
			let domain = match addr {
				SocketAddr::V4(_) => Domain::IPV4,
				SocketAddr::V6(_) => Domain::IPV6,
			};

			let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
				.map_err(|err| Error::Socket("failed to create socks5 server socket", err))?;

			if addr.is_ipv6()
				&& let Some(dual_stack) = dual_stack
			{
				socket
					.set_only_v6(!dual_stack)
					.map_err(|err| Error::Socket("socks5 server dual-stack socket setting error", err))?;
			}

			socket
				.set_reuse_address(true)
				.map_err(|err| Error::Socket("failed to set socks5 server socket to reuse_address", err))?;

			socket
				.set_nonblocking(true)
				.map_err(|err| Error::Socket("failed setting socks5 server socket as non-blocking", err))?;

			socket
				.bind(&SockAddr::from(addr))
				.map_err(|err| Error::Socket("failed to bind socks5 server socket", err))?;

			socket
				.listen(i32::MAX)
				.map_err(|err| Error::Socket("failed to listen on socks5 server socket", err))?;

			TcpListener::from_std(StdTcpListener::from(socket))
				.map_err(|err| Error::Socket("failed to create socks5 server socket", err))?
		};

		// `fast_socks5` verifies credentials via a closure, so the username and
		// password are kept as UTF-8 strings. Config supplies raw bytes; lossy
		// decoding preserves the previous behaviour for well-formed credentials.
		let auth = match (username, password) {
			(Some(username), Some(password)) => AuthConfig::Password {
				username: String::from_utf8_lossy(&username).into_owned(),
				password: String::from_utf8_lossy(&password).into_owned(),
			},
			(None, None) => AuthConfig::NoAuth,
			_ => return Err(Error::InvalidSocks5Auth),
		};

		Ok(Self {
			listener,
			dual_stack,
			max_pkt_size,
			next_assoc_id: AtomicU16::new(0),
			auth,
		})
	}

	/// Accept SOCKS5 connections until `cancel` fires, then wait for in-flight
	/// session tasks to wind down (each gets a child token, so cancellation
	/// aborts handshakes and relays promptly).
	pub async fn start(cancel: CancellationToken) {
		let server = SERVER.get().unwrap();

		info!(
			"[socks5] server started, listening on {}",
			server.listener.local_addr().unwrap()
		);

		let conn_tasks = tokio_util::task::TaskTracker::new();
		loop {
			tokio::select! {
				_ = cancel.cancelled() => {
					info!("[socks5] cancellation received, shutting down");
					break;
				}
				res = server.listener.accept() => match res {
					Ok((stream, addr)) => {
						let span = tracing::info_span!("socks5", peer = %addr);
						let conn_cancel = cancel.child_token();
						conn_tasks.spawn(
							async move {
								tokio::select! {
									_ = conn_cancel.cancelled() => {
										debug!("session aborted by shutdown");
									}
									_ = Self::handle_socks5_conn(server, stream, addr) => {}
								}
							}
							.instrument(span),
						);
					}
					Err(err) => warn!("[socks5] failed to establish connection: {err}"),
				}
			}
		}
		conn_tasks.close();
		conn_tasks.wait().await;
	}

	async fn handle_socks5_conn(server: &Server, stream: TcpStream, peer_addr: SocketAddr) {
		debug!("connection established");

		// The relay UDP socket (for UDP ASSOCIATE) is bound on and reported with
		// the local IP of the accepted control connection, mirroring the previous
		// behaviour. Captured before the stream is consumed by the handshake.
		let local_ip = stream.local_addr().map(|a| a.ip()).unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

		// SOCKS5 authentication handshake.
		let proto = match &server.auth {
			AuthConfig::NoAuth => match Socks5ServerProtocol::accept_no_auth(stream).await {
				Ok(proto) => proto,
				Err(err) => {
					warn!(error = %err, "handshake error");
					return;
				}
			},
			AuthConfig::Password { username, password } => {
				match Socks5ServerProtocol::accept_password_auth(stream, |u, p| u == *username && p == *password).await {
					Ok((proto, _)) => proto,
					Err(err) => {
						warn!(error = %err, "authentication error");
						return;
					}
				}
			}
		};

		let (proto, cmd, target_addr) = match proto.read_command().await {
			Ok(res) => res,
			Err(err) => {
				warn!(error = %err, "reading command error");
				return;
			}
		};

		match cmd {
			Socks5Command::TCPConnect => {
				info!(target = %target_addr, "connect");
				Self::handle_connect(proto, target_addr, peer_addr).await;
			}
			Socks5Command::UDPAssociate => {
				let assoc_id = server.next_assoc_id.fetch_add(1, Ordering::Relaxed);
				info!(assoc_id = format_args!("{assoc_id:#06x}"), "associate");
				Self::handle_associate(proto, assoc_id, peer_addr, local_ip, server.dual_stack, server.max_pkt_size).await;
			}
			Socks5Command::TCPBind => {
				warn!("[socks5] [{peer_addr}] [bind] command not supported");
				if let Err(err) = proto.reply_error(&ReplyError::CommandNotSupported).await {
					warn!("[socks5] [{peer_addr}] [bind] command reply error: {err}");
				}
			}
		}

		debug!("connection closed");
	}
}
