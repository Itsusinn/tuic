use std::{
	net::{SocketAddr, TcpListener as StdTcpListener},
	sync::{
		Arc,
		atomic::{AtomicU16, Ordering},
	},
};

use moka::future::Cache;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socks5_proto::{Address, Reply};
use socks5_server::{
	Auth, Connection, Server as Socks5Server,
	auth::{NoAuth, Password},
};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::error::Error;

mod handle_task;
mod udp_session;

pub use self::udp_session::UdpSession;

pub struct Server {
	inner: Socks5Server,
	dual_stack: Option<bool>,
	max_pkt_size: usize,
	next_assoc_id: AtomicU16,
}

impl Server {
	pub fn new(
		addr: SocketAddr,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
		username: Option<Vec<u8>>,
		password: Option<Vec<u8>>,
	) -> Result<Self, Error> {
		let socket = {
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

		let auth: Arc<dyn Auth + Send + Sync> = match (username, password) {
			(Some(username), Some(password)) => Arc::new(Password::new(username, password)),
			(None, None) => Arc::new(NoAuth),
			_ => return Err(Error::InvalidSocks5Auth),
		};

		Ok(Self {
			inner: Socks5Server::new(socket, auth),
			dual_stack,
			max_pkt_size,
			next_assoc_id: AtomicU16::new(0),
		})
	}

	pub async fn start(ctx: Arc<crate::AppContext>) {
		let server = match ctx.socks5.as_ref() {
			Some(s) => s.clone(),
			None => return,
		};

		warn!("[socks5] server started, listening on {}", server.inner.local_addr().unwrap());

		loop {
			match server.inner.accept().await {
				Ok((conn, addr)) => {
					debug!("[socks5] [{addr}] connection established");

					let server = server.clone();
					let ctx = ctx.clone();
					tokio::spawn(async move {
						match conn.handshake().await {
							Ok(Connection::Associate(associate, _)) => match Self::allocate_assoc_id(&server, &ctx).await {
								Some(assoc_id) => {
									info!("[socks5] [{addr}] [associate] [{assoc_id:#06x}]");
									Self::handle_associate(associate, assoc_id, server.dual_stack, server.max_pkt_size, ctx)
										.await;
								}
								None => {
									error!(
										"[socks5] [{addr}] [associate] no available assoc_id (SOCKS5 ID space [0x0000,0x7FFF] \
										 exhausted); rejecting"
									);
									if let Ok(mut assoc) = associate.reply(Reply::GeneralFailure, Address::unspecified()).await
									{
										let _ = assoc.shutdown().await;
									}
								}
							},
							Ok(Connection::Bind(bind, _)) => {
								info!("[socks5] [{addr}] [bind]");
								Self::handle_bind(bind).await;
							}
							Ok(Connection::Connect(connect, target_addr)) => {
								info!("[socks5] [{addr}] [connect] {target_addr}");
								Self::handle_connect(connect, target_addr, ctx).await;
							}
							Err(err) => warn!("[socks5] [{addr}] handshake error: {err}"),
						};

						debug!("[socks5] [{addr}] connection closed");
					});
				}
				Err(err) => warn!("[socks5] failed to establish connection: {err}"),
			}
		}
	}

	/// Allocate a fresh assoc_id in the SOCKS5 half of the 16-bit space
	/// (`0x0000..=0x7FFF`). The high half (`0x8000..=0xFFFF`) is reserved for
	/// the UDP forwarder, so the two never collide.
	///
	/// Skips IDs currently in use by the session cache. Returns `None` only
	/// when every slot in the 32K-entry space is taken (i.e. the cache is
	/// saturated by live SOCKS5 sessions), which would also be blocked by the
	/// 1024 cache cap in practice.
	async fn allocate_assoc_id(server: &Arc<Self>, ctx: &Arc<crate::AppContext>) -> Option<u16> {
		allocate_socks5_assoc_id(&server.next_assoc_id, &ctx.socks5_udp_sessions).await
	}
}

/// SOCKS5 half of the 16-bit assoc_id space.
pub(crate) const SOCKS5_ID_MASK: u16 = 0x7FFF;

/// Allocate a fresh SOCKS5 assoc_id from `counter`, skipping any ID currently
/// present in `cache`. Returns `None` after scanning all 32K slots without
/// finding a free one. Extracted so the lookup-skip + wraparound behaviour can
/// be unit-tested without standing up a full `AppContext`.
pub(crate) async fn allocate_socks5_assoc_id<V>(counter: &AtomicU16, cache: &Cache<u16, V>) -> Option<u16>
where
	V: Clone + Send + Sync + 'static,
{
	const MAX_TRIES: u32 = (SOCKS5_ID_MASK as u32) + 1;

	for _ in 0..MAX_TRIES {
		let id = counter.fetch_add(1, Ordering::Relaxed) & SOCKS5_ID_MASK;
		if !cache.contains_key(&id) {
			return Some(id);
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use moka::future::Cache;

	use super::*;

	fn build_cache(capacity: u64) -> Cache<u16, ()> {
		Cache::builder().max_capacity(capacity).build()
	}

	#[tokio::test]
	async fn assoc_id_stays_in_socks5_half() {
		let counter = AtomicU16::new(0);
		let cache: Cache<u16, ()> = build_cache(1024);

		for _ in 0..10_000 {
			let id = allocate_socks5_assoc_id(&counter, &cache).await.unwrap();
			assert!(id <= SOCKS5_ID_MASK, "id {id:#06x} outside SOCKS5 half");
		}
	}

	#[tokio::test]
	async fn assoc_id_wraps_through_high_half_back_to_low() {
		// Start the counter near a wrap so a single allocation crosses 0xFFFF -> 0x0000
		// at the raw-counter level. The mask should keep the visible id below 0x8000.
		let counter = AtomicU16::new(0xFFFE);
		let cache: Cache<u16, ()> = build_cache(8);

		let a = allocate_socks5_assoc_id(&counter, &cache).await.unwrap();
		let b = allocate_socks5_assoc_id(&counter, &cache).await.unwrap();
		let c = allocate_socks5_assoc_id(&counter, &cache).await.unwrap();
		let d = allocate_socks5_assoc_id(&counter, &cache).await.unwrap();

		for id in [a, b, c, d] {
			assert!(id <= SOCKS5_ID_MASK, "id {id:#06x} leaked into forwarder half");
		}
		// 0xFFFE & 0x7FFF = 0x7FFE, 0xFFFF & 0x7FFF = 0x7FFF,
		// 0x0000 & 0x7FFF = 0x0000, 0x0001 & 0x7FFF = 0x0001.
		assert_eq!([a, b, c, d], [0x7FFE, 0x7FFF, 0x0000, 0x0001]);
	}

	#[tokio::test]
	async fn assoc_id_skips_occupied() {
		let counter = AtomicU16::new(0);
		let cache: Cache<u16, ()> = build_cache(1024);
		cache.insert(0, ()).await;
		cache.insert(1, ()).await;
		cache.insert(2, ()).await;

		let id = allocate_socks5_assoc_id(&counter, &cache).await.unwrap();
		assert_eq!(id, 3, "should skip the three pre-inserted ids");
	}

	#[tokio::test]
	async fn assoc_id_saturated_returns_none() {
		// Cap large enough to hold the whole SOCKS5 half so no entries are evicted
		// while we fill it.
		let cap = (SOCKS5_ID_MASK as u64) + 1;
		let counter = AtomicU16::new(0);
		let cache: Cache<u16, ()> = build_cache(cap);
		for id in 0..=SOCKS5_ID_MASK {
			cache.insert(id, ()).await;
		}
		cache.run_pending_tasks().await;

		assert!(
			allocate_socks5_assoc_id(&counter, &cache).await.is_none(),
			"allocator must surrender when every SOCKS5 slot is taken"
		);
	}

	#[tokio::test]
	async fn assoc_id_freed_slot_is_reused() {
		let cap = (SOCKS5_ID_MASK as u64) + 1;
		let counter = AtomicU16::new(0);
		let cache: Cache<u16, ()> = build_cache(cap);
		for id in 0..=SOCKS5_ID_MASK {
			cache.insert(id, ()).await;
		}
		cache.run_pending_tasks().await;
		assert!(allocate_socks5_assoc_id(&counter, &cache).await.is_none());

		// Free one specific slot; the next allocation should land on it after the
		// counter sweeps back around.
		cache.invalidate(&0x0123).await;
		cache.run_pending_tasks().await;

		let id = allocate_socks5_assoc_id(&counter, &cache).await.unwrap();
		assert_eq!(id, 0x0123);
	}
}
