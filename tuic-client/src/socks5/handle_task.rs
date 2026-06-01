use std::{io::ErrorKind, sync::Arc, time::Duration};

use socks5_proto::{Address, Reply};
use socks5_server::{
	Associate, Bind, Connect,
	connection::{associate, bind, connect},
};
use tokio::{
	io::{self, AsyncWriteExt},
	time,
};
use tracing::{debug, error, info, warn};
use tuic_core::Address as TuicAddress;

use super::{Server, udp_session::UdpSession};
use crate::{connection::ERROR_CODE, error::Error};

impl Server {
	pub async fn handle_associate(
		assoc: Associate<associate::NeedReply>,
		assoc_id: u16,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
		ctx: Arc<crate::AppContext>,
	) {
		let peer_addr = assoc.peer_addr().unwrap();
		let local_ip = assoc.local_addr().unwrap().ip();

		info!(
			"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] starting UDP associate, local_ip: {local_ip}, dual_stack: \
			 {:?}",
			dual_stack
		);

		match UdpSession::new(assoc_id, peer_addr, local_ip, dual_stack, max_pkt_size) {
			Ok(session) => {
				let local_addr = session.local_addr().unwrap();
				info!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] bound to {local_addr}");

				let mut assoc = match assoc.reply(Reply::Succeeded, Address::SocketAddress(local_addr)).await {
					Ok(assoc) => assoc,
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}");
						return;
					}
				};

				ctx.socks5_udp_sessions.insert(assoc_id, session.clone()).await;

				let idle_timeout = ctx.socks5_udp_idle_timeout;
				let ctx_loop = ctx.clone();
				let session_for_recv = session.clone();
				let handle_local_incoming_pkt = async move {
					loop {
						let (pkt, target_addr) = match session_for_recv.recv().await {
							Ok(res) => res,
							Err(Error::Io(err)) if err.kind() == ErrorKind::Other => {
								// Protocol-level rejects (wrong source addr, fragmented packet, etc.)
								// — drop this packet and keep serving the session.
								warn!(
									"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] dropping malformed UDP packet: {err}"
								);
								continue;
							}
							Err(err) => {
								// Underlying socket failure — the session is no longer functional,
								// stop the recv loop so the cleanup path runs.
								error!(
									"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] unrecoverable UDP recv error, \
									 ending session: {err}"
								);
								break;
							}
						};

						let ctx_fwd = ctx_loop.clone();
						let forward = async move {
							let target_addr = match target_addr {
								Address::DomainAddress(domain, port) => TuicAddress::DomainAddress(domain, port),
								Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
							};

							match ctx_fwd.get_conn().await {
								Ok(conn) => conn.packet(pkt, target_addr, assoc_id).await,
								Err(err) => Err(err)?,
							}
						};

						tokio::spawn(async move {
							match forward.await {
								Ok(()) => {}
								Err(err) => {
									warn!(
										"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed relaying UDP packet: \
										 {err}"
									);
								}
							}
						});
					}
				};

				// Defensive idle watcher: walks up against the session's `last_activity`
				// (touched on every send/recv) and tears the session down when no traffic
				// has flowed for the configured timeout. Protects the relay from sessions
				// stranded by clients that hold the control TCP open without ever sending
				// UDP, and reclaims the cache slot for new associations.
				let session_for_idle = session.clone();
				let idle_watcher = async move {
					if idle_timeout.is_zero() {
						std::future::pending::<()>().await;
						return;
					}
					loop {
						let idle = session_for_idle.idle_for();
						if idle >= idle_timeout {
							warn!(
								"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] idle for {idle:?} (>= \
								 {idle_timeout:?}); closing session"
							);
							return;
						}
						let remaining = idle_timeout - idle;
						time::sleep(remaining.max(Duration::from_millis(100))).await;
					}
				};

				tokio::select! {
					res = assoc.wait_until_closed() => {
						if let Err(err) = res {
							warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] associate connection error: {err}");
						}
					}
					_ = handle_local_incoming_pkt => {}
					_ = idle_watcher => {}
				}

				debug!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] stopped associating");

				// Remove may legitimately return None: the cache TTI or a parallel cleanup
				// path may have evicted the entry first. Either way the session is dead;
				// just continue to the dissociate handshake with the relay.
				if ctx.socks5_udp_sessions.remove(&assoc_id).await.is_none() {
					debug!(
						"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] session already absent from registry on cleanup"
					);
				}

				if let Ok(conn) = ctx.get_conn().await
					&& let Err(err) = conn.dissociate(assoc_id).await
				{
					warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed stopping UDP relaying session: {err}")
				}
			}
			Err(err) => {
				warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed setting up UDP associate session: {err}");

				match assoc.reply(Reply::GeneralFailure, Address::unspecified()).await {
					Ok(mut assoc) => {
						let _ = assoc.shutdown().await;
					}
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}")
					}
				}
			}
		}
	}

	pub async fn handle_bind(bind: Bind<bind::NeedFirstReply>) {
		let peer_addr = bind.peer_addr().unwrap();
		warn!("[socks5] [{peer_addr}] [bind] command not supported");

		match bind.reply(Reply::CommandNotSupported, Address::unspecified()).await {
			Ok(mut bind) => {
				let _ = bind.shutdown().await;
			}
			Err(err) => warn!("[socks5] [{peer_addr}] [bind] command reply error: {err}"),
		}
	}

	pub async fn handle_connect(conn: Connect<connect::NeedReply>, addr: Address, ctx: Arc<crate::AppContext>) {
		let peer_addr = conn.peer_addr().unwrap();
		let target_addr = match addr {
			Address::DomainAddress(domain, port) => TuicAddress::DomainAddress(domain, port),
			Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
		};

		let relay = match ctx.get_conn().await {
			Ok(conn) => conn.connect(target_addr.clone()).await,
			Err(err) => Err(err),
		};

		match relay {
			Ok(mut relay) => match conn.reply(Reply::Succeeded, Address::unspecified()).await {
				Ok(mut conn) => match io::copy_bidirectional(&mut conn, &mut relay).await {
					Ok(_) => {}
					Err(err) => {
						let _ = conn.shutdown().await;
						let _ = relay.reset(ERROR_CODE);
						warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] TCP stream relaying error: {err}");
					}
				},
				Err(err) => {
					let _ = relay.shutdown().await;
					warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] command reply error: {err}");
				}
			},
			Err(err) => {
				warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] unable to relay TCP stream: {err}");

				match conn.reply(Reply::GeneralFailure, Address::unspecified()).await {
					Ok(mut conn) => {
						let _ = conn.shutdown().await;
					}
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] command reply error: {err}")
					}
				}
			}
		}
	}
}
