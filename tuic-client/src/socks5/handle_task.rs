use socks5_proto::{Address, Reply};
use socks5_server::{
	Associate, Bind, Connect,
	connection::{associate, bind, connect},
};
use tokio::io::{self, AsyncWriteExt};
use tracing::{debug, warn};
use tuic_core::Address as TuicAddress;

use super::{Server, UDP_SESSIONS, udp_session::UdpSession};
use crate::connection::{Connection as TuicConnection, ERROR_CODE};

impl Server {
	pub async fn handle_associate(
		assoc: Associate<associate::NeedReply>,
		assoc_id: u16,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
	) {
		let peer_addr = assoc.peer_addr().unwrap();
		let local_ip = assoc.local_addr().unwrap().ip();

		match UdpSession::new(assoc_id, peer_addr, local_ip, dual_stack, max_pkt_size) {
			Ok(session) => {
				let local_addr = session.local_addr().unwrap();
				debug!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] bound to {local_addr}");

				let mut assoc = match assoc.reply(Reply::Succeeded, Address::SocketAddress(local_addr)).await {
					Ok(assoc) => assoc,
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}");
						return;
					}
				};

				UDP_SESSIONS.get().unwrap().write().await.insert(assoc_id, session.clone());

				let handle_local_incoming_pkt = async move {
					loop {
						let (pkt, target_addr) = match session.recv().await {
							Ok(res) => res,
							Err(err) => {
								warn!(
									"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed to receive UDP packet: {err}"
								);
								continue;
							}
						};

						let forward = async move {
							let target_addr = match target_addr {
								Address::DomainAddress(domain, port) => TuicAddress::DomainAddress(domain, port),
								Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
							};

							match TuicConnection::get_conn().await {
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

				match tokio::select! {
					res = assoc.wait_until_closed() => res,
					_ = handle_local_incoming_pkt => unreachable!(),
				} {
					Ok(()) => {}
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] associate connection error: {err}")
					}
				}

				debug!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] stopped associating");

				UDP_SESSIONS.get().unwrap().write().await.remove(&assoc_id).unwrap();

				if let Ok(conn) = TuicConnection::get_conn().await
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

	pub async fn handle_connect(conn: Connect<connect::NeedReply>, addr: Address) {
		let peer_addr = conn.peer_addr().unwrap();
		let target_addr = match addr {
			Address::DomainAddress(domain, port) => TuicAddress::DomainAddress(domain, port),
			Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
		};

		let relay = match TuicConnection::get_conn().await {
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
