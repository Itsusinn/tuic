use super::{udp_session::UdpSession, ServerInstance, UDP_SESSIONS};
use crate::connection::{Connection as TuicConnection, ERROR_CODE};
use socks5_proto::{Address, Reply};
use socks5_server::{
    connection::{associate, bind, connect},
    Associate, Bind, Connect,
};
use std::io::{Error as IoError, ErrorKind};
use tokio::io::{self, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tuic::Address as TuicAddress;

impl<A> ServerInstance<A> {
    pub async fn handle_associate(
        assoc: Associate<associate::state::NeedReply>,
        assoc_id: u16,
        dual_stack: Option<bool>,
        max_pkt_size: usize,
    ) {
        let peer_addr = assoc.peer_addr().unwrap();
        let local_ip = assoc.local_addr().unwrap().ip();

        match UdpSession::new(assoc_id, peer_addr, local_ip, dual_stack, max_pkt_size) {
            Ok(session) => {
                let local_addr = session.local_addr().unwrap();
                log::debug!(
                    "[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] bound to {local_addr}"
                );

                let mut assoc = match assoc
                    .reply(Reply::Succeeded, Address::SocketAddress(local_addr))
                    .await
                {
                    Ok(assoc) => assoc,
                    Err((err, mut conn)) => {
                        let _ = conn.shutdown().await;
                        log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}");
                        return;
                    }
                };

                UDP_SESSIONS
                    .get()
                    .unwrap()
                    .lock()
                    .insert(assoc_id, session.clone());

                let handle_local_incoming_pkt = async move {
                    loop {
                        let (pkt, target_addr) = match session.recv().await {
                            Ok(res) => res,
                            Err(err) => {
                                log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed to receive UDP packet: {err}");
                                continue;
                            }
                        };

                        let forward = async move {
                            let target_addr = match target_addr {
                                Address::DomainAddress(domain, port) => {
                                    let domain = String::from_utf8(domain).map_err(|_e| {
                                        IoError::new(ErrorKind::InvalidInput, "invalid domain")
                                    })?;
                                    TuicAddress::DomainAddress(domain, port)
                                }
                                Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
                            };

                            match TuicConnection::get().await {
                                Ok(conn) => conn.packet(pkt, target_addr, assoc_id).await,
                                Err(err) => Err(err),
                            }
                        };

                        tokio::spawn(async move {
                            match forward.await {
                                Ok(()) => {}
                                Err(err) => {
                                    log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed relaying UDP packet: {err}");
                                }
                            }
                        });
                    }
                };

                match tokio::select! {
                    res = assoc.wait_close() => res,
                    _ = handle_local_incoming_pkt => unreachable!(),
                } {
                    Ok(()) => {}
                    Err(err) => {
                        log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] associate connection error: {err}")
                    }
                }

                log::debug!(
                    "[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] stopped associating"
                );

                UDP_SESSIONS
                    .get()
                    .unwrap()
                    .lock()
                    .remove(&assoc_id)
                    .unwrap();

                let res = match TuicConnection::get().await {
                    Ok(conn) => conn.dissociate(assoc_id).await,
                    Err(err) => Err(err),
                };

                match res {
                    Ok(()) => {}
                    Err(err) => log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed stopping UDP relaying session: {err}"),
                }
            }
            Err(err) => {
                log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed setting up UDP associate session: {err}");

                match assoc
                    .reply(Reply::GeneralFailure, Address::unspecified())
                    .await
                {
                    Ok(mut assoc) => {
                        let _ = assoc.close().await;
                    }
                    Err((err, mut conn)) => {
                        let _ = conn.shutdown().await;
                        log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}");
                    }
                }
            }
        }
    }

    pub async fn handle_bind(bind: Bind<bind::state::NeedFirstReply>) {
        let peer_addr = bind.peer_addr().unwrap();
        log::warn!("[socks5] [{peer_addr}] [bind] command not supported");

        match bind
            .reply(Reply::CommandNotSupported, Address::unspecified())
            .await
        {
            Ok(mut bind) => {
                let _ = bind.close().await;
            }
            Err((err, mut conn)) => {
                let _ = conn.shutdown().await;
                log::warn!("[socks5] [{peer_addr}] [bind] command reply error: {err}");
            }
        }
    }

    pub async fn handle_connect(conn: Connect<connect::state::NeedReply>, addr: Address) {
        let peer_addr = conn.peer_addr().unwrap();

        let target_addr = match addr {
            Address::DomainAddress(domain, port) => String::from_utf8(domain)
                .map_err(|e| {
                    IoError::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "invalid domain ~`{}`",
                            String::from_utf8_lossy(e.as_bytes())
                        ),
                    )
                })
                .map(|domain| TuicAddress::DomainAddress(domain, port)),
            Address::SocketAddress(addr) => Ok(TuicAddress::SocketAddress(addr)),
        };

        let relay = match target_addr {
            Ok(target_addr) => {
                let relay_ret = match TuicConnection::get().await {
                    Ok(conn) => conn.connect(target_addr.clone()).await,
                    Err(err) => Err(err),
                };
                (relay_ret, Some(target_addr))
            }
            Err(e) => (Err(e.into()), None),
        };

        match relay {
            (Ok(relay), Some(target_addr)) => {
                let mut relay = relay.compat();

                match conn.reply(Reply::Succeeded, Address::unspecified()).await {
                    Ok(mut conn) => match io::copy_bidirectional(&mut conn, &mut relay).await {
                        Ok(_) => {}
                        Err(err) => {
                            let _ = conn.shutdown().await;
                            let _ = relay.get_mut().reset(ERROR_CODE);
                            log::warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] TCP stream relaying error: {err}");
                        }
                    },
                    Err((err, mut conn)) => {
                        let _ = conn.shutdown().await;
                        let _ = relay.shutdown().await;
                        log::warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] command reply error: {err}");
                    }
                }
            }
            (Ok(_relay), None) => unreachable!(),
            (Err(err), target_addr) => {
                let target_addr = target_addr
                    .map(|a| format!("{}", a))
                    .unwrap_or(String::from("invalid"));

                log::warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] unable to relay TCP stream: {err}");

                match conn
                    .reply(Reply::GeneralFailure, Address::unspecified())
                    .await
                {
                    Ok(mut conn) => {
                        let _ = conn.shutdown().await;
                    }
                    Err((err, mut conn)) => {
                        let _ = conn.shutdown().await;
                        log::warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] command reply error: {err}");
                    }
                }
            }
        }
    }
}
