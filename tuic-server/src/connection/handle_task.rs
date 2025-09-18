use std::{
    collections::hash_map::Entry,
    io::{Error as IoError, ErrorKind},
    net::{IpAddr, SocketAddr},
};

use bytes::Bytes;
use eyre::{OptionExt, eyre};
use tokio::{
    io::AsyncWriteExt,
    net::{self, TcpSocket, TcpStream},
};
use tracing::{info, warn};
use tuic::Address;
use tuic_quinn::{Authenticate, Connect, Packet};

use super::{Connection, ERROR_CODE, UdpSession};
use crate::{
    error::Error,
    io::exchange_tcp,
    restful,
    utils::{IpMode, UdpRelayMode},
};

impl Connection {
    fn get_bind_ip(&self, is_ipv6: bool) -> Option<IpAddr> {
        if is_ipv6 {
            self.ctx.cfg.outbound.default.bind_ipv6.map(IpAddr::from)
        } else {
            self.ctx.cfg.outbound.default.bind_ipv4.map(IpAddr::from)
        }
    }

    fn create_socket(&self, target_addr: &SocketAddr) -> std::io::Result<TcpSocket> {
        let socket = if target_addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(
            self.ctx
                .cfg
                .outbound
                .default
                .bind_device
                .as_ref()
                .map(|s| s.as_bytes()),
        )?;
        if let Some(bind_ip) = self.get_bind_ip(target_addr.is_ipv6()) {
            socket.bind(SocketAddr::new(bind_ip, 0))?;
        }

        Ok(socket)
    }

    pub async fn handle_authenticate(&self, auth: Authenticate) {
        info!(
            "[{id:#010x}] [{addr}] [{user}] [AUTH] {auth_uuid}",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
            auth_uuid = auth.uuid(),
        );
    }

    pub async fn handle_connect(&self, mut conn: Connect) {
        let target_addr = conn.addr().to_string();

        info!(
            "[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} ",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        let process = async {
            // Resolve DNS and collect all addresses.
            let addrs = self.resolve_and_filter_addresses(conn.addr()).await?;
            let mut stream = self.connect_to_addresses(addrs).await?;

            stream.set_nodelay(true)?;

            // a -> b tx
            // a <- b rx
            let (tx, rx, err) = exchange_tcp(&mut conn, &mut stream).await;
            if err.is_some() {
                _ = conn.reset(ERROR_CODE);
            } else {
                _ = conn.finish();
            }
            _ = stream.shutdown().await;

            let uuid = self
                .auth
                .get()
                .ok_or_eyre("Unexpected autherization state")?;
            restful::traffic_tx(&self.ctx, &uuid, tx as u64);
            restful::traffic_rx(&self.ctx, &uuid, rx as u64);
            if let Some(err) = err {
                return Err(err);
            }
            Ok(())
        };

        match process.await {
            Ok(()) => {}
            Err(err) => warn!(
                "[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr}: {err}",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
            ),
        }
    }

    async fn resolve_and_filter_addresses(&self, addr: &Address) -> eyre::Result<Vec<SocketAddr>> {
        let mut addrs: Vec<SocketAddr> = resolve_dns(addr).await?.collect();

        match self.ctx.cfg.outbound.default.ip_mode.unwrap() {
            IpMode::PreferV4 => {
                addrs.sort_by_key(|a| !a.is_ipv4());
            }
            IpMode::PreferV6 => {
                addrs.sort_by_key(|a| !a.is_ipv6());
            }
            IpMode::OnlyV4 => {
                addrs.retain(|a| a.is_ipv4());
            }
            IpMode::OnlyV6 => {
                addrs.retain(|a| a.is_ipv6());
            }
            _ => {}
        }

        if addrs.is_empty() {
            return Err(eyre!("No addresses available after filtering"));
        }

        Ok(addrs)
    }

    async fn connect_to_addresses(&self, addrs: Vec<SocketAddr>) -> eyre::Result<TcpStream> {
        let mut last_error = None;

        for addr in addrs {
            match self.create_socket(&addr) {
                Ok(socket) => match socket.connect(addr).await {
                    Ok(stream) => return Ok(stream),
                    Err(err) => last_error = Some(err),
                },
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error
            .map(|e| eyre!(e))
            .unwrap_or_else(|| eyre!("Failed to connect to any address")))
    }

    pub async fn handle_packet(&self, pkt: Packet, mode: UdpRelayMode) {
        let assoc_id = pkt.assoc_id();
        let pkt_id = pkt.pkt_id();
        let frag_id = pkt.frag_id();
        let frag_total = pkt.frag_total();

        info!(
            "[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] \
             [{pkt_id:#06x}] fragment {frag_id}/{frag_total}",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
            frag_id = frag_id + 1,
        );

        self.udp_relay_mode.store(Some(mode).into());

        let (pkt, addr, assoc_id) = match pkt.accept().await {
            Ok(None) => return,
            Ok(Some(res)) => res,
            Err(err) => {
                warn!(
                    "[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] \
                     [{pkt_id:#06x}] fragment {frag_id}/{frag_total}: {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                    frag_id = frag_id + 1,
                );
                return;
            }
        };

        let process = async {
            info!(
                "[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] \
                 [{pkt_id:#06x}] to {src_addr}",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
                src_addr = addr,
            );

            let guard = self.udp_sessions.read().await;
            let session = guard.get(&assoc_id).map(|v| v.to_owned());
            drop(guard);
            let session = match session {
                Some(v) => v,
                None => match self.udp_sessions.write().await.entry(assoc_id) {
                    Entry::Occupied(entry) => entry.get().clone(),
                    Entry::Vacant(entry) => {
                        let session = UdpSession::new(self.ctx.clone(), self.clone(), assoc_id)?;
                        entry.insert(session.clone());
                        session
                    }
                },
            };

            let Some(socket_addr) = resolve_dns(&addr).await?.next() else {
                return Err(Error::from(IoError::new(
                    ErrorKind::NotFound,
                    "no address resolved",
                )));
            };
            let uuid = self
                .auth
                .get()
                .ok_or_eyre("Unexpected autherization state")?;
            restful::traffic_tx(&self.ctx, &uuid, pkt.len() as u64);
            if let Some(session) = session.upgrade() {
                session.send(pkt, socket_addr).await
            } else {
                Err(eyre!("UdpSession dropped already").into())
            }
        };

        if let Err(err) = process.await {
            warn!(
                "[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] \
                 [{pkt_id:#06x}] to {src_addr}: {err}",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
                src_addr = addr,
            );
        }
    }

    pub async fn handle_dissociate(&self, assoc_id: u16) {
        info!(
            "[{id:#010x}] [{addr}] [{user}] [UDP-DROP] [{assoc_id:#06x}]",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        if let Some(session) = self.udp_sessions.write().await.remove(&assoc_id)
            && let Some(session) = session.upgrade()
        {
            session.close().await;
        }
    }

    pub async fn handle_heartbeat(&self) {
        info!(
            "[{id:#010x}] [{addr}] [{user}] [HB]",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );
    }

    pub async fn relay_packet(self, pkt: Bytes, addr: Address, assoc_id: u16) -> eyre::Result<()> {
        let addr_display = addr.to_string();

        info!(
            "[{id:#010x}] [{addr}] [{user}] [UDP-IN] [{assoc_id:#06x}] [to-{mode}] from {src_addr}",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
            mode = self.udp_relay_mode.load().unwrap(),
            src_addr = addr_display,
        );

        restful::traffic_rx(
            &self.ctx,
            &self.auth.get().ok_or_eyre("Unreachable")?,
            pkt.len() as u64,
        );

        let res = match self.udp_relay_mode.load().unwrap() {
            UdpRelayMode::Native => self.model.packet_native(pkt, addr, assoc_id),
            UdpRelayMode::Quic => self.model.packet_quic(pkt, addr, assoc_id).await,
        };

        if let Err(err) = res {
            warn!(
                "[{id:#010x}] [{addr}] [{user}] [UDP-IN] [{assoc_id:#06x}] [to-{mode}] from \
                 {src_addr}: {err}",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
                mode = self.udp_relay_mode.load().unwrap(),
                src_addr = addr_display,
            );
        }
        Ok(())
    }
}

async fn resolve_dns(addr: &Address) -> Result<impl Iterator<Item = SocketAddr>, IoError> {
    match addr {
        Address::None => Err(IoError::new(ErrorKind::InvalidInput, "empty address")),
        Address::DomainAddress(domain, port) => Ok(net::lookup_host((domain.as_str(), *port))
            .await?
            .collect::<Vec<_>>()
            .into_iter()),
        Address::SocketAddress(addr) => Ok(vec![*addr].into_iter()),
    }
}
