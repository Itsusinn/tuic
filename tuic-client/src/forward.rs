use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener as StdTcpListener},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use once_cell::sync::OnceCell;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io,
    io::AsyncWriteExt,
    net::{TcpListener, UdpSocket},
    sync::RwLock as AsyncRwLock,
};
use tracing::{debug, info, warn};
use tuic::Address as TuicAddress;

use crate::{
    config::{TcpForward, UdpForward},
    connection::Connection as TuicConnection,
    error::Error,
};

// Global UDP forward session registry
pub static UDP_SESSIONS: OnceCell<AsyncRwLock<HashMap<u16, ForwardUdpSession>>> = OnceCell::new();
static NEXT_ASSOC_ID: AtomicU16 = AtomicU16::new(0);

fn next_assoc_id() -> u16 {
    // Use high bit set to avoid collision with SOCKS5-generated assoc IDs
    0x8000 | (NEXT_ASSOC_ID.fetch_add(1, Ordering::Relaxed) & 0x7fff)
}

#[derive(Clone)]
pub struct ForwardUdpSession {
    socket: Arc<UdpSocket>,
    src_addr: SocketAddr,
    assoc_id: u16,
}

impl ForwardUdpSession {
    pub fn new(socket: Arc<UdpSocket>, src_addr: SocketAddr, assoc_id: u16) -> Self {
        Self {
            socket,
            src_addr,
            assoc_id,
        }
    }

    pub async fn send(&self, pkt: Bytes) -> Result<(), Error> {
        if let Err(err) = self.socket.send_to(&pkt, self.src_addr).await {
            warn!(
                "[forward-udp] [{assoc:#06x}] failed sending packet to {dst}: {err}",
                assoc = self.assoc_id,
                dst = self.src_addr,
            );
            return Err(Error::Io(err));
        }
        Ok(())
    }
}

pub async fn start(tcp: Vec<TcpForward>, udp: Vec<UdpForward>) {
    // Init UDP session map
    let _ = UDP_SESSIONS.set(AsyncRwLock::new(HashMap::new()));

    for entry in tcp {
        tokio::spawn(run_tcp_forwarder(entry));
    }
    for entry in udp {
        tokio::spawn(run_udp_forwarder(entry));
    }
}

async fn run_tcp_forwarder(entry: TcpForward) {
    match create_tcp_listener(entry.listen) {
        Ok(listener) => {
            warn!(
                "[forward-tcp] listening on {listen} -> {remote:?}",
                listen = listener.local_addr().unwrap(),
                remote = entry.remote
            );
            loop {
                match listener.accept().await {
                    Ok((mut inbound, peer)) => {
                        let remote = entry.remote.clone();
                        tokio::spawn(async move {
                            info!("[forward-tcp] [{peer}] connected", peer = peer);
                            let fut = async {
                                let conn = TuicConnection::get_conn().await?;
                                let remote_addr = TuicAddress::DomainAddress(remote.0, remote.1);
                                let mut relay = conn.connect(remote_addr).await?;
                                match io::copy_bidirectional(&mut inbound, &mut relay).await {
                                    Ok((_lr, _rl)) => {
                                        let _ = relay.shutdown().await;
                                    }
                                    Err(err) => {
                                        warn!("[forward-tcp] [{peer}] relay error: {err}");
                                    }
                                }
                                Ok::<(), Error>(())
                            };
                            if let Err(err) = fut.await {
                                warn!("[forward-tcp] [{peer}] error: {err}");
                            }
                            debug!("[forward-tcp] [{peer}] closed");
                        });
                    }
                    Err(err) => warn!("[forward-tcp] accept error: {err}"),
                }
            }
        }
        Err(err) => warn!("[forward-tcp] failed to bind listener: {err}"),
    }
}

fn create_tcp_listener(addr: SocketAddr) -> Result<TcpListener, Error> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|err| Error::Socket("failed to create tcp forward socket", err))?;
    socket
        .set_reuse_address(true)
        .map_err(|err| Error::Socket("failed to set tcp forward socket reuse_address", err))?;
    socket
        .set_nonblocking(true)
        .map_err(|err| Error::Socket("failed setting tcp forward socket as non-blocking", err))?;
    socket
        .bind(&SockAddr::from(addr))
        .map_err(|err| Error::Socket("failed to bind tcp forward socket", err))?;
    socket
        .listen(i32::MAX)
        .map_err(|err| Error::Socket("failed to listen on tcp forward socket", err))?;
    TcpListener::from_std(StdTcpListener::from(socket))
        .map_err(|err| Error::Socket("failed to create tcp forward socket", err))
}

async fn run_udp_forwarder(entry: UdpForward) {
    let socket = match UdpSocket::bind(entry.listen).await {
        Ok(s) => s,
        Err(err) => {
            warn!(
                "[forward-udp] failed to bind {addr}: {err}",
                addr = entry.listen
            );
            return;
        }
    };
    let socket = Arc::new(socket);
    warn!(
        "[forward-udp] listening on {listen} -> {remote:?} timeout={timeout:?}",
        listen = entry.listen,
        remote = entry.remote,
        timeout = entry.timeout
    );

    let mut buf = vec![0u8; 65535];
    // Map from client src addr to assoc_id for this forwarder instance
    let mut src_map: HashMap<SocketAddr, u16> = HashMap::new();

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src_addr)) => {
                let pkt = Bytes::copy_from_slice(&buf[..n]);
                let assoc_id = match src_map.get(&src_addr).cloned() {
                    Some(id) => id,
                    None => {
                        let id = next_assoc_id();
                        // register session
                        let session = ForwardUdpSession::new(socket.clone(), src_addr, id);
                        UDP_SESSIONS
                            .get()
                            .unwrap()
                            .write()
                            .await
                            .insert(id, session);
                        src_map.insert(src_addr, id);
                        // Spawn timeout watcher
                        tokio::spawn(expire_after(id, entry.timeout));
                        id
                    }
                };

                let remote = entry.remote.clone();
                tokio::spawn(async move {
                    match TuicConnection::get_conn().await {
                        Ok(conn) => {
                            let remote_addr = TuicAddress::DomainAddress(remote.0, remote.1);
                            if let Err(err) = conn.packet(pkt, remote_addr, assoc_id).await {
                                warn!(
                                    "[forward-udp] [{assoc:#06x}] send packet error: {err}",
                                    assoc = assoc_id
                                );
                            }
                        }
                        Err(err) => warn!("[forward-udp] failed to get relay connection: {err}"),
                    }
                });
            }
            Err(err) => warn!("[forward-udp] recv_from error: {err}"),
        }
    }
}

async fn expire_after(assoc_id: u16, timeout: Duration) {
    tokio::time::sleep(timeout).await;
    if let Some(session) = UDP_SESSIONS.get().and_then(|m| Some(m)) {
        let mut w = session.write().await;
        if let Some(_s) = w.remove(&assoc_id) {
            debug!(
                "[forward-udp] [{assoc:#06x}] timeout; dissociate",
                assoc = assoc_id
            );
            if let Ok(conn) = TuicConnection::get_conn().await {
                if let Err(err) = conn.dissociate(assoc_id).await {
                    warn!(
                        "[forward-udp] [{assoc:#06x}] dissociate error: {err}",
                        assoc = assoc_id
                    );
                }
            }
        }
    }
}
