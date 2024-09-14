use std::{
    collections::HashMap,
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use arc_swap::ArcSwap;
use quinn::{Connecting, Connection as QuinnConnection, VarInt};
use register_count::Counter;
use tokio::{sync::RwLock as AsyncRwLock, time};
use tracing::{info, warn};
use tuic_quinn::{side, Authenticate, Connection as Model};

use self::{authenticated::Authenticated, udp_session::UdpSession};
use crate::{error::Error, restful, utils::UdpRelayMode, CONFIG};

mod authenticated;
mod handle_stream;
mod handle_task;
mod udp_session;

pub const ERROR_CODE: VarInt = VarInt::from_u32(0);
pub const INIT_CONCURRENT_STREAMS: u32 = 32;

#[derive(Clone)]
pub struct Connection {
    inner: QuinnConnection,
    model: Model<side::Server>,
    auth: Authenticated,
    udp_sessions: Arc<AsyncRwLock<HashMap<u16, UdpSession>>>,
    udp_relay_mode: Arc<ArcSwap<Option<UdpRelayMode>>>,
    remote_uni_stream_cnt: Counter,
    remote_bi_stream_cnt: Counter,
    max_concurrent_uni_streams: Arc<AtomicU32>,
    max_concurrent_bi_streams: Arc<AtomicU32>,
}

#[allow(clippy::too_many_arguments)]
impl Connection {
    pub async fn handle(conn: Connecting) {
        let addr = conn.remote_address();

        let init = async {
            let conn = if CONFIG.zero_rtt_handshake {
                match conn.into_0rtt() {
                    Ok((conn, _)) => conn,
                    Err(conn) => conn.await?,
                }
            } else {
                conn.await?
            };

            Ok::<_, Error>(Self::new(conn))
        };

        match init.await {
            Ok(conn) => {
                info!(
                    "[{id:#010x}] [{addr}] [{user}] connection established",
                    id = conn.id(),
                    user = conn.auth,
                );

                tokio::spawn(conn.clone().timeout_authenticate(CONFIG.auth_timeout));
                tokio::spawn(conn.clone().collect_garbage());

                loop {
                    if conn.is_closed() {
                        break;
                    }

                    let handle_incoming = async {
                        tokio::select! {
                            res = conn.inner.accept_uni() =>
                                tokio::spawn(conn.clone().handle_uni_stream(res?, conn.remote_uni_stream_cnt.reg())),
                            res = conn.inner.accept_bi() =>
                                tokio::spawn(conn.clone().handle_bi_stream(res?, conn.remote_bi_stream_cnt.reg())),
                            res = conn.inner.read_datagram() =>
                                tokio::spawn(conn.clone().handle_datagram(res?)),
                        };

                        Ok::<_, Error>(())
                    };

                    match handle_incoming.await {
                        Ok(()) => {}
                        Err(err) if err.is_trivial() => {
                            log::debug!(
                                "[{id:#010x}] [{addr}] [{user}] {err}",
                                id = conn.id(),
                                user = conn.auth,
                            );
                        }
                        Err(err) => log::warn!(
                            "[{id:#010x}] [{addr}] [{user}] connection error: {err}",
                            id = conn.id(),
                            user = conn.auth,
                        ),
                    }
                }
            }
            Err(err) if err.is_trivial() => {
                log::debug!(
                    "[{id:#010x}] [{addr}] [unauthenticated] {err}",
                    id = u32::MAX,
                );
            }
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [unauthenticated] {err}",
                    id = u32::MAX,
                )
            }
        }
    }

    fn new(conn: QuinnConnection) -> Self {
        Self {
            inner: conn.clone(),
            model: Model::<side::Server>::new(conn),
            auth: Authenticated::new(),
            udp_sessions: Arc::new(AsyncRwLock::new(HashMap::new())),
            udp_relay_mode: Arc::new(ArcSwap::new(None.into())),
            remote_uni_stream_cnt: Counter::new(),
            remote_bi_stream_cnt: Counter::new(),
            max_concurrent_uni_streams: Arc::new(AtomicU32::new(INIT_CONCURRENT_STREAMS)),
            max_concurrent_bi_streams: Arc::new(AtomicU32::new(INIT_CONCURRENT_STREAMS)),
        }
    }

    async fn authenticate(&self, auth: &Authenticate) -> Result<(), Error> {
        if self.auth.get().is_some() {
            Err(Error::DuplicatedAuth)
        } else if CONFIG
            .users
            .get(&auth.uuid())
            .map_or(false, |password| auth.validate(password))
        {
            self.auth.set(auth.uuid()).await;
            Ok(())
        } else {
            Err(Error::AuthFailed(auth.uuid()))
        }
    }

    async fn timeout_authenticate(self, timeout: Duration) {
        time::sleep(timeout).await;

        match self.auth.get() {
            Some(uuid) => {
                restful::client_connect(&uuid);
            }
            None => {
                warn!(
                    "[{id:#010x}] [{addr}] [unauthenticated] [authenticate] timeout",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                );
                self.close();
            }
        }
    }

    async fn collect_garbage(self) {
        loop {
            time::sleep(CONFIG.gc_interval).await;

            if self.is_closed() {
                if let Some(uuid) = self.auth.get() {
                    restful::client_disconnect(&uuid);
                }
                break;
            }

            log::debug!(
                "[{id:#010x}] [{addr}] [{user}] packet fragment garbage collecting event",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
            );
            self.model.collect_garbage(CONFIG.gc_lifetime);
        }
    }

    fn id(&self) -> u32 {
        self.inner.stable_id() as u32
    }

    fn is_closed(&self) -> bool {
        self.inner.close_reason().is_some()
    }

    fn close(&self) {
        self.inner.close(ERROR_CODE, &[]);
    }
}
