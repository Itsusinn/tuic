use std::sync::atomic::Ordering;

use bytes::Bytes;
use quinn::{RecvStream, SendStream, VarInt};
use register_count::Register;
use tokio::time;
use tracing::{debug, warn};
use tuic_quinn::Task;

use super::Connection;
use crate::{error::Error, utils::UdpRelayMode};

impl Connection {
    pub async fn handle_uni_stream(self, recv: RecvStream, reg: Register) {
        debug!(
            "[{id:#010x}] [{addr}] [{user}] incoming unidirectional stream",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        let current_max = self.max_concurrent_uni_streams.load(Ordering::Relaxed);

        if self.remote_uni_stream_cnt.count() as u32 >= current_max - 1
            && let Ok(_) = self.max_concurrent_uni_streams.compare_exchange(
                current_max,
                current_max * 2,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
        {
            debug!(
                "[{id:#010x}] reached max concurrent uni_streams, setting bigger limitation={num}",
                id = self.id(),
                num = current_max * 2
            );
            self.inner
                .set_max_concurrent_uni_streams(VarInt::from(current_max * 2));
        }

        let pre_process = async {
            let task = time::timeout(
                self.ctx.cfg.task_negotiation_timeout,
                self.model.accept_uni_stream(recv),
            )
            .await
            .map_err(|_| Error::TaskNegotiationTimeout)??;

            if let Task::Authenticate(auth) = &task {
                self.authenticate(auth).await?;
            }

            tokio::select! {
                () = self.auth.wait() => {}
                err = self.inner.closed() => return Err(Error::from(err)),
            };

            let same_pkt_src = matches!(task, Task::Packet(_))
                && matches!(**self.udp_relay_mode.load(), Some(UdpRelayMode::Native));
            if same_pkt_src {
                return Err(Error::UnexpectedPacketSource);
            }

            Ok(task)
        };

        match pre_process.await {
            Ok(Task::Authenticate(auth)) => self.handle_authenticate(auth).await,
            Ok(Task::Packet(pkt)) => self.handle_packet(pkt, UdpRelayMode::Quic).await,
            Ok(Task::Dissociate(assoc_id)) => self.handle_dissociate(assoc_id).await,
            Ok(_) => unreachable!(), // already filtered in `tuic_quinn`
            Err(err) => {
                warn!(
                    "[{id:#010x}] [{addr}] [{user}] handling incoming unidirectional stream \
                     error: {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                );
                self.close();
            }
        }
        drop(reg);
    }

    pub async fn handle_bi_stream(self, (send, recv): (SendStream, RecvStream), reg: Register) {
        debug!(
            "[{id:#010x}] [{addr}] [{user}] incoming bidirectional stream",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        let current_max = self.max_concurrent_bi_streams.load(Ordering::Relaxed);

        if self.remote_bi_stream_cnt.count() as u32 >= current_max - 1
            && let Ok(_) = self.max_concurrent_bi_streams.compare_exchange(
                current_max,
                current_max * 2,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
        {
            debug!(
                "[{id:#010x}] reached max concurrent bi_streams, setting bigger limitation={num}",
                id = self.id(),
                num = current_max * 2
            );
            self.inner
                .set_max_concurrent_bi_streams(VarInt::from(current_max * 2));
        }

        let pre_process = async {
            let task = time::timeout(
                self.ctx.cfg.task_negotiation_timeout,
                self.model.accept_bi_stream(send, recv),
            )
            .await
            .map_err(|_| Error::TaskNegotiationTimeout)??;

            tokio::select! {
                () = self.auth.wait() => {}
                err = self.inner.closed() => return Err(Error::from(err)),
            };

            Ok(task)
        };

        match pre_process.await {
            Ok(Task::Connect(conn)) => self.handle_connect(conn).await,
            Ok(_) => unreachable!(), // already filtered in `tuic_quinn`
            Err(err) => {
                warn!(
                    "[{id:#010x}] [{addr}] [{user}] handling incoming bidirectional stream error: \
                     {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                );
                self.close();
            }
        }
        drop(reg);
    }

    pub async fn handle_datagram(self, dg: Bytes) {
        debug!(
            "[{id:#010x}] [{addr}] [{user}] incoming datagram",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        let pre_process = async {
            let task = self.model.accept_datagram(dg)?;

            tokio::select! {
                () = self.auth.wait() => {}
                err = self.inner.closed() => return Err(Error::from(err)),
            };

            let same_pkt_src = matches!(task, Task::Packet(_))
                && matches!(**self.udp_relay_mode.load(), Some(UdpRelayMode::Quic));
            if same_pkt_src {
                return Err(Error::UnexpectedPacketSource);
            }

            Ok(task)
        };

        match pre_process.await {
            Ok(Task::Packet(pkt)) => self.handle_packet(pkt, UdpRelayMode::Native).await,
            Ok(Task::Heartbeat) => self.handle_heartbeat().await,
            Ok(_) => unreachable!(),
            Err(err) => {
                warn!(
                    "[{id:#010x}] [{addr}] [{user}] handling incoming datagram error: {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                );
                self.close();
            }
        }
    }
}
