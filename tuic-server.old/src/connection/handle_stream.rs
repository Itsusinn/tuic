use bytes::Bytes;
use tokio::time;
use tracing::{debug, warn};
use tuic_core::quinn::{StreamRx, StreamTx, Task};

use super::Connection;
use crate::{error::Error, utils::UdpRelayMode};

impl Connection {
	pub async fn handle_uni_stream<R: StreamRx>(self, recv: R) {
		debug!("incoming unidirectional stream");

		let pre_process = async {
			let task = time::timeout(self.ctx.cfg.task_negotiation_timeout, self.model.accept_uni_stream(recv))
				.await
				.map_err(|_| Error::TaskNegotiationTimeout)??;

			if let Task::Authenticate(auth) = &task {
				self.authenticate(auth).await?;
			}

			if !self.auth.is_authenticated() {
				tokio::select! {
					() = self.auth.wait() => {}
					err = self.inner.closed() => return Err(Error::from(err)),
				};
			}

			if matches!(task, Task::Packet(_)) && matches!(**self.udp_relay_mode.load(), Some(UdpRelayMode::Native)) {
				return Err(Error::UnexpectedPacketSource);
			}

			Ok(task)
		};

		match pre_process.await {
			Ok(Task::Authenticate(auth)) => self.handle_authenticate(auth).await,
			Ok(Task::Packet(pkt)) => self.handle_packet(pkt, UdpRelayMode::Quic).await,
			Ok(Task::Dissociate(assoc_id)) => self.handle_dissociate(assoc_id).await,
			Ok(_) => unreachable!(),
			Err(err) => {
				warn!("handling incoming unidirectional stream error: {err}");
				self.close();
			}
		}
	}

	pub async fn handle_bi_stream<S: StreamTx, R: StreamRx>(self, (send, recv): (S, R)) {
		debug!("incoming bidirectional stream");

		let pre_process = async {
			let task = time::timeout(self.ctx.cfg.task_negotiation_timeout, self.model.accept_bi_stream(send, recv))
				.await
				.map_err(|_| Error::TaskNegotiationTimeout)??;

			if !self.auth.is_authenticated() {
				tokio::select! {
					() = self.auth.wait() => {}
					err = self.inner.closed() => return Err(Error::from(err)),
				};
			}

			Ok(task)
		};

		match pre_process.await {
			Ok(Task::Connect(conn)) => self.handle_connect(conn).await,
			Ok(_) => unreachable!(),
			Err(err) => {
				warn!("handling incoming bidirectional stream error: {err}");
				self.close();
			}
		}
	}

	pub async fn handle_datagram(self, dg: Bytes) {
		debug!("incoming datagram");

		let pre_process = async {
			let task = self.model.accept_datagram(dg)?;

			if !self.auth.is_authenticated() {
				tokio::select! {
					() = self.auth.wait() => {}
					err = self.inner.closed() => return Err(Error::from(err)),
				};
			}

			if matches!(task, Task::Packet(_)) && matches!(**self.udp_relay_mode.load(), Some(UdpRelayMode::Quic)) {
				return Err(Error::UnexpectedPacketSource);
			}

			Ok(task)
		};

		match pre_process.await {
			Ok(Task::Packet(pkt)) => self.handle_packet(pkt, UdpRelayMode::Native).await,
			Ok(Task::Heartbeat) => self.handle_heartbeat().await,
			Ok(_) => unreachable!(),
			Err(err) => {
				warn!("handling incoming datagram error: {err}");
				self.close();
			}
		}
	}
}
