use std::sync::atomic::Ordering;

use bytes::Bytes;
use quinn::{RecvStream, SendStream, VarInt};
use register_count::Register;
use tokio::time;
use tracing::{debug, warn};
use tuic_core::quinn::Task;

use super::Connection;
use crate::{error::Error, utils::UdpRelayMode};

enum UniStreamSource {
	Normal(RecvStream),
	Prefetched(RecvStream, Bytes),
}

enum BiStreamSource {
	Normal(SendStream, RecvStream),
	Prefetched(SendStream, RecvStream, Bytes),
}

impl Connection {
	pub async fn handle_uni_stream(self, recv: RecvStream, reg: Register) {
		self.handle_uni_stream_inner(UniStreamSource::Normal(recv), reg).await;
	}

	pub async fn handle_uni_stream_prefixed(self, recv: RecvStream, prefix: Bytes, reg: Register) {
		self.handle_uni_stream_inner(UniStreamSource::Prefetched(recv, prefix), reg)
			.await;
	}

	async fn handle_uni_stream_inner(self, source: UniStreamSource, reg: Register) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] incoming unidirectional stream",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		self.maybe_expand_uni_stream_limit();

		let pre_process = async {
			let task = match source {
				UniStreamSource::Normal(recv) => {
					time::timeout(self.ctx.cfg.task_negotiation_timeout, self.model.accept_uni_stream(recv))
						.await
						.map_err(|_| Error::TaskNegotiationTimeout)??
				}
				UniStreamSource::Prefetched(recv, prefix) => time::timeout(
					self.ctx.cfg.task_negotiation_timeout,
					self.model.accept_uni_stream_prefixed(recv, prefix),
				)
				.await
				.map_err(|_| Error::TaskNegotiationTimeout)??,
			};

			if let Task::Authenticate(auth) = &task {
				self.authenticate(auth).await?;
			}

			// Fast path: if already authenticated, skip the select
			if !self.auth.is_authenticated() {
				tokio::select! {
					() = self.auth.wait() => {}
					err = self.inner.closed() => return Err(Error::from(err)),
				};
			}

			let same_pkt_src =
				matches!(task, Task::Packet(_)) && matches!(**self.udp_relay_mode.load(), Some(UdpRelayMode::Native));
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
					"[{id:#010x}] [{addr}] [{user}] handling incoming unidirectional stream error: {err}",
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
		self.handle_bi_stream_inner(BiStreamSource::Normal(send, recv), reg).await;
	}

	pub async fn handle_bi_stream_prefixed(self, (send, recv): (SendStream, RecvStream), prefix: Bytes, reg: Register) {
		self.handle_bi_stream_inner(BiStreamSource::Prefetched(send, recv, prefix), reg)
			.await;
	}

	async fn handle_bi_stream_inner(self, source: BiStreamSource, reg: Register) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] incoming bidirectional stream",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		self.maybe_expand_bi_stream_limit();

		let pre_process = async {
			let task = match source {
				BiStreamSource::Normal(send, recv) => {
					time::timeout(self.ctx.cfg.task_negotiation_timeout, self.model.accept_bi_stream(send, recv))
						.await
						.map_err(|_| Error::TaskNegotiationTimeout)??
				}
				BiStreamSource::Prefetched(send, recv, prefix) => time::timeout(
					self.ctx.cfg.task_negotiation_timeout,
					self.model.accept_bi_stream_prefixed(send, recv, prefix),
				)
				.await
				.map_err(|_| Error::TaskNegotiationTimeout)??,
			};

			// Fast path: if already authenticated, skip the select
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
			Ok(_) => unreachable!(), // already filtered in `tuic_quinn`
			Err(err) => {
				warn!(
					"[{id:#010x}] [{addr}] [{user}] handling incoming bidirectional stream error: {err}",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
				);
				self.close();
			}
		}
		drop(reg);
	}

	fn maybe_expand_uni_stream_limit(&self) {
		let current_max = self.max_concurrent_uni_streams.load(Ordering::Relaxed);

		if self.remote_uni_stream_cnt.count() >= (current_max as f32 * 0.7) as usize
			&& let Ok(_) = self.max_concurrent_uni_streams.compare_exchange(
				current_max,
				current_max * 2,
				Ordering::AcqRel,
				Ordering::Acquire,
			) {
			debug!(
				"[{id:#010x}] reached max concurrent uni_streams, setting bigger limitation={num}",
				id = self.id(),
				num = current_max * 2
			);
			self.inner.set_max_concurrent_uni_streams(VarInt::from(current_max * 2));
		}
	}

	fn maybe_expand_bi_stream_limit(&self) {
		let current_max = self.max_concurrent_bi_streams.load(Ordering::Relaxed);

		if self.remote_bi_stream_cnt.count() >= (current_max as f32 * 0.7) as usize
			&& let Ok(_) = self.max_concurrent_bi_streams.compare_exchange(
				current_max,
				current_max * 2,
				Ordering::AcqRel,
				Ordering::Acquire,
			) {
			debug!(
				"[{id:#010x}] reached max concurrent bi_streams, setting bigger limitation={num}",
				id = self.id(),
				num = current_max * 2
			);
			self.inner.set_max_concurrent_bi_streams(VarInt::from(current_max * 2));
		}
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

			// Fast path: if already authenticated, skip the select
			if !self.auth.is_authenticated() {
				tokio::select! {
					() = self.auth.wait() => {}
					err = self.inner.closed() => return Err(Error::from(err)),
				};
			}

			let same_pkt_src =
				matches!(task, Task::Packet(_)) && matches!(**self.udp_relay_mode.load(), Some(UdpRelayMode::Quic));
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
