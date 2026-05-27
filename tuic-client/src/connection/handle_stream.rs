use bytes::Bytes;
use tracing::{debug, warn};
use tuic_core::quinn::{RecvStream, SendStream, Task};

use super::Connection;
use crate::{error::Error, utils::UdpRelayMode};

impl Connection {
	pub async fn accept_uni_stream(&self) -> Result<RecvStream, Error> {
		Ok(self.conn.accept_uni().await?)
	}

	pub async fn accept_bi_stream(&self) -> Result<(SendStream, RecvStream), Error> {
		Ok(self.conn.accept_bi().await?)
	}

	pub async fn accept_datagram(&self) -> Result<Bytes, Error> {
		Ok(self.conn.read_datagram().await?)
	}

	pub async fn handle_uni_stream(self, recv: RecvStream) {
		debug!("[relay] incoming unidirectional stream");

		let res = match self.model.accept_uni_stream(recv).await {
			Err(err) => Err(Error::Model(err)),
			Ok(Task::Packet(pkt)) => match self.udp_relay_mode {
				UdpRelayMode::Quic => {
					self.handle_packet(pkt).await;
					Ok(())
				}
				UdpRelayMode::Native => Err(Error::WrongPacketSource),
			},
			_ => unreachable!(),
		};

		if let Err(err) = res {
			warn!("[relay] incoming unidirectional stream error: {err}");
		}
	}

	pub async fn handle_bi_stream(self, send: SendStream, recv: RecvStream) {
		debug!("[relay] incoming bidirectional stream");

		let res = match self.model.accept_bi_stream(send, recv).await {
			Err(err) => Err::<(), _>(Error::Model(err)),
			_ => unreachable!(),
		};

		if let Err(err) = res {
			warn!("[relay] incoming bidirectional stream error: {err}");
		}
	}

	pub async fn handle_datagram(self, dg: Bytes) {
		debug!("[relay] incoming datagram");

		let res = match self.model.accept_datagram(dg) {
			Err(err) => Err(Error::Model(err)),
			Ok(Task::Packet(pkt)) => match self.udp_relay_mode {
				UdpRelayMode::Native => {
					self.handle_packet(pkt).await;
					Ok(())
				}
				UdpRelayMode::Quic => Err(Error::WrongPacketSource),
			},
			_ => unreachable!(),
		};

		if let Err(err) = res {
			warn!("[relay] incoming datagram error: {err}");
		}
	}
}
