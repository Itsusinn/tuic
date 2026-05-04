use std::{
	sync::{Arc, atomic::AtomicU32},
	time::Duration,
};

use arc_swap::ArcSwap;
use bytes::Bytes;
use moka::future::Cache;
use peekable::tokio::AsyncPeekExt;
use quinn::{Connecting, Connection as QuinnConnection, VarInt};
use register_count::Counter;
use smallvec::SmallVec;
use tokio::time;
use tracing::{Instrument, Span, debug, info, info_span, warn};
use tuic_core::quinn::{Authenticate, Connection as Model, side};

use self::{authenticated::Authenticated, udp_session::UdpSession};
use crate::{AppContext, camouflage, error::Error, restful, utils::UdpRelayMode};

mod authenticated;
mod handle_stream;
mod handle_task;
mod udp_session;

pub const ERROR_CODE: VarInt = VarInt::from_u32(0);
pub const INIT_CONCURRENT_STREAMS: u32 = 512;

enum H3Dispatch {
	Tuic(Option<PrefetchedFirstEventTuic>),
	Camouflage {
		prefetched_uni: Option<crate::h3_quinn_compat::PeekableRecvStream>,
		prefetched_bi:  Option<crate::h3_quinn_compat::PrefetchedBiRecv>,
	},
}

enum FirstEvent {
	Uni(quinn::RecvStream),
	Bi(quinn::SendStream, quinn::RecvStream),
	Datagram(Bytes),
}

enum ClassifiedRecvStream {
	Tuic(crate::h3_quinn_compat::PeekableRecvStream),
	Camouflage(crate::h3_quinn_compat::PeekableRecvStream),
}

enum PrefetchedFirstEventTuic {
	Uni(crate::h3_quinn_compat::PeekableRecvStream),
	Bi {
		send: quinn::SendStream,
		recv: crate::h3_quinn_compat::PeekableRecvStream,
	},
	Datagram(Bytes),
}

#[derive(Clone)]
pub struct Connection {
	ctx: Arc<AppContext>,
	inner: QuinnConnection,
	model: Model<side::Server>,
	auth: Authenticated,
	udp_sessions: Cache<u16, Arc<UdpSession>>,
	udp_relay_mode: Arc<ArcSwap<Option<UdpRelayMode>>>,
	remote_uni_stream_cnt: Counter,
	remote_bi_stream_cnt: Counter,
	max_concurrent_uni_streams: Arc<AtomicU32>,
	max_concurrent_bi_streams: Arc<AtomicU32>,
}

impl Connection {
	pub async fn handle(ctx: Arc<AppContext>, conn: Connecting) {
		let peer_addr = conn.remote_address();

		let init = async {
			let conn = if ctx.cfg.zero_rtt_handshake {
				match conn.into_0rtt() {
					Ok((conn, _)) => conn,
					Err(conn) => conn.await?,
				}
			} else {
				conn.await?
			};

			Ok::<_, Error>(Self::new(ctx.clone(), conn))
		};

		match init.await {
			Ok(conn) => {
				let conn_span = info_span!(
					"conn",
					id = conn.id(),
					addr = %conn.inner.remote_address(),
					user = tracing::field::Empty,
				);

				if ctx.cfg.camouflage.as_ref().is_some_and(|cfg| cfg.enabled) {
					match conn.classify_h3_dispatch().await {
						Ok(H3Dispatch::Camouflage {
							prefetched_uni,
							prefetched_bi,
						}) => {
							if let Err(err) =
								camouflage::handle(ctx.clone(), conn.inner.clone(), prefetched_uni, prefetched_bi).await
							{
								warn!(parent: &conn_span, "camouflage: {err}");
							}
							return;
						}
						Ok(H3Dispatch::Tuic(first_event)) => {
							info!(parent: &conn_span, "connection established");
							tokio::spawn(
								conn.clone()
									.timeout_authenticate(ctx.cfg.auth_timeout)
									.instrument(conn_span.clone()),
							);
							tokio::spawn(conn.clone().collect_garbage().instrument(conn_span.clone()));
							if let Some(first_event) = first_event {
								let span = conn_span.clone();
								match first_event {
									PrefetchedFirstEventTuic::Uni(recv) => {
										tokio::spawn(
											conn.clone()
												.handle_uni_stream(recv, conn.remote_uni_stream_cnt.reg())
												.instrument(span),
										);
									}
									PrefetchedFirstEventTuic::Bi { send, recv } => {
										tokio::spawn(
											conn.clone()
												.handle_bi_stream((send, recv), conn.remote_bi_stream_cnt.reg())
												.instrument(span),
										);
									}
									PrefetchedFirstEventTuic::Datagram(dg) => {
										tokio::spawn(conn.clone().handle_datagram(dg).instrument(span));
									}
								}
							}

							conn.run_tuic_event_loop().instrument(conn_span).await;
							return;
						}
						Err(err) => {
							warn!(parent: &conn_span, "classifier: {err}");
							conn.close();
							return;
						}
					}
				}

				info!(parent: &conn_span, "connection established");
				tokio::spawn(
					conn.clone()
						.timeout_authenticate(ctx.cfg.auth_timeout)
						.instrument(conn_span.clone()),
				);
				tokio::spawn(conn.clone().collect_garbage().instrument(conn_span.clone()));
				conn.run_tuic_event_loop().instrument(conn_span).await;
			}
			Err(err) if err.is_trivial() => {
				debug!(id = u32::MAX, addr = %peer_addr, "{err}");
			}
			Err(err) => {
				warn!(id = u32::MAX, addr = %peer_addr, "{err}")
			}
		}
	}

	fn new(ctx: Arc<AppContext>, conn: QuinnConnection) -> Self {
		Self {
			ctx,
			inner: conn.clone(),
			model: Model::<side::Server>::new(conn),
			auth: Authenticated::new(),
			udp_sessions: Cache::new(u16::MAX as u64),
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
		} else if self
			.ctx
			.cfg
			.users
			.get(&auth.uuid())
			.is_some_and(|password| auth.validate(password))
		{
			self.auth.set(auth.uuid()).await;
			Span::current().record("user", auth.uuid().to_string());
			Ok(())
		} else {
			Err(Error::AuthFailed(auth.uuid()))
		}
	}

	async fn timeout_authenticate(self, timeout: Duration) {
		time::sleep(timeout).await;

		match self.auth.get() {
			Some(uuid) => {
				restful::client_connect(&self.ctx, &uuid, self.inner).await;
			}
			None => {
				warn!("[authenticate] timeout");
				self.close();
			}
		}
	}

	async fn collect_garbage(self) {
		loop {
			time::sleep(self.ctx.cfg.gc_interval).await;

			if self.is_closed() {
				if let Some(uuid) = self.auth.get() {
					restful::client_disconnect(&self.ctx, &uuid, self.inner).await;
				}
				break;
			}

			debug!("packet fragment garbage collecting event");
			self.model.collect_garbage(self.ctx.cfg.gc_lifetime);
		}
	}

	fn id(&self) -> u32 {
		self.inner.stable_id() as u32
	}

	async fn classify_h3_dispatch(&self) -> Result<H3Dispatch, Error> {
		let classify_timeout = self.ctx.cfg.task_negotiation_timeout;
		let first_event = match time::timeout(classify_timeout, async {
			tokio::select! {
				res = self.inner.accept_uni() => {
					let recv = res?;
					Ok::<_, Error>(FirstEvent::Uni(recv))
				}
				res = self.inner.accept_bi() => {
					let (send, recv) = res?;
					Ok::<_, Error>(FirstEvent::Bi(send, recv))
				}
				res = self.inner.read_datagram() => {
					let dg = res?;
					Ok::<_, Error>(FirstEvent::Datagram(dg))
				}
			}
		})
		.await
		{
			Ok(Ok(event)) => event,
			Ok(Err(err)) => return Err(err),
			Err(_) => {
				return Ok(H3Dispatch::Camouflage {
					prefetched_uni: None,
					prefetched_bi:  None,
				});
			}
		};

		match first_event {
			FirstEvent::Uni(recv) => match self.classify_recv_stream(recv, classify_timeout).await? {
				ClassifiedRecvStream::Tuic(recv) => Ok(H3Dispatch::Tuic(Some(PrefetchedFirstEventTuic::Uni(recv)))),
				ClassifiedRecvStream::Camouflage(recv) => Ok(H3Dispatch::Camouflage {
					prefetched_uni: Some(recv),
					prefetched_bi:  None,
				}),
			},
			FirstEvent::Bi(send, recv) => match self.classify_recv_stream(recv, classify_timeout).await? {
				ClassifiedRecvStream::Tuic(recv) => Ok(H3Dispatch::Tuic(Some(PrefetchedFirstEventTuic::Bi { send, recv }))),
				ClassifiedRecvStream::Camouflage(recv) => Ok(H3Dispatch::Camouflage {
					prefetched_uni: None,
					prefetched_bi:  Some(crate::h3_quinn_compat::PrefetchedBiRecv { send, recv }),
				}),
			},
			FirstEvent::Datagram(dg) => {
				if self.is_tuic_datagram(&dg) {
					Ok(H3Dispatch::Tuic(Some(PrefetchedFirstEventTuic::Datagram(dg))))
				} else {
					Ok(H3Dispatch::Camouflage {
						prefetched_uni: None,
						prefetched_bi:  None,
					})
				}
			}
		}
	}

	async fn classify_recv_stream(&self, recv: quinn::RecvStream, timeout: Duration) -> Result<ClassifiedRecvStream, Error> {
		let mut recv = recv.peekable_with_buffer::<SmallVec<[u8; 4]>>();
		let mut prefix = [0u8; 2];
		let read = time::timeout(timeout, recv.peek_exact(&mut prefix))
			.await
			.map_err(|_| Error::TaskNegotiationTimeout)?;
		if let Err(err) = read {
			return Err(Error::Other(eyre::eyre!("failed peeking classifier prefix: {err:?}")));
		}

		if self.is_tuic_prefix(prefix) {
			Ok(ClassifiedRecvStream::Tuic(recv))
		} else {
			Ok(ClassifiedRecvStream::Camouflage(recv))
		}
	}

	fn is_tuic_prefix(&self, prefix: [u8; 2]) -> bool {
		prefix[0] == tuic_core::VERSION && (prefix[1] <= tuic_core::Header::TYPE_CODE_HEARTBEAT)
	}

	fn is_tuic_datagram(&self, dg: &Bytes) -> bool {
		dg.len() >= 2 && self.is_tuic_prefix([dg[0], dg[1]])
	}

	async fn run_tuic_event_loop(&self) {
		let span = Span::current();
		loop {
			if self.is_closed() {
				break;
			}

			let handle_incoming = async {
				tokio::select! {
					res = self.inner.accept_uni() =>
						tokio::spawn(self.clone().handle_uni_stream(res?, self.remote_uni_stream_cnt.reg()).instrument(span.clone())),
					res = self.inner.accept_bi() =>
						tokio::spawn(self.clone().handle_bi_stream(res?, self.remote_bi_stream_cnt.reg()).instrument(span.clone())),
					res = self.inner.read_datagram() =>
						tokio::spawn(self.clone().handle_datagram(res?).instrument(span.clone())),
				};

				Ok::<_, Error>(())
			};

			match handle_incoming.await {
				Ok(()) => {}
				Err(err) if err.is_trivial() => {
					debug!("{err}");
				}
				Err(err) => warn!("connection error: {err}"),
			}
		}
	}

	fn is_closed(&self) -> bool {
		self.inner.close_reason().is_some()
	}

	fn close(&self) {
		self.inner.close(ERROR_CODE, &[]);
	}
}
