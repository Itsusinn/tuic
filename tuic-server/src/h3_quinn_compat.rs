use std::{
	convert::TryInto,
	future::Future,
	pin::Pin,
	sync::Arc,
	task::{self, Poll},
};

use bytes::{Buf, Bytes};
use futures::{
	Stream,
	stream::{self},
};
use futures_util::{StreamExt, ready};
use h3::{
	error::Code,
	quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf},
};
use peekable::future::AsyncPeekable;
use quinn::{AcceptBi, AcceptUni, OpenBi, OpenUni, ReadError, VarInt};
use tokio_util::sync::ReusableBoxFuture;

type BoxStreamSync<'a, T> = Pin<Box<dyn Stream<Item = T> + Sync + Send + 'a>>;

pub type PeekableRecvStream = AsyncPeekable<quinn::RecvStream>;

pub struct PrefetchedBiRecv {
	pub send: quinn::SendStream,
	pub recv: PeekableRecvStream,
}

pub struct Connection {
	conn:           quinn::Connection,
	incoming_bi:    BoxStreamSync<'static, <AcceptBi<'static> as Future>::Output>,
	opening_bi:     Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
	incoming_uni:   BoxStreamSync<'static, <AcceptUni<'static> as Future>::Output>,
	opening_uni:    Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
	prefetched_bi:  Option<PrefetchedBiRecv>,
	prefetched_uni: Option<RecvStream>,
}

impl Connection {
	pub fn new(conn: quinn::Connection) -> Self {
		Self {
			conn:           conn.clone(),
			incoming_bi:    Box::pin(stream::unfold(conn.clone(), |conn| async {
				Some((conn.accept_bi().await, conn))
			})),
			opening_bi:     None,
			incoming_uni:   Box::pin(stream::unfold(conn.clone(), |conn| async {
				Some((conn.accept_uni().await, conn))
			})),
			opening_uni:    None,
			prefetched_bi:  None,
			prefetched_uni: None,
		}
	}

	pub fn new_with_prefetched(
		conn: quinn::Connection,
		prefetched_uni: Option<PeekableRecvStream>,
		prefetched_bi: Option<PrefetchedBiRecv>,
	) -> Self {
		let mut this = Self::new(conn);
		this.prefetched_uni = prefetched_uni.map(RecvStream::new_peekable);
		this.prefetched_bi = prefetched_bi;
		this
	}
}

impl<B> quic::Connection<B> for Connection
where
	B: Buf,
{
	type OpenStreams = OpenStreams;
	type RecvStream = RecvStream;

	fn poll_accept_bidi(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
		if let Some(prefetched) = self.prefetched_bi.take() {
			return Poll::Ready(Ok(Self::BidiStream {
				send: Self::SendStream::new(prefetched.send),
				recv: Self::RecvStream::new_peekable(prefetched.recv),
			}));
		}

		let (send, recv) = ready!(self.incoming_bi.poll_next_unpin(cx))
			.expect("self.incoming_bi never returns None")
			.map_err(convert_connection_error)?;
		Poll::Ready(Ok(Self::BidiStream {
			send: Self::SendStream::new(send),
			recv: Self::RecvStream::new(recv),
		}))
	}

	fn poll_accept_recv(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
		if let Some(stream) = self.prefetched_uni.take() {
			return Poll::Ready(Ok(stream));
		}

		let recv = ready!(self.incoming_uni.poll_next_unpin(cx))
			.expect("self.incoming_uni never returns None")
			.map_err(convert_connection_error)?;
		Poll::Ready(Ok(Self::RecvStream::new(recv)))
	}

	fn opener(&self) -> Self::OpenStreams {
		OpenStreams {
			conn:        self.conn.clone(),
			opening_bi:  None,
			opening_uni: None,
		}
	}
}

fn convert_connection_error(err: quinn::ConnectionError) -> ConnectionErrorIncoming {
	match err {
		quinn::ConnectionError::ApplicationClosed(close) => ConnectionErrorIncoming::ApplicationClose {
			error_code: close.error_code.into(),
		},
		quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
		error @ quinn::ConnectionError::VersionMismatch
		| error @ quinn::ConnectionError::TransportError(_)
		| error @ quinn::ConnectionError::ConnectionClosed(_)
		| error @ quinn::ConnectionError::Reset
		| error @ quinn::ConnectionError::LocallyClosed
		| error @ quinn::ConnectionError::CidsExhausted => ConnectionErrorIncoming::Undefined(Arc::new(error)),
	}
}

impl<B> quic::OpenStreams<B> for Connection
where
	B: Buf,
{
	type BidiStream = BidiStream<B>;
	type SendStream = SendStream<B>;

	fn poll_open_bidi(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
		let bi = self.opening_bi.get_or_insert_with(|| {
			Box::pin(stream::unfold(self.conn.clone(), |conn| async {
				Some((conn.open_bi().await, conn))
			}))
		});

		let (send, recv) = ready!(bi.poll_next_unpin(cx))
			.expect("BoxStream does not return None")
			.map_err(|err| StreamErrorIncoming::ConnectionErrorIncoming {
				connection_error: convert_connection_error(err),
			})?;

		Poll::Ready(Ok(Self::BidiStream {
			send: Self::SendStream::new(send),
			recv: RecvStream::new(recv),
		}))
	}

	fn poll_open_send(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
		let uni = self.opening_uni.get_or_insert_with(|| {
			Box::pin(stream::unfold(self.conn.clone(), |conn| async {
				Some((conn.open_uni().await, conn))
			}))
		});

		let send = ready!(uni.poll_next_unpin(cx))
			.expect("BoxStream does not return None")
			.map_err(|err| StreamErrorIncoming::ConnectionErrorIncoming {
				connection_error: convert_connection_error(err),
			})?;
		Poll::Ready(Ok(Self::SendStream::new(send)))
	}

	fn close(&mut self, code: Code, reason: &[u8]) {
		self.conn
			.close(VarInt::from_u64(code.value()).expect("error code VarInt"), reason);
	}
}

pub struct OpenStreams {
	conn:        quinn::Connection,
	opening_bi:  Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
	opening_uni: Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
}

impl<B> quic::OpenStreams<B> for OpenStreams
where
	B: Buf,
{
	type BidiStream = BidiStream<B>;
	type SendStream = SendStream<B>;

	fn poll_open_bidi(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
		let bi = self.opening_bi.get_or_insert_with(|| {
			Box::pin(stream::unfold(self.conn.clone(), |conn| async {
				Some((conn.open_bi().await, conn))
			}))
		});

		let (send, recv) = ready!(bi.poll_next_unpin(cx))
			.expect("BoxStream does not return None")
			.map_err(|err| StreamErrorIncoming::ConnectionErrorIncoming {
				connection_error: convert_connection_error(err),
			})?;

		Poll::Ready(Ok(Self::BidiStream {
			send: Self::SendStream::new(send),
			recv: RecvStream::new(recv),
		}))
	}

	fn poll_open_send(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
		let uni = self.opening_uni.get_or_insert_with(|| {
			Box::pin(stream::unfold(self.conn.clone(), |conn| async {
				Some((conn.open_uni().await, conn))
			}))
		});

		let send = ready!(uni.poll_next_unpin(cx))
			.expect("BoxStream does not return None")
			.map_err(|err| StreamErrorIncoming::ConnectionErrorIncoming {
				connection_error: convert_connection_error(err),
			})?;
		Poll::Ready(Ok(Self::SendStream::new(send)))
	}

	fn close(&mut self, code: Code, reason: &[u8]) {
		self.conn
			.close(VarInt::from_u64(code.value()).expect("error code VarInt"), reason);
	}
}

impl Clone for OpenStreams {
	fn clone(&self) -> Self {
		Self {
			conn:        self.conn.clone(),
			opening_bi:  None,
			opening_uni: None,
		}
	}
}

pub struct BidiStream<B: Buf> {
	send: SendStream<B>,
	recv: RecvStream,
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
	type RecvStream = RecvStream;
	type SendStream = SendStream<B>;

	fn split(self) -> (Self::SendStream, Self::RecvStream) {
		(self.send, self.recv)
	}
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
	type Buf = Bytes;

	fn poll_data(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
		self.recv.poll_data(cx)
	}

	fn stop_sending(&mut self, error_code: u64) {
		self.recv.stop_sending(error_code)
	}

	fn recv_id(&self) -> StreamId {
		self.recv.recv_id()
	}
}

impl<B: Buf> quic::SendStream<B> for BidiStream<B> {
	fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		self.send.poll_ready(cx)
	}

	fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		self.send.poll_finish(cx)
	}

	fn reset(&mut self, reset_code: u64) {
		self.send.reset(reset_code)
	}

	fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
		self.send.send_data(data)
	}

	fn send_id(&self) -> StreamId {
		self.send.send_id()
	}
}

impl<B: Buf> quic::SendStreamUnframed<B> for BidiStream<B> {
	fn poll_send<D: Buf>(&mut self, cx: &mut task::Context<'_>, buf: &mut D) -> Poll<Result<usize, StreamErrorIncoming>> {
		self.send.poll_send(cx, buf)
	}
}

pub struct RecvStream {
	stream:            Option<PeekableRecvStream>,
	recv_id:           StreamId,
	pending_stop_code: Option<u64>,
	read_chunk_fut:    ReadChunkFuture,
}

type ReadChunkFuture = ReusableBoxFuture<'static, (PeekableRecvStream, Result<Option<quinn::Chunk>, quinn::ReadError>)>;

impl RecvStream {
	fn new(stream: quinn::RecvStream) -> Self {
		let num: u64 = stream.id().into();
		Self::new_inner(AsyncPeekable::new(stream), num)
	}

	fn new_peekable(stream: PeekableRecvStream) -> Self {
		let num: u64 = stream.get_ref().1.id().into();
		Self::new_inner(stream, num)
	}

	fn new_inner(stream: PeekableRecvStream, stream_id: u64) -> Self {
		Self {
			stream:            Some(stream),
			recv_id:           stream_id.try_into().expect("invalid stream id"),
			pending_stop_code: None,
			read_chunk_fut:    ReusableBoxFuture::new(async { unreachable!() }),
		}
	}
}

impl quic::RecvStream for RecvStream {
	type Buf = Bytes;

	fn poll_data(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
		if let Some(stream) = self.stream.as_mut() {
			let (buffered, _) = stream.get_ref();
			if !buffered.is_empty() {
				let buffered = Bytes::copy_from_slice(buffered);
				stream.consume_in_place();
				return Poll::Ready(Ok(Some(buffered)));
			}
		}

		if let Some(mut stream) = self.stream.take() {
			self.read_chunk_fut.set(async move {
				let chunk = stream.get_mut().1.read_chunk(usize::MAX, true).await;
				(stream, chunk)
			})
		}

		let (stream, chunk) = ready!(self.read_chunk_fut.poll(cx));
		self.stream = Some(stream);
		if let Some(stop_code) = self.pending_stop_code.take() {
			self.stop_sending(stop_code);
		}
		Poll::Ready(Ok(chunk.map_err(convert_read_error_to_stream_error)?.map(|c| c.bytes)))
	}

	fn stop_sending(&mut self, error_code: u64) {
		if let Some(stream) = self.stream.as_mut() {
			stream
				.get_mut()
				.1
				.stop(VarInt::from_u64(error_code).expect("invalid error_code"))
				.ok();
		} else {
			self.pending_stop_code = Some(error_code);
		}
	}

	fn recv_id(&self) -> StreamId {
		self.recv_id
	}
}

fn convert_read_error_to_stream_error(error: ReadError) -> StreamErrorIncoming {
	match error {
		ReadError::Reset(var_int) => StreamErrorIncoming::StreamTerminated {
			error_code: var_int.into_inner(),
		},
		ReadError::ConnectionLost(connection_error) => StreamErrorIncoming::ConnectionErrorIncoming {
			connection_error: convert_connection_error(connection_error),
		},
		error @ ReadError::ClosedStream => StreamErrorIncoming::Unknown(Box::new(error)),
		ReadError::IllegalOrderedRead => panic!("h3_quinn_compat only performs ordered reads"),
		error @ ReadError::ZeroRttRejected => StreamErrorIncoming::Unknown(Box::new(error)),
	}
}

fn convert_write_error_to_stream_error(error: quinn::WriteError) -> StreamErrorIncoming {
	match error {
		quinn::WriteError::Stopped(var_int) => StreamErrorIncoming::StreamTerminated {
			error_code: var_int.into_inner(),
		},
		quinn::WriteError::ConnectionLost(connection_error) => StreamErrorIncoming::ConnectionErrorIncoming {
			connection_error: convert_connection_error(connection_error),
		},
		error @ quinn::WriteError::ClosedStream | error @ quinn::WriteError::ZeroRttRejected => {
			StreamErrorIncoming::Unknown(Box::new(error))
		}
	}
}

pub struct SendStream<B: Buf> {
	stream:  quinn::SendStream,
	writing: Option<WriteBuf<B>>,
}

impl<B: Buf> SendStream<B> {
	fn new(stream: quinn::SendStream) -> Self {
		Self { stream, writing: None }
	}
}

impl<B: Buf> quic::SendStream<B> for SendStream<B> {
	fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		if let Some(ref mut data) = self.writing {
			while data.has_remaining() {
				let stream = Pin::new(&mut self.stream);
				let written = ready!(stream.poll_write(cx, data.chunk())).map_err(convert_write_error_to_stream_error)?;
				data.advance(written);
			}
		}

		self.writing = None;
		Poll::Ready(Ok(()))
	}

	fn poll_finish(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		Poll::Ready(self.stream.finish().map_err(|e| StreamErrorIncoming::Unknown(Box::new(e))))
	}

	fn reset(&mut self, reset_code: u64) {
		let _ = self.stream.reset(VarInt::from_u64(reset_code).unwrap_or(VarInt::MAX));
	}

	fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
		if self.writing.is_some() {
			return Err(StreamErrorIncoming::ConnectionErrorIncoming {
				connection_error: ConnectionErrorIncoming::InternalError("internal error in the http stack".to_string()),
			});
		}
		self.writing = Some(data.into());
		Ok(())
	}

	fn send_id(&self) -> StreamId {
		let num: u64 = self.stream.id().into();
		num.try_into().expect("invalid stream id")
	}
}

impl<B: Buf> quic::SendStreamUnframed<B> for SendStream<B> {
	fn poll_send<D: Buf>(&mut self, cx: &mut task::Context<'_>, buf: &mut D) -> Poll<Result<usize, StreamErrorIncoming>> {
		if self.writing.is_some() {
			panic!("poll_send called while send stream is not ready")
		}

		let stream = Pin::new(&mut self.stream);
		match ready!(stream.poll_write(cx, buf.chunk())) {
			Ok(written) => {
				buf.advance(written);
				Poll::Ready(Ok(written))
			}
			Err(err) => Poll::Ready(Err(convert_write_error_to_stream_error(err))),
		}
	}
}
