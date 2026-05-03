use std::{
	fmt::{Debug, Formatter, Result as FmtResult},
	io::{Cursor, Error as IoError},
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};

pub use ::quinn;
use ::quinn::{Connection as QuinnConnection, ConnectionError, RecvStream, SendDatagramError, SendStream, VarInt};
use bytes::{BufMut, Bytes, BytesMut};
use peekable::{buffer::Buffer, tokio::AsyncPeekable};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tracing::warn;
use uuid::Uuid;

use self::side::Side;
use crate::{
	Address, Header, UnmarshalError,
	model::{
		AssembleError, Authenticate as AuthenticateModel, Connect as ConnectModel, Connection as ConnectionModel,
		KeyingMaterialExporter as KeyingMaterialExporterImpl, Packet as PacketModel, side as model_side,
	},
};

pub mod side {
	//! Side marker types for a connection.

	#[derive(Clone, Debug)]
	pub struct Client;
	#[derive(Clone, Debug)]
	pub struct Server;

	pub(super) enum Side<C, S> {
		Client(C),
		Server(S),
	}
}

/// Trait abstracting QUIC send stream operations.
pub trait StreamTx: tokio::io::AsyncWrite + futures_util::AsyncWrite + Unpin + Send {
	/// Notify the peer that no more data will be written to this stream.
	fn finish(&mut self) -> Result<(), ::quinn::ClosedStream>;
	/// Wait for the stream to be stopped or read to completion by the peer.
	fn stopped(&mut self) -> impl std::future::Future<Output = Result<Option<VarInt>, ::quinn::StoppedError>> + Send;
	/// Close the send stream immediately with the given error code.
	fn reset(&mut self, error_code: VarInt) -> Result<(), ::quinn::ClosedStream>;
}

/// Trait abstracting QUIC receive stream operations.
pub trait StreamRx: tokio::io::AsyncRead + Unpin + Send {
	/// Stop accepting data and notify the peer to stop transmitting.
	fn stop(&mut self, error_code: VarInt) -> Result<(), ::quinn::ClosedStream>;
}

impl StreamTx for ::quinn::SendStream {
	fn finish(&mut self) -> Result<(), ::quinn::ClosedStream> {
		SendStream::finish(self)
	}

	fn stopped(&mut self) -> impl std::future::Future<Output = Result<Option<VarInt>, ::quinn::StoppedError>> + Send {
		SendStream::stopped(self)
	}

	fn reset(&mut self, error_code: VarInt) -> Result<(), ::quinn::ClosedStream> {
		SendStream::reset(self, error_code)
	}
}

impl StreamRx for ::quinn::RecvStream {
	fn stop(&mut self, error_code: VarInt) -> Result<(), ::quinn::ClosedStream> {
		RecvStream::stop(self, error_code)
	}
}

impl<R: StreamRx, B: Buffer + Send> StreamRx for AsyncPeekable<R, B> {
	fn stop(&mut self, error_code: VarInt) -> Result<(), ::quinn::ClosedStream> {
		let (_, inner) = self.get_mut();
		inner.stop(error_code)
	}
}

/// The TUIC Connection.
///
/// This struct takes a clone of `quinn::Connection` for performing TUIC
/// operations.
#[derive(Clone)]
pub struct Connection<Side> {
	conn:    QuinnConnection,
	model:   ConnectionModel<Bytes>,
	_marker: Side,
}

impl<Side> Connection<Side> {
	/// Sends a `Packet` using UDP relay mode `native`.
	pub fn packet_native(&self, pkt: impl AsRef<[u8]>, addr: Address, assoc_id: u16) -> eyre::Result<()> {
		let Some(max_pkt_size) = self.conn.max_datagram_size() else {
			return Err(Error::SendDatagram(SendDatagramError::Disabled))?;
		};

		let model = self.model.send_packet(assoc_id, addr, max_pkt_size);

		for (header, frag) in model.into_fragments(pkt.as_ref()) {
			let mut buf = BytesMut::with_capacity(header.len() + frag.len());
			header.write(&mut buf);
			buf.put_slice(frag);
			self.conn.send_datagram(Bytes::from(buf))?;
		}

		Ok(())
	}

	/// Sends a `Packet` using UDP relay mode `quic`.
	pub async fn packet_quic(&self, pkt: impl AsRef<[u8]>, addr: Address, assoc_id: u16) -> eyre::Result<()> {
		let model = self.model.send_packet(assoc_id, addr, u16::MAX as usize);

		for (header, frag) in model.into_fragments(pkt.as_ref()) {
			let mut send = self.conn.open_uni().await?;
			header.async_marshal(&mut send).await?;
			send.write_all(frag).await?;
			send.finish()?;
			send.stopped().await?;
		}
		Ok(())
	}

	/// Returns the number of `Connect` tasks
	pub fn task_connect_count(&self) -> usize {
		self.model.task_connect_count()
	}

	/// Returns the number of active UDP sessions
	pub fn task_associate_count(&self) -> usize {
		self.model.task_associate_count()
	}

	/// Removes packet fragments that can not be reassembled within the
	/// specified timeout
	pub fn collect_garbage(&self, timeout: Duration) {
		self.model.collect_garbage(timeout);
	}

	fn keying_material_exporter(&self) -> KeyingMaterialExporter {
		KeyingMaterialExporter(self.conn.clone())
	}
}

impl Connection<side::Client> {
	/// Creates a new client side `Connection`.
	pub fn new(conn: QuinnConnection) -> Self {
		Self {
			conn,
			model: ConnectionModel::new(),
			_marker: side::Client,
		}
	}

	/// Sends an `Authenticate` command.
	pub async fn authenticate(&self, uuid: Uuid, password: impl AsRef<[u8]>) -> eyre::Result<()> {
		let model = self.model.send_authenticate(uuid, password, &self.keying_material_exporter());

		let mut send = self.conn.open_uni().await?;
		model.header().async_marshal(&mut send).await?;
		send.finish()?;
		send.stopped().await?;
		Ok(())
	}

	/// Sends a `Connect` command.
	pub async fn connect(&self, addr: Address) -> Result<Connect, Error> {
		let model = self.model.send_connect(addr);
		let (mut send, recv) = self.conn.open_bi().await?;
		model.header().async_marshal(&mut send).await?;
		Ok(Connect::new(Side::Client(model), send, recv))
	}

	/// Sends a `Dissociate` command.
	pub async fn dissociate(&self, assoc_id: u16) -> eyre::Result<()> {
		let model = self.model.send_dissociate(assoc_id);
		let mut send = self.conn.open_uni().await?;
		model.header().async_marshal(&mut send).await?;
		send.finish()?;
		send.stopped().await?;
		Ok(())
	}

	/// Sends a `Heartbeat` command.
	pub async fn heartbeat(&self) -> Result<(), Error> {
		let model = self.model.send_heartbeat();
		let mut buf = Vec::with_capacity(model.header().len());
		model.header().async_marshal(&mut buf).await.unwrap();
		self.conn.send_datagram(Bytes::from(buf))?;
		Ok(())
	}

	/// Try to parse a unidirectional stream as a TUIC command.
	///
	/// The stream should be accepted by `quinn::Connection::accept_uni()`
	/// from the same `QuinnConnection`.
	pub async fn accept_uni_stream<R: StreamRx>(&self, mut recv: R) -> Result<Task<SendStream, R>, Error> {
		let header = match Header::async_unmarshal(&mut recv).await {
			Ok(header) => header,
			Err(err) => return Err(Error::UnmarshalUniStream(err)),
		};

		match header {
			Header::Authenticate(_) => Err(Error::BadCommandUniStream("authenticate")),
			Header::Connect(_) => Err(Error::BadCommandUniStream("connect")),
			Header::Packet(pkt) => {
				let assoc_id = pkt.assoc_id();
				let pkt_id = pkt.pkt_id();
				self.model
					.recv_packet(pkt)
					.map_or(Err(Error::InvalidUdpSession(assoc_id, pkt_id)), |pkt| {
						Ok(Task::Packet(Packet::new(pkt, PacketSource::Quic(recv))))
					})
			}
			Header::Dissociate(_) => Err(Error::BadCommandUniStream("dissociate")),
			Header::Heartbeat(_) => Err(Error::BadCommandUniStream("heartbeat")),
		}
	}

	/// Try to parse a pair of send/receive streams as a TUIC command.
	///
	/// The pair of streams should be accepted by
	/// `quinn::Connection::accept_bi()` from the same `QuinnConnection`.
	pub async fn accept_bi_stream<S: StreamTx, R: StreamRx>(&self, _send: S, mut recv: R) -> Result<Task<S, R>, Error> {
		let header = match Header::async_unmarshal(&mut recv).await {
			Ok(header) => header,
			Err(err) => return Err(Error::UnmarshalBiStream(err)),
		};

		match header {
			Header::Authenticate(_) => Err(Error::BadCommandBiStream("authenticate")),
			Header::Connect(_) => Err(Error::BadCommandBiStream("connect")),
			Header::Packet(_) => Err(Error::BadCommandBiStream("packet")),
			Header::Dissociate(_) => Err(Error::BadCommandBiStream("dissociate")),
			Header::Heartbeat(_) => Err(Error::BadCommandBiStream("heartbeat")),
		}
	}

	/// Try to parse a QUIC Datagram as a TUIC command.
	///
	/// The Datagram should be accepted by `quinn::Connection::read_datagram()`
	/// from the same `quinn::Connection`.
	pub fn accept_datagram(&self, dg: Bytes) -> Result<Task, Error> {
		let mut dg = Cursor::new(dg);

		let header = match Header::unmarshal(&mut dg) {
			Ok(header) => header,
			Err(err) => return Err(Error::UnmarshalDatagram(err, dg.into_inner())),
		};

		match header {
			Header::Authenticate(_) => Err(Error::BadCommandDatagram("authenticate", dg.into_inner())),
			Header::Connect(_) => Err(Error::BadCommandDatagram("connect", dg.into_inner())),
			Header::Packet(pkt) if let Some(inner_pkt) = self.model.recv_packet(pkt.clone()) => {
				let pos = dg.position() as usize;
				let mut buf = dg.into_inner();
				if (pos + inner_pkt.size() as usize) <= buf.len() {
					buf = buf.slice(pos..pos + inner_pkt.size() as usize);
					Ok(Task::Packet(Packet::new(inner_pkt, PacketSource::Native(buf))))
				} else {
					Err(Error::PayloadLength(inner_pkt.size() as usize, buf.len() - pos))
				}
			}
			Header::Packet(pkt) => Err(Error::InvalidUdpSession(pkt.assoc_id(), pkt.pkt_id())),
			Header::Dissociate(_) => Err(Error::BadCommandDatagram("dissociate", dg.into_inner())),
			Header::Heartbeat(_) => Err(Error::BadCommandDatagram("heartbeat", dg.into_inner())),
		}
	}
}

impl Connection<side::Server> {
	/// Creates a new server side `Connection`.
	pub fn new(conn: QuinnConnection) -> Self {
		Self {
			conn,
			model: ConnectionModel::new(),
			_marker: side::Server,
		}
	}

	/// Try to parse a unidirectional stream as a TUIC command.
	///
	/// The stream should be accepted by `quinn::Connection::accept_uni()`
	/// from the same `QuinnConnection`.
	pub async fn accept_uni_stream<R: StreamRx>(&self, mut recv: R) -> Result<Task<SendStream, R>, Error> {
		let header = match Header::async_unmarshal(&mut recv).await {
			Ok(header) => header,
			Err(err) => return Err(Error::UnmarshalUniStream(err)),
		};

		match header {
			Header::Authenticate(auth) => {
				let model = self.model.recv_authenticate(auth);
				Ok(Task::Authenticate(Authenticate::new(model, self.keying_material_exporter())))
			}
			Header::Connect(_) => Err(Error::BadCommandUniStream("connect")),
			Header::Packet(pkt) => {
				let model = self.model.recv_packet_unrestricted(pkt);
				Ok(Task::Packet(Packet::new(model, PacketSource::Quic(recv))))
			}
			Header::Dissociate(dissoc) => {
				let model = self.model.recv_dissociate(dissoc);
				Ok(Task::Dissociate(model.assoc_id()))
			}
			Header::Heartbeat(_) => Err(Error::BadCommandUniStream("heartbeat")),
		}
	}

	/// Try to parse a pair of send/receive streams as a TUIC command.
	///
	/// The pair of streams should be accepted by
	/// `quinn::Connection::accept_bi()` from the same `QuinnConnection`.
	pub async fn accept_bi_stream<S: StreamTx, R: StreamRx>(&self, send: S, mut recv: R) -> Result<Task<S, R>, Error> {
		let header = match Header::async_unmarshal(&mut recv).await {
			Ok(header) => header,
			Err(err) => return Err(Error::UnmarshalBiStream(err)),
		};

		match header {
			Header::Authenticate(_) => Err(Error::BadCommandBiStream("authenticate")),
			Header::Connect(conn) => {
				let model = self.model.recv_connect(conn);
				Ok(Task::Connect(Connect::new(Side::Server(model), send, recv)))
			}
			Header::Packet(_) => Err(Error::BadCommandBiStream("packet")),
			Header::Dissociate(_) => Err(Error::BadCommandBiStream("dissociate")),
			Header::Heartbeat(_) => Err(Error::BadCommandBiStream("heartbeat")),
		}
	}

	/// Try to parse a QUIC Datagram as a TUIC command.
	///
	/// The Datagram should be accepted by `quinn::Connection::read_datagram()`
	/// from the same `quinn::Connection`.
	pub fn accept_datagram(&self, dg: Bytes) -> Result<Task, Error> {
		let mut dg = Cursor::new(dg);

		let header = match Header::unmarshal(&mut dg) {
			Ok(header) => header,
			Err(err) => return Err(Error::UnmarshalDatagram(err, dg.into_inner())),
		};

		match header {
			Header::Authenticate(_) => Err(Error::BadCommandDatagram("authenticate", dg.into_inner())),
			Header::Connect(_) => Err(Error::BadCommandDatagram("connect", dg.into_inner())),
			Header::Packet(pkt) => {
				let model = self.model.recv_packet_unrestricted(pkt);
				let pos = dg.position() as usize;
				let buf = dg.into_inner().slice(pos..pos + model.size() as usize);
				Ok(Task::Packet(Packet::new(model, PacketSource::Native(buf))))
			}
			Header::Dissociate(_) => Err(Error::BadCommandDatagram("dissociate", dg.into_inner())),
			Header::Heartbeat(hb) => {
				let _ = self.model.recv_heartbeat(hb);
				Ok(Task::Heartbeat)
			}
		}
	}
}

impl<Side> Debug for Connection<Side> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		f.debug_struct("Connection")
			.field("conn", &self.conn)
			.field("model", &self.model)
			.finish()
	}
}

/// A received `Authenticate` command.
#[derive(Debug)]
pub struct Authenticate {
	model:    AuthenticateModel<model_side::Rx>,
	exporter: KeyingMaterialExporter,
}

impl Authenticate {
	fn new(model: AuthenticateModel<model_side::Rx>, exporter: KeyingMaterialExporter) -> Self {
		Self { model, exporter }
	}

	/// The UUID of the client.
	pub fn uuid(&self) -> Uuid {
		self.model.uuid()
	}

	/// The hashed token.
	pub fn token(&self) -> [u8; 32] {
		self.model.token()
	}

	/// Validates if the given password is matching the hashed token.
	pub fn validate(&self, password: impl AsRef<[u8]>) -> bool {
		self.model.is_valid(password, &self.exporter)
	}
}

/// A received `Connect` command.
///
/// Generic over the QUIC send/receive stream types, allowing use with
/// different QUIC implementations that implement `StreamTx`/`StreamRx`.
pub struct Connect<S: StreamTx = SendStream, R: StreamRx = RecvStream> {
	model:    Side<ConnectModel<model_side::Tx>, ConnectModel<model_side::Rx>>,
	pub send: S,
	pub recv: R,
}

impl<S: StreamTx, R: StreamRx> Connect<S, R> {
	fn new(model: Side<ConnectModel<model_side::Tx>, ConnectModel<model_side::Rx>>, send: S, recv: R) -> Self {
		Self { model, send, recv }
	}

	/// Returns the `Connect` address
	pub fn addr(&self) -> &Address {
		match &self.model {
			Side::Client(model) => {
				let Header::Connect(conn) = model.header() else {
					unreachable!()
				};
				conn.addr()
			}
			Side::Server(model) => model.addr(),
		}
	}

	/// Immediately closes the `Connect` streams with the given error code.
	/// Returns the result of closing the send and receive streams,
	/// respectively.
	pub fn reset(&mut self, error_code: VarInt) -> eyre::Result<()> {
		self.send.reset(error_code)?;
		self.recv.stop(error_code)?;
		Ok(())
	}

	/// Tx: send FIN mark
	/// Rx: refuse accepting data
	pub async fn finish(&mut self) -> eyre::Result<()> {
		self.send.finish()?;
		self.recv.stop(VarInt::from_u32(0))?;
		Ok(())
	}
}

impl<S: StreamTx, R: StreamRx> AsyncRead for Connect<S, R> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
		AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
	}
}

impl<S: StreamTx, R: StreamRx> AsyncWrite for Connect<S, R> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, IoError>> {
		AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
		AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
		AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
	}
}

impl<S: StreamTx + Debug, R: StreamRx + Debug> Debug for Connect<S, R> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		let model = match &self.model {
			Side::Client(model) => model as &dyn Debug,
			Side::Server(model) => model as &dyn Debug,
		};

		f.debug_struct("Connect")
			.field("model", model)
			.field("send", &self.send)
			.field("recv", &self.recv)
			.finish()
	}
}

/// Source of a received `Packet` command.
#[derive(Debug)]
pub enum PacketSource<R: StreamRx = RecvStream> {
	Quic(R),
	Native(Bytes),
}

/// A received `Packet` command.
pub struct Packet<R: StreamRx = RecvStream> {
	model: PacketModel<model_side::Rx, Bytes>,
	src:   PacketSource<R>,
}

impl<R: StreamRx> Packet<R> {
	fn new(model: PacketModel<model_side::Rx, Bytes>, src: PacketSource<R>) -> Self {
		Self { src, model }
	}

	/// Returns the UDP session ID
	pub fn assoc_id(&self) -> u16 {
		self.model.assoc_id()
	}

	/// Returns the packet ID
	pub fn pkt_id(&self) -> u16 {
		self.model.pkt_id()
	}

	/// Returns the fragment ID
	pub fn frag_id(&self) -> u8 {
		self.model.frag_id()
	}

	/// Returns the total number of fragments
	pub fn frag_total(&self) -> u8 {
		self.model.frag_total()
	}

	/// Whether the packet is from UDP relay mode `quic`
	pub fn is_from_quic(&self) -> bool {
		matches!(self.src, PacketSource::Quic(_))
	}

	/// Whether the packet is from UDP relay mode `native`
	pub fn is_from_native(&self) -> bool {
		matches!(self.src, PacketSource::Native(_))
	}

	/// Accepts the packet payload. If the packet is fragmented and not yet
	/// fully assembled, `Ok(None)` is returned.
	pub async fn accept(self) -> Result<Option<(Bytes, Address, u16)>, Error> {
		let pkt = match self.src {
			PacketSource::Quic(mut recv) => {
				let mut buf = vec![0; self.model.size() as usize];
				AsyncReadExt::read_exact(&mut recv, &mut buf).await?;
				Bytes::from(buf)
			}
			PacketSource::Native(pkt) => pkt,
		};

		let mut asm = Vec::new();

		Ok(self
			.model
			.assemble(pkt)?
			.map(|pkt| pkt.assemble(&mut asm))
			.map(|(addr, assoc_id)| (Bytes::from(asm), addr, assoc_id)))
	}
}

impl<R: StreamRx + Debug> Debug for Packet<R> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		f.debug_struct("Packet")
			.field("model", &self.model)
			.field("src", &self.src)
			.finish()
	}
}

/// Type of tasks that can be received.
#[non_exhaustive]
#[derive(Debug)]
pub enum Task<S: StreamTx = SendStream, R: StreamRx = RecvStream> {
	Authenticate(Authenticate),
	Connect(Connect<S, R>),
	Packet(Packet<R>),
	Dissociate(u16),
	Heartbeat,
}

#[derive(Debug)]
struct KeyingMaterialExporter(QuinnConnection);

impl KeyingMaterialExporterImpl for KeyingMaterialExporter {
	fn export_keying_material(&self, label: &[u8], context: &[u8]) -> [u8; 32] {
		let mut buf = [0; 32];
		if let Err(err) = self.0.export_keying_material(&mut buf, label, context) {
			warn!("export keying material error {:#?}", err);
			buf = [0; 32];
		}
		buf
	}
}

/// Errors that can occur when processing a task.
#[derive(Debug, Error)]
pub enum Error {
	#[error(transparent)]
	IoError(#[from] IoError),
	#[error(transparent)]
	Connection(#[from] ConnectionError),
	#[error(transparent)]
	SendDatagram(#[from] SendDatagramError),
	#[error("expecting payload length {0} but got {1}")]
	PayloadLength(usize, usize),
	#[error("packet {1:#06x} on invalid udp session {0:#06x}")]
	InvalidUdpSession(u16, u16),
	#[error(transparent)]
	Assemble(#[from] AssembleError),
	#[error("error unmarshalling uni_stream: {0}")]
	UnmarshalUniStream(UnmarshalError),
	#[error("error unmarshalling bi_stream: {0}")]
	UnmarshalBiStream(UnmarshalError),
	#[error("error unmarshalling datagram: {0}")]
	UnmarshalDatagram(UnmarshalError, Bytes),
	#[error("bad command `{0}` from uni_stream")]
	BadCommandUniStream(&'static str),
	#[error("bad command `{0}` from bi_stream")]
	BadCommandBiStream(&'static str),
	#[error("bad command `{0}` from datagram")]
	BadCommandDatagram(&'static str, Bytes),
	#[error(transparent)]
	QuicWriteError(#[from] ::quinn::WriteError),
}
