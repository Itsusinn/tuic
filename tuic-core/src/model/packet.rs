use std::{
	fmt::{Debug, Formatter, Result as FmtResult},
	marker::PhantomData,
	sync::Arc,
};

use parking_lot::Mutex;

use super::{
	Assemblable, AssembleError, UdpSessions,
	side,
};
use crate::{Address, Header, Packet as PacketHeader};

// ── Per-model Side (with an extra type param `B` for buffered data) ─────

pub trait PacketTypes<B> {
	type TxData;
	type RxData;
}

enum PacketSide<M, B>
where
	M: PacketTypes<B>,
{
	Tx(<M as PacketTypes<B>>::TxData),
	Rx(<M as PacketTypes<B>>::RxData),
}

// ── Data types per side ──────────────────────────────────────────────────

pub struct Tx {
	assoc_id:     u16,
	pkt_id:       u16,
	addr:         Address,
	max_pkt_size: usize,
}

pub struct Rx<B> {
	sessions:   Arc<Mutex<UdpSessions<B>>>,
	assoc_id:   u16,
	pkt_id:     u16,
	frag_total: u8,
	frag_id:    u8,
	size:       u16,
	addr:       Address,
}

// ── Marker → concrete type mapping ──────────────────────────────────────

impl<B> PacketTypes<B> for side::Tx {
	type TxData = Tx;
	type RxData = !;
}

impl<B> PacketTypes<B> for side::Rx {
	type TxData = !;
	type RxData = Rx<B>;
}

// ── Public wrapper ───────────────────────────────────────────────────────

pub struct Packet<M, B>
where
	M: PacketTypes<B>,
{
	inner:   PacketSide<M, B>,
	_marker: PhantomData<M>,
}

// ── Tx side ─────────────────────────────────────────────────────────────

impl<B> Packet<side::Tx, B> {
	pub(super) fn new(assoc_id: u16, pkt_id: u16, addr: Address, max_pkt_size: usize) -> Self {
		Self {
			inner:   PacketSide::Tx(Tx {
				assoc_id,
				pkt_id,
				addr,
				max_pkt_size,
			}),
			_marker: PhantomData,
		}
	}

	pub fn into_fragments<'a>(self, payload: &'a [u8]) -> Fragments<'a> {
		match self.inner {
			PacketSide::Tx(tx) => {
				Fragments::new(tx.assoc_id, tx.pkt_id, tx.addr, tx.max_pkt_size, payload)
			}
			_ => unreachable!(),
		}
	}

	pub fn assoc_id(&self) -> u16 {
		match &self.inner {
			PacketSide::Tx(tx) => tx.assoc_id,
			_ => unreachable!(),
		}
	}

	pub fn pkt_id(&self) -> u16 {
		match &self.inner {
			PacketSide::Tx(tx) => tx.pkt_id,
			_ => unreachable!(),
		}
	}

	pub fn addr(&self) -> &Address {
		match &self.inner {
			PacketSide::Tx(tx) => &tx.addr,
			_ => unreachable!(),
		}
	}
}

impl<B> Debug for Packet<side::Tx, B> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match &self.inner {
			PacketSide::Tx(tx) => f
				.debug_struct("Packet")
				.field("assoc_id", &tx.assoc_id)
				.field("pkt_id", &tx.pkt_id)
				.field("addr", &tx.addr)
				.field("max_pkt_size", &tx.max_pkt_size)
				.finish(),
			_ => unreachable!(),
		}
	}
}

// ── Rx side ─────────────────────────────────────────────────────────────

impl<B> Packet<side::Rx, B>
where
	B: AsRef<[u8]>,
{
	pub(super) fn new(
		sessions: Arc<Mutex<UdpSessions<B>>>,
		assoc_id: u16,
		pkt_id: u16,
		frag_total: u8,
		frag_id: u8,
		size: u16,
		addr: Address,
	) -> Self {
		Self {
			inner:   PacketSide::Rx(Rx {
				sessions,
				assoc_id,
				pkt_id,
				frag_total,
				frag_id,
				size,
				addr,
			}),
			_marker: PhantomData,
		}
	}

	pub fn assemble(self, data: B) -> Result<Option<Assemblable<B>>, AssembleError> {
		match self.inner {
			PacketSide::Rx(rx) => {
				let mut sessions = rx.sessions.lock();
				sessions.insert(rx.assoc_id, rx.pkt_id, rx.frag_total, rx.frag_id, rx.size, rx.addr, data)
			}
			_ => unreachable!(),
		}
	}

	pub fn assoc_id(&self) -> u16 {
		match &self.inner {
			PacketSide::Rx(rx) => rx.assoc_id,
			_ => unreachable!(),
		}
	}

	pub fn pkt_id(&self) -> u16 {
		match &self.inner {
			PacketSide::Rx(rx) => rx.pkt_id,
			_ => unreachable!(),
		}
	}

	pub fn frag_id(&self) -> u8 {
		match &self.inner {
			PacketSide::Rx(rx) => rx.frag_id,
			_ => unreachable!(),
		}
	}

	pub fn frag_total(&self) -> u8 {
		match &self.inner {
			PacketSide::Rx(rx) => rx.frag_total,
			_ => unreachable!(),
		}
	}

	pub fn addr(&self) -> &Address {
		match &self.inner {
			PacketSide::Rx(rx) => &rx.addr,
			_ => unreachable!(),
		}
	}

	pub fn size(&self) -> u16 {
		match &self.inner {
			PacketSide::Rx(rx) => rx.size,
			_ => unreachable!(),
		}
	}
}

impl<B> Debug for Packet<side::Rx, B> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match &self.inner {
			PacketSide::Rx(rx) => f
				.debug_struct("Packet")
				.field("assoc_id", &rx.assoc_id)
				.field("pkt_id", &rx.pkt_id)
				.field("frag_total", &rx.frag_total)
				.field("frag_id", &rx.frag_id)
				.field("size", &rx.size)
				.field("addr", &rx.addr)
				.finish(),
			_ => unreachable!(),
		}
	}
}

/// Iterator over fragments of a packet
#[derive(Debug)]
pub struct Fragments<'a> {
	assoc_id:        u16,
	pkt_id:          u16,
	addr:            Address,
	max_pkt_size:    usize,
	frag_total:      u8,
	next_frag_id:    u8,
	next_frag_start: usize,
	payload:         &'a [u8],
}

impl<'a> Fragments<'a> {
	fn new(assoc_id: u16, pkt_id: u16, addr: Address, max_pkt_size: usize, payload: &'a [u8]) -> Self {
		let header_addr_ref = Header::Packet(PacketHeader::new(0, 0, 0, 0, 0, addr));
		let header_addr_none_ref = Header::Packet(PacketHeader::new(0, 0, 0, 0, 0, Address::None));

		let first_frag_size = max_pkt_size - header_addr_ref.len();
		let frag_size_addr_none = max_pkt_size - header_addr_none_ref.len();

		let Header::Packet(pkt) = header_addr_ref else {
			unreachable!()
		};
		let (_, _, _, _, _, addr) = pkt.into();

		let frag_total = if first_frag_size < payload.as_ref().len() {
			(1 + (payload.as_ref().len() - first_frag_size) / frag_size_addr_none + 1) as u8
		} else {
			1u8
		};

		Self {
			assoc_id,
			pkt_id,
			addr,
			max_pkt_size,
			frag_total,
			next_frag_id: 0,
			next_frag_start: 0,
			payload,
		}
	}
}

impl<'a> Iterator for Fragments<'a> {
	type Item = (Header, &'a [u8]);

	fn next(&mut self) -> Option<Self::Item> {
		if self.next_frag_id < self.frag_total {
			let header_ref = Header::Packet(PacketHeader::new(0, 0, 0, 0, 0, self.addr.take()));

			let payload_size = self.max_pkt_size - header_ref.len();
			let next_frag_end = (self.next_frag_start + payload_size).min(self.payload.as_ref().len());

			let Header::Packet(pkt) = header_ref else { unreachable!() };
			let (_, _, _, _, _, addr) = pkt.into();

			let header = Header::Packet(PacketHeader::new(
				self.assoc_id,
				self.pkt_id,
				self.frag_total,
				self.next_frag_id,
				(next_frag_end - self.next_frag_start) as u16,
				addr,
			));

			let payload = &self.payload[self.next_frag_start..next_frag_end];

			self.next_frag_id += 1;
			self.next_frag_start = next_frag_end;

			Some((header, payload))
		} else {
			None
		}
	}
}

impl ExactSizeIterator for Fragments<'_> {
	fn len(&self) -> usize {
		self.frag_total as usize
	}
}
