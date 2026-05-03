use std::{
	fmt::{Debug, Formatter, Result as FmtResult},
	marker::PhantomData,
};

use super::side;
use crate::{Dissociate as DissociateHeader, Header};

// ── Per-model Side ──────────────────────────────────────────────────────

pub trait DissociateTypes {
	type TxData;
	type RxData;
}

enum DissociateSide<M: DissociateTypes> {
	Tx(<M as DissociateTypes>::TxData),
	Rx(<M as DissociateTypes>::RxData),
}

// ── Data types per side ──────────────────────────────────────────────────

pub struct Tx {
	header: Header,
}

pub struct Rx {
	assoc_id: u16,
}

// ── Marker → concrete type mapping ──────────────────────────────────────

impl DissociateTypes for side::Tx {
	type TxData = Tx;
	type RxData = !;
}

impl DissociateTypes for side::Rx {
	type TxData = !;
	type RxData = Rx;
}

// ── Public wrapper ───────────────────────────────────────────────────────

pub struct Dissociate<M: DissociateTypes> {
	inner:   DissociateSide<M>,
	_marker: PhantomData<M>,
}

// ── Tx side ─────────────────────────────────────────────────────────────

impl Dissociate<side::Tx> {
	pub(super) fn new(assoc_id: u16) -> Self {
		Self {
			inner:   DissociateSide::Tx(Tx {
				header: Header::Dissociate(DissociateHeader::new(assoc_id)),
			}),
			_marker: PhantomData,
		}
	}

	pub fn header(&self) -> &Header {
		match &self.inner {
			DissociateSide::Tx(tx) => &tx.header,
			_ => unreachable!(),
		}
	}
}

impl Debug for Dissociate<side::Tx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match &self.inner {
			DissociateSide::Tx(tx) => f.debug_struct("Dissociate").field("header", &tx.header).finish(),
			_ => unreachable!(),
		}
	}
}

// ── Rx side ─────────────────────────────────────────────────────────────

impl Dissociate<side::Rx> {
	pub(super) fn new(assoc_id: u16) -> Self {
		Self {
			inner:   DissociateSide::Rx(Rx { assoc_id }),
			_marker: PhantomData,
		}
	}

	pub fn assoc_id(&self) -> u16 {
		match &self.inner {
			DissociateSide::Rx(rx) => rx.assoc_id,
			_ => unreachable!(),
		}
	}
}

impl Debug for Dissociate<side::Rx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match &self.inner {
			DissociateSide::Rx(rx) => f.debug_struct("Dissociate").field("assoc_id", &rx.assoc_id).finish(),
			_ => unreachable!(),
		}
	}
}
