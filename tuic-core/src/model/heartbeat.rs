use std::{
	fmt::{Debug, Formatter, Result as FmtResult},
	marker::PhantomData,
};

use super::side;
use crate::{Header, Heartbeat as HeartbeatHeader};

// ── Per-model Side ──────────────────────────────────────────────────────

pub trait HeartbeatTypes {
	type TxData;
	type RxData;
}

enum HeartbeatSide<M: HeartbeatTypes> {
	Tx(<M as HeartbeatTypes>::TxData),
	Rx(<M as HeartbeatTypes>::RxData),
}

pub struct Tx {
	header: Header,
}

pub struct Rx;

impl HeartbeatTypes for side::Tx {
	type RxData = !;
	type TxData = Tx;
}

impl HeartbeatTypes for side::Rx {
	type RxData = Rx;
	type TxData = !;
}

pub struct Heartbeat<M: HeartbeatTypes> {
	inner:   HeartbeatSide<M>,
	_marker: PhantomData<M>,
}

// ── Tx side ─────────────────────────────────────────────────────────────

impl Heartbeat<side::Tx> {
	pub(super) fn new() -> Self {
		Self {
			inner:   HeartbeatSide::Tx(Tx {
				header: Header::Heartbeat(HeartbeatHeader::new()),
			}),
			_marker: PhantomData,
		}
	}

	pub fn header(&self) -> &Header {
		match &self.inner {
			HeartbeatSide::Tx(tx) => &tx.header,
			HeartbeatSide::Rx(!),
		}
	}
}

impl Debug for Heartbeat<side::Tx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match &self.inner {
			HeartbeatSide::Tx(tx) => f.debug_struct("Heartbeat").field("header", &tx.header).finish(),
			HeartbeatSide::Rx(!),
		}
	}
}

// ── Rx side ─────────────────────────────────────────────────────────────

impl Heartbeat<side::Rx> {
	pub(super) fn new() -> Self {
		Self {
			inner:   HeartbeatSide::Rx(Rx),
			_marker: PhantomData,
		}
	}
}

impl Debug for Heartbeat<side::Rx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		f.debug_struct("Heartbeat").finish()
	}
}
