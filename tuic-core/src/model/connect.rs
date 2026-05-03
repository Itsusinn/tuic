use std::{
	fmt::{Debug, Formatter, Result as FmtResult},
	marker::PhantomData,
};

use register_count::Register;

use super::side;
use crate::{Address, Connect as ConnectHeader, Header};

// ── Per-model Side ──────────────────────────────────────────────────────

pub trait ConnectTypes {
	type TxData;
	type RxData;
}

enum ConnectSide<M: ConnectTypes> {
	Tx(<M as ConnectTypes>::TxData),
	Rx(<M as ConnectTypes>::RxData),
}

pub struct Tx {
	header:    Header,
	_task_reg: Register,
}

pub struct Rx {
	addr:      Address,
	_task_reg: Register,
}

impl ConnectTypes for side::Tx {
	type TxData = Tx;
	type RxData = !;
}

impl ConnectTypes for side::Rx {
	type TxData = !;
	type RxData = Rx;
}

pub struct Connect<M: ConnectTypes> {
	inner:   ConnectSide<M>,
	_marker: PhantomData<M>,
}

// ── Tx side ─────────────────────────────────────────────────────────────

impl Connect<side::Tx> {
	pub(super) fn new(task_reg: Register, addr: Address) -> Self {
		Self {
			inner:   ConnectSide::Tx(Tx {
				header:    Header::Connect(ConnectHeader::new(addr)),
				_task_reg: task_reg,
			}),
			_marker: PhantomData,
		}
	}

	pub fn header(&self) -> &Header {
		match &self.inner {
			ConnectSide::Tx(tx) => &tx.header,
			ConnectSide::Rx(!),
		}
	}

	fn tx_ref(&self) -> &Tx {
		match &self.inner {
			ConnectSide::Tx(tx) => tx,
			ConnectSide::Rx(!),
		}
	}
}

impl Debug for Connect<side::Tx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		let tx = self.tx_ref();
		f.debug_struct("Connect").field("header", &tx.header).finish()
	}
}

// ── Rx side ─────────────────────────────────────────────────────────────

impl Connect<side::Rx> {
	pub(super) fn new(task_reg: Register, addr: Address) -> Self {
		Self {
			inner:   ConnectSide::Rx(Rx {
				addr,
				_task_reg: task_reg,
			}),
			_marker: PhantomData,
		}
	}

	pub fn addr(&self) -> &Address {
		match &self.inner {
			ConnectSide::Rx(rx) => &rx.addr,
			ConnectSide::Tx(!),
		}
	}

	fn rx_ref(&self) -> &Rx {
		match &self.inner {
			ConnectSide::Rx(rx) => rx,
			ConnectSide::Tx(!),
		}
	}
}

impl Debug for Connect<side::Rx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		let rx = self.rx_ref();
		f.debug_struct("Connect").field("addr", &rx.addr).finish()
	}
}
