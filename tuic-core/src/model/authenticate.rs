use std::{
	fmt::{Debug, Formatter, Result as FmtResult},
	marker::PhantomData,
};

use uuid::Uuid;

use super::side;
use crate::{Authenticate as AuthenticateHeader, Header};

// ── Per-model Side ──────────────────────────────────────────────────────

pub trait AuthenticateTypes {
	type TxData;
	type RxData;
}

enum AuthenticateSide<M: AuthenticateTypes> {
	Tx(<M as AuthenticateTypes>::TxData),
	Rx(<M as AuthenticateTypes>::RxData),
}

pub struct Tx {
	header: Header,
}

pub struct Rx {
	uuid:  Uuid,
	token: [u8; 32],
}

impl AuthenticateTypes for side::Tx {
	type RxData = !;
	type TxData = Tx;
}

impl AuthenticateTypes for side::Rx {
	type RxData = Rx;
	type TxData = !;
}

pub struct Authenticate<M: AuthenticateTypes> {
	inner:   AuthenticateSide<M>,
	_marker: PhantomData<M>,
}

// ── Tx side ─────────────────────────────────────────────────────────────

impl Authenticate<side::Tx> {
	pub(super) fn new(uuid: Uuid, password: impl AsRef<[u8]>, exporter: &impl KeyingMaterialExporter) -> Self {
		Self {
			inner:   AuthenticateSide::Tx(Tx {
				header: Header::Authenticate(AuthenticateHeader::new(
					uuid,
					exporter.export_keying_material(uuid.as_ref(), password.as_ref()),
				)),
			}),
			_marker: PhantomData,
		}
	}

	pub fn header(&self) -> &Header {
		match &self.inner {
			AuthenticateSide::Tx(tx) => &tx.header,
			AuthenticateSide::Rx(!),
		}
	}
}

impl Debug for Authenticate<side::Tx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match &self.inner {
			AuthenticateSide::Tx(tx) => f.debug_struct("Authenticate").field("header", &tx.header).finish(),
			AuthenticateSide::Rx(!),
		}
	}
}

// ── Rx side ─────────────────────────────────────────────────────────────

impl Authenticate<side::Rx> {
	pub(super) fn new(uuid: Uuid, token: [u8; 32]) -> Self {
		Self {
			inner:   AuthenticateSide::Rx(Rx { uuid, token }),
			_marker: PhantomData,
		}
	}

	pub fn uuid(&self) -> Uuid {
		match &self.inner {
			AuthenticateSide::Rx(rx) => rx.uuid,
			AuthenticateSide::Tx(!),
		}
	}

	pub fn token(&self) -> [u8; 32] {
		match &self.inner {
			AuthenticateSide::Rx(rx) => rx.token,
			AuthenticateSide::Tx(!),
		}
	}

	pub fn is_valid(&self, password: impl AsRef<[u8]>, exporter: &impl KeyingMaterialExporter) -> bool {
		match &self.inner {
			AuthenticateSide::Rx(rx) => {
				rx.token == exporter.export_keying_material(rx.uuid.as_ref(), password.as_ref())
			}
			AuthenticateSide::Tx(!),
		}
	}
}

impl Debug for Authenticate<side::Rx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match &self.inner {
			AuthenticateSide::Rx(rx) => f
				.debug_struct("Authenticate")
				.field("uuid", &rx.uuid)
				.field("token", &rx.token)
				.finish(),
			AuthenticateSide::Tx(!),
		}
	}
}

/// The trait for exporting keying material
pub trait KeyingMaterialExporter {
	/// Exports keying material
	fn export_keying_material(&self, label: &[u8], context: &[u8]) -> [u8; 32];
}
