use std::fmt::{Debug, Formatter, Result as FmtResult};

use uuid::Uuid;

use super::side::{self, Side};
use crate::{Authenticate as AuthenticateHeader, Header};

/// Error returned when TLS keying material export fails.
#[derive(Debug)]
pub struct ExportError;

/// The model of the `Authenticate` command
pub struct Authenticate<M> {
	inner: Side<Tx, Rx>,
	_marker: M,
}

struct Tx {
	header: Header,
}

impl Authenticate<side::Tx> {
	pub(super) fn new(
		uuid: Uuid,
		password: impl AsRef<[u8]>,
		exporter: &impl KeyingMaterialExporter,
	) -> Result<Self, ExportError> {
		let token = exporter.export_keying_material(uuid.as_ref(), password.as_ref())?;

		Ok(Self {
			inner: Side::Tx(Tx {
				header: Header::Authenticate(AuthenticateHeader::new(uuid, token)),
			}),
			_marker: side::Tx,
		})
	}

	/// Returns the header of the `Authenticate` command
	pub fn header(&self) -> &Header {
		let Side::Tx(tx) = &self.inner else { unreachable!() };
		&tx.header
	}
}

impl Debug for Authenticate<side::Tx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		let Side::Tx(tx) = &self.inner else { unreachable!() };
		f.debug_struct("Authenticate").field("header", &tx.header).finish()
	}
}

struct Rx {
	uuid: Uuid,
	token: [u8; 32],
}

impl Authenticate<side::Rx> {
	pub(super) fn new(uuid: Uuid, token: [u8; 32]) -> Self {
		Self {
			inner: Side::Rx(Rx { uuid, token }),
			_marker: side::Rx,
		}
	}

	/// Returns the UUID of the peer
	pub fn uuid(&self) -> Uuid {
		let Side::Rx(rx) = &self.inner else { unreachable!() };
		rx.uuid
	}

	/// Returns the token of the peer
	pub fn token(&self) -> [u8; 32] {
		let Side::Rx(rx) = &self.inner else { unreachable!() };
		rx.token
	}

	/// Returns whether the token is valid.
	///
	/// Returns `Err(ExportError)` if the TLS keying material export
	/// itself fails — in that case authentication MUST be rejected
	/// regardless of any token comparison.
	pub fn is_valid(&self, password: impl AsRef<[u8]>, exporter: &impl KeyingMaterialExporter) -> Result<bool, ExportError> {
		let Side::Rx(rx) = &self.inner else { unreachable!() };
		let expected = exporter.export_keying_material(rx.uuid.as_ref(), password.as_ref())?;
		Ok(rx.token == expected)
	}
}

impl Debug for Authenticate<side::Rx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		let Side::Rx(rx) = &self.inner else { unreachable!() };
		f.debug_struct("Authenticate")
			.field("uuid", &rx.uuid)
			.field("token", &rx.token)
			.finish()
	}
}

/// The trait for exporting keying material
pub trait KeyingMaterialExporter {
	/// Exports keying material
	fn export_keying_material(&self, label: &[u8], context: &[u8]) -> Result<[u8; 32], ExportError>;
}
