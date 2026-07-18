use std::io::Error as IoError;

use quinn::{ConnectError, ConnectionError};
use rustls::Error as RustlsError;
use thiserror::Error;

// NOTE: `Timeout`, `InvalidSocks5Auth`, `Socks5` are currently unconstructed in
// the workspace. `WrongPacketSource` IS constructed (PR1 wired it into the
// UDP-associate first-packet check). Keeping the rest as `pub` API for future
// call sites rather than removing — they encode legitimate, named failure
// modes the client may want to surface.
#[derive(Debug, Error)]
pub enum Error {
	#[error(transparent)]
	Io(#[from] IoError),
	#[error(transparent)]
	Connect(#[from] ConnectError),
	#[error(transparent)]
	Rustls(#[from] RustlsError),
	#[error("{0}: {1}")]
	Socket(&'static str, IoError),
	#[error("timeout establishing connection")]
	Timeout,
	#[error("received packet from an unexpected source")]
	WrongPacketSource,
	#[error("invalid socks5 authentication")]
	InvalidSocks5Auth,
	#[error("socks5 error: {0}")]
	Socks5(String),
	#[error(transparent)]
	Other(#[from] anyhow::Error),
}

impl From<ConnectionError> for Error {
	fn from(err: ConnectionError) -> Self {
		Self::Io(IoError::from(err))
	}
}
