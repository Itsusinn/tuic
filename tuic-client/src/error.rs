use std::io::Error as IoError;

use quinn::{ConnectError, ConnectionError};
use rustls::Error as RustlsError;
use thiserror::Error;
use tuic_quinn::Error as ModelError;

#[derive(Debug, Error)]
pub enum Error {
	#[error(transparent)]
	Io(#[from] IoError),
	#[error(transparent)]
	Connect(#[from] ConnectError),
	#[error(transparent)]
	Model(#[from] ModelError),
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
	#[error(transparent)]
	Other(#[from] anyhow::Error),
}

impl From<ConnectionError> for Error {
	fn from(err: ConnectionError) -> Self {
		Self::Io(IoError::from(err))
	}
}
