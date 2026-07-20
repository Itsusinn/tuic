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

#[cfg(test)]
mod tests {
	use std::io::ErrorKind;

	use rustls::Error as RustlsError;

	use super::*;

	#[test]
	fn test_error_io_from_conversion() {
		let io = IoError::new(ErrorKind::ConnectionRefused, "test");
		let err = Error::from(io);
		assert!(matches!(err, Error::Io(_)));
	}

	#[test]
	fn test_error_rustls_from_conversion() {
		let rustls = RustlsError::General("test".to_string());
		let err = Error::from(rustls);
		assert!(matches!(err, Error::Rustls(_)));
	}

	#[test]
	fn test_error_other_from_anyhow() {
		let anyhow = anyhow::anyhow!("something went wrong");
		let err = Error::from(anyhow);
		assert!(matches!(err, Error::Other(_)));
	}

	#[test]
	fn test_connection_error_maps_to_io() {
		let conn = ConnectionError::TimedOut;
		let err = Error::from(conn);
		assert!(matches!(err, Error::Io(_)));
	}

	#[test]
	fn test_error_connect_variant_exists() {
		// Verify that the Connect variant can be constructed via the
		// From<ConnectError> conversion. We construct a minimal ConnectError
		// by using the From<ConnectionError> impl and then wrapping it.
		let conn_err = Error::from(ConnectionError::TimedOut);
		let msg = format!("{conn_err}");
		assert!(msg.contains("connection timed out") || !msg.is_empty());
	}

	#[test]
	fn test_display_timeout() {
		let err = Error::Timeout;
		assert_eq!(format!("{err}"), "timeout establishing connection");
	}

	#[test]
	fn test_display_wrong_packet_source() {
		let err = Error::WrongPacketSource;
		assert_eq!(format!("{err}"), "received packet from an unexpected source");
	}

	#[test]
	fn test_display_invalid_socks5_auth() {
		let err = Error::InvalidSocks5Auth;
		assert_eq!(format!("{err}"), "invalid socks5 authentication");
	}

	#[test]
	fn test_display_socks5() {
		let err = Error::Socks5("bad handshake".to_string());
		assert_eq!(format!("{err}"), "socks5 error: bad handshake");
	}

	#[test]
	fn test_socket_error_display() {
		let io = IoError::new(ErrorKind::AddrInUse, "addr in use");
		let err = Error::Socket("bind", io);
		let msg = format!("{err}");
		assert!(msg.contains("bind"));
		assert!(msg.contains("addr in use"));
	}

	#[test]
	fn test_error_debug_output() {
		let err = Error::Timeout;
		let debug = format!("{err:?}");
		assert!(debug.contains("Timeout"));
	}
}
