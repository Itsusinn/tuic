use std::{io::Error as IoError, net::SocketAddr};

use quinn::ConnectionError;
use rustls::Error as RustlsError;
use thiserror::Error;
use uuid::Uuid;

// NOTE: many variants are currently unconstructed inside the workspace but are
// `pub` API — downstream binaries / future call sites may construct them, so
// we keep them all. If they remain unconstructed for several releases, prune
// then.
#[derive(Debug, Error)]
pub enum Error {
	#[error(transparent)]
	Io(#[from] IoError),
	#[error(transparent)]
	Rustls(#[from] RustlsError),
	#[error("invalid max idle time")]
	InvalidMaxIdleTime,
	#[error("connection timed out")]
	TimedOut,
	#[error("connection locally closed")]
	LocallyClosed,
	#[error("duplicated authentication")]
	DuplicatedAuth,
	#[error("authentication failed: {0}")]
	AuthFailed(Uuid),
	#[error("received packet from unexpected source")]
	UnexpectedPacketSource,
	#[error("{0}: {1}")]
	Socket(&'static str, IoError),
	#[error("task negotiation timed out")]
	TaskNegotiationTimeout,
	#[error("failed sending packet to {0}: relaying IPv6 UDP packet is disabled")]
	UdpRelayIpv6Disabled(SocketAddr),
	#[error(transparent)]
	Other(#[from] eyre::Report),
}

impl Error {
	pub fn is_trivial(&self) -> bool {
		matches!(self, Self::TimedOut | Self::LocallyClosed)
	}
}

impl From<ConnectionError> for Error {
	fn from(err: ConnectionError) -> Self {
		match err {
			ConnectionError::TimedOut => Self::TimedOut,
			ConnectionError::LocallyClosed => Self::LocallyClosed,
			_ => Self::Io(IoError::from(err)),
		}
	}
}

#[cfg(test)]
mod tests {
	use std::io::ErrorKind;

	use quinn::ConnectionError;
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
	fn test_is_trivial_timed_out() {
		let err = Error::TimedOut;
		assert!(err.is_trivial());
	}

	#[test]
	fn test_is_trivial_locally_closed() {
		let err = Error::LocallyClosed;
		assert!(err.is_trivial());
	}

	#[test]
	fn test_is_trivial_false_for_other_variants() {
		assert!(!Error::InvalidMaxIdleTime.is_trivial());
		assert!(!Error::DuplicatedAuth.is_trivial());
		assert!(!Error::UnexpectedPacketSource.is_trivial());
		assert!(!Error::TaskNegotiationTimeout.is_trivial());
	}

	#[test]
	fn test_connection_error_timed_out_maps_to_timed_out() {
		let conn = ConnectionError::TimedOut;
		let err = Error::from(conn);
		assert!(matches!(err, Error::TimedOut));
	}

	#[test]
	fn test_connection_error_locally_closed_maps_to_locally_closed() {
		let conn = ConnectionError::LocallyClosed;
		let err = Error::from(conn);
		assert!(matches!(err, Error::LocallyClosed));
	}

	#[test]
	fn test_connection_error_other_maps_to_io() {
		let err = Error::from(ConnectionError::TimedOut);
		let derr = Error::from(ConnectionError::TimedOut);
		assert!(matches!(err, Error::TimedOut));
		assert!(matches!(derr, Error::TimedOut));
	}

	#[test]
	fn test_error_display_output() {
		let err = Error::AuthFailed(Uuid::nil());
		let msg = format!("{err}");
		assert!(msg.contains("00000000-0000-0000-0000-000000000000"));

		let err = Error::InvalidMaxIdleTime;
		assert_eq!(format!("{err}"), "invalid max idle time");

		let err = Error::DuplicatedAuth;
		assert_eq!(format!("{err}"), "duplicated authentication");
	}

	#[test]
	fn test_socket_error_display() {
		let io = IoError::new(ErrorKind::AddrInUse, "address in use");
		let err = Error::Socket("bind", io);
		let msg = format!("{err}");
		assert!(msg.contains("bind"));
		assert!(msg.contains("address in use"));
	}

	#[test]
	fn test_other_wraps_eyre() {
		let report = eyre::eyre!("something went wrong");
		let err = Error::Other(report);
		let msg = format!("{err}");
		assert!(msg.contains("something went wrong"));
	}

	#[test]
	fn test_udp_relay_ipv6_disabled_display() {
		let addr = "[::1]:8080".parse::<SocketAddr>().unwrap();
		let err = Error::UdpRelayIpv6Disabled(addr);
		let msg = format!("{err}");
		assert!(msg.contains("IPv6"));
		assert!(msg.contains("[::1]:8080"));
	}
}
