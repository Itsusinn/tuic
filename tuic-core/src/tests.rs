use std::io::Cursor;

use uuid::Uuid;

use super::*;

// Test Address serialization and deserialization
#[test]
fn test_address_none() {
	let addr = Address::None;
	assert_eq!(addr.type_code(), Address::TYPE_CODE_NONE);
	assert_eq!(addr.len(), 1);
	assert!(addr.is_none());
	assert!(!addr.is_domain());
	assert!(!addr.is_ipv4());
	assert!(!addr.is_ipv6());
}

#[test]
fn test_address_domain() {
	let addr = Address::DomainAddress("example.com".to_string(), 443);
	assert_eq!(addr.type_code(), Address::TYPE_CODE_DOMAIN);
	assert_eq!(addr.len(), 1 + 1 + "example.com".len() + 2);
	assert!(addr.is_domain());
	assert!(!addr.is_none());
	assert_eq!(addr.port(), 443);
	assert_eq!(addr.to_string(), "example.com:443");
}

#[test]
fn test_address_ipv4() {
	use std::net::{Ipv4Addr, SocketAddr};
	let socket = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 8080));
	let addr = Address::SocketAddress(socket);
	assert_eq!(addr.type_code(), Address::TYPE_CODE_IPV4);
	assert_eq!(addr.len(), 1 + 4 + 2);
	assert!(addr.is_ipv4());
	assert!(!addr.is_ipv6());
	assert_eq!(addr.port(), 8080);
	assert_eq!(addr.to_string(), "127.0.0.1:8080");
}

#[test]
fn test_address_ipv6() {
	use std::net::{Ipv6Addr, SocketAddr};
	let socket = SocketAddr::from((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 9000));
	let addr = Address::SocketAddress(socket);
	assert_eq!(addr.type_code(), Address::TYPE_CODE_IPV6);
	assert_eq!(addr.len(), 1 + 16 + 2);
	assert!(addr.is_ipv6());
	assert!(!addr.is_ipv4());
	assert_eq!(addr.port(), 9000);
}

#[test]
fn test_address_take() {
	let mut addr = Address::DomainAddress("test.com".to_string(), 80);
	let taken = addr.take();
	assert!(addr.is_none());
	match taken {
		Address::DomainAddress(domain, port) => {
			assert_eq!(domain, "test.com");
			assert_eq!(port, 80);
		}
		_ => panic!("Expected domain address"),
	}
}

// Test Authenticate command
#[test]
fn test_authenticate_creation() {
	let uuid = Uuid::new_v4();
	let token = [0u8; 32];
	let auth = Authenticate::new(uuid, token);

	assert_eq!(auth.uuid(), uuid);
	assert_eq!(auth.token(), token);
	assert_eq!(Authenticate::type_code(), 0x00);
	assert_eq!(auth.len(), 48);
}

#[test]
fn test_authenticate_into() {
	let uuid = Uuid::new_v4();
	let token = [1u8; 32];
	let auth = Authenticate::new(uuid, token);

	let (extracted_uuid, extracted_token): (Uuid, [u8; 32]) = auth.into();
	assert_eq!(extracted_uuid, uuid);
	assert_eq!(extracted_token, token);
}

// Test Connect command
#[test]
fn test_connect_creation() {
	let addr = Address::DomainAddress("test.com".to_string(), 443);
	let conn = Connect::new(addr.clone());

	assert_eq!(Connect::type_code(), 0x01);
	assert_eq!(conn.addr(), &addr);
	assert_eq!(conn.len(), addr.len());
}

// Test Packet command
#[test]
fn test_packet_creation() {
	let addr = Address::DomainAddress("example.com".to_string(), 53);
	let pkt = Packet::new(100, 200, 5, 2, 1024, addr.clone());

	assert_eq!(pkt.assoc_id(), 100);
	assert_eq!(pkt.pkt_id(), 200);
	assert_eq!(pkt.frag_total(), 5);
	assert_eq!(pkt.frag_id(), 2);
	assert_eq!(pkt.size(), 1024);
	assert_eq!(pkt.addr(), &addr);
	assert_eq!(Packet::type_code(), 0x02);
	assert_eq!(pkt.len(), 2 + 2 + 1 + 1 + 2 + addr.len());
}

#[test]
fn test_packet_into() {
	let addr = Address::DomainAddress("test.com".to_string(), 80);
	let pkt = Packet::new(1, 2, 3, 4, 5, addr.clone());

	let (assoc_id, pkt_id, frag_total, frag_id, size, extracted_addr) = pkt.into();
	assert_eq!(assoc_id, 1);
	assert_eq!(pkt_id, 2);
	assert_eq!(frag_total, 3);
	assert_eq!(frag_id, 4);
	assert_eq!(size, 5);
	assert_eq!(extracted_addr, addr);
}

// Test Dissociate command
#[test]
fn test_dissociate_creation() {
	let dissoc = Dissociate::new(12345);

	assert_eq!(dissoc.assoc_id(), 12345);
	assert_eq!(Dissociate::type_code(), 0x03);
	assert_eq!(dissoc.len(), 2);
}

#[test]
fn test_dissociate_into() {
	let dissoc = Dissociate::new(999);
	let (assoc_id,): (u16,) = dissoc.into();
	assert_eq!(assoc_id, 999);
}

// Test Heartbeat command
#[test]
fn test_heartbeat_creation() {
	let hb = Heartbeat::new();

	assert_eq!(Heartbeat::type_code(), 0x04);
	assert_eq!(hb.len(), 0);
}

#[test]
fn test_heartbeat_default() {
	let _hb = Heartbeat;
	assert_eq!(Heartbeat::type_code(), 0x04);
}

// Test Header enum
#[test]
fn test_header_type_codes() {
	let uuid = Uuid::new_v4();
	let token = [0u8; 32];
	let auth = Authenticate::new(uuid, token);
	let header = Header::Authenticate(auth);
	assert_eq!(header.type_code(), Header::TYPE_CODE_AUTHENTICATE);

	let conn = Connect::new(Address::None);
	let header = Header::Connect(conn);
	assert_eq!(header.type_code(), Header::TYPE_CODE_CONNECT);

	let pkt = Packet::new(1, 2, 3, 4, 5, Address::None);
	let header = Header::Packet(pkt);
	assert_eq!(header.type_code(), Header::TYPE_CODE_PACKET);

	let dissoc = Dissociate::new(100);
	let header = Header::Dissociate(dissoc);
	assert_eq!(header.type_code(), Header::TYPE_CODE_DISSOCIATE);

	let hb = Heartbeat::new();
	let header = Header::Heartbeat(hb);
	assert_eq!(header.type_code(), Header::TYPE_CODE_HEARTBEAT);
}

#[test]
fn test_header_len() {
	let uuid = Uuid::new_v4();
	let token = [0u8; 32];
	let auth = Authenticate::new(uuid, token);
	let header = Header::Authenticate(auth);
	assert_eq!(header.len(), 2 + 48);

	let addr = Address::DomainAddress("test.com".to_string(), 80);
	let conn = Connect::new(addr.clone());
	let header = Header::Connect(conn);
	assert_eq!(header.len(), 2 + addr.len());
}

// Marshal and unmarshal tests (when features are enabled)
#[cfg(feature = "marshal")]
#[test]
fn test_marshal_unmarshal_authenticate() {
	let uuid = Uuid::new_v4();
	let token = [42u8; 32];
	let auth = Authenticate::new(uuid, token);
	let header = Header::Authenticate(auth);

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

	match decoded {
		Header::Authenticate(decoded_auth) => {
			assert_eq!(decoded_auth.uuid(), uuid);
			assert_eq!(decoded_auth.token(), token);
		}
		_ => panic!("Expected Authenticate header"),
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_marshal_unmarshal_connect() {
	let addr = Address::DomainAddress("example.com".to_string(), 443);
	let conn = Connect::new(addr.clone());
	let header = Header::Connect(conn);

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

	match decoded {
		Header::Connect(decoded_conn) => {
			assert_eq!(decoded_conn.addr(), &addr);
		}
		_ => panic!("Expected Connect header"),
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_marshal_unmarshal_packet() {
	let addr = Address::DomainAddress("udp.test".to_string(), 53);
	let pkt = Packet::new(123, 456, 10, 5, 2048, addr.clone());
	let header = Header::Packet(pkt);

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

	match decoded {
		Header::Packet(decoded_pkt) => {
			assert_eq!(decoded_pkt.assoc_id(), 123);
			assert_eq!(decoded_pkt.pkt_id(), 456);
			assert_eq!(decoded_pkt.frag_total(), 10);
			assert_eq!(decoded_pkt.frag_id(), 5);
			assert_eq!(decoded_pkt.size(), 2048);
			assert_eq!(decoded_pkt.addr(), &addr);
		}
		_ => panic!("Expected Packet header"),
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_marshal_unmarshal_dissociate() {
	let dissoc = Dissociate::new(999);
	let header = Header::Dissociate(dissoc);

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

	match decoded {
		Header::Dissociate(decoded_dissoc) => {
			assert_eq!(decoded_dissoc.assoc_id(), 999);
		}
		_ => panic!("Expected Dissociate header"),
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_marshal_unmarshal_heartbeat() {
	let hb = Heartbeat::new();
	let header = Header::Heartbeat(hb);

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

	match decoded {
		Header::Heartbeat(_) => {}
		_ => panic!("Expected Heartbeat header"),
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_marshal_unmarshal_ipv4_address() {
	use std::net::{Ipv4Addr, SocketAddr};
	let socket = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 1), 8080));
	let addr = Address::SocketAddress(socket);
	let conn = Connect::new(addr.clone());
	let header = Header::Connect(conn);

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

	match decoded {
		Header::Connect(decoded_conn) => {
			assert_eq!(decoded_conn.addr(), &addr);
		}
		_ => panic!("Expected Connect header"),
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_marshal_unmarshal_ipv6_address() {
	use std::net::{Ipv6Addr, SocketAddr};
	let socket = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443));
	let addr = Address::SocketAddress(socket);
	let conn = Connect::new(addr.clone());
	let header = Header::Connect(conn);

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

	match decoded {
		Header::Connect(decoded_conn) => {
			assert_eq!(decoded_conn.addr(), &addr);
		}
		_ => panic!("Expected Connect header"),
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_unmarshal_invalid_version() {
	let buf = vec![0x99, 0x00]; // Invalid version
	let mut cursor = Cursor::new(buf);
	let result = Header::unmarshal(&mut cursor);

	assert!(result.is_err());
	match result.unwrap_err() {
		UnmarshalError::InvalidVersion(ver) => assert_eq!(ver, 0x99),
		_ => panic!("Expected InvalidVersion error"),
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_unmarshal_invalid_command() {
	let buf = vec![VERSION, 0x99]; // Invalid command
	let mut cursor = Cursor::new(buf);
	let result = Header::unmarshal(&mut cursor);

	assert!(result.is_err());
	match result.unwrap_err() {
		UnmarshalError::InvalidCommand(cmd) => assert_eq!(cmd, 0x99),
		_ => panic!("Expected InvalidCommand error"),
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_marshal_unmarshal_address_none() {
	let pkt = Packet::new(1, 2, 1, 0, 100, Address::None);
	let header = Header::Packet(pkt);

	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();

	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();

	match decoded {
		Header::Packet(decoded_pkt) => {
			assert!(decoded_pkt.addr().is_none());
		}
		_ => panic!("Expected Packet header"),
	}
}
