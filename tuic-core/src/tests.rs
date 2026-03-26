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

// ========== Model tests ==========

#[cfg(feature = "model")]
mod model_tests {
	use std::time::Duration;

	use uuid::Uuid;

	use crate::{
		Address,
		model::{Connection, KeyingMaterialExporter},
	};

	/// A mock keying material exporter for testing
	struct MockExporter;

	impl KeyingMaterialExporter for MockExporter {
		fn export_keying_material(&self, label: &[u8], context: &[u8]) -> [u8; 32] {
			let mut result = [0u8; 32];
			// Simple deterministic hash for testing
			for (i, b) in label.iter().chain(context.iter()).enumerate() {
				result[i % 32] ^= b;
			}
			result
		}
	}

	#[test]
	fn test_connection_creation() {
		let conn = Connection::<Vec<u8>>::new();
		assert_eq!(conn.task_connect_count(), 0);
		assert_eq!(conn.task_associate_count(), 0);
	}

	#[test]
	fn test_send_authenticate() {
		let conn = Connection::<Vec<u8>>::new();
		let uuid = Uuid::new_v4();
		let password = "test_password";
		let exporter = MockExporter;

		let auth_tx = conn.send_authenticate(uuid, password, &exporter);
		let header = auth_tx.header();
		assert_eq!(header.type_code(), 0x00); // Authenticate
	}

	#[test]
	fn test_recv_authenticate_valid() {
		let conn = Connection::<Vec<u8>>::new();
		let uuid = Uuid::new_v4();
		let password = "test_password";
		let exporter = MockExporter;

		let token = exporter.export_keying_material(uuid.as_ref(), password.as_ref());
		let header = crate::Authenticate::new(uuid, token);

		let auth_rx = conn.recv_authenticate(header);
		assert_eq!(auth_rx.uuid(), uuid);
		assert!(auth_rx.is_valid(password, &exporter));
	}

	#[test]
	fn test_recv_authenticate_invalid() {
		let conn = Connection::<Vec<u8>>::new();
		let uuid = Uuid::new_v4();
		let exporter = MockExporter;

		let token = [0u8; 32]; // wrong token
		let header = crate::Authenticate::new(uuid, token);

		let auth_rx = conn.recv_authenticate(header);
		assert_eq!(auth_rx.uuid(), uuid);
		assert!(!auth_rx.is_valid("test_password", &exporter));
	}

	#[test]
	fn test_send_recv_connect_task_counting() {
		let conn = Connection::<Vec<u8>>::new();
		assert_eq!(conn.task_connect_count(), 0);

		let addr = Address::DomainAddress("example.com".to_string(), 443);
		let connect_tx = conn.send_connect(addr.clone());
		assert_eq!(conn.task_connect_count(), 1);

		let addr2 = Address::DomainAddress("test.com".to_string(), 80);
		let connect_tx2 = conn.send_connect(addr2);
		assert_eq!(conn.task_connect_count(), 2);

		drop(connect_tx);
		assert_eq!(conn.task_connect_count(), 1);

		drop(connect_tx2);
		assert_eq!(conn.task_connect_count(), 0);
	}

	#[test]
	fn test_recv_connect() {
		let conn = Connection::<Vec<u8>>::new();
		let addr = Address::DomainAddress("example.com".to_string(), 443);
		let header = crate::Connect::new(addr.clone());

		let connect_rx = conn.recv_connect(header);
		assert_eq!(connect_rx.addr(), &addr);
		assert_eq!(conn.task_connect_count(), 1);

		drop(connect_rx);
		assert_eq!(conn.task_connect_count(), 0);
	}

	#[test]
	fn test_send_recv_dissociate() {
		let conn = Connection::<Vec<u8>>::new();

		// First create a UDP session by sending a packet
		let _pkt = conn.send_packet(42, Address::DomainAddress("test.com".to_string(), 53), 1200);
		assert_eq!(conn.task_associate_count(), 1);

		// Dissociate
		let dissoc_tx = conn.send_dissociate(42);
		assert_eq!(dissoc_tx.header().type_code(), 0x03);
		assert_eq!(conn.task_associate_count(), 0);
	}

	#[test]
	fn test_recv_dissociate() {
		let conn = Connection::<Vec<u8>>::new();

		// Create a session via recv_packet_unrestricted
		let header = crate::Packet::new(99, 0, 1, 0, 5, Address::DomainAddress("test.com".to_string(), 80));
		let _pkt = conn.recv_packet_unrestricted(header);
		assert_eq!(conn.task_associate_count(), 1);

		let dissoc_header = crate::Dissociate::new(99);
		let _dissoc_rx = conn.recv_dissociate(dissoc_header);
		assert_eq!(conn.task_associate_count(), 0);
	}

	#[test]
	fn test_send_heartbeat() {
		let conn = Connection::<Vec<u8>>::new();
		let hb = conn.send_heartbeat();
		assert_eq!(hb.header().type_code(), 0x04);
	}

	#[test]
	fn test_recv_heartbeat() {
		let conn = Connection::<Vec<u8>>::new();
		let header = crate::Heartbeat::new();
		let _hb = conn.recv_heartbeat(header);
		// Just ensure it doesn't panic
	}

	#[test]
	fn test_packet_fragmentation_single() {
		let conn = Connection::<Vec<u8>>::new();
		let pkt = conn.send_packet(1, Address::DomainAddress("test.com".to_string(), 53), 1200);

		let payload = vec![0u8; 100];
		let fragments: Vec<_> = pkt.into_fragments(payload).collect();

		assert_eq!(fragments.len(), 1);
		let (header, data) = &fragments[0];
		assert_eq!(header.type_code(), 0x02); // Packet
		assert_eq!(data.len(), 100);
	}

	#[test]
	fn test_packet_fragmentation_multiple() {
		let conn = Connection::<Vec<u8>>::new();
		// Use a very small max_pkt_size to force fragmentation
		let pkt = conn.send_packet(1, Address::DomainAddress("test.com".to_string(), 53), 50);

		let payload = vec![0xAB; 200];
		let fragments: Vec<_> = pkt.into_fragments(payload).collect();

		assert!(fragments.len() > 1);

		// First fragment should have address, rest should have None
		let (first_header, _) = &fragments[0];
		match first_header {
			crate::Header::Packet(p) => {
				assert!(!p.addr().is_none());
				assert_eq!(p.frag_id(), 0);
				assert_eq!(p.frag_total(), fragments.len() as u8);
			}
			_ => panic!("Expected Packet header"),
		}

		// Subsequent fragments should have Address::None
		for (i, (header, _)) in fragments.iter().enumerate().skip(1) {
			match header {
				crate::Header::Packet(p) => {
					assert!(p.addr().is_none());
					assert_eq!(p.frag_id(), i as u8);
				}
				_ => panic!("Expected Packet header"),
			}
		}

		// Total payload size should match
		let total_size: usize = fragments.iter().map(|(_, data)| data.len()).sum();
		assert_eq!(total_size, 200);
	}

	#[test]
	fn test_packet_assembly_single_fragment() {
		let conn = Connection::<Vec<u8>>::new();
		let payload = b"hello world";

		// Receive a single-fragment packet
		let header = crate::Packet::new(
			1,
			0,
			1,
			0,
			payload.len() as u16,
			Address::DomainAddress("test.com".to_string(), 53),
		);
		let pkt_rx = conn.recv_packet_unrestricted(header);

		let result = pkt_rx.assemble(payload.to_vec()).unwrap();
		assert!(result.is_some());

		let assembled = result.unwrap();
		let mut buf = Vec::new();
		let (addr, assoc_id) = assembled.assemble(&mut buf);
		assert_eq!(buf, payload);
		assert_eq!(assoc_id, 1);
		assert_eq!(addr, Address::DomainAddress("test.com".to_string(), 53));
	}

	#[test]
	fn test_packet_assembly_multi_fragment() {
		let conn = Connection::<Vec<u8>>::new();

		// Fragment 0 (first, has address)
		let header0 = crate::Packet::new(1, 0, 3, 0, 5, Address::DomainAddress("test.com".to_string(), 53));
		let pkt0 = conn.recv_packet_unrestricted(header0);
		let result0 = pkt0.assemble(vec![1, 2, 3, 4, 5]).unwrap();
		assert!(result0.is_none()); // not complete yet

		// Fragment 1 (middle, no address)
		let header1 = crate::Packet::new(1, 0, 3, 1, 5, Address::None);
		let pkt1 = conn.recv_packet_unrestricted(header1);
		let result1 = pkt1.assemble(vec![6, 7, 8, 9, 10]).unwrap();
		assert!(result1.is_none()); // not complete yet

		// Fragment 2 (last, no address)
		let header2 = crate::Packet::new(1, 0, 3, 2, 3, Address::None);
		let pkt2 = conn.recv_packet_unrestricted(header2);
		let result2 = pkt2.assemble(vec![11, 12, 13]).unwrap();
		assert!(result2.is_some()); // now complete

		let assembled = result2.unwrap();
		let mut buf = Vec::new();
		let (addr, assoc_id) = assembled.assemble(&mut buf);
		assert_eq!(buf, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
		assert_eq!(assoc_id, 1);
		assert_eq!(addr, Address::DomainAddress("test.com".to_string(), 53));
	}

	#[test]
	fn test_packet_assembly_invalid_frag_id() {
		let conn = Connection::<Vec<u8>>::new();

		// frag_id >= frag_total should fail
		let header = crate::Packet::new(1, 0, 2, 5, 5, Address::DomainAddress("test.com".to_string(), 53));
		let pkt = conn.recv_packet_unrestricted(header);
		let result = pkt.assemble(vec![1, 2, 3, 4, 5]);
		assert!(result.is_err());
	}

	#[test]
	fn test_packet_assembly_duplicate_fragment() {
		let conn = Connection::<Vec<u8>>::new();

		// Send first fragment
		let header0 = crate::Packet::new(1, 0, 2, 0, 5, Address::DomainAddress("test.com".to_string(), 53));
		let pkt0 = conn.recv_packet_unrestricted(header0);
		pkt0.assemble(vec![1, 2, 3, 4, 5]).unwrap();

		// Send duplicate fragment 0
		let header0_dup = crate::Packet::new(1, 0, 2, 0, 5, Address::DomainAddress("test.com".to_string(), 53));
		let pkt0_dup = conn.recv_packet_unrestricted(header0_dup);
		let result = pkt0_dup.assemble(vec![1, 2, 3, 4, 5]);
		assert!(result.is_err());
	}

	#[test]
	fn test_packet_assembly_first_frag_no_address() {
		let conn = Connection::<Vec<u8>>::new();

		// First fragment (frag_id=0) must have an address
		let header = crate::Packet::new(1, 0, 2, 0, 5, Address::None);
		let pkt = conn.recv_packet_unrestricted(header);
		let result = pkt.assemble(vec![1, 2, 3, 4, 5]);
		assert!(result.is_err());
	}

	#[test]
	fn test_packet_assembly_non_first_frag_with_address() {
		let conn = Connection::<Vec<u8>>::new();

		// First send fragment 0
		let header0 = crate::Packet::new(1, 0, 2, 0, 5, Address::DomainAddress("test.com".to_string(), 53));
		let pkt0 = conn.recv_packet_unrestricted(header0);
		pkt0.assemble(vec![1, 2, 3, 4, 5]).unwrap();

		// Non-first fragment should NOT have an address
		let header1 = crate::Packet::new(1, 0, 2, 1, 5, Address::DomainAddress("other.com".to_string(), 80));
		let pkt1 = conn.recv_packet_unrestricted(header1);
		let result = pkt1.assemble(vec![6, 7, 8, 9, 10]);
		assert!(result.is_err());
	}

	#[test]
	fn test_recv_packet_unknown_session() {
		let conn = Connection::<Vec<u8>>::new();

		// recv_packet returns None for unknown assoc_id
		let header = crate::Packet::new(999, 0, 1, 0, 5, Address::DomainAddress("test.com".to_string(), 53));
		let result = conn.recv_packet(header);
		assert!(result.is_none());
	}

	#[test]
	fn test_recv_packet_known_session() {
		let conn = Connection::<Vec<u8>>::new();

		// Create a session first via send_packet
		let _pkt = conn.send_packet(42, Address::DomainAddress("test.com".to_string(), 53), 1200);

		// Now recv_packet should find the session
		let header = crate::Packet::new(42, 0, 1, 0, 5, Address::DomainAddress("reply.com".to_string(), 53));
		let result = conn.recv_packet(header);
		assert!(result.is_some());
	}

	#[test]
	fn test_collect_garbage() {
		let conn = Connection::<Vec<u8>>::new();

		// Create session and receive a partial packet
		let header = crate::Packet::new(1, 0, 2, 0, 5, Address::DomainAddress("test.com".to_string(), 53));
		let pkt = conn.recv_packet_unrestricted(header);
		pkt.assemble(vec![1, 2, 3, 4, 5]).unwrap();

		// Wait a tiny bit so elapsed > 0
		std::thread::sleep(Duration::from_millis(10));

		// Garbage collect with very short timeout should remove incomplete packets
		conn.collect_garbage(Duration::from_nanos(1));

		// The session still exists, so recv_packet should find it.
		// But the old packet buffer for pkt_id=0 should be gone (GC'd).
		// Sending a new complete single-fragment packet should succeed.
		let header_new = crate::Packet::new(1, 1, 1, 0, 3, Address::DomainAddress("new.com".to_string(), 80));
		let pkt_new = conn.recv_packet(header_new);
		assert!(pkt_new.is_some());
		let result = pkt_new.unwrap().assemble(vec![10, 20, 30]).unwrap();
		assert!(result.is_some()); // single fragment completes immediately
	}

	#[test]
	fn test_multiple_udp_sessions() {
		let conn = Connection::<Vec<u8>>::new();

		// Create multiple sessions
		let _p1 = conn.send_packet(1, Address::DomainAddress("a.com".to_string(), 53), 1200);
		let _p2 = conn.send_packet(2, Address::DomainAddress("b.com".to_string(), 53), 1200);
		let _p3 = conn.send_packet(3, Address::DomainAddress("c.com".to_string(), 53), 1200);

		assert_eq!(conn.task_associate_count(), 3);

		conn.send_dissociate(1);
		assert_eq!(conn.task_associate_count(), 2);

		conn.send_dissociate(2);
		conn.send_dissociate(3);
		assert_eq!(conn.task_associate_count(), 0);
	}

	#[test]
	fn test_connection_clone() {
		let conn = Connection::<Vec<u8>>::new();
		let conn2 = conn.clone();

		let _pkt = conn.send_packet(1, Address::DomainAddress("test.com".to_string(), 53), 1200);
		assert_eq!(conn.task_associate_count(), 1);
		assert_eq!(conn2.task_associate_count(), 1); // shared state
	}

	#[test]
	fn test_fragments_exact_size_iterator() {
		let conn = Connection::<Vec<u8>>::new();
		let pkt = conn.send_packet(1, Address::DomainAddress("test.com".to_string(), 53), 50);

		let payload = vec![0xAB; 200];
		let fragments = pkt.into_fragments(payload);
		let expected_len = fragments.len();
		let actual: Vec<_> = fragments.collect();
		assert_eq!(actual.len(), expected_len);
	}
}
