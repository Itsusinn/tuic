// Integration tests for TUIC protocol
// Tests the marshal/unmarshal round-trip for all protocol types

use tuic::{Address, Authenticate, Connect, Dissociate, Header, Heartbeat, Packet};
use uuid::Uuid;

#[cfg(feature = "marshal")]
#[test]
fn test_full_protocol_roundtrip() {
	use std::io::Cursor;

	// Test all header types can be marshaled and unmarshaled correctly
	
	// 1. Authenticate
	let uuid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
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
		_ => panic!("Wrong header type"),
	}
	
	// 2. Connect with different address types
	let addresses = vec![
		Address::None,
		Address::DomainAddress("example.com".to_string(), 443),
		Address::SocketAddress("192.168.1.1:8080".parse().unwrap()),
		Address::SocketAddress("[2001:db8::1]:9000".parse().unwrap()),
	];
	
	for addr in addresses {
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
			_ => panic!("Wrong header type"),
		}
	}
	
	// 3. Packet
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
		_ => panic!("Wrong header type"),
	}
	
	// 4. Dissociate
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
		_ => panic!("Wrong header type"),
	}
	
	// 5. Heartbeat
	let hb = Heartbeat::new();
	let header = Header::Heartbeat(hb);
	
	let mut buf = Vec::new();
	header.marshal(&mut buf).unwrap();
	
	let mut cursor = Cursor::new(buf);
	let decoded = Header::unmarshal(&mut cursor).unwrap();
	
	match decoded {
		Header::Heartbeat(_) => {}
		_ => panic!("Wrong header type"),
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_fragmented_udp_packets() {
	use std::io::Cursor;

	// Simulate a UDP packet split into 3 fragments
	let total_frags = 3;
	let assoc_id = 100;
	let pkt_id = 200;
	
	for frag_id in 0..total_frags {
		let addr = if frag_id == 0 {
			// First fragment has address
			Address::DomainAddress("destination.com".to_string(), 5353)
		} else {
			// Subsequent fragments have no address
			Address::None
		};
		
		let pkt = Packet::new(assoc_id, pkt_id, total_frags, frag_id, 500, addr.clone());
		let header = Header::Packet(pkt);
		
		let mut buf = Vec::new();
		header.marshal(&mut buf).unwrap();
		
		let mut cursor = Cursor::new(buf);
		let decoded = Header::unmarshal(&mut cursor).unwrap();
		
		match decoded {
			Header::Packet(decoded_pkt) => {
				assert_eq!(decoded_pkt.assoc_id(), assoc_id);
				assert_eq!(decoded_pkt.pkt_id(), pkt_id);
				assert_eq!(decoded_pkt.frag_total(), total_frags);
				assert_eq!(decoded_pkt.frag_id(), frag_id);
				assert_eq!(decoded_pkt.addr(), &addr);
			}
			_ => panic!("Wrong header type"),
		}
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_edge_case_values() {
	use std::io::Cursor;

	// Test edge case values for Packet
	let test_cases = vec![
		(0u16, 0u16, 1u8, 0u8, 0u16),        // Minimum values
		(u16::MAX, u16::MAX, u8::MAX, u8::MAX - 1, u16::MAX), // Maximum values
		(32768, 16384, 128, 64, 8192),       // Mid-range values
	];
	
	for (assoc_id, pkt_id, frag_total, frag_id, size) in test_cases {
		let addr = Address::DomainAddress("test.com".to_string(), 1234);
		let pkt = Packet::new(assoc_id, pkt_id, frag_total, frag_id, size, addr.clone());
		let header = Header::Packet(pkt);
		
		let mut buf = Vec::new();
		header.marshal(&mut buf).unwrap();
		
		let mut cursor = Cursor::new(buf);
		let decoded = Header::unmarshal(&mut cursor).unwrap();
		
		match decoded {
			Header::Packet(decoded_pkt) => {
				assert_eq!(decoded_pkt.assoc_id(), assoc_id);
				assert_eq!(decoded_pkt.pkt_id(), pkt_id);
				assert_eq!(decoded_pkt.frag_total(), frag_total);
				assert_eq!(decoded_pkt.frag_id(), frag_id);
				assert_eq!(decoded_pkt.size(), size);
			}
			_ => panic!("Wrong header type"),
		}
	}
}

#[cfg(feature = "marshal")]
#[test]
fn test_various_domain_names() {
	use std::io::Cursor;

	// Test various domain name lengths and formats
	let domains = vec![
		"a.b",                                   // Short domain
		"example.com",                           // Common domain
		"subdomain.example.com",                 // Subdomain
		"very.long.subdomain.example.com",      // Multiple subdomains
		"localhost",                             // Localhost
		"192-168-1-1.example.com",              // Dash-separated
		&"a".repeat(63),                        // Maximum label length
	];
	
	for domain in domains {
		let addr = Address::DomainAddress(domain.to_string(), 443);
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
			_ => panic!("Wrong header type"),
		}
	}
}

#[test]
fn test_address_serialization_lengths() {
	// Test that serialization lengths are calculated correctly
	let none_addr = Address::None;
	assert_eq!(none_addr.len(), 1);
	
	let domain_addr = Address::DomainAddress("example.com".to_string(), 443);
	assert_eq!(domain_addr.len(), 1 + 1 + "example.com".len() + 2);
	
	let ipv4_addr = Address::SocketAddress("192.168.1.1:8080".parse().unwrap());
	assert_eq!(ipv4_addr.len(), 1 + 4 + 2);
	
	let ipv6_addr = Address::SocketAddress("[2001:db8::1]:9000".parse().unwrap());
	assert_eq!(ipv6_addr.len(), 1 + 16 + 2);
}

#[test]
fn test_header_serialization_lengths() {
	// Test that header lengths are calculated correctly
	let uuid = Uuid::new_v4();
	let token = [0u8; 32];
	let auth = Authenticate::new(uuid, token);
	let header = Header::Authenticate(auth);
	assert_eq!(header.len(), 2 + 48); // version + type + auth data
	
	let conn = Connect::new(Address::None);
	let header = Header::Connect(conn);
	assert_eq!(header.len(), 2 + 1); // version + type + address
	
	let pkt = Packet::new(1, 2, 3, 4, 5, Address::None);
	let header = Header::Packet(pkt);
	assert_eq!(header.len(), 2 + 2 + 2 + 1 + 1 + 2 + 1); // version + type + packet fields + address
	
	let dissoc = Dissociate::new(100);
	let header = Header::Dissociate(dissoc);
	assert_eq!(header.len(), 2 + 2); // version + type + assoc_id
	
	let hb = Heartbeat::new();
	let header = Header::Heartbeat(hb);
	assert_eq!(header.len(), 2); // version + type only
}
