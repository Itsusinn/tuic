//! Codec boundary cases; no client or server is started.
use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use wind_tuic::proto::{Address, AddressCodec, CmdCodec, CmdType, Command};

fn roundtrip_command(cmd_type: CmdType, command: Command) -> Command {
	let mut buf = BytesMut::new();
	CmdCodec(cmd_type).encode(command, &mut buf).unwrap();
	CmdCodec(cmd_type).decode(&mut buf).unwrap().unwrap()
}

fn roundtrip_address(addr: Address) -> Address {
	let mut buf = BytesMut::new();
	AddressCodec.encode(addr, &mut buf).unwrap();
	AddressCodec.decode(&mut buf).unwrap().unwrap()
}

#[test]
fn test_fragmented_udp_packets() {
	// Simulate a UDP packet split into 3 fragments
	let total_frags: u8 = 3;
	let assoc_id: u16 = 100;
	let pkt_id: u16 = 200;

	for frag_id in 0..total_frags {
		let addr = if frag_id == 0 {
			// First fragment has address
			Address::Domain("destination.com".to_string(), 5353)
		} else {
			// Subsequent fragments have no address
			Address::None
		};

		let cmd = Command::Packet {
			assoc_id,
			pkt_id,
			frag_total: total_frags,
			frag_id,
			size: 500,
		};

		let decoded_cmd = roundtrip_command(CmdType::Packet, cmd.clone());

		assert_eq!(&decoded_cmd, &cmd);

		let decoded_addr = roundtrip_address(addr.clone());
		assert_eq!(decoded_addr, addr);
	}
}

#[test]
fn test_edge_case_values() {
	let test_cases: Vec<(u16, u16, u8, u8, u16)> = vec![
		(0, 0, 1, 0, 0),                                      // Minimum values
		(u16::MAX, u16::MAX, u8::MAX, u8::MAX - 1, u16::MAX), // Maximum values
		(32768, 16384, 128, 64, 8192),                        // Mid-range values
	];

	for (assoc_id, pkt_id, frag_total, frag_id, size) in test_cases {
		let cmd = Command::Packet {
			assoc_id,
			pkt_id,
			frag_total,
			frag_id,
			size,
		};

		let decoded_cmd = roundtrip_command(CmdType::Packet, cmd.clone());

		match decoded_cmd {
			Command::Packet {
				assoc_id: d_assoc_id,
				pkt_id: d_pkt_id,
				frag_total: d_frag_total,
				frag_id: d_frag_id,
				size: d_size,
			} => {
				assert_eq!(d_assoc_id, assoc_id);
				assert_eq!(d_pkt_id, pkt_id);
				assert_eq!(d_frag_total, frag_total);
				assert_eq!(d_frag_id, frag_id);
				assert_eq!(d_size, size);
			}
			_ => panic!("Wrong command type"),
		}
	}
}

#[test]
fn test_various_domain_names() {
	let binding = "a".repeat(63);
	let domains = vec![
		"a.b",                             // Short domain
		"example.com",                     // Common domain
		"subdomain.example.com",           // Subdomain
		"very.long.subdomain.example.com", // Multiple subdomains
		"localhost",                       // Localhost
		"192-168-1-1.example.com",         // Dash-separated
		&binding,                          // Maximum label length
	];

	for domain in domains {
		let addr = Address::Domain(domain.to_string(), 443);
		let decoded_addr = roundtrip_address(addr.clone());
		assert_eq!(decoded_addr, addr);
	}
}
