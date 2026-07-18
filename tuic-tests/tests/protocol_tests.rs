//! Protocol- and config-level tests for the shared `tuic-core` crate and the
//! `tuic-server` `[backend]` configuration.
//!
//! These complement the end-to-end tests in `integration_tests.rs`:
//!
//! * The TUIC wire codecs and the free decode helpers now live in `tuic-core`
//!   and are shared verbatim by both the quinn (`wind-tuic`) and tokio-quiche
//!   (`wind-tuiche`) backends. The tests below pin the on-wire byte layout,
//!   verify the codec/decoder paths agree, and exercise the error handling that
//!   the production read paths rely on.
//! * The UDP fragment-reassembly state machine (also shared via `tuic-core`) is
//!   driven through a few representative scenarios from a consumer crate.
//! * The new `[backend]` config section (mode + per-backend tuning) is checked
//!   for sane defaults and deserialization.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::Encoder;
use tuic_core::proto::{
	Address, AddressCodec, CmdCodec, CmdType, Command, Header, HeaderCodec, VER, address_to_target, decode_address,
	decode_command, decode_header,
};
use uuid::Uuid;
use wind_core::types::TargetAddr;

// ---------------------------------------------------------------------------
// Wire-format stability — lock the exact on-wire byte layout so the
// tuic-core extraction (and any future codec change) cannot silently alter it.
// ---------------------------------------------------------------------------

fn encode(header: CmdType, command: Command, address: Option<Address>) -> BytesMut {
	let mut buf = BytesMut::new();
	HeaderCodec.encode(Header::new(header), &mut buf).unwrap();
	CmdCodec(header).encode(command, &mut buf).unwrap();
	if let Some(addr) = address {
		AddressCodec.encode(addr, &mut buf).unwrap();
	}
	buf
}

#[test]
fn wire_format_connect_ipv4_is_stable() {
	let buf = encode(
		CmdType::Connect,
		Command::Connect,
		Some(Address::IPv4(Ipv4Addr::LOCALHOST, 80)),
	);
	// VER(5) CMD(Connect=1) ATYP(IPv4=1) 127.0.0.1 port=80(0x0050)
	assert_eq!(&buf[..], &[VER, 1, 1, 127, 0, 0, 1, 0, 80]);
}

#[test]
fn wire_format_auth_is_stable() {
	let buf = encode(
		CmdType::Auth,
		Command::Auth {
			uuid: Uuid::from_u128(0),
			token: [1u8; 32],
		},
		None,
	);
	let mut expected = vec![VER, 0];
	expected.extend_from_slice(&[0u8; 16]); // uuid
	expected.extend_from_slice(&[1u8; 32]); // token
	assert_eq!(&buf[..], &expected[..]);
}

#[test]
fn wire_format_domain_address_is_stable() {
	let mut buf = BytesMut::new();
	AddressCodec
		.encode(Address::Domain("ab.cd".to_string(), 443), &mut buf)
		.unwrap();
	// ATYP(Domain=0) LEN(5) "ab.cd" port=443(0x01BB)
	assert_eq!(&buf[..], &[0, 5, b'a', b'b', b'.', b'c', b'd', 0x01, 0xBB]);
}

// ---------------------------------------------------------------------------
// The free `decode_*` helpers (used on the production hot path by both
// backends) must agree with the `Encoder` codecs for every command/address.
// ---------------------------------------------------------------------------

#[test]
fn decode_helpers_agree_with_codecs_for_all_commands() {
	// Connect + every address type.
	for addr in [
		Address::None,
		Address::IPv4(Ipv4Addr::new(10, 0, 0, 1), 1234),
		Address::IPv6(Ipv6Addr::LOCALHOST, 8443),
		Address::Domain("example.test".to_string(), 53),
	] {
		let frame = encode(CmdType::Connect, Command::Connect, Some(addr.clone()));
		let mut b: Bytes = frame.freeze();
		let header = decode_header(&mut b, "connect").unwrap();
		assert_eq!(header.command, CmdType::Connect);
		assert!(matches!(
			decode_command(CmdType::Connect, &mut b, "connect").unwrap(),
			Command::Connect
		));
		assert_eq!(decode_address(&mut b, "connect").unwrap(), addr);
		assert_eq!(b.remaining(), 0, "frame should be fully consumed");
	}

	// Packet command round-trip via the helper.
	let frame = encode(
		CmdType::Packet,
		Command::Packet {
			assoc_id: 7,
			pkt_id: 9,
			frag_total: 3,
			frag_id: 1,
			size: 4,
		},
		Some(Address::IPv4(Ipv4Addr::LOCALHOST, 9000)),
	);
	let mut b: Bytes = {
		let mut buf = frame;
		buf.extend_from_slice(b"data"); // 4-byte payload
		buf.freeze()
	};
	let header = decode_header(&mut b, "packet").unwrap();
	assert_eq!(header.command, CmdType::Packet);
	let cmd = decode_command(CmdType::Packet, &mut b, "packet").unwrap();
	let Command::Packet { assoc_id, size, .. } = cmd else {
		panic!("expected Packet");
	};
	assert_eq!(assoc_id, 7);
	assert_eq!(size, 4);
	let addr = decode_address(&mut b, "packet").unwrap();
	assert_eq!(addr, Address::IPv4(Ipv4Addr::LOCALHOST, 9000));
	assert_eq!(b.remaining(), size as usize);
	assert_eq!(&b.copy_to_bytes(size as usize)[..], b"data");

	// Dissociate + Heartbeat.
	let frame = encode(CmdType::Dissociate, Command::Dissociate { assoc_id: 42 }, None);
	let mut b = frame.freeze();
	let _ = decode_header(&mut b, "diss").unwrap();
	assert!(matches!(
		decode_command(CmdType::Dissociate, &mut b, "diss").unwrap(),
		Command::Dissociate { assoc_id: 42 }
	));

	let frame = encode(CmdType::Heartbeat, Command::Heartbeat, None);
	let mut b = frame.freeze();
	let header = decode_header(&mut b, "hb").unwrap();
	assert_eq!(header.command, CmdType::Heartbeat);
}

// ---------------------------------------------------------------------------
// Malformed / truncated input must produce errors, never panics.
// ---------------------------------------------------------------------------

#[test]
fn decode_header_rejects_bad_version_and_unknown_command() {
	// Wrong version byte.
	let mut b: &[u8] = &[VER + 1, 1];
	assert!(decode_header(&mut b, "ctx").is_err());

	// Unknown command type (5 is not a defined CmdType).
	let mut b: &[u8] = &[VER, 5];
	assert!(decode_header(&mut b, "ctx").is_err());

	// Truncated (only the version byte).
	let mut b: &[u8] = &[VER];
	assert!(decode_header(&mut b, "ctx").is_err());
}

#[test]
fn decode_command_and_address_reject_truncated_input() {
	// Auth needs 16 + 32 bytes of body; give it fewer.
	let mut b: &[u8] = &[0u8; 10];
	assert!(decode_command(CmdType::Auth, &mut b, "ctx").is_err());

	// Packet command needs 8 bytes.
	let mut b: &[u8] = &[0u8; 3];
	assert!(decode_command(CmdType::Packet, &mut b, "ctx").is_err());

	// Domain address (ATYP=0 on the wire) claiming length 5 but with no body.
	let mut b: &[u8] = &[0, 0x05];
	assert!(decode_address(&mut b, "ctx").is_err());

	// IPv4 address (ATYP=1) missing the final port byte.
	let mut b: &[u8] = &[1, 127, 0, 0, 1, 0];
	assert!(decode_address(&mut b, "ctx").is_err());
}

// ---------------------------------------------------------------------------
// TargetAddr <-> Address conversions (shared by both backends).
// ---------------------------------------------------------------------------

#[test]
fn target_addr_roundtrips_through_address_and_wire() {
	let targets = [
		TargetAddr::IPv4(Ipv4Addr::new(203, 0, 113, 7), 443),
		TargetAddr::IPv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9000),
		TargetAddr::Domain("proxy.example".to_string(), 8080),
	];
	for target in targets {
		// TargetAddr -> Address -> wire -> Address -> TargetAddr
		let addr: Address = target.clone().into();
		let mut buf = BytesMut::new();
		AddressCodec.encode(addr, &mut buf).unwrap();
		let mut b = buf.freeze();
		let decoded = decode_address(&mut b, "rt").unwrap();
		assert_eq!(address_to_target(decoded).unwrap(), target);
	}
}

#[test]
fn address_none_cannot_become_target() {
	assert!(address_to_target(Address::None).is_err());
}

// ---------------------------------------------------------------------------
// UDP fragment reassembly state machine (shared via tuic-core), driven from a
// consumer crate to confirm the public API is usable end-to-end.
// ---------------------------------------------------------------------------

mod udp {
	use std::net::Ipv4Addr;

	use bytes::Bytes;
	use tuic_core::udp::{FragmentInfo, FragmentReassemblyBuffer};
	use wind_core::types::TargetAddr;

	fn info(frag_total: u8, frag_id: u8, target: TargetAddr) -> FragmentInfo {
		FragmentInfo {
			assoc_id: 1,
			pkt_id: 7,
			frag_total,
			frag_id,
			source: None,
			target,
		}
	}

	#[tokio::test]
	async fn single_fragment_completes_immediately() {
		let buf = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::LOCALHOST, 9);
		let pkt = buf
			.add_fragment(info(1, 0, target.clone()), Bytes::from_static(b"hello"))
			.await
			.expect("single fragment completes");
		assert_eq!(&pkt.payload[..], b"hello");
		assert_eq!(pkt.target, target);
	}

	#[tokio::test]
	async fn out_of_order_fragments_reassemble() {
		let buf = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::LOCALHOST, 9);
		assert!(
			buf.add_fragment(info(3, 2, target.clone()), Bytes::from_static(b"C"))
				.await
				.is_none()
		);
		assert!(
			buf.add_fragment(info(3, 0, target.clone()), Bytes::from_static(b"A"))
				.await
				.is_none()
		);
		let pkt = buf
			.add_fragment(info(3, 1, target.clone()), Bytes::from_static(b"B"))
			.await
			.expect("third fragment completes the packet");
		assert_eq!(&pkt.payload[..], b"ABC");
	}

	#[tokio::test]
	async fn forged_fragment_fields_are_rejected() {
		let buf = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::LOCALHOST, 9);
		// frag_total == 0 is meaningless.
		assert!(
			buf.add_fragment(info(0, 0, target.clone()), Bytes::from_static(b"x"))
				.await
				.is_none()
		);
		// frag_id >= frag_total is out of range.
		assert!(
			buf.add_fragment(info(2, 5, target.clone()), Bytes::from_static(b"x"))
				.await
				.is_none()
		);
		// A legitimate packet still reassembles afterwards.
		assert!(
			buf.add_fragment(info(2, 0, target.clone()), Bytes::from_static(b"AA"))
				.await
				.is_none()
		);
		let pkt = buf
			.add_fragment(info(2, 1, target.clone()), Bytes::from_static(b"BB"))
			.await
			.expect("legitimate packet completes");
		assert_eq!(&pkt.payload[..], b"AABB");
	}
}

// ---------------------------------------------------------------------------
// `[backend]` configuration: mode selection + per-backend tuning subsections.
// ---------------------------------------------------------------------------

mod backend_config {
	use tuic_server::config::{BackendConfig, BackendMode};

	#[test]
	fn defaults_to_quinn() {
		let cfg = BackendConfig::default();
		assert_eq!(cfg.mode, BackendMode::Quinn);
		// Per-backend tuning falls back to sane defaults.
		assert_eq!(cfg.quinn.initial_mtu, 1200);
		assert_eq!(cfg.quiche.max_concurrent_bi_streams, 100);
	}

	#[test]
	fn deserializes_quiche_mode_with_subsections() {
		let cfg: BackendConfig = json5::from_str(
			r#"{
				mode: "quiche",
				quinn: { initial_mtu: 1400 },
				quiche: { max_concurrent_bi_streams: 50, zero_rtt: true }
			}"#,
		)
		.expect("backend config should deserialize");

		assert_eq!(cfg.mode, BackendMode::Quiche);
		assert_eq!(cfg.quinn.initial_mtu, 1400);
		assert_eq!(cfg.quiche.max_concurrent_bi_streams, 50);
		assert!(cfg.quiche.zero_rtt);
		// Unspecified quiche fields keep their defaults.
		assert_eq!(cfg.quiche.max_concurrent_uni_streams, 100);
	}

	#[test]
	fn mode_is_case_insensitive_lowercase_only() {
		// serde rename_all = "lowercase": only the lowercase spelling is valid.
		assert_eq!(json5::from_str::<BackendMode>(r#""quiche""#).unwrap(), BackendMode::Quiche);
		assert!(json5::from_str::<BackendMode>(r#""Quiche""#).is_err());
	}
}
