//! CodSpeed benchmark harness for the TUIC workspace.
//!
//! Run it through the CodSpeed CLI (`cargo codspeed run --bench codspeed`) or
//! directly (`cargo bench --bench codspeed`); both execute the same functions,
//! because `criterion` here is the `codspeed-criterion-compat` mirror.
//!
//! The suite is layered, because the layers need different instrumentation
//! modes:
//!
//! * **In-process cases** (the TUIC wire codecs in both directions — the
//!   `Encoder`/`Decoder` pair and the free `decode_*` helpers production
//!   actually calls — native-mode UDP fragment reassembly and capacity
//!   eviction, legacy ACL parsing and lowering, startup configuration parsing)
//!   run in every mode, including `memory` under Valgrind.
//! * **End-to-end cases** (a real `tuic-server` + `tuic-client` pair relaying
//!   TCP and a fragmented UDP datagram through a loopback SOCKS5 proxy, quinn
//!   and quiche backends) are admitted only when `TUIC_BENCH_E2E` is set. A
//!   Valgrind-instrumented loop cannot complete a QUIC handshake in a usable
//!   amount of time, so those cases belong on the self-hosted `walltime`
//!   runner, which sets `TUIC_BENCH_E2E=all`; see
//!   `.github/workflows/codspeed.yml`.
//!
//! Configuration inputs come from the existing TUIC fixtures
//! (`tuic-{server,client}/tests/config/*.toml`) rather than hand-written
//! copies, so the benchmarks parse exactly what the configuration regressions
//! already cover.

use std::{
	hint::black_box,
	net::{Ipv4Addr, Ipv6Addr},
	time::Duration,
};

use criterion::{criterion_group, criterion_main};
use tokio_util::codec::{Decoder as _, Encoder as _};
use tuic_server::{
	config::EnvState as ServerEnvState,
	legacy::{acl_to_rules, parse_acl_rule, parse_multiline_acl_string},
};
use wind_core::types::TargetAddr;
use wind_tuic::{
	proto::{Address, AddressCodec, CmdCodec, CmdType, Command, Header, HeaderCodec},
	udp::{FragmentInfo, FragmentReassemblyBuffer},
};

mod fixtures {
	//! Parse inputs, taken from the crate fixtures that already gate these
	//! configuration formats in `cargo test`.

	/// A complete `tuic-server` configuration: legacy `[quic]` transport keys
	/// (migrated on parse) plus a `[users]` table.
	pub const SERVER_TOML: &str = include_str!("../../tuic-server/tests/config/valid_toml_config.toml");

	/// A `tuic-server` configuration whose `rules` array covers the Metacubex
	/// rule types the server compiles at startup.
	pub const SERVER_RULES_TOML: &str = include_str!("../../tuic-server/tests/config/rules_parsing.toml");

	/// A `tuic-server` configuration with an indented multi-line legacy `acl`
	/// string; the parser trims every line itself.
	pub const SERVER_ACL_TOML: &str = include_str!("../../tuic-server/tests/config/acl_parsing.toml");

	/// A fully populated `tuic-client` configuration: relay, TLS, backend
	/// tuning, and the local SOCKS5 listener.
	pub const CLIENT_TOML: &str = include_str!("../../tuic-client/tests/config/toml_full_config.toml");

	/// One multi-line ACL block containing every dialect shape the parser
	/// accepts: bare ports, explicit `tcp/`+`udp/` lists, comments, CIDR, exact
	/// domain, wildcard domain, a named outbound, and a hijack target.
	pub const ACL_BLOCK: &str = "\
allow localhost udp/53
allow localhost udp/53,tcp/80,tcp/443,udp/443
# if udp/tcp is omitted, match both
allow localhost 443
reject 10.6.0.0/16
allow google.com
allow *.google.com
reject *.cn
reject localhost
custom_outbound_name example.com 80,443
default 8.8.4.4 udp/53 1.1.1.1";
}

/// The relay target used by the fragment cases. It is never dialed: reassembly
/// is pure bookkeeping.
const FRAGMENT_TARGET: TargetAddr = TargetAddr::IPv4(Ipv4Addr::new(192, 0, 2, 20), 443);

// ===========================================================================
// Runtimes
// ===========================================================================

/// Runtime for the in-process cases: they only await codec-free futures that
/// complete immediately, so a current-thread runtime with a timer is enough.
fn micro_runtime() -> tokio::runtime::Runtime {
	tokio::runtime::Builder::new_current_thread()
		.enable_time()
		.build()
		.unwrap_or_else(|error| panic!("tokio runtime build failed: {error}"))
}

/// Runtime for the end-to-end cases: real sockets, timers, and QUIC drivers.
fn e2e_runtime() -> tokio::runtime::Runtime {
	tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.worker_threads(2)
		.build()
		.unwrap_or_else(|error| panic!("tokio runtime build failed: {error}"))
}

// ===========================================================================
// TUIC wire codecs
// ===========================================================================

/// The per-packet header/command/address encode + decode path shared by the
/// quinn and quiche backends.
fn bench_wire_codec(c: &mut criterion::Criterion) {
	let mut group = c.benchmark_group("tuic/proto");

	// `Header` is not `Copy`, and the two-byte construction is part of the
	// encoder's own cost, so build it per iteration rather than cloning a
	// captured value.
	let mut header_codec = HeaderCodec;
	group.bench_function("header encode+decode", |b| {
		let mut buf = bytes::BytesMut::with_capacity(2);
		b.iter(|| {
			header_codec
				.encode(Header::new(CmdType::Connect), &mut buf)
				.unwrap_or_else(|error| panic!("header encode failed: {error}"));
			let decoded = header_codec
				.decode(&mut buf)
				.unwrap_or_else(|error| panic!("header decode failed: {error}"));
			black_box(decoded)
		})
	});

	for (label, address) in [
		("domain", Address::Domain("benchmark.example.com".to_string(), 8443)),
		("ipv4", Address::IPv4(Ipv4Addr::new(192, 0, 2, 10), 443)),
		("ipv6", Address::IPv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10), 443)),
	] {
		let mut address_codec = AddressCodec;
		group.bench_function(format!("address encode+decode ({label})"), |b| {
			let mut buf = bytes::BytesMut::with_capacity(32);
			b.iter(|| {
				address_codec
					.encode(address.clone(), &mut buf)
					.unwrap_or_else(|error| panic!("address encode failed: {error}"));
				let decoded = address_codec
					.decode(&mut buf)
					.unwrap_or_else(|error| panic!("address decode failed: {error}"));
				black_box(decoded)
			})
		});
	}

	// The address a client sends in a CONNECT/PACKET command, plus the
	// conversion the server performs before it dials the target.
	let mut target_codec = AddressCodec;
	group.bench_function("address decode + to target", |b| {
		let mut buf = bytes::BytesMut::with_capacity(32);
		b.iter(|| {
			buf.clear();
			target_codec
				.encode(Address::Domain("benchmark.example.com".to_string(), 443), &mut buf)
				.unwrap_or_else(|error| panic!("address encode failed: {error}"));
			let decoded = target_codec
				.decode(&mut buf)
				.unwrap_or_else(|error| panic!("address decode failed: {error}"));
			black_box(decoded.map(wind_tuic::proto::address_to_target).and_then(Result::ok))
		})
	});

	let mut connect_codec = CmdCodec(CmdType::Connect);
	group.bench_function("command connect encode+decode", |b| {
		let mut buf = bytes::BytesMut::with_capacity(8);
		b.iter(|| {
			connect_codec
				.encode(Command::Connect, &mut buf)
				.unwrap_or_else(|error| panic!("command encode failed: {error}"));
			let decoded = connect_codec
				.decode(&mut buf)
				.unwrap_or_else(|error| panic!("command decode failed: {error}"));
			black_box(decoded)
		})
	});

	let packet = Command::Packet {
		assoc_id: 7,
		pkt_id: 42,
		frag_total: 4,
		frag_id: 2,
		size: 1200,
	};
	let mut packet_codec = CmdCodec(CmdType::Packet);
	group.bench_function("command packet encode+decode", |b| {
		let mut buf = bytes::BytesMut::with_capacity(8);
		b.iter(|| {
			packet_codec
				.encode(packet.clone(), &mut buf)
				.unwrap_or_else(|error| panic!("command encode failed: {error}"));
			let decoded = packet_codec
				.decode(&mut buf)
				.unwrap_or_else(|error| panic!("command decode failed: {error}"));
			black_box(decoded)
		})
	});

	let auth = Command::Auth {
		uuid: uuid::Uuid::nil(),
		token: [0x5a; 32],
	};
	let mut auth_codec = CmdCodec(CmdType::Auth);
	group.bench_function("command auth encode+decode", |b| {
		let mut buf = bytes::BytesMut::with_capacity(48);
		b.iter(|| {
			auth_codec
				.encode(auth.clone(), &mut buf)
				.unwrap_or_else(|error| panic!("command encode failed: {error}"));
			let decoded = auth_codec
				.decode(&mut buf)
				.unwrap_or_else(|error| panic!("command decode failed: {error}"));
			black_box(decoded)
		})
	});

	// The free helpers the server and both front-ends call per command. They
	// are not the `Decoder` impls above: those serve `FramedRead`-style
	// consumers and map incomplete input to `Ok(None)`, while production
	// parses an already-assembled command and maps incomplete input to an
	// error.
	let mut header_bytes = bytes::BytesMut::with_capacity(2);
	header_codec
		.encode(Header::new(CmdType::Connect), &mut header_bytes)
		.unwrap_or_else(|error| panic!("header encode failed: {error}"));
	let header_bytes = header_bytes.freeze();
	group.bench_function("decode header (production helper)", |b| {
		b.iter(|| {
			let mut buf = header_bytes.clone();
			black_box(
				wind_tuic::proto::decode_header(&mut buf, "bench")
					.unwrap_or_else(|error| panic!("header decode failed: {error}")),
			)
		})
	});

	let mut packet_bytes = bytes::BytesMut::with_capacity(8);
	packet_codec
		.encode(packet.clone(), &mut packet_bytes)
		.unwrap_or_else(|error| panic!("command encode failed: {error}"));
	let packet_bytes = packet_bytes.freeze();
	group.bench_function("decode packet command (production helper)", |b| {
		b.iter(|| {
			let mut buf = packet_bytes.clone();
			black_box(
				wind_tuic::proto::decode_command(CmdType::Packet, &mut buf, "bench")
					.unwrap_or_else(|error| panic!("command decode failed: {error}")),
			)
		})
	});

	let mut address_bytes = bytes::BytesMut::with_capacity(32);
	let mut address_codec = AddressCodec;
	address_codec
		.encode(Address::Domain("benchmark.example.com".to_string(), 443), &mut address_bytes)
		.unwrap_or_else(|error| panic!("address encode failed: {error}"));
	let address_bytes = address_bytes.freeze();
	group.bench_function("decode address (production helper)", |b| {
		b.iter(|| {
			let mut buf = address_bytes.clone();
			black_box(
				wind_tuic::proto::decode_address(&mut buf, "bench")
					.unwrap_or_else(|error| panic!("address decode failed: {error}")),
			)
		})
	});

	group.finish();
}

// ===========================================================================
// Native-mode UDP fragment reassembly
// ===========================================================================

/// Add one fragment, discarding the (ordinary: group still incomplete) result.
fn push_fragment(
	runtime: &tokio::runtime::Runtime,
	buffer: &FragmentReassemblyBuffer,
	assoc_id: u16,
	pkt_id: u16,
	frag_total: u8,
	frag_id: u8,
) {
	black_box(runtime.block_on(buffer.add_fragment(
		FragmentInfo {
			assoc_id,
			pkt_id,
			frag_total,
			frag_id,
			source: None,
			target: FRAGMENT_TARGET,
		},
		bytes::Bytes::from_static(&[0u8; 64]),
	)));
}

/// The receive path that turns attacker-controlled fragments back into one
/// datagram.
fn bench_udp_fragments(c: &mut criterion::Criterion) {
	let runtime = micro_runtime();
	let mut group = c.benchmark_group("tuic/udp");
	// Keep the memory-instrumented run bounded: both cases insert many groups.
	group.sample_size(20);
	group.measurement_time(Duration::from_secs(10));

	// 16 fragments of 1400 bytes — a ~22 KiB datagram — replayed as one
	// reassembly per iteration. The payload arrives as one `Bytes` and is
	// sliced per fragment the way a QUIC datagram buffer would be, so the
	// measurement is the reassembly itself rather than the input allocation.
	group.bench_function("reassemble 16x1400B", |b| {
		let mut payload = bytes::BytesMut::with_capacity(16 * 1400);
		let mut chunk = [0u8; 1400];
		for frag_id in 0..16u8 {
			chunk.fill(frag_id);
			payload.extend_from_slice(&chunk);
		}
		let payload = payload.freeze();
		b.iter_batched(
			|| {
				let buffer = FragmentReassemblyBuffer::default();
				(payload.clone(), buffer)
			},
			|(mut payload, buffer)| {
				runtime.block_on(async {
					let mut reassembled = None;
					for frag_id in 0..16u8 {
						reassembled = buffer
							.add_fragment(
								FragmentInfo {
									assoc_id: 1,
									pkt_id: 1,
									frag_total: 16,
									frag_id,
									source: Some(FRAGMENT_TARGET),
									target: FRAGMENT_TARGET,
								},
								payload.split_to(1400),
							)
							.await;
					}
					black_box(reassembled)
				})
			},
			criterion::BatchSize::SmallInput,
		)
	});

	// Capacity pressure. `FragmentReassemblyBuffer` keeps at most
	// `MAX_INCOMPLETE_GROUPS` (1000) incomplete groups and drops the oldest
	// when a new group would exceed it, so the setup fills the buffer to
	// exactly that bound and the measured step is the one insertion that
	// has to evict. The bound is a private constant; this literal has to
	// track it, because a larger bound would silently turn this case back
	// into plain insertion.
	group.bench_function("insert at the 1000-group bound (evicts oldest)", |b| {
		b.iter_batched(
			|| {
				let buffer = FragmentReassemblyBuffer::default();
				for assoc_id in 0..1000u16 {
					push_fragment(&runtime, &buffer, assoc_id, 1, 2, 1);
				}
				buffer
			},
			|buffer| {
				push_fragment(&runtime, &buffer, 1000, 1, 2, 1);
				black_box(())
			},
			criterion::BatchSize::LargeInput,
		)
	});

	group.finish();
}

// ===========================================================================
// Legacy ACL parsing and lowering
// ===========================================================================

/// The space-separated legacy ACL dialect, plus its lowering into the routing
/// rules the server compiles at startup.
fn bench_acl(c: &mut criterion::Criterion) {
	let mut group = c.benchmark_group("tuic/acl");

	group.bench_function("parse rule (localhost ports)", |b| {
		b.iter(|| {
			black_box(
				parse_acl_rule("allow localhost udp/53,tcp/80,tcp/443,udp/443")
					.unwrap_or_else(|error| panic!("ACL rule parse failed: {error}")),
			)
		})
	});

	group.bench_function("parse rule (wildcard domain)", |b| {
		b.iter(|| {
			black_box(
				parse_acl_rule("custom_outbound_name *.example.com 80-443")
					.unwrap_or_else(|error| panic!("ACL rule parse failed: {error}")),
			)
		})
	});

	group.bench_function("parse multiline block (10 rules)", |b| {
		b.iter(|| {
			black_box(
				parse_multiline_acl_string(fixtures::ACL_BLOCK)
					.unwrap_or_else(|error| panic!("ACL block parse failed: {error}")),
			)
		})
	});

	group.bench_function("parse + lower multiline block", |b| {
		b.iter(|| {
			let rules = parse_multiline_acl_string(fixtures::ACL_BLOCK)
				.unwrap_or_else(|error| panic!("ACL block parse failed: {error}"));
			black_box(acl_to_rules(&rules).unwrap_or_else(|error| panic!("ACL lowering failed: {error}")))
		})
	});

	group.finish();
}

// ===========================================================================
// Startup configuration parsing
// ===========================================================================

/// The scratch directory and config path a staged fixture uses.
struct StagedConfig {
	dir: tempfile::TempDir,
	path: std::path::PathBuf,
}

impl StagedConfig {
	fn cleanup(self) {
		drop(self.dir);
	}
}

/// Stage a fixture the way a deployment has it: a private scratch directory
/// holding the config file, with the fixture's `data_dir` — if it declares one
/// — retargeted inside that directory.
///
/// The retargeting matters: `parse_config` resolves a relative `data_dir`
/// against the process working directory and creates it, so running the
/// fixture unchanged would leave a stray directory next to the benchmark
/// binary. A field is never *added*: `tuic-client`'s schema denies unknown
/// fields, so injecting `data_dir` into a fixture that has none would turn the
/// case into a parse failure.
fn stage_config(contents: &str, name: &str) -> StagedConfig {
	let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
	let work = dir.path().join("work");
	let data_dir = work.join("data");
	std::fs::create_dir_all(&data_dir).unwrap_or_else(|error| panic!("scratch dir failed: {error}"));
	let data_dir_literal = data_dir.to_str().unwrap_or_else(|| panic!("temp dir path is not UTF-8"));

	// TOML basic strings escape the Windows separator; on Unix it is a no-op.
	let escaped = data_dir_literal.replace('\\', "\\\\");
	let staged = contents.replace("data_dir = \"", &format!("data_dir = \"{escaped}"));

	let path = work.join(name);
	std::fs::write(&path, staged).unwrap_or_else(|error| panic!("fixture write failed: {error}"));
	StagedConfig { dir, path }
}

/// Configuration parsing: read the file, merge Figment defaults, run the legacy
/// migration, and resolve relative paths against the data directory.
///
/// Staging the file (and removing the directory it resolves into) happens in
/// the batch setup, so the measurement is the parse rather than the filesystem
/// work around it.
fn bench_config(c: &mut criterion::Criterion) {
	let runtime = micro_runtime();
	let mut group = c.benchmark_group("tuic/config");

	for (name, contents) in [
		("server toml (legacy quic keys)", fixtures::SERVER_TOML),
		("server toml (routing rules)", fixtures::SERVER_RULES_TOML),
		("server toml (multiline acl)", fixtures::SERVER_ACL_TOML),
	] {
		group.bench_function(name, |b| {
			b.iter_batched(
				|| stage_config(contents, "config.toml"),
				|staged| {
					let cli = tuic_server::config::Cli {
						config: Some(staged.path.clone()),
						dir: None,
						init: false,
					};
					let parsed = runtime.block_on(tuic_server::config::parse_config(cli, ServerEnvState::default()));
					staged.cleanup();
					black_box(parsed.unwrap_or_else(|error| panic!("server config parse failed: {error}")))
				},
				criterion::BatchSize::SmallInput,
			)
		});
	}

	group.bench_function("client toml (full relay + backend)", |b| {
		b.iter_batched(
			|| stage_config(fixtures::CLIENT_TOML, "config.toml"),
			|staged| {
				let cli = tuic_client::config::Cli {
					config: Some(staged.path.clone()),
				};
				let parsed = tuic_client::config::Config::parse(cli, tuic_client::config::EnvState::default());
				staged.cleanup();
				black_box(parsed.unwrap_or_else(|error| panic!("client config parse failed: {error}")))
			},
			criterion::BatchSize::SmallInput,
		)
	});

	group.finish();
}

// ===========================================================================
// End-to-end relay
// ===========================================================================

/// Whether the end-to-end cases are admitted.
///
/// Off by default so `cargo bench` and the Valgrind-instrumented CodSpeed modes
/// stay in-process; the `walltime` CI job sets `TUIC_BENCH_E2E=all`.
fn e2e_enabled() -> bool {
	std::env::var("TUIC_BENCH_E2E").is_ok_and(|value| !value.is_empty() && value != "0")
}

/// Whether the end-to-end cases should also cover the quiche backend
/// (`TUIC_BENCH_E2E=quiche` or `all`). Compiled only with the `quiche` feature,
/// which is also the only configuration whose suite constructs that backend.
#[cfg(feature = "quiche")]
fn e2e_wants_quiche() -> bool {
	std::env::var("TUIC_BENCH_E2E").is_ok_and(|value| value.eq_ignore_ascii_case("quiche") || value.eq_ignore_ascii_case("all"))
}

/// A TCP echo server that serves every connection, so no benchmark iteration
/// waits on an accept that will never come.
async fn run_tcp_echo_loop() -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
	use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.unwrap_or_else(|error| panic!("echo listener failed: {error}"));
	let addr = listener
		.local_addr()
		.unwrap_or_else(|error| panic!("echo listener addr failed: {error}"));

	let task = tokio::spawn(async move {
		loop {
			let Ok((mut socket, _)) = listener.accept().await else {
				return;
			};
			tokio::spawn(async move {
				let mut buf = vec![0u8; 4096];
				loop {
					match socket.read(&mut buf).await {
						Ok(0) | Err(_) => return,
						Ok(n) => {
							if socket.write_all(&buf[..n]).await.is_err() {
								return;
							}
						}
					}
				}
			});
		}
	});

	(task, addr)
}

/// A UDP echo server that answers every datagram from every source, so the
/// retransmitting relay helper can always be served.
async fn run_udp_echo_loop() -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
	let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
		.await
		.unwrap_or_else(|error| panic!("UDP echo bind failed: {error}"));
	let addr = socket
		.local_addr()
		.unwrap_or_else(|error| panic!("UDP echo addr failed: {error}"));

	let task = tokio::spawn(async move {
		let socket = socket;
		let mut buf = vec![0u8; 65535];
		loop {
			let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
				return;
			};
			let _ = socket.send_to(&buf[..n], peer).await;
		}
	});

	(task, addr)
}

/// Both echo endpoints a relay bench case dials through the proxy.
struct EchoServers {
	tcp: tokio::task::JoinHandle<()>,
	tcp_addr: std::net::SocketAddr,
	udp: tokio::task::JoinHandle<()>,
	udp_addr: std::net::SocketAddr,
}

impl EchoServers {
	async fn start() -> Self {
		let (tcp, tcp_addr) = run_tcp_echo_loop().await;
		let (udp, udp_addr) = run_udp_echo_loop().await;
		Self {
			tcp,
			tcp_addr,
			udp,
			udp_addr,
		}
	}

	fn abort(self) {
		self.tcp.abort();
		self.udp.abort();
	}
}

/// Which QUIC backend the end-to-end pair drives.
#[derive(Clone, Copy, PartialEq, Eq)]
enum E2eBackend {
	Quinn,
	/// Only constructed where the workspace's `quiche` feature is on, which is
	/// also the only configuration in which this variant's match arm exists.
	#[cfg(feature = "quiche")]
	Quiche,
}

impl E2eBackend {
	fn label(self) -> &'static str {
		match self {
			Self::Quinn => "quinn",
			#[cfg(feature = "quiche")]
			Self::Quiche => "quiche",
		}
	}
}

/// Relay latency through a real TUIC pair: QUIC handshake, TUIC authentication,
/// and then either a TCP stream relay or a native-mode UDP datagram relay over
/// loopback. Every iteration dials a fresh SOCKS5 connection, so connection
/// setup is part of the measurement.
fn bench_e2e_backend(c: &mut criterion::Criterion, backend: E2eBackend) {
	let label = backend.label();
	let runtime = e2e_runtime();
	let mut group = c.benchmark_group("tuic/e2e");
	group.sample_size(10);
	group.measurement_time(Duration::from_secs(20));

	let echo = runtime.block_on(EchoServers::start());
	let pair = runtime.block_on(async {
		match backend {
			E2eBackend::Quinn => tuic_tests::start_quinn_pair(false).await,
			#[cfg(feature = "quiche")]
			E2eBackend::Quiche => tuic_tests::start_quiche_pair(false).await,
		}
	});
	let socks = pair.socks5_addr();

	group.bench_function(format!("tcp relay + echo first byte ({label})"), |b| {
		b.iter(|| {
			let socks = socks.clone();
			let payload = [0xa5u8; 1024];
			runtime.block_on(async {
				let ok = tokio::time::timeout(
					Duration::from_secs(10),
					tuic_tests::test_tcp_through_socks5(&socks, echo.tcp_addr, &payload, &format!("codspeed-tcp-{label}")),
				)
				.await
				.unwrap_or_else(|_| panic!("TCP relay bench iteration timed out"));
				assert!(ok, "TCP relay bench iteration did not echo its payload");
				black_box(ok)
			})
		})
	});

	// 4000 B is deliberately above the native-mode fragmentation threshold
	// (`max_datagram_size` minus header and address, roughly 1.2 KiB), so this
	// case drives the send-side split into fragments as well as reassembly on
	// the way back. 1024 B would stay on the single-datagram path.
	group.bench_function(format!("udp relay 4000B fragmented + echo ({label})"), |b| {
		b.iter(|| {
			let socks = socks.clone();
			// The relay helper binds its own send socket and lets the kernel
			// choose the port; `:0` is the address it asks SOCKS5 to associate
			// from.
			let bind = "127.0.0.1:0"
				.parse()
				.unwrap_or_else(|error| panic!("invalid bind addr: {error}"));
			let payload = [0x5au8; 4000];
			runtime.block_on(async {
				let ok = tokio::time::timeout(
					// Larger than the helper's own 5 s retransmit deadline, so a
					// slow relay is reported by the helper rather than here.
					Duration::from_secs(15),
					tuic_tests::test_udp_through_socks5_sized(
						&socks,
						echo.udp_addr,
						&payload,
						&format!("codspeed-udp-{label}"),
						bind,
						4096,
					),
				)
				.await
				.unwrap_or_else(|_| panic!("UDP relay bench iteration timed out"));
				assert!(ok, "UDP relay bench iteration did not echo its payload");
				black_box(ok)
			})
		})
	});

	group.finish();
	echo.abort();
	// `TestPair::shutdown` drains both processes and needs the runtime that
	// started them.
	runtime.block_on(pair.shutdown());
}

/// Relay latency through the default quinn backend; admitted by
/// `TUIC_BENCH_E2E`.
fn bench_e2e_quinn(c: &mut criterion::Criterion) {
	if !e2e_enabled() {
		return;
	}
	bench_e2e_backend(c, E2eBackend::Quinn);
}

/// The same relay cases over the tokio-quiche backend. Compiled only where
/// `tuic-server`/`tuic-client` expose it (64-bit hosts, `quiche` feature).
#[cfg(feature = "quiche")]
fn bench_e2e_quiche(c: &mut criterion::Criterion) {
	if !e2e_enabled() || !e2e_wants_quiche() {
		return;
	}
	bench_e2e_backend(c, E2eBackend::Quiche);
}

/// The quiche cases are compiled out on targets without the backend, so the
/// harness always builds; `TUIC_BENCH_E2E=quiche`/`all` selects them at
/// runtime.
#[cfg(not(feature = "quiche"))]
fn bench_e2e_quiche(_c: &mut criterion::Criterion) {}

fn all_benches(c: &mut criterion::Criterion) {
	bench_wire_codec(c);
	bench_udp_fragments(c);
	bench_acl(c);
	bench_config(c);
	bench_e2e_quinn(c);
	bench_e2e_quiche(c);
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
