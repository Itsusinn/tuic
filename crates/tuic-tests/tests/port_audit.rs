//! Guards the `ipv6_integration` module header against a stale port list.
//!
//! The test binds both the TUIC server and the SOCKS5 listener to `:0` and
//! reads the port back from the returned guard. A header that still cites a
//! fixed port therefore describes an address the test never uses, which is how
//! it read while the code was being migrated off hardcoded ports. Keeping this
//! audit beside the test file lets it inspect the real header without matching
//! its own examples.

/// The paths the ipv6 integration test binds to `:0`; none of them may be
/// documented with a fixed port. IPv4 is included because the same test
/// material is copied between the IPv4 and IPv6 variants.
const DYNAMIC_HOSTS: &[&str] = &["[::1]", "127.0.0.1"];

/// The test file whose header is audited.
const TEST_FILE: &str = "ipv6_integration.rs";

/// Whether `line` is a plain `//` comment. Doc comments (`//!`, `///`) document
/// modules and items, not the list of addresses the test uses.
fn is_comment(line: &str) -> bool {
	let line = line.trim_end();
	line.starts_with("//") && !line.starts_with("//!") && !line.starts_with("///")
}

/// Every run of consecutive plain `//` lines, in source order, separated by the
/// non-comment lines between them.
fn comment_blocks(source: &str) -> Vec<Vec<&str>> {
	let mut blocks: Vec<Vec<&str>> = vec![Vec::new()];
	for line in source.lines() {
		if is_comment(line) {
			if let Some(block) = blocks.last_mut() {
				block.push(line);
			}
		} else {
			blocks.push(Vec::new());
		}
	}
	blocks
}

/// The first non-empty comment block: the list of addresses and relays this
/// test claims to set up.
fn module_header(source: &str) -> Vec<&str> {
	comment_blocks(source)
		.into_iter()
		.find(|block| !block.is_empty())
		.unwrap_or_default()
}

/// Whether `line` writes `host:port` for one of `hosts` with a fixed,
/// non-zero port, e.g. `[::1]:8444` or `127.0.0.1:1081`.
fn names_a_fixed_port(line: &str, hosts: &[&str]) -> bool {
	hosts.iter().any(|host| {
		line.match_indices(host).any(
			|(at, _)| matches!(&line.as_bytes()[at + host.len()..], [b':', digit, ..] if digit.is_ascii_digit() && *digit != b'0'),
		)
	})
}

/// The header lines that still name a loopback host with a fixed port.
fn cited_fixed_ports(header: &[&str], hosts: &[&str]) -> Vec<String> {
	header
		.iter()
		.copied()
		.filter(|line| names_a_fixed_port(line, hosts))
		.map(str::to_string)
		.collect()
}

/// The detector has to fire on a fixed non-zero port, otherwise it would guard
/// nothing.
#[test]
fn a_header_that_cites_a_fixed_port_is_rejected() {
	let hosts = ["192.0.2.10"];
	let cited = [
		"// - Server listening on 192.0.2.10:8444 (localhost)",
		"// - SOCKS5 proxy on 192.0.2.10:1081",
	];
	assert!(
		cited.iter().all(|line| names_a_fixed_port(line, &hosts)),
		"the detector must flag a fixed non-zero port"
	);
	assert_eq!(
		cited_fixed_ports(&cited, &hosts).len(),
		cited.len(),
		"each citing line must be reported"
	);
}

/// A dynamic bind, a bare host and unrelated numbers are not citations.
#[test]
fn a_dynamic_bind_and_its_derived_addresses_are_accepted() {
	let hosts = ["192.0.2.10"];
	let dynamic = [
		"server: \"192.0.2.10:0\".parse::<SocketAddr>()?,",
		"// - Server bound on 192.0.2.10:0 (localhost, OS-assigned port)",
		"// - Server bound on 192.0.2.10 (localhost, OS-assigned port)",
		"server: (\"192.0.2.10\".to_string(), server.local_addr.port()),",
		"// the caller keeps the 8444 constant for its own retry budget",
	];
	assert!(
		dynamic.iter().all(|line| !names_a_fixed_port(line, &hosts)),
		"a zero port, a bare host and an unrelated number must not be flagged"
	);
	assert!(
		cited_fixed_ports(&dynamic, &hosts).is_empty(),
		"none of the accepted lines may be reported"
	);
}

/// The header is the first plain comment block, and it stops at the first line
/// that is not one: the module doc comment above it and the items below it are
/// not claims about the ports in use.
#[test]
fn the_header_is_the_first_plain_comment_block() {
	let source = "//! doc\n\n#![allow(unused_imports)]\n\n// first claim\n// second claim\n\nconst X: u8 = 1;\n// an example \
	              192.0.2.10:8444\n";
	let header = module_header(source);
	assert_eq!(
		header,
		["// first claim", "// second claim"],
		"the header block must stop at the blank line"
	);
	assert!(
		cited_fixed_ports(&header, &["192.0.2.10"]).is_empty(),
		"a claim below the header must not be audited"
	);
}

/// The header of the real test file cites no fixed port.
#[test]
fn the_module_header_cites_no_fixed_port() {
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/ipv6_integration.rs");
	let source = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path} to audit its header: {e}"));
	let header = module_header(&source);
	assert!(
		!header.is_empty(),
		"{TEST_FILE} must document the endpoints it sets up, but no comment block was found"
	);
	let cited = cited_fixed_ports(&header, DYNAMIC_HOSTS);
	assert!(
		cited.is_empty(),
		"the header must describe the bind request, not an address the OS assigns, but these lines still name a fixed port: \
		 {cited:?}"
	);
}
