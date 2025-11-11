use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use derive_more::Display;
use pest::Parser;
use pest_derive::Parser;
use serde::{Deserialize, Deserializer, Serialize, de};

#[derive(Parser)]
#[grammar = "acl.pest"]
struct AclParser;

/// Represents a single ACL rule with parsed components
#[derive(Debug, Clone, PartialEq, Serialize, Display)]
#[display("{outbound} {addr}{}", format_optional_parts(ports, hijack))]
pub struct AclRule {
	/// The outbound name to use for this rule
	pub outbound: String,
	/// The target address (IP, CIDR, domain, wildcard domain)
	pub addr:     AclAddress,
	/// Optional port specifications
	pub ports:    Option<AclPorts>,
	/// Optional hijack IP address for redirection
	pub hijack:   Option<String>,
}

fn format_optional_parts(ports: &Option<AclPorts>, hijack: &Option<String>) -> String {
	let mut result = String::new();
	if let Some(p) = ports {
		result.push_str(&format!(" {}", p));
	}
	if let Some(h) = hijack {
		result.push_str(&format!(" {}", h));
	}
	result
}

/// Represents different types of addresses in ACL rules
#[derive(Debug, Clone, PartialEq, Serialize, Display)]
pub enum AclAddress {
	/// Single IP address (IPv4 or IPv6)
	#[display("{_0}")]
	Ip(String),
	/// CIDR notation (e.g., "10.6.0.0/16")
	#[display("{_0}")]
	Cidr(String),
	/// Domain name (e.g., "google.com")
	#[display("{_0}")]
	Domain(String),
	/// Wildcard domain (e.g., "*.google.com")
	#[display("{_0}")]
	WildcardDomain(String),
	/// Special localhost identifier
	#[display("localhost")]
	Localhost,
	/// Match any address (when address is omitted)
	#[display("*")]
	Any,
}

/// Represents port specifications with optional protocols
#[derive(Debug, Clone, PartialEq, Serialize, Display)]
#[display("{}", format_port_list(&entries))]
pub struct AclPorts {
	/// List of port ranges or single ports with optional protocols
	pub entries: Vec<AclPortEntry>,
}

fn format_port_list(entries: &[AclPortEntry]) -> String {
	entries.iter().map(|e| e.to_string()).collect::<Vec<_>>().join(",")
}

/// A single port entry with optional protocol specification
#[derive(Debug, Clone, PartialEq, Serialize, Copy, Display)]
#[display("{}{}", format_protocol(protocol), port_spec)]
pub struct AclPortEntry {
	/// Protocol (TCP, UDP, or both if None)
	pub protocol:  Option<AclProtocol>,
	/// Port specification (single port or range)
	pub port_spec: AclPortSpec,
}

fn format_protocol(protocol: &Option<AclProtocol>) -> String {
	match protocol {
		Some(p) => format!("{}/", p),
		None => String::new(),
	}
}

/// Protocol specification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Copy, Display)]
pub enum AclProtocol {
	#[display("tcp")]
	Tcp,
	#[display("udp")]
	Udp,
}

/// Port specification (single port or range)
#[derive(Debug, Clone, PartialEq, Serialize, Copy, Display)]
pub enum AclPortSpec {
	/// Single port
	#[display("{_0}")]
	Single(u16),
	/// Port range (inclusive)
	#[display("{_0}-{_1}")]
	Range(u16, u16),
}

// ============================================================================
// Matching Logic
// ============================================================================

impl AclRule {
	/// Returns `true` if the supplied socket address, port and transport
	/// protocol satisfy this rule.
	pub(crate) fn matching(&self, addr: SocketAddr, port: u16, is_tcp: bool) -> bool {
		self.matches_address(addr.ip()) && self.matches_port(port, is_tcp)
	}

	/// Check if the rule matches the given IP address
	fn matches_address(&self, ip: IpAddr) -> bool {
		match &self.addr {
			AclAddress::Ip(ip_str) => ip_str.parse::<IpAddr>().map_or(false, |parsed| parsed == ip),
			AclAddress::Cidr(cidr_str) => cidr_str
				.parse::<ip_network::IpNetwork>()
				.map_or(false, |net| net.contains(ip)),
			AclAddress::Domain(domain) => Self::match_domain(domain, ip),
			AclAddress::WildcardDomain(pattern) => Self::match_wildcard_domain(pattern, ip),
			AclAddress::Localhost => Self::is_loopback(ip),
			AclAddress::Any => true,
		}
	}

	/// Check if the rule matches the given port and protocol
	fn matches_port(&self, port: u16, is_tcp: bool) -> bool {
		match &self.ports {
			None => true,
			Some(ports) => ports.entries.iter().any(|entry| entry.matches(port, is_tcp)),
		}
	}

	/// Match a domain against an IP address
	fn match_domain(domain: &str, ip: IpAddr) -> bool {
		if domain.eq_ignore_ascii_case("localhost") {
			return Self::is_loopback(ip);
		}

		(domain, 0)
			.to_socket_addrs()
			.ok()
			.map_or(false, |mut iter| iter.any(|sa| sa.ip() == ip))
	}

	/// Match a wildcard domain against an IP address
	fn match_wildcard_domain(pattern: &str, ip: IpAddr) -> bool {
		let stripped = pattern
			.strip_prefix("*.")
			.or_else(|| pattern.strip_prefix("suffix:"))
			.unwrap_or(pattern);

		if stripped.eq_ignore_ascii_case("localhost") {
			Self::is_loopback(ip)
		} else {
			(stripped, 0)
				.to_socket_addrs()
				.ok()
				.map_or(false, |mut iter| iter.any(|sa| sa.ip() == ip))
		}
	}

	/// Check if an IP address is loopback (localhost)
	#[inline]
	fn is_loopback(ip: IpAddr) -> bool {
		match ip {
			IpAddr::V4(v4) => v4.is_loopback(),
			IpAddr::V6(v6) => v6.is_loopback(),
		}
	}
}

impl AclPortEntry {
	/// Check if this port entry matches the given port and protocol
	fn matches(&self, port: u16, is_tcp: bool) -> bool {
		self.matches_protocol(is_tcp) && self.matches_port(port)
	}

	/// Check if the protocol matches
	#[inline]
	fn matches_protocol(&self, is_tcp: bool) -> bool {
		match self.protocol {
			Some(AclProtocol::Tcp) => is_tcp,
			Some(AclProtocol::Udp) => !is_tcp,
			None => true,
		}
	}

	/// Check if the port specification matches
	#[inline]
	fn matches_port(&self, port: u16) -> bool {
		match self.port_spec {
			AclPortSpec::Single(p) => p == port,
			AclPortSpec::Range(start, end) => (start..=end).contains(&port),
		}
	}
}

// ============================================================================
// Parsing Functions
// ============================================================================

/// Parse a single ACL rule from string format
pub(crate) fn parse_acl_rule(rule: &str) -> eyre::Result<AclRule> {
	if rule.starts_with('#') || rule.is_empty() {
		return Err(eyre::eyre!("Comment or empty line"));
	}

	parse_with_pest(rule)
}

/// Parse ACL rule using pest parser
fn parse_with_pest(rule: &str) -> eyre::Result<AclRule> {
	let mut pairs = AclParser::parse(Rule::acl_rule, rule).map_err(|e| eyre::eyre!("Parse error: {}", e))?;

	let rule_pair = pairs.next().ok_or_else(|| eyre::eyre!("Empty rule"))?;

	let mut outbound = String::new();
	let mut addr = AclAddress::Any;
	let mut ports = None;
	let mut hijack = None;

	for pair in rule_pair.into_inner() {
		match pair.as_rule() {
			Rule::outbound => outbound = pair.as_str().to_string(),
			Rule::address => addr = parse_address_from_pair(pair)?,
			Rule::ports => ports = parse_ports_from_pair(pair)?,
			Rule::hijack => hijack = Some(pair.as_str().to_string()),
			Rule::EOI => {}
			_ => {}
		}
	}

	Ok(AclRule {
		outbound,
		addr,
		ports,
		hijack,
	})
}

/// Parse address from pest pair
fn parse_address_from_pair(pair: pest::iterators::Pair<Rule>) -> eyre::Result<AclAddress> {
	let inner = pair.into_inner().next().ok_or_else(|| eyre::eyre!("Empty address"))?;

	Ok(match inner.as_rule() {
		Rule::localhost_kw | Rule::suffix_localhost => AclAddress::Localhost,
		Rule::any_addr => AclAddress::Any,
		Rule::wildcard_domain => AclAddress::WildcardDomain(inner.as_str().to_string()),
		Rule::cidr => AclAddress::Cidr(inner.as_str().to_string()),
		Rule::ipv4 | Rule::ipv6 => AclAddress::Ip(inner.as_str().to_string()),
		Rule::domain => AclAddress::Domain(inner.as_str().to_string()),
		_ => return Err(eyre::eyre!("Unknown address type: {:?}", inner.as_rule())),
	})
}

/// Parse ports from pest pair
fn parse_ports_from_pair(pair: pest::iterators::Pair<Rule>) -> eyre::Result<Option<AclPorts>> {
	let inner = pair.into_inner().next().ok_or_else(|| eyre::eyre!("Empty ports"))?;

	match inner.as_rule() {
		Rule::any_port => Ok(None),
		Rule::port_list => {
			let entries = inner
				.into_inner()
				.filter(|p| p.as_rule() == Rule::port_entry)
				.map(parse_port_entry_from_pair)
				.collect::<Result<Vec<_>, _>>()?;

			Ok(Some(AclPorts { entries }))
		}
		_ => Err(eyre::eyre!("Unknown ports type: {:?}", inner.as_rule())),
	}
}

/// Parse single port entry from pest pair
fn parse_port_entry_from_pair(pair: pest::iterators::Pair<Rule>) -> eyre::Result<AclPortEntry> {
	let inner = pair.into_inner().next().ok_or_else(|| eyre::eyre!("Empty port entry"))?;

	match inner.as_rule() {
		Rule::protocol_port => {
			let mut inner_pairs = inner.into_inner();
			let protocol_pair = inner_pairs.next().ok_or_else(|| eyre::eyre!("Missing protocol"))?;
			let port_spec_pair = inner_pairs.next().ok_or_else(|| eyre::eyre!("Missing port spec"))?;

			let protocol = match protocol_pair
				.into_inner()
				.next()
				.ok_or_else(|| eyre::eyre!("Empty protocol"))?
				.as_rule()
			{
				Rule::tcp => Some(AclProtocol::Tcp),
				Rule::udp => Some(AclProtocol::Udp),
				_ => None,
			};

			let port_spec = parse_port_spec_from_pair(port_spec_pair)?;
			Ok(AclPortEntry { protocol, port_spec })
		}
		Rule::port_spec => {
			let port_spec = parse_port_spec_from_pair(inner)?;
			Ok(AclPortEntry {
				protocol: None,
				port_spec,
			})
		}
		_ => Err(eyre::eyre!("Unknown port entry type: {:?}", inner.as_rule())),
	}
}

/// Parse port specification from pest pair
fn parse_port_spec_from_pair(pair: pest::iterators::Pair<Rule>) -> eyre::Result<AclPortSpec> {
	let inner = pair.into_inner().next().ok_or_else(|| eyre::eyre!("Empty port spec"))?;

	match inner.as_rule() {
		Rule::single_port => {
			let port = inner
				.as_str()
				.parse::<u16>()
				.map_err(|_| eyre::eyre!("Invalid port: {}", inner.as_str()))?;
			Ok(AclPortSpec::Single(port))
		}
		Rule::port_range => {
			let range_str = inner.as_str();
			let parts: Vec<&str> = range_str.split('-').collect();

			if parts.len() != 2 {
				return Err(eyre::eyre!("Invalid port range: {}", range_str));
			}

			let start = parts[0]
				.parse::<u16>()
				.map_err(|_| eyre::eyre!("Invalid start port: {}", parts[0]))?;
			let end = parts[1]
				.parse::<u16>()
				.map_err(|_| eyre::eyre!("Invalid end port: {}", parts[1]))?;

			if start > end {
				return Err(eyre::eyre!("Invalid port range: {} > {}", start, end));
			}

			Ok(AclPortSpec::Range(start, end))
		}
		_ => Err(eyre::eyre!("Unknown port spec type: {:?}", inner.as_rule())),
	}
}

/// Parse a multiline string into ACL rules
fn parse_multiline_acl_string(input: &str) -> eyre::Result<Vec<AclRule>> {
	input
		.lines()
		.enumerate()
		.map(|(i, line)| (i, line.trim()))
		.filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
		.map(|(i, line)| parse_acl_rule(line).map_err(|e| eyre::eyre!("Line {}: {}", i + 1, e)))
		.collect()
}

// ============================================================================
// Serde Deserialize Implementations
// ============================================================================

impl<'de> Deserialize<'de> for AclAddress {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let input = s.trim();
		let pairs =
			AclParser::parse(Rule::address, input).map_err(|e| de::Error::custom(format!("Failed to parse address: {e}")))?;

		let pair = pairs
			.into_iter()
			.next()
			.ok_or_else(|| de::Error::custom("No address found"))?;

		parse_address_from_pair(pair).map_err(|e| de::Error::custom(e.to_string()))
	}
}

impl<'de> Deserialize<'de> for AclPorts {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let input = s.trim();
		let pairs =
			AclParser::parse(Rule::ports, input).map_err(|e| de::Error::custom(format!("Failed to parse ports: {e}")))?;

		let pair = pairs.into_iter().next().ok_or_else(|| de::Error::custom("No ports found"))?;

		parse_ports_from_pair(pair)
			.map_err(|e| de::Error::custom(e.to_string()))?
			.ok_or_else(|| de::Error::custom("Failed to parse ports"))
	}
}

impl<'de> Deserialize<'de> for AclPortEntry {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let input = s.trim();
		let pairs = AclParser::parse(Rule::port_entry, input)
			.map_err(|e| de::Error::custom(format!("Failed to parse port entry: {e}")))?;

		let pair = pairs
			.into_iter()
			.next()
			.ok_or_else(|| de::Error::custom("No port entry found"))?;

		parse_port_entry_from_pair(pair).map_err(|e| de::Error::custom(e.to_string()))
	}
}

impl<'de> Deserialize<'de> for AclProtocol {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		match s.to_lowercase().as_str() {
			"tcp" => Ok(AclProtocol::Tcp),
			"udp" => Ok(AclProtocol::Udp),
			_ => Err(de::Error::custom(format!("Invalid protocol: {}", s))),
		}
	}
}

impl<'de> Deserialize<'de> for AclPortSpec {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let input = s.trim();
		let pairs = AclParser::parse(Rule::port_spec, input)
			.map_err(|e| de::Error::custom(format!("Failed to parse port spec: {e}")))?;

		let pair = pairs
			.into_iter()
			.next()
			.ok_or_else(|| de::Error::custom("No port spec found"))?;

		parse_port_spec_from_pair(pair).map_err(|e| de::Error::custom(e.to_string()))
	}
}

impl<'de> Deserialize<'de> for AclRule {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		#[derive(Deserialize)]
		struct AclRuleHelper {
			outbound: String,
			addr:     String,
			ports:    Option<String>,
			hijack:   Option<String>,
		}

		let helper = AclRuleHelper::deserialize(deserializer)?;
		let addr = serde::Deserialize::deserialize(de::value::StrDeserializer::<D::Error>::new(&helper.addr))?;
		let ports = helper
			.ports
			.map(|s| serde::Deserialize::deserialize(de::value::StrDeserializer::<D::Error>::new(&s)))
			.transpose()?;

		Ok(AclRule {
			outbound: helper.outbound,
			addr,
			ports,
			hijack: helper.hijack,
		})
	}
}

/// Deserialize the `acl` field which may be either:
///   * an array of TOML tables (array-of-tables format)
///   * a single multiline string with space-separated rules
pub fn deserialize_acl<'de, D>(deserializer: D) -> Result<Vec<AclRule>, D::Error>
where
	D: Deserializer<'de>,
{
	use std::fmt;

	use serde::de::Visitor;

	struct AclVisitor;

	impl<'de> Visitor<'de> for AclVisitor {
		type Value = Vec<AclRule>;

		fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
			formatter.write_str("a sequence of ACL rule tables or a multiline string")
		}

		fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
		where
			A: de::SeqAccess<'de>,
		{
			let mut vec = Vec::new();
			while let Some(rule) = seq.next_element::<AclRule>()? {
				vec.push(rule);
			}
			Ok(vec)
		}

		fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
		where
			E: de::Error,
		{
			use serde::de::Unexpected;
			parse_multiline_acl_string(v).map_err(|e| de::Error::invalid_value(Unexpected::Str(v), &e.to_string().as_str()))
		}

		fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
		where
			E: de::Error,
		{
			self.visit_str(&v)
		}
	}

	deserializer.deserialize_any(AclVisitor)
}

#[cfg(test)]
mod tests {
	use std::net::{Ipv4Addr, Ipv6Addr};

	use super::*;

	// Helper functions
	fn v4(addr: &str, port: u16) -> SocketAddr {
		SocketAddr::new(IpAddr::V4(addr.parse::<Ipv4Addr>().unwrap()), port)
	}

	fn v6(addr: &str, port: u16) -> SocketAddr {
		SocketAddr::new(IpAddr::V6(addr.parse::<Ipv6Addr>().unwrap()), port)
	}

	// ========================================================================
	// Address Matching Tests
	// ========================================================================

	#[test]
	fn ip_exact_match() {
		let rule = AclRule {
			addr:     AclAddress::Ip("203.0.113.7".into()),
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("203.0.113.7", 12345), 12345, true));
		assert!(!rule.matching(v4("203.0.113.8", 12345), 12345, true));
		assert!(!rule.matching(v6("2001:db8::1", 12345), 12345, true));
	}

	#[test]
	fn cidr_match() {
		let rule = AclRule {
			addr:     AclAddress::Cidr("10.0.0.0/8".into()),
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("10.1.2.3", 0), 0, false));
		assert!(!rule.matching(v4("192.0.2.1", 0), 0, false));
		assert!(!rule.matching(v6("::1", 0), 0, false));
	}

	#[test]
	fn domain_match_localhost() {
		let rule = AclRule {
			addr:     AclAddress::Domain("localhost".into()),
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("127.0.0.1", 0), 0, true));
		assert!(rule.matching(v6("::1", 0), 0, true));
		assert!(!rule.matching(v4("8.8.8.8", 0), 0, true));
	}

	#[test]
	fn wildcard_domain_match_suffix_localhost() {
		let rule = AclRule {
			addr:     AclAddress::WildcardDomain("suffix:localhost".into()),
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("127.0.0.1", 0), 0, true));
		assert!(rule.matching(v6("::1", 0), 0, true));
		assert!(!rule.matching(v4("8.8.8.8", 0), 0, true));
	}

	#[test]
	fn localhost_match() {
		let rule = AclRule {
			addr:     AclAddress::Localhost,
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("127.0.0.1", 0), 0, true));
		assert!(rule.matching(v6("::1", 0), 0, true));
		assert!(!rule.matching(v4("192.0.2.1", 0), 0, true));
	}

	#[test]
	fn any_match() {
		let rule = AclRule {
			addr:     AclAddress::Any,
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("203.0.113.1", 0), 0, true));
		assert!(rule.matching(v6("2001:db8::42", 0), 0, true));
	}

	#[test]
	fn ipv6_cidr_match() {
		let rule = AclRule {
			addr:     AclAddress::Cidr("2001:db8::/32".into()),
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v6("2001:db8::1", 80), 80, true));
		assert!(rule.matching(v6("2001:db8:1::1", 80), 80, true));
		assert!(!rule.matching(v6("2001:db9::1", 80), 80, true));
		assert!(!rule.matching(v6("2002:db8::1", 80), 80, true));
		assert!(!rule.matching(v4("10.0.0.1", 80), 80, true));
	}

	#[test]
	fn cidr_slash_32() {
		let rule = AclRule {
			addr:     AclAddress::Cidr("192.168.1.100/32".into()),
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("192.168.1.100", 80), 80, true));
		assert!(!rule.matching(v4("192.168.1.101", 80), 80, true));
		assert!(!rule.matching(v4("192.168.1.99", 80), 80, true));
	}

	#[test]
	fn cidr_slash_0() {
		let rule = AclRule {
			addr:     AclAddress::Cidr("0.0.0.0/0".into()),
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("1.2.3.4", 80), 80, true));
		assert!(rule.matching(v4("192.168.1.1", 80), 80, true));
		assert!(rule.matching(v4("255.255.255.255", 80), 80, true));
		assert!(!rule.matching(v6("::1", 80), 80, true));
	}

	#[test]
	fn invalid_ip_address() {
		let rule = AclRule {
			addr:     AclAddress::Ip("not.an.ip.address".into()),
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(!rule.matching(v4("1.2.3.4", 80), 80, true));
		assert!(!rule.matching(v6("::1", 80), 80, true));
	}

	#[test]
	fn invalid_cidr() {
		let rule = AclRule {
			addr:     AclAddress::Cidr("invalid/cidr".into()),
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(!rule.matching(v4("10.0.0.1", 80), 80, true));
		assert!(!rule.matching(v6("2001:db8::1", 80), 80, true));
	}

	#[test]
	fn loopback_addresses() {
		let rule = AclRule {
			addr:     AclAddress::Localhost,
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("127.0.0.1", 80), 80, true));
		assert!(rule.matching(v4("127.0.0.2", 80), 80, true));
		assert!(rule.matching(v4("127.255.255.255", 80), 80, true));
		assert!(rule.matching(v6("::1", 80), 80, true));
		assert!(!rule.matching(v4("192.168.1.1", 80), 80, true));
		assert!(!rule.matching(v6("2001:db8::1", 80), 80, true));
	}

	// ========================================================================
	// Port Matching Tests
	// ========================================================================

	#[test]
	fn ports_none_matches_everything() {
		let rule = AclRule {
			addr:     AclAddress::Any,
			ports:    None,
			outbound: "default".to_string(),
			hijack:   None,
		};

		for port in [0u16, 22, 80, 443, 65535] {
			assert!(rule.matching(v4("1.2.3.4", port), port, true));
			assert!(rule.matching(v4("1.2.3.4", port), port, false));
		}
	}

	#[test]
	fn single_port_without_protocol() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol:  None,
				port_spec: AclPortSpec::Single(8080),
			}],
		};

		let rule = AclRule {
			addr:     AclAddress::Any,
			ports:    Some(ports),
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("10.0.0.1", 8080), 8080, true));
		assert!(rule.matching(v4("10.0.0.1", 8080), 8080, false));
		assert!(!rule.matching(v4("10.0.0.1", 80), 80, true));
		assert!(!rule.matching(v4("10.0.0.1", 443), 443, false));
	}

	#[test]
	fn port_range_with_protocol() {
		let ports = AclPorts {
			entries: vec![
				AclPortEntry {
					protocol:  Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Range(1000, 1005),
				},
				AclPortEntry {
					protocol:  Some(AclProtocol::Udp),
					port_spec: AclPortSpec::Range(2000, 2002),
				},
			],
		};

		let rule = AclRule {
			addr:     AclAddress::Any,
			ports:    Some(ports),
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("8.8.8.8", 1003), 1003, true));
		assert!(!rule.matching(v4("8.8.8.8", 999), 999, true));
		assert!(rule.matching(v4("8.8.8.8", 2001), 2001, false));
		assert!(!rule.matching(v4("8.8.8.8", 1999), 1999, false));
	}

	#[test]
	fn port_range_boundary() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol:  None,
				port_spec: AclPortSpec::Range(100, 200),
			}],
		};

		let rule = AclRule {
			addr:     AclAddress::Any,
			ports:    Some(ports),
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("1.1.1.1", 100), 100, true));
		assert!(rule.matching(v4("1.1.1.1", 200), 200, true));
		assert!(!rule.matching(v4("1.1.1.1", 99), 99, true));
		assert!(!rule.matching(v4("1.1.1.1", 201), 201, true));
		assert!(rule.matching(v4("1.1.1.1", 150), 150, false));
	}

	#[test]
	fn edge_case_port_zero() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol:  None,
				port_spec: AclPortSpec::Single(0),
			}],
		};

		let rule = AclRule {
			addr:     AclAddress::Any,
			ports:    Some(ports),
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("1.2.3.4", 0), 0, true));
		assert!(!rule.matching(v4("1.2.3.4", 1), 1, true));
	}

	#[test]
	fn edge_case_port_max() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol:  None,
				port_spec: AclPortSpec::Single(65535),
			}],
		};

		let rule = AclRule {
			addr:     AclAddress::Any,
			ports:    Some(ports),
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("1.2.3.4", 65535), 65535, true));
		assert!(!rule.matching(v4("1.2.3.4", 65534), 65534, true));
	}

	#[test]
	fn address_and_port_combination() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol:  Some(AclProtocol::Tcp),
				port_spec: AclPortSpec::Single(22),
			}],
		};

		let rule = AclRule {
			addr:     AclAddress::Ip("192.0.2.10".into()),
			ports:    Some(ports),
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("192.0.2.10", 22), 22, true));
		assert!(!rule.matching(v4("192.0.2.11", 22), 22, true));
		assert!(!rule.matching(v4("192.0.2.10", 23), 23, true));
		assert!(!rule.matching(v4("192.0.2.10", 22), 22, false));
	}

	#[test]
	fn ports_defined_but_protocol_mismatch() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol:  Some(AclProtocol::Tcp),
				port_spec: AclPortSpec::Single(443),
			}],
		};

		let rule = AclRule {
			addr:     AclAddress::Any,
			ports:    Some(ports),
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(!rule.matching(v4("1.1.1.1", 443), 443, false));
		assert!(rule.matching(v4("1.1.1.1", 443), 443, true));
	}

	#[test]
	fn empty_allowed_port_set_is_rejected() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol:  Some(AclProtocol::Tcp),
				port_spec: AclPortSpec::Single(9999),
			}],
		};

		let rule = AclRule {
			addr:     AclAddress::Any,
			ports:    Some(ports),
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(!rule.matching(v4("8.8.8.8", 9999), 9999, false));
	}

	#[test]
	fn multiple_port_entries() {
		let ports = AclPorts {
			entries: vec![
				AclPortEntry {
					protocol:  Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Single(80),
				},
				AclPortEntry {
					protocol:  Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Single(443),
				},
				AclPortEntry {
					protocol:  Some(AclProtocol::Udp),
					port_spec: AclPortSpec::Range(5000, 5100),
				},
			],
		};

		let rule = AclRule {
			addr:     AclAddress::Any,
			ports:    Some(ports),
			outbound: "default".to_string(),
			hijack:   None,
		};

		assert!(rule.matching(v4("1.2.3.4", 80), 80, true));
		assert!(rule.matching(v4("1.2.3.4", 443), 443, true));
		assert!(!rule.matching(v4("1.2.3.4", 8080), 8080, true));
		assert!(rule.matching(v4("1.2.3.4", 5050), 5050, false));
		assert!(!rule.matching(v4("1.2.3.4", 4999), 4999, false));
		assert!(!rule.matching(v4("1.2.3.4", 5101), 5101, false));
	}

	// ========================================================================
	// Parsing Tests
	// ========================================================================

	#[test]
	fn parse_simple_rule() -> eyre::Result<()> {
		let rule_str = "allow 192.168.1.0/24 tcp/443,udp/53";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "allow");
		assert_eq!(rule.addr, AclAddress::Cidr("192.168.1.0/24".to_string()));
		assert!(rule.ports.is_some());

		let ports = rule.ports.unwrap();
		assert_eq!(ports.entries.len(), 2);
		assert_eq!(ports.entries[0].protocol, Some(AclProtocol::Tcp));
		assert_eq!(ports.entries[0].port_spec, AclPortSpec::Single(443));
		assert_eq!(ports.entries[1].protocol, Some(AclProtocol::Udp));
		assert_eq!(ports.entries[1].port_spec, AclPortSpec::Single(53));
		Ok(())
	}

	#[test]
	fn parse_wildcard_domain() -> eyre::Result<()> {
		let rule_str = "deny *.google.com";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "deny");
		assert_eq!(rule.addr, AclAddress::WildcardDomain("*.google.com".to_string()));
		assert!(rule.ports.is_none());
		Ok(())
	}

	#[test]
	fn parse_port_range() -> eyre::Result<()> {
		let rule_str = "allow 10.0.0.1 1000-2000";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "allow");
		assert_eq!(rule.addr, AclAddress::Ip("10.0.0.1".to_string()));

		let ports = rule.ports.unwrap();
		assert_eq!(ports.entries.len(), 1);
		assert_eq!(ports.entries[0].port_spec, AclPortSpec::Range(1000, 2000));
		assert_eq!(ports.entries[0].protocol, None);
		Ok(())
	}

	#[test]
	fn parse_any_address_any_port() -> eyre::Result<()> {
		let rule_str = "proxy * *";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "proxy");
		assert_eq!(rule.addr, AclAddress::Any);
		assert!(rule.ports.is_none());
		Ok(())
	}

	#[test]
	fn parse_with_hijack() -> eyre::Result<()> {
		let rule_str = "redirect 8.8.8.8 tcp/53 10.0.0.1";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "redirect");
		assert_eq!(rule.addr, AclAddress::Ip("8.8.8.8".to_string()));
		assert_eq!(rule.hijack, Some("10.0.0.1".to_string()));
		Ok(())
	}

	#[test]
	fn parse_localhost() -> eyre::Result<()> {
		let rule_str = "allow localhost";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "allow");
		assert_eq!(rule.addr, AclAddress::Localhost);
		Ok(())
	}

	#[test]
	fn parse_ipv6_address() -> eyre::Result<()> {
		let rule_str = "allow 2001:db8::1";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "allow");
		assert_eq!(rule.addr, AclAddress::Ip("2001:db8::1".to_string()));
		Ok(())
	}

	#[test]
	fn parse_ipv6_cidr() -> eyre::Result<()> {
		let rule_str = "block 2001:db8::/32";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "block");
		assert_eq!(rule.addr, AclAddress::Cidr("2001:db8::/32".to_string()));
		Ok(())
	}

	#[test]
	fn parse_comment_line() {
		let rule_str = "# This is a comment";
		let result = parse_acl_rule(rule_str);

		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("Comment"));
	}

	#[test]
	fn parse_empty_line() {
		let result = parse_acl_rule("");

		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("empty"));
	}

	#[test]
	fn parse_multiline_string() -> eyre::Result<()> {
		let input = r#"
allow 192.168.1.0/24
deny *.ads.com
# Comment line
allow localhost tcp/8080

block 10.0.0.0/8 udp/53
"#;
		let rules = parse_multiline_acl_string(input)?;

		assert_eq!(rules.len(), 4);
		assert_eq!(rules[0].outbound, "allow");
		assert_eq!(rules[1].outbound, "deny");
		assert_eq!(rules[2].outbound, "allow");
		assert_eq!(rules[3].outbound, "block");
		Ok(())
	}

	#[test]
	fn parse_mixed_protocols() -> eyre::Result<()> {
		let rule_str = "allow * tcp/80,443,udp/53";
		let rule = parse_acl_rule(rule_str)?;

		let ports = rule.ports.unwrap();
		assert_eq!(ports.entries.len(), 3);
		assert_eq!(ports.entries[0].protocol, Some(AclProtocol::Tcp));
		assert_eq!(ports.entries[0].port_spec, AclPortSpec::Single(80));
		assert_eq!(ports.entries[1].port_spec, AclPortSpec::Single(443));
		assert_eq!(ports.entries[2].protocol, Some(AclProtocol::Udp));
		assert_eq!(ports.entries[2].port_spec, AclPortSpec::Single(53));
		Ok(())
	}

	// ========================================================================
	// Display Tests
	// ========================================================================

	#[test]
	fn display_acl_rule() {
		let rule = AclRule {
			outbound: "allow".to_string(),
			addr:     AclAddress::Ip("192.168.1.1".to_string()),
			ports:    None,
			hijack:   None,
		};

		assert_eq!(rule.to_string(), "allow 192.168.1.1");
	}

	#[test]
	fn display_acl_rule_with_ports() {
		let rule = AclRule {
			outbound: "allow".to_string(),
			addr:     AclAddress::Any,
			ports:    Some(AclPorts {
				entries: vec![AclPortEntry {
					protocol:  Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Single(443),
				}],
			}),
			hijack:   None,
		};

		assert_eq!(rule.to_string(), "allow * tcp/443");
	}

	#[test]
	fn display_acl_rule_with_hijack() {
		let rule = AclRule {
			outbound: "redirect".to_string(),
			addr:     AclAddress::Ip("8.8.8.8".to_string()),
			ports:    None,
			hijack:   Some("10.0.0.1".to_string()),
		};

		assert_eq!(rule.to_string(), "redirect 8.8.8.8 10.0.0.1");
	}

	#[test]
	fn display_port_entry() {
		let entry = AclPortEntry {
			protocol:  Some(AclProtocol::Tcp),
			port_spec: AclPortSpec::Single(80),
		};

		assert_eq!(entry.to_string(), "tcp/80");
	}

	#[test]
	fn display_port_entry_no_protocol() {
		let entry = AclPortEntry {
			protocol:  None,
			port_spec: AclPortSpec::Range(1000, 2000),
		};

		assert_eq!(entry.to_string(), "1000-2000");
	}

	#[test]
	fn display_ports() {
		let ports = AclPorts {
			entries: vec![
				AclPortEntry {
					protocol:  Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Single(80),
				},
				AclPortEntry {
					protocol:  Some(AclProtocol::Udp),
					port_spec: AclPortSpec::Single(53),
				},
			],
		};

		assert_eq!(ports.to_string(), "tcp/80,udp/53");
	}

	// ========================================================================
	// Deserialization Tests
	// ========================================================================

	#[test]
	fn deserialize_address_ip() -> eyre::Result<()> {
		let toml = r#"addr = "192.168.1.1""#;
		#[derive(Deserialize)]
		struct Test {
			addr: AclAddress,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.addr, AclAddress::Ip("192.168.1.1".to_string()));
		Ok(())
	}

	#[test]
	fn deserialize_address_cidr() -> eyre::Result<()> {
		let toml = r#"addr = "10.0.0.0/8""#;
		#[derive(Deserialize)]
		struct Test {
			addr: AclAddress,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.addr, AclAddress::Cidr("10.0.0.0/8".to_string()));
		Ok(())
	}

	#[test]
	fn deserialize_address_localhost() -> eyre::Result<()> {
		let toml = r#"addr = "localhost""#;
		#[derive(Deserialize)]
		struct Test {
			addr: AclAddress,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.addr, AclAddress::Localhost);
		Ok(())
	}

	#[test]
	fn deserialize_address_wildcard() -> eyre::Result<()> {
		let toml = r#"addr = "*.google.com""#;
		#[derive(Deserialize)]
		struct Test {
			addr: AclAddress,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.addr, AclAddress::WildcardDomain("*.google.com".to_string()));
		Ok(())
	}

	#[test]
	fn deserialize_protocol_tcp() -> eyre::Result<()> {
		let toml = r#"proto = "tcp""#;
		#[derive(Deserialize)]
		struct Test {
			proto: AclProtocol,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.proto, AclProtocol::Tcp);
		Ok(())
	}

	#[test]
	fn deserialize_protocol_udp_uppercase() -> eyre::Result<()> {
		let toml = r#"proto = "UDP""#;
		#[derive(Deserialize)]
		struct Test {
			proto: AclProtocol,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.proto, AclProtocol::Udp);
		Ok(())
	}

	#[test]
	fn deserialize_port_spec_single() -> eyre::Result<()> {
		let toml = r#"spec = "80""#;
		#[derive(Deserialize)]
		struct Test {
			spec: AclPortSpec,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.spec, AclPortSpec::Single(80));
		Ok(())
	}

	#[test]
	fn deserialize_port_spec_range() -> eyre::Result<()> {
		let toml = r#"spec = "1000-2000""#;
		#[derive(Deserialize)]
		struct Test {
			spec: AclPortSpec,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.spec, AclPortSpec::Range(1000, 2000));
		Ok(())
	}

	#[test]
	fn deserialize_port_entry() -> eyre::Result<()> {
		let toml = r#"entry = "tcp/443""#;
		#[derive(Deserialize)]
		struct Test {
			entry: AclPortEntry,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.entry.protocol, Some(AclProtocol::Tcp));
		assert_eq!(test.entry.port_spec, AclPortSpec::Single(443));
		Ok(())
	}

	#[test]
	fn deserialize_ports() -> eyre::Result<()> {
		let toml = r#"ports = "tcp/80,udp/53""#;
		#[derive(Deserialize)]
		struct Test {
			ports: AclPorts,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.ports.entries.len(), 2);
		assert_eq!(test.ports.entries[0].protocol, Some(AclProtocol::Tcp));
		assert_eq!(test.ports.entries[1].protocol, Some(AclProtocol::Udp));
		Ok(())
	}

	#[test]
	fn deserialize_acl_rule_from_toml() -> eyre::Result<()> {
		let toml = r#"
outbound = "allow"
addr = "192.168.1.0/24"
ports = "tcp/443,udp/53"
"#;
		let rule: AclRule = toml::from_str(toml)?;

		assert_eq!(rule.outbound, "allow");
		assert_eq!(rule.addr, AclAddress::Cidr("192.168.1.0/24".to_string()));
		assert!(rule.ports.is_some());

		let ports = rule.ports.unwrap();
		assert_eq!(ports.entries.len(), 2);
		Ok(())
	}

	#[test]
	fn deserialize_acl_multiline_string() -> eyre::Result<()> {
		let toml = r#"
acl = """
allow 192.168.1.0/24 tcp/443
deny *.ads.com
allow localhost
"""
"#;
		#[derive(Deserialize)]
		struct Config {
			#[serde(deserialize_with = "deserialize_acl")]
			acl: Vec<AclRule>,
		}

		let config: Config = toml::from_str(toml)?;
		assert_eq!(config.acl.len(), 3);
		assert_eq!(config.acl[0].outbound, "allow");
		assert_eq!(config.acl[1].outbound, "deny");
		assert_eq!(config.acl[2].outbound, "allow");
		Ok(())
	}

	#[test]
	fn deserialize_acl_array_of_tables() -> eyre::Result<()> {
		let toml = r#"
[[acl]]
outbound = "allow"
addr = "192.168.1.0/24"
ports = "tcp/443"

[[acl]]
outbound = "deny"
addr = "*.ads.com"
"#;
		#[derive(Deserialize)]
		struct Config {
			#[serde(deserialize_with = "deserialize_acl")]
			acl: Vec<AclRule>,
		}

		let config: Config = toml::from_str(toml)?;
		assert_eq!(config.acl.len(), 2);
		assert_eq!(config.acl[0].outbound, "allow");
		assert_eq!(config.acl[1].outbound, "deny");
		Ok(())
	}
}
