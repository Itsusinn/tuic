//! tuic-server legacy ACL syntax.
//!
//! A tuic-server–specific rule dialect. This is **not** Hysteria's ACL: real
//! Hysteria 2 uses a function-call form (`outbound(address, proto/port,
//! hijack)`), whereas this dialect is space-separated. Parses lines of the
//! shape `<outbound> [address] [ports] [hijack]`, e.g. `proxy 10.6.0.0/16
//! tcp/443` — into [`AclRule`]s and compiles them to `wind_core::rule::Rule`s
//! via [`acl_to_rules`].

#[cfg(test)]
use std::net::{IpAddr, SocketAddr};

use derive_more::Display;
use pest::Parser;
use pest_derive::Parser;
use serde::{Deserialize, Deserializer, Serialize, de};
#[cfg(test)]
use wind_core::is_private_ip;
use wind_core::rule::{self as wrule, NetworkType};

#[derive(Parser)]
#[grammar = "legacy/acl.pest"]
struct AclParser;

/// Represents a single ACL rule with parsed components
#[derive(Debug, Clone, PartialEq, Serialize, Display)]
#[display("{outbound} {addr}{}", format_optional_parts(ports, hijack))]
pub struct AclRule {
	/// The outbound name to use for this rule
	pub outbound: String,
	/// The target address (IP, CIDR, domain, wildcard domain)
	pub addr: AclAddress,
	/// Optional port specifications
	pub ports: Option<AclPorts>,
	/// Optional hijack IP address for redirection
	pub hijack: Option<String>,
}

// Used by the derive(Display) macro on `AclRule`. The macro expands to a
// `write!` call, so anything implementing `Display` works — return type was
// `String` purely for the previous `format!`-based implementation.
struct OptionalParts<'a> {
	ports: &'a Option<AclPorts>,
	hijack: &'a Option<String>,
}

impl<'a> std::fmt::Display for OptionalParts<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if let Some(p) = self.ports {
			write!(f, " {p}")?;
		}
		if let Some(h) = self.hijack {
			write!(f, " {h}")?;
		}
		Ok(())
	}
}

fn format_optional_parts<'a>(ports: &'a Option<AclPorts>, hijack: &'a Option<String>) -> OptionalParts<'a> {
	OptionalParts { ports, hijack }
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
	/// Special private address identifier (LAN addresses)
	#[display("private")]
	Private,
	/// Match any address (when address is omitted)
	#[display("*")]
	Any,
}

/// Represents port specifications with optional protocols
#[derive(Debug, Clone, PartialEq, Serialize, Display)]
#[display("{}", format_port_list(entries))]
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
	pub protocol: Option<AclProtocol>,
	/// Port specification (single port or range)
	pub port_spec: AclPortSpec,
}

fn format_protocol(protocol: &Option<AclProtocol>) -> &'static str {
	// Allocation-free: each combination maps to a fixed string literal. The
	// derive(Display) macro just needs `Display`, which `&str` already
	// implements, so we can return the borrowed literal directly.
	match protocol {
		Some(AclProtocol::Tcp) => "tcp/",
		Some(AclProtocol::Udp) => "udp/",
		None => "",
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

#[cfg(test)]
impl AclRule {
	/// Returns `true` if the supplied socket address, port and transport
	/// protocol satisfy this rule.
	pub(crate) async fn matching(&self, addr: SocketAddr, port: u16, is_tcp: bool) -> bool {
		self.matches_address(addr.ip()).await && self.matches_port(port, is_tcp)
	}

	/// Check if the rule matches the given IP address
	async fn matches_address(&self, ip: IpAddr) -> bool {
		match &self.addr {
			AclAddress::Ip(ip_str) => ip_str.parse::<IpAddr>() == Ok(ip),
			AclAddress::Cidr(cidr_str) => cidr_str.parse::<ip_network::IpNetwork>().is_ok_and(|net| net.contains(ip)),
			AclAddress::Domain(domain) => {
				if domain.eq_ignore_ascii_case("localhost") {
					Self::is_loopback(ip)
				} else {
					false
				}
			}
			AclAddress::WildcardDomain(pattern) => {
				let stripped = pattern
					.strip_prefix("*.")
					.or_else(|| pattern.strip_prefix("suffix:"))
					.unwrap_or(pattern);

				if stripped.eq_ignore_ascii_case("localhost") {
					Self::is_loopback(ip)
				} else {
					false
				}
			}
			AclAddress::Localhost => Self::is_loopback(ip),
			AclAddress::Private => is_private_ip(&ip),
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

	/// Check if an IP address is loopback (localhost)
	#[inline]
	fn is_loopback(ip: IpAddr) -> bool {
		match ip {
			IpAddr::V4(v4) => v4.is_loopback(),
			IpAddr::V6(v6) => v6.is_loopback(),
		}
	}
}

#[cfg(test)]
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

/// Parse a single ACL rule from string format
pub fn parse_acl_rule(rule: &str) -> eyre::Result<AclRule> {
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
		Rule::private_kw => AclAddress::Private,
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

/// Parse a multiline string into ACL rules.
///
/// Blank lines and `#` comment lines are skipped; every other line is parsed
/// as a single [`AclRule`] via [`parse_acl_rule`].
pub fn parse_multiline_acl_string(input: &str) -> eyre::Result<Vec<AclRule>> {
	input
		.lines()
		.enumerate()
		.map(|(i, line)| (i, line.trim()))
		.filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
		.map(|(i, line)| parse_acl_rule(line).map_err(|e| eyre::eyre!("Line {}: {}", i + 1, e)))
		.collect()
}

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
			addr: String,
			ports: Option<String>,
			hijack: Option<String>,
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

/// Convert a list of legacy ACL rules into Metacubex-style [`wrule::Rule`]s.
///
/// Each [`AclRule`] may expand to *multiple* Metacubex rules because:
///
/// * Port ranges and protocol-filtered ports produce additional compound rules.
/// * `Localhost` / `Private` addresses expand into OR-groups of CIDR rules.
/// * Domain/WildcardDomain ACL rules that previously only matched when DNS-
///   resolved to an IP are now converted to domain-level Metacubex rules so
///   they can match *before* resolution.
pub fn acl_to_rules(acl: &[AclRule]) -> Vec<wrule::Rule> {
	acl.iter().flat_map(acl_rule_to_rules).collect()
}

/// Convert a single [`AclRule`] into one or more Metacubex rules.
fn acl_rule_to_rules(acl: &AclRule) -> Vec<wrule::Rule> {
	let target = normalize_outbound(&acl.outbound);

	let addr_rules = address_to_rule_types(&acl.addr);

	let port_conds = ports_to_conditions(&acl.ports);

	// When there are no port conditions, one rule per address condition.
	// When there are port conditions, AND(addr, port) for each combination.
	if port_conds.is_empty() {
		return addr_rules
			.into_iter()
			.map(|rt| wrule::Rule {
				rule_type: rt,
				target: target.clone(),
				options: Vec::new(),
			})
			.collect();
	}

	// If address is `Any` (match-all), the conditions are only port-based.
	if matches!(acl.addr, AclAddress::Any) {
		return port_conds
			.into_iter()
			.map(|rt| wrule::Rule {
				rule_type: rt,
				target: target.clone(),
				options: Vec::new(),
			})
			.collect();
	}

	// Otherwise: for *each* address rule, AND it with each port condition.
	let mut result = Vec::new();
	for ar in &addr_rules {
		for pc in &port_conds {
			let and_sub = vec![
				wrule::Rule {
					rule_type: clone_rule_type(ar),
					target: String::new(),
					options: Vec::new(),
				},
				wrule::Rule {
					rule_type: clone_rule_type(pc),
					target: String::new(),
					options: Vec::new(),
				},
			];
			result.push(wrule::Rule {
				rule_type: wrule::RuleType::And(and_sub),
				target: target.clone(),
				options: Vec::new(),
			});
		}
	}
	result
}

/// Map `"allow"` / `"default"` → `"default"`, keep the rest as-is.
fn normalize_outbound(name: &str) -> String {
	match name {
		"allow" | "default" => "default".to_string(),
		other => other.to_string(),
	}
}

/// Convert an [`AclAddress`] into one or more [`wrule::RuleType`]s.
fn address_to_rule_types(addr: &AclAddress) -> Vec<wrule::RuleType> {
	match addr {
		AclAddress::Ip(ip_str) => {
			// First parse the literal as an `IpAddr` so we can pick the
			// correct host-prefix length. The previous implementation tried
			// `{ip}/32` first — `ipnet::IpNet` HAPPILY accepts
			// `"2001:db8::1/32"`, because `/32` is a legal IPv6 prefix length,
			// but it returns the network `2001:db8::/32` instead of the host
			// `/128`, silently expanding the ACL to cover all of `2001:db8::/32`.
			// Now parse the address first, then construct the host-prefixed
			// CIDR by IP family. Truly malformed literals return an empty Vec
			// (drops the rule) instead of falling back to `0.0.0.0/32`, which
			// turned bad data into a silently-passing "match nothing" rule.
			match ip_str.parse::<std::net::IpAddr>() {
				Ok(std::net::IpAddr::V4(v4)) => {
					if let Ok(net) = ipnet::Ipv4Net::new(v4, 32) {
						vec![wrule::RuleType::IpCidr(ipnet::IpNet::V4(net))]
					} else {
						vec![]
					}
				}
				Ok(std::net::IpAddr::V6(v6)) => {
					if let Ok(net) = ipnet::Ipv6Net::new(v6, 128) {
						vec![wrule::RuleType::IpCidr(ipnet::IpNet::V6(net))]
					} else {
						vec![]
					}
				}
				Err(e) => {
					tracing::warn!("ACL entry {ip_str:?} could not be parsed as IPv4/IPv6 ({e}); rule dropped");
					vec![]
				}
			}
		}
		AclAddress::Cidr(cidr_str) => {
			// The grammar accepts prefixes like `/999` (acl.pest only bounds the
			// digit count), so a malformed CIDR such as `10.0.0.0/99` can reach
			// here. Warn on failure -- like the `Ip` arm above -- instead of
			// dropping the rule silently, which would fail-open (e.g. a `reject`
			// rule vanishing and its traffic being allowed).
			match cidr_str.parse::<ipnet::IpNet>() {
				Ok(net) => vec![wrule::RuleType::IpCidr(net)],
				Err(e) => {
					tracing::warn!("ACL entry {cidr_str:?} could not be parsed as a CIDR ({e}); rule dropped");
					vec![]
				}
			}
		}
		AclAddress::Domain(domain) => {
			vec![wrule::RuleType::Domain(domain.clone())]
		}
		AclAddress::WildcardDomain(pattern) => {
			// `*.example.com` or `suffix:example.com` → DOMAIN-SUFFIX
			let stripped = pattern
				.strip_prefix("*.")
				.or_else(|| pattern.strip_prefix("suffix:"))
				.unwrap_or(pattern);
			vec![wrule::RuleType::DomainSuffix(stripped.to_string())]
		}
		AclAddress::Localhost => {
			// Expand to loopback CIDRs (127.0.0.0/8 + ::1/128)
			vec![
				wrule::RuleType::IpCidr("127.0.0.0/8".parse().unwrap()),
				wrule::RuleType::IpCidr("::1/128".parse().unwrap()),
			]
		}
		AclAddress::Private => {
			// RFC 1918 + link-local + loopback
			let cidrs = [
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
				"127.0.0.0/8",
				"169.254.0.0/16",
				"::1/128",
				"fc00::/7",
				"fe80::/10",
			];
			cidrs
				.iter()
				.filter_map(|c| c.parse().ok())
				.map(wrule::RuleType::IpCidr)
				.collect()
		}
		AclAddress::Any => {
			vec![wrule::RuleType::Match]
		}
	}
}

/// Convert optional [`AclPorts`] into zero or more [`wrule::RuleType`]s.
///
/// Returns an empty vec when no port filter is configured.
fn ports_to_conditions(ports: &Option<AclPorts>) -> Vec<wrule::RuleType> {
	let Some(ports) = ports else {
		return Vec::new();
	};

	ports.entries.iter().map(port_entry_to_rule_type).collect()
}

/// Convert a single [`AclPortEntry`] into a [`wrule::RuleType`].
fn port_entry_to_rule_type(entry: &AclPortEntry) -> wrule::RuleType {
	let port_rule = match entry.port_spec {
		AclPortSpec::Single(p) => wrule::RuleType::DstPort(p),
		AclPortSpec::Range(lo, hi) => wrule::RuleType::DstPortRange(lo, hi),
	};

	match entry.protocol {
		None => port_rule,
		Some(proto) => {
			let net_type = match proto {
				AclProtocol::Tcp => NetworkType::Tcp,
				AclProtocol::Udp => NetworkType::Udp,
			};
			// AND(NETWORK, PORT)
			wrule::RuleType::And(vec![
				wrule::Rule {
					rule_type: wrule::RuleType::Network(net_type),
					target: String::new(),
					options: Vec::new(),
				},
				wrule::Rule {
					rule_type: port_rule,
					target: String::new(),
					options: Vec::new(),
				},
			])
		}
	}
}

/// Clone a `RuleType` (needed because `Regex` doesn't derive `Clone`).
fn clone_rule_type(rt: &wrule::RuleType) -> wrule::RuleType {
	// Round-trip through Display → parse.  This works for all types that are
	// produced by the conversion above (no Regex types are generated).
	let s = format!("{rt},__CLONE");
	wrule::Rule::parse(&s).map(|r| r.rule_type).unwrap_or(wrule::RuleType::Match)
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

	#[tokio::test]
	async fn ip_exact_match() {
		let rule = AclRule {
			addr: AclAddress::Ip("203.0.113.7".into()),
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("203.0.113.7", 12345), 12345, true).await);
		assert!(!rule.matching(v4("203.0.113.8", 12345), 12345, true).await);
		assert!(!rule.matching(v6("2001:db8::1", 12345), 12345, true).await);
	}

	#[tokio::test]
	async fn cidr_match() {
		let rule = AclRule {
			addr: AclAddress::Cidr("10.0.0.0/8".into()),
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("10.1.2.3", 0), 0, false).await);
		assert!(!rule.matching(v4("192.0.2.1", 0), 0, false).await);
		assert!(!rule.matching(v6("::1", 0), 0, false).await);
	}

	#[tokio::test]
	async fn domain_match_localhost() {
		let rule = AclRule {
			addr: AclAddress::Domain("localhost".into()),
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("127.0.0.1", 0), 0, true).await);
		assert!(rule.matching(v6("::1", 0), 0, true).await);
		assert!(!rule.matching(v4("8.8.8.8", 0), 0, true).await);
	}

	#[tokio::test]
	async fn wildcard_domain_match_suffix_localhost() {
		let rule = AclRule {
			addr: AclAddress::WildcardDomain("suffix:localhost".into()),
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("127.0.0.1", 0), 0, true).await);
		assert!(rule.matching(v6("::1", 0), 0, true).await);
		assert!(!rule.matching(v4("8.8.8.8", 0), 0, true).await);
	}

	#[tokio::test]
	async fn localhost_match() {
		let rule = AclRule {
			addr: AclAddress::Localhost,
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("127.0.0.1", 0), 0, true).await);
		assert!(rule.matching(v6("::1", 0), 0, true).await);
		assert!(!rule.matching(v4("192.0.2.1", 0), 0, true).await);
	}

	#[tokio::test]
	async fn private_match_ipv4() {
		let rule = AclRule {
			addr: AclAddress::Private,
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		// Test 10.0.0.0/8 range
		assert!(rule.matching(v4("10.0.0.0", 0), 0, true).await);
		assert!(rule.matching(v4("10.0.0.1", 0), 0, true).await);
		assert!(rule.matching(v4("10.255.255.255", 0), 0, true).await);

		// Test 172.16.0.0/12 range
		assert!(rule.matching(v4("172.16.0.0", 0), 0, true).await);
		assert!(rule.matching(v4("172.16.0.1", 0), 0, true).await);
		assert!(rule.matching(v4("172.31.255.255", 0), 0, true).await);
		assert!(!rule.matching(v4("172.15.255.255", 0), 0, true).await);
		assert!(!rule.matching(v4("172.32.0.0", 0), 0, true).await);

		// Test 192.168.0.0/16 range
		assert!(rule.matching(v4("192.168.0.0", 0), 0, true).await);
		assert!(rule.matching(v4("192.168.1.1", 0), 0, true).await);
		assert!(rule.matching(v4("192.168.255.255", 0), 0, true).await);

		// Test 169.254.0.0/16 range (Link-local)
		assert!(rule.matching(v4("169.254.0.0", 0), 0, true).await);
		assert!(rule.matching(v4("169.254.1.1", 0), 0, true).await);
		assert!(rule.matching(v4("169.254.255.255", 0), 0, true).await);

		// Test public addresses (should not match)
		assert!(!rule.matching(v4("8.8.8.8", 0), 0, true).await);
		assert!(!rule.matching(v4("1.1.1.1", 0), 0, true).await);
		assert!(!rule.matching(v4("203.0.113.1", 0), 0, true).await);
	}

	#[tokio::test]
	async fn private_match_ipv6() {
		let rule = AclRule {
			addr: AclAddress::Private,
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		// Test fc00::/7 (Unique Local Address)
		assert!(rule.matching(v6("fc00::1", 0), 0, true).await);
		assert!(rule.matching(v6("fd00::1", 0), 0, true).await);
		assert!(rule.matching(v6("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0), 0, true).await);

		// Test fe80::/10 (Link-local)
		assert!(rule.matching(v6("fe80::1", 0), 0, true).await);
		assert!(rule.matching(v6("fe80::dead:beef", 0), 0, true).await);
		assert!(rule.matching(v6("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0), 0, true).await);

		// Test public addresses (should not match)
		assert!(!rule.matching(v6("2001:db8::1", 0), 0, true).await);
		assert!(!rule.matching(v6("2606:4700:4700::1111", 0), 0, true).await);
	}

	#[tokio::test]
	async fn parse_private_keyword() {
		let result = parse_acl_rule("allow private").unwrap();
		assert_eq!(result.outbound, "allow");
		assert_eq!(result.addr, AclAddress::Private);
		assert_eq!(result.ports, None);
		assert_eq!(result.hijack, None);
	}

	#[tokio::test]
	async fn parse_private_with_ports() {
		let result = parse_acl_rule("block private tcp/80,udp/53").unwrap();
		assert_eq!(result.outbound, "block");
		assert_eq!(result.addr, AclAddress::Private);
		assert!(result.ports.is_some());
	}

	#[tokio::test]
	async fn keyword_prefix_of_domain_is_not_swallowed() {
		// `private`/`localhost` must be complete tokens, not prefixes. Before the
		// boundary assertion, `proxy privatetracker.org` parsed as
		// addr=Private + hijack="tracker.org", silently rerouting all of RFC1918.
		let result = parse_acl_rule("proxy privatetracker.org").unwrap();
		assert_eq!(result.outbound, "proxy");
		assert_eq!(result.addr, AclAddress::Domain("privatetracker.org".into()));
		assert_eq!(result.hijack, None);

		let result = parse_acl_rule("allow localhost5.com").unwrap();
		assert_eq!(result.addr, AclAddress::Domain("localhost5.com".into()));
		assert_eq!(result.ports, None);
		assert_eq!(result.hijack, None);

		// The bare keywords still parse as keywords.
		assert_eq!(parse_acl_rule("allow private").unwrap().addr, AclAddress::Private);
		assert_eq!(parse_acl_rule("allow localhost").unwrap().addr, AclAddress::Localhost);
	}

	#[tokio::test]
	async fn any_match() {
		let rule = AclRule {
			addr: AclAddress::Any,
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("203.0.113.1", 0), 0, true).await);
		assert!(rule.matching(v6("2001:db8::42", 0), 0, true).await);
	}

	#[tokio::test]
	async fn ipv6_cidr_match() {
		let rule = AclRule {
			addr: AclAddress::Cidr("2001:db8::/32".into()),
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v6("2001:db8::1", 80), 80, true).await);
		assert!(rule.matching(v6("2001:db8:1::1", 80), 80, true).await);
		assert!(!rule.matching(v6("2001:db9::1", 80), 80, true).await);
		assert!(!rule.matching(v6("2002:db8::1", 80), 80, true).await);
		assert!(!rule.matching(v4("10.0.0.1", 80), 80, true).await);
	}

	#[tokio::test]
	async fn cidr_slash_32() {
		let rule = AclRule {
			addr: AclAddress::Cidr("192.168.1.100/32".into()),
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("192.168.1.100", 80), 80, true).await);
		assert!(!rule.matching(v4("192.168.1.101", 80), 80, true).await);
		assert!(!rule.matching(v4("192.168.1.99", 80), 80, true).await);
	}

	#[tokio::test]
	async fn cidr_slash_0() {
		let rule = AclRule {
			addr: AclAddress::Cidr("0.0.0.0/0".into()),
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("1.2.3.4", 80), 80, true).await);
		assert!(rule.matching(v4("192.168.1.1", 80), 80, true).await);
		assert!(rule.matching(v4("255.255.255.255", 80), 80, true).await);
		assert!(!rule.matching(v6("::1", 80), 80, true).await);
	}

	#[tokio::test]
	async fn invalid_ip_address() {
		let rule = AclRule {
			addr: AclAddress::Ip("not.an.ip.address".into()),
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(!rule.matching(v4("1.2.3.4", 80), 80, true).await);
		assert!(!rule.matching(v6("::1", 80), 80, true).await);
	}

	#[tokio::test]
	async fn invalid_cidr() {
		let rule = AclRule {
			addr: AclAddress::Cidr("invalid/cidr".into()),
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(!rule.matching(v4("10.0.0.1", 80), 80, true).await);
		assert!(!rule.matching(v6("2001:db8::1", 80), 80, true).await);
	}

	#[tokio::test]
	async fn loopback_addresses() {
		let rule = AclRule {
			addr: AclAddress::Localhost,
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("127.0.0.1", 80), 80, true).await);
		assert!(rule.matching(v4("127.0.0.2", 80), 80, true).await);
		assert!(rule.matching(v4("127.255.255.255", 80), 80, true).await);
		assert!(rule.matching(v6("::1", 80), 80, true).await);
		assert!(!rule.matching(v4("192.168.1.1", 80), 80, true).await);
		assert!(!rule.matching(v6("2001:db8::1", 80), 80, true).await);
	}

	#[tokio::test]
	async fn ports_none_matches_everything() {
		let rule = AclRule {
			addr: AclAddress::Any,
			ports: None,
			outbound: "default".to_string(),
			hijack: None,
		};

		for port in [0u16, 22, 80, 443, 65535] {
			assert!(rule.matching(v4("1.2.3.4", port), port, true).await);
			assert!(rule.matching(v4("1.2.3.4", port), port, false).await);
		}
	}

	#[tokio::test]
	async fn single_port_without_protocol() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol: None,
				port_spec: AclPortSpec::Single(8080),
			}],
		};

		let rule = AclRule {
			addr: AclAddress::Any,
			ports: Some(ports),
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("10.0.0.1", 8080), 8080, true).await);
		assert!(rule.matching(v4("10.0.0.1", 8080), 8080, false).await);
		assert!(!rule.matching(v4("10.0.0.1", 80), 80, true).await);
		assert!(!rule.matching(v4("10.0.0.1", 443), 443, false).await);
	}

	#[tokio::test]
	async fn port_range_with_protocol() {
		let ports = AclPorts {
			entries: vec![
				AclPortEntry {
					protocol: Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Range(1000, 1005),
				},
				AclPortEntry {
					protocol: Some(AclProtocol::Udp),
					port_spec: AclPortSpec::Range(2000, 2002),
				},
			],
		};

		let rule = AclRule {
			addr: AclAddress::Any,
			ports: Some(ports),
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("8.8.8.8", 1003), 1003, true).await);
		assert!(!rule.matching(v4("8.8.8.8", 999), 999, true).await);
		assert!(rule.matching(v4("8.8.8.8", 2001), 2001, false).await);
		assert!(!rule.matching(v4("8.8.8.8", 1999), 1999, false).await);
	}

	#[tokio::test]
	async fn port_range_boundary() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol: None,
				port_spec: AclPortSpec::Range(100, 200),
			}],
		};

		let rule = AclRule {
			addr: AclAddress::Any,
			ports: Some(ports),
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("1.1.1.1", 100), 100, true).await);
		assert!(rule.matching(v4("1.1.1.1", 200), 200, true).await);
		assert!(!rule.matching(v4("1.1.1.1", 99), 99, true).await);
		assert!(!rule.matching(v4("1.1.1.1", 201), 201, true).await);
		assert!(rule.matching(v4("1.1.1.1", 150), 150, false).await);
	}

	#[tokio::test]
	async fn edge_case_port_zero() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol: None,
				port_spec: AclPortSpec::Single(0),
			}],
		};

		let rule = AclRule {
			addr: AclAddress::Any,
			ports: Some(ports),
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("1.2.3.4", 0), 0, true).await);
		assert!(!rule.matching(v4("1.2.3.4", 1), 1, true).await);
	}

	#[tokio::test]
	async fn edge_case_port_max() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol: None,
				port_spec: AclPortSpec::Single(65535),
			}],
		};

		let rule = AclRule {
			addr: AclAddress::Any,
			ports: Some(ports),
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("1.2.3.4", 65535), 65535, true).await);
		assert!(!rule.matching(v4("1.2.3.4", 65534), 65534, true).await);
	}

	#[tokio::test]
	async fn address_and_port_combination() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol: Some(AclProtocol::Tcp),
				port_spec: AclPortSpec::Single(22),
			}],
		};

		let rule = AclRule {
			addr: AclAddress::Ip("192.0.2.10".into()),
			ports: Some(ports),
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("192.0.2.10", 22), 22, true).await);
		assert!(!rule.matching(v4("192.0.2.11", 22), 22, true).await);
		assert!(!rule.matching(v4("192.0.2.10", 23), 23, true).await);
		assert!(!rule.matching(v4("192.0.2.10", 22), 22, false).await);
	}

	#[tokio::test]
	async fn ports_defined_but_protocol_mismatch() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol: Some(AclProtocol::Tcp),
				port_spec: AclPortSpec::Single(443),
			}],
		};

		let rule = AclRule {
			addr: AclAddress::Any,
			ports: Some(ports),
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(!rule.matching(v4("1.1.1.1", 443), 443, false).await);
		assert!(rule.matching(v4("1.1.1.1", 443), 443, true).await);
	}

	#[tokio::test]
	async fn empty_allowed_port_set_is_rejected() {
		let ports = AclPorts {
			entries: vec![AclPortEntry {
				protocol: Some(AclProtocol::Tcp),
				port_spec: AclPortSpec::Single(9999),
			}],
		};

		let rule = AclRule {
			addr: AclAddress::Any,
			ports: Some(ports),
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(!rule.matching(v4("8.8.8.8", 9999), 9999, false).await);
	}

	#[tokio::test]
	async fn multiple_port_entries() {
		let ports = AclPorts {
			entries: vec![
				AclPortEntry {
					protocol: Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Single(80),
				},
				AclPortEntry {
					protocol: Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Single(443),
				},
				AclPortEntry {
					protocol: Some(AclProtocol::Udp),
					port_spec: AclPortSpec::Range(5000, 5100),
				},
			],
		};

		let rule = AclRule {
			addr: AclAddress::Any,
			ports: Some(ports),
			outbound: "default".to_string(),
			hijack: None,
		};

		assert!(rule.matching(v4("1.2.3.4", 80), 80, true).await);
		assert!(rule.matching(v4("1.2.3.4", 443), 443, true).await);
		assert!(!rule.matching(v4("1.2.3.4", 8080), 8080, true).await);
		assert!(rule.matching(v4("1.2.3.4", 5050), 5050, false).await);
		assert!(!rule.matching(v4("1.2.3.4", 4999), 4999, false).await);
		assert!(!rule.matching(v4("1.2.3.4", 5101), 5101, false).await);
	}

	#[tokio::test]
	async fn parse_simple_rule() -> eyre::Result<()> {
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

	#[tokio::test]
	async fn parse_wildcard_domain() -> eyre::Result<()> {
		let rule_str = "deny *.google.com";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "deny");
		assert_eq!(rule.addr, AclAddress::WildcardDomain("*.google.com".to_string()));
		assert!(rule.ports.is_none());
		Ok(())
	}

	#[tokio::test]
	async fn parse_port_range() -> eyre::Result<()> {
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

	#[tokio::test]
	async fn parse_any_address_any_port() -> eyre::Result<()> {
		let rule_str = "proxy * *";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "proxy");
		assert_eq!(rule.addr, AclAddress::Any);
		assert!(rule.ports.is_none());
		Ok(())
	}

	#[tokio::test]
	async fn parse_with_hijack() -> eyre::Result<()> {
		let rule_str = "redirect 8.8.8.8 tcp/53 10.0.0.1";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "redirect");
		assert_eq!(rule.addr, AclAddress::Ip("8.8.8.8".to_string()));
		assert_eq!(rule.hijack, Some("10.0.0.1".to_string()));
		Ok(())
	}

	#[tokio::test]
	async fn parse_localhost() -> eyre::Result<()> {
		let rule_str = "allow localhost";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "allow");
		assert_eq!(rule.addr, AclAddress::Localhost);
		Ok(())
	}

	#[tokio::test]
	async fn parse_ipv6_address() -> eyre::Result<()> {
		let rule_str = "allow 2001:db8::1";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "allow");
		assert_eq!(rule.addr, AclAddress::Ip("2001:db8::1".to_string()));
		Ok(())
	}

	#[tokio::test]
	async fn parse_ipv6_cidr() -> eyre::Result<()> {
		let rule_str = "block 2001:db8::/32";
		let rule = parse_acl_rule(rule_str)?;

		assert_eq!(rule.outbound, "block");
		assert_eq!(rule.addr, AclAddress::Cidr("2001:db8::/32".to_string()));
		Ok(())
	}

	#[tokio::test]
	async fn parse_comment_line() {
		let rule_str = "# This is a comment";
		let result = parse_acl_rule(rule_str);

		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("Comment"));
	}

	#[tokio::test]
	async fn parse_empty_line() {
		let result = parse_acl_rule("");

		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("empty"));
	}

	#[tokio::test]
	async fn parse_multiline_string() -> eyre::Result<()> {
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

	#[tokio::test]
	async fn parse_mixed_protocols() -> eyre::Result<()> {
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

	#[tokio::test]
	async fn display_acl_rule() {
		let rule = AclRule {
			outbound: "allow".to_string(),
			addr: AclAddress::Ip("192.168.1.1".to_string()),
			ports: None,
			hijack: None,
		};

		assert_eq!(rule.to_string(), "allow 192.168.1.1");
	}

	#[tokio::test]
	async fn display_acl_rule_with_ports() {
		let rule = AclRule {
			outbound: "allow".to_string(),
			addr: AclAddress::Any,
			ports: Some(AclPorts {
				entries: vec![AclPortEntry {
					protocol: Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Single(443),
				}],
			}),
			hijack: None,
		};

		assert_eq!(rule.to_string(), "allow * tcp/443");
	}

	#[tokio::test]
	async fn display_acl_rule_with_hijack() {
		let rule = AclRule {
			outbound: "redirect".to_string(),
			addr: AclAddress::Ip("8.8.8.8".to_string()),
			ports: None,
			hijack: Some("10.0.0.1".to_string()),
		};

		assert_eq!(rule.to_string(), "redirect 8.8.8.8 10.0.0.1");
	}

	#[tokio::test]
	async fn display_port_entry() {
		let entry = AclPortEntry {
			protocol: Some(AclProtocol::Tcp),
			port_spec: AclPortSpec::Single(80),
		};

		assert_eq!(entry.to_string(), "tcp/80");
	}

	#[tokio::test]
	async fn display_port_entry_no_protocol() {
		let entry = AclPortEntry {
			protocol: None,
			port_spec: AclPortSpec::Range(1000, 2000),
		};

		assert_eq!(entry.to_string(), "1000-2000");
	}

	#[tokio::test]
	async fn display_ports() {
		let ports = AclPorts {
			entries: vec![
				AclPortEntry {
					protocol: Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Single(80),
				},
				AclPortEntry {
					protocol: Some(AclProtocol::Udp),
					port_spec: AclPortSpec::Single(53),
				},
			],
		};

		assert_eq!(ports.to_string(), "tcp/80,udp/53");
	}

	#[tokio::test]
	async fn deserialize_address_ip() -> eyre::Result<()> {
		let toml = r#"addr = "192.168.1.1""#;
		#[derive(Deserialize)]
		struct Test {
			addr: AclAddress,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.addr, AclAddress::Ip("192.168.1.1".to_string()));
		Ok(())
	}

	#[tokio::test]
	async fn deserialize_address_cidr() -> eyre::Result<()> {
		let toml = r#"addr = "10.0.0.0/8""#;
		#[derive(Deserialize)]
		struct Test {
			addr: AclAddress,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.addr, AclAddress::Cidr("10.0.0.0/8".to_string()));
		Ok(())
	}

	#[tokio::test]
	async fn deserialize_address_localhost() -> eyre::Result<()> {
		let toml = r#"addr = "localhost""#;
		#[derive(Deserialize)]
		struct Test {
			addr: AclAddress,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.addr, AclAddress::Localhost);
		Ok(())
	}

	#[tokio::test]
	async fn deserialize_address_wildcard() -> eyre::Result<()> {
		let toml = r#"addr = "*.google.com""#;
		#[derive(Deserialize)]
		struct Test {
			addr: AclAddress,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.addr, AclAddress::WildcardDomain("*.google.com".to_string()));
		Ok(())
	}

	#[tokio::test]
	async fn deserialize_protocol_tcp() -> eyre::Result<()> {
		let toml = r#"proto = "tcp""#;
		#[derive(Deserialize)]
		struct Test {
			proto: AclProtocol,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.proto, AclProtocol::Tcp);
		Ok(())
	}

	#[tokio::test]
	async fn deserialize_protocol_udp_uppercase() -> eyre::Result<()> {
		let toml = r#"proto = "UDP""#;
		#[derive(Deserialize)]
		struct Test {
			proto: AclProtocol,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.proto, AclProtocol::Udp);
		Ok(())
	}

	#[tokio::test]
	async fn deserialize_port_spec_single() -> eyre::Result<()> {
		let toml = r#"spec = "80""#;
		#[derive(Deserialize)]
		struct Test {
			spec: AclPortSpec,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.spec, AclPortSpec::Single(80));
		Ok(())
	}

	#[tokio::test]
	async fn deserialize_port_spec_range() -> eyre::Result<()> {
		let toml = r#"spec = "1000-2000""#;
		#[derive(Deserialize)]
		struct Test {
			spec: AclPortSpec,
		}
		let test: Test = toml::from_str(toml)?;

		assert_eq!(test.spec, AclPortSpec::Range(1000, 2000));
		Ok(())
	}

	#[tokio::test]
	async fn deserialize_port_entry() -> eyre::Result<()> {
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

	#[tokio::test]
	async fn deserialize_ports() -> eyre::Result<()> {
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

	#[tokio::test]
	async fn deserialize_acl_rule_from_toml() -> eyre::Result<()> {
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

	#[tokio::test]
	async fn deserialize_acl_multiline_string() -> eyre::Result<()> {
		let toml = r#"
acl = """
allow 192.168.1.0/24 tcp/443
deny *.ads.com
allow localhost
allow private
"""
"#;
		#[derive(Deserialize)]
		struct Config {
			#[serde(deserialize_with = "deserialize_acl")]
			acl: Vec<AclRule>,
		}

		let config: Config = toml::from_str(toml)?;
		assert_eq!(config.acl.len(), 4);
		assert_eq!(config.acl[0].outbound, "allow");
		assert_eq!(config.acl[1].outbound, "deny");
		assert_eq!(config.acl[2].outbound, "allow");
		assert_eq!(config.acl[3].addr, AclAddress::Private);
		Ok(())
	}

	#[tokio::test]
	async fn deserialize_acl_array_of_tables() -> eyre::Result<()> {
		let toml = r#"
[[acl]]
outbound = "allow"
addr = "192.168.1.0/24"
ports = "tcp/443"

[[acl]]
outbound = "deny"
addr = "*.ads.com"

[[acl]]
outbound = "deny"
addr = "private"
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
		assert_eq!(config.acl[2].addr, AclAddress::Private);
		Ok(())
	}

	#[test]
	fn convert_ip_acl_to_rule() {
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::Ip("1.2.3.4".into()),
			ports: None,
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);
		assert_eq!(rules[0].target, "proxy");
		let ctx = wrule::MatchContext {
			dst_ip: Some("1.2.3.4".parse().unwrap()),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx));
	}

	#[test]
	fn convert_cidr_acl_to_rule() {
		let acl = AclRule {
			outbound: "direct".into(),
			addr: AclAddress::Cidr("10.0.0.0/8".into()),
			ports: None,
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);
		let ctx = wrule::MatchContext {
			dst_ip: Some("10.1.2.3".parse().unwrap()),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx));
		let ctx_no = wrule::MatchContext {
			dst_ip: Some("192.168.1.1".parse().unwrap()),
			..Default::default()
		};
		assert!(!rules[0].matches(&ctx_no));
	}

	#[test]
	fn convert_domain_acl_to_rule() {
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::Domain("example.com".into()),
			ports: None,
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);
		assert!(matches!(rules[0].rule_type, wrule::RuleType::Domain(ref d) if d == "example.com"));
	}

	#[test]
	fn convert_wildcard_acl_to_domain_suffix() {
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::WildcardDomain("*.google.com".into()),
			ports: None,
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);
		let ctx = wrule::MatchContext {
			domain: Some("www.google.com"),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx));
		let ctx_root = wrule::MatchContext {
			domain: Some("google.com"),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx_root));
	}

	#[test]
	fn convert_localhost_acl_expands_to_two_cidrs() {
		let acl = AclRule {
			outbound: "reject".into(),
			addr: AclAddress::Localhost,
			ports: None,
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 2); // 127.0.0.0/8 + ::1/128
		let ctx = wrule::MatchContext {
			dst_ip: Some("127.0.0.1".parse().unwrap()),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx));
	}

	#[test]
	fn convert_private_acl_expands_to_multiple_cidrs() {
		let acl = AclRule {
			outbound: "direct".into(),
			addr: AclAddress::Private,
			ports: None,
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert!(rules.len() >= 6); // multiple RFC 1918 + link-local + loopback
		// 10.x should match one of them
		let ctx = wrule::MatchContext {
			dst_ip: Some("10.0.0.1".parse().unwrap()),
			..Default::default()
		};
		assert!(rules.iter().any(|r| r.matches(&ctx)));
	}

	#[test]
	fn convert_any_with_no_ports_gives_match_all() {
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::Any,
			ports: None,
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);
		assert!(matches!(rules[0].rule_type, wrule::RuleType::Match));
	}

	#[test]
	fn convert_acl_with_port() {
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::Any,
			ports: Some(AclPorts {
				entries: vec![AclPortEntry {
					protocol: None,
					port_spec: AclPortSpec::Single(443),
				}],
			}),
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);
		let ctx = wrule::MatchContext {
			dst_port: Some(443),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx));
		let ctx_no = wrule::MatchContext {
			dst_port: Some(80),
			..Default::default()
		};
		assert!(!rules[0].matches(&ctx_no));
	}

	#[test]
	fn convert_acl_with_port_range() {
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::Any,
			ports: Some(AclPorts {
				entries: vec![AclPortEntry {
					protocol: None,
					port_spec: AclPortSpec::Range(8000, 9000),
				}],
			}),
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);
		let ctx = wrule::MatchContext {
			dst_port: Some(8500),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx));
	}

	#[test]
	fn convert_acl_with_protocol_port() {
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::Any,
			ports: Some(AclPorts {
				entries: vec![AclPortEntry {
					protocol: Some(AclProtocol::Tcp),
					port_spec: AclPortSpec::Single(443),
				}],
			}),
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);
		// TCP 443 → match
		let ctx_tcp = wrule::MatchContext {
			dst_port: Some(443),
			network: Some(NetworkType::Tcp),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx_tcp));
		// UDP 443 → no match
		let ctx_udp = wrule::MatchContext {
			dst_port: Some(443),
			network: Some(NetworkType::Udp),
			..Default::default()
		};
		assert!(!rules[0].matches(&ctx_udp));
	}

	#[test]
	fn convert_addr_with_port_produces_and_rule() {
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::Cidr("10.0.0.0/8".into()),
			ports: Some(AclPorts {
				entries: vec![AclPortEntry {
					protocol: None,
					port_spec: AclPortSpec::Single(80),
				}],
			}),
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);
		assert!(matches!(rules[0].rule_type, wrule::RuleType::And(_)));
		// 10.1.2.3:80 → match
		let ctx = wrule::MatchContext {
			dst_ip: Some("10.1.2.3".parse().unwrap()),
			dst_port: Some(80),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx));
		// 10.1.2.3:443 → no match
		let ctx_no = wrule::MatchContext {
			dst_ip: Some("10.1.2.3".parse().unwrap()),
			dst_port: Some(443),
			..Default::default()
		};
		assert!(!rules[0].matches(&ctx_no));
	}

	#[test]
	fn convert_allow_outbound_to_default() {
		let acl = AclRule {
			outbound: "allow".into(),
			addr: AclAddress::Any,
			ports: None,
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules[0].target, "default");
	}

	#[test]
	fn convert_multiple_acl_rules() {
		let acls = vec![
			AclRule {
				outbound: "reject".into(),
				addr: AclAddress::Localhost,
				ports: None,
				hijack: None,
			},
			AclRule {
				outbound: "proxy".into(),
				addr: AclAddress::Domain("google.com".into()),
				ports: None,
				hijack: None,
			},
		];
		let rules = acl_to_rules(&acls);
		// Localhost → 2 rules, Domain → 1 rule
		assert_eq!(rules.len(), 3);
		assert_eq!(rules[0].target, "reject");
		assert_eq!(rules[2].target, "proxy");
	}

	// -- Additional conversion tests --

	#[test]
	fn convert_suffix_prefix_domain() {
		// `suffix:example.com` should convert to DOMAIN-SUFFIX
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::WildcardDomain("suffix:example.com".into()),
			ports: None,
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);
		let ctx = wrule::MatchContext {
			domain: Some("sub.example.com"),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx));
		let ctx_exact = wrule::MatchContext {
			domain: Some("example.com"),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx_exact));
	}

	#[test]
	fn convert_multiple_ports_with_address() {
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::Cidr("172.16.0.0/12".into()),
			ports: Some(AclPorts {
				entries: vec![
					AclPortEntry {
						protocol: None,
						port_spec: AclPortSpec::Single(80),
					},
					AclPortEntry {
						protocol: None,
						port_spec: AclPortSpec::Single(443),
					},
				],
			}),
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		// Each port × cidr → one AND rule per port
		assert_eq!(rules.len(), 2);

		// 172.16.1.1:80 → match first rule
		let ctx80 = wrule::MatchContext {
			dst_ip: Some("172.16.1.1".parse().unwrap()),
			dst_port: Some(80),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx80));

		// 172.16.1.1:443 → match second rule
		let ctx443 = wrule::MatchContext {
			dst_ip: Some("172.16.1.1".parse().unwrap()),
			dst_port: Some(443),
			..Default::default()
		};
		assert!(rules[1].matches(&ctx443));

		// 172.16.1.1:8080 → no match
		let ctx_no = wrule::MatchContext {
			dst_ip: Some("172.16.1.1".parse().unwrap()),
			dst_port: Some(8080),
			..Default::default()
		};
		assert!(!rules[0].matches(&ctx_no));
		assert!(!rules[1].matches(&ctx_no));
	}

	#[test]
	fn convert_port_range() {
		let acl = AclRule {
			outbound: "proxy".into(),
			addr: AclAddress::Any,
			ports: Some(AclPorts {
				entries: vec![AclPortEntry {
					protocol: None,
					port_spec: AclPortSpec::Range(1000, 2000),
				}],
			}),
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		assert_eq!(rules.len(), 1);

		let ctx_in = wrule::MatchContext {
			dst_port: Some(1500),
			..Default::default()
		};
		assert!(rules[0].matches(&ctx_in));

		let ctx_out = wrule::MatchContext {
			dst_port: Some(999),
			..Default::default()
		};
		assert!(!rules[0].matches(&ctx_out));
	}

	#[test]
	fn convert_private_address_produces_multiple_cidrs() {
		let acl = AclRule {
			outbound: "direct".into(),
			addr: AclAddress::Private,
			ports: None,
			hijack: None,
		};
		let rules = acl_rule_to_rules(&acl);
		// Private produces 8 CIDR rules
		assert!(rules.len() >= 8);
		for rule in &rules {
			assert_eq!(rule.target, "direct");
		}

		// 192.168.1.1 → should match one of the rules
		let ctx = wrule::MatchContext {
			dst_ip: Some("192.168.1.1".parse().unwrap()),
			..Default::default()
		};
		assert!(rules.iter().any(|r| r.matches(&ctx)));

		// 8.8.8.8 → should not match any
		let ctx_pub = wrule::MatchContext {
			dst_ip: Some("8.8.8.8".parse().unwrap()),
			..Default::default()
		};
		assert!(!rules.iter().any(|r| r.matches(&ctx_pub)));
	}

	// ------------------------------------------------------------------
	// PR4-O regression tests for `address_to_rule_types`
	// ------------------------------------------------------------------

	/// IPv6 literals must produce a `/128` host route, not a `/32` network
	/// route. Previously `format!("{ip}/32").parse::<ipnet::IpNet>()` was
	/// tried first; `ipnet` accepts `/32` for IPv6 too and silently returned
	/// the network `2001:db8::/32`, expanding the ACL by ~96 bits.
	#[test]
	fn acl_ipv6_address_yields_128_host_route() {
		let acl = AclRule {
			outbound: "direct".into(),
			addr: AclAddress::Ip("2001:db8::1".into()),
			ports: None,
			hijack: None,
		};
		let rules = acl_to_rules(std::slice::from_ref(&acl));
		assert!(!rules.is_empty(), "expected at least one rule");
		let ctx_match = wrule::MatchContext {
			dst_ip: Some("2001:db8::1".parse().unwrap()),
			..Default::default()
		};
		assert!(rules.iter().any(|r| r.matches(&ctx_match)));

		let ctx_outside = wrule::MatchContext {
			dst_ip: Some("2001:db8::2".parse().unwrap()),
			..Default::default()
		};
		assert!(
			!rules.iter().any(|r| r.matches(&ctx_outside)),
			"a /128 host rule must NOT match a different IPv6 in the same /32",
		);
	}

	/// IPv4 case stays correct.
	#[test]
	fn acl_ipv4_address_yields_32_host_route() {
		let acl = AclRule {
			outbound: "direct".into(),
			addr: AclAddress::Ip("10.0.0.5".into()),
			ports: None,
			hijack: None,
		};
		let rules = acl_to_rules(std::slice::from_ref(&acl));
		let ctx = wrule::MatchContext {
			dst_ip: Some("10.0.0.5".parse().unwrap()),
			..Default::default()
		};
		assert!(rules.iter().any(|r| r.matches(&ctx)));
		let ctx2 = wrule::MatchContext {
			dst_ip: Some("10.0.0.6".parse().unwrap()),
			..Default::default()
		};
		assert!(!rules.iter().any(|r| r.matches(&ctx2)));
	}

	/// Malformed IP literals must drop the rule (returning `vec![]`) instead
	/// of falling back to `0.0.0.0/32`, which previously turned bad data into
	/// a silently "matches nothing" rule that hid the configuration error.
	#[test]
	fn acl_malformed_ip_drops_rule() {
		let acl = AclRule {
			outbound: "direct".into(),
			addr: AclAddress::Ip("not-an-ip".into()),
			ports: None,
			hijack: None,
		};
		let rules = acl_to_rules(std::slice::from_ref(&acl));
		assert!(rules.is_empty(), "malformed IP must drop the rule");
	}

	// ------------------------------------------------------------------
	// PR5-K regression: `format_protocol` / `format_optional_parts` Display
	// output must still match the parser-accepted spelling.
	// ------------------------------------------------------------------

	#[test]
	fn format_protocol_zero_alloc_output() {
		assert_eq!(super::format_protocol(&Some(super::AclProtocol::Tcp)), "tcp/");
		assert_eq!(super::format_protocol(&Some(super::AclProtocol::Udp)), "udp/");
		assert_eq!(super::format_protocol(&None), "");
	}

	#[test]
	fn format_optional_parts_display() {
		// Empty case — no ports + no hijack ⇒ empty Display.
		let s = super::format_optional_parts(&None, &None).to_string();
		assert_eq!(s, "");

		// Hijack only.
		let s = super::format_optional_parts(&None, &Some("10.0.0.1".into())).to_string();
		assert_eq!(s, " 10.0.0.1");
	}
}
