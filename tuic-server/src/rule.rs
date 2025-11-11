//! # Metacubex-style Rule Parser
//!
//! This module implements parsing and matching for routing rules similar to Clash/Mihomo (Metacubex).
//!
//! ## Supported Rule Types
//!
//! ### Domain Rules
//! - `DOMAIN` - Exact domain match
//! - `DOMAIN-SUFFIX` - Domain suffix match (includes subdomains)
//! - `DOMAIN-KEYWORD` - Domain contains keyword
//! - `DOMAIN-WILDCARD` - Wildcard pattern matching
//! - `DOMAIN-REGEX` - Regular expression matching
//! - `GEOSITE` - GeoSite database matching
//!
//! ### IP Rules
//! - `IP-CIDR` - IPv4/IPv6 CIDR matching
//! - `IP-CIDR6` - IPv6 CIDR matching
//! - `IP-SUFFIX` - IP network suffix matching
//! - `IP-ASN` - Autonomous System Number matching
//! - `GEOIP` - GeoIP country code matching
//!
//! ### Source IP Rules
//! - `SRC-GEOIP` - Source IP GeoIP matching
//! - `SRC-IP-ASN` - Source IP ASN matching
//! - `SRC-IP-CIDR` - Source IP CIDR matching
//! - `SRC-IP-SUFFIX` - Source IP suffix matching
//!
//! ### Port Rules
//! - `DST-PORT` - Destination port matching
//! - `SRC-PORT` - Source port matching
//!
//! ### Inbound Rules
//! - `IN-PORT` - Inbound port matching
//! - `IN-TYPE` - Inbound type (SOCKS/HTTP)
//! - `IN-USER` - Inbound user matching
//! - `IN-NAME` - Inbound name matching
//!
//! ### Process Rules
//! - `PROCESS-PATH` - Process path matching
//! - `PROCESS-PATH-REGEX` - Process path regex matching
//! - `PROCESS-NAME` - Process name matching
//! - `PROCESS-NAME-REGEX` - Process name regex matching
//! - `UID` - User ID matching
//!
//! ### Network Rules
//! - `NETWORK` - Network type (tcp/udp)
//! - `DSCP` - DSCP value matching
//!
//! ### Advanced Rules
//! - `RULE-SET` - External rule set reference
//! - `AND` - Logical AND of multiple rules
//! - `OR` - Logical OR of multiple rules
//! - `NOT` - Logical NOT of a rule
//! - `SUB-RULE` - Sub-rule reference
//! - `MATCH` - Match all (default rule)
//!
//! ## Usage Example
//!
//! ```rust
//! use tuic_server::rule::{Rule, MatchContext, NetworkType};
//! use std::net::IpAddr;
//!
//! // Parse a single rule
//! let rule = Rule::parse("DOMAIN-SUFFIX,google.com,PROXY").unwrap();
//!
//! // Create a match context
//! let ctx = MatchContext {
//!     domain: Some("www.google.com"),
//!     network: Some(NetworkType::Tcp),
//!     dst_port: Some(443),
//!     ..Default::default()
//! };
//!
//! // Check if the rule matches
//! if rule.matches(&ctx) {
//!     println!("Matched! Target: {}", rule.target);
//! }
//!
//! // Parse multiple rules from text
//! let rules_text = r#"
//! DOMAIN,ad.com,REJECT
//! DOMAIN-SUFFIX,google.com,PROXY
//! IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
//! MATCH,DIRECT
//! "#;
//!
//! let rules: Vec<_> = Rule::parse_rules(rules_text)
//!     .into_iter()
//!     .filter_map(|r| r.ok())
//!     .collect();
//! ```
//!
//! ## Format
//!
//! Rules follow the format: `RULE_TYPE,VALUE,TARGET[,OPTIONS...]`
//!
//! - `RULE_TYPE`: The type of rule (e.g., DOMAIN, IP-CIDR)
//! - `VALUE`: The value to match against (e.g., domain name, IP range)
//! - `TARGET`: The action/outbound to use (e.g., DIRECT, PROXY, REJECT)
//! - `OPTIONS`: Optional parameters (e.g., no-resolve)

use std::net::IpAddr;

use derive_more::Display;
use ipnet::{IpNet, Ipv6Net};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Represents a routing rule similar to Clash/Mihomo style
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
	/// The rule type and its parameters
	pub rule_type: RuleType,
	/// The target/action for this rule (e.g., "DIRECT", "PROXY", "REJECT", "auto")
	pub target:    String,
	/// Additional options (e.g., "no-resolve")
	pub options:   Vec<String>,
}

/// All supported rule types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum RuleType {
	// Domain rules
	Domain(String),
	DomainSuffix(String),
	DomainKeyword(String),
	DomainWildcard(String),
	#[serde(with = "serde_regex")]
	DomainRegex(Regex),
	GeoSite(String),

	// IP rules
	IpCidr(IpNet),
	IpCidr6(Ipv6Net),
	IpSuffix(IpNet),
	IpAsn(u32),
	GeoIp(String),

	// Source IP rules
	SrcGeoIp(String),
	SrcIpAsn(u32),
	SrcIpCidr(IpNet),
	SrcIpSuffix(IpNet),

	// Port rules
	DstPort(u16),
	SrcPort(u16),

	// Inbound rules
	InPort(u16),
	InType(InboundType),
	InUser(String),
	InName(String),

	// Process rules
	ProcessPath(String),
	#[serde(with = "serde_regex")]
	ProcessPathRegex(Regex),
	ProcessName(String),
	#[serde(with = "serde_regex")]
	ProcessNameRegex(Regex),
	Uid(u32),

	// Network rules
	Network(NetworkType),
	Dscp(u8),

	// Advanced rules
	RuleSet(String),
	And(Vec<Rule>),
	Or(Vec<Rule>),
	Not(Box<Rule>),
	SubRule(Box<Rule>, String),

	// Match all
	Match,
}

/// Inbound connection types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
pub enum InboundType {
	#[display("SOCKS")]
	Socks,
	#[display("HTTP")]
	Http,
	#[display("SOCKS/HTTP")]
	SocksOrHttp,
}

/// Network protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
	#[display("tcp")]
	Tcp,
	#[display("udp")]
	Udp,
}

// ============================================================================
// Parsing Implementation
// ============================================================================

impl Rule {
	/// Parse a rule from string format: RULE_TYPE,VALUE,TARGET[,OPTIONS...]
	pub fn parse(line: &str) -> Result<Self, RuleParseError> {
		let line = line.trim();
		
		// Skip comments and empty lines
		if line.is_empty() || line.starts_with('#') {
			return Err(RuleParseError::EmptyOrComment);
		}

		let parts: Vec<&str> = line.split(',').collect();
		if parts.len() < 2 {
			return Err(RuleParseError::InvalidFormat(
				"Rule must have at least type and target".to_string(),
			));
		}

		let rule_type_str = parts[0].trim();
		
		// Handle MATCH rule (only has target, no value)
		if rule_type_str.eq_ignore_ascii_case("MATCH") {
			if parts.len() < 2 {
				return Err(RuleParseError::InvalidFormat(
					"MATCH rule must have target".to_string(),
				));
			}
			return Ok(Rule {
				rule_type: RuleType::Match,
				target:    parts[1].trim().to_string(),
				options:   parts[2..].iter().map(|s| s.trim().to_string()).collect(),
			});
		}

		// All other rules need at least 3 parts: TYPE,VALUE,TARGET
		if parts.len() < 3 {
			return Err(RuleParseError::InvalidFormat(format!(
				"Rule type '{}' requires value and target",
				rule_type_str
			)));
		}

		let value = parts[1].trim();
		let target = parts[2].trim().to_string();
		let options: Vec<String> = parts[3..].iter().map(|s| s.trim().to_string()).collect();

		let rule_type = Self::parse_rule_type(rule_type_str, value)?;

		Ok(Rule {
			rule_type,
			target,
			options,
		})
	}

	fn parse_rule_type(type_str: &str, value: &str) -> Result<RuleType, RuleParseError> {
		let type_upper = type_str.to_uppercase();
		
		match type_upper.as_str() {
			// Domain rules
			"DOMAIN" => Ok(RuleType::Domain(value.to_string())),
			"DOMAIN-SUFFIX" => Ok(RuleType::DomainSuffix(value.to_string())),
			"DOMAIN-KEYWORD" => Ok(RuleType::DomainKeyword(value.to_string())),
			"DOMAIN-WILDCARD" => Ok(RuleType::DomainWildcard(value.to_string())),
			"DOMAIN-REGEX" => {
				let regex = Regex::new(value)
					.map_err(|e| RuleParseError::InvalidRegex(e.to_string()))?;
				Ok(RuleType::DomainRegex(regex))
			}
			"GEOSITE" => Ok(RuleType::GeoSite(value.to_string())),

			// IP rules
			"IP-CIDR" => {
				let net = value.parse::<IpNet>()
					.map_err(|e| RuleParseError::InvalidIpCidr(e.to_string()))?;
				Ok(RuleType::IpCidr(net))
			}
			"IP-CIDR6" => {
				let net = value.parse::<Ipv6Net>()
					.map_err(|e| RuleParseError::InvalidIpCidr(e.to_string()))?;
				Ok(RuleType::IpCidr6(net))
			}
			"IP-SUFFIX" => {
				let net = value.parse::<IpNet>()
					.map_err(|e| RuleParseError::InvalidIpCidr(e.to_string()))?;
				Ok(RuleType::IpSuffix(net))
			}
			"IP-ASN" => {
				let asn = value.parse::<u32>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::IpAsn(asn))
			}
			"GEOIP" => Ok(RuleType::GeoIp(value.to_string())),

			// Source IP rules
			"SRC-GEOIP" => Ok(RuleType::SrcGeoIp(value.to_string())),
			"SRC-IP-ASN" => {
				let asn = value.parse::<u32>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::SrcIpAsn(asn))
			}
			"SRC-IP-CIDR" => {
				let net = value.parse::<IpNet>()
					.map_err(|e| RuleParseError::InvalidIpCidr(e.to_string()))?;
				Ok(RuleType::SrcIpCidr(net))
			}
			"SRC-IP-SUFFIX" => {
				let net = value.parse::<IpNet>()
					.map_err(|e| RuleParseError::InvalidIpCidr(e.to_string()))?;
				Ok(RuleType::SrcIpSuffix(net))
			}

			// Port rules
			"DST-PORT" => {
				let port = value.parse::<u16>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::DstPort(port))
			}
			"SRC-PORT" => {
				let port = value.parse::<u16>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::SrcPort(port))
			}

			// Inbound rules
			"IN-PORT" => {
				let port = value.parse::<u16>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::InPort(port))
			}
			"IN-TYPE" => {
				let in_type = match value.to_uppercase().as_str() {
					"SOCKS" => InboundType::Socks,
					"HTTP" => InboundType::Http,
					"SOCKS/HTTP" => InboundType::SocksOrHttp,
					_ => return Err(RuleParseError::InvalidInboundType(value.to_string())),
				};
				Ok(RuleType::InType(in_type))
			}
			"IN-USER" => Ok(RuleType::InUser(value.to_string())),
			"IN-NAME" => Ok(RuleType::InName(value.to_string())),

			// Process rules
			"PROCESS-PATH" => Ok(RuleType::ProcessPath(value.to_string())),
			"PROCESS-PATH-REGEX" => {
				let regex = Regex::new(value)
					.map_err(|e| RuleParseError::InvalidRegex(e.to_string()))?;
				Ok(RuleType::ProcessPathRegex(regex))
			}
			"PROCESS-NAME" => Ok(RuleType::ProcessName(value.to_string())),
			"PROCESS-NAME-REGEX" => {
				let regex = Regex::new(value)
					.map_err(|e| RuleParseError::InvalidRegex(e.to_string()))?;
				Ok(RuleType::ProcessNameRegex(regex))
			}
			"UID" => {
				let uid = value.parse::<u32>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::Uid(uid))
			}

			// Network rules
			"NETWORK" => {
				let net_type = match value.to_lowercase().as_str() {
					"tcp" => NetworkType::Tcp,
					"udp" => NetworkType::Udp,
					_ => return Err(RuleParseError::InvalidNetworkType(value.to_string())),
				};
				Ok(RuleType::Network(net_type))
			}
			"DSCP" => {
				let dscp = value.parse::<u8>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::Dscp(dscp))
			}

			// Advanced rules
			"RULE-SET" => Ok(RuleType::RuleSet(value.to_string())),
			"AND" => {
				let sub_rules = Self::parse_compound_rules(value)?;
				Ok(RuleType::And(sub_rules))
			}
			"OR" => {
				let sub_rules = Self::parse_compound_rules(value)?;
				Ok(RuleType::Or(sub_rules))
			}
			"NOT" => {
				let sub_rules = Self::parse_compound_rules(value)?;
				if sub_rules.len() != 1 {
					return Err(RuleParseError::InvalidFormat(
						"NOT rule must contain exactly one sub-rule".to_string(),
					));
				}
				Ok(RuleType::Not(Box::new(sub_rules.into_iter().next().unwrap())))
			}
			"SUB-RULE" => {
				// SUB-RULE format: (NETWORK,tcp),sub-rule
				// The value contains the condition and sub-rule name
				let sub_rules = Self::parse_compound_rules(value)?;
				if sub_rules.is_empty() {
					return Err(RuleParseError::InvalidFormat(
						"SUB-RULE must contain a condition".to_string(),
					));
				}
				// For now, we'll store the first rule; actual implementation may vary
				Ok(RuleType::SubRule(
					Box::new(sub_rules.into_iter().next().unwrap()),
					String::new(),
				))
			}

			_ => Err(RuleParseError::UnknownRuleType(type_str.to_string())),
		}
	}

	/// Parse compound rules like: ((DOMAIN,baidu.com),(NETWORK,UDP))
	fn parse_compound_rules(value: &str) -> Result<Vec<Rule>, RuleParseError> {
		let value = value.trim();
		
		// Remove outer parentheses if present
		let content = if value.starts_with('(') && value.ends_with(')') {
			&value[1..value.len() - 1]
		} else {
			return Err(RuleParseError::InvalidFormat(
				"Compound rule must be wrapped in parentheses".to_string(),
			));
		};

		let mut rules = Vec::new();
		let mut depth = 0;
		let mut start = 0;
		
		for (i, ch) in content.char_indices() {
			match ch {
				'(' => depth += 1,
				')' => depth -= 1,
				',' if depth == 0 => {
					let rule_str = &content[start..i].trim();
					if !rule_str.is_empty() {
						// Parse inner rule: (DOMAIN,baidu.com)
						let inner = rule_str.strip_prefix('(')
							.and_then(|s| s.strip_suffix(')'))
							.unwrap_or(rule_str);
						
						// For compound rules, we need to add a dummy target
						let rule_with_target = format!("{},TEMP", inner);
						let mut rule = Rule::parse(&rule_with_target)?;
						rule.target = String::new(); // Clear dummy target
						rules.push(rule);
					}
					start = i + 1;
				}
				_ => {}
			}
		}

		// Handle the last rule
		let rule_str = content[start..].trim();
		if !rule_str.is_empty() {
			let inner = rule_str.strip_prefix('(')
				.and_then(|s| s.strip_suffix(')'))
				.unwrap_or(rule_str);
			
			let rule_with_target = format!("{},TEMP", inner);
			let mut rule = Rule::parse(&rule_with_target)?;
			rule.target = String::new();
			rules.push(rule);
		}

		Ok(rules)
	}

	/// Parse multiple rules from a string (one rule per line)
	pub fn parse_rules(content: &str) -> Vec<Result<Rule, RuleParseError>> {
		content
			.lines()
			.filter(|line| {
				let trimmed = line.trim();
				!trimmed.is_empty() && !trimmed.starts_with('#')
			})
			.map(|line| Rule::parse(line))
			.collect()
	}
}

// ============================================================================
// Matching Logic
// ============================================================================

/// Context for rule matching
pub struct MatchContext<'a> {
	// Connection info
	pub src_ip:          Option<IpAddr>,
	pub dst_ip:          Option<IpAddr>,
	pub src_port:        Option<u16>,
	pub dst_port:        Option<u16>,
	pub domain:          Option<&'a str>,
	
	// Network info
	pub network:         Option<NetworkType>,
	pub dscp:            Option<u8>,
	
	// Inbound info
	pub inbound_port:    Option<u16>,
	pub inbound_type:    Option<InboundType>,
	pub inbound_user:    Option<&'a str>,
	pub inbound_name:    Option<&'a str>,
	
	// Process info
	pub process_path:    Option<&'a str>,
	pub process_name:    Option<&'a str>,
	pub uid:             Option<u32>,
	
	// GeoIP/ASN lookup functions (provided by caller)
	pub geoip_lookup:    Option<&'a dyn Fn(&str, IpAddr) -> bool>,
	pub asn_lookup:      Option<&'a dyn Fn(u32, IpAddr) -> bool>,
	pub geosite_lookup:  Option<&'a dyn Fn(&str, &str) -> bool>,
}

impl<'a> std::fmt::Debug for MatchContext<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("MatchContext")
			.field("src_ip", &self.src_ip)
			.field("dst_ip", &self.dst_ip)
			.field("src_port", &self.src_port)
			.field("dst_port", &self.dst_port)
			.field("domain", &self.domain)
			.field("network", &self.network)
			.field("dscp", &self.dscp)
			.field("inbound_port", &self.inbound_port)
			.field("inbound_type", &self.inbound_type)
			.field("inbound_user", &self.inbound_user)
			.field("inbound_name", &self.inbound_name)
			.field("process_path", &self.process_path)
			.field("process_name", &self.process_name)
			.field("uid", &self.uid)
			.field("geoip_lookup", &self.geoip_lookup.is_some())
			.field("asn_lookup", &self.asn_lookup.is_some())
			.field("geosite_lookup", &self.geosite_lookup.is_some())
			.finish()
	}
}

impl<'a> Clone for MatchContext<'a> {
	fn clone(&self) -> Self {
		Self {
			src_ip:         self.src_ip,
			dst_ip:         self.dst_ip,
			src_port:       self.src_port,
			dst_port:       self.dst_port,
			domain:         self.domain,
			network:        self.network,
			dscp:           self.dscp,
			inbound_port:   self.inbound_port,
			inbound_type:   self.inbound_type,
			inbound_user:   self.inbound_user,
			inbound_name:   self.inbound_name,
			process_path:   self.process_path,
			process_name:   self.process_name,
			uid:            self.uid,
			geoip_lookup:   self.geoip_lookup,
			asn_lookup:     self.asn_lookup,
			geosite_lookup: self.geosite_lookup,
		}
	}
}

impl Rule {
	/// Check if this rule matches the given context
	pub fn matches(&self, ctx: &MatchContext) -> bool {
		match &self.rule_type {
			RuleType::Domain(domain) => {
				ctx.domain.map_or(false, |d| d.eq_ignore_ascii_case(domain))
			}
			
			RuleType::DomainSuffix(suffix) => {
				ctx.domain.map_or(false, |d| {
					d.eq_ignore_ascii_case(suffix) || 
					d.to_lowercase().ends_with(&format!(".{}", suffix.to_lowercase()))
				})
			}
			
			RuleType::DomainKeyword(keyword) => {
				ctx.domain.map_or(false, |d| d.to_lowercase().contains(&keyword.to_lowercase()))
			}
			
			RuleType::DomainWildcard(pattern) => {
				ctx.domain.map_or(false, |d| {
					Self::wildcard_match(pattern, d)
				})
			}
			
			RuleType::DomainRegex(regex) => {
				ctx.domain.map_or(false, |d| regex.is_match(d))
			}
			
			RuleType::GeoSite(site) => {
				ctx.domain.and_then(|d| {
					ctx.geosite_lookup.map(|f| f(site, d))
				}).unwrap_or(false)
			}
			
			RuleType::IpCidr(net) => {
				ctx.dst_ip.map_or(false, |ip| net.contains(&ip))
			}
			
			RuleType::IpCidr6(net) => {
				ctx.dst_ip.and_then(|ip| match ip {
					IpAddr::V6(v6) => Some(net.contains(&v6)),
					_ => None,
				}).unwrap_or(false)
			}
			
			RuleType::IpSuffix(net) => {
				// IP-SUFFIX matches if the IP is in the network
				ctx.dst_ip.map_or(false, |ip| net.contains(&ip))
			}
			
			RuleType::IpAsn(asn) => {
				ctx.dst_ip.and_then(|ip| {
					ctx.asn_lookup.map(|f| f(*asn, ip))
				}).unwrap_or(false)
			}
			
			RuleType::GeoIp(country) => {
				ctx.dst_ip.and_then(|ip| {
					ctx.geoip_lookup.map(|f| f(country, ip))
				}).unwrap_or(false)
			}
			
			RuleType::SrcGeoIp(country) => {
				ctx.src_ip.and_then(|ip| {
					ctx.geoip_lookup.map(|f| f(country, ip))
				}).unwrap_or(false)
			}
			
			RuleType::SrcIpAsn(asn) => {
				ctx.src_ip.and_then(|ip| {
					ctx.asn_lookup.map(|f| f(*asn, ip))
				}).unwrap_or(false)
			}
			
			RuleType::SrcIpCidr(net) => {
				ctx.src_ip.map_or(false, |ip| net.contains(&ip))
			}
			
			RuleType::SrcIpSuffix(net) => {
				ctx.src_ip.map_or(false, |ip| net.contains(&ip))
			}
			
			RuleType::DstPort(port) => {
				ctx.dst_port.map_or(false, |p| p == *port)
			}
			
			RuleType::SrcPort(port) => {
				ctx.src_port.map_or(false, |p| p == *port)
			}
			
			RuleType::InPort(port) => {
				ctx.inbound_port.map_or(false, |p| p == *port)
			}
			
			RuleType::InType(in_type) => {
				ctx.inbound_type.map_or(false, |t| {
					match in_type {
						InboundType::SocksOrHttp => {
							t == InboundType::Socks || t == InboundType::Http
						}
						_ => t == *in_type,
					}
				})
			}
			
			RuleType::InUser(user) => {
				ctx.inbound_user.map_or(false, |u| u == user)
			}
			
			RuleType::InName(name) => {
				ctx.inbound_name.map_or(false, |n| n == name)
			}
			
			RuleType::ProcessPath(path) => {
				ctx.process_path.map_or(false, |p| p == path)
			}
			
			RuleType::ProcessPathRegex(regex) => {
				ctx.process_path.map_or(false, |p| regex.is_match(p))
			}
			
			RuleType::ProcessName(name) => {
				ctx.process_name.map_or(false, |n| n == name)
			}
			
			RuleType::ProcessNameRegex(regex) => {
				ctx.process_name.map_or(false, |n| regex.is_match(n))
			}
			
			RuleType::Uid(uid) => {
				ctx.uid.map_or(false, |u| u == *uid)
			}
			
			RuleType::Network(net_type) => {
				ctx.network.map_or(false, |n| n == *net_type)
			}
			
			RuleType::Dscp(dscp) => {
				ctx.dscp.map_or(false, |d| d == *dscp)
			}
			
			RuleType::RuleSet(_name) => {
				// RuleSet matching would require loading external rule sets
				// This is a placeholder
				false
			}
			
			RuleType::And(rules) => {
				rules.iter().all(|rule| rule.matches(ctx))
			}
			
			RuleType::Or(rules) => {
				rules.iter().any(|rule| rule.matches(ctx))
			}
			
			RuleType::Not(rule) => {
				!rule.matches(ctx)
			}
			
			RuleType::SubRule(rule, _name) => {
				// SubRule would require loading named sub-rules
				// For now, just match the contained rule
				rule.matches(ctx)
			}
			
			RuleType::Match => {
				// MATCH always matches
				true
			}
		}
	}

	/// Simple wildcard matching (supports * and ?)
	fn wildcard_match(pattern: &str, text: &str) -> bool {
		let pattern = pattern.to_lowercase();
		let text = text.to_lowercase();
		
		// Convert wildcard pattern to regex
		let mut regex_pattern = String::from("^");
		for ch in pattern.chars() {
			match ch {
				'*' => regex_pattern.push_str(".*"),
				'?' => regex_pattern.push('.'),
				c if c.is_ascii_punctuation() && c != '*' && c != '?' => {
					regex_pattern.push('\\');
					regex_pattern.push(c);
				}
				c => regex_pattern.push(c),
			}
		}
		regex_pattern.push('$');
		
		Regex::new(&regex_pattern)
			.map(|re| re.is_match(&text))
			.unwrap_or(false)
	}
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone, PartialEq, Display)]
pub enum RuleParseError {
	#[display("Empty line or comment")]
	EmptyOrComment,
	
	#[display("Invalid format: {_0}")]
	InvalidFormat(String),
	
	#[display("Unknown rule type: {_0}")]
	UnknownRuleType(String),
	
	#[display("Invalid regex: {_0}")]
	InvalidRegex(String),
	
	#[display("Invalid IP/CIDR: {_0}")]
	InvalidIpCidr(String),
	
	#[display("Invalid number: {_0}")]
	InvalidNumber(String),
	
	#[display("Invalid inbound type: {_0}")]
	InvalidInboundType(String),
	
	#[display("Invalid network type: {_0}")]
	InvalidNetworkType(String),
}

impl std::error::Error for RuleParseError {}

// ============================================================================
// Display Implementation
// ============================================================================

impl std::fmt::Display for Rule {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.rule_type)?;
		if !self.target.is_empty() {
			write!(f, ",{}", self.target)?;
		}
		for opt in &self.options {
			write!(f, ",{}", opt)?;
		}
		Ok(())
	}
}

impl std::fmt::Display for RuleType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			RuleType::Domain(v) => write!(f, "DOMAIN,{}", v),
			RuleType::DomainSuffix(v) => write!(f, "DOMAIN-SUFFIX,{}", v),
			RuleType::DomainKeyword(v) => write!(f, "DOMAIN-KEYWORD,{}", v),
			RuleType::DomainWildcard(v) => write!(f, "DOMAIN-WILDCARD,{}", v),
			RuleType::DomainRegex(v) => write!(f, "DOMAIN-REGEX,{}", v),
			RuleType::GeoSite(v) => write!(f, "GEOSITE,{}", v),
			RuleType::IpCidr(v) => write!(f, "IP-CIDR,{}", v),
			RuleType::IpCidr6(v) => write!(f, "IP-CIDR6,{}", v),
			RuleType::IpSuffix(v) => write!(f, "IP-SUFFIX,{}", v),
			RuleType::IpAsn(v) => write!(f, "IP-ASN,{}", v),
			RuleType::GeoIp(v) => write!(f, "GEOIP,{}", v),
			RuleType::SrcGeoIp(v) => write!(f, "SRC-GEOIP,{}", v),
			RuleType::SrcIpAsn(v) => write!(f, "SRC-IP-ASN,{}", v),
			RuleType::SrcIpCidr(v) => write!(f, "SRC-IP-CIDR,{}", v),
			RuleType::SrcIpSuffix(v) => write!(f, "SRC-IP-SUFFIX,{}", v),
			RuleType::DstPort(v) => write!(f, "DST-PORT,{}", v),
			RuleType::SrcPort(v) => write!(f, "SRC-PORT,{}", v),
			RuleType::InPort(v) => write!(f, "IN-PORT,{}", v),
			RuleType::InType(v) => write!(f, "IN-TYPE,{}", v),
			RuleType::InUser(v) => write!(f, "IN-USER,{}", v),
			RuleType::InName(v) => write!(f, "IN-NAME,{}", v),
			RuleType::ProcessPath(v) => write!(f, "PROCESS-PATH,{}", v),
			RuleType::ProcessPathRegex(v) => write!(f, "PROCESS-PATH-REGEX,{}", v),
			RuleType::ProcessName(v) => write!(f, "PROCESS-NAME,{}", v),
			RuleType::ProcessNameRegex(v) => write!(f, "PROCESS-NAME-REGEX,{}", v),
			RuleType::Uid(v) => write!(f, "UID,{}", v),
			RuleType::Network(v) => write!(f, "NETWORK,{}", v),
			RuleType::Dscp(v) => write!(f, "DSCP,{}", v),
			RuleType::RuleSet(v) => write!(f, "RULE-SET,{}", v),
			RuleType::And(rules) => {
				write!(f, "AND,(")?;
				for (i, rule) in rules.iter().enumerate() {
					if i > 0 {
						write!(f, ",")?;
					}
					write!(f, "({})", rule.rule_type)?;
				}
				write!(f, ")")
			}
			RuleType::Or(rules) => {
				write!(f, "OR,(")?;
				for (i, rule) in rules.iter().enumerate() {
					if i > 0 {
						write!(f, ",")?;
					}
					write!(f, "({})", rule.rule_type)?;
				}
				write!(f, ")")
			}
			RuleType::Not(rule) => write!(f, "NOT,(({}))", rule.rule_type),
			RuleType::SubRule(rule, name) => write!(f, "SUB-RULE,(({}))),{}", rule.rule_type, name),
			RuleType::Match => write!(f, "MATCH"),
		}
	}
}

// ============================================================================
// Regex Serialization Helper
// ============================================================================

mod serde_regex {
	use regex::Regex;
	use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

	pub fn serialize<S>(regex: &Regex, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		regex.as_str().serialize(serializer)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Regex, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		Regex::new(&s).map_err(de::Error::custom)
	}
}

impl<'a> Default for MatchContext<'a> {
	fn default() -> Self {
		Self {
			src_ip:         None,
			dst_ip:         None,
			src_port:       None,
			dst_port:       None,
			domain:         None,
			network:        None,
			dscp:           None,
			inbound_port:   None,
			inbound_type:   None,
			inbound_user:   None,
			inbound_name:   None,
			process_path:   None,
			process_name:   None,
			uid:            None,
			geoip_lookup:   None,
			asn_lookup:     None,
			geosite_lookup: None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_domain_rules() {
		let rule = Rule::parse("DOMAIN,ad.com,REJECT").unwrap();
		assert_eq!(rule.target, "REJECT");
		assert!(matches!(rule.rule_type, RuleType::Domain(_)));

		let rule = Rule::parse("DOMAIN-SUFFIX,google.com,auto").unwrap();
		assert_eq!(rule.target, "auto");
		assert!(matches!(rule.rule_type, RuleType::DomainSuffix(_)));

		let rule = Rule::parse("DOMAIN-KEYWORD,google,auto").unwrap();
		assert!(matches!(rule.rule_type, RuleType::DomainKeyword(_)));
	}

	#[test]
	fn test_parse_ip_rules() {
		let rule = Rule::parse("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve").unwrap();
		assert_eq!(rule.target, "DIRECT");
		assert_eq!(rule.options, vec!["no-resolve"]);
		assert!(matches!(rule.rule_type, RuleType::IpCidr(_)));

		let rule = Rule::parse("IP-CIDR6,2620:0:2d0:200::7/32,auto").unwrap();
		assert!(matches!(rule.rule_type, RuleType::IpCidr6(_)));
	}

	#[test]
	fn test_parse_port_rules() {
		let rule = Rule::parse("DST-PORT,80,DIRECT").unwrap();
		assert!(matches!(rule.rule_type, RuleType::DstPort(80)));

		let rule = Rule::parse("SRC-PORT,7777,DIRECT").unwrap();
		assert!(matches!(rule.rule_type, RuleType::SrcPort(7777)));
	}

	#[test]
	fn test_parse_match_rule() {
		let rule = Rule::parse("MATCH,auto").unwrap();
		assert_eq!(rule.target, "auto");
		assert!(matches!(rule.rule_type, RuleType::Match));
	}

	#[test]
	fn test_domain_matching() {
		let rule = Rule::parse("DOMAIN,example.com,PROXY").unwrap();
		let ctx = MatchContext {
			domain: Some("example.com"),
			..Default::default()
		};
		assert!(rule.matches(&ctx));

		let ctx = MatchContext {
			domain: Some("other.com"),
			..Default::default()
		};
		assert!(!rule.matches(&ctx));
	}

	#[test]
	fn test_domain_suffix_matching() {
		let rule = Rule::parse("DOMAIN-SUFFIX,google.com,PROXY").unwrap();
		
		let ctx = MatchContext {
			domain: Some("www.google.com"),
			..Default::default()
		};
		assert!(rule.matches(&ctx));

		let ctx = MatchContext {
			domain: Some("google.com"),
			..Default::default()
		};
		assert!(rule.matches(&ctx));

		let ctx = MatchContext {
			domain: Some("google.co.uk"),
			..Default::default()
		};
		assert!(!rule.matches(&ctx));
	}
}
