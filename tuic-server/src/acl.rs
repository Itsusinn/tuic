use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    str::FromStr,
};

use serde::Serialize;

/// Represents a single ACL rule with parsed components
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AclRule {
    /// The outbound name to use for this rule (e.g., "allow", "reject",
    /// "custom_outbound")
    pub outbound: String,
    /// The target address (IP, CIDR, domain, wildcard domain)
    pub addr: AclAddress,
    /// Optional port specifications
    pub ports: Option<AclPorts>,
    /// Optional hijack IP address for redirection
    pub hijack: Option<String>,
}

/// Represents different types of addresses in ACL rules
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum AclAddress {
    /// Single IP address (IPv4 or IPv6)
    Ip(String),
    /// CIDR notation (e.g., "10.6.0.0/16")
    Cidr(String),
    /// Domain name (e.g., "google.com")
    Domain(String),
    /// Wildcard domain (e.g., "*.google.com")
    WildcardDomain(String),
    /// Special localhost identifier
    Localhost,
    /// Match any address (when address is omitted)
    Any,
}

/// Represents port specifications with optional protocols
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AclPorts {
    /// List of port ranges or single ports with optional protocols
    pub entries: Vec<AclPortEntry>,
}

impl AclRule {
    /// Returns `true` if the supplied socket address, port and transport
    /// protocol satisfy this rule.
    ///
    /// * `addr` – remote IP address of the request.
    /// * `port` – destination port the client wants to reach.
    /// * `is_tcp` – `true` for TCP, `false` for UDP.
    pub(crate) fn matching(&self, addr: SocketAddr, port: u16, is_tcp: bool) -> bool {
        // ---------- address matching ----------
        let addr_match = match &self.addr {
            // Exact IP address
            AclAddress::Ip(ip_str) => {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    addr.ip() == ip
                } else {
                    false
                }
            }

            // CIDR block
            AclAddress::Cidr(cidr_str) => {
                if let Ok(net) = cidr_str.parse::<ip_network::IpNetwork>() {
                    net.contains(addr.ip())
                } else {
                    false
                }
            }

            // Exact domain name – resolve it and compare the resulting IPs
            AclAddress::Domain(domain) => {
                // Special‑case localhost to be deterministic and platform‑independent.
                if domain.eq_ignore_ascii_case("localhost") {
                    match addr.ip() {
                        IpAddr::V4(v4) => v4.is_loopback(),
                        IpAddr::V6(v6) => v6.is_loopback(),
                    }
                } else {
                    // Resolve the domain (port is irrelevant, we just need the IPs)
                    // Using `0` as a dummy port – `ToSocketAddrs` ignores it for name resolution.
                    let resolver = (domain.as_str(), 0);
                    match resolver.to_socket_addrs() {
                        Ok(iter) => iter.map(|sa| sa.ip()).any(|ip| ip == addr.ip()),
                        Err(_) => false,
                    }
                }
            }

            // Wild‑card domain (e.g. "*.example.com" or "suffix:example.com")
            AclAddress::WildcardDomain(pattern) => {
                // Strip leading "*." if present; also support the `suffix:` syntax.
                let stripped = if let Some(rest) = pattern.strip_prefix("*.") {
                    rest
                } else if let Some(rest) = pattern.strip_prefix("suffix:") {
                    rest
                } else {
                    // Not a recognised wildcard – treat as a literal domain.
                    pattern.as_str()
                };

                // Special‑case localhost to be deterministic and platform‑independent.
                if stripped.eq_ignore_ascii_case("localhost") {
                    match addr.ip() {
                        IpAddr::V4(v4) => v4.is_loopback(),
                        IpAddr::V6(v6) => v6.is_loopback(),
                    }
                } else {
                    // Resolve the base domain and compare IPs.
                    let resolver = (stripped, 0);
                    match resolver.to_socket_addrs() {
                        Ok(iter) => iter.map(|sa| sa.ip()).any(|ip| ip == addr.ip()),
                        Err(_) => false,
                    }
                }
            }

            // Loop‑back address – matches both IPv4 and IPv6 loop‑back.
            AclAddress::Localhost => {
                match addr.ip() {
                    // IPv4 loopback (127.0.0.0/8, but we only need the exact address)
                    IpAddr::V4(v4) if v4.is_loopback() => true,

                    // IPv6 loopback (::1)
                    IpAddr::V6(v6) if v6.is_loopback() => true,

                    // Anything else does not match the “localhost” shortcut
                    _ => false,
                }
            }

            // Matches any address.
            AclAddress::Any => true,
        };

        if !addr_match {
            return false;
        }

        // ---------- port & protocol matching ----------
        // If no port filter is defined, the rule matches any port.
        if let Some(ports) = &self.ports {
            // Build a set of (port, protocol) pairs that satisfy the rule.
            // `protocol == None` means “either”.
            let mut allowed = HashSet::new();

            for entry in &ports.entries {
                // Apply protocol filter if present.
                let proto_ok = match entry.protocol {
                    Some(AclProtocol::Tcp) => is_tcp,
                    Some(AclProtocol::Udp) => !is_tcp,
                    None => true,
                };

                if !proto_ok {
                    continue;
                }

                match &entry.port_spec {
                    AclPortSpec::Single(p) => {
                        allowed.insert((*p, entry.protocol.clone()));
                    }
                    AclPortSpec::Range(start, end) => {
                        for p in *start..=*end {
                            allowed.insert((p, entry.protocol.clone()));
                        }
                    }
                }
            }

            // If the rule defined ports but none survived the protocol filter,
            // the request must be rejected.
            if allowed.is_empty() {
                return false;
            }

            // Finally, check that the requested port/protocol pair is allowed.
            allowed.iter().any(|&(p, _)| p == port)
        } else {
            // No port restrictions → always true.
            true
        }
    }
}
/// A single port entry with optional protocol specification
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AclPortEntry {
    /// Protocol (TCP, UDP, or both if None)
    pub protocol: Option<AclProtocol>,
    /// Port specification (single port or range)
    pub port_spec: AclPortSpec,
}

/// Protocol specification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum AclProtocol {
    Tcp,
    Udp,
}

/// Port specification (single port or range)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum AclPortSpec {
    /// Single port
    Single(u16),
    /// Port range (inclusive)
    Range(u16, u16),
}

impl FromStr for AclRule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_acl_rule(s.trim())
    }
}

impl fmt::Display for AclRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.outbound, self.addr)?;
        if let Some(ports) = &self.ports {
            write!(f, " {ports}")?;
        }
        if let Some(hijack) = &self.hijack {
            write!(f, " {hijack}")?;
        }
        Ok(())
    }
}

impl fmt::Display for AclAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclAddress::Ip(ip) => write!(f, "{ip}"),
            AclAddress::Cidr(cidr) => write!(f, "{cidr}"),
            AclAddress::Domain(domain) => write!(f, "{domain}"),
            AclAddress::WildcardDomain(domain) => write!(f, "{domain}"),
            AclAddress::Localhost => write!(f, "localhost"),
            AclAddress::Any => write!(f, "*"),
        }
    }
}

impl fmt::Display for AclPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries: Vec<String> = self.entries.iter().map(|e| e.to_string()).collect();
        write!(f, "{}", entries.join(","))
    }
}

impl fmt::Display for AclPortEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(protocol) = &self.protocol {
            write!(f, "{}/{}", protocol, self.port_spec)
        } else {
            write!(f, "{}", self.port_spec)
        }
    }
}

impl fmt::Display for AclProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclProtocol::Tcp => write!(f, "tcp"),
            AclProtocol::Udp => write!(f, "udp"),
        }
    }
}

impl fmt::Display for AclPortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclPortSpec::Single(port) => write!(f, "{port}"),
            AclPortSpec::Range(start, end) => write!(f, "{start}-{end}"),
        }
    }
}

/// Parse a single ACL rule from string format
pub(crate) fn parse_acl_rule(rule: &str) -> Result<AclRule, String> {
    // Skip comments and empty lines
    if rule.starts_with('#') || rule.is_empty() {
        return Err("Comment or empty line".to_string());
    }

    let parts: Vec<&str> = rule.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty rule".to_string());
    }

    let outbound = parts[0].to_string();

    // Parse address (second part, optional)
    let addr = if parts.len() > 1 {
        parse_acl_address(parts[1])?
    } else {
        AclAddress::Any
    };

    // Parse ports (third part, optional)
    // A solitary "*" after the address means “any port”, which we model by
    // leaving `ports` as `None`.  All other strings are forwarded to the
    // existing port parser.
    let ports = if parts.len() > 2 {
        if parts[2] == "*" {
            None
        } else {
            Some(parse_acl_ports(parts[2])?)
        }
    } else {
        None
    };

    // Parse hijack address (fourth part, optional)
    let hijack = if parts.len() > 3 {
        Some(parts[3].to_string())
    } else {
        None
    };

    Ok(AclRule {
        outbound,
        addr,
        ports,
        hijack,
    })
}

/// Parse address component of ACL rule
pub(crate) fn parse_acl_address(addr: &str) -> Result<AclAddress, String> {
    if addr == "localhost" || addr == "suffix:localhost" {
        Ok(AclAddress::Localhost)
    } else if addr == "*" {
        Ok(AclAddress::Any)
    } else if addr.starts_with("*.") || addr.starts_with("suffix:") {
        // Treat both leading "*." and explicit "suffix:" prefix as wildcard domain
        // patterns
        Ok(AclAddress::WildcardDomain(addr.to_string()))
    } else if addr.contains('/') {
        // CIDR notation
        Ok(AclAddress::Cidr(addr.to_string()))
    } else if addr.parse::<std::net::Ipv4Addr>().is_ok()
        || addr.parse::<std::net::Ipv6Addr>().is_ok()
    {
        Ok(AclAddress::Ip(addr.to_string()))
    } else {
        // Assume it's a domain name
        Ok(AclAddress::Domain(addr.to_string()))
    }
}

impl FromStr for AclAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_acl_address(s.trim())
    }
}

/// Parse port specification
pub(crate) fn parse_acl_ports(ports_str: &str) -> Result<AclPorts, String> {
    let entries: Result<Vec<_>, _> = ports_str
        .split(',')
        .map(|part| parse_acl_port_entry(part.trim()))
        .collect();

    Ok(AclPorts { entries: entries? })
}

impl FromStr for AclPorts {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_acl_ports(s.trim())
    }
}

/// Parse a single port entry (e.g., "80", "tcp/443", "1000-2000")
pub(crate) fn parse_acl_port_entry(entry: &str) -> Result<AclPortEntry, String> {
    // Check for protocol specification
    if let Some((protocol_str, port_str)) = entry.split_once('/') {
        let protocol = match protocol_str.to_lowercase().as_str() {
            "tcp" => AclProtocol::Tcp,
            "udp" => AclProtocol::Udp,
            _ => return Err(format!("Invalid protocol: {protocol_str}")),
        };
        let port_spec = parse_port_spec(port_str)?;
        Ok(AclPortEntry {
            protocol: Some(protocol),
            port_spec,
        })
    } else {
        // No protocol specified, matches both TCP and UDP
        let port_spec = parse_port_spec(entry)?;
        Ok(AclPortEntry {
            protocol: None,
            port_spec,
        })
    }
}

/// Parse port specification (single port or range)
fn parse_port_spec(port_str: &str) -> Result<AclPortSpec, String> {
    if let Some((start_str, end_str)) = port_str.split_once('-') {
        // Port range
        let start = start_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid start port: {start_str}"))?;
        let end = end_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid end port: {end_str}"))?;

        if start > end {
            return Err(format!("Invalid port range: {start} > {end}"));
        }

        Ok(AclPortSpec::Range(start, end))
    } else {
        // Single port
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port: {port_str}"))?;
        Ok(AclPortSpec::Single(port))
    }
}

#[cfg(test)]
mod tests {
    //! Tests for `AclRule::matching`.
    //! They cover all address flavours (IP, CIDR, domain, wildcard‑domain,
    //! localhost, any) and the port / protocol filtering logic.
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    /// Helper that builds a `SocketAddr` from an IPv4 string and a port.
    fn v4(addr: &str, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(addr.parse::<Ipv4Addr>().unwrap()), port)
    }

    /// Helper that builds a `SocketAddr` from an IPv6 string and a port.
    fn v6(addr: &str, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(addr.parse::<Ipv6Addr>().unwrap()), port)
    }

    #[test]
    fn ip_exact_match() {
        // rule accepts only 203.0.113.7
        let rule = AclRule {
            addr: AclAddress::Ip("203.0.113.7".into()),
            ports: None,
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        assert!(rule.matching(v4("203.0.113.7", 12345), 12345, true));
        assert!(!rule.matching(v4("203.0.113.8", 12345), 12345, true));
        // IPv6 must not match an IPv4 rule
        assert!(!rule.matching(v6("2001:db8::1", 12345), 12345, true));
    }

    #[test]
    fn cidr_match() {
        // 10.0.0.0/8
        let rule = AclRule {
            addr: AclAddress::Cidr("10.0.0.0/8".into()),
            ports: None,
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        assert!(rule.matching(v4("10.1.2.3", 0), 0, false));
        assert!(!rule.matching(v4("192.0.2.1", 0), 0, false));
        // IPv6 never matches an IPv4 CIDR
        assert!(!rule.matching(v6("::1", 0), 0, false));
    }

    #[test]
    fn domain_match_localhost() {
        // “localhost” resolves to 127.0.0.1 and ::1 on every platform
        let rule = AclRule {
            addr: AclAddress::Domain("localhost".into()),
            ports: None,
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        // IPv4 localhost
        assert!(rule.matching(v4("127.0.0.1", 0), 0, true));
        // IPv6 localhost
        assert!(rule.matching(v6("::1", 0), 0, true));
        // Some other address must not match
        assert!(!rule.matching(v4("8.8.8.8", 0), 0, true));
    }

    #[test]
    fn wildcard_domain_match_suffix_localhost() {
        // The implementation treats a leading “suffix:” as a wildcard.
        // It will resolve the part after the prefix (here “localhost”).
        let rule = AclRule {
            addr: AclAddress::WildcardDomain("suffix:localhost".into()),
            ports: None,
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        assert!(rule.matching(v4("127.0.0.1", 0), 0, true));
        assert!(rule.matching(v6("::1", 0), 0, true));
        // a non‑matching host
        assert!(!rule.matching(v4("8.8.8.8", 0), 0, true));
    }

    #[test]
    fn localhost_match() {
        // Explicit localhost shortcut (both IPv4 and IPv6)
        let rule = AclRule {
            addr: AclAddress::Localhost,
            ports: None,
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        assert!(rule.matching(v4("127.0.0.1", 0), 0, true));
        assert!(rule.matching(v6("::1", 0), 0, true));
        assert!(!rule.matching(v4("192.0.2.1", 0), 0, true));
    }

    #[test]
    fn any_match() {
        // “any” matches everything regardless of address.
        let rule = AclRule {
            addr: AclAddress::Any,
            ports: None,
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        assert!(rule.matching(v4("203.0.113.1", 0), 0, true));
        assert!(rule.matching(v6("2001:db8::42", 0), 0, true));
    }

    #[test]
    fn ports_none_matches_everything() {
        // No ports defined → every port / protocol should be accepted.
        let rule = AclRule {
            addr: AclAddress::Any,
            ports: None,
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        for port in [0u16, 22, 80, 443, 65535] {
            assert!(rule.matching(v4("1.2.3.4", port), port, true));
            assert!(rule.matching(v4("1.2.3.4", port), port, false));
        }
    }

    #[test]
    fn single_port_without_protocol() {
        // Accept only port 8080, protocol‑agnostic.
        let ports = AclPorts {
            entries: vec![AclPortEntry {
                protocol: None,
                port_spec: AclPortSpec::Single(8080),
            }],
        };

        let rule = AclRule {
            addr: AclAddress::Any,
            ports: Some(ports),
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        assert!(rule.matching(v4("10.0.0.1", 8080), 8080, true));
        assert!(rule.matching(v4("10.0.0.1", 8080), 8080, false));
        // Anything else must be rejected.
        assert!(!rule.matching(v4("10.0.0.1", 80), 80, true));
        assert!(!rule.matching(v4("10.0.0.1", 443), 443, false));
    }

    #[test]
    fn port_range_with_protocol() {
        // Allow TCP ports 1000‑1005, UDP ports 2000‑2002.
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
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        // TCP inside range → ok
        assert!(rule.matching(v4("8.8.8.8", 1003), 1003, true));
        // TCP outside range → reject
        assert!(!rule.matching(v4("8.8.8.8", 999), 999, true));

        // UDP inside range → ok
        assert!(rule.matching(v4("8.8.8.8", 2001), 2001, false));
        // UDP outside range → reject
        assert!(!rule.matching(v4("8.8.8.8", 1999), 1999, false));
    }

    #[test]
    fn address_and_port_combination() {
        // Only allow TCP 22 to 192.0.2.10, everything else is blocked.
        let ports = AclPorts {
            entries: vec![AclPortEntry {
                protocol: Some(AclProtocol::Tcp),
                port_spec: AclPortSpec::Single(22),
            }],
        };

        let rule = AclRule {
            addr: AclAddress::Ip("192.0.2.10".into()),
            ports: Some(ports),
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        // Matching address, matching port, matching protocol → true
        assert!(rule.matching(v4("192.0.2.10", 22), 22, true));

        // Wrong address
        assert!(!rule.matching(v4("192.0.2.11", 22), 22, true));

        // Right address, wrong port
        assert!(!rule.matching(v4("192.0.2.10", 23), 23, true));

        // Right address & port but UDP → rejected because protocol is TCP‑only
        assert!(!rule.matching(v4("192.0.2.10", 22), 22, false));
    }

    #[test]
    fn ports_defined_but_protocol_mismatch_results_in_rejection() {
        // Rule says “tcp/443”.  We ask for the same port but UDP → must be rejected.
        let ports = AclPorts {
            entries: vec![AclPortEntry {
                protocol: Some(AclProtocol::Tcp),
                port_spec: AclPortSpec::Single(443),
            }],
        };

        let rule = AclRule {
            addr: AclAddress::Any,
            ports: Some(ports),
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        // UDP request → false
        assert!(!rule.matching(v4("1.1.1.1", 443), 443, false));

        // TCP request → true
        assert!(rule.matching(v4("1.1.1.1", 443), 443, true));
    }

    #[test]
    fn empty_allowed_port_set_is_rejected() {
        // A rule with a port entry that is filtered out by protocol should reject
        // everything, even if the address matches.
        let ports = AclPorts {
            entries: vec![AclPortEntry {
                protocol: Some(AclProtocol::Tcp), // only TCP allowed
                port_spec: AclPortSpec::Single(9999),
            }],
        };

        let rule = AclRule {
            addr: AclAddress::Any,
            ports: Some(ports),
            outbound: "default".parse().unwrap(),
            hijack: None,
        };

        // UDP request – the only entry is filtered out → false
        assert!(!rule.matching(v4("8.8.8.8", 9999), 9999, false));
    }
}
