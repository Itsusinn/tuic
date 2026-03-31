use std::{
	fs,
	net::{IpAddr, SocketAddr},
	path::PathBuf,
};

use anyhow::Context;
use rustls::{RootCertStore, pki_types::CertificateDer};
use tokio::net;
// Re-export common types from tuic-core
pub use tuic_core::{CongestionControl, StackPrefer, UdpRelayMode};

use crate::error::Error;

pub fn load_certs(paths: Vec<PathBuf>, disable_native: bool) -> Result<RootCertStore, Error> {
	let mut certs = RootCertStore::empty();

	for cert_path in &paths {
		let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
		let cert_chain = if cert_path.extension().is_some_and(|x| x == "der") {
			vec![CertificateDer::from(cert_chain)]
		} else {
			rustls_pemfile::certs(&mut &*cert_chain)
				.collect::<Result<_, _>>()
				.context("invalid PEM-encoded certificate")?
		};
		certs.add_parsable_certificates(cert_chain);
	}

	if !disable_native {
		for cert in rustls_native_certs::load_native_certs().certs {
			_ = certs.add(cert);
		}
	}

	Ok(certs)
}

pub struct ServerAddr {
	domain:             String,
	port:               u16,
	ip:                 Option<IpAddr>,
	pub ipstack_prefer: StackPrefer,
	sni:                Option<String>,
}

impl ServerAddr {
	pub fn new(domain: String, port: u16, ip: Option<IpAddr>, ipstack_prefer: StackPrefer) -> Self {
		Self::with_sni(domain, port, ip, ipstack_prefer, None)
	}

	pub fn with_sni(domain: String, port: u16, ip: Option<IpAddr>, ipstack_prefer: StackPrefer, sni: Option<String>) -> Self {
		// Strip brackets from IPv6 addresses (e.g., "[::1]" -> "::1")
		// Brackets are URL notation and not valid in TLS server names
		let domain = if domain.starts_with('[') && domain.ends_with(']') {
			domain[1..domain.len() - 1].to_string()
		} else {
			domain
		};

		Self {
			domain,
			port,
			ip,
			ipstack_prefer,
			sni,
		}
	}

	pub fn server_name(&self) -> &str {
		self.sni.as_deref().unwrap_or(&self.domain)
	}

	pub async fn resolve(&self) -> Result<impl Iterator<Item = SocketAddr>, Error> {
		if let Some(ip) = self.ip {
			Ok(vec![SocketAddr::from((ip, self.port))].into_iter())
		} else {
			let mut addrs: Vec<SocketAddr> = net::lookup_host((self.domain.as_str(), self.port)).await?.collect();
			match self.ipstack_prefer {
				StackPrefer::V4only => {
					addrs.retain(|a| matches!(a, SocketAddr::V4(_)));
				}
				StackPrefer::V6only => {
					addrs.retain(|a| matches!(a, SocketAddr::V6(_)));
				}
				StackPrefer::V4first => {
					addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
				}
				StackPrefer::V6first => {
					addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
				}
			}
			Ok(addrs.into_iter())
		}
	}
}

#[cfg(test)]
mod tests {
	use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

	use super::*;

	#[test]
	fn test_server_addr_basic() {
		let addr = ServerAddr::new("example.com".to_string(), 443, None, StackPrefer::V4only);
		assert_eq!(addr.server_name(), "example.com");
	}

	#[test]
	fn test_server_addr_with_sni() {
		let addr = ServerAddr::with_sni(
			"example.com".to_string(),
			443,
			None,
			StackPrefer::V4only,
			Some("sni.example.com".to_string()),
		);
		assert_eq!(addr.server_name(), "sni.example.com");
	}

	#[test]
	fn test_server_addr_sni_none_fallback() {
		let addr = ServerAddr::with_sni("example.com".to_string(), 443, None, StackPrefer::V4only, None);
		assert_eq!(addr.server_name(), "example.com");
	}

	#[test]
	fn test_server_addr_ipv6_bracket_stripping() {
		let addr = ServerAddr::new("[::1]".to_string(), 443, None, StackPrefer::V6only);
		assert_eq!(addr.server_name(), "::1");
	}

	#[test]
	fn test_server_addr_ipv6_no_brackets() {
		let addr = ServerAddr::new("::1".to_string(), 443, None, StackPrefer::V6only);
		assert_eq!(addr.server_name(), "::1");
	}

	#[test]
	fn test_server_addr_with_sni_and_brackets() {
		let addr = ServerAddr::with_sni(
			"[::1]".to_string(),
			443,
			None,
			StackPrefer::V6only,
			Some("custom-sni.com".to_string()),
		);
		// SNI takes precedence over domain
		assert_eq!(addr.server_name(), "custom-sni.com");
		// But the domain itself should have brackets stripped
		assert_eq!(addr.domain, "::1");
	}

	#[tokio::test]
	async fn test_resolve_with_explicit_ip() {
		let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
		let addr = ServerAddr::new("ignored-domain.com".to_string(), 8080, Some(ip), StackPrefer::V4only);

		let resolved: Vec<SocketAddr> = addr.resolve().await.unwrap().collect();
		assert_eq!(resolved.len(), 1);
		assert_eq!(resolved[0], SocketAddr::from(([1, 2, 3, 4], 8080)));
	}

	#[tokio::test]
	async fn test_resolve_with_explicit_ipv6() {
		let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
		let addr = ServerAddr::new("ignored.com".to_string(), 9090, Some(ip), StackPrefer::V6only);

		let resolved: Vec<SocketAddr> = addr.resolve().await.unwrap().collect();
		assert_eq!(resolved.len(), 1);
		assert_eq!(resolved[0], SocketAddr::from((Ipv6Addr::LOCALHOST, 9090)));
	}

	#[tokio::test]
	async fn test_resolve_localhost() {
		let addr = ServerAddr::new("localhost".to_string(), 80, None, StackPrefer::V4only);
		let resolved: Vec<SocketAddr> = addr.resolve().await.unwrap().collect();
		// With V4only, should only return IPv4 addresses
		for a in &resolved {
			assert!(a.is_ipv4());
		}
		assert!(!resolved.is_empty());
	}
}
