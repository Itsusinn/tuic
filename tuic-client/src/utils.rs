use std::{
	fs,
	net::{IpAddr, SocketAddr},
	path::PathBuf,
};

use anyhow::Context;
use rustls::{RootCertStore, pki_types::CertificateDer};
use tokio::net;
pub use wind_core::StackPrefer;
pub use wind_tuic::quinn::{CongestionControl, UdpRelayMode};

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
	domain: String,
	port: u16,
	ip: Option<IpAddr>,
	pub ipstack_prefer: StackPrefer,
	sni: Option<String>,
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
	use super::*;

	#[test]
	fn test_server_addr_strips_ipv6_brackets() {
		let addr = ServerAddr::new("[::1]".to_string(), 443, None, StackPrefer::V4first);
		assert_eq!(addr.domain, "::1");
	}

	#[test]
	fn test_server_addr_preserves_hostname() {
		let addr = ServerAddr::new("example.com".to_string(), 443, None, StackPrefer::V4first);
		assert_eq!(addr.domain, "example.com");
	}

	#[test]
	fn test_server_addr_strips_brackets_preserves_ipv4() {
		let addr = ServerAddr::new("192.168.1.1".to_string(), 443, None, StackPrefer::V4first);
		assert_eq!(addr.domain, "192.168.1.1");
	}

	#[test]
	fn test_server_name_defaults_to_domain() {
		let addr = ServerAddr::new("example.com".to_string(), 443, None, StackPrefer::V4first);
		assert_eq!(addr.server_name(), "example.com");
	}

	#[test]
	fn test_server_name_uses_sni_when_provided() {
		let addr = ServerAddr::with_sni(
			"real.internal".to_string(),
			443,
			None,
			StackPrefer::V4first,
			Some("public.example.com".to_string()),
		);
		assert_eq!(addr.server_name(), "public.example.com");
	}

	#[test]
	fn test_server_name_uses_domain_when_sni_none() {
		let addr = ServerAddr::with_sni("example.com".to_string(), 443, None, StackPrefer::V4first, None);
		assert_eq!(addr.server_name(), "example.com");
	}

	#[tokio::test]
	async fn test_resolve_with_explicit_ip() {
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		let addr = ServerAddr::new("ignored".to_string(), 8080, Some(ip), StackPrefer::V4first);
		let results: Vec<SocketAddr> = addr.resolve().await.unwrap().collect();
		assert_eq!(results.len(), 1);
		assert_eq!(results[0], SocketAddr::new(ip, 8080));
	}

	#[tokio::test]
	async fn test_resolve_with_explicit_ipv6() {
		let ip: IpAddr = "::1".parse().unwrap();
		let addr = ServerAddr::new("[::1]".to_string(), 9090, Some(ip), StackPrefer::V6first);
		let results: Vec<SocketAddr> = addr.resolve().await.unwrap().collect();
		assert_eq!(results.len(), 1);
		assert_eq!(results[0], SocketAddr::new(ip, 9090));
	}

	#[test]
	fn test_construct_with_standard_port() {
		let addr = ServerAddr::new("localhost".to_string(), 22, None, StackPrefer::V4first);
		assert_eq!(addr.port, 22);
		assert_eq!(addr.domain, "localhost");
	}

	#[test]
	fn test_ipstack_prefer_values_distinct() {
		assert_ne!(StackPrefer::V4only, StackPrefer::V6only, "prefer values must be distinct");
	}
}
