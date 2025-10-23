use std::{
	fs,
	net::{IpAddr, SocketAddr},
	path::PathBuf,
	str::FromStr,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackPrefer {
	V4only,
	V6only,
	V4first,
	V6first,
}

impl FromStr for StackPrefer {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_ascii_lowercase().as_str() {
			"v4" => Ok(StackPrefer::V4only),
			"v6" => Ok(StackPrefer::V6only),
			"v4v6" => Ok(StackPrefer::V4first),
			"v6v4" => Ok(StackPrefer::V6first),
			_ => Err("invalid stack preference"),
		}
	}
}

use anyhow::Context;
use rustls::{RootCertStore, pki_types::CertificateDer};
use tokio::net;

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
}

impl ServerAddr {
	pub fn new(domain: String, port: u16, ip: Option<IpAddr>, ipstack_prefer: StackPrefer) -> Self {
		Self {
			domain,
			port,
			ip,
			ipstack_prefer,
		}
	}

	pub fn server_name(&self) -> &str {
		&self.domain
	}

	pub async fn resolve(&self) -> Result<impl Iterator<Item = SocketAddr>, Error> {
		// no extra imports needed
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

#[derive(Clone, Copy)]
pub enum UdpRelayMode {
	Native,
	Quic,
}

impl FromStr for UdpRelayMode {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.eq_ignore_ascii_case("native") {
			Ok(Self::Native)
		} else if s.eq_ignore_ascii_case("quic") {
			Ok(Self::Quic)
		} else {
			Err("invalid UDP relay mode")
		}
	}
}

pub enum CongestionControl {
	Cubic,
	NewReno,
	Bbr,
}

impl FromStr for CongestionControl {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.eq_ignore_ascii_case("cubic") {
			Ok(Self::Cubic)
		} else if s.eq_ignore_ascii_case("new_reno") || s.eq_ignore_ascii_case("newreno") {
			Ok(Self::NewReno)
		} else if s.eq_ignore_ascii_case("bbr") {
			Ok(Self::Bbr)
		} else {
			Err("invalid congestion control")
		}
	}
}
