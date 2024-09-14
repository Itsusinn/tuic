use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use anyhow::Context;
use rustls::{pki_types::CertificateDer, RootCertStore};
use tokio::net;

use crate::error::Error;

pub fn load_certs(paths: Vec<PathBuf>, disable_native: bool) -> Result<RootCertStore, Error> {
    let mut certs = RootCertStore::empty();

    for cert_path in &paths {
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
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
}

impl ServerAddr {
    pub fn new(domain: String, port: u16, ip: Option<IpAddr>) -> Self {
        Self { domain, port, ip }
    }

    pub fn server_name(&self) -> &str {
        &self.domain
    }

    pub async fn resolve(&self) -> Result<impl Iterator<Item = SocketAddr>, Error> {
        if let Some(ip) = self.ip {
            Ok(vec![SocketAddr::from((ip, self.port))].into_iter())
        } else {
            Ok(net::lookup_host((self.domain.as_str(), self.port))
                .await?
                .collect::<Vec<_>>()
                .into_iter())
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
