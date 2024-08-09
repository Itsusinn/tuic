use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    fs::{self, File},
    io::{BufReader, Error as IoError},
    path::PathBuf,
    str::FromStr,
};

pub fn load_certs(path: PathBuf) -> Result<Vec<CertificateDer<'static>>, IoError> {
    let certs = if path.extension().map_or(false, |x| x == "der") {
        vec![CertificateDer::from(fs::read(&path)?)]
    } else {
        let mut file = BufReader::new(File::open(&path)?);
        rustls_pemfile::certs(&mut file).collect::<Result<_, _>>()?
    };

    Ok(certs)
}

pub fn load_priv_key(path: PathBuf) -> Result<PrivateKeyDer<'static>, IoError> {
    let priv_key = if path.extension().map_or(false, |x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(&path)?))
    } else {
        let mut file = BufReader::new(File::open(&path)?);
        rustls_pemfile::private_key(&mut file)?
            .ok_or_else(|| IoError::new(std::io::ErrorKind::InvalidData, "no private keys found"))?
    };

    Ok(priv_key)
}

#[derive(Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

impl Display for UdpRelayMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Native => write!(f, "native"),
            Self::Quic => write!(f, "quic"),
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
