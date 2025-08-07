use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};

use educe::Educe;
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Educe)]
#[educe(Default)]
pub enum CongestionController {
    #[educe(Default)]
    Bbr,
    Cubic,
    NewReno,
}

// TODO remove in 2.0.0
impl FromStr for CongestionController {
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

pub trait FutResultExt<T, E, Fut> {
    async fn log_err(self) -> Option<T>;
}
impl<T, Fut> FutResultExt<T, eyre::Report, Fut> for Fut
where
    Fut: std::future::Future<Output = Result<T, eyre::Report>>,
{
    #[inline(always)]
    async fn log_err(self) -> Option<T> {
        match self.await {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::error!("{:?}", e);
                None
            }
        }
    }
}
