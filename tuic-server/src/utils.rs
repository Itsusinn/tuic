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
	#[serde(alias = "new_reno")]
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
	fn log_err(self) -> impl std::future::Future<Output = Option<T>>;
}
impl<T, Fut> FutResultExt<T, eyre::Report, Fut> for Fut
where
	Fut: std::future::Future<Output = Result<T, eyre::Report>> + Send,
	T: Send,
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

/// Preference for selecting IP addresses when resolving a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpMode {
	PreferV4,
	PreferV6,
	OnlyV4,
	OnlyV6,
	Auto,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_udp_relay_mode_display() {
		assert_eq!(UdpRelayMode::Native.to_string(), "native");
		assert_eq!(UdpRelayMode::Quic.to_string(), "quic");
	}

	#[test]
	fn test_congestion_controller_from_str() {
		assert_eq!(CongestionController::from_str("bbr").unwrap(), CongestionController::Bbr);
		assert_eq!(CongestionController::from_str("BBR").unwrap(), CongestionController::Bbr);
		assert_eq!(CongestionController::from_str("cubic").unwrap(), CongestionController::Cubic);
		assert_eq!(CongestionController::from_str("CUBIC").unwrap(), CongestionController::Cubic);
		assert_eq!(
			CongestionController::from_str("new_reno").unwrap(),
			CongestionController::NewReno
		);
		assert_eq!(
			CongestionController::from_str("newreno").unwrap(),
			CongestionController::NewReno
		);
		assert_eq!(
			CongestionController::from_str("NEWRENO").unwrap(),
			CongestionController::NewReno
		);

		assert!(CongestionController::from_str("invalid").is_err());
		assert!(CongestionController::from_str("").is_err());
	}

	#[test]
	fn test_congestion_controller_serde() {
		// Test serialization
		let bbr = CongestionController::Bbr;
		let json = serde_json::to_string(&bbr).unwrap();
		assert_eq!(json, "\"bbr\"");

		let cubic = CongestionController::Cubic;
		let json = serde_json::to_string(&cubic).unwrap();
		assert_eq!(json, "\"cubic\"");

		// Test deserialization
		let bbr: CongestionController = serde_json::from_str("\"bbr\"").unwrap();
		assert_eq!(bbr, CongestionController::Bbr);

		let newreno: CongestionController = serde_json::from_str("\"newreno\"").unwrap();
		assert_eq!(newreno, CongestionController::NewReno);
	}

	#[test]
	fn test_congestion_controller_default() {
		let default = CongestionController::default();
		assert_eq!(default, CongestionController::Bbr);
	}

	#[test]
	fn test_ip_mode_serde() {
		// Test serialization
		let prefer_v4 = IpMode::PreferV4;
		let json = serde_json::to_string(&prefer_v4).unwrap();
		assert_eq!(json, "\"prefer_v4\"");

		let only_v6 = IpMode::OnlyV6;
		let json = serde_json::to_string(&only_v6).unwrap();
		assert_eq!(json, "\"only_v6\"");

		// Test deserialization
		let auto: IpMode = serde_json::from_str("\"auto\"").unwrap();
		assert_eq!(auto, IpMode::Auto);

		let prefer_v6: IpMode = serde_json::from_str("\"prefer_v6\"").unwrap();
		assert_eq!(prefer_v6, IpMode::PreferV6);
	}

	#[test]
	fn test_ip_mode_variants() {
		// Test all variants exist and are distinct
		let modes = vec![
			IpMode::PreferV4,
			IpMode::PreferV6,
			IpMode::OnlyV4,
			IpMode::OnlyV6,
			IpMode::Auto,
		];

		assert_eq!(modes.len(), 5);

		// Test equality
		assert_eq!(IpMode::PreferV4, IpMode::PreferV4);
		assert_ne!(IpMode::PreferV4, IpMode::PreferV6);
	}
}
