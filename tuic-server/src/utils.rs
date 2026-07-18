// Re-export common types from wind-core and wind-tuic
pub use wind_core::StackPrefer;
pub use wind_tuic::quinn::UdpRelayMode;

// Type alias for backward compatibility
pub type CongestionController = wind_tuic::quinn::CongestionControl;

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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_stack_prefer_serde() {
		let v4_only = StackPrefer::V4only;
		let json = serde_json::to_string(&v4_only).unwrap();
		assert_eq!(json, "\"v4only\"");

		let v6_only = StackPrefer::V6only;
		let json = serde_json::to_string(&v6_only).unwrap();
		assert_eq!(json, "\"v6only\"");

		let v4_first: StackPrefer = serde_json::from_str("\"v4first\"").unwrap();
		assert_eq!(v4_first, StackPrefer::V4first);

		let v6_first: StackPrefer = serde_json::from_str("\"v6first\"").unwrap();
		assert_eq!(v6_first, StackPrefer::V6first);
	}

	#[test]
	fn test_stack_prefer_variants() {
		let modes = [
			StackPrefer::V4only,
			StackPrefer::V6only,
			StackPrefer::V4first,
			StackPrefer::V6first,
		];

		assert_eq!(modes.len(), 4);
		assert_eq!(StackPrefer::V4only, StackPrefer::V4only);
		assert_ne!(StackPrefer::V4only, StackPrefer::V6only);
	}
}
