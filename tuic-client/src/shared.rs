//! Shared, lazily-initialized TUIC outbound handle.
//!
//! The outbound connection is created asynchronously in a background task.
//! Handlers and forwarders wait for readiness on first use via
//! [`SharedOutbound::get`].

use std::sync::Arc;

use crate::wind_adapter::TuicOutboundAdapter;

/// A thread-safe handle to a TUIC outbound that may not be ready yet.
///
/// Created before the QUIC connection is established. Callers that need the
/// outbound call [`get`](Self::get), which waits for the background setup
/// task to finish.
pub struct SharedOutbound {
	inner: std::sync::Mutex<Option<Arc<TuicOutboundAdapter>>>,
	ready: tokio::sync::Notify,
}

impl SharedOutbound {
	pub fn new() -> Arc<Self> {
		Arc::new(Self {
			inner: std::sync::Mutex::new(None),
			ready: tokio::sync::Notify::new(),
		})
	}

	/// Store a fully-initialized adapter. Notifies all waiters.
	pub fn set(&self, outbound: TuicOutboundAdapter) {
		*self.inner.lock().unwrap() = Some(Arc::new(outbound));
		self.ready.notify_waiters();
	}

	/// Wait for the outbound to be ready and return a cloneable handle.
	pub async fn get(&self) -> eyre::Result<Arc<TuicOutboundAdapter>> {
		loop {
			if let Some(out) = self.inner.lock().unwrap().clone() {
				return Ok(out);
			}
			self.ready.notified().await;
		}
	}
}
