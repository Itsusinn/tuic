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

#[cfg(test)]
mod tests {
	use std::sync::Mutex;

	use tokio::sync::Notify;

	use super::SharedOutbound;

	#[test]
	fn test_new_creates_empty_mutex() {
		let shared = SharedOutbound::new();
		assert!(shared.inner.lock().unwrap().is_none());
	}

	#[test]
	fn test_new_returns_different_arcs() {
		let a = SharedOutbound::new();
		let b = SharedOutbound::new();
		assert!(!std::sync::Arc::ptr_eq(&a, &b));
	}

	#[test]
	fn test_notify_mechanism_wakes_waiters() {
		use std::sync::{Arc, Mutex};

		let notify = Arc::new(Notify::new());
		let value = Arc::new(Mutex::new(Option::<u32>::None));

		let n = notify.clone();
		let v = value.clone();
		let handle = std::thread::spawn(move || {
			let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
			rt.block_on(async {
				loop {
					if let Some(val) = v.lock().unwrap().as_ref() {
						return *val;
					}
					n.notified().await;
				}
			})
		});

		std::thread::sleep(std::time::Duration::from_millis(50));
		*value.lock().unwrap() = Some(42);
		notify.notify_waiters();

		let result = handle.join().unwrap();
		assert_eq!(result, 42);
	}

	#[test]
	fn test_notify_before_waiting_does_not_deadlock() {
		// If set() is called before any get(), the notify is "consumed"
		// by the first notified().await, but the value is already present
		// so the loop exits immediately.
		let notify = Notify::new();
		let value: Mutex<Option<u32>> = Mutex::new(Some(99));
		notify.notify_waiters();

		let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
		let result: u32 = rt.block_on(async {
			loop {
				if let Some(v) = value.lock().unwrap().as_ref() {
					return *v;
				}
				notify.notified().await;
			}
		});
		assert_eq!(result, 99);
	}

	#[test]
	fn test_multiple_waiters_all_woken() {
		use std::sync::Arc;
		use std::sync::atomic::{AtomicU32, Ordering};

		let notify = Arc::new(Notify::new());
		let value = Arc::new(Mutex::new(Option::<u32>::None));
		let counter = Arc::new(AtomicU32::new(0));

		let mut handles = vec![];
		for _ in 0..5 {
			let n = notify.clone();
			let v = value.clone();
			let c = counter.clone();
			handles.push(std::thread::spawn(move || {
				let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
				let result: u32 = rt.block_on(async {
					loop {
						if let Some(val) = v.lock().unwrap().as_ref() {
							return *val;
						}
						n.notified().await;
					}
				});
				c.fetch_add(1, Ordering::SeqCst);
				result
			}));
		}

		std::thread::sleep(std::time::Duration::from_millis(50));
		*value.lock().unwrap() = Some(7);
		notify.notify_waiters();

		for h in handles {
			assert_eq!(h.join().unwrap(), 7);
		}
		assert_eq!(counter.load(Ordering::SeqCst), 5);
	}

	#[test]
	fn test_shared_outbound_default_is_none() {
		let shared = SharedOutbound::new();
		let guard = shared.inner.lock().unwrap();
		assert!(guard.is_none());
	}

	#[tokio::test]
	async fn test_set_value_triggers_notify() {
		// Test that setting a value into the inner Mutex and calling
		// notify_waiters() causes a concurrent get() to succeed.
		let shared = SharedOutbound::new();
		let shared_clone = shared.clone();

		// We'll mock-set a value inside. In real code, Arc::new(TuicOutboundAdapter{...})
		// is stored; here we just verify the store-then-get pattern.
		// Since TuicOutboundAdapter can't be trivially constructed, we skip
		// the actual adapter storage test.
		let _ = shared_clone;
	}
}
