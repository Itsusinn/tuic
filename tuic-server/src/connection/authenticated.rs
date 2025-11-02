use std::{
	fmt::{Display, Formatter, Result as FmtResult},
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
};

use arc_swap::ArcSwapOption;
use tokio::sync::Notify;
use uuid::Uuid;

#[derive(Clone)]
pub struct Authenticated(Arc<AuthenticatedInner>);

struct AuthenticatedInner {
	/// uuid that waiting for auth
	uuid:             ArcSwapOption<Uuid>,
	notify:           Notify,
	is_authenticated: AtomicBool,
}

// The whole thing below is just an observable boolean
impl Authenticated {
	pub fn new() -> Self {
		Self(Arc::new(AuthenticatedInner {
			uuid:             ArcSwapOption::new(None),
			notify:           Notify::new(),
			is_authenticated: AtomicBool::new(false),
		}))
	}

	/// invoking 'set' means auth success
	pub async fn set(&self, uuid: Uuid) {
		self.0.uuid.store(Some(Arc::new(uuid)));

		// Mark as authenticated and notify all waiters
		self.0.is_authenticated.store(true, Ordering::SeqCst);
		self.0.notify.notify_waiters();
	}

	pub fn get(&self) -> Option<Uuid> {
		self.0.uuid.load().as_deref().cloned()
	}

	/// Check if already authenticated (non-blocking)
	pub fn is_authenticated(&self) -> bool {
		self.0.is_authenticated.load(Ordering::SeqCst)
	}

	/// waiting for auth success
	pub async fn wait(&self) {
		// If already authenticated, return immediately
		if self.0.is_authenticated.load(Ordering::SeqCst) {
			return;
		}

		// Create the notified future BEFORE the double-check
		// This ensures we don't miss notifications that happen between check and await
		let notified = self.0.notify.notified();

		// Double-check after creating the future to avoid unnecessary wait
		if self.0.is_authenticated.load(Ordering::SeqCst) {
			return;
		}

		// Now wait for notification
		notified.await;
	}
}

impl Display for Authenticated {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match self.get() {
			Some(uuid) => write!(f, "{uuid}"),
			None => write!(f, "unauthenticated"),
		}
	}
}

#[cfg(test)]
mod tests {
	use uuid::Uuid;

	use super::*;

	#[tokio::test]
	async fn test_authenticated_get_set() {
		let auth = Authenticated::new();
		assert!(auth.get().is_none());
		let uuid = Uuid::new_v4();
		auth.set(uuid).await;
		assert_eq!(auth.get(), Some(uuid));
	}

	#[tokio::test]
	async fn test_authenticated_wait() {
		let auth = Authenticated::new();
		let uuid = Uuid::new_v4();
		let auth_clone = auth.clone();
		let wait_fut = tokio::spawn(async move {
			auth_clone.wait().await;
			assert_eq!(auth_clone.get(), Some(uuid));
		});
		auth.set(uuid).await;
		wait_fut.await.unwrap();
	}
}
