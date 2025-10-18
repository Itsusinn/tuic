use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use arc_swap::ArcSwap;
use tokio::sync::Notify;
use uuid::Uuid;

#[derive(Clone)]
pub struct Authenticated(Arc<AuthenticatedInner>);

struct AuthenticatedInner {
    /// uuid that waiting for auth
    uuid: ArcSwap<Option<Uuid>>,
    notify: Notify,
    is_authenticated: AtomicBool,
}

// The whole thing below is just an observable boolean
impl Authenticated {
    pub fn new() -> Self {
        Self(Arc::new(AuthenticatedInner {
            uuid: ArcSwap::new(None.into()),
            notify: Notify::new(),
            is_authenticated: AtomicBool::new(false),
        }))
    }

    /// invoking 'set' means auth success
    pub async fn set(&self, uuid: Uuid) {
        self.0.uuid.store(Some(uuid).into());

        // Mark as authenticated and notify all waiters
        self.0.is_authenticated.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub fn get(&self) -> Option<Uuid> {
        **self.0.uuid.load()
    }

    /// waiting for auth success
    pub async fn wait(&self) {
        // If already authenticated, return immediately
        if self.0.is_authenticated.load(Ordering::SeqCst) {
            return;
        }

        // Otherwise, wait for notification
        self.0.notify.notified().await;
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

    #[tokio::test]
    async fn test_authenticated_wait_race() {
        let auth = Authenticated::new();
        let uuid = Uuid::new_v4();

        // Create multiple waiters to simulate a race condition
        let mut wait_tasks = Vec::new();
        for _ in 0..5 {
            let auth_clone = auth.clone();
            let uuid_clone = uuid;
            let task = tokio::spawn(async move {
                auth_clone.wait().await;
                assert_eq!(auth_clone.get(), Some(uuid_clone));
            });
            wait_tasks.push(task);
        }

        // Small delay to ensure all tasks are waiting
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Authenticate
        auth.set(uuid).await;

        // Ensure all tasks complete successfully
        for task in wait_tasks {
            task.await.unwrap();
        }
    }
}
