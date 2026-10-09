//! Per-user connection admission, independent of the RESTful API listener.

use std::collections::HashMap;

use async_trait::async_trait;
use tokio::sync::Mutex;
use wind_core::{ConnInfo, ConnectDecision, ConnectionHooks, UserId};

#[derive(Default)]
struct Reservations {
	connections: HashMap<u64, Option<UserId>>,
	counts: HashMap<UserId, usize>,
}

pub(crate) struct PerUserConnectionLimit {
	maximum: usize,
	reservations: Mutex<Reservations>,
}

impl PerUserConnectionLimit {
	pub(crate) fn new(maximum: usize) -> Self {
		Self {
			maximum,
			reservations: Mutex::new(Reservations::default()),
		}
	}
}

#[async_trait]
impl ConnectionHooks for PerUserConnectionLimit {
	async fn on_connect(&self, info: &ConnInfo) -> ConnectDecision {
		if self.maximum > 0 {
			// Keep pre-auth connections too: a late authentication callback
			// must not recreate a reservation after disconnect has removed it.
			self.reservations.lock().await.connections.entry(info.conn_id).or_default();
		}
		ConnectDecision::Accept
	}

	async fn on_authenticated(&self, info: &ConnInfo, user: &UserId) -> ConnectDecision {
		if self.maximum == 0 {
			return ConnectDecision::Accept;
		}
		// Reserve under the same lock as the limit check: Wind registers an
		// authenticated connection only after these hooks have returned.
		let mut reservations = self.reservations.lock().await;
		let Some(existing) = reservations.connections.get(&info.conn_id) else {
			return ConnectDecision::Reject("connection closed before authentication".into());
		};
		if let Some(existing) = existing {
			return if existing == user {
				ConnectDecision::Accept
			} else {
				ConnectDecision::Reject("connection already reserved for another user".into())
			};
		}
		let count = reservations.counts.entry(user.clone()).or_default();
		if *count >= self.maximum {
			return ConnectDecision::Reject("maximum clients per user reached".into());
		}
		*count += 1;
		reservations.connections.insert(info.conn_id, Some(user.clone()));
		ConnectDecision::Accept
	}

	async fn on_disconnect(&self, info: &ConnInfo, _user: Option<&UserId>) {
		// A subsequent hook can veto authentication before Wind publishes the
		// user, so release by connection id even when the callback has no user.
		let mut reservations = self.reservations.lock().await;
		if let Some(Some(user)) = reservations.connections.remove(&info.conn_id)
			&& let Some(count) = reservations.counts.get_mut(&user)
		{
			*count -= 1;
			if *count == 0 {
				reservations.counts.remove(&user);
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use std::{net::SocketAddr, sync::Arc, time::Duration};

	use tokio::{sync::Barrier, task::JoinSet, time::timeout};
	use wind_core::{Protocol, hooks::FanOutConnectionHooks};

	use super::*;

	fn info(conn_id: u64) -> ConnInfo {
		ConnInfo {
			remote_addr: SocketAddr::from(([127, 0, 0, 1], 1000)),
			protocol: Protocol::Tuic,
			conn_id,
		}
	}

	async fn admit(limit: &PerUserConnectionLimit, conn_id: u64, user: &UserId) -> ConnectDecision {
		assert!(limit.on_connect(&info(conn_id)).await.is_accept());
		limit.on_authenticated(&info(conn_id), user).await
	}

	#[tokio::test]
	async fn per_user_connection_limit_releases_only_reserved_connections() {
		let limit = PerUserConnectionLimit::new(1);
		let alice = UserId::from("alice");
		let bob = UserId::from("bob");
		assert!(admit(&limit, 1, &alice).await.is_accept());
		assert!(admit(&limit, 2, &bob).await.is_accept());
		assert!(!admit(&limit, 3, &alice).await.is_accept());
		limit.on_disconnect(&info(3), Some(&alice)).await;
		limit.on_disconnect(&info(4), None).await;
		assert!(!admit(&limit, 5, &alice).await.is_accept());
		limit.on_disconnect(&info(5), None).await;
		limit.on_disconnect(&info(1), Some(&alice)).await;
		limit.on_disconnect(&info(1), Some(&alice)).await;
		assert!(admit(&limit, 6, &alice).await.is_accept());
		assert!(!admit(&limit, 7, &bob).await.is_accept());
		limit.on_disconnect(&info(7), None).await;
		limit.on_disconnect(&info(6), Some(&alice)).await;
		limit.on_disconnect(&info(2), Some(&bob)).await;
		let reservations = limit.reservations.lock().await;
		assert!(reservations.connections.is_empty());
		assert!(reservations.counts.is_empty());
	}

	#[tokio::test]
	async fn zero_per_user_connection_limit_is_unlimited() {
		let limit = PerUserConnectionLimit::new(0);
		let user = UserId::from("alice");
		for conn_id in 1..=16 {
			assert!(admit(&limit, conn_id, &user).await.is_accept());
		}
		assert!(limit.reservations.lock().await.connections.is_empty());
	}

	#[tokio::test]
	async fn repeated_admission_does_not_reserve_twice() {
		let limit = PerUserConnectionLimit::new(2);
		let user = UserId::from("alice");
		assert!(admit(&limit, 1, &user).await.is_accept());
		assert!(limit.on_authenticated(&info(1), &user).await.is_accept());
		assert!(!limit.on_authenticated(&info(1), &UserId::from("bob")).await.is_accept());
		assert!(admit(&limit, 2, &user).await.is_accept());
		assert!(!admit(&limit, 3, &user).await.is_accept());
	}

	struct RejectAuth;

	#[async_trait]
	impl ConnectionHooks for RejectAuth {
		async fn on_authenticated(&self, _info: &ConnInfo, _user: &UserId) -> ConnectDecision {
			ConnectDecision::Reject("test veto".into())
		}
	}

	#[tokio::test]
	async fn later_authentication_rejection_does_not_leak_reservation() {
		let limit = Arc::new(PerUserConnectionLimit::new(1));
		let hooks = FanOutConnectionHooks(vec![limit.clone(), Arc::new(RejectAuth)]);
		let user = UserId::from("alice");
		assert!(hooks.on_connect(&info(1)).await.is_accept());
		assert!(!hooks.on_authenticated(&info(1), &user).await.is_accept());
		hooks.on_disconnect(&info(1), None).await;
		assert!(admit(&limit, 2, &user).await.is_accept());
	}

	#[tokio::test]
	async fn disconnect_before_authentication_cannot_leak_a_reservation() {
		let limit = PerUserConnectionLimit::new(1);
		let user = UserId::from("alice");
		assert!(limit.on_connect(&info(1)).await.is_accept());
		limit.on_disconnect(&info(1), None).await;
		assert!(!limit.on_authenticated(&info(1), &user).await.is_accept());
		assert!(admit(&limit, 2, &user).await.is_accept());
		limit.on_disconnect(&info(2), Some(&user)).await;
		let reservations = limit.reservations.lock().await;
		assert!(reservations.connections.is_empty());
		assert!(reservations.counts.is_empty());
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
	async fn concurrent_per_user_connection_admission_cannot_exceed_limit() -> eyre::Result<()> {
		const MAXIMUM: usize = 3;
		const ATTEMPTS: usize = 32;
		let limit = Arc::new(PerUserConnectionLimit::new(MAXIMUM));
		let barrier = Arc::new(Barrier::new(ATTEMPTS));
		let user = UserId::from("alice");
		let mut tasks = JoinSet::new();
		for conn_id in 0..ATTEMPTS as u64 {
			let limit = limit.clone();
			let barrier = barrier.clone();
			let user = user.clone();
			tasks.spawn(async move {
				assert!(limit.on_connect(&info(conn_id)).await.is_accept());
				barrier.wait().await;
				(conn_id, limit.on_authenticated(&info(conn_id), &user).await.is_accept())
			});
		}
		let outcomes = timeout(Duration::from_secs(5), async {
			let mut outcomes = Vec::new();
			while let Some(outcome) = tasks.join_next().await {
				outcomes.push(outcome?);
			}
			Ok::<_, eyre::Report>(outcomes)
		})
		.await??;
		assert_eq!(outcomes.iter().filter(|(_, admitted)| *admitted).count(), MAXIMUM);
		for (conn_id, _) in outcomes {
			limit.on_disconnect(&info(conn_id), None).await;
		}
		let reservations = limit.reservations.lock().await;
		assert!(reservations.connections.is_empty());
		assert!(reservations.counts.is_empty());
		Ok(())
	}
}
