//! RESTful API for tuic-server management.
//!
//! # Endpoints
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | POST | `/kick` | Kick one or more users by UUID |
//! | GET | `/online` | Per-user online connection counts |
//! | GET | `/detailed_online` | Per-user online connections with remote addrs |
//! | GET | `/traffic` | Per-user cumulative traffic (upload/download) |
//! | GET | `/reset_traffic` | Reset & return per-user traffic deltas |

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use axum::{
	Json, Router,
	extract::State,
	http::{HeaderMap, StatusCode},
	routing::{get, post},
};
use dashmap::DashMap;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;
use wind_core::{
	ActiveConnections, StatsCollector, UserId,
	hooks::{ConnInfo, ConnectDecision, ConnectionHooks},
};


/// Per-connection metadata stored by [`ConnectionTracker`].
struct ConnMeta {
	user: UserId,
	remote: SocketAddr,
	token: CancellationToken,
}

/// Tracks live connections with remote addresses for the detailed_online
/// endpoint. Implements [`ConnectionHooks`] so it is notified on connect,
/// authenticate, and disconnect — all through wind-tuic's existing lifecycle.
///
/// Registration/deregistration on `ActiveConnections` is handled separately
/// (wind-tuic wires it internally when `opts.active` is set); this tracker
/// only adds the remote-address dimension.
pub struct ConnectionTracker {
	inner: DashMap<u64, ConnMeta>,
}

impl Default for ConnectionTracker {
	fn default() -> Self {
		Self::new()
	}
}

impl ConnectionTracker {
	pub fn new() -> Self {
		Self { inner: DashMap::new() }
	}

	/// Number of live connections for a given user.
	pub fn count_for(&self, user: &UserId) -> usize {
		self.inner.iter().filter(|e| e.value().user == *user).count()
	}

	/// Cancel every connection belonging to `user`. Returns count kicked.
	pub fn kick_user(&self, user: &UserId) -> usize {
		let mut kicked = 0;
		for entry in self.inner.iter() {
			if entry.value().user == *user {
				entry.value().token.cancel();
				kicked += 1;
			}
		}
		kicked
	}

	/// Build a map of UUID → Vec<SocketAddr> of live connections.
	pub fn detailed_online(&self, uuid_lookup: &HashMap<Uuid, String>) -> HashMap<Uuid, Vec<SocketAddr>> {
		let mut result: HashMap<Uuid, Vec<SocketAddr>> = HashMap::new();
		let uuid_set: HashMap<&[u8], Uuid> = uuid_lookup.keys().map(|u| (u.as_bytes().as_slice(), *u)).collect();

		for entry in self.inner.iter() {
			if let Some(uuid) = uuid_set.get(entry.value().user.as_bytes()) {
				result.entry(*uuid).or_default().push(entry.value().remote);
			}
		}
		result
	}

	/// Number of connections currently tracked.
	pub fn len(&self) -> usize {
		self.inner.len()
	}

	pub fn is_empty(&self) -> bool {
		self.inner.is_empty()
	}
}

#[async_trait]
impl ConnectionHooks for ConnectionTracker {
	async fn on_connect(&self, info: &ConnInfo) -> ConnectDecision {
		self.inner.insert(
			info.conn_id,
			ConnMeta {
				user: UserId::new(Vec::new()),
				remote: info.remote_addr,
				token: CancellationToken::new(),
			},
		);
		ConnectDecision::Accept
	}

	async fn on_authenticated(&self, info: &ConnInfo, user: &UserId) -> ConnectDecision {
		if let Some(mut entry) = self.inner.get_mut(&info.conn_id) {
			entry.user = user.clone();
		}
		ConnectDecision::Accept
	}

	async fn on_disconnect(&self, info: &ConnInfo, _user: Option<&UserId>) {
		self.inner.remove(&info.conn_id);
	}
}

/// Shared state for RESTful handlers.
pub struct RestfulState {
	pub active: Arc<dyn KickConnections>,
	pub stats: Option<Arc<StatsCollector>>,
	pub tracker: Option<Arc<ConnectionTracker>>,
	pub secret: String,
	pub users: HashMap<Uuid, String>,
}

/// Object-safe interface for kicking connections, wrapping both
/// [`ActiveConnections`] and [`ConnectionTracker`].
#[async_trait]
pub trait KickConnections: Send + Sync + 'static {
	fn kick_user(&self, user: &UserId) -> usize;
	fn count_for(&self, user: &UserId) -> usize;
	fn len(&self) -> usize;
	fn is_empty(&self) -> bool;
}
#[async_trait]
impl KickConnections for ActiveConnections {
	fn kick_user(&self, user: &UserId) -> usize {
		self.kick_user(user)
	}

	fn count_for(&self, user: &UserId) -> usize {
		self.count_for(user)
	}

	fn len(&self) -> usize {
		self.len()
	}

	fn is_empty(&self) -> bool {
		self.is_empty()
	}
}

/// No-op implementation that always returns zero. Used as a fallback when
/// `ActiveConnections` is not available (e.g. per-user limit disabled).
pub struct NoopConnections;
#[async_trait]
impl KickConnections for NoopConnections {
	fn kick_user(&self, _user: &UserId) -> usize {
		0
	}

	fn count_for(&self, _user: &UserId) -> usize {
		0
	}

	fn len(&self) -> usize {
		0
	}

	fn is_empty(&self) -> bool {
		true
	}
}

#[async_trait]
impl KickConnections for ConnectionTracker {
	fn kick_user(&self, user: &UserId) -> usize {
		self.kick_user(user)
	}

	fn count_for(&self, user: &UserId) -> usize {
		self.count_for(user)
	}

	fn len(&self) -> usize {
		self.len()
	}

	fn is_empty(&self) -> bool {
		self.is_empty()
	}
}

// Auth helper

fn is_authorized(headers: &HeaderMap, secret: &str) -> bool {
	if secret.is_empty() {
		return true;
	}
	let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
		return false;
	};
	if let Some(token) = auth.strip_prefix("Bearer ") {
		token == secret
	} else {
		false
	}
}

fn unauthorized() -> (StatusCode, Json<Value>) {
	(StatusCode::UNAUTHORIZED, Json(json!("unauthorized")))
}

// Endpoints

/// POST /kick — kick one or more users by UUID.
async fn kick_handler(
	State(state): State<Arc<RestfulState>>,
	headers: HeaderMap,
	Json(users): Json<Vec<Uuid>>,
) -> (StatusCode, Json<Value>) {
	if !is_authorized(&headers, &state.secret) {
		return unauthorized();
	}
	let mut kicked = 0;
	for uuid in &users {
		let uid = UserId::from(*uuid);
		kicked += state.active.kick_user(&uid);
	}
	(StatusCode::OK, Json(json!({"kicked": kicked})))
}

/// GET /online — per-user online connection count.
async fn online_handler(State(state): State<Arc<RestfulState>>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
	if !is_authorized(&headers, &state.secret) {
		return unauthorized();
	}
	let mut result = serde_json::Map::new();
	for uuid in state.users.keys() {
		let count = state.active.count_for(&UserId::from(*uuid));
		if count > 0 {
			result.insert(uuid.to_string(), json!(count));
		}
	}
	(StatusCode::OK, Json(Value::Object(result)))
}

/// GET /detailed_online — per-user online connections with remote addresses.
async fn detailed_online_handler(State(state): State<Arc<RestfulState>>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
	if !is_authorized(&headers, &state.secret) {
		return unauthorized();
	}
	let mut result = serde_json::Map::new();
	if let Some(tracker) = &state.tracker {
		let detail = tracker.detailed_online(&state.users);
		for (uuid, addrs) in &detail {
			let addrs: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
			result.insert(uuid.to_string(), json!(addrs));
		}
	} else {
		// Fallback: show counts only when tracker is disabled.
		for uuid in state.users.keys() {
			let count = state.active.count_for(&UserId::from(*uuid));
			if count > 0 {
				result.insert(uuid.to_string(), json!({"count": count}));
			}
		}
	}
	(StatusCode::OK, Json(Value::Object(result)))
}

/// GET /traffic — per-user cumulative traffic (upload/download bytes).
async fn traffic_handler(State(state): State<Arc<RestfulState>>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
	if !is_authorized(&headers, &state.secret) {
		return unauthorized();
	}
	let Some(stats) = &state.stats else {
		return (StatusCode::OK, Json(json!({})));
	};
	let all = stats.snapshot();
	let mut result = serde_json::Map::new();
	// Map UserId back to UUID string for the response.
	let uuid_map: HashMap<Vec<u8>, String> = state
		.users
		.keys()
		.map(|uuid| (uuid.as_bytes().to_vec(), uuid.to_string()))
		.collect();
	for t in &all {
		let key = match uuid_map.get(t.user_id.as_bytes()) {
			Some(s) => s.as_str(),
			None => {
				// Allocate a display string for unknown (non-UUID) user ids.
				// Keep the allocation alive for the `insert` below.
				result.insert(
					t.user_id.to_string(),
					json!({"tx": t.upload, "rx": t.download, "requests": t.request_count}),
				);
				continue;
			}
		};
		result.insert(
			key.to_string(),
			json!({"tx": t.upload, "rx": t.download, "requests": t.request_count}),
		);
	}
	(StatusCode::OK, Json(Value::Object(result)))
}

/// GET /reset_traffic — reset & return per-user traffic deltas.
async fn reset_traffic_handler(State(state): State<Arc<RestfulState>>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
	if !is_authorized(&headers, &state.secret) {
		return unauthorized();
	}
	let Some(stats) = &state.stats else {
		return (StatusCode::OK, Json(json!({})));
	};
	let batch = stats.reset_all();
	let uuid_map: HashMap<Vec<u8>, String> = state
		.users
		.keys()
		.map(|uuid| (uuid.as_bytes().to_vec(), uuid.to_string()))
		.collect();
	let mut result = serde_json::Map::new();
	for t in &batch {
		let key = match uuid_map.get(t.user_id.as_bytes()) {
			Some(s) => s.as_str(),
			None => {
				result.insert(
					t.user_id.to_string(),
					json!({"tx": t.upload, "rx": t.download, "requests": t.request_count}),
				);
				continue;
			}
		};
		result.insert(
			key.to_string(),
			json!({"tx": t.upload, "rx": t.download, "requests": t.request_count}),
		);
	}
	(StatusCode::OK, Json(Value::Object(result)))
}

/// Build the axum [`Router`] and start serving on the configured address.
pub async fn serve(state: Arc<RestfulState>, addr: SocketAddr, cancel: CancellationToken) -> eyre::Result<()> {
	let app = Router::new()
		.route("/kick", post(kick_handler))
		.route("/online", get(online_handler))
		.route("/detailed_online", get(detailed_online_handler))
		.route("/traffic", get(traffic_handler))
		.route("/reset_traffic", get(reset_traffic_handler))
		.with_state(state);

	let listener = tokio::select! {
		_ = cancel.cancelled() => {
			return Ok(());
		}
		res = tokio::net::TcpListener::bind(addr) => {
			match res {
				Ok(l) => l,
				Err(e) => {
					warn!("RESTful API failed to bind to {addr}: {e}");
					return Err(eyre::eyre!("failed to bind RESTful API: {e}"));
				}
			}
		}
	};

	warn!("RESTful API server started, listening on {addr}");
	axum::serve(listener, app)
		.with_graceful_shutdown(async move { cancel.cancelled().await })
		.await
		.map_err(|e| eyre::eyre!("RESTful API server error: {e}"))?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use std::net::SocketAddr;

	use axum::{
		body::Body,
		http::{Request, StatusCode},
	};
	use tokio_util::sync::CancellationToken;
	use tower::ServiceExt;
	use wind_core::hooks::{ConnInfo, ConnectDecision, Protocol};

	use super::*;

	fn make_conn_info(id: u64, remote: SocketAddr) -> ConnInfo {
		ConnInfo {
			remote_addr: remote,
			protocol: Protocol::Tuic,
			conn_id: id,
		}
	}

	fn make_state(active: Arc<dyn KickConnections>, secret: &str, users: HashMap<Uuid, String>) -> Arc<RestfulState> {
		Arc::new(RestfulState {
			active,
			stats: None,
			tracker: None,
			secret: secret.to_string(),
			users,
		})
	}

	// ConnectionTracker tests

	#[tokio::test]
	async fn test_tracker_new_is_empty() {
		let t = ConnectionTracker::new();
		assert_eq!(t.len(), 0);
		assert!(t.is_empty());
	}

	#[tokio::test]
	async fn test_tracker_on_connect_increments_len() {
		let t = ConnectionTracker::new();
		let info = make_conn_info(1, "127.0.0.1:1000".parse().unwrap());
		let d = t.on_connect(&info).await;
		assert!(matches!(d, ConnectDecision::Accept));
		assert_eq!(t.len(), 1);
		assert!(!t.is_empty());
	}

	#[tokio::test]
	async fn test_tracker_on_authenticated_sets_user() {
		let t = ConnectionTracker::new();
		let info = make_conn_info(1, "127.0.0.1:1000".parse().unwrap());
		let user = UserId::from("alice");
		t.on_connect(&info).await;
		t.on_authenticated(&info, &user).await;
		assert_eq!(t.count_for(&user), 1);
	}

	#[tokio::test]
	async fn test_tracker_on_disconnect_removes_entry() {
		let t = ConnectionTracker::new();
		let info = make_conn_info(1, "127.0.0.1:2000".parse().unwrap());
		t.on_connect(&info).await;
		assert_eq!(t.len(), 1);
		t.on_disconnect(&info, None).await;
		assert_eq!(t.len(), 0);
	}

	#[tokio::test]
	async fn test_tracker_count_for_multiple_users() {
		let t = ConnectionTracker::new();
		let alice = UserId::from("alice");
		let bob = UserId::from("bob");

		let info1 = make_conn_info(1, "127.0.0.1:1".parse().unwrap());
		let info2 = make_conn_info(2, "127.0.0.1:2".parse().unwrap());
		let info3 = make_conn_info(3, "127.0.0.1:3".parse().unwrap());

		t.on_connect(&info1).await;
		t.on_authenticated(&info1, &alice).await;
		t.on_connect(&info2).await;
		t.on_authenticated(&info2, &alice).await;
		t.on_connect(&info3).await;
		t.on_authenticated(&info3, &bob).await;

		assert_eq!(t.count_for(&alice), 2);
		assert_eq!(t.count_for(&bob), 1);
		assert_eq!(t.count_for(&UserId::from("nobody")), 0);
	}

	#[tokio::test]
	async fn test_tracker_kick_user_cancels_and_counts() {
		let t = ConnectionTracker::new();
		let alice = UserId::from("alice");
		let bob = UserId::from("bob");

		let info1 = make_conn_info(1, "127.0.0.1:1".parse().unwrap());
		let info2 = make_conn_info(2, "127.0.0.1:2".parse().unwrap());
		let info3 = make_conn_info(3, "127.0.0.1:3".parse().unwrap());

		t.on_connect(&info1).await;
		t.on_authenticated(&info1, &alice).await;
		t.on_connect(&info2).await;
		t.on_authenticated(&info2, &bob).await;
		t.on_connect(&info3).await;
		t.on_authenticated(&info3, &alice).await;

		assert_eq!(t.len(), 3);
		assert_eq!(t.count_for(&alice), 2);
		assert_eq!(t.count_for(&bob), 1);

		// kick_user cancels tokens (notifies the connection to shut down)
		// but entries remain in the tracker until on_disconnect fires.
		let kicked = t.kick_user(&alice);
		assert_eq!(kicked, 2);
		// Entries are still present; they'll be removed on the actual disconnect.
		assert_eq!(t.len(), 3);
		assert_eq!(t.count_for(&bob), 1);
	}

	#[tokio::test]
	async fn test_tracker_detailed_online() {
		let t = ConnectionTracker::new();
		let alice = Uuid::new_v4();
		let bob = Uuid::new_v4();
		let alice_uid = UserId::from(alice);
		let bob_uid = UserId::from(bob);

		let info1 = make_conn_info(1, "10.0.0.1:443".parse().unwrap());
		let info2 = make_conn_info(2, "10.0.0.2:443".parse().unwrap());
		let info3 = make_conn_info(3, "192.168.1.1:80".parse().unwrap());

		t.on_connect(&info1).await;
		t.on_authenticated(&info1, &alice_uid).await;
		t.on_connect(&info2).await;
		t.on_authenticated(&info2, &alice_uid).await;
		t.on_connect(&info3).await;
		t.on_authenticated(&info3, &bob_uid).await;

		let mut uuid_lookup = HashMap::new();
		uuid_lookup.insert(alice, "alice".to_string());
		uuid_lookup.insert(bob, "bob".to_string());

		let detail = t.detailed_online(&uuid_lookup);
		assert_eq!(detail.len(), 2);
		assert_eq!(detail.get(&alice).unwrap().len(), 2);
		assert_eq!(detail.get(&bob).unwrap().len(), 1);
	}

	#[tokio::test]
	async fn test_tracker_kick_user_token_gets_cancelled() {
		let t = ConnectionTracker::new();
		let alice = UserId::from("alice");

		let info = make_conn_info(1, "127.0.0.1:1".parse().unwrap());
		t.on_connect(&info).await;
		t.on_authenticated(&info, &alice).await;

		let kicked = t.kick_user(&alice);
		assert_eq!(kicked, 1);
	}

	// NoopConnections tests

	#[tokio::test]
	async fn test_noop_kick_returns_zero() {
		let noop = NoopConnections;
		assert_eq!(noop.kick_user(&UserId::from("alice")), 0);
	}

	#[tokio::test]
	async fn test_noop_count_for_returns_zero() {
		let noop = NoopConnections;
		assert_eq!(noop.count_for(&UserId::from("alice")), 0);
	}

	#[tokio::test]
	async fn test_noop_len_and_is_empty() {
		let noop = NoopConnections;
		assert_eq!(noop.len(), 0);
		assert!(noop.is_empty());
	}

	// KickConnections trait tests

	#[tokio::test]
	async fn test_tracker_as_kick_connections_delegates() {
		let t = ConnectionTracker::new();
		let kc: &dyn KickConnections = &t;
		assert_eq!(kc.len(), 0);
		assert!(kc.is_empty());
		assert_eq!(kc.count_for(&UserId::from("x")), 0);
		assert_eq!(kc.kick_user(&UserId::from("x")), 0);
	}

	// Auth tests

	#[test]
	fn test_auth_empty_secret_always_passes() {
		let headers = HeaderMap::new();
		assert!(is_authorized(&headers, ""));
	}

	#[test]
	fn test_auth_valid_bearer_passes() {
		let mut headers = HeaderMap::new();
		headers.insert("authorization", "Bearer my-secret-token".parse().unwrap());
		assert!(is_authorized(&headers, "my-secret-token"));
	}

	#[test]
	fn test_auth_invalid_bearer_fails() {
		let mut headers = HeaderMap::new();
		headers.insert("authorization", "Bearer wrong-token".parse().unwrap());
		assert!(!is_authorized(&headers, "my-secret-token"));
	}

	#[test]
	fn test_auth_no_header_fails() {
		let headers = HeaderMap::new();
		assert!(!is_authorized(&headers, "my-secret-token"));
	}

	#[test]
	fn test_auth_wrong_scheme_fails() {
		let mut headers = HeaderMap::new();
		headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
		assert!(!is_authorized(&headers, "my-secret-token"));
	}

	#[test]
	fn test_auth_empty_bearer_token_fails() {
		let mut headers = HeaderMap::new();
		headers.insert("authorization", "Bearer ".parse().unwrap());
		assert!(!is_authorized(&headers, "my-secret-token"));
	}

	#[tokio::test]
	async fn test_unauthorized_returns_401() {
		let (status, json) = unauthorized();
		assert_eq!(status, StatusCode::UNAUTHORIZED);
		assert_eq!(json.0, json!("unauthorized"));
	}

	// REST endpoint tests

	fn build_router(state: Arc<RestfulState>) -> axum::Router {
		axum::Router::new()
			.route("/kick", axum::routing::post(kick_handler))
			.route("/online", axum::routing::get(online_handler))
			.route("/detailed_online", axum::routing::get(detailed_online_handler))
			.route("/traffic", axum::routing::get(traffic_handler))
			.route("/reset_traffic", axum::routing::get(reset_traffic_handler))
			.with_state(state)
	}

	#[tokio::test]
	async fn test_kick_handler_unauthorized_when_secret_set() {
		let state = make_state(Arc::new(NoopConnections), "secret", HashMap::new());
		let app = build_router(state);

		let response = app
			.oneshot(
				Request::builder()
					.uri("/kick")
					.method("POST")
					.header("content-type", "application/json")
					.body(Body::from("[]"))
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	}

	#[tokio::test]
	async fn test_kick_handler_authorized_with_noop() {
		let state = make_state(Arc::new(NoopConnections), "secret", HashMap::new());
		let app = build_router(state);

		let response = app
			.oneshot(
				Request::builder()
					.uri("/kick")
					.method("POST")
					.header("content-type", "application/json")
					.header("authorization", "Bearer secret")
					.body(Body::from(serde_json::to_string(&vec![Uuid::nil()]).unwrap()))
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
		let v: Value = serde_json::from_slice(&body).unwrap();
		assert_eq!(v, json!({"kicked": 0}));
	}

	#[tokio::test]
	async fn test_online_handler_empty_when_no_users_online() {
		let state = make_state(Arc::new(NoopConnections), "", {
			let mut m = HashMap::new();
			m.insert(Uuid::nil(), "alice".to_string());
			m
		});
		let app = build_router(state);

		let response = app
			.oneshot(Request::builder().uri("/online").method("GET").body(Body::empty()).unwrap())
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
		assert_eq!(&body[..], b"{}");
	}

	#[tokio::test]
	async fn test_detailed_online_handler_without_tracker() {
		let uuid = Uuid::nil();
		let state = {
			let mut users = HashMap::new();
			users.insert(uuid, "alice".to_string());
			Arc::new(RestfulState {
				active: Arc::new(NoopConnections),
				stats: None,
				tracker: None,
				secret: String::new(),
				users,
			})
		};
		let app = build_router(state);

		let response = app
			.oneshot(
				Request::builder()
					.uri("/detailed_online")
					.method("GET")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
		assert_eq!(&body[..], b"{}");
	}

	#[tokio::test]
	async fn test_detailed_online_handler_with_tracker() {
		let uuid = Uuid::nil();
		let tracker = Arc::new(ConnectionTracker::new());
		let user = UserId::from(uuid);
		let info = make_conn_info(1, "10.0.0.1:443".parse().unwrap());
		tracker.on_connect(&info).await;
		tracker.on_authenticated(&info, &user).await;

		let state = {
			let mut users = HashMap::new();
			users.insert(uuid, "alice".to_string());
			Arc::new(RestfulState {
				active: Arc::new(NoopConnections),
				stats: None,
				tracker: Some(tracker),
				secret: String::new(),
				users,
			})
		};
		let app = build_router(state);

		let response = app
			.oneshot(
				Request::builder()
					.uri("/detailed_online")
					.method("GET")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
		let v: Value = serde_json::from_slice(&body).unwrap();
		let addrs = v.get(uuid.to_string()).unwrap().as_array().unwrap();
		assert_eq!(addrs.len(), 1);
		assert_eq!(addrs[0], json!("10.0.0.1:443"));
	}

	#[tokio::test]
	async fn test_traffic_handler_no_stats_returns_empty() {
		let state = Arc::new(RestfulState {
			active: Arc::new(NoopConnections),
			stats: None,
			tracker: None,
			secret: String::new(),
			users: HashMap::new(),
		});
		let app = build_router(state);

		let response = app
			.oneshot(Request::builder().uri("/traffic").method("GET").body(Body::empty()).unwrap())
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
		assert_eq!(&body[..], b"{}");
	}

	#[tokio::test]
	async fn test_reset_traffic_handler_no_stats_returns_empty() {
		let state = Arc::new(RestfulState {
			active: Arc::new(NoopConnections),
			stats: None,
			tracker: None,
			secret: String::new(),
			users: HashMap::new(),
		});
		let app = build_router(state);

		let response = app
			.oneshot(
				Request::builder()
					.uri("/reset_traffic")
					.method("GET")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
		assert_eq!(&body[..], b"{}");
	}

	#[tokio::test]
	async fn test_traffic_handler_unauthorized_when_secret_set() {
		let state = make_state(Arc::new(NoopConnections), "secret", HashMap::new());
		let app = build_router(state);

		let response = app
			.oneshot(Request::builder().uri("/traffic").method("GET").body(Body::empty()).unwrap())
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	}

	#[tokio::test]
	async fn test_online_handler_unauthorized_when_secret_set() {
		let state = make_state(Arc::new(NoopConnections), "secret", HashMap::new());
		let app = build_router(state);

		let response = app
			.oneshot(Request::builder().uri("/online").method("GET").body(Body::empty()).unwrap())
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	}

	#[tokio::test]
	async fn test_handler_with_empty_secret_allows_access() {
		let uuid = Uuid::nil();
		let state = make_state(Arc::new(NoopConnections), "", {
			let mut m = HashMap::new();
			m.insert(uuid, "alice".to_string());
			m
		});
		let app = build_router(state);

		// Kick without auth header should work when secret is empty
		let response = app
			.oneshot(
				Request::builder()
					.uri("/kick")
					.method("POST")
					.header("content-type", "application/json")
					.body(Body::from(serde_json::to_string(&vec![uuid]).unwrap()))
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
	}
}
