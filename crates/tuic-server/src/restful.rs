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
//! | POST | `/reset_traffic` | Reset & return per-user traffic deltas |

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
use tokio::sync::watch;
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
}

/// Tracks live connections with remote addresses for the detailed_online
/// endpoint. Implements [`ConnectionHooks`] so it is notified on connect,
/// authenticate, and disconnect — all through wind-tuic's existing lifecycle.
///
/// Registration/deregistration on `ActiveConnections` is handled separately
/// (wind-tuic wires it internally when `opts.active` is set); this tracker
/// only adds the remote-address dimension.
///
/// It deliberately holds **no** cancellation handle: `ConnectionHooks` never
/// receives the connection's cancel token, so a tracker-side kick could only
/// cancel a token of its own making and would report success without closing
/// anything. Closing connections is [`ActiveConnections`]' job, reachable
/// through [`KickConnections`] on the RESTful state.
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

/// Outcome reported to the server core once the RESTful task has something to
/// say about its listen socket.
///
/// `Ok(addr)` is the **actually bound** address (the OS-assigned port when
/// `restful.addr` ends in `:0`); `Err` carries why the socket could never be
/// bound. Both variants are cheap to clone because the channel hands the value
/// to every receiver by reference.
pub type RestfulBindOutcome = Result<SocketAddr, Arc<str>>;

/// Sender half of the channel used by `restful::serve` to report a
/// [`RestfulBindOutcome`] to the server core.
///
/// While the value is `None` the socket is not bound yet; if **all** senders
/// are dropped with the value still `None`, the task ended without ever
/// reaching a bind attempt.
pub type RestfulAddrTx = watch::Sender<Option<RestfulBindOutcome>>;

/// Receiver half of [`RestfulAddrTx`].
pub type RestfulAddrRx = watch::Receiver<Option<RestfulBindOutcome>>;

/// Create the bind-outcome channel shared between the server core and the
/// RESTful task.
pub fn restful_addr_channel() -> (RestfulAddrTx, RestfulAddrRx) {
	watch::channel(None)
}

/// Shared state for RESTful handlers.
pub struct RestfulState {
	pub active: Arc<dyn KickConnections>,
	pub stats: Option<Arc<StatsCollector>>,
	pub tracker: Option<Arc<ConnectionTracker>>,
	pub secret: String,
	pub users: HashMap<Uuid, String>,
}

/// Object-safe interface for kicking connections. Implemented by
/// [`ActiveConnections`], which is the only registry wired to the live
/// connections' cancel tokens, and by [`NoopConnections`] when that registry is
/// disabled.
pub trait KickConnections: Send + Sync + 'static {
	fn kick_user(&self, user: &UserId) -> usize;
	fn count_for(&self, user: &UserId) -> usize;
	fn len(&self) -> usize;
	fn is_empty(&self) -> bool;
}

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

// Auth helper

/// Compare a caller-supplied token against the configured secret without
/// revealing, through execution time, where the two first differ.
///
/// `==` on byte strings is free to stop at the first mismatching byte, so the
/// response latency of an unauthenticated request would depend on the length of
/// the shared prefix between the guess and the secret — enough to recover the
/// secret byte by byte. This loop instead folds every byte into one accumulator
/// and inspects it only at the end.
///
/// Lengths are compared up front and are **not** hidden: the token is
/// attacker-supplied, so its length is the attacker's own input, and this
/// matches the slice semantics of `subtle`'s `ConstantTimeEq`. The result goes
/// through `black_box` so the optimizer cannot rewrite the loop back into an
/// early-exiting `memcmp`.
fn constant_time_eq(candidate: &[u8], secret: &[u8]) -> bool {
	if candidate.len() != secret.len() {
		return false;
	}
	let mut diff = 0u8;
	for (candidate_byte, secret_byte) in candidate.iter().zip(secret.iter()) {
		diff |= candidate_byte ^ secret_byte;
	}
	std::hint::black_box(diff) == 0
}

/// Whether a listener on `addr` with `secret` would answer management requests
/// from the network without asking for credentials.
///
/// An empty secret deliberately disables authentication on every endpoint (see
/// the documented default of `restful.secret`). That is only safe while the
/// socket stays on this host, so a wildcard or routable local address turns
/// `/kick` and `/reset_traffic` into unauthenticated remote controls. The
/// check uses the **bound** address and treats anything that is not a loopback
/// address as exposed; an IPv4-mapped loopback address is conservatively
/// reported too, which is fail-loud rather than fail-open.
fn unauthenticated_and_exposed(addr: SocketAddr, secret: &str) -> bool {
	secret.is_empty() && !addr.ip().is_loopback()
}

fn is_authorized(headers: &HeaderMap, secret: &str) -> bool {
	if secret.is_empty() {
		return true;
	}
	let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
		return false;
	};
	if let Some(token) = auth.strip_prefix("Bearer ") {
		constant_time_eq(token.as_bytes(), secret.as_bytes())
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

/// POST /reset_traffic — reset & return per-user traffic deltas.
///
/// Registered as `POST` because the handler mutates state
/// (`StatsCollector::reset_all` drains the per-user counters): a `GET` would
/// let any intermediary, prefetcher, or crawler zero the traffic accounting
/// without the operator's intent.
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
///
/// Reports the outcome through `bound_addr`: the actually bound address on
/// success, or the bind failure. The bind failure is published *before* the
/// error is returned so a caller that is waiting on the channel learns that the
/// management API is not coming up instead of seeing it silently disappear.
pub async fn serve(
	state: Arc<RestfulState>,
	addr: SocketAddr,
	cancel: CancellationToken,
	bound_addr: Option<RestfulAddrTx>,
) -> eyre::Result<()> {
	let app = Router::new()
		.route("/kick", post(kick_handler))
		.route("/online", get(online_handler))
		.route("/detailed_online", get(detailed_online_handler))
		.route("/traffic", get(traffic_handler))
		.route("/reset_traffic", post(reset_traffic_handler))
		.with_state(Arc::clone(&state));

	let listener = tokio::select! {
		_ = cancel.cancelled() => {
			return Ok(());
		}
		res = tokio::net::TcpListener::bind(addr) => {
			match res {
				Ok(l) => l,
				Err(e) => {
					warn!("RESTful API failed to bind to {addr}: {e}");
					let reason: Arc<str> = Arc::from(format!("failed to bind RESTful API to {addr}: {e}").as_str());
					if let Some(tx) = bound_addr.as_ref() {
						tx.send_replace(Some(Err(reason)));
					}
					return Err(eyre::eyre!("failed to bind RESTful API: {e}"));
				}
			}
		}
	};

	let bound = listener.local_addr()?;
	if let Some(tx) = bound_addr.as_ref() {
		let _ = tx.send_replace(Some(Ok(bound)));
	}

	if unauthenticated_and_exposed(bound, &state.secret) {
		warn!(
			"RESTful API is listening on {bound} with an empty secret: /kick and /reset_traffic accept unauthenticated \
			 requests from the network; set restful.secret or bind restful.addr to a loopback address"
		);
	}

	// Log the socket the OS actually gave us, not the configured one: with
	// `restful.addr = "...:0"` the configured port is 0 and tells the operator
	// nothing about where the management API listens.
	warn!("RESTful API server started, listening on {bound}");
	axum::serve(listener, app)
		.with_graceful_shutdown(async move { cancel.cancelled().await })
		.await
		.map_err(|e| eyre::eyre!("RESTful API server error: {e}"))?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use std::{fmt, net::SocketAddr, sync::Mutex};

	use axum::{
		body::Body,
		http::{Request, StatusCode},
	};
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

	/// Records every kick and returns a count the caller chooses, so a test can
	/// tell the injected registry's answer apart from the tracker's own number
	/// of live entries. `ConnectionTracker` deliberately does not implement
	/// `KickConnections`: it cannot cancel a live connection (it never receives
	/// the connection's cancel token), so exposing it as a kick handle would
	/// make `/kick` report a nonzero count while nothing was closed.
	struct RecordingKicks {
		kicked: Mutex<Vec<UserId>>,
		report: usize,
	}

	impl KickConnections for RecordingKicks {
		fn kick_user(&self, user: &UserId) -> usize {
			self.kicked.lock().unwrap().push(user.clone());
			self.report
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

	#[tokio::test]
	async fn test_kick_handler_delegates_to_injected_registry() {
		let target = Uuid::from_u128(0x1234);
		let registry = Arc::new(RecordingKicks {
			kicked: Mutex::new(Vec::new()),
			report: 7,
		});
		let state = make_state(registry.clone(), "", HashMap::new());
		let app = build_router(state);

		let response = app
			.oneshot(
				Request::builder()
					.uri("/kick")
					.method("POST")
					.header("content-type", "application/json")
					.body(Body::from(serde_json::to_string(&vec![target]).unwrap()))
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
		let v: Value = serde_json::from_slice(&body).unwrap();
		// The reported count is the registry's, not the tracker's.
		assert_eq!(v, json!({"kicked": 7}));
		assert_eq!(registry.kicked.lock().unwrap().as_slice(), [UserId::from(target)]);
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

	#[test]
	fn test_auth_rejects_equal_length_near_misses() {
		// Same length as the secret, differing only in the first / last byte:
		// the two cases a prefix-timing attack steers towards. Both must be
		// rejected, and the rejection must not come from the prefix check.
		for guess in ["Bearer Xy-secret-token", "Bearer my-secret-tokeX"] {
			let mut headers = HeaderMap::new();
			headers.insert("authorization", guess.parse().unwrap());
			assert_eq!(guess.len() - "Bearer ".len(), "my-secret-token".len());
			assert!(!is_authorized(&headers, "my-secret-token"), "accepted {guess}");
		}
		assert!(constant_time_eq(b"my-secret-token", b"my-secret-token"));
	}

	#[test]
	fn test_constant_time_eq_accepts_only_identical_byte_strings() {
		assert!(constant_time_eq(b"", b""));
		assert!(constant_time_eq(b"\x00\xff", b"\x00\xff"));
		// Equal length, single differing byte at either end.
		assert!(!constant_time_eq(b"secret", b"xecret"));
		assert!(!constant_time_eq(b"secret", b"secreu"));
		// One is a prefix of the other.
		assert!(!constant_time_eq(b"secret", b"secret-longer"));
		assert!(!constant_time_eq(b"secret-longer", b"secret"));
		assert!(!constant_time_eq(b"", b"s"));
	}

	#[test]
	fn test_empty_secret_is_only_tolerated_on_loopback() {
		let loopback = ["127.0.0.1:13471".parse().unwrap(), "[::1]:13471".parse().unwrap()];
		let exposed: [SocketAddr; 3] = [
			"0.0.0.0:13471".parse().unwrap(),
			"[::]:13471".parse().unwrap(),
			"192.0.2.10:13471".parse().unwrap(),
		];

		for addr in loopback {
			assert!(
				!unauthenticated_and_exposed(addr, ""),
				"loopback listener {addr} with an empty secret must not be reported"
			);
			assert!(!unauthenticated_and_exposed(addr, "s3cret"));
		}
		for addr in exposed {
			assert!(
				unauthenticated_and_exposed(addr, ""),
				"listener {addr} reachable from the network with an empty secret must be reported"
			);
			assert!(
				!unauthenticated_and_exposed(addr, "s3cret"),
				"a configured secret must silence the report for {addr}"
			);
		}
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
			.route("/reset_traffic", axum::routing::post(reset_traffic_handler))
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
					.method("POST")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
		assert_eq!(&body[..], b"{}");
	}

	/// `/reset_traffic` drains the traffic counters, so it must not be
	/// reachable through a safe method: a `GET` (or any other non-`POST`
	/// method) must be rejected by the router with `405 Method Not
	/// Allowed`.
	#[tokio::test]
	async fn test_reset_traffic_state_change_requires_post() {
		let state = Arc::new(RestfulState {
			active: Arc::new(NoopConnections),
			stats: None,
			tracker: None,
			secret: String::new(),
			users: HashMap::new(),
		});

		for method in ["GET", "HEAD", "DELETE", "PUT"] {
			let response = build_router(state.clone())
				.oneshot(
					Request::builder()
						.uri("/reset_traffic")
						.method(method)
						.body(Body::empty())
						.unwrap(),
				)
				.await
				.unwrap();

			assert_eq!(
				response.status(),
				StatusCode::METHOD_NOT_ALLOWED,
				"{method} /reset_traffic must not be routed to the reset handler"
			);
		}

		let response = build_router(state)
			.oneshot(
				Request::builder()
					.uri("/reset_traffic")
					.method("POST")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
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

	// Bind-outcome reporting (`serve` → server core)

	#[tokio::test]
	async fn test_serve_publishes_bind_failure_instead_of_exiting_silently() {
		// Occupy a port so `serve` cannot bind it.
		let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let taken = blocker.local_addr().unwrap();

		let state = make_state(Arc::new(NoopConnections), "", HashMap::new());
		let (tx, mut rx) = restful_addr_channel();
		let err = serve(state, taken, CancellationToken::new(), Some(tx))
			.await
			.expect_err("binding an occupied port must fail");
		assert!(
			err.to_string().contains("failed to bind RESTful API"),
			"unexpected error: {err}"
		);

		let reported = rx
			.wait_for(|outcome| outcome.is_some())
			.await
			.expect("the failure must be reported on the channel, not only logged");
		match reported.as_ref() {
			Some(Err(reason)) => assert!(
				reason.contains("failed to bind RESTful API"),
				"unexpected reported reason: {reason}"
			),
			other => panic!("the channel must carry the bind failure, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_serve_publishes_the_actually_bound_address() {
		let state = make_state(Arc::new(NoopConnections), "", HashMap::new());
		let (tx, mut rx) = restful_addr_channel();
		let cancel = CancellationToken::new();
		let task = tokio::spawn(serve(state, "127.0.0.1:0".parse().unwrap(), cancel.clone(), Some(tx)));

		let reported = rx
			.wait_for(|outcome| outcome.is_some())
			.await
			.expect("a successful bind must be reported");
		match reported.as_ref() {
			Some(Ok(addr)) => {
				assert_ne!(addr.port(), 0, "the OS-assigned port must be reported, got {addr}");
				assert!(addr.ip().is_loopback(), "unexpected bind address {addr}");
			}
			other => panic!("expected the bound address, got {other:?}"),
		}

		cancel.cancel();
		task.await.unwrap().unwrap();
	}

	// Exposure reporting (empty secret on a non-loopback bind)

	/// Minimal `tracing` subscriber that keeps the message of every warning
	/// event, so a test can assert what `serve` told the operator without
	/// adding a dev-dependency.
	struct WarnCapture {
		warnings: Arc<Mutex<Vec<String>>>,
	}

	/// Records the `message` field of an event.
	#[derive(Default)]
	struct MessageField(Option<String>);

	impl tracing::field::Visit for MessageField {
		fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
			if field.name() == "message" {
				self.0 = Some(value.to_string());
			}
		}

		fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
			if field.name() == "message" {
				self.0 = Some(format!("{value:?}"));
			}
		}
	}

	impl tracing::Subscriber for WarnCapture {
		fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
			*metadata.level() == tracing::Level::WARN
		}

		fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::Id {
			tracing::Id::from_u64(1)
		}

		fn record(&self, _span: &tracing::Id, _values: &tracing::span::Record<'_>) {}

		fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}

		fn event(&self, event: &tracing::Event<'_>) {
			let mut field = MessageField::default();
			event.record(&mut field);
			if let (Some(message), Ok(mut warnings)) = (field.0, self.warnings.lock()) {
				warnings.push(message);
			}
		}

		fn enter(&self, _span: &tracing::Id) {}

		fn exit(&self, _span: &tracing::Id) {}
	}

	/// Run `serve` on `addr` with an empty secret while capturing warnings, and
	/// return everything it logged plus the address it actually bound. The task
	/// is cancelled and awaited before the log is read, so every warning it
	/// produced is in the result.
	async fn serve_with_captured_warnings(addr: SocketAddr) -> (Vec<String>, SocketAddr) {
		let warnings = Arc::new(Mutex::new(Vec::new()));
		let guard = tracing::subscriber::set_default(WarnCapture {
			warnings: Arc::clone(&warnings),
		});

		let state = make_state(Arc::new(NoopConnections), "", HashMap::new());
		let (tx, mut rx) = restful_addr_channel();
		let cancel = CancellationToken::new();
		let task = tokio::spawn(serve(state, addr, cancel.clone(), Some(tx)));
		let reported = rx
			.wait_for(|outcome| outcome.is_some())
			.await
			.expect("serve must report its listen socket");
		let bound = match reported.as_ref() {
			Some(Ok(bound)) => *bound,
			other => panic!("expected a successful bind, got {other:?}"),
		};
		cancel.cancel();
		task.await.unwrap().unwrap();

		drop(guard);
		let warnings = warnings.lock().map(|w| w.clone()).unwrap_or_default();
		(warnings, bound)
	}

	#[tokio::test]
	async fn test_serve_reports_an_unauthenticated_listener_reachable_from_the_network() {
		// The documented default — a loopback bind with no secret — stays
		// quiet.
		let (loopback, _) = serve_with_captured_warnings("127.0.0.1:0".parse().unwrap()).await;
		assert!(
			!loopback.iter().any(|warning| warning.contains("empty secret")),
			"a loopback listener must not be reported as exposed: {loopback:?}"
		);

		// Binding every interface with no secret is the combination an operator
		// has to hear about. The socket is bound but never contacted.
		let (wildcard, _) = serve_with_captured_warnings("0.0.0.0:0".parse().unwrap()).await;
		let report = wildcard
			.iter()
			.find(|warning| warning.contains("empty secret"))
			.unwrap_or_else(|| panic!("a wildcard listener with an empty secret must be reported: {wildcard:?}"));
		assert!(
			report.contains("0.0.0.0") && report.contains("restful.secret"),
			"the report must name the bound address and the fix: {report}"
		);
	}

	#[tokio::test]
	async fn test_startup_log_reports_the_actually_bound_address() {
		// `restful.addr` may ask for port 0; the operator has to be told the
		// port the OS picked, otherwise a working management API looks
		// unreachable (the configured port is literally 0).
		let (warnings, bound) = serve_with_captured_warnings("127.0.0.1:0".parse().unwrap()).await;
		assert_ne!(bound.port(), 0, "the OS must assign a real port");

		let started = warnings
			.iter()
			.find(|warning| warning.contains("RESTful API server started"))
			.unwrap_or_else(|| panic!("serve must log that it started: {warnings:?}"));
		assert!(
			started.contains(&bound.to_string()),
			"the startup log must name the bound address {bound}: {started}"
		);
	}
}
