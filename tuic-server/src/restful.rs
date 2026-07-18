//! RESTful API for tuic-server management.
//!
//! Provides an HTTP API for querying online users, traffic statistics, and
//! kicking users, backed by wind's [`StatsCollector`], [`ActiveConnections`],
//! and [`ConnectionHooks`].
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

use std::{
	collections::HashMap,
	net::SocketAddr,
	sync::Arc,
};

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
	hooks::{ConnectDecision, ConnInfo, ConnectionHooks},
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

impl ConnectionTracker {
	pub fn new() -> Self {
		Self {
			inner: DashMap::new(),
		}
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
		let uuid_set: HashMap<&[u8], Uuid> = uuid_lookup
			.keys()
			.map(|u| (u.as_bytes().as_slice(), *u))
			.collect();

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
}

/// No-op implementation that always returns zero. Used as a fallback when
/// `ActiveConnections` is not available (e.g. per-user limit disabled).
pub struct NoopConnections;
#[async_trait]
impl KickConnections for NoopConnections {
	fn kick_user(&self, _user: &UserId) -> usize { 0 }
	fn count_for(&self, _user: &UserId) -> usize { 0 }
	fn len(&self) -> usize { 0 }
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
}

// ─── Auth helper ─────────────────────────────────────────────────────────────

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

// ─── Endpoints ───────────────────────────────────────────────────────────────

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
async fn online_handler(
	State(state): State<Arc<RestfulState>>,
	headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
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
async fn detailed_online_handler(
	State(state): State<Arc<RestfulState>>,
	headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
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
async fn traffic_handler(
	State(state): State<Arc<RestfulState>>,
	headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
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
		.iter()
		.map(|(uuid, _)| (uuid.as_bytes().to_vec(), uuid.to_string()))
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
async fn reset_traffic_handler(
	State(state): State<Arc<RestfulState>>,
	headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
	if !is_authorized(&headers, &state.secret) {
		return unauthorized();
	}
	let Some(stats) = &state.stats else {
		return (StatusCode::OK, Json(json!({})));
	};
	let batch = stats.reset_all();
	let uuid_map: HashMap<Vec<u8>, String> = state
		.users
		.iter()
		.map(|(uuid, _)| (uuid.as_bytes().to_vec(), uuid.to_string()))
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
