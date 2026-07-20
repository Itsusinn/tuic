use std::{
	collections::HashMap,
	net::SocketAddr,
	sync::{Arc, atomic::Ordering},
};

use axum::{
	Json, Router,
	extract::State,
	http::StatusCode,
	routing::{get, post},
};
use axum_extra::{
	TypedHeader,
	headers::{Authorization, authorization::Bearer},
};
use moka::future::Cache;
use serde_json::json;
use tracing::warn;
use tuic_core::quinn::{QuinnConnection, VarInt};
use uuid::Uuid;

use crate::AppContext;

pub async fn start(ctx: Arc<AppContext>) {
	let restful = ctx.cfg.restful.as_ref().unwrap();
	let addr = restful.addr;
	let app = Router::new()
		.route("/kick", post(kick))
		.route("/online", get(list_online))
		.route("/detailed_online", get(list_detailed_online))
		.route("/traffic", get(list_traffic))
		.route("/reset_traffic", get(reset_traffic))
		.with_state(ctx);
	let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
	warn!("RESTful server started, listening on {addr}");
	axum::serve(listener, app).await.unwrap();
}

async fn kick(
	State(ctx): State<Arc<AppContext>>,
	token: TypedHeader<Authorization<Bearer>>,
	Json(users): Json<Vec<Uuid>>,
) -> StatusCode {
	if let Some(restful) = &ctx.cfg.restful
		&& !restful.secret.is_empty()
		&& restful.secret != token.token()
	{
		return StatusCode::UNAUTHORIZED;
	}
	for user in users {
		if let Some(cache) = ctx.online_clients.get(&user).await {
			for (_id, client) in cache.iter() {
				client.close(VarInt::from_u32(6002), "Client got kicked".as_bytes());
			}
		}
	}
	StatusCode::OK
}

async fn list_online(
	State(ctx): State<Arc<AppContext>>,
	token: TypedHeader<Authorization<Bearer>>,
) -> (StatusCode, Json<HashMap<Uuid, usize>>) {
	if let Some(restful) = &ctx.cfg.restful
		&& !restful.secret.is_empty()
		&& restful.secret != token.token()
	{
		return (StatusCode::UNAUTHORIZED, Json(HashMap::new()));
	}
	let mut result = HashMap::new();
	for (user, count) in ctx.online_counter.iter() {
		let count = count.load(Ordering::Relaxed);
		if count != 0 {
			result.insert(user.to_owned(), count);
		}
	}

	(StatusCode::OK, Json(result))
}

async fn list_detailed_online(
	State(ctx): State<Arc<AppContext>>,
	token: TypedHeader<Authorization<Bearer>>,
) -> (StatusCode, Json<HashMap<Uuid, Vec<SocketAddr>>>) {
	if let Some(restful) = &ctx.cfg.restful
		&& !restful.secret.is_empty()
		&& restful.secret != token.token()
	{
		return (StatusCode::UNAUTHORIZED, Json(HashMap::new()));
	}
	let mut result = HashMap::new();
	for (user, cache) in ctx.online_clients.iter() {
		let addrs: Vec<SocketAddr> = cache.iter().map(|(_, client)| client.remote_address()).collect();
		if addrs.is_empty() {
			continue;
		}
		result.insert(*user, addrs);
	}

	(StatusCode::OK, Json(result))
}

async fn list_traffic(
	State(ctx): State<Arc<AppContext>>,
	token: TypedHeader<Authorization<Bearer>>,
) -> (StatusCode, Json<HashMap<Uuid, serde_json::Value>>) {
	if let Some(restful) = &ctx.cfg.restful
		&& !restful.secret.is_empty()
		&& restful.secret != token.token()
	{
		return (StatusCode::UNAUTHORIZED, Json(HashMap::new()));
	}
	let mut result = HashMap::new();
	for (uuid, (tx, rx)) in ctx.traffic_stats.iter() {
		let tx = tx.load(Ordering::Relaxed);
		let rx = rx.load(Ordering::Relaxed);
		if tx != 0 || rx != 0 {
			result.insert(*uuid, json!({"tx": tx, "rx":rx}));
		}
	}

	(StatusCode::OK, Json(result))
}

async fn reset_traffic(
	State(ctx): State<Arc<AppContext>>,
	token: TypedHeader<Authorization<Bearer>>,
) -> (StatusCode, Json<HashMap<Uuid, serde_json::Value>>) {
	if let Some(restful) = &ctx.cfg.restful
		&& !restful.secret.is_empty()
		&& restful.secret != token.token()
	{
		return (StatusCode::UNAUTHORIZED, Json(HashMap::new()));
	}
	let mut result = HashMap::new();
	for (uuid, (tx, rx)) in ctx.traffic_stats.iter() {
		let tx = tx.swap(0, Ordering::Relaxed);
		let rx = rx.swap(0, Ordering::Relaxed);
		if tx != 0 || rx != 0 {
			result.insert(*uuid, json!({"tx": tx, "rx":rx}));
		}
	}

	(StatusCode::OK, Json(result))
}

pub async fn client_connect(ctx: &AppContext, uuid: &Uuid, conn: QuinnConnection) -> bool {
	let Some(cfg) = ctx.cfg.restful.as_ref() else {
		return true;
	};
	let Some(counter) = ctx.online_counter.get(uuid) else {
		warn!("UUID {uuid} not in users table during client_connect, closing connection");
		conn.close(VarInt::from_u32(6003), b"Internal error");
		return false;
	};

	loop {
		let current = counter.load(Ordering::Acquire);
		if cfg.maximum_clients_per_user != 0 && current >= cfg.maximum_clients_per_user {
			conn.close(VarInt::from_u32(6001), b"Reached maximum clients limitation");
			return false;
		}
		if counter
			.compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
			.is_ok()
		{
			break;
		}
	}

	let cap = if cfg.maximum_clients_per_user == 0 {
		10000
	} else {
		cfg.maximum_clients_per_user as u64
	};
	let cache = ctx.online_clients.get_with(*uuid, async { Arc::new(Cache::new(cap)) }).await;

	let client: crate::compat::QuicClient = conn.into();
	cache.insert(client.stable_id(), client).await;
	true
}
pub async fn client_disconnect(ctx: &AppContext, uuid: &Uuid, conn: QuinnConnection) {
	if let Some(counter) = ctx.online_counter.get(uuid) {
		if counter
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| current.checked_sub(1))
			.is_err()
		{
			warn!("UUID {uuid} online counter already zero during client_disconnect");
		}
	} else {
		warn!("UUID {uuid} not in users table during client_disconnect");
	}

	if let Some(cache) = ctx.online_clients.get(uuid).await {
		let client: crate::compat::QuicClient = conn.into();
		cache.invalidate(&client.stable_id()).await;
	}
}

pub fn traffic_tx(ctx: &AppContext, uuid: &Uuid, size: usize) {
	if let Some((tx, _)) = ctx.traffic_stats.get(uuid) {
		tx.fetch_add(size, Ordering::SeqCst);
	}
}

pub fn traffic_rx(ctx: &AppContext, uuid: &Uuid, size: usize) {
	if let Some((__, rx)) = ctx.traffic_stats.get(uuid) {
		rx.fetch_add(size, Ordering::SeqCst);
	}
}
