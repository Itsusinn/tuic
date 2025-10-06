use std::{
    collections::{HashMap, HashSet},
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
use quinn::{Connection as QuinnConnection, VarInt};
use serde_json::json;
use tracing::warn;
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
        && restful.secret.is_empty()
        && restful.secret != token.token()
    {
        return StatusCode::UNAUTHORIZED;
    }
    for user in users {
        if let Some(list) = ctx.online_clients.get(&user).await {
            for client in list.iter() {
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
        && restful.secret.is_empty()
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
        && restful.secret.is_empty()
        && restful.secret != token.token()
    {
        return (StatusCode::UNAUTHORIZED, Json(HashMap::new()));
    }
    let mut result = HashMap::new();
    for (user, list) in ctx.online_clients.clone_locking().await.into_iter() {
        if list.is_empty() {
            continue;
        }
        result.insert(user, list.into_iter().map(|v| v.remote_address()).collect());
    }

    (StatusCode::OK, Json(result))
}

async fn list_traffic(
    State(ctx): State<Arc<AppContext>>,
    token: TypedHeader<Authorization<Bearer>>,
) -> (StatusCode, Json<HashMap<Uuid, serde_json::Value>>) {
    if let Some(restful) = &ctx.cfg.restful
        && restful.secret.is_empty()
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
        && restful.secret.is_empty()
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

pub async fn client_connect(ctx: &AppContext, uuid: &Uuid, conn: QuinnConnection) {
    let cfg = ctx.cfg.restful.as_ref().unwrap();
    let current = ctx
        .online_counter
        .get(uuid)
        .expect("Authorized UUID not present in users table")
        .fetch_add(1, Ordering::Release);
    if cfg.maximum_clients_per_user != 0 && current > cfg.maximum_clients_per_user {
        conn.close(
            VarInt::from_u32(6001),
            b"Reached maximum clients limitation",
        );
        return;
    }
    ctx.online_clients
        .upsert(*uuid, HashSet::new, |v| {
            v.insert(conn.into());
        })
        .await;
}
pub async fn client_disconnect(ctx: &AppContext, uuid: &Uuid, conn: QuinnConnection) {
    ctx.online_counter
        .get(uuid)
        .expect("Authorized UUID not present in users table")
        .fetch_sub(1, Ordering::SeqCst);
    if let Some(mut pair) = ctx.online_clients.get_mut(uuid).await {
        pair.remove(&conn.into());
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
