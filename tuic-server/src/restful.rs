use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    ops::Deref,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};

use arc_swap::ArcSwap;
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
use chashmap::CHashMap;
use quinn::{Connection as QuinnConnection, VarInt};
use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use crate::AppContext;

static ONLINE_COUNTER: LazyLock<ArcSwap<HashMap<Uuid, AtomicU64>>> =
    LazyLock::new(ArcSwap::default);
static ONLINE_CLIENTS: LazyLock<CHashMap<Uuid, HashSet<QuicClient>>> = LazyLock::new(CHashMap::new);
static TRAFFIC_STATS: LazyLock<ArcSwap<HashMap<Uuid, (AtomicU64, AtomicU64)>>> =
    LazyLock::new(ArcSwap::default); // (tx, rx)

#[derive(Clone)]
struct QuicClient(QuinnConnection);
impl Deref for QuicClient {
    type Target = QuinnConnection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<QuinnConnection> for QuicClient {
    fn from(value: QuinnConnection) -> Self {
        Self(value)
    }
}
impl std::hash::Hash for QuicClient {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.stable_id().hash(state);
    }
}
impl PartialEq for QuicClient {
    fn eq(&self, other: &Self) -> bool {
        self.0.stable_id() == other.0.stable_id()
    }
}
impl Eq for QuicClient {}

pub async fn start(ctx: Arc<AppContext>) {
    let mut online = HashMap::new();
    for (user, _) in ctx.cfg.users.iter() {
        online.insert(user.to_owned(), AtomicU64::new(0));
    }

    let mut traffic = HashMap::new();
    for (user, _) in ctx.cfg.users.iter() {
        traffic.insert(user.to_owned(), (AtomicU64::new(0), AtomicU64::new(0)));
    }

    ONLINE_COUNTER.swap(Arc::new(online));
    TRAFFIC_STATS.swap(Arc::new(traffic));

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
        && restful.secret == ""
        && restful.secret != token.token()
    {
        return StatusCode::UNAUTHORIZED;
    }
    for user in users {
        if let Some(list) = ONLINE_CLIENTS.get(&user).await {
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
) -> (StatusCode, Json<HashMap<Uuid, u64>>) {
    if let Some(restful) = &ctx.cfg.restful
        && restful.secret == ""
        && restful.secret != token.token()
    {
        return (StatusCode::UNAUTHORIZED, Json(HashMap::new()));
    }
    let mut result = HashMap::new();
    for (user, count) in ONLINE_COUNTER.load().iter() {
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
        && restful.secret == ""
        && restful.secret != token.token()
    {
        return (StatusCode::UNAUTHORIZED, Json(HashMap::new()));
    }
    let mut result = HashMap::new();
    for (user, list) in ONLINE_CLIENTS.clone_locking().await.into_iter() {
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
        && restful.secret == ""
        && restful.secret != token.token()
    {
        return (StatusCode::UNAUTHORIZED, Json(HashMap::new()));
    }
    let mut result = HashMap::new();
    for (uuid, (tx, rx)) in TRAFFIC_STATS.load().iter() {
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
        && restful.secret == ""
        && restful.secret != token.token()
    {
        return (StatusCode::UNAUTHORIZED, Json(HashMap::new()));
    }
    let mut result = HashMap::new();
    for (uuid, (tx, rx)) in TRAFFIC_STATS.load().iter() {
        let tx = tx.swap(0, Ordering::Relaxed);
        let rx = rx.swap(0, Ordering::Relaxed);
        if tx != 0 || rx != 0 {
            result.insert(*uuid, json!({"tx": tx, "rx":rx}));
        }
    }

    (StatusCode::OK, Json(result))
}

pub async fn client_connect(ctx: &AppContext, uuid: &Uuid, conn: QuinnConnection) {
    if ctx.cfg.restful.is_none() {
        return;
    }
    let cfg = ctx.cfg.restful.as_ref().unwrap();
    let current = ONLINE_COUNTER
        .load()
        .get(uuid)
        .expect("Authorized UUID not present in users table")
        .fetch_add(1, Ordering::Release);
    if cfg.maximum_clients_per_user != 0 && current > cfg.maximum_clients_per_user {
        conn.close(
            VarInt::from_u32(6001),
            "Reached maximum clients limitation".as_bytes(),
        );
        return;
    }
    ONLINE_CLIENTS
        .upsert(*uuid, HashSet::new, |v| {
            v.insert(conn.into());
        })
        .await;
}
pub async fn client_disconnect(ctx: &AppContext, uuid: &Uuid, conn: QuinnConnection) {
    if ctx.cfg.restful.is_none() {
        return;
    }
    ONLINE_COUNTER
        .load()
        .get(uuid)
        .expect("Authorized UUID not present in users table")
        .fetch_sub(1, Ordering::SeqCst);
    if let Some(mut pair) = ONLINE_CLIENTS.get_mut(uuid).await {
        pair.remove(&conn.into());
    }
}

pub fn traffic_tx(ctx: &AppContext, uuid: &Uuid, size: u64) {
    if ctx.cfg.restful.is_none() {
        return;
    }
    if let Some((tx, _)) = TRAFFIC_STATS.load().get(uuid) {
        tx.fetch_add(size, Ordering::SeqCst);
    }
}

pub fn traffic_rx(ctx: &AppContext, uuid: &Uuid, size: u64) {
    if ctx.cfg.restful.is_none() {
        return;
    }
    if let Some((__, rx)) = TRAFFIC_STATS.load().get(uuid) {
        rx.fetch_add(size, Ordering::SeqCst);
    }
}
