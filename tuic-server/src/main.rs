use std::{
    collections::{HashMap, HashSet},
    process,
    sync::{Arc, atomic::AtomicUsize},
};

use chashmap::CHashMap;
use config::{Config, parse_config};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::time::LocalTime, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use crate::{compat::QuicClient, old_config::ConfigError, server::Server};

mod acl;
mod compat;
mod config;
mod connection;
mod error;
mod io;
mod old_config;
mod restful;
mod server;
mod tls;
mod utils;

#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

struct AppContext {
    pub cfg: Config,
    pub online_counter: HashMap<Uuid, AtomicUsize>,
    pub online_clients: CHashMap<Uuid, HashSet<QuicClient>>,
    pub traffic_stats: HashMap<Uuid, (AtomicUsize, AtomicUsize)>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cfg = match parse_config(lexopt::Parser::from_env()).await {
        Ok(cfg) => cfg,
        Err(ConfigError::Version(msg) | ConfigError::Help(msg)) => {
            println!("{msg}");
            process::exit(0);
        }
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    };
    run(cfg).await
}

pub async fn run(cfg: Config) -> eyre::Result<()> {
    let mut online_counter = HashMap::new();
    for (user, _) in cfg.users.iter() {
        online_counter.insert(user.to_owned(), AtomicUsize::new(0));
    }

    let mut traffic_stats = HashMap::new();
    for (user, _) in cfg.users.iter() {
        traffic_stats.insert(user.to_owned(), (AtomicUsize::new(0), AtomicUsize::new(0)));
    }

    let ctx = Arc::new(AppContext {
        cfg,
        online_counter,
        online_clients: CHashMap::new(),
        traffic_stats,
    });

    let filter = tracing_subscriber::filter::Targets::new()
        .with_targets(vec![
            ("tuic", ctx.cfg.log_level),
            ("tuic_quinn", ctx.cfg.log_level),
            ("tuic_server", ctx.cfg.log_level),
        ])
        .with_default(LevelFilter::INFO);
    let registry = tracing_subscriber::registry();
    registry
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_timer(LocalTime::new(time::macros::format_description!(
                    "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
                ))),
        )
        .try_init()?;
    tokio::spawn(async move {
        match Server::init(ctx.clone()).await {
            Ok(server) => server.start().await,
            Err(err) => {
                eprintln!("{err}");
                process::exit(1);
            }
        }
    });
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for event");
    Ok(())
}
