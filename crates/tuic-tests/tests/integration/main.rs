//! Collaboration between selected endpoints, plugins and fixtures.

#[path = "../support/upstream_proxy.rs"]
pub mod proxy_fixture;
#[path = "../support/shutdown_config.rs"]
mod shutdown_fixture;
#[path = "../support/tls.rs"]
mod tls_fixture_support;

#[cfg(not(target_arch = "loongarch64"))]
mod ech;
mod echo;
mod graceful_shutdown;
mod guard_drop;
mod negative_handshake;
#[cfg(not(target_arch = "loongarch64"))]
mod quiche_cert_reload;
#[cfg(not(target_arch = "loongarch64"))]
mod quiche_zero_rtt_resumption;
mod quinn_zero_rtt_resumption;
mod shutdown_config;
mod test_helpers;
mod tls_fixture;
mod tls_options;
mod upstream_proxy;
