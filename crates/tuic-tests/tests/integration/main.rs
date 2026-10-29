//! Collaboration between selected endpoints, plugins and fixtures.

#[path = "../support/upstream_proxy.rs"]
pub mod proxy_fixture;
#[path = "../support/shutdown_config.rs"]
mod shutdown_fixture;
#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
#[path = "../support/tls.rs"]
mod tls_fixture_support;

mod echo;
mod graceful_shutdown;
mod guard_drop;
mod negative_handshake;
mod quiche_cert_reload;
mod quiche_zero_rtt_resumption;
mod quinn_zero_rtt_resumption;
mod shutdown_config;
mod test_helpers;
mod tls_fixture;
mod tls_options;
mod upstream_proxy;
