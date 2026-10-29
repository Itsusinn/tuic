//! Complete application paths through public network entry points.

#[path = "../support/forward.rs"]
mod forward;
#[path = "../support/upstream_proxy.rs"]
pub mod proxy_fixture;

mod concurrency;
mod forwarding;
mod ipv6;
mod masquerade;
mod payload_sizes;
mod reconnect_quiche;
mod reconnect_quinn;
mod relay_semantics;
mod restful_traffic_stats;
mod udp_fragmentation_quiche;
mod udp_fragmentation_quinn;
mod upstream_proxy;
mod zero_rtt_config;
