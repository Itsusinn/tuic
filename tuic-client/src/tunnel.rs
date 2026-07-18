//! Tunnel inbounds: re-exported from [`wind_base`].
//!
//! These are kept as a re-export for backward compatibility; new code should
//! import directly from `wind_base::tunnel`.

pub use wind_base::tunnel::{TunnelTcpInbound, TunnelUdpInbound};
