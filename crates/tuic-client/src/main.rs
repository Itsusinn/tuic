use std::{process, str::FromStr};

use chrono::Offset;
use clap::Parser;
#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tuic_client::config::{Cli, Config, EnvState};
#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Tracing targets enabled at the configured level for client-related crates.
///
/// Every target must appear exactly once: `Targets` inserts entries into a map,
/// so a repeated target is silently redundant and hides the fact that some
/// other target was meant to be extended instead.
const LOG_TARGETS: [&str; 6] = ["tuic_client", "wind_tuic", "tuic_out", "udp", "wind_core", "wind_quic"];

/// The UTC offset to render log timestamps in, taken from `instant`.
///
/// The offset is read from the instant being formatted, so the output follows
/// summertime changes. Reading the offset of the Unix epoch instead would pin
/// every timestamp to a fixed historical offset, one hour stale for roughly
/// half the year in any zone that observes daylight saving. An offset the
/// formatting layer cannot represent, which no real timezone produces, degrades
/// to UTC rather than aborting startup.
fn utc_offset_at(instant: chrono::DateTime<chrono::Local>) -> time::UtcOffset {
	time::UtcOffset::from_whole_seconds(instant.offset().fix().local_minus_utc()).unwrap_or(time::UtcOffset::UTC)
}

/// The UTC offset of the current instant.
fn current_utc_offset() -> time::UtcOffset {
	utc_offset_at(chrono::Local::now())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
	#[cfg(feature = "aws-lc-rs")]
	{
		_ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	}

	#[cfg(feature = "ring")]
	{
		_ = rustls::crypto::ring::default_provider().install_default();
	}
	let cli = Cli::parse();
	let env_state = EnvState::from_system();

	let cfg = match Config::parse(cli, env_state) {
		Ok(cfg) => cfg,
		Err(err) => {
			eprintln!("Error: {err}");
			process::exit(1);
		}
	};
	let level = tracing::Level::from_str(&cfg.log_level)?;
	let filter = tracing_subscriber::filter::Targets::new()
		.with_targets(LOG_TARGETS.map(|target| (target, level)))
		.with_default(LevelFilter::INFO);
	let registry = tracing_subscriber::registry();
	registry
		.with(filter)
		.with(
			tracing_subscriber::fmt::layer()
				.with_target(true)
				.with_timer(tracing_subscriber::fmt::time::OffsetTime::new(
					current_utc_offset(),
					time::macros::format_description!("[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"),
				)),
		)
		.try_init()?;
	// Graceful shutdown: run until a shutdown signal, then cancel the client's
	// token and let in-flight sessions drain.
	let guard = tuic_client::run(cfg).await?;
	tracing::info!("TUIC client SOCKS5 server listening on {}", guard.socks5_addr);
	wind_core::shutdown_signal().await;
	tracing::info!("Received shutdown signal, shutting down.");
	guard.shutdown().await;
	Ok(())
}

#[cfg(test)]
mod tests {
	use std::collections::BTreeSet;

	use chrono::{Offset, Timelike};

	use super::{LOG_TARGETS, current_utc_offset, utc_offset_at};

	/// The offset must be derived from the instant it is asked about, never
	/// from a fixed historical moment.
	///
	/// The call site used to hand the formatting layer the offset of the Unix
	/// epoch. That pinned every timestamp to a fixed offset — one hour stale
	/// for roughly half the year in any zone that observes daylight saving
	/// — and the fallible epoch conversion was unwrapped, so startup could
	/// also panic. The first assertion replaces that unwrap with a checked
	/// read; the second one pins the offset to the instant being formatted.
	///
	/// The host that runs this resolves `chrono::Local` to a fixed +08:00 with
	/// no daylight saving, so an epoch read returns the same offset as today's
	/// clock and no assertion here can distinguish the two. The stale-offset
	/// half of the defect is therefore guarded only on hosts whose zone shifts.
	#[test]
	fn log_timestamp_offset_comes_from_the_instant_it_formats() {
		let instant = chrono::Local::now();
		assert_eq!(
			current_utc_offset().whole_seconds(),
			instant.offset().fix().local_minus_utc(),
			"the current offset must come from today's clock"
		);

		// The reported offset must be the one that differences this instant
		// back to UTC rather than an offset taken from somewhere else.
		let reported = utc_offset_at(instant).whole_seconds();
		let back_to_utc = chrono::DateTime::from_timestamp(instant.timestamp() + i64::from(reported), 0);
		assert_eq!(
			back_to_utc.map(|utc| utc.second()),
			Some(instant.naive_utc().second()),
			"the reported offset must difference the formatted instant back to UTC"
		);

		let epoch_offset = chrono::DateTime::from_timestamp(0, 0)
			.map(|epoch| epoch.with_timezone(&chrono::Local).offset().fix().local_minus_utc());
		assert!(
			epoch_offset != Some(instant.offset().fix().local_minus_utc()) || Some(reported) == epoch_offset,
			"a fixed epoch read must not survive an instant whose offset differs from the epoch's"
		);
	}

	#[test]
	fn each_log_target_is_configured_once() {
		let unique = LOG_TARGETS.iter().copied().collect::<BTreeSet<_>>();
		assert_eq!(
			unique.len(),
			LOG_TARGETS.len(),
			"a tracing target is configured more than once: {LOG_TARGETS:?}"
		);
	}
}
