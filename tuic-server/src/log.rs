use std::io;

use eyre::Context as _;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{Layer, fmt::time::LocalTime, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::config::{Config, LogConfig, LogFormat, LogRotation};

/// RAII guards that keep background tasks alive for the program's lifetime.
pub struct LogGuards {
	_file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Initialise tracing from [`Config`].
pub fn init(config: &Config) -> eyre::Result<LogGuards> {
	let filter = tracing_subscriber::filter::Targets::new()
		.with_targets(vec![
			("tuic", config.log_level),
			("tuic_quinn", config.log_level),
			("tuic_server", config.log_level),
		])
		.with_default(LevelFilter::INFO);

	let (file_writer, file_guard) = build_file_writer(&config.log)?;
	let writer = move || -> Box<dyn io::Write + Send> {
		match file_writer.as_ref() {
			Some(fw) => Box::new(TeeWriter {
				a: io::stdout(),
				b: fw.clone(),
			}),
			None => Box::new(io::stdout()),
		}
	};

	let timer = LocalTime::new(time::macros::format_description!(
		"[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
	));

	let fmt_layer: BoxedLayer<tracing_subscriber::Registry> = match config.log.format {
		LogFormat::Text if config.log.compact => tracing_subscriber::fmt::layer()
			.with_target(false)
			.with_thread_ids(false)
			.with_timer(timer)
			.with_writer(writer)
			.compact()
			.with_filter(filter)
			.boxed(),
		LogFormat::Text => tracing_subscriber::fmt::layer()
			.with_target(false)
			.with_thread_ids(false)
			.with_timer(timer)
			.with_writer(writer)
			.with_filter(filter)
			.boxed(),
		LogFormat::Json => tracing_subscriber::fmt::layer()
			.with_target(true)
			.with_timer(timer)
			.with_writer(writer)
			.json()
			.with_current_span(true)
			.with_span_list(false)
			.with_filter(filter)
			.boxed(),
	};

	tracing_subscriber::registry()
		.with(fmt_layer)
		.try_init()
		.context("installing tracing subscriber")?;

	Ok(LogGuards { _file_guard: file_guard })
}

/// Build a cloneable, non-blocking file writer if `log_file` is set.
fn build_file_writer(
	t: &LogConfig,
) -> eyre::Result<(
	Option<tracing_appender::non_blocking::NonBlocking>,
	Option<tracing_appender::non_blocking::WorkerGuard>,
)> {
	let Some(path) = t.log_file.as_ref() else {
		return Ok((None, None));
	};

	let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).map(|p| p.to_owned());
	let file_name = path
		.file_name()
		.ok_or_else(|| eyre::eyre!("log.log_file must include a file name: {path:?}"))?
		.to_owned();
	let dir = dir.unwrap_or_else(|| std::path::PathBuf::from("."));

	if let Err(e) = std::fs::create_dir_all(&dir) {
		return Err(eyre::eyre!("creating log directory {dir:?}: {e}"));
	}

	let appender = match t.log_rotation {
		LogRotation::Never => tracing_appender::rolling::never(&dir, &file_name),
		LogRotation::Hourly => tracing_appender::rolling::hourly(&dir, &file_name),
		LogRotation::Daily => tracing_appender::rolling::daily(&dir, &file_name),
	};
	let (nb, guard) = tracing_appender::non_blocking(appender);
	Ok((Some(nb), Some(guard)))
}

/// Tee writer: writes to two sinks, returning the first error.
struct TeeWriter<A: io::Write, B: io::Write> {
	a: A,
	b: B,
}

impl<A: io::Write, B: io::Write> io::Write for TeeWriter<A, B> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		let n = self.a.write(buf)?;
		let _ = self.b.write_all(&buf[..n]);
		Ok(n)
	}

	fn flush(&mut self) -> io::Result<()> {
		let r = self.a.flush();
		let _ = self.b.flush();
		r
	}
}

type BoxedLayer<S> = Box<dyn Layer<S> + Send + Sync>;
