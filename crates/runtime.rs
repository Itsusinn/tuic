//! Application task ownership, including the fallible startup phase.

use std::{future::Future, sync::Arc, time::Duration};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wind_core::AppContext;

pub(crate) struct Runtime {
	ctx: Arc<AppContext>,
	run_task: Option<JoinHandle<eyre::Result<()>>>,
	bridge: JoinHandle<()>,
}

impl Runtime {
	/// Establish ownership before plugin construction can spawn any tasks.
	pub(crate) fn new(ctx: Arc<AppContext>, cancel: CancellationToken) -> Self {
		if cancel.is_cancelled() {
			ctx.token.cancel();
		}
		let app_token = ctx.token.clone();
		let bridge = tokio::spawn(async move {
			tokio::select! {
				_ = cancel.cancelled() => app_token.cancel(),
				_ = app_token.cancelled() => {},
			}
		});
		Self {
			ctx,
			run_task: None,
			bridge,
		}
	}

	pub(crate) fn start(&mut self, run: impl Future<Output = eyre::Result<()>> + Send + 'static) {
		self.run_task = Some(tokio::spawn(run));
	}

	/// Consume a completed handle so cleanup never polls it a second time.
	async fn join_run(&mut self) -> Option<Result<eyre::Result<()>, tokio::task::JoinError>> {
		let result = self.run_task.as_mut()?.await;
		self.run_task.take();
		Some(result)
	}

	pub(crate) async fn exited(&mut self, application: &str) -> eyre::Report {
		match self.join_run().await {
			Some(Ok(Err(error))) => error,
			Some(Err(error)) => eyre::eyre!("{application} task failed: {error}"),
			_ => eyre::eyre!("{application} exited before reporting its bound address"),
		}
	}

	pub(crate) async fn bound_address<T: Clone>(
		&mut self,
		receiver: &mut tokio::sync::watch::Receiver<Option<T>>,
		application: &str,
	) -> eyre::Result<T> {
		let token = self.ctx.token.clone();
		tokio::select! {
			result = receiver.wait_for(|address| address.is_some()) => {
				let address = result.map_err(|_| eyre::eyre!("{application} exited before reporting its bound address"))?;
				address.clone().ok_or_else(|| eyre::eyre!("{application} did not report its bound address"))
			},
			error = self.exited(application) => Err(error),
			_ = token.cancelled() => Err(eyre::eyre!("{application} startup cancelled")),
		}
	}

	/// Startup rollback and normal shutdown share one total drain budget.
	pub(crate) async fn shutdown(&mut self) {
		self.ctx.token.cancel();
		self.bridge.abort();
		self.ctx.tasks.close();
		if tokio::time::timeout(Duration::from_secs(10), async {
			let _ = self.join_run().await;
			self.ctx.tasks.wait().await;
		})
		.await
		.is_err()
		{
			if let Some(task) = &self.run_task {
				task.abort();
			}
		}
	}
}

impl Drop for Runtime {
	fn drop(&mut self) {
		// Dropping a startup future cannot await. Cancel tracked tasks
		// directly; aborting only App::run would detach its
		// independently spawned tasks.
		self.ctx.token.cancel();
		self.ctx.tasks.close();
		if let Some(task) = &self.run_task {
			task.abort();
		}
		self.bridge.abort();
	}
}

#[cfg(test)]
mod tests {
	use std::{future::pending, net::SocketAddr};

	use tokio::sync::oneshot;
	use wind_core::{App, Plugin, RouteAction, Router};

	use super::*;

	struct TestRouter;

	impl Router for TestRouter {
		async fn route(&self, _: &wind_core::FlowContext) -> eyre::Result<RouteAction> {
			Ok(RouteAction::Reject("test router".into()))
		}
	}

	struct BackgroundPlugin {
		bound: oneshot::Sender<SocketAddr>,
		fail: bool,
	}

	impl Plugin<TestRouter> for BackgroundPlugin {
		async fn build(self, app: App<TestRouter>) -> eyre::Result<App<TestRouter>> {
			// Like the REST API and eager outbound, this task is created before
			// App::run exists. Dropping App alone cannot release its socket.
			let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
			let address = socket.local_addr()?;
			let token = app.context().token.clone();
			app.context().tasks.spawn(async move {
				token.cancelled().await;
				drop(socket);
			});
			let _ = self.bound.send(address);
			if self.fail {
				Err(eyre::eyre!("test plugin failed after spawning a task"))
			} else {
				pending().await
			}
		}
	}

	async fn build(app: App<TestRouter>, cancel: CancellationToken, plugin: BackgroundPlugin) -> eyre::Result<()> {
		let mut runtime = Runtime::new(app.context().clone(), cancel);
		let result = app.add_plugin(plugin).await;
		runtime.shutdown().await;
		result.map(|_| ())
	}

	async fn released(address: SocketAddr) -> eyre::Result<()> {
		tokio::time::timeout(Duration::from_secs(5), async {
			loop {
				if std::net::UdpSocket::bind(address).is_ok() {
					break;
				}
				tokio::task::yield_now().await;
			}
		})
		.await?;
		Ok(())
	}

	#[tokio::test]
	async fn plugin_error_drains_build_tasks_without_cancelling_caller() -> eyre::Result<()> {
		let app = App::new();
		let ctx = app.context().clone();
		let cancel = CancellationToken::new();
		let (bound, address) = oneshot::channel();
		let result = tokio::time::timeout(
			Duration::from_secs(5),
			build(app, cancel.clone(), BackgroundPlugin { bound, fail: true }),
		)
		.await?;
		assert!(result.is_err());
		assert!(ctx.token.is_cancelled());
		assert!(!cancel.is_cancelled());
		assert!(ctx.tasks.is_empty());
		let _rebound = std::net::UdpSocket::bind(address.await?)?;
		Ok(())
	}

	#[tokio::test]
	async fn dropping_pending_plugin_build_releases_its_background_socket() -> eyre::Result<()> {
		let app = App::new();
		let ctx = app.context().clone();
		let cancel = CancellationToken::new();
		let (bound, address) = oneshot::channel();
		let mut startup = Box::pin(build(app, cancel.clone(), BackgroundPlugin { bound, fail: false }));
		let address = tokio::time::timeout(Duration::from_secs(5), async {
			tokio::select! {
				address = address => address.map_err(eyre::Report::from),
				result = &mut startup => Err(eyre::eyre!("pending startup completed unexpectedly: {result:?}")),
			}
		})
		.await??;
		drop(startup);
		assert!(ctx.token.is_cancelled());
		assert!(!cancel.is_cancelled());
		released(address).await
	}

	#[tokio::test]
	async fn aborting_pending_plugin_build_releases_its_background_socket() -> eyre::Result<()> {
		let app = App::new();
		let ctx = app.context().clone();
		let (bound, address) = oneshot::channel();
		let task = tokio::spawn(build(app, CancellationToken::new(), BackgroundPlugin { bound, fail: false }));
		let address = tokio::time::timeout(Duration::from_secs(5), address).await??;
		task.abort();
		let result = tokio::time::timeout(Duration::from_secs(5), task).await?;
		assert!(result.is_err());
		assert!(ctx.token.is_cancelled());
		released(address).await
	}

	#[tokio::test]
	async fn timing_out_pending_plugin_build_releases_its_background_socket() -> eyre::Result<()> {
		let app = App::new();
		let ctx = app.context().clone();
		let (bound, address) = oneshot::channel();
		let result = tokio::time::timeout(
			Duration::from_millis(20),
			build(app, CancellationToken::new(), BackgroundPlugin { bound, fail: false }),
		)
		.await;
		assert!(result.is_err());
		assert!(ctx.token.is_cancelled());
		released(address.await?).await
	}

	#[tokio::test]
	async fn completed_run_handle_is_not_polled_again_during_cleanup() -> eyre::Result<()> {
		let ctx = Arc::new(AppContext::default());
		let mut runtime = Runtime::new(ctx, CancellationToken::new());
		runtime.start(async { Err(eyre::eyre!("startup run failed")) });
		let (_sender, mut receiver) = tokio::sync::watch::channel(None::<SocketAddr>);
		let result = runtime.bound_address(&mut receiver, "test").await;
		assert!(result.is_err_and(|error| error.to_string() == "startup run failed"));
		runtime.shutdown().await;
		Ok(())
	}

	#[tokio::test]
	async fn cancellation_ends_an_open_address_handshake() -> eyre::Result<()> {
		let ctx = Arc::new(AppContext::default());
		let cancel = CancellationToken::new();
		let mut runtime = Runtime::new(ctx.clone(), cancel.clone());
		let token = ctx.token.clone();
		runtime.start(async move {
			token.cancelled().await;
			Ok(())
		});
		let (_sender, mut receiver) = tokio::sync::watch::channel(None::<SocketAddr>);
		cancel.cancel();
		let result = tokio::time::timeout(Duration::from_secs(5), runtime.bound_address(&mut receiver, "test")).await?;
		assert!(result.is_err());
		runtime.shutdown().await;
		Ok(())
	}
}
