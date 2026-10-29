//! Complete SOCKS/TUIC paths: remote DNS, recovery and TCP/UDP forwards.

use std::{sync::atomic::Ordering, time::Duration};

use tokio::task::JoinHandle;

use super::{
	forward,
	proxy_fixture::{LIMIT, Proxy, relay_for, server},
};

struct EchoTask(JoinHandle<()>);
impl Drop for EchoTask {
	fn drop(&mut self) {
		self.0.abort();
	}
}

async fn recover_client(client: &tuic_client::ClientGuard) -> eyre::Result<()> {
	tokio::time::timeout(LIMIT, async {
		loop {
			// The shared echo helper accepts one connection, so every retry
			// needs its own server instead of reusing the completed first one.
			let (task, addr) = tuic_tests::run_tcp_echo_server("127.0.0.1:0", "chain reconnect").await;
			let _echo = EchoTask(task);
			if tuic_tests::test_tcp_through_socks5(&client.socks5_addr.to_string(), addr, b"reconnected", "chain reconnect")
				.await
			{
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	})
	.await?;
	Ok(())
}

async fn full_client(mode: tuic_client::config::BackendMode, lazy: bool) -> eyre::Result<()> {
	let (server, cfg, _dir) = server().await?;
	let proxy = Proxy::start(server.local_addr, false).await?;
	let mut relay = relay_for(&cfg, proxy.config())?;
	relay.ip = None; // Only our proxy knows relay-test.invalid; local DNS must never run.
	relay.backend_mode = mode;
	relay.lazy = lazy;
	if mode == tuic_client::config::BackendMode::Quiche {
		relay.skip_cert_verify = true; // Quiche cannot load the temporary custom CA.
		relay.certificates.clear();
		relay.disable_native_certs = false;
	}
	let mut client_cfg = tuic_client::Config {
		relay,
		..Default::default()
	};
	client_cfg.local.server = "127.0.0.1:0".parse()?;
	let client = tokio::time::timeout(LIMIT, tuic_client::run(client_cfg)).await??;
	let (echo, addr) = tuic_tests::run_tcp_echo_server("127.0.0.1:0", "chained TCP").await;
	assert!(
		tokio::time::timeout(
			LIMIT,
			tuic_tests::test_tcp_through_socks5(&client.socks5_addr.to_string(), addr, b"through chain", "chain")
		)
		.await?
	);
	echo.abort();
	let (echo, addr, _guard) = tuic_tests::run_udp_echo_server("127.0.0.1:0", "chained UDP").await;
	assert!(
		tokio::time::timeout(
			LIMIT,
			tuic_tests::test_udp_through_socks5(
				&client.socks5_addr.to_string(),
				addr,
				b"through UDP chain",
				"chain",
				"127.0.0.1:0".parse()?
			)
		)
		.await?
	);
	echo.abort();
	assert!(proxy.packets.load(Ordering::SeqCst) > 0 && proxy.replies.load(Ordering::SeqCst) > 0);
	proxy.disconnect.notify_waiters();
	tokio::time::timeout(LIMIT, async {
		while proxy.associations.load(Ordering::SeqCst) < 2 {
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	})
	.await?;
	// Wait for UDP traffic to migrate to the new proxy association before
	// restarting the server, so its close notification reaches the client.
	recover_client(&client).await?;
	server.shutdown().await;
	let server = tokio::time::timeout(LIMIT, tuic_server::run(cfg)).await??;
	recover_client(&client).await?;
	client.shutdown().await;
	proxy.shutdown().await?;
	server.shutdown().await;
	Ok(())
}

#[tokio::test]
async fn quinn_chain_uses_remote_dns_for_eager_and_lazy_tcp_and_udp() -> eyre::Result<()> {
	for lazy in [false, true] {
		full_client(tuic_client::config::BackendMode::Quinn, lazy).await?;
	}
	Ok(())
}

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
#[tokio::test]
async fn quiche_chain_uses_remote_dns_for_eager_and_lazy_tcp_and_udp() -> eyre::Result<()> {
	for lazy in [false, true] {
		full_client(tuic_client::config::BackendMode::Quiche, lazy).await?;
	}
	Ok(())
}

async fn chained_forwards(mode: tuic_client::config::BackendMode, lazy: bool) -> eyre::Result<()> {
	let (server, cfg, _dir) = server().await?;
	let proxy = Proxy::start(server.local_addr, false).await?;
	let mut relay = relay_for(&cfg, proxy.config())?;
	// The proxy is the only resolver for this name: bypassing SOCKS cannot
	// accidentally turn a passing loopback test into a direct connection.
	relay.ip = None;
	relay.backend_mode = mode;
	relay.lazy = lazy;
	if mode == tuic_client::config::BackendMode::Quiche {
		relay.skip_cert_verify = true;
		relay.certificates.clear();
		relay.disable_native_certs = false;
	}
	let result = forward::exercise(tuic_client::Config {
		relay,
		..Default::default()
	})
	.await;
	let observed = proxy.associations.load(Ordering::SeqCst) > 0
		&& proxy.packets.load(Ordering::SeqCst) > 0
		&& proxy.replies.load(Ordering::SeqCst) > 0;
	let proxy_result = proxy.shutdown().await;
	server.shutdown().await;
	result?;
	proxy_result?;
	eyre::ensure!(observed, "configured SOCKS5 proxy did not carry the forward traffic");
	Ok(())
}

#[tokio::test]
async fn quinn_eager_socks_chain_tcp_udp_forward() -> eyre::Result<()> {
	chained_forwards(tuic_client::config::BackendMode::Quinn, false).await
}

#[tokio::test]
async fn quinn_lazy_socks_chain_tcp_udp_forward() -> eyre::Result<()> {
	chained_forwards(tuic_client::config::BackendMode::Quinn, true).await
}

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
#[tokio::test]
async fn quiche_eager_socks_chain_tcp_udp_forward() -> eyre::Result<()> {
	chained_forwards(tuic_client::config::BackendMode::Quiche, false).await
}

#[cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]
#[tokio::test]
async fn quiche_lazy_socks_chain_tcp_udp_forward() -> eyre::Result<()> {
	chained_forwards(tuic_client::config::BackendMode::Quiche, true).await
}
