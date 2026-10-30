//! SOCKS5 -> TUIC (Quinn or Quiche client) -> Quiche server with mandatory ECH.
#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]

use std::time::Duration;

#[path = "../support/ech.rs"]
mod fixture;
use fixture::ech_files;
use tokio::time::timeout;
use tokio_util::task::AbortOnDropHandle;
use tuic_tests::{
	Backend, install_crypto_provider, quiche_server_config, restful_request, run_tcp_echo_server, run_udp_echo_server,
	test_tcp_through_socks5, test_udp_through_socks5, tuic_client_config,
};
use uuid::Uuid;

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::test]
async fn ech_quiche_tcp_and_udp() -> eyre::Result<()> {
	ech_relay(Backend::Quiche, false).await
}

#[tokio::test]
async fn ech_quiche_with_resumption_enabled() -> eyre::Result<()> {
	ech_relay(Backend::Quiche, true).await
}

#[cfg(feature = "aws-lc-rs")]
#[tokio::test]
async fn ech_quiche_server_quinn_client_tcp_and_udp() -> eyre::Result<()> {
	ech_relay(Backend::Quinn, false).await
}

#[cfg(feature = "aws-lc-rs")]
#[tokio::test]
async fn ech_quiche_server_quinn_client_with_resumption_enabled() -> eyre::Result<()> {
	ech_relay(Backend::Quinn, true).await
}

async fn ech_relay(backend: Backend, zero_rtt: bool) -> eyre::Result<()> {
	install_crypto_provider();
	let dir = tempfile::tempdir()?;
	let (ech, list) = ech_files(dir.path(), 1)?;
	let uuid = Uuid::new_v4();
	let mut scfg = quiche_server_config("127.0.0.1:0".parse()?, dir.path().into(), uuid, "test", zero_rtt);
	scfg.tls.ech = Some(ech);
	// Quinn exercises certificate and inner-name verification, not just ECH
	// interoperability with verification disabled.
	let cert_path = dir.path().join("server.pem");
	if backend == Backend::Quinn {
		let cert = rcgen::generate_simple_self_signed(vec!["private.example".into()])?;
		let key_path = dir.path().join("server.key");
		std::fs::write(&cert_path, cert.cert.pem())?;
		std::fs::write(&key_path, cert.signing_key.serialize_pem())?;
		scfg.tls.self_sign = false;
		scfg.tls.certificate = cert_path.clone();
		scfg.tls.private_key = key_path;
	}
	scfg.restful.enabled = true;
	scfg.restful.addr = "127.0.0.1:0".parse()?;
	scfg.restful.secret = String::new();
	let server = timeout(DEADLINE, tuic_server::run(scfg)).await??;
	let mut ccfg = tuic_client_config(server.local_addr.port(), 0, uuid, "test", zero_rtt, backend);
	ccfg.relay.disable_sni = false;
	if backend == Backend::Quinn {
		ccfg.relay.skip_cert_verify = false;
		ccfg.relay.certificates = vec![cert_path];
	}
	ccfg.relay.sni = Some("private.example".into());
	ccfg.relay.ech_config_list = Some(list);
	ccfg.relay.lazy = false;
	ccfg.relay.reconnect_initial_backoff = Duration::from_millis(50);
	ccfg.relay.reconnect_max_backoff = Duration::from_millis(100);
	let client = timeout(DEADLINE, tuic_client::run(ccfg)).await??;
	let socks = client.socks5_addr.to_string();
	let (tcp, tcp_addr) = run_tcp_echo_server("127.0.0.1:0", "ech-tcp").await;
	let _tcp = AbortOnDropHandle::new(tcp);
	assert!(timeout(DEADLINE, test_tcp_through_socks5(&socks, tcp_addr, b"ech-tcp", "ech")).await?);
	let (udp, udp_addr, _socket) = run_udp_echo_server("127.0.0.1:0", "ech-udp").await;
	let _udp = AbortOnDropHandle::new(udp);
	assert!(
		timeout(
			DEADLINE,
			test_udp_through_socks5(&socks, udp_addr, b"ech-udp", "ech", "127.0.0.1:0".parse()?)
		)
		.await?
	);
	let restful = server.restful_addr.ok_or_else(|| eyre::eyre!("REST listener missing"))?;
	let response = timeout(
		DEADLINE,
		restful_request(restful, "POST", "/kick", Some(&format!("[\"{uuid}\"]"))),
	)
	.await?;
	let response: serde_json::Value = serde_json::from_str(&response)?;
	assert!(response["kicked"].as_u64().unwrap_or(0) > 0);
	timeout(DEADLINE, async {
		loop {
			let (task, addr) = run_tcp_echo_server("127.0.0.1:0", "ech-reconnect").await;
			let _task = AbortOnDropHandle::new(task);
			if test_tcp_through_socks5(&socks, addr, b"ech-reconnect", "ech-reconnect").await {
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	})
	.await?;
	client.shutdown().await;
	server.shutdown().await;
	Ok(())
}
