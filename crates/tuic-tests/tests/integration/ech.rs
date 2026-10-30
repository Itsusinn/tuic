//! Reject invalid ECH configurations and handshakes without downgrading.
#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]

use std::time::Duration;

#[path = "../support/ech.rs"]
mod fixture;
use fixture::ech_files;
use tokio::time::timeout;
use tuic_tests::{Backend, install_crypto_provider, quiche_server_config, tuic_client_config};
use uuid::Uuid;

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::test]
async fn ech_quiche_rejection_never_falls_back() -> eyre::Result<()> {
	rejection_never_falls_back(Backend::Quiche).await
}

#[cfg(feature = "aws-lc-rs")]
#[tokio::test]
async fn ech_quinn_rejection_never_falls_back() -> eyre::Result<()> {
	rejection_never_falls_back(Backend::Quinn).await
}

#[cfg(feature = "aws-lc-rs")]
#[tokio::test]
async fn ech_quinn_still_verifies_certificate_and_inner_name() -> eyre::Result<()> {
	install_crypto_provider();
	let dir = tempfile::tempdir()?;
	let (ech, list) = ech_files(dir.path(), 1)?;
	let cert = rcgen::generate_simple_self_signed(vec!["private.example".into()])?;
	let cert_path = dir.path().join("cert.pem");
	let key_path = dir.path().join("key.pem");
	std::fs::write(&cert_path, cert.cert.pem())?;
	std::fs::write(&key_path, cert.signing_key.serialize_pem())?;
	let uuid = Uuid::new_v4();
	let mut scfg = quiche_server_config("127.0.0.1:0".parse()?, dir.path().into(), uuid, "test", false);
	scfg.tls.ech = Some(ech);
	scfg.tls.self_sign = false;
	scfg.tls.certificate = cert_path.clone();
	scfg.tls.private_key = key_path;
	let server = timeout(DEADLINE, tuic_server::run(scfg)).await??;
	for (trust, name, should_connect) in [
		(false, "private.example", false),
		(true, "wrong.example", false),
		(true, "private.example", true),
	] {
		let mut cfg = tuic_client_config(server.local_addr.port(), 0, uuid, "test", false, Backend::Quinn);
		cfg.relay.disable_sni = false;
		cfg.relay.skip_cert_verify = false;
		cfg.relay.sni = Some(name.into());
		cfg.relay.ech_config_list = Some(list.clone());
		cfg.relay.lazy = false;
		if trust {
			cfg.relay.certificates = vec![cert_path.clone()];
		}
		let result = timeout(DEADLINE, tuic_client::run(cfg)).await?;
		assert_eq!(
			result.is_ok(),
			should_connect,
			"certificate trust and inner name must both match"
		);
		if let Ok(client) = result {
			client.shutdown().await;
		}
	}
	server.shutdown().await;
	Ok(())
}

async fn rejection_never_falls_back(backend: Backend) -> eyre::Result<()> {
	install_crypto_provider();
	let dir = tempfile::tempdir()?;
	let (ech, good_list) = ech_files(dir.path(), 1)?;
	let (_, stale_list) = ech_files(dir.path(), 2)?;
	let uuid = Uuid::new_v4();
	let mut scfg = quiche_server_config("127.0.0.1:0".parse()?, dir.path().into(), uuid, "test", false);
	scfg.tls.ech = Some(ech);
	let server = timeout(DEADLINE, tuic_server::run(scfg)).await??;
	let malformed = dir.path().join("malformed.list");
	std::fs::write(&malformed, [0, 8, 1])?;
	let unsupported = dir.path().join("unsupported.list");
	std::fs::write(&unsupported, [0, 4, 0xfa, 0xfa, 0, 0])?;
	let empty = dir.path().join("empty.list");
	std::fs::write(&empty, [0, 0])?;
	for list in [stale_list, malformed, unsupported, empty] {
		let mut cfg = tuic_client_config(server.local_addr.port(), 0, uuid, "test", false, backend);
		cfg.relay.disable_sni = false;
		cfg.relay.ech_config_list = Some(list);
		cfg.relay.lazy = false;
		assert!(
			timeout(DEADLINE, tuic_client::run(cfg)).await?.is_err(),
			"ECH failure must reject startup"
		);
	}
	server.shutdown().await;
	// An ordinary TLS server must not turn a mandatory ECH connection into plaintext SNI.
	let scfg = quiche_server_config("127.0.0.1:0".parse()?, dir.path().into(), uuid, "test", false);
	let server = timeout(DEADLINE, tuic_server::run(scfg)).await??;
	let mut cfg = tuic_client_config(server.local_addr.port(), 0, uuid, "test", false, backend);
	cfg.relay.disable_sni = false;
	cfg.relay.ech_config_list = Some(good_list);
	cfg.relay.lazy = false;
	assert!(timeout(DEADLINE, tuic_client::run(cfg)).await?.is_err());
	server.shutdown().await;
	Ok(())
}

#[tokio::test]
async fn ech_quiche_server_rejects_mismatched_key() -> eyre::Result<()> {
	install_crypto_provider();
	let dir = tempfile::tempdir()?;
	let (mut ech, _) = ech_files(dir.path(), 1)?;
	let (other, _) = ech_files(dir.path(), 2)?;
	ech.private_key = other.private_key;
	let mut cfg = quiche_server_config("127.0.0.1:0".parse()?, dir.path().into(), Uuid::new_v4(), "test", false);
	cfg.tls.ech = Some(ech);
	assert!(timeout(DEADLINE, tuic_server::run(cfg)).await?.is_err());
	Ok(())
}
