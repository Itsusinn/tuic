use tuic_server::{Config, TuicServerPlugin};
use wind_core::App;

#[tokio::test]
async fn invalid_outbound_type_fails_plugin_startup() -> eyre::Result<()> {
	for named in [false, true] {
		let mut cfg = Config::default();
		let mut rule = cfg.outbound.default.clone();
		rule.kind = "sock5".into();
		if named {
			cfg.outbound.named.insert("upstream".into(), rule);
		} else {
			cfg.outbound.default = rule;
		}
		let error = App::new()
			.add_plugin(TuicServerPlugin::new(cfg))
			.await
			.err()
			.ok_or_else(|| eyre::eyre!("invalid outbound accepted"))?;
		assert!(error.to_string().contains("unknown type"));
	}
	Ok(())
}

#[tokio::test]
async fn missing_geodata_fails_plugin_before_listening() -> eyre::Result<()> {
	let dir = tempfile::tempdir()?;
	let mut cfg = Config::default();
	cfg.geodata.geosite = Some(dir.path().join("missing-site.dat"));
	cfg.geodata.geoip = Some(dir.path().join("missing-ip.dat"));
	let error = App::new()
		.add_plugin(TuicServerPlugin::new(cfg))
		.await
		.err()
		.ok_or_else(|| eyre::eyre!("missing database accepted"))?;
	assert!(error.to_string().contains("read geosite database"));
	Ok(())
}
