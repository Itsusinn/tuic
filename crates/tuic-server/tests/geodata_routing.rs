//! GeoIP routing through the same `AclEngine` wiring `wind_adapter::TuicRouter`
//! uses: a `GEOIP,CN,reject` Metacubex rule fed via
//! `AclEngine::builder().rules()` plus a geodata database. Guards against the
//! geodata staying unwired (which would make geo rules a silent no-op /
//! fail-open).

use std::{net::Ipv4Addr, sync::Arc};

use geosite_rs::{Cidr, GeoIp, GeoIpList, GeoSiteList, encode_geoip, encode_geosite};
use wind_acl::AclEngine;
use wind_core::{RouteAction, Router, rule::Rule, types::TargetAddr};
use wind_geodata::GeoData;

fn ipv4(addr: &str, port: u16) -> TargetAddr {
	TargetAddr::IPv4(addr.parse::<Ipv4Addr>().unwrap(), port)
}

/// Build a geodata cache whose CN block is 1.2.3.0/24 (empty geosite).
fn build_geodata() -> (tempfile::TempPath, Arc<GeoData>) {
	let geoip = GeoIpList {
		entry: vec![GeoIp {
			country_code: "CN".to_string(),
			cidr: vec![Cidr {
				ip: [1, 2, 3, 0].to_vec(),
				prefix: 24,
			}],
			..Default::default()
		}],
	};
	let geosite = GeoSiteList { entry: vec![] };
	let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
	let geo = GeoData::build_and_open(&encode_geosite(geosite), &encode_geoip(geoip), &tmp).unwrap();
	(tmp, Arc::new(geo))
}

#[tokio::test]
async fn geoip_rule_routes_through_the_server_engine() {
	let (_tmp, geo) = build_geodata();

	// Mirror TuicRouter::new: raw wind rules (here a Metacubex GEOIP rule, as it
	// would arrive via `config.rules`) plus the geodata database.
	let engine = AclEngine::builder("direct")
		.rules([Rule::parse("GEOIP,CN,reject").unwrap()])
		.geodata(geo)
		.build()
		.unwrap();

	// 1.2.3.4 is in the CN block → rejected.
	let cn = engine.route(&ipv4("1.2.3.4", 443), true).await.unwrap();
	assert!(
		matches!(cn, RouteAction::Reject(_)),
		"CN IP should be rejected by GEOIP,CN,reject"
	);

	// 9.9.9.9 is outside CN → falls through to the default outbound.
	let other = engine.route(&ipv4("9.9.9.9", 443), true).await.unwrap();
	assert!(
		matches!(other, RouteAction::Forward(o) if o == "direct"),
		"non-CN IP should reach the default outbound"
	);
}

#[tokio::test]
async fn geoip_rule_is_noop_without_geodata() {
	// The exact same rule, but no database wired: it compiles yet cannot match,
	// so the CN IP falls through (documents the fail-open the startup warning
	// flags).
	let engine = AclEngine::builder("direct")
		.rules([Rule::parse("GEOIP,CN,reject").unwrap()])
		.build()
		.unwrap();

	let cn = engine.route(&ipv4("1.2.3.4", 443), true).await.unwrap();
	assert!(
		matches!(cn, RouteAction::Forward(o) if o == "direct"),
		"without geodata the GEOIP rule must not match"
	);
}
