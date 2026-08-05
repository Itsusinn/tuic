//! Routing-decision tests for the tuic-server legacy ACL dialect.
//!
//! These parse the space-separated legacy ACL and lower it to
//! `wind_rule::Rule`s via [`acl_to_rules`] — the same lowering
//! `wind_adapter::TuicRouter` feeds into its router — then route through a
//! `wind_acl::AclEngine` built from those rules. `AclEngine` preserves the
//! same first-match-wins semantics as the legacy `AclRouter` (see
//! `tests/geodata_routing.rs` for another `AclEngine`-based routing test), so
//! these first-match assertions hold.

use std::net::Ipv4Addr;

use tuic_server::legacy::{acl_to_rules, parse_multiline_acl_string};
use wind_acl::AclEngine;
use wind_core::{
	FlowContext, RouteAction, Router,
	hooks::Protocol,
	rule::{NetworkType, Rule},
	types::TargetAddr,
};

fn ipv4(addr: &str, port: u16) -> TargetAddr {
	TargetAddr::IPv4(addr.parse::<Ipv4Addr>().unwrap(), port)
}

/// Minimal context; the `tcp` flag selects the network type.
fn fc(target: &TargetAddr, tcp: bool) -> FlowContext {
	FlowContext {
		target: target.clone(),
		network: if tcp { NetworkType::Tcp } else { NetworkType::Udp },
		source: None,
		inbound_tag: "tuic-test".into(),
		protocol: Protocol::Tuic,
		user: None,
		inbound_port: None,
		inbound_type: None,
	}
}

fn forwarded(action: &RouteAction) -> Option<&str> {
	match action {
		RouteAction::Forward(name) => Some(name.as_str()),
		RouteAction::Reject(_) => None,
	}
}

#[tokio::test]
async fn legacy_acl_compiles_and_matches() {
	// `reject` is a rejection keyword; `private` expands to RFC1918 + loopback
	// CIDRs.
	let acl = parse_multiline_acl_string("reject private\nproxy 1.1.1.1 tcp/443").unwrap();
	let engine = AclEngine::builder("direct").rules(acl_to_rules(&acl)).build().unwrap();

	// Private destination → rejected by the first ACL rule.
	let priv_action = engine.route(&fc(&ipv4("192.168.1.5", 1234), true)).await.unwrap();
	assert!(matches!(priv_action, RouteAction::Reject(_)));

	// 1.1.1.1:443/tcp → proxy.
	let proxy_action = engine.route(&fc(&ipv4("1.1.1.1", 443), true)).await.unwrap();
	assert_eq!(forwarded(&proxy_action), Some("proxy"));

	// 1.1.1.1:443/udp → no ACL match (tcp-only), falls through to default.
	let udp_action = engine.route(&fc(&ipv4("1.1.1.1", 443), false)).await.unwrap();
	assert_eq!(forwarded(&udp_action), Some("direct"));
}

#[tokio::test]
async fn legacy_acl_rules_precede_clash_rules() {
	// Both a legacy ACL rule and a Clash rule match 1.1.1.1. tuic-server places
	// converted legacy rules before explicit Clash rules, so first-match-wins
	// makes the legacy target ("aclwin") win.
	let acl = parse_multiline_acl_string("aclwin 1.1.1.1").unwrap();
	let clash = Rule::parse("IP-CIDR,1.1.1.1/32,clashwin").unwrap();

	let rules: Vec<Rule> = acl_to_rules(&acl).into_iter().chain(std::iter::once(clash)).collect();
	let engine = AclEngine::builder("direct").rules(rules).build().unwrap();

	let action = engine.route(&fc(&ipv4("1.1.1.1", 443), true)).await.unwrap();
	assert_eq!(forwarded(&action), Some("aclwin"));
}
