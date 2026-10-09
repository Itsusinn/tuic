//! Enforce server destination restrictions at the outbound boundary.

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use wind_core::{
	FlowContext, Outbound, Resolver,
	resolve::resolve_target_with_preference,
	tcp::AbstractTcpStream,
	types::TargetAddr,
	udp::UdpStream,
	utils::{StackPrefer, is_private_ip},
};

use crate::config::ExperimentalConfig;

pub(crate) fn check_destination(addr: SocketAddr, restrictions: &ExperimentalConfig) -> eyre::Result<()> {
	// IPv4-mapped IPv6 destinations reach the same host as their IPv4 form.
	let ip = addr.ip().to_canonical();
	if restrictions.drop_loopback && ip.is_loopback() {
		eyre::bail!("loopback address rejected: {addr}");
	}
	if restrictions.drop_private && is_private_ip(&ip) {
		eyre::bail!("private address rejected: {addr}");
	}
	Ok(())
}

pub(crate) struct GuardedOutbound {
	pub inner: Arc<dyn Outbound>,
	pub resolver: Arc<dyn Resolver>,
	pub ip_mode: Option<StackPrefer>,
	pub restrictions: ExperimentalConfig,
}

impl GuardedOutbound {
	async fn checked_target(&self, target: &TargetAddr) -> eyre::Result<TargetAddr> {
		let addr = resolve_target_with_preference(target, self.resolver.as_ref(), self.ip_mode).await?;
		check_destination(addr, &self.restrictions)?;
		// Hand the actual checked address to the outbound, preventing a second
		// DNS lookup (including remote DNS through SOCKS5) after the check.
		Ok(addr.into())
	}
}

#[async_trait]
impl Outbound for GuardedOutbound {
	async fn handle_tcp(&self, mut ctx: FlowContext, stream: Box<dyn AbstractTcpStream>) -> eyre::Result<()> {
		ctx.target = self.checked_target(&ctx.target).await?;
		self.inner.handle_tcp(ctx, stream).await
	}

	async fn handle_udp(&self, ctx: FlowContext, stream: UdpStream) -> eyre::Result<()> {
		let UdpStream { tx, mut rx } = stream;
		let (checked_tx, checked_rx) = tokio::sync::mpsc::channel(32);
		let forward = async move {
			while let Some(mut packet) = rx.recv().await {
				packet.target = match self.checked_target(&packet.target).await {
					Ok(target) => target,
					Err(error) => {
						tracing::debug!(target = %packet.target, %error, "dropping UDP destination");
						continue;
					}
				};
				if checked_tx.send(packet).await.is_err() {
					break;
				}
			}
		};
		let relay = self.inner.handle_udp(ctx, UdpStream { tx, rx: checked_rx });
		tokio::pin!(relay);
		// Both futures belong to the session: dropping it cancels all work.
		// If input closes first, drop checked_tx and let the handler drain its
		// queued packets; DirectOutbound exits when that receiver closes.
		tokio::select! {
			result = &mut relay => result,
			_ = forward => relay.await,
		}
	}
}

#[cfg(test)]
mod tests {
	use std::{
		future::Future,
		net::IpAddr,
		pin::Pin,
		sync::atomic::{AtomicUsize, Ordering},
		time::Duration,
	};

	use bytes::Bytes;
	use tokio::sync::{Mutex, mpsc};
	use wind_core::{hooks::Protocol, resolve::resolve_target, rule::NetworkType, udp::UdpPacket};

	use super::*;

	struct ChangingResolver {
		calls: AtomicUsize,
		first: IpAddr,
		later: IpAddr,
		all: Vec<IpAddr>,
	}

	impl Resolver for ChangingResolver {
		fn resolve<'a>(&'a self, _: &'a str) -> Pin<Box<dyn Future<Output = eyre::Result<IpAddr>> + Send + 'a>> {
			Box::pin(async move {
				Ok(if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
					self.first
				} else {
					self.later
				})
			})
		}

		fn resolve_all<'a>(&'a self, _: &'a str) -> Pin<Box<dyn Future<Output = eyre::Result<Vec<IpAddr>>> + Send + 'a>> {
			Box::pin(async move { Ok(self.all.clone()) })
		}
	}

	struct RecordingOutbound {
		seen: Mutex<Vec<TargetAddr>>,
		resolver: Arc<dyn Resolver>,
	}

	#[async_trait]
	impl Outbound for RecordingOutbound {
		async fn handle_tcp(&self, ctx: FlowContext, _: Box<dyn AbstractTcpStream>) -> eyre::Result<()> {
			let actual = resolve_target(&ctx.target, self.resolver.as_ref()).await?;
			self.seen.lock().await.push(actual.into());
			Ok(())
		}

		async fn handle_udp(&self, _: FlowContext, mut stream: UdpStream) -> eyre::Result<()> {
			while let Some(packet) = stream.rx.recv().await {
				let actual = resolve_target(&packet.target, self.resolver.as_ref()).await?;
				self.seen.lock().await.push(actual.into());
			}
			Ok(())
		}
	}

	fn context(target: TargetAddr) -> FlowContext {
		FlowContext {
			target,
			network: NetworkType::Tcp,
			source: None,
			inbound_tag: "destination-test".into(),
			protocol: Protocol::Tuic,
			user: None,
			inbound_port: None,
			inbound_type: None,
		}
	}

	fn resolver(first: &str, later: &str, all: &[&str]) -> eyre::Result<Arc<ChangingResolver>> {
		Ok(Arc::new(ChangingResolver {
			calls: AtomicUsize::new(0),
			first: first.parse()?,
			later: later.parse()?,
			all: all.iter().map(|ip| ip.parse()).collect::<Result<_, _>>()?,
		}))
	}

	fn guard(resolver: Arc<dyn Resolver>, ip_mode: Option<StackPrefer>) -> (GuardedOutbound, Arc<RecordingOutbound>) {
		let inner = Arc::new(RecordingOutbound {
			seen: Mutex::new(Vec::new()),
			resolver: resolver.clone(),
		});
		let guard = GuardedOutbound {
			inner: inner.clone(),
			resolver,
			ip_mode,
			restrictions: ExperimentalConfig::default(),
		};
		(guard, inner)
	}

	#[tokio::test]
	async fn selected_address_is_checked_without_rejecting_other_dns_records() -> eyre::Result<()> {
		let resolver = resolver("203.0.113.1", "127.0.0.1", &["203.0.113.1", "::1"])?;
		let target = TargetAddr::Domain("probe.invalid".into(), 443);
		let (v6, inner) = guard(resolver.clone(), Some(StackPrefer::V6only));
		let (_, stream) = tokio::io::duplex(1);
		let error = v6.handle_tcp(context(target.clone()), Box::new(stream)).await.err();
		assert!(error.is_some_and(|error| error.to_string().contains("loopback address rejected")));
		assert!(inner.seen.lock().await.is_empty());

		let (v4, inner) = guard(resolver, Some(StackPrefer::V4first));
		let (_, stream) = tokio::io::duplex(1);
		v4.handle_tcp(context(target), Box::new(stream)).await?;
		assert_eq!(
			*inner.seen.lock().await,
			vec![TargetAddr::from("203.0.113.1:443".parse::<SocketAddr>()?)]
		);
		Ok(())
	}

	#[tokio::test]
	async fn named_outbound_factory_blocks_real_loopback_and_disabled_guards_allow_it() -> eyre::Result<()> {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};
		use wind_core::{RouteAction, Router, rule::Rule};

		use crate::{
			config::OutboundRule,
			wind_adapter::{TuicRouter, make_guarded_outbound_action},
		};

		let listener = tokio::net::TcpListener::bind("[::1]:0").await?;
		let resolver = resolver("203.0.113.1", "203.0.113.1", &["203.0.113.1", "::1"])?;
		let target = TargetAddr::Domain("probe.invalid".into(), listener.local_addr()?.port());
		let rule = OutboundRule {
			ip_mode: Some(StackPrefer::V6only),
			..Default::default()
		};
		let cfg = crate::Config {
			rules: vec![Rule::parse("DOMAIN,probe.invalid,v6")?, Rule::parse("MATCH,default")?],
			..Default::default()
		};
		let router = TuicRouter::new(&cfg, resolver.clone(), None)?;
		assert!(matches!(router.route(&context(target.clone())).await?, RouteAction::Forward(name) if name == "v6"));
		let outbound = make_guarded_outbound_action(&rule, resolver.clone(), Duration::from_secs(1), &cfg.experimental);
		let (_, stream) = tokio::io::duplex(1);
		let result = tokio::time::timeout(
			Duration::from_secs(2),
			outbound.handle_tcp(context(target.clone()), Box::new(stream)),
		)
		.await?;
		assert!(result.is_err());
		assert!(
			tokio::time::timeout(Duration::from_millis(100), listener.accept())
				.await
				.is_err()
		);

		let restrictions = ExperimentalConfig {
			drop_loopback: false,
			drop_private: false,
		};
		let outbound = make_guarded_outbound_action(&rule, resolver, Duration::from_secs(1), &restrictions);
		let (mut client, stream) = tokio::io::duplex(1);
		let relay = outbound.handle_tcp(context(target), Box::new(stream));
		let echo = async {
			let (mut socket, _) = listener.accept().await?;
			let marker = socket.read_u8().await?;
			socket.write_all(&[marker]).await?;
			socket.shutdown().await?;
			Ok::<_, eyre::Report>(())
		};
		let exchange = async {
			client.write_all(&[42]).await?;
			assert_eq!(client.read_u8().await?, 42);
			client.shutdown().await?;
			Ok::<_, eyre::Report>(())
		};
		tokio::time::timeout(Duration::from_secs(2), async { tokio::try_join!(relay, echo, exchange) }).await??;
		Ok(())
	}

	#[tokio::test]
	async fn outbound_rechecks_dns_changes_after_routing_and_router_rejects_mapped_loopback() -> eyre::Result<()> {
		use wind_core::{RouteAction, Router};

		use crate::wind_adapter::{TuicRouter, make_guarded_outbound_action};

		let resolver = resolver("203.0.113.1", "127.0.0.1", &[])?;
		let mut cfg = crate::Config::default();
		cfg.outbound.default.ip_mode = None;
		let router = TuicRouter::new(&cfg, resolver.clone(), None)?;
		let target = TargetAddr::Domain("rebound.invalid".into(), 443);
		assert!(matches!(
			router.route(&context(target.clone())).await?,
			RouteAction::Forward(_)
		));
		let outbound = make_guarded_outbound_action(
			&cfg.outbound.default,
			resolver.clone(),
			Duration::from_secs(1),
			&cfg.experimental,
		);
		let (_, stream) = tokio::io::duplex(1);
		let error = outbound.handle_tcp(context(target), Box::new(stream)).await.err();
		assert!(error.is_some_and(|error| error.to_string().contains("loopback address rejected")));
		assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);
		let mapped = TargetAddr::from("[::ffff:127.0.0.1]:443".parse::<SocketAddr>()?);
		assert!(matches!(router.route(&context(mapped)).await?, RouteAction::Reject(_)));
		Ok(())
	}

	#[tokio::test]
	async fn checked_dns_address_is_pinned_for_tcp_and_udp() -> eyre::Result<()> {
		let resolver = resolver("203.0.113.1", "127.0.0.1", &[])?;
		let (outbound, inner) = guard(resolver.clone(), None);
		let target = TargetAddr::Domain("probe.invalid".into(), 443);
		let (_, stream) = tokio::io::duplex(1);
		outbound.handle_tcp(context(target.clone()), Box::new(stream)).await?;
		assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
		assert_eq!(
			*inner.seen.lock().await,
			vec![TargetAddr::from("203.0.113.1:443".parse::<SocketAddr>()?)]
		);

		let resolver = self::resolver("203.0.113.1", "127.0.0.1", &[])?;
		let (outbound, inner) = guard(resolver.clone(), None);
		let (tx, _responses) = mpsc::channel(1);
		let (send, rx) = mpsc::channel(1);
		send.send(UdpPacket {
			source: None,
			target: target.clone(),
			payload: Bytes::new(),
		})
		.await?;
		drop(send);
		tokio::time::timeout(
			Duration::from_secs(2),
			outbound.handle_udp(context(target), UdpStream { tx, rx }),
		)
		.await??;
		assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
		assert_eq!(
			*inner.seen.lock().await,
			vec![TargetAddr::from("203.0.113.1:443".parse::<SocketAddr>()?)]
		);
		Ok(())
	}

	#[test]
	fn destination_restrictions_cover_each_flag_and_mapped_addresses() -> eyre::Result<()> {
		let cases = [
			("127.0.0.1:80", true, false, true),
			("[::1]:80", true, false, true),
			("[::ffff:127.0.0.1]:80", true, false, true),
			("10.0.0.1:80", false, true, true),
			("[::ffff:192.168.1.1]:80", false, true, true),
			("[fd00::1]:80", false, true, true),
			("127.0.0.1:80", false, true, false),
			("10.0.0.1:80", true, false, false),
			("203.0.113.1:80", true, true, false),
			("[2001:db8::1]:80", true, true, false),
		];
		for (addr, drop_loopback, drop_private, rejected) in cases {
			let restrictions = ExperimentalConfig {
				drop_loopback,
				drop_private,
			};
			assert_eq!(check_destination(addr.parse()?, &restrictions).is_err(), rejected, "{addr}");
		}
		Ok(())
	}

	#[tokio::test]
	async fn every_udp_packet_is_checked_and_allowed_packets_drain_in_order() -> eyre::Result<()> {
		let (outbound, inner) = guard(resolver("203.0.113.1", "::1", &["203.0.113.1", "::1"])?, None);
		let (tx, _responses) = mpsc::channel(1);
		let (send, rx) = mpsc::channel(128);
		let safe = TargetAddr::from("203.0.113.1:53".parse::<SocketAddr>()?);
		let targets = [
			safe.clone(),
			TargetAddr::from("127.0.0.1:53".parse::<SocketAddr>()?),
			TargetAddr::from("10.0.0.1:53".parse::<SocketAddr>()?),
			TargetAddr::Domain("probe.invalid".into(), 53),
			TargetAddr::Domain("rebound.invalid".into(), 53),
		];
		for target in targets.into_iter().chain(std::iter::repeat_n(safe.clone(), 64)) {
			send.send(UdpPacket {
				source: None,
				target,
				payload: Bytes::new(),
			})
			.await?;
		}
		drop(send);
		tokio::time::timeout(
			Duration::from_secs(2),
			outbound.handle_udp(context(safe.clone()), UdpStream { tx, rx }),
		)
		.await??;
		assert_eq!(*inner.seen.lock().await, vec![safe; 66]);
		Ok(())
	}

	struct PausedOutbound {
		gate: tokio::sync::Notify,
		seen: AtomicUsize,
	}

	#[async_trait]
	impl Outbound for PausedOutbound {
		async fn handle_tcp(&self, _: FlowContext, _: Box<dyn AbstractTcpStream>) -> eyre::Result<()> {
			Ok(())
		}

		async fn handle_udp(&self, _: FlowContext, mut stream: UdpStream) -> eyre::Result<()> {
			self.gate.notified().await;
			while stream.rx.recv().await.is_some() {
				self.seen.fetch_add(1, Ordering::Relaxed);
			}
			Ok(())
		}
	}

	#[tokio::test]
	async fn udp_guard_has_bounded_backpressure_and_drains_after_input_closes() -> eyre::Result<()> {
		let resolver = resolver("203.0.113.1", "203.0.113.1", &[])?;
		let inner = Arc::new(PausedOutbound {
			gate: tokio::sync::Notify::new(),
			seen: AtomicUsize::new(0),
		});
		let outbound = GuardedOutbound {
			inner: inner.clone(),
			resolver: resolver.clone(),
			ip_mode: None,
			restrictions: ExperimentalConfig::default(),
		};
		let (tx, _responses) = mpsc::channel(1);
		let (send, rx) = mpsc::channel(1);
		let target = TargetAddr::Domain("probe.invalid".into(), 53);
		let sending_done = std::sync::atomic::AtomicBool::new(false);
		let sending = async {
			for _ in 0..100 {
				send.send(UdpPacket {
					source: None,
					target: target.clone(),
					payload: Bytes::new(),
				})
				.await?;
			}
			sending_done.store(true, Ordering::Relaxed);
			drop(send);
			Ok::<_, eyre::Report>(())
		};
		let release = async {
			while resolver.calls.load(Ordering::Relaxed) < 33 {
				tokio::task::yield_now().await;
			}
			// 32 queued packets plus one pending send. The producer must wait
			// rather than accumulating an unbounded checked packet queue.
			assert_eq!(resolver.calls.load(Ordering::Relaxed), 33);
			assert!(!sending_done.load(Ordering::Relaxed));
			inner.gate.notify_one();
		};
		let relaying = outbound.handle_udp(context(target.clone()), UdpStream { tx, rx });
		tokio::time::timeout(Duration::from_secs(2), async {
			let (sent, relayed, ()) = tokio::join!(sending, relaying, release);
			sent?;
			relayed
		})
		.await??;
		assert_eq!(inner.seen.load(Ordering::Relaxed), 100);
		Ok(())
	}

	struct RefusingOutbound;

	#[async_trait]
	impl Outbound for RefusingOutbound {
		async fn handle_tcp(&self, _: FlowContext, _: Box<dyn AbstractTcpStream>) -> eyre::Result<()> {
			Ok(())
		}

		async fn handle_udp(&self, _: FlowContext, _: UdpStream) -> eyre::Result<()> {
			eyre::bail!("handler ended");
		}
	}

	#[tokio::test]
	async fn ending_udp_handler_cancels_idle_forwarder_and_closes_input() -> eyre::Result<()> {
		let outbound = GuardedOutbound {
			inner: Arc::new(RefusingOutbound),
			resolver: resolver("203.0.113.1", "::1", &[])?,
			ip_mode: None,
			restrictions: ExperimentalConfig::default(),
		};
		let (tx, mut responses) = mpsc::channel(1);
		let (send, rx) = mpsc::channel(1);
		let target = TargetAddr::Domain("probe.invalid".into(), 53);
		let result = tokio::time::timeout(
			Duration::from_secs(2),
			outbound.handle_udp(context(target), UdpStream { tx, rx }),
		)
		.await?;
		assert!(result.is_err());
		assert!(send.is_closed(), "the cancelled forwarder must drop its input receiver");
		assert!(responses.recv().await.is_none());
		Ok(())
	}
}
