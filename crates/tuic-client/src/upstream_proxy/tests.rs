use fast_socks5::server::Socks5ServerProtocol;
use tokio::{net::TcpListener, task::JoinHandle};

use super::*;

const TIMEOUT: Duration = Duration::from_secs(3);

struct RelayCase {
	endpoint: UdpSocket,
	proxy: UdpSocket,
	proxy_peer: SocketAddr,
	_control: TcpStream,
	task: JoinHandle<eyre::Result<()>>,
}

impl Drop for RelayCase {
	fn drop(&mut self) {
		self.task.abort();
	}
}

async fn relay_case(target: SocketAddr, buffer_hint: usize) -> eyre::Result<RelayCase> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let control = TcpStream::connect(listener.local_addr()?).await?;
	let (server_control, _) = listener.accept().await?;
	let proxy = UdpSocket::bind("127.0.0.1:0").await?;
	let udp = UdpSocket::bind("127.0.0.1:0").await?;
	udp.connect(proxy.local_addr()?).await?;
	let proxy_peer = udp.local_addr()?;
	let local = UdpSocket::bind("127.0.0.1:0").await?;
	let endpoint = UdpSocket::bind("127.0.0.1:0").await?;
	local.connect(endpoint.local_addr()?).await?;
	endpoint.connect(local.local_addr()?).await?;
	let task = tokio::spawn(async move {
		let mut association = Association { control, udp };
		relay_datagrams(&local, &mut association, target, buffer_hint).await
	});
	Ok(RelayCase {
		endpoint,
		proxy,
		proxy_peer,
		_control: server_control,
		task,
	})
}

#[tokio::test]
async fn malformed_fragmented_and_wrong_target_replies_are_dropped() -> eyre::Result<()> {
	let target = SocketAddr::from(([127, 0, 0, 1], 443));
	let case = relay_case(target, 0).await?;
	let mut valid = fast_socks5::new_udp_header(target)?;
	valid.extend_from_slice(b"valid");
	let mut reserved = valid.clone();
	reserved[0] = 1;
	let mut fragmented = valid.clone();
	fragmented[2] = 1;
	let mut wrong = fast_socks5::new_udp_header(SocketAddr::from(([127, 0, 0, 1], 444)))?;
	wrong.extend_from_slice(b"wrong");
	let mut domain = fast_socks5::new_udp_header(("localhost", 443))?;
	domain.extend_from_slice(b"wrong");
	for packet in [vec![], vec![0], vec![0, 0, 0, 1], reserved, fragmented, wrong, domain] {
		case.proxy.send_to(&packet, case.proxy_peer).await?;
	}
	case.proxy.send_to(&valid, case.proxy_peer).await?;
	let mut buf = [0; 128];
	let len = tokio::time::timeout(TIMEOUT, case.endpoint.recv(&mut buf)).await??;
	assert_eq!(&buf[..len], b"valid");
	assert!(
		tokio::time::timeout(Duration::from_millis(50), case.endpoint.recv(&mut buf))
			.await
			.is_err()
	);
	Ok(())
}

#[tokio::test]
async fn wrong_udp_source_and_local_sender_cannot_inject_datagrams() -> eyre::Result<()> {
	let target = SocketAddr::from(([127, 0, 0, 1], 443));
	let case = relay_case(target, 2048).await?;
	let attacker = UdpSocket::bind("127.0.0.1:0").await?;
	let mut packet = fast_socks5::new_udp_header(target)?;
	packet.extend_from_slice(b"injected");
	attacker.send_to(&packet, case.proxy_peer).await?;
	attacker.send_to(b"injected", case.endpoint.peer_addr()?).await?;
	let mut buf = [0; 128];
	assert!(
		tokio::time::timeout(Duration::from_millis(50), case.endpoint.recv(&mut buf))
			.await
			.is_err()
	);
	assert!(
		tokio::time::timeout(Duration::from_millis(50), case.proxy.recv_from(&mut buf))
			.await
			.is_err()
	);
	case.endpoint.send(b"outgoing").await?;
	let (len, _) = tokio::time::timeout(TIMEOUT, case.proxy.recv_from(&mut buf)).await??;
	let (frag, destination, payload) = fast_socks5::parse_udp_request(&buf[..len]).await?;
	assert_eq!(frag, 0);
	assert_eq!(destination, TargetAddr::Ip(target));
	assert_eq!(payload, b"outgoing");
	Ok(())
}

#[tokio::test]
async fn tiny_and_unbounded_buffer_hints_preserve_whole_datagrams() -> eyre::Result<()> {
	let target = SocketAddr::from(([127, 0, 0, 1], 443));
	for hint in [0, usize::MAX] {
		let case = relay_case(target, hint).await?;
		let payload = vec![0xa5; 65000];
		case.endpoint.send(&payload).await?;
		let mut buf = vec![0; UDP_BUFFER_SIZE];
		let (len, _) = tokio::time::timeout(TIMEOUT, case.proxy.recv_from(&mut buf)).await??;
		let (_, destination, received) = fast_socks5::parse_udp_request(&buf[..len]).await?;
		assert_eq!(destination, TargetAddr::Ip(target));
		assert_eq!(received, payload);
		case.proxy.send_to(&buf[..len], case.proxy_peer).await?;
		let len = tokio::time::timeout(TIMEOUT, case.endpoint.recv(&mut buf)).await??;
		assert_eq!(&buf[..len], payload);
	}
	Ok(())
}

type ProxySession = JoinHandle<eyre::Result<(TcpStream, UdpSocket)>>;

async fn proxy_session(port_zero: bool) -> eyre::Result<(ProxyConfig, ProxySession)> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let addr = listener.local_addr()?;
	let task = tokio::spawn(async move {
		let (stream, _) = listener.accept().await?;
		let proto = Socks5ServerProtocol::accept_no_auth(stream).await?;
		let (proto, command, _) = proto.read_command().await?;
		assert_eq!(command, Socks5Command::UDPAssociate);
		let udp = UdpSocket::bind("127.0.0.1:0").await?;
		let reply = SocketAddr::from(([0, 0, 0, 0], if port_zero { 0 } else { udp.local_addr()?.port() }));
		let stream = proto.reply_success(reply).await?;
		Ok((stream, udp))
	});
	Ok((
		ProxyConfig {
			server: (addr.ip().to_string(), addr.port()),
			..Default::default()
		},
		task,
	))
}

fn no_reconnect() -> ReconnectConfig {
	ReconnectConfig {
		enabled: false,
		..Default::default()
	}
}

#[tokio::test]
async fn unspecified_relay_uses_control_peer_and_zero_port_is_rejected() -> eyre::Result<()> {
	let token = CancellationToken::new();
	let (proxy, task) = proxy_session(false).await?;
	let association = associate(&proxy, TIMEOUT, &token).await?;
	let (_control, udp) = tokio::time::timeout(TIMEOUT, task).await???;
	assert_eq!(association.udp.peer_addr()?, udp.local_addr()?);
	let (proxy, task) = proxy_session(true).await?;
	assert!(associate(&proxy, TIMEOUT, &token).await.is_err());
	let _ = tokio::time::timeout(TIMEOUT, task).await???;
	Ok(())
}

#[tokio::test]
async fn bridge_drop_and_parent_cancellation_release_the_bridge_port() -> eyre::Result<()> {
	for drop_bridge in [true, false] {
		let ctx = AppContext::default();
		let (proxy, task) = proxy_session(false).await?;
		let bridge = ProxyBridge::new(&ctx, proxy, "127.0.0.1:443".parse()?, TIMEOUT, no_reconnect()).await?;
		let (mut control, _udp) = tokio::time::timeout(TIMEOUT, task).await???;
		let addr = bridge.peer_addr;
		let scoped = bridge.ctx.clone();
		assert!(std::net::UdpSocket::bind(addr).is_err());
		if drop_bridge {
			drop(bridge);
		} else {
			ctx.token.cancel();
		}
		ctx.tasks.close();
		tokio::time::timeout(TIMEOUT, ctx.tasks.wait()).await?;
		assert!(scoped.token.is_cancelled());
		assert_eq!(
			tokio::time::timeout(TIMEOUT, control.read_u8())
				.await?
				.err()
				.map(|e| e.kind()),
			Some(std::io::ErrorKind::UnexpectedEof)
		);
		let _rebound = std::net::UdpSocket::bind(addr)?;
		assert_eq!(ctx.token.is_cancelled(), !drop_bridge);
	}
	Ok(())
}

#[tokio::test]
async fn control_eof_without_reconnect_cancels_the_quic_context() -> eyre::Result<()> {
	let ctx = AppContext::default();
	let (proxy, task) = proxy_session(false).await?;
	let bridge = ProxyBridge::new(&ctx, proxy, "127.0.0.1:443".parse()?, TIMEOUT, no_reconnect()).await?;
	let (control, _udp) = tokio::time::timeout(TIMEOUT, task).await???;
	drop(control);
	tokio::time::timeout(TIMEOUT, bridge.ctx.token.cancelled()).await?;
	ctx.tasks.close();
	tokio::time::timeout(TIMEOUT, ctx.tasks.wait()).await?;
	assert!(!ctx.token.is_cancelled());
	Ok(())
}

#[tokio::test]
async fn association_setup_is_bounded_and_cancellable() -> eyre::Result<()> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let addr = listener.local_addr()?;
	let proxy = ProxyConfig {
		server: (addr.ip().to_string(), addr.port()),
		..Default::default()
	};
	let token = CancellationToken::new();
	let result = associate(&proxy, Duration::from_millis(50), &token).await;
	assert!(result.err().is_some_and(|error| error.to_string().contains("timed out")));
	let token2 = token.clone();
	let (_stream, _) = listener.accept().await?;
	let pending = associate(&proxy, TIMEOUT, &token);
	let cancel = async {
		token2.cancel();
	};
	let (result, ()) = tokio::join!(pending, cancel);
	assert!(result.is_err());
	Ok(())
}

#[tokio::test]
async fn invalid_credentials_are_rejected_before_opening_control() -> eyre::Result<()> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let addr = listener.local_addr()?;
	for (username, password) in [
		(Some("u".into()), None),
		(None, Some("p".into())),
		(Some("".into()), Some("p".into())),
		(Some("u".repeat(256)), Some("p".into())),
	] {
		let proxy = ProxyConfig {
			server: (addr.ip().to_string(), addr.port()),
			username,
			password,
			..Default::default()
		};
		assert!(associate(&proxy, TIMEOUT, &CancellationToken::new()).await.is_err());
	}
	assert!(
		tokio::time::timeout(Duration::from_millis(50), listener.accept())
			.await
			.is_err()
	);
	Ok(())
}
