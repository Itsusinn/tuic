use fast_socks5::{Socks5Command, server::Socks5ServerProtocol};
use tokio::{
	io::AsyncReadExt,
	net::{TcpListener, TcpStream, UdpSocket},
	task::JoinHandle,
};

use super::*;
use crate::config::ProxyConfig;
const LIMIT: Duration = Duration::from_secs(3);

struct TestChain {
	chain: ProxyChain,
	endpoint: UdpSocket,
	control: TcpStream,
	proxy: UdpSocket,
}

async fn chain(ctx: &AppContext) -> eyre::Result<TestChain> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let address = listener.local_addr()?;
	let task: JoinHandle<eyre::Result<_>> = tokio::spawn(async move {
		let (stream, _) = listener.accept().await?;
		let proto = Socks5ServerProtocol::accept_no_auth(stream).await?;
		let (proto, command, _) = proto.read_command().await?;
		assert_eq!(command, Socks5Command::UDPAssociate);
		let proxy = UdpSocket::bind("127.0.0.1:0").await?;
		let control = proto.reply_success(proxy.local_addr()?).await?;
		Ok((control, proxy))
	});
	let relay = Relay {
		server: ("remote.invalid".into(), 443),
		reconnect: false,
		proxy: Some(ProxyConfig {
			server: (address.ip().to_string(), address.port()),
			..Default::default()
		}),
		..Default::default()
	};
	let chain = ProxyChain::new(ctx, &relay)?;
	let endpoint = UdpSocket::from_std((chain.socket_factory)(chain.peer_addr)?)?;
	endpoint.connect(chain.peer_addr).await?;
	endpoint.send(b"initial").await?;
	let (control, proxy) = tokio::time::timeout(LIMIT, task).await???;
	let mut buffer = [0; 256];
	tokio::time::timeout(LIMIT, proxy.recv_from(&mut buffer)).await??;
	Ok(TestChain {
		chain,
		endpoint,
		control,
		proxy,
	})
}

#[tokio::test]
async fn drop_and_parent_cancellation_release_the_tunnel_port() -> eyre::Result<()> {
	for drop_chain in [true, false] {
		let ctx = AppContext::default();
		let TestChain {
			chain,
			endpoint: _endpoint,
			mut control,
			proxy: _proxy,
		} = chain(&ctx).await?;
		let addr = chain.peer_addr;
		let scoped = chain.ctx.clone();
		assert!(std::net::UdpSocket::bind(addr).is_err());
		if drop_chain {
			drop(chain);
		} else {
			ctx.token.cancel();
		}
		ctx.tasks.close();
		tokio::time::timeout(LIMIT, ctx.tasks.wait()).await?;
		assert!(scoped.token.is_cancelled());
		assert_eq!(
			tokio::time::timeout(LIMIT, control.read_u8()).await?.err().map(|e| e.kind()),
			Some(std::io::ErrorKind::UnexpectedEof)
		);
		let _rebound = std::net::UdpSocket::bind(addr)?;
		assert_eq!(ctx.token.is_cancelled(), !drop_chain);
	}
	Ok(())
}

#[tokio::test]
async fn control_eof_without_reconnect_cancels_only_the_chain() -> eyre::Result<()> {
	let ctx = AppContext::default();
	let case = chain(&ctx).await?;
	drop(case.control);
	tokio::time::timeout(LIMIT, case.chain.ctx.token.cancelled()).await?;
	ctx.tasks.close();
	tokio::time::timeout(LIMIT, ctx.tasks.wait()).await?;
	assert!(!ctx.token.is_cancelled());
	Ok(())
}

#[tokio::test]
async fn another_local_sender_cannot_inject_into_the_tunnel() -> eyre::Result<()> {
	let ctx = AppContext::default();
	let case = chain(&ctx).await?;
	let attacker = UdpSocket::bind("127.0.0.1:0").await?;
	attacker.send_to(b"injected", case.chain.peer_addr).await?;
	let mut buffer = [0; 256];
	assert!(
		tokio::time::timeout(Duration::from_millis(50), case.proxy.recv_from(&mut buffer))
			.await
			.is_err()
	);
	case.endpoint.send(b"valid").await?;
	let (size, _) = tokio::time::timeout(LIMIT, case.proxy.recv_from(&mut buffer)).await??;
	let (_, target, payload) = fast_socks5::parse_udp_request(&buffer[..size]).await?;
	assert_eq!(
		target,
		fast_socks5::util::target_addr::TargetAddr::Domain("remote.invalid".into(), 443)
	);
	assert_eq!(payload, b"valid");
	drop(case);
	ctx.tasks.close();
	tokio::time::timeout(LIMIT, ctx.tasks.wait()).await?;
	Ok(())
}
