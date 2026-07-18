use std::{
	net::{IpAddr, Ipv4Addr, SocketAddr},
	sync::Arc,
};

use fast_socks5::{
	ReplyError,
	server::{Socks5ServerProtocol, states, wait_on_tcp},
	util::target_addr::TargetAddr as SocksTargetAddr,
};
use tokio::{net::TcpStream, sync::mpsc};
use tracing::{debug, warn};
use wind_core::{
	AbstractOutbound,
	udp::{UdpPacket, UdpStream},
};

use super::{
	Server,
	udp_session::{UdpSession, convert_target_addr, reply_origin_socket},
};
use crate::wind_adapter::{TuicOutboundAdapter, get_connection};

type CommandProto = Socks5ServerProtocol<TcpStream, states::CommandRead>;

impl Server {
	/// Handle a SOCKS5 `CONNECT`: reply success and hand the raw stream to the
	/// wind-tuic outbound, which relays it through the QUIC tunnel.
	pub async fn handle_connect(proto: CommandProto, addr: SocksTargetAddr, peer_addr: SocketAddr) {
		let target_addr = convert_target_addr(&addr);

		let inner = match proto.reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await {
			Ok(stream) => stream,
			Err(err) => {
				warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] command reply error: {err}");
				return;
			}
		};

		match get_connection() {
			Some(adapter) => {
				if let Err(err) = adapter
					.handle_tcp(target_addr.clone(), inner, None::<TuicOutboundAdapter>)
					.await
				{
					warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] TCP stream relay error: {err}");
				}
			}
			None => {
				warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] no wind connection available");
			}
		}
	}

	/// Handle a SOCKS5 `UDP ASSOCIATE`: bind a relay socket, reply with its
	/// address, then bridge SOCKS5 UDP datagrams to/from the wind-tuic outbound
	/// via a channel-backed [`UdpStream`]. The association ends when the client
	/// tears down the controlling TCP connection.
	pub async fn handle_associate(
		proto: CommandProto,
		assoc_id: u16,
		peer_addr: SocketAddr,
		reply_ip: IpAddr,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
	) {
		let session = match UdpSession::new(assoc_id, peer_addr, reply_ip, dual_stack, max_pkt_size) {
			Ok(session) => session,
			Err(err) => {
				warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed setting up UDP associate session: {err}");
				if let Err(err) = proto.reply_error(&ReplyError::GeneralFailure).await {
					warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}");
				}
				return;
			}
		};

		let local_addr = match session.local_addr() {
			Ok(addr) => addr,
			Err(err) => {
				warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed reading relay socket addr: {err}");
				let _ = proto.reply_error(&ReplyError::GeneralFailure).await;
				return;
			}
		};

		// Reply with the relay's reachable address; `reply_success` returns the
		// underlying control stream, whose EOF signals association teardown.
		let mut ctrl = match proto.reply_success(SocketAddr::new(reply_ip, local_addr.port())).await {
			Ok(ctrl) => ctrl,
			Err(err) => {
				warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}");
				return;
			}
		};

		debug!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] bound to {local_addr}");

		let session = Arc::new(session);

		// wind UdpStream channels.
		//   local_to_remote: packets from the local SOCKS5 client → outbound (reads rx)
		//   remote_to_local: packets from remote → local SOCKS5 client (outbound writes
		// tx)
		let (local_to_remote_tx, local_to_remote_rx) = mpsc::channel::<UdpPacket>(128);
		let (remote_to_local_tx, mut remote_to_local_rx) = mpsc::channel::<UdpPacket>(128);

		let wind_udp_stream = UdpStream {
			tx: remote_to_local_tx,
			rx: local_to_remote_rx,
		};

		// Drive the outbound UDP relay through the wind-tuic connection.
		let outbound_handle = tokio::spawn(async move {
			match get_connection() {
				Some(adapter) => {
					if let Err(err) = adapter.handle_udp(wind_udp_stream, None::<TuicOutboundAdapter>).await {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] wind UDP handler error: {err}");
					}
				}
				None => {
					warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] no wind connection available");
				}
			}
		});

		// remote → local: wrap replies in a SOCKS5 UDP header and send to the client.
		let session_send = session.clone();
		let remote_handle = tokio::spawn(async move {
			while let Some(pkt) = remote_to_local_rx.recv().await {
				let origin = reply_origin_socket(&pkt);
				if let Err(err) = session_send.send(&pkt.payload, origin).await {
					warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed sending UDP packet to local: {err}");
				}
			}
		});

		// local → remote: parse the SOCKS5 UDP header and forward payloads to the
		// outbound.
		let session_recv = session.clone();
		let local_incoming = async move {
			loop {
				match session_recv.recv().await {
					Ok((payload, target_addr)) => {
						let packet = UdpPacket {
							source: None,
							target: convert_target_addr(&target_addr),
							payload,
						};
						if local_to_remote_tx.send(packet).await.is_err() {
							break;
						}
					}
					// Dropped datagram (spoofed source or malformed header): keep
					// serving the association rather than tearing it down.
					Err(crate::error::Error::WrongPacketSource) | Err(crate::error::Error::Socks5(_)) => continue,
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed to receive UDP packet: {err}");
						break;
					}
				}
			}
		};

		// The association lives until either the client closes the control TCP
		// connection or the relay loop stops.
		tokio::select! {
			_ = local_incoming => {}
			res = wait_on_tcp(&mut ctrl) => {
				if let Err(err) = res {
					debug!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] control connection closed: {err}");
				}
			}
		}

		debug!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] stopped associating");

		// Let the outbound UDP handler wind down on its own instead of aborting
		// it. By this point `local_incoming` has ended (or been cancelled by the
		// select), so its `local_to_remote_tx` is dropped and the handler's input
		// channel is closed — `handle_udp` then exits gracefully and sends the
		// `Dissociate` to the server. `abort()` here would kill it mid-teardown,
		// leaking the server-side association until its GC timeout. Detaching (via
		// drop) lets the self-terminating task finish that teardown.
		drop(outbound_handle);
		remote_handle.abort();
	}
}
