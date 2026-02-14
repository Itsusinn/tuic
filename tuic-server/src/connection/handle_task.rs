use std::{
	collections::hash_map::Entry,
	io::{Error as IoError, ErrorKind},
	net::{IpAddr, SocketAddr},
};

use bytes::Bytes;
use eyre::{OptionExt, eyre};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{self, TcpSocket, TcpStream},
};
use tracing::{info, warn};
use tuic_core::{
	Address, is_private_ip,
	quinn::{Authenticate, Connect, Packet},
};

use super::{Connection, ERROR_CODE, UdpSession};
use crate::{
	config::OutboundRule,
	error::Error,
	io::copy_io,
	restful,
	utils::{StackPrefer, UdpRelayMode},
};

impl Connection {
	fn select_outbound_rule<'a>(&'a self, name: &str) -> &'a OutboundRule {
		if name.eq_ignore_ascii_case("default") || name.eq_ignore_ascii_case("direct") {
			&self.ctx.cfg.outbound.default
		} else {
			self.ctx
				.cfg
				.outbound
				.named
				.get(name)
				.unwrap_or(&self.ctx.cfg.outbound.default)
		}
	}

	async fn decide_acl_for_addrs(
		&self,
		addrs: &[SocketAddr],
		port: u16,
		is_tcp: bool,
		domain: Option<&str>,
	) -> (String, Option<IpAddr>, bool) {
		// Returns (outbound_name, hijack_ip, drop)

		use crate::acl::{AclAddress, AclPortSpec, AclProtocol};

		// Helper: port/protocol matching
		let ports_proto_ok = |rule: &crate::acl::AclRule| -> bool {
			if let Some(ports) = &rule.ports {
				use std::collections::HashSet;
				let mut allowed: HashSet<(u16, Option<AclProtocol>)> = HashSet::new();
				for entry in &ports.entries {
					let proto_ok = match entry.protocol {
						Some(AclProtocol::Tcp) => is_tcp,
						Some(AclProtocol::Udp) => !is_tcp,
						None => true,
					};
					if !proto_ok {
						continue;
					}
					match entry.port_spec {
						AclPortSpec::Single(p) => {
							allowed.insert((p, entry.protocol));
						}
						AclPortSpec::Range(start, end) => {
							for p in start..=end {
								allowed.insert((p, entry.protocol));
							}
						}
					}
				}
				if allowed.is_empty() {
					return false;
				}
				allowed.iter().any(|&(p, _)| p == port)
			} else {
				true
			}
		};

		// Helper: domain and wildcard matching
		let domain_matches = |addr: &AclAddress, dom: &str| -> bool {
			match addr {
				AclAddress::Domain(d) => d.eq_ignore_ascii_case(dom),
				AclAddress::WildcardDomain(pattern) => {
					let stripped = if let Some(rest) = pattern.strip_prefix("*.") {
						rest
					} else if let Some(rest) = pattern.strip_prefix("suffix:") {
						rest
					} else {
						pattern.as_str()
					};
					let dom_l = dom.to_ascii_lowercase();
					let suf_l = stripped.to_ascii_lowercase();
					dom_l == suf_l || dom_l.ends_with(&format!(".{suf_l}"))
				}
				_ => false,
			}
		};

		for rule in &self.ctx.cfg.acl {
			let matched = if let Some(dom) = domain {
				match &rule.addr {
					AclAddress::Domain(_) | AclAddress::WildcardDomain(_) => {
						domain_matches(&rule.addr, dom) && ports_proto_ok(rule)
					}
					_ => {
						let mut found = false;
						for sa in addrs {
							if rule.matching(*sa, port, is_tcp).await {
								found = true;
								break;
							}
						}
						found
					}
				}
			} else {
				let mut found = false;
				for sa in addrs {
					if rule.matching(*sa, port, is_tcp).await {
						found = true;
						break;
					}
				}
				found
			};

			if matched {
				let hijack = rule.hijack.as_ref().and_then(|h| h.parse::<IpAddr>().ok());
				if rule.outbound.eq_ignore_ascii_case("drop") {
					return ("drop".to_string(), hijack, true);
				}
				return (rule.outbound.clone(), hijack, false);
			}
		}
		// Built-in safety: drop localhost if no explicit rule matched
		if self.ctx.cfg.experimental.drop_loopback && addrs.iter().any(|sa| sa.ip().is_loopback()) {
			return ("drop".to_string(), None, true);
		}
		if self.ctx.cfg.experimental.drop_private && addrs.iter().any(|sa| is_private_ip(&sa.ip())) {
			return ("drop".to_string(), None, true);
		}

		("default".to_string(), None, false)
	}

	fn get_bind_ip(&self, is_ipv6: bool, outbound: &OutboundRule) -> Option<IpAddr> {
		if is_ipv6 {
			outbound.bind_ipv6.map(IpAddr::from)
		} else {
			outbound.bind_ipv4.map(IpAddr::from)
		}
	}

	fn create_socket(&self, target_addr: &SocketAddr, outbound: &OutboundRule) -> std::io::Result<TcpSocket> {
		let socket = if target_addr.is_ipv4() {
			TcpSocket::new_v4()?
		} else {
			TcpSocket::new_v6()?
		};
		#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
		socket.bind_device(outbound.bind_device.as_ref().map(|s| s.as_bytes()))?;
		if let Some(bind_ip) = self.get_bind_ip(target_addr.is_ipv6(), outbound) {
			socket.bind(SocketAddr::new(bind_ip, 0))?;
		}

		Ok(socket)
	}

	pub async fn handle_authenticate(&self, auth: Authenticate) {
		info!(
			"[{id:#010x}] [{addr}] [{user}] [AUTH] {auth_uuid}",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
			auth_uuid = auth.uuid(),
		);
	}

	pub async fn handle_connect(&self, mut conn: Connect) {
		let target_addr = conn.addr().to_string();

		info!(
			"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} ",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		let process = async {
			// First resolve using default outbound to get candidate IPs
			let default_outbound = &self.ctx.cfg.outbound.default;
			let initial_addrs = self.resolve_and_filter_addresses(conn.addr(), default_outbound, None).await?;

			// Decide ACL based on resolved addresses
			let port = conn.addr().port();
			let domain = match conn.addr() {
				Address::DomainAddress(d, _) => Some(d.as_str()),
				_ => None,
			};
			let (outbound_name, hijack, drop) = self.decide_acl_for_addrs(&initial_addrs, port, true, domain).await;

			if drop {
				warn!(
					"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} blocked by ACL",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
				);
				_ = conn.reset(ERROR_CODE);
				return Ok(());
			}

			// Select outbound rule
			let outbound = self.select_outbound_rule(&outbound_name);

			// Establish connection according to outbound type
			let mut stream = if outbound.kind.eq_ignore_ascii_case("socks5") {
				self.connect_via_socks5(outbound, conn.addr(), hijack).await?
			} else {
				// Resolve again if outbound/ip_mode differs or hijack is requested
				let addrs = self.resolve_and_filter_addresses(conn.addr(), outbound, hijack).await?;
				self.connect_to_addresses(addrs, outbound).await?
			};

			stream.set_nodelay(true)?;

			// a -> b tx
			// a <- b rx
			let (tx, rx, err) = copy_io(&mut conn, &mut stream).await;
			if err.is_some() {
				_ = conn.reset(ERROR_CODE);
			} else {
				_ = conn.finish().await;
			}
			_ = stream.shutdown().await;

			let uuid = self.auth.get().ok_or_eyre("Unexpected authorization state")?;
			restful::traffic_tx(&self.ctx, &uuid, tx);
			restful::traffic_rx(&self.ctx, &uuid, rx);
			if let Some(err) = err {
				return Err(err.into());
			}
			eyre::Ok(())
		};

		match process.await {
			Ok(()) => {}
			Err(err) => warn!(
				"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr}: {err}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
			),
		}
	}

	async fn resolve_and_filter_addresses(
		&self,
		addr: &Address,
		outbound: &OutboundRule,
		hijack: Option<IpAddr>,
	) -> eyre::Result<Vec<SocketAddr>> {
		// If hijack is specified, bypass DNS and use hijack IP with original port
		if let Some(hijack_ip) = hijack {
			let port = addr.port();
			let sa = SocketAddr::new(hijack_ip, port);
			return Ok(vec![sa]);
		}

		let mut addrs: Vec<SocketAddr> = resolve_dns(addr).await?.collect();

		match outbound.ip_mode.unwrap_or(StackPrefer::V4first) {
			StackPrefer::V4first => {
				addrs.sort_by_key(|a| !a.is_ipv4());
			}
			StackPrefer::V6first => {
				addrs.sort_by_key(|a| !a.is_ipv6());
			}
			StackPrefer::V4only => {
				addrs.retain(|a| a.is_ipv4());
			}
			StackPrefer::V6only => {
				addrs.retain(|a| a.is_ipv6());
			}
		}

		if addrs.is_empty() {
			return Err(eyre!("No addresses available after filtering"));
		}

		Ok(addrs)
	}

	async fn connect_to_addresses(&self, addrs: Vec<SocketAddr>, outbound: &OutboundRule) -> eyre::Result<TcpStream> {
		let mut last_error = None;

		for addr in addrs {
			match self.create_socket(&addr, outbound) {
				Ok(socket) => match socket.connect(addr).await {
					Ok(stream) => return Ok(stream),
					Err(err) => last_error = Some(err),
				},
				Err(err) => last_error = Some(err),
			}
		}

		Err(last_error
			.map(|e| eyre!(e))
			.unwrap_or_else(|| eyre!("Failed to connect to any address")))
	}

	pub async fn handle_packet(&self, pkt: Packet, mode: UdpRelayMode) {
		let assoc_id = pkt.assoc_id();
		let pkt_id = pkt.pkt_id();
		let frag_id = pkt.frag_id();
		let frag_total = pkt.frag_total();

		info!(
			"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment \
			 {frag_id}/{frag_total}",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
			frag_id = frag_id + 1,
		);

		self.udp_relay_mode.store(Some(mode).into());

		let (pkt, addr, assoc_id) = match pkt.accept().await {
			Ok(None) => return,
			Ok(Some(res)) => res,
			Err(err) => {
				warn!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment \
					 {frag_id}/{frag_total}: {err}",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					frag_id = frag_id + 1,
				);
				return;
			}
		};

		let process = async {
			info!(
				"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
				src_addr = addr,
			);

			let guard = self.udp_sessions.read().await;
			let session = guard.get(&assoc_id).map(|v| v.to_owned());
			drop(guard);
			let session = match session {
				Some(v) => v,
				None => match self.udp_sessions.write().await.entry(assoc_id) {
					Entry::Occupied(entry) => entry.get().clone(),
					Entry::Vacant(entry) => {
						let session = UdpSession::new(self.ctx.clone(), self.clone(), assoc_id)?;
						entry.insert(session.clone());
						session
					}
				},
			};

			// Resolve using default outbound and apply ACL
			let initial_addrs: Vec<SocketAddr> = resolve_dns(&addr).await?.collect();
			if initial_addrs.is_empty() {
				return Err(Error::from(IoError::new(ErrorKind::NotFound, "no address resolved")));
			}

			let domain = match &addr {
				Address::DomainAddress(d, _) => Some(d.as_str()),
				_ => None,
			};
			let (outbound_name, hijack, should_drop) =
				self.decide_acl_for_addrs(&initial_addrs, addr.port(), false, domain).await;
			if should_drop {
				// Silently drop the packet as per ACL
				warn!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr} \
					 blocked by ACL",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					src_addr = addr,
				);
				return Ok(());
			}

			// Evaluate outbound policy for UDP
			let outbound = self.select_outbound_rule(&outbound_name);
			if outbound.kind.eq_ignore_ascii_case("socks5") {
				// Block UDP by default when a SOCKS5 outbound is selected, unless explicitly
				// allowed
				let allow_udp = outbound.allow_udp.unwrap_or(false);
				if !allow_udp {
					warn!(
						"[{id:#010x}] [{addr}] [{user}] [UDP-OUT-SOCKS5] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to \
						 {src_addr} blocked by ACL",
						id = self.id(),
						addr = self.inner.remote_address(),
						user = self.auth,
						src_addr = addr,
					);
					// Silently drop UDP to avoid leaking QUIC/HTTP3 when SOCKS5 is requested
					return Ok(());
				} else {
					// We don't support UDP via SOCKS5 yet; fall back to direct
					info!(
						"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] outbound '{outbound_name}' allows UDP but \
						 UDP via SOCKS5 not supported; using direct as you configured",
						id = self.id(),
						addr = self.inner.remote_address(),
						user = self.auth,
					);
				}
			} else if !outbound.kind.eq_ignore_ascii_case("direct") {
				// Outbound other than direct is not supported for UDP yet; proceed as direct
				warn!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] outbound '{outbound_name}' not supported; \
					 using direct",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
				);
			}

			let socket_addr = if let Some(h) = hijack {
				SocketAddr::new(h, addr.port())
			} else {
				// Use the first address resolved
				initial_addrs[0]
			};

			let uuid = self.auth.get().ok_or_eyre("Unexpected authorization state")?;
			restful::traffic_tx(&self.ctx, &uuid, pkt.len());
			if let Some(session) = session.upgrade() {
				session.send(pkt, socket_addr).await
			} else {
				Err(eyre!("UdpSession dropped already").into())
			}
		};

		if let Err(err) = process.await {
			warn!(
				"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr}: {err}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
				src_addr = addr,
			);
		}
	}

	pub async fn handle_dissociate(&self, assoc_id: u16) {
		info!(
			"[{id:#010x}] [{addr}] [{user}] [UDP-DROP] [{assoc_id:#06x}]",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		if let Some(session) = self.udp_sessions.write().await.remove(&assoc_id)
			&& let Some(session) = session.upgrade()
		{
			session.close().await;
		}
	}

	pub async fn handle_heartbeat(&self) {
		info!(
			"[{id:#010x}] [{addr}] [{user}] [HB]",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);
	}

	pub async fn relay_packet(self, pkt: Bytes, addr: Address, assoc_id: u16) -> eyre::Result<()> {
		let addr_display = addr.to_string();

		info!(
			"[{id:#010x}] [{addr}] [{user}] [UDP-IN] [{assoc_id:#06x}] [to-{mode}] from {src_addr}",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
			mode = self.udp_relay_mode.load().unwrap(),
			src_addr = addr_display,
		);

		restful::traffic_rx(&self.ctx, &self.auth.get().ok_or_eyre("Unreachable")?, pkt.len());

		let res = match self.udp_relay_mode.load().unwrap() {
			UdpRelayMode::Native => self.model.packet_native(pkt, addr, assoc_id),
			UdpRelayMode::Quic => self.model.packet_quic(pkt, addr, assoc_id).await,
		};

		if let Err(err) = res {
			warn!(
				"[{id:#010x}] [{addr}] [{user}] [UDP-IN] [{assoc_id:#06x}] [to-{mode}] from {src_addr}: {err}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
				mode = self.udp_relay_mode.load().unwrap(),
				src_addr = addr_display,
			);
		}
		Ok(())
	}
}

async fn resolve_dns(addr: &Address) -> Result<impl Iterator<Item = SocketAddr>, IoError> {
	match addr {
		Address::None => Err(IoError::new(ErrorKind::InvalidInput, "empty address")),
		Address::DomainAddress(domain, port) => Ok(net::lookup_host((domain.as_str(), *port))
			.await?
			.collect::<Vec<_>>()
			.into_iter()),
		Address::SocketAddress(addr) => Ok(vec![*addr].into_iter()),
	}
}

impl Connection {
	async fn connect_via_socks5(
		&self,
		outbound: &OutboundRule,
		target: &Address,
		hijack: Option<IpAddr>,
	) -> eyre::Result<TcpStream> {
		// 1) Resolve and connect to the SOCKS5 proxy
		let proxy_addr = outbound
			.addr
			.as_ref()
			.ok_or_else(|| eyre!("socks5 outbound requires 'addr'"))?;
		let proxy_addrs: Vec<SocketAddr> = net::lookup_host(proxy_addr.as_str()).await?.collect();
		if proxy_addrs.is_empty() {
			return Err(eyre!("No addresses resolved for SOCKS5 proxy: {proxy_addr}"));
		}
		let mut stream = self.connect_to_addresses(proxy_addrs, outbound).await?;

		// 2) Greeting / Method selection
		let (has_userpass, username, password) = match (&outbound.username, &outbound.password) {
			(Some(u), Some(p)) => (true, Some(u.as_bytes()), Some(p.as_bytes())),
			(None, None) => (false, None, None),
			_ => {
				return Err(eyre!(
					"invalid socks5 auth config: username/password must be both set or both omitted"
				));
			}
		};

		if has_userpass {
			// Offer both: NoAuth(0x00) and User/Pass(0x02)
			let greet = [0x05u8, 0x02, 0x00, 0x02];
			stream.write_all(&greet).await?;
		} else {
			let greet = [0x05u8, 0x01, 0x00];
			stream.write_all(&greet).await?;
		}
		let mut resp = [0u8; 2];
		stream.read_exact(&mut resp).await?;
		if resp[0] != 0x05 {
			return Err(eyre!("invalid socks5 version in method selection: {}", resp[0]));
		}
		let method = resp[1];
		if method == 0xFF {
			return Err(eyre!("socks5 proxy has no acceptable auth methods"));
		}

		// 3) Username/Password sub-negotiation if required
		if method == 0x02 {
			let u = username.unwrap();
			let p = password.unwrap();
			if u.len() > 255 || p.len() > 255 {
				return Err(eyre!("socks5 username/password too long"));
			}
			let mut buf = Vec::with_capacity(3 + u.len() + p.len());
			buf.push(0x01); // subnegotiation version
			buf.push(u.len() as u8);
			buf.extend_from_slice(u);
			buf.push(p.len() as u8);
			buf.extend_from_slice(p);
			stream.write_all(&buf).await?;
			let mut auth_resp = [0u8; 2];
			stream.read_exact(&mut auth_resp).await?;
			if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
				return Err(eyre!("socks5 username/password auth failed (code={})", auth_resp[1]));
			}
		}

		// 4) CONNECT request to target
		let (atyp, addr_bytes, port): (u8, Vec<u8>, u16) = if let Some(ip) = hijack {
			match ip {
				std::net::IpAddr::V4(v4) => (0x01, v4.octets().to_vec(), target.port()),
				std::net::IpAddr::V6(v6) => (0x04, v6.octets().to_vec(), target.port()),
			}
		} else {
			match target {
				Address::DomainAddress(domain, port) => {
					if domain.len() > 255 {
						return Err(eyre!("domain name too long for socks5: {}", domain));
					}
					let mut v = Vec::with_capacity(1 + domain.len());
					v.push(domain.len() as u8);
					v.extend_from_slice(domain.as_bytes());
					(0x03, v, *port)
				}
				Address::SocketAddress(sa) => match sa {
					SocketAddr::V4(v4) => (0x01, v4.ip().octets().to_vec(), v4.port()),
					SocketAddr::V6(v6) => (0x04, v6.ip().octets().to_vec(), v6.port()),
				},
				Address::None => return Err(eyre!("invalid target address for CONNECT: none")),
			}
		};

		let mut req = Vec::with_capacity(4 + addr_bytes.len() + 2);
		req.push(0x05); // version
		req.push(0x01); // CONNECT
		req.push(0x00); // RSV
		req.push(atyp);
		req.extend_from_slice(&addr_bytes);
		req.push((port >> 8) as u8);
		req.push((port & 0xFF) as u8);
		stream.write_all(&req).await?;

		// 5) Read CONNECT reply
		let mut hdr = [0u8; 4];
		stream.read_exact(&mut hdr).await?;
		if hdr[0] != 0x05 {
			return Err(eyre!("invalid socks5 version in reply: {}", hdr[0]));
		}
		if hdr[1] != 0x00 {
			return Err(eyre!("socks5 connect failed, reply code={}", hdr[1]));
		}
		let atyp = hdr[3];
		match atyp {
			0x01 => {
				let mut rest = [0u8; 6];
				stream.read_exact(&mut rest).await?;
			}
			0x03 => {
				let mut len = [0u8; 1];
				stream.read_exact(&mut len).await?;
				let mut skip = vec![0u8; len[0] as usize + 2];
				stream.read_exact(&mut skip).await?;
			}
			0x04 => {
				let mut rest = [0u8; 18];
				stream.read_exact(&mut rest).await?;
			}
			_ => return Err(eyre!("invalid socks5 ATYP in reply: {}", atyp)),
		}

		Ok(stream)
	}
}
