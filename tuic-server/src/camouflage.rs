use std::sync::Arc;

use axum::http::{
	HeaderName, Request, Response, Uri,
	header::{CONTENT_LENGTH, HOST, HeaderValue},
};
use bytes::{Buf, Bytes};
use futures::stream;
use futures_util::StreamExt;
use h3::{error::Code, server};
use quinn::Connection;
use reqwest::{Client, Method, Url};
use tracing::{debug, info, warn};

use crate::{AppContext, config::CamouflageConfig};

#[derive(Clone)]
pub struct BackendRoute {
	backend: Url,
	backend_host_override: Option<String>,
	client: Client,
}

impl BackendRoute {
	pub fn from_config(camouflage: Option<&CamouflageConfig>) -> eyre::Result<Option<Self>> {
		let Some(camouflage) = camouflage.filter(|cfg| cfg.enabled) else {
			return Ok(None);
		};

		let mut backend = Url::parse(camouflage.reverse_proxy_url.as_str())?;
		let backend_host = backend
			.host_str()
			.ok_or_else(|| eyre::eyre!("`camouflage.reverse_proxy_url` must contain a host"))?
			.to_string();
		let backend_port = backend
			.port_or_known_default()
			.ok_or_else(|| eyre::eyre!("`camouflage.reverse_proxy_url` has no known port"))?;

		let mut client_builder = Client::builder()
			.danger_accept_invalid_certs(camouflage.skip_backend_tls_verify)
			.connect_timeout(camouflage.request_timeout);
		let mut backend_host_override = camouflage.reverse_proxy_hostname.clone();

		if let Some(reverse_proxy_hostname) = camouflage.reverse_proxy_hostname.as_deref() {
			backend
				.set_host(Some(reverse_proxy_hostname))
				.map_err(|_| eyre::eyre!("invalid `camouflage.reverse_proxy_hostname`: {reverse_proxy_hostname}"))?;
			if let Ok(ip) = backend_host.parse::<std::net::IpAddr>() {
				client_builder = client_builder.resolve(reverse_proxy_hostname, std::net::SocketAddr::new(ip, backend_port));
			}
			backend_host_override = Some(reverse_proxy_hostname.to_string());
		}

		let client = client_builder.build()?;
		Ok(Some(Self {
			backend,
			backend_host_override,
			client,
		}))
	}
}

pub async fn handle(
	ctx: Arc<AppContext>,
	conn: Connection,
	prefetched_uni: Option<crate::h3_quinn_compat::PeekableRecvStream>,
	prefetched_bi: Option<crate::h3_quinn_compat::PrefetchedBiRecv>,
) -> eyre::Result<()> {
	let Some(route) = ctx.camouflage.as_ref() else {
		return Ok(());
	};

	info!(
		id = conn.stable_id() as u32,
		addr = %conn.remote_address(),
		"HTTP/3 camouflage enabled, reverse proxy target={target}, backend_host={host:?}",
		target = route.backend,
		host = route.backend_host_override
	);

	let quic_conn = crate::h3_quinn_compat::Connection::new_with_prefetched(conn, prefetched_uni, prefetched_bi);
	let mut h3_conn = server::Connection::new(quic_conn).await?;

	loop {
		let Some(resolver) = accept_request(&mut h3_conn).await? else {
			break;
		};
		let (request, stream) = resolver.resolve_request().await?;
		debug!(
			"[camouflage] incoming h3 request: method={} uri={}",
			request.method(),
			request.uri()
		);

		let route = route.clone();
		tokio::spawn(async move {
			if let Err(err) = forward_request(route, request, stream).await {
				warn!("[camouflage] request forwarding failed: {err}");
			}
		});
	}

	Ok(())
}

async fn accept_request<C>(
	h3_conn: &mut server::Connection<C, Bytes>,
) -> eyre::Result<Option<server::RequestResolver<C, Bytes>>>
where
	C: h3::quic::Connection<Bytes>,
{
	match h3_conn.accept().await {
		Ok(resolver) => Ok(resolver),
		Err(err) if err.is_h3_no_error() => Ok(None),
		Err(err) => Err(err.into()),
	}
}

async fn forward_request<S>(
	route: BackendRoute,
	request: Request<()>,
	stream: server::RequestStream<S, Bytes>,
) -> eyre::Result<()>
where
	S: h3::quic::BidiStream<Bytes>,
	<S as h3::quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
{
	let target = rewrite_target_url(&route.backend, request.uri())?;
	let method = Method::from_bytes(request.method().as_str().as_bytes())?;
	let mut backend_request = route.client.request(method, target);

	for (name, value) in request.headers() {
		if is_forwardable_header(name) {
			backend_request = backend_request.header(name, value);
		}
	}
	if let Some(host) = route.backend_host_override.as_deref() {
		backend_request = backend_request.header(HOST, host);
	} else if let Some(host) = request
		.headers()
		.get(HOST)
		.and_then(|h| HeaderValue::from_bytes(h.as_bytes()).ok())
	{
		backend_request = backend_request.header(HOST, host);
	}

	let (mut send_half, mut recv_half) = stream.split();

	if request_has_body(&request) {
		let body_stream = stream::unfold(Some(recv_half), |state| async move {
			let mut recv = state?;
			match recv.recv_data().await {
				Ok(Some(mut chunk)) => {
					let remaining = chunk.remaining();
					let bytes = chunk.copy_to_bytes(remaining);
					Some((Ok::<Bytes, std::io::Error>(bytes), Some(recv)))
				}
				Ok(None) => None,
				Err(e) => Some((Err(std::io::Error::other(e.to_string())), None)),
			}
		});
		backend_request = backend_request.body(reqwest::Body::wrap_stream(body_stream));
	} else {
		while recv_half.recv_data().await?.is_some() {}
	}

	let backend_response = match backend_request.send().await {
		Ok(resp) => resp,
		Err(err) => {
			let resp = Response::builder().status(502).body(())?;
			let _ = send_half.send_response(resp).await;
			let _ = send_half.finish().await;
			return Err(err.into());
		}
	};
	let status = backend_response.status();
	let headers = backend_response.headers().clone();
	let expected_body_len = headers
		.get(CONTENT_LENGTH)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.parse::<u64>().ok());

	let mut response = Response::builder().status(status);
	for (name, value) in &headers {
		if is_forwardable_response_header(name) {
			response = response.header(name, value);
		}
	}
	let response = response.body(())?;
	send_half.send_response(response).await?;

	let mut sent_body_len = 0u64;
	let mut body_stream = backend_response.bytes_stream();
	while let Some(chunk) = body_stream.next().await {
		let chunk = match chunk {
			Ok(chunk) => chunk,
			Err(err) => {
				send_half.stop_stream(Code::H3_INTERNAL_ERROR);
				return Err(err.into());
			}
		};
		if !chunk.is_empty() {
			sent_body_len += chunk.len() as u64;
			if expected_body_len.is_some_and(|expected| sent_body_len > expected) {
				send_half.stop_stream(Code::H3_INTERNAL_ERROR);
				return Err(eyre::eyre!(
					"backend response body exceeded content-length: sent {sent_body_len} bytes, expected {expected} bytes",
					expected = expected_body_len.unwrap()
				));
			}
			if let Err(err) = send_half.send_data(chunk).await {
				send_half.stop_stream(Code::H3_INTERNAL_ERROR);
				return Err(err.into());
			}
		}
	}
	if let Some(expected) = expected_body_len
		&& sent_body_len != expected
	{
		send_half.stop_stream(Code::H3_INTERNAL_ERROR);
		return Err(eyre::eyre!(
			"backend response body ended early: sent {sent_body_len} bytes, expected {expected} bytes"
		));
	}
	send_half.finish().await?;
	Ok(())
}

fn rewrite_target_url(backend: &Url, uri: &Uri) -> eyre::Result<Url> {
	let mut target = backend.clone();
	let path_and_query = uri.path_and_query().map(|v| v.as_str()).unwrap_or("/");
	target.set_path("");
	target.set_query(None);
	let target = target.join(path_and_query)?;
	Ok(target)
}

fn is_forwardable_header(name: &HeaderName) -> bool {
	is_forwardable_common_header(name) && !matches!(name.as_str().to_ascii_lowercase().as_str(), "content-length")
}

fn is_forwardable_response_header(name: &HeaderName) -> bool {
	is_forwardable_common_header(name)
}

fn request_has_body(request: &Request<()>) -> bool {
	if request
		.headers()
		.get(CONTENT_LENGTH)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.parse::<u64>().ok())
		.is_some_and(|len| len > 0)
	{
		return true;
	}

	matches!(
		*request.method(),
		axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::PATCH
	)
}

fn is_forwardable_common_header(name: &HeaderName) -> bool {
	!matches!(
		name.as_str().to_ascii_lowercase().as_str(),
		"connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" | "te" | "trailer" | "host"
	)
}
