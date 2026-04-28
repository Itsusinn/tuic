use std::sync::Arc;

use axum::http::{
	HeaderName, Request, Response, Uri,
	header::{HOST, HeaderValue},
};
use bytes::{Buf, Bytes};
use futures_util::StreamExt;
use h3::server;
use quinn::Connection;
use reqwest::{Client, Method, Url};
use tracing::{debug, info, warn};

use crate::{AppContext, config::CamouflageConfig, h3_quinn_compat};

const MAX_REQUEST_BODY_SIZE: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_BODY_SIZE: usize = 64 * 1024 * 1024;

pub async fn handle(
	ctx: Arc<AppContext>,
	conn: Connection,
	prefetched_uni: Option<h3_quinn_compat::PeekableRecvStream>,
	prefetched_bi: Option<h3_quinn_compat::PrefetchedBiRecv>,
) -> eyre::Result<()> {
	let Some(camouflage) = ctx.cfg.camouflage.as_ref().filter(|cfg| cfg.enabled) else {
		return Ok(());
	};

	let (backend, backend_host_override, client) = build_backend_route(camouflage)?;

	info!(
		"[{id:#010x}] [{addr}] [camouflage] HTTP/3 camouflage enabled, reverse proxy target={target}, backend_host={host:?}",
		id = conn.stable_id() as u32,
		addr = conn.remote_address(),
		target = backend,
		host = backend_host_override
	);

	let quic_conn = h3_quinn_compat::Connection::new_with_prefetched(conn, prefetched_uni, prefetched_bi);
	let mut h3_conn = server::Connection::new(quic_conn).await?;

	while let Some(resolver) = h3_conn.accept().await? {
		let (request, mut stream) = resolver.resolve_request().await?;
		debug!(
			"[camouflage] incoming h3 request: method={} uri={}",
			request.method(),
			request.uri()
		);

		match forward_request(&client, &backend, backend_host_override.as_deref(), request, &mut stream).await {
			Ok(()) => {}
			Err(err) => {
				warn!("[camouflage] request forwarding failed: {err}");
				let resp = Response::builder().status(502).body(())?;
				_ = stream.send_response(resp).await;
				_ = stream.finish().await;
			}
		}
	}

	Ok(())
}

fn build_backend_route(camouflage: &CamouflageConfig) -> eyre::Result<(Url, Option<String>, Client)> {
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
		.timeout(camouflage.request_timeout);
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
	Ok((backend, backend_host_override, client))
}

async fn forward_request<S>(
	client: &Client,
	backend: &Url,
	backend_host_override: Option<&str>,
	request: Request<()>,
	stream: &mut server::RequestStream<S, Bytes>,
) -> eyre::Result<()>
where
	S: h3::quic::BidiStream<Bytes>,
{
	let target = rewrite_target_url(backend, request.uri())?;
	let method = Method::from_bytes(request.method().as_str().as_bytes())?;
	let mut backend_request = client.request(method, target);

	for (name, value) in request.headers() {
		if is_forwardable_header(name) {
			backend_request = backend_request.header(name, value);
		}
	}
	if let Some(host) = backend_host_override {
		backend_request = backend_request.header(HOST, host);
	} else if let Some(host) = request
		.headers()
		.get(HOST)
		.and_then(|h| HeaderValue::from_bytes(h.as_bytes()).ok())
	{
		backend_request = backend_request.header(HOST, host);
	}

	let request_body = read_request_body(stream).await?;
	if !request_body.is_empty() {
		backend_request = backend_request.body(request_body);
	}

	let backend_response = backend_request.send().await?;
	let status = backend_response.status();
	let headers = backend_response.headers().clone();

	let mut response = Response::builder().status(status);
	for (name, value) in &headers {
		if is_forwardable_header(name) {
			response = response.header(name, value);
		}
	}
	let response = response.body(())?;
	stream.send_response(response).await?;

	let mut body_size = 0usize;
	let mut body_stream = backend_response.bytes_stream();
	while let Some(chunk) = body_stream.next().await {
		let chunk = chunk?;
		body_size += chunk.len();
		if body_size > MAX_RESPONSE_BODY_SIZE {
			return Err(eyre::eyre!(
				"response body too large: {} bytes (max {})",
				body_size,
				MAX_RESPONSE_BODY_SIZE
			));
		}
		if !chunk.is_empty() {
			stream.send_data(chunk).await?;
		}
	}
	stream.finish().await?;
	Ok(())
}

async fn read_request_body<S>(stream: &mut server::RequestStream<S, Bytes>) -> eyre::Result<Bytes>
where
	S: h3::quic::BidiStream<Bytes>,
{
	let mut body = Vec::new();

	while let Some(mut chunk) = stream.recv_data().await? {
		let remaining = chunk.remaining();
		body.extend_from_slice(chunk.copy_to_bytes(remaining).as_ref());
		if body.len() > MAX_REQUEST_BODY_SIZE {
			return Err(eyre::eyre!(
				"request body too large: {} bytes (max {})",
				body.len(),
				MAX_REQUEST_BODY_SIZE
			));
		}
	}
	let _ = stream.recv_trailers().await?;

	Ok(Bytes::from(body))
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
	!matches!(
		name.as_str().to_ascii_lowercase().as_str(),
		"connection"
			| "keep-alive"
			| "proxy-connection"
			| "transfer-encoding"
			| "upgrade"
			| "te" | "trailer"
			| "host" | "content-length"
	)
}
