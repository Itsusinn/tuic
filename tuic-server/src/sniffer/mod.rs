pub mod http;
pub mod tls;

use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug)]
pub enum SniffResult {
	Tls(String),
	Http(String),
	Unknown,
	NeedMoreData,
}

const MAX_SNIFF_BYTES: usize = 4096;

pub async fn sniff<R: AsyncRead + Unpin>(stream: &mut R, buffer: &mut Vec<u8>) -> std::io::Result<SniffResult> {
	let mut temp_buf = [0u8; 1024];

	loop {
		if let Some(sni) = tls::parse_sni(buffer) {
			return Ok(SniffResult::Tls(sni));
		}
		if let Some(host) = http::parse_host(buffer) {
			return Ok(SniffResult::Http(host));
		}

		// If we've reached max bytes and still can't identify, give up
		if buffer.len() >= MAX_SNIFF_BYTES {
			return Ok(SniffResult::Unknown);
		}

		// Read more data
		let n = stream.read(&mut temp_buf).await?;
		if n == 0 {
			// EOF
			return Ok(SniffResult::Unknown);
		}

		buffer.extend_from_slice(&temp_buf[..n]);
	}
}

/// Non-destructive sniff using Peekable wrapper. This will peek into the stream
/// and populate `buffer` with the peeked bytes for later forwarding if needed.
pub async fn sniff_peek<R: AsyncRead + Unpin>(stream: &mut R, buffer: &mut Vec<u8>) -> std::io::Result<SniffResult> {
	let mut peek = crate::io::Peekable::new(stream, MAX_SNIFF_BYTES);
	let _ = peek.peek(1024).await?;
	let buf = peek.buffered();
	if let Some(sni) = tls::parse_sni(buf) {
		return Ok(SniffResult::Tls(sni));
	}
	if let Some(host) = http::parse_host(buf) {
		return Ok(SniffResult::Http(host));
	}
	// copy buffered bytes into buffer for forwarding
	buffer.extend_from_slice(buf);
	Ok(SniffResult::Unknown)
}
