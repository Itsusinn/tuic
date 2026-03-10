pub mod tls;
pub mod http;

use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug)]
pub enum SniffResult {
	Tls(String),
	Http(String),
	Unknown,
	NeedMoreData,
}

const MAX_SNIFF_BYTES: usize = 4096;

pub async fn sniff<R: AsyncRead + Unpin>(
	stream: &mut R,
	buffer: &mut Vec<u8>,
) -> std::io::Result<SniffResult> {
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
