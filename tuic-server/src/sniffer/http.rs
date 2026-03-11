use httparse::Request;

pub fn parse_host(data: &[u8]) -> Option<String> {
	// Basic check for HTTP methods to avoid parsing binary data unnecessarily
	let methods: &[&[u8]] = &[
		b"GET ",
		b"POST ",
		b"HEAD ",
		b"PUT ",
		b"DELETE ",
		b"OPTIONS ",
		b"TRACE ",
		b"CONNECT ",
		b"PATCH ",
	];

	let is_http = methods.iter().any(|m| data.starts_with(m));
	if !is_http {
		return None;
	}

	let mut headers = [httparse::EMPTY_HEADER; 64];
	let mut req = Request::new(&mut headers);

	match req.parse(data) {
		Ok(_) => {
			for header in req.headers.iter() {
				if header.name.eq_ignore_ascii_case("host") {
					if let Ok(host_str) = std::str::from_utf8(header.value) {
						// Remove port if present, e.g., "example.com:80" -> "example.com"
						let host_only = host_str.split(':').next().unwrap_or(host_str).trim();
						if !host_only.is_empty() {
							return Some(host_only.to_string());
						}
					}
				}
			}
			None
		}
		Err(_) => None,
	}
}
