pub fn parse_sni(data: &[u8]) -> Option<String> {
	if data.len() < 5 {
		return None; // Need more data
	}

	// Check if it's a TLS Handshake record (0x16)
	if data[0] != 0x16 {
		return None;
	}

	// Check version (TLS 1.0 - TLS 1.3 usually have 0x03 as major version)
	if data[1] != 0x03 {
		return None;
	}

	let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
	if data.len() < 5 + record_len {
		return None; // Need more data for the full record
	}

	// Start parsing Handshake message
	let mut pos = 5;

	// Handshake Type: Client Hello (1)
	if data[pos] != 0x01 {
		return None;
	}
	pos += 1;

	// Length of Client Hello (3 bytes)
	let _msg_len = ((data[pos] as usize) << 16) | ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
	pos += 3;

	// Client Version (2 bytes)
	pos += 2;

	// Client Random (32 bytes)
	pos += 32;

	// Session ID length + Session ID
	if pos >= data.len() {
		return None;
	}
	let session_id_len = data[pos] as usize;
	pos += 1 + session_id_len;

	// Cipher Suites length + Cipher Suites
	if pos + 2 > data.len() {
		return None;
	}
	let cipher_suites_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
	pos += 2 + cipher_suites_len;

	// Compression Methods length + Compression Methods
	if pos >= data.len() {
		return None;
	}
	let comp_methods_len = data[pos] as usize;
	pos += 1 + comp_methods_len;

	// Extensions Length
	if pos + 2 > data.len() {
		return None;
	}
	let ext_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
	pos += 2;

	let ext_end = pos + ext_len;
	if ext_end > data.len() {
		return None;
	}

	// Parse extensions
	while pos + 4 <= ext_end {
		let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
		let ext_length = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
		pos += 4;

		if pos + ext_length > ext_end {
			break;
		}

		// Server Name Indication (type 0)
		if ext_type == 0 {
			let mut sni_pos = pos;
			if sni_pos + 2 > pos + ext_length {
				break;
			}

			// Server Name list length
			let _list_len = ((data[sni_pos] as usize) << 8) | (data[sni_pos + 1] as usize);
			sni_pos += 2;

			// Parse names
			while sni_pos + 3 <= pos + ext_length {
				let name_type = data[sni_pos];
				let name_len = ((data[sni_pos + 1] as usize) << 8) | (data[sni_pos + 2] as usize);
				sni_pos += 3;

				if sni_pos + name_len > pos + ext_length {
					break;
				}

				// Host_name type is 0
				if name_type == 0 {
					if let Ok(sni) = std::str::from_utf8(&data[sni_pos..sni_pos + name_len]) {
						return Some(sni.to_string());
					}
				}
				sni_pos += name_len;
			}
		}

		pos += ext_length;
	}

	None
}
