use std::path::Path;

use boring::pkey::{Id, PKey};

/// Fresh X25519 material and RFC ECHConfig encoding; no checked-in private keys.
pub fn ech_files(dir: &Path, id: u8) -> eyre::Result<(tuic_server::config::EchConfig, std::path::PathBuf)> {
	let key = PKey::generate(Id::X25519)?;
	let mut public = [0; 32];
	let mut private = [0; 32];
	key.raw_public_key(&mut public)?;
	key.raw_private_key(&mut private)?;
	let public_name = b"public.example";
	let mut contents = vec![id, 0, 0x20, 0, 32]; // config_id, X25519 KEM, public-key length
	contents.extend(public);
	contents.extend([0, 4, 0, 1, 0, 1, 0]); // HKDF-SHA256/AES-128-GCM, maximum_name_length
	contents.push(u8::try_from(public_name.len())?);
	contents.extend(public_name);
	contents.extend([0, 0]); // no extensions
	let mut config = vec![0xfe, 0x0d];
	config.extend(u16::try_from(contents.len())?.to_be_bytes());
	config.extend(contents);
	let mut list = u16::try_from(config.len())?.to_be_bytes().to_vec();
	list.extend(&config);
	let config_path = dir.join(format!("ech-{id}.config"));
	let key_path = dir.join(format!("ech-{id}.key"));
	let list_path = dir.join(format!("ech-{id}.list"));
	std::fs::write(&config_path, config)?;
	std::fs::write(&key_path, private)?;
	std::fs::write(&list_path, list)?;
	Ok((
		tuic_server::config::EchConfig {
			config: config_path,
			private_key: key_path,
		},
		list_path,
	))
}
