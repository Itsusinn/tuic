use std::collections::HashSet;

use super::shutdown_fixture::{build_minimal_server_config, build_server_config_with_user};

// ---------------------------------------------------------------------------
// data-directory ownership
// ---------------------------------------------------------------------------

/// Every server config this file builds must carry its own data directory, so
/// that no two cases — running in parallel here, or in two sequential runs —
/// can share one path.
///
/// The directory used to be a fixed name under the system temp dir
/// (`tuic-graceful-shutdown-test` and friends) that nothing removed. A shared
/// path is a latent cross-run conflict even while it happens to stay empty:
/// the server writes into `data_dir` as soon as geodata or ACME is enabled.
/// The guard also means the directory is gone when the test ends rather than
/// accumulating in the temp dir.
#[test]
fn each_server_config_owns_a_unique_data_dir() {
	let uuid = uuid::Uuid::new_v4();

	let (minimal, minimal_dir) = build_minimal_server_config();
	let (active, active_dir) = build_server_config_with_user(uuid, "test-password");
	let (traffic, traffic_dir) = build_server_config_with_user(uuid, "test-pass");

	let dirs = [&minimal_dir, &active_dir, &traffic_dir];
	let paths: Vec<std::path::PathBuf> = dirs.iter().map(|d| d.path().to_path_buf()).collect();
	// The directory must be one level under the system temp dir; compare the
	// canonical parent so a trailing separator cannot make the check vacuous.
	let temp_dir = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalise the system temp dir");

	assert_eq!(
		paths.iter().collect::<HashSet<_>>().len(),
		paths.len(),
		"each config must get its own data directory, got {paths:?}"
	);
	for (config, path) in [(&minimal, &paths[0]), (&active, &paths[1]), (&traffic, &paths[2])] {
		assert_eq!(
			&config.data_dir, path,
			"the config must point at the directory its guard owns"
		);
		assert_eq!(
			path.parent().and_then(|p| std::fs::canonicalize(p).ok()),
			Some(temp_dir.clone()),
			"{} must live under the system temp dir",
			path.display()
		);
		let name = path
			.file_name()
			.and_then(|n| n.to_str())
			.expect("the data directory must have a UTF-8 name");
		let suffix = name
			.strip_prefix("tuic-graceful-shutdown-")
			.unwrap_or_else(|| panic!("{name} must be named after the case that owns it"));
		assert!(
			uuid::Uuid::parse_str(suffix).is_ok(),
			"{name} must end in a UUID so two runs cannot collide"
		);
		assert!(path.is_dir(), "{} must exist while its guard is alive", path.display());
	}
}
