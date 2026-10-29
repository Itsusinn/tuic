//! Socket and directory lifecycle checks for the test harness.
use std::{path::Path, time::Duration};

use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	time::timeout,
};
use tuic_tests::{TempDataDir, run_tcp_echo_server};

/// Count the entries of a directory. Used to prove that a data directory
/// comes and goes, so the caller passes a directory it owns exclusively.
fn count_entries(dir: &Path) -> usize {
	std::fs::read_dir(dir).expect("the directory must be readable").count()
}

/// Write a file into `dir` so it cannot be mistaken for an empty directory.
fn seed(dir: &Path) {
	std::fs::write(dir.join("seed.txt"), b"seed").expect("writing into the data dir must succeed");
}

/// The echo helper must hand back every byte it received, even when the
/// payload is bigger than one receive buffer and arrives in several TCP
/// segments. It used to issue exactly one 1024-byte `read` followed by one
/// echo, so the peer saw a truncated reply and then EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_echo_server_returns_a_payload_larger_than_one_read() {
	let (echo_task, echo_addr) = run_tcp_echo_server("127.0.0.1:0", "split-echo").await;

	// 3000 bytes is roughly three times the helper's receive buffer; each
	// 1500-byte write is itself split by the send/receive boundary so a
	// single read can never observe the whole payload.
	let payload: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
	let mut stream = tokio::net::TcpStream::connect(echo_addr).await.unwrap();
	for chunk in payload.chunks(1500) {
		stream.write_all(chunk).await.unwrap();
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	// Half-close so the echo server observes EOF instead of waiting for its
	// read deadline to expire.
	stream.shutdown().await.unwrap();

	let mut echoed = Vec::new();
	let read = timeout(Duration::from_secs(5), stream.read_to_end(&mut echoed)).await;
	echo_task.abort();

	read.expect("the echo must complete before the deadline")
		.expect("reading the echo must succeed");
	assert_eq!(echoed, payload, "the echo server must return every byte it received");
}

/// The per-case server data directory has to be removed again, in both the
/// normal `Drop` path and after an explicit `cleanup`. It used to be a bare
/// `PathBuf` under the system temp dir with nothing owning its removal, so
/// every case leaked one directory (with a generated self-signed
/// certificate in it) on every run.
///
/// Each half of the test runs under its own empty parent directory, so the
/// assertion cannot observe a data directory created by another case in a
/// parallel thread or left behind by an earlier run.
#[test]
fn a_temp_data_dir_is_deleted_when_its_guard_is_dropped() {
	let base = TempDataDir::new("wind-tuic-test-guard-base");
	let base_path = base.path().to_path_buf();

	{
		let guard = TempDataDir::with_base(&base_path, "case");
		let path = guard.path().to_path_buf();
		seed(&path);
		assert!(path.is_dir(), "{} must exist while the guard is alive", path.display());
		assert_eq!(count_entries(&base_path), 1, "the guard must own exactly one directory");
		drop(guard);
		assert!(!path.exists(), "{} must be gone once the guard is dropped", path.display());
		assert_eq!(count_entries(&base_path), 0, "dropping the guard must remove its directory");
	}

	{
		let guard = TempDataDir::with_base(&base_path, "case");
		let path = guard.path().to_path_buf();
		seed(&path);
		guard.cleanup();
		assert!(
			!path.exists(),
			"{} must be gone right after an explicit cleanup",
			path.display()
		);
		drop(guard);
		assert!(!path.exists(), "{} must stay gone after cleanup", path.display());
		assert_eq!(count_entries(&base_path), 0, "an explicit cleanup must remove it");
	}
}
