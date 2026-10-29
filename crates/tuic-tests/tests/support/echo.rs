use std::{net::SocketAddr, time::Duration};

use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpListener,
	time::timeout,
};
use tracing::info;

/// Upper bound for one echoed connection: the peer may connect and then go
/// silent, and the per-connection task must not stay alive forever.
const ECHO_DEADLINE: Duration = Duration::from_secs(3);

/// Start a multi-connection TCP echo server that handles `count` concurrent
/// connections, each in its own spawned task.
pub async fn run_multi_echo(addr: &str, count: usize) -> (tokio::task::JoinHandle<()>, SocketAddr) {
	let listener = TcpListener::bind(addr).await.unwrap();
	let server_addr = listener.local_addr().unwrap();
	info!("[multi-echo] listening on {server_addr}, expecting {count} connections");

	let handle = tokio::spawn(async move {
		let mut accepted = 0;
		while accepted < count {
			match listener.accept().await {
				Ok((mut socket, peer)) => {
					accepted += 1;
					info!("[multi-echo] connection {accepted}/{count} from {peer}");
					tokio::spawn(async move {
						let mut buf = vec![0u8; 65536];
						// Echo every chunk until the peer half-closes or the
						// deadline elapses: one `read` + `write_all` truncates
						// payloads that arrive split across TCP segments,
						// because the socket closes right after that echo.
						let deadline = std::time::Instant::now() + ECHO_DEADLINE;
						loop {
							let remaining = deadline.saturating_duration_since(std::time::Instant::now());
							match timeout(remaining, socket.read(&mut buf)).await {
								Ok(Ok(0)) => break,
								Ok(Ok(n)) => {
									if let Err(e) = socket.write_all(&buf[..n]).await {
										info!("[multi-echo] failed to echo {n} bytes back: {e}");
										break;
									}
								}
								Ok(Err(e)) => {
									info!("[multi-echo] read error: {e}");
									break;
								}
								Err(_) => {
									info!("[multi-echo] connection idle past the echo deadline");
									break;
								}
							}
						}
					});
				}
				Err(e) => {
					info!("[multi-echo] accept error: {e}");
					break;
				}
			}
		}
		info!("[multi-echo] all {accepted} connections handled");
	});

	(handle, server_addr)
}
