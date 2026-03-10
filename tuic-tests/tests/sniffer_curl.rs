use std::{net::SocketAddr, process::Stdio};

use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpListener,
	process::Command,
	sync::oneshot,
};

#[tokio::test]
async fn curl_sniffer_integration() {
	// Skip test if curl not found
	if which::which("curl").is_err() {
		eprintln!("curl not found; skipping test");
		return;
	}

	// Start a simple HTTP backend that returns 200 and captures Host
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let (tx, rx) = oneshot::channel::<String>();

	tokio::spawn(async move {
		let (mut s, _) = listener.accept().await.unwrap();
		let mut buf = [0u8; 4096];
		let n = s.read(&mut buf).await.unwrap();
		let req = String::from_utf8_lossy(&buf[..n]);
		// parse Host header
		let host = req
			.lines()
			.find(|l| l.to_ascii_lowercase().starts_with("host:"))
			.map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim().to_string())
			.unwrap_or_default();
		let _ = tx.send(host);
		let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
		let _ = s.write_all(resp).await;
	});

	// Configure to use local tuic server: assume tuic server already running on
	// 127.0.0.1:1080 as SOCKS5 We'll call curl via --socks5-hostname to force
	// hostname to be sent through proxy and let sniffer detect Host header
	let url = format!("http://example.test:{}/ping", addr.port());
	let mut cmd = Command::new("curl");
	cmd.arg("--socks5-hostname").arg("127.0.0.1:1080");
	cmd.arg("-sS").arg("-o").arg("/dev/null").arg("-w").arg("%{http_code}");
	cmd.arg(&url);
	cmd.stdout(Stdio::piped());
	let mut child = cmd.spawn().expect("failed to spawn curl");
	let output = child.wait_with_output().await.expect("curl run failed");
	let code = String::from_utf8_lossy(&output.stdout);
	assert_eq!(code, "200");

	// receive host seen by backend
	let received = rx.await.unwrap_or_default();
	assert_eq!(received, "example.test");
}
