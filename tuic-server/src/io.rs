use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BUFFER_SIZE: usize = 16 * 1024;

pub async fn copy_io<A, B>(a: &mut A, b: &mut B) -> (usize, usize, Option<std::io::Error>)
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	let mut a2b = unsafe { Box::new_uninit_slice(BUFFER_SIZE).assume_init() };
	let mut b2a = unsafe { Box::new_uninit_slice(BUFFER_SIZE).assume_init() };

	let mut a2b_num = 0;
	let mut b2a_num = 0;

	let mut a_eof = false;
	let mut b_eof = false;

	let mut last_err = None;

	loop {
		tokio::select! {
		   a2b_res = a.read(&mut a2b), if !a_eof => match a2b_res {
			  Ok(num) => {
				 if num == 0 {
					a_eof = true;
					if let Err(err) = b.shutdown().await {
						last_err = Some(err);
					}
					if b_eof {
						break;
					}
				 } else {
					a2b_num += num;
					if let Err(err) = b.write_all(&a2b[..num]).await {
						last_err = Some(err);
						break;
					}
				 }
			  },
			  Err(err) => {
				 last_err = Some(err);
				 break;
			  }
		   },
		   b2a_res = b.read(&mut b2a), if !b_eof => match b2a_res {
			  Ok(num) => {
				 if num == 0 {
					b_eof = true;
					if let Err(err) = a.shutdown().await {
						last_err = Some(err);
					}
					if a_eof {
						break;
					}
				 } else {
					b2a_num += num;
					if let Err(err) = a.write_all(&b2a[..num]).await {
						last_err = Some(err);
						break;
					}
				 }
			  },
			  Err(err) => {
				 last_err = Some(err);
				 break;
			  },
		   }
		}
	}

	(a2b_num, b2a_num, last_err)
}

#[cfg(test)]
mod tests {
	use tokio::io::duplex;

	use super::*;

	#[tokio::test]
	async fn test_copy_io_bidirectional() {
		let (mut client, mut server_side) = duplex(1024);
		let (mut remote, mut remote_side) = duplex(1024);

		let data_to_remote = b"hello from client";
		let data_to_client = b"hello from remote";

		// Spawn writer tasks that write and then shut down
		let client_writer = tokio::spawn(async move {
			client.write_all(data_to_remote).await.unwrap();
			client.shutdown().await.unwrap();
			// Read response
			let mut buf = Vec::new();
			client.read_to_end(&mut buf).await.unwrap();
			buf
		});

		let remote_writer = tokio::spawn(async move {
			remote_side.write_all(data_to_client).await.unwrap();
			remote_side.shutdown().await.unwrap();
			let mut buf = Vec::new();
			remote_side.read_to_end(&mut buf).await.unwrap();
			buf
		});

		let (a2b, b2a, err) = copy_io(&mut server_side, &mut remote).await;

		assert_eq!(a2b, data_to_remote.len());
		assert_eq!(b2a, data_to_client.len());
		assert!(err.is_none());

		let client_received = client_writer.await.unwrap();
		let remote_received = remote_writer.await.unwrap();
		assert_eq!(client_received, data_to_client);
		assert_eq!(remote_received, data_to_remote);
	}

	#[tokio::test]
	async fn test_copy_io_empty_streams() {
		let (mut client, mut server_side) = duplex(1024);
		let (mut remote, mut remote_side) = duplex(1024);

		// Close both sides immediately
		tokio::spawn(async move {
			client.shutdown().await.unwrap();
		});
		tokio::spawn(async move {
			remote_side.shutdown().await.unwrap();
		});

		let (a2b, b2a, _err) = copy_io(&mut server_side, &mut remote).await;

		assert_eq!(a2b, 0);
		assert_eq!(b2a, 0);
	}

	#[tokio::test]
	async fn test_copy_io_one_direction_only() {
		let (mut client, mut server_side) = duplex(1024);
		let (mut remote, mut remote_side) = duplex(1024);

		let data = b"one way only";

		tokio::spawn(async move {
			client.write_all(data).await.unwrap();
			client.shutdown().await.unwrap();
			// Drain incoming
			let mut buf = Vec::new();
			let _ = client.read_to_end(&mut buf).await;
		});

		tokio::spawn(async move {
			// Only read, don't write
			remote_side.shutdown().await.unwrap();
			let mut buf = Vec::new();
			let _ = remote_side.read_to_end(&mut buf).await;
		});

		let (a2b, b2a, _err) = copy_io(&mut server_side, &mut remote).await;

		assert_eq!(a2b, data.len());
		assert_eq!(b2a, 0);
	}

	#[tokio::test]
	async fn test_copy_io_large_data() {
		let (mut client, mut server_side) = duplex(64 * 1024);
		let (mut remote, mut remote_side) = duplex(64 * 1024);

		let data = vec![0xAB; 100_000];
		let data_clone = data.clone();

		tokio::spawn(async move {
			client.write_all(&data_clone).await.unwrap();
			client.shutdown().await.unwrap();
			let mut buf = Vec::new();
			let _ = client.read_to_end(&mut buf).await;
		});

		tokio::spawn(async move {
			// Echo!
			remote_side.shutdown().await.unwrap();
			let mut buf = Vec::new();
			let _ = remote_side.read_to_end(&mut buf).await;
		});

		let (a2b, b2a, _err) = copy_io(&mut server_side, &mut remote).await;

		assert_eq!(a2b, 100_000);
		assert_eq!(b2a, 0);
	}
}
