use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BUFFER_SIZE: usize = 16 * 1024;

pub async fn copy_io<A, B>(a: &mut A, b: &mut B) -> (usize, usize, Option<std::io::Error>)
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	let a2b = Box::new_uninit_slice(BUFFER_SIZE);
	let mut a2b = unsafe { a2b.assume_init() };
	let b2a = Box::new_uninit_slice(BUFFER_SIZE);
	let mut b2a = unsafe { b2a.assume_init() };

	let mut a2b_num = 0;
	let mut b2a_num = 0;

	let mut last_err = None;

	loop {
		tokio::select! {
		   a2b_res = a.read(&mut a2b) => match a2b_res {
			  Ok(num) => {
				 // EOF
				 if num == 0 {
					break;
				 }
				 a2b_num += num;
				 if let Err(err) = b.write_all(&a2b[..num]).await {
					last_err = Some(err);
					break;
				 }
			  },
			  Err(err) => {
				 last_err = Some(err);
				 break;
			  }
		   },
		   b2a_res = b.read(&mut b2a) => match b2a_res {
			  Ok(num) => {
				 // EOF
				 if num == 0 {
					break;
				 }
				 b2a_num += num;
				 if let Err(err) = a.write_all(&b2a[..num]).await {
					last_err = Some(err);
					break;
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
	use super::*;

	#[tokio::test]
	async fn test_copy_io_bidirectional() {
		// Create two duplex streams: client-side and server-side
		let (mut client_a, mut client_b) = tokio::io::duplex(1024);
		let (mut server_a, mut server_b) = tokio::io::duplex(1024);

		let data_to_server = b"Request from client";
		let data_to_client = b"Response from server";

		// Spawn copy_io to connect the two streams
		let copy_task = tokio::spawn(async move { copy_io(&mut client_b, &mut server_b).await });

		// Write from client side
		client_a.write_all(data_to_server).await.unwrap();

		// Write from server side
		server_a.write_all(data_to_client).await.unwrap();

		// Read on client side (should receive data from server)
		let mut client_buf = vec![0u8; data_to_client.len()];
		client_a.read_exact(&mut client_buf).await.unwrap();

		// Read on server side (should receive data from client)
		let mut server_buf = vec![0u8; data_to_server.len()];
		server_a.read_exact(&mut server_buf).await.unwrap();

		assert_eq!(&client_buf, data_to_client);
		assert_eq!(&server_buf, data_to_server);

		// Close both ends
		drop(client_a);
		drop(server_a);

		let (a2b_count, b2a_count, err) = copy_task.await.unwrap();

		assert!(err.is_none());
		assert_eq!(a2b_count, data_to_server.len());
		assert_eq!(b2a_count, data_to_client.len());
	}

	#[tokio::test]
	async fn test_copy_io_one_direction() {
		// Create two duplex streams
		let (mut left_a, mut left_b) = tokio::io::duplex(1024);
		let (mut right_a, mut right_b) = tokio::io::duplex(1024);

		let test_data = b"Hello, world!";

		// Spawn copy_io to connect the streams
		let copy_task = tokio::spawn(async move { copy_io(&mut left_b, &mut right_b).await });

		// Write from left side
		left_a.write_all(test_data).await.unwrap();

		// Read from right side
		let mut buf = vec![0u8; test_data.len()];
		right_a.read_exact(&mut buf).await.unwrap();

		assert_eq!(&buf, test_data);

		// Close streams
		drop(left_a);
		drop(right_a);

		let (a2b_count, b2a_count, _err) = copy_task.await.unwrap();

		assert_eq!(a2b_count, test_data.len());
		assert_eq!(b2a_count, 0);
	}
}
