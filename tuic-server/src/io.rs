use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BUFFER_SIZE: usize = 16 * 1024;

pub async fn copy_io<A, B>(a: &mut A, b: &mut B) -> (usize, usize, Option<std::io::Error>)
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	// let a2b = bytes::BytesMut::with_capacity(BUFFER_SIZE);

	let a2b = Box::new_uninit_slice(BUFFER_SIZE);
	let mut a2b = unsafe { a2b.assume_init() };
	let b2a = Box::new_uninit_slice(BUFFER_SIZE);
	let mut b2a = unsafe { b2a.assume_init() };

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
