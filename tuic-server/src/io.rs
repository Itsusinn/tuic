use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BUFFER_SIZE: usize = 16 * 1024;

pub async fn copy_io<A, B>(a: &mut A, b: &mut B) -> (usize, usize, Option<std::io::Error>)
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut a2b = [0u8; BUFFER_SIZE];
    let mut b2a = [0u8; BUFFER_SIZE];

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
