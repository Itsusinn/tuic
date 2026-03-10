#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    use tokio::io::duplex;
    use tuic_server::io::Peekable;

    #[tokio::test]
    async fn test_peekable_basic() {
        let (mut a, mut b) = duplex(1024);
        // write some bytes from 'a' side
        a.write_all(b"hello").await.unwrap();

        // wrap reader side 'b' into Peekable
        let mut reader = Peekable::new(b, 4096);

        // peek 3 bytes
        let s = reader.peek(3).await.unwrap();
        assert_eq!(s, b"hel");

        // subsequent read should still get full data
        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
    }
}
