use std::{pin::Pin, task::{Context, Poll}, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A wrapper that allows peeking into the stream without permanently consuming bytes.
/// After peek, subsequent reads will still return the peeked bytes first.
pub struct Peekable<T> {
    inner: T,
    buf: Vec<u8>,
    pos: usize,
    max_buf: usize,
}

impl<T> Peekable<T> {
    pub fn new(inner: T, max_buf: usize) -> Self {
        Self { inner, buf: Vec::new(), pos: 0, max_buf }
    }

    /// Returns unread buffered bytes
    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Consume n bytes from the buffer
    pub fn consume(&mut self, n: usize) {
        let avail = self.buf.len().saturating_sub(self.pos);
        let take = n.min(avail);
        self.pos += take;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
    }

    pub fn into_inner(self) -> T { self.inner }
}

impl<T: AsyncRead + Unpin> Peekable<T> {
    /// Ensure at least `need` bytes are buffered (if possible). Returns current buffered slice.
    pub async fn peek(&mut self, need: usize) -> io::Result<&[u8]> {
        if self.buf.len().saturating_sub(self.pos) >= need { return Ok(self.buffered()); }
        // read until have need or reach max_buf
        let mut tmp = [0u8; 1024];
        while self.buf.len().saturating_sub(self.pos) < need {
            if self.max_buf > 0 && self.buf.len().saturating_sub(self.pos) >= self.max_buf { break; }
            let n = Pin::new(&mut self.inner).read(&mut tmp).await?;
            if n == 0 { break; }
            self.buf.extend_from_slice(&tmp[..n]);
            if self.max_buf > 0 && self.buf.len().saturating_sub(self.pos) >= self.max_buf { break; }
        }
        Ok(self.buffered())
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Peekable<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, dst: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.buf.len() {
            let avail = &self.buf[self.pos..];
            let to_copy = avail.len().min(dst.remaining());
            dst.put_slice(&avail[..to_copy]);
            self.pos += to_copy;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        // delegate
        let inner = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.inner) };
        inner.poll_read(cx, dst)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Peekable<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let inner = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.inner) };
        inner.poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.inner) };
        inner.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.inner) };
        inner.poll_shutdown(cx)
    }
}
