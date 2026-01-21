use std::{mem::MaybeUninit, pin::Pin, task::Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const SIZE: usize = 4096;

pub const fn buf() -> [MaybeUninit<u8>; SIZE] {
    [MaybeUninit::uninit(); SIZE]
}

pub struct TeeStream<'a, R, W> {
    reader: R,
    writer: W,
    buf: ReadBuf<'a>,
    write_pos: usize,
}

impl<'a, R: AsyncRead + Unpin, W: AsyncWrite + Unpin> TeeStream<'a, R, W> {
    pub const fn new(reader: R, writer: W, buf: ReadBuf<'a>) -> Self {
        Self {
            reader,
            writer,
            buf,
            write_pos: 0,
        }
    }

    /// Try to write buffered data starting from write_pos, returning additional bytes written.
    /// Returns an error if the writer fails (not if it would block).
    fn flush_to_writer(&mut self, cx: &mut std::task::Context<'_>) -> std::io::Result<usize> {
        let data = self.buf.filled();
        let start = self.write_pos;
        let mut written = 0;

        while start + written < data.len() {
            match Pin::new(&mut self.writer).poll_write(cx, &data[start + written..]) {
                Poll::Ready(Ok(0)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write zero bytes to tee writer",
                    ));
                }
                Poll::Ready(Ok(n)) => written += n,
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => break,
            }
        }
        Ok(written)
    }

    /// Try to flush buffered data to writer. If successful, forward to caller and return Ready.
    /// If writer would block, keep buffered and return Pending.
    fn try_flush_and_forward(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let buffered_len = self.buf.filled().len();
        let written = self.flush_to_writer(cx)?;
        self.write_pos += written;

        if self.write_pos < buffered_len {
            // Writer would block, retry on next poll_read
            return Poll::Pending;
        }

        // All buffered data written - forward to caller
        buf.put_slice(self.buf.filled());
        self.buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }

    pub fn into_inner(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

impl<'a, R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for TeeStream<'a, R, W> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // If we have buffered data from a previous read, try to finish writing it
        if !this.buf.filled().is_empty() {
            return this.try_flush_and_forward(cx, buf);
        }

        // Read new data from reader into our internal buffer
        match Pin::new(&mut this.reader).poll_read(cx, &mut this.buf) {
            Poll::Ready(Ok(())) => {
                if this.buf.filled().is_empty() {
                    // EOF
                    return Poll::Ready(Ok(()));
                }

                // Try to write the data to the writer, then forward to caller
                this.try_flush_and_forward(cx, buf)
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tee_stream() {
        use tokio::io::AsyncReadExt;
        let src = b"Hello, world!";

        let mut buf = buf();
        let mut copy = Vec::<u8>::new();
        let mut stream = TeeStream::new(&src[..], &mut copy, ReadBuf::uninit(&mut buf[..]));

        let mut read_buf = Vec::new();
        stream.read_to_end(&mut read_buf).await.unwrap();

        assert_eq!(&read_buf, src);
        assert_eq!(&copy, src);
    }
}
