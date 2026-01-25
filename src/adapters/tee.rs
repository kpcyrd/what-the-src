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
    read_pos: usize,
}

impl<'a, R: AsyncRead + Unpin, W: AsyncWrite + Unpin> TeeStream<'a, R, W> {
    pub const fn new(reader: R, writer: W, buf: ReadBuf<'a>) -> Self {
        Self {
            reader,
            writer,
            buf,
            write_pos: 0,
            read_pos: 0,
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

        // First, try to write any data that hasn't been written yet
        if self.write_pos < buffered_len {
            let written = self.flush_to_writer(cx)?;
            self.write_pos += written;

            if self.write_pos < buffered_len {
                // Writer would block, retry on next poll_read
                return Poll::Pending;
            }
        }

        // All data written to writer - now forward to caller
        let to_forward = (buffered_len - self.read_pos).min(buf.remaining());
        if to_forward > 0 {
            let buffered = self.buf.filled();
            buf.put_slice(&buffered[self.read_pos..self.read_pos + to_forward]);
            self.read_pos += to_forward;
        }

        if self.read_pos < buffered_len {
            // Caller's buffer is full, but we have more data to forward
            // Return Ready since we did make progress
            return Poll::Ready(Ok(()));
        }

        // All data has been written and forwarded - clear state
        self.buf.clear();
        self.write_pos = 0;
        self.read_pos = 0;
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
    use std::io;
    use std::task::Context;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_tee_stream_basic() {
        let src = b"Hello, world!";

        let mut buf = buf();
        let mut copy = Vec::<u8>::new();
        let mut stream = TeeStream::new(&src[..], &mut copy, ReadBuf::uninit(&mut buf[..]));

        let mut read_buf = Vec::new();
        stream.read_to_end(&mut read_buf).await.unwrap();

        assert_eq!(&read_buf, src);
        assert_eq!(&copy, src);
    }

    #[tokio::test]
    async fn test_tee_stream_empty() {
        let src = b"";

        let mut buf = buf();
        let mut copy = Vec::<u8>::new();
        let mut stream = TeeStream::new(&src[..], &mut copy, ReadBuf::uninit(&mut buf[..]));

        let mut read_buf = Vec::new();
        stream.read_to_end(&mut read_buf).await.unwrap();

        assert_eq!(&read_buf, src);
        assert_eq!(&copy, src);
    }

    #[tokio::test]
    async fn test_tee_stream_large_data() {
        let src = vec![0x42u8; 10000];

        let mut buf = buf();
        let mut copy = Vec::<u8>::new();
        let mut stream = TeeStream::new(&src[..], &mut copy, ReadBuf::uninit(&mut buf[..]));

        let mut read_buf = Vec::new();
        stream.read_to_end(&mut read_buf).await.unwrap();

        assert_eq!(&read_buf, &src);
        assert_eq!(&copy, &src);
    }

    #[tokio::test]
    async fn test_tee_stream_small_reads() {
        let src = b"Hello, world!";

        let mut buf = buf();
        let mut copy = Vec::<u8>::new();
        let mut stream = TeeStream::new(&src[..], &mut copy, ReadBuf::uninit(&mut buf[..]));

        // Read data in small chunks
        let mut read_buf = Vec::new();
        let mut chunk = [0u8; 3];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            read_buf.extend_from_slice(&chunk[..n]);
        }

        assert_eq!(&read_buf, src);
        assert_eq!(&copy, src);
    }

    // Mock writer that only writes partial data
    struct PartialWriter {
        data: Vec<u8>,
        chunk_size: usize,
    }

    impl PartialWriter {
        fn new(chunk_size: usize) -> Self {
            Self {
                data: Vec::new(),
                chunk_size,
            }
        }
    }

    impl AsyncWrite for PartialWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let to_write = buf.len().min(self.chunk_size);
            self.data.extend_from_slice(&buf[..to_write]);
            Poll::Ready(Ok(to_write))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_tee_stream_partial_writes() {
        let src = b"Hello, world! This is a longer message.";

        let mut buf = buf();
        let mut writer = PartialWriter::new(5); // Only write 5 bytes at a time
        let mut stream = TeeStream::new(&src[..], &mut writer, ReadBuf::uninit(&mut buf[..]));

        let mut read_buf = Vec::new();
        stream.read_to_end(&mut read_buf).await.unwrap();

        assert_eq!(&read_buf, src);
        assert_eq!(&writer.data, src);
    }
}
