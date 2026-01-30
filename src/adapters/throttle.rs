use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

/// Mock writer that only writes partial data for testing throttled writes
pub struct PartialWriter {
    pub data: Vec<u8>,
    pub chunk_size: usize,
}

impl PartialWriter {
    pub fn new(chunk_size: usize) -> Self {
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

/// Mock reader that only reads partial data for testing throttled reads
pub struct PartialReader<R> {
    pub reader: R,
    pub chunk_size: usize,
}

impl<R> PartialReader<R> {
    pub fn new(reader: R, chunk_size: usize) -> Self {
        Self { reader, chunk_size }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PartialReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Limit the capacity of the buffer view
        let max_read = buf.remaining().min(self.chunk_size);

        // Use unfilled_mut to get the writable portion, limited to max_read
        let unfilled = buf.initialize_unfilled_to(max_read);
        let mut limited_buf = ReadBuf::new(unfilled);

        // Read into the limited buffer
        match Pin::new(&mut self.reader).poll_read(cx, &mut limited_buf) {
            Poll::Ready(Ok(())) => {
                let n = limited_buf.filled().len();
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_partial_reader() {
        let data = b"Hello, world! This is a longer message.";
        let mut reader = PartialReader::new(&data[..], 2);

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).await.unwrap();

        assert_eq!(n, 2);
    }
}
