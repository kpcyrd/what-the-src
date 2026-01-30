use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{self, AsyncRead, ReadBuf};

pub const SIZE: usize = 16;

pub const fn buf() -> [MaybeUninit<u8>; SIZE] {
    [MaybeUninit::uninit(); SIZE]
}

pub struct ReadAhead<'a, R> {
    reader: R,
    buf: ReadBuf<'a>,
    read_pos: usize,
    eof: bool,
}

impl<'a, R: AsyncRead + Unpin> ReadAhead<'a, R> {
    pub fn new(reader: R, buf: ReadBuf<'a>) -> Self {
        Self {
            reader,
            buf,
            read_pos: 0,
            eof: false,
        }
    }

    pub async fn peek(&mut self) -> io::Result<&[u8]> {
        while self.buf.remaining() > 0 && !self.eof {
            let n = tokio_util::io::read_buf(&mut self.reader, &mut self.buf).await?;
            if n == 0 {
                self.eof = true;
            }
        }

        Ok(self.buf.filled())
    }
}

impl<'a, R: AsyncRead + Unpin> AsyncRead for ReadAhead<'a, R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();

        // Return peeked data (if any)
        if let Some(remaining) = this.buf.filled().get(this.read_pos..)
            && !remaining.is_empty()
        {
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.read_pos = this.read_pos.saturating_add(to_copy);
            return Poll::Ready(Ok(()));
        }

        // Don't try to read more if we've hit EOF during peek
        if this.eof {
            return Poll::Ready(Ok(()));
        }

        // Read new data from reader into their buffer
        match Pin::new(&mut this.reader).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::throttle::PartialReader;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_readahead_basic() {
        let src = b"Hello, world!" as &[u8];
        let mut buf = buf();
        let mut stream = ReadAhead::new(src, ReadBuf::uninit(&mut buf));

        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(src, &output);
    }

    #[tokio::test]
    async fn test_readahead_peeked() {
        let src =
            b"Hello, world! This is a little bit more text to verify the peek works." as &[u8];
        let mut buf = buf();
        let mut stream = ReadAhead::new(src, ReadBuf::uninit(&mut buf));

        let peek = stream.peek().await.unwrap();
        assert_eq!(peek, b"Hello, world! Th");

        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(src, &output);
    }

    #[tokio::test]
    async fn test_readahead_peeked_short_reads() {
        let src =
            b"Hello, world! This is a little bit more text to verify the peek works." as &[u8];
        let throttle = PartialReader::new(src, 2);
        let mut buf = buf();
        let mut stream = ReadAhead::new(throttle, ReadBuf::uninit(&mut buf));

        let peek = stream.peek().await.unwrap();
        assert_eq!(peek, b"Hello, world! Th");

        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(src, &output);
    }

    #[tokio::test]
    async fn test_readahead_peeked_short_reads_little_data() {
        let src = b"Hello" as &[u8];
        let throttle = PartialReader::new(src, 2);
        let mut buf = buf();
        let mut stream = ReadAhead::new(throttle, ReadBuf::uninit(&mut buf));

        let peek = stream.peek().await.unwrap();
        assert_eq!(peek, b"Hello");

        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(src, &output);
    }
}
