use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncSeek, AsyncWrite, SeekFrom};

pub struct OptionalWriter<W> {
    writer: Option<W>,
    position: u64,
}

impl<W> OptionalWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Some(writer),
            position: 0,
        }
    }

    pub const fn discard() -> Self {
        Self {
            writer: None,
            position: 0,
        }
    }

    /// Consumes the wrapper and returns the inner writer.
    pub fn into_inner(self) -> Option<W> {
        self.writer
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for OptionalWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(writer) = &mut self.writer {
            Pin::new(writer).poll_write(cx, buf)
        } else {
            // Pretend we wrote everything
            let bytes = buf.len();
            self.position = self.position.saturating_add(bytes as u64);
            Poll::Ready(Ok(bytes))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(writer) = &mut self.writer {
            Pin::new(writer).poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(writer) = &mut self.writer {
            Pin::new(writer).poll_shutdown(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl<W: AsyncSeek + Unpin> AsyncSeek for OptionalWriter<W> {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        if let Some(writer) = &mut self.writer {
            Pin::new(writer).start_seek(position)
        } else {
            self.position = match position {
                SeekFrom::Start(n) => n,
                SeekFrom::End(_n) => {
                    return Err(io::Error::other("Only SeekFrom::Start is supported"));
                }
                SeekFrom::Current(_n) => {
                    return Err(io::Error::other("Only SeekFrom::Start is supported"));
                }
            };
            Ok(())
        }
    }

    fn poll_complete(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<u64>> {
        if let Some(writer) = &mut self.writer {
            Pin::new(writer).poll_complete(cx)
        } else {
            Poll::Ready(Ok(self.position))
        }
    }
}
