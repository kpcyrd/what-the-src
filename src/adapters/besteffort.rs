use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncWrite};

/// A wrapper around an AsyncWrite that silently swallows errors after the first failure.
/// After an error occurs, all subsequent writes are ignored but report success.
/// This is useful for tee streams where a writer failure shouldn't cancel the read operation.
pub struct BestEffortWriter<W> {
    writer: W,
    error: Option<io::Error>,
}

impl<W> BestEffortWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            error: None,
        }
    }

    /// Returns true if the writer has encountered an error and stopped accepting data.
    pub fn has_failed(&self) -> bool {
        self.error.is_some()
    }

    /// Returns a reference to the error that caused the writer to fail, if any.
    pub fn error(&self) -> Option<&io::Error> {
        self.error.as_ref()
    }

    /// Consumes the wrapper and returns the inner writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for BestEffortWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.error.is_some() {
            // Pretend we wrote everything
            return Poll::Ready(Ok(buf.len()));
        }

        match Pin::new(&mut self.writer).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(err)) => {
                self.error = Some(err);
                // Pretend we wrote everything to not propagate the error
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.error.is_some() {
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.writer).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => {
                self.error = Some(err);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.error.is_some() {
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.writer).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => {
                self.error = Some(err);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    struct FailingWriter {
        data: Vec<u8>,
        fail_after: usize,
    }

    impl FailingWriter {
        fn new(fail_after: usize) -> Self {
            Self {
                data: Vec::new(),
                fail_after,
            }
        }
    }

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.data.len() >= self.fail_after {
                Poll::Ready(Err(io::Error::other("intentional failure")))
            } else {
                let to_write = (self.fail_after - self.data.len()).min(buf.len());
                self.data.extend_from_slice(&buf[..to_write]);
                Poll::Ready(Ok(to_write))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_best_effort_writer_success() {
        let inner = Vec::<u8>::new();
        let mut writer = BestEffortWriter::new(inner);

        writer.write_all(b"Hello").await.unwrap();
        writer.write_all(b", world!").await.unwrap();

        assert!(!writer.has_failed());
        assert_eq!(&writer.into_inner(), b"Hello, world!");
    }

    #[tokio::test]
    async fn test_best_effort_writer_failure() {
        let inner = FailingWriter::new(5);
        let mut writer = BestEffortWriter::new(inner);

        // First write succeeds
        writer.write_all(b"Hello").await.unwrap();
        assert!(!writer.has_failed());
        assert!(writer.error().is_none());

        // Second write would fail in inner writer, but BestEffortWriter swallows it
        writer.write_all(b", world!").await.unwrap();
        assert!(writer.has_failed());
        assert!(writer.error().is_some());
        assert_eq!(writer.error().unwrap().kind(), io::ErrorKind::Other);

        // Third write also "succeeds" but nothing is written
        writer.write_all(b" More text").await.unwrap();
        assert!(writer.has_failed());

        let inner = writer.into_inner();
        assert_eq!(&inner.data, b"Hello");
    }

    #[tokio::test]
    async fn test_best_effort_writer_immediate_failure() {
        let inner = FailingWriter::new(0);
        let mut writer = BestEffortWriter::new(inner);

        // Write "succeeds" but nothing is actually written
        writer.write_all(b"Hello").await.unwrap();
        assert!(writer.has_failed());

        let inner = writer.into_inner();
        assert!(inner.data.is_empty());
    }
}
