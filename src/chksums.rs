use digest::Digest;
use sha2::Sha256;
use std::pin::Pin;
use std::result;
use std::task::Poll;
use tokio::io::{AsyncRead, ReadBuf};

pub struct Hasher<R> {
    reader: R,
    sha256: Sha256,
}

impl<R: AsyncRead + Unpin> AsyncRead for Hasher<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<result::Result<(), std::io::Error>> {
        let before = buf.filled().len();
        if let Poll::Ready(x) = Pin::new(&mut self.reader).poll_read(cx, buf) {
            let buf = buf.filled();
            self.sha256.update(&buf[before..]);
            Poll::Ready(x)
        } else {
            Poll::Pending
        }
    }
}

impl<R> Hasher<R> {
    pub fn new(reader: R) -> Self {
        let sha256 = Sha256::new();
        Hasher { reader, sha256 }
    }

    pub fn digests(self) -> (R, Checksums) {
        (
            self.reader,
            Checksums {
                sha256: format!("sha256:{}", hex::encode(self.sha256.finalize())),
            },
        )
    }
}

#[derive(Debug)]
pub struct Checksums {
    pub sha256: String,
}
