use digest::Digest;
use sha2::{Sha256, Sha512};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{self, AsyncRead, ReadBuf};

pub struct Hasher<R> {
    reader: R,
    sha256: Sha256,
    sha512: Sha512,
}

impl<R: AsyncRead + Unpin> AsyncRead for Hasher<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        if let Poll::Ready(x) = Pin::new(&mut self.reader).poll_read(cx, buf) {
            let buf = buf.filled();
            self.sha256.update(&buf[before..]);
            self.sha512.update(&buf[before..]);
            Poll::Ready(x)
        } else {
            Poll::Pending
        }
    }
}

impl<R> Hasher<R> {
    pub fn new(reader: R) -> Self {
        let sha256 = Sha256::new();
        let sha512 = Sha512::new();
        Hasher {
            reader,
            sha256,
            sha512,
        }
    }

    pub fn digests(self) -> (R, Checksums) {
        (
            self.reader,
            Checksums {
                sha256: format!("sha256:{}", hex::encode(self.sha256.finalize())),
                sha512: format!("sha512:{}", hex::encode(self.sha512.finalize())),
            },
        )
    }
}

#[derive(Debug)]
pub struct Checksums {
    pub sha256: String,
    pub sha512: String,
}
