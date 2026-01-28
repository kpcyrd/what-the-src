use blake2::Blake2b512;
use digest::Digest;
use sha2::{Sha256, Sha512};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{self, AsyncRead, ReadBuf};

pub struct Hasher<R> {
    reader: R,
    sha256: Sha256,
    sha512: Sha512,
    blake2b: Blake2b512,
    size: u64,
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
            let new = &buf[before..];
            self.sha256.update(new);
            self.sha512.update(new);
            self.blake2b.update(new);
            self.size = self.size.saturating_add(new.len() as u64);
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
        let blake2b = Blake2b512::new();
        Hasher {
            reader,
            sha256,
            sha512,
            blake2b,
            size: 0,
        }
    }

    pub fn digests(self) -> (R, Checksums) {
        (
            self.reader,
            Checksums {
                sha256: format!("sha256:{}", hex::encode(self.sha256.finalize())),
                sha512: format!("sha512:{}", hex::encode(self.sha512.finalize())),
                blake2b: format!("blake2b:{}", hex::encode(self.blake2b.finalize())),
                size: self.size,
            },
        )
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Checksums {
    pub sha256: String,
    pub sha512: String,
    pub blake2b: String,
    pub size: u64,
}

pub fn sha256(data: &[u8]) -> String {
    let mut sha256 = Sha256::new();
    sha256.update(data);
    format!("sha256:{}", hex::encode(sha256.finalize()))
}
