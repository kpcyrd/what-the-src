use crate::adapters::readahead::ReadAhead;
use crate::errors::*;
use async_compression::tokio::bufread::{BzDecoder, GzipDecoder, XzDecoder};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{self, AsyncBufRead, AsyncRead, BufReader, ReadBuf};

pub async fn auto<R: AsyncRead + Unpin>(
    reader: R,
) -> Result<Decompressor<BufReader<ReadAhead<R>>>> {
    let mut reader = ReadAhead::new(reader);
    let magic = reader.peek().await?;

    // Detect compression type and select decompressor
    Ok(if magic.starts_with(b"\x1F\x8B") {
        let reader = io::BufReader::new(reader);
        Decompressor::gz(reader)
    } else if magic.starts_with(b"\xFD\x37\x7A\x58\x5A") {
        let reader = io::BufReader::new(reader);
        Decompressor::xz(reader)
    } else if magic.starts_with(b"\x42\x5A\x68") {
        let reader = io::BufReader::new(reader);
        Decompressor::bz2(reader)
    } else {
        let reader = io::BufReader::new(reader);
        Decompressor::Plain(reader)
    })
}

pub enum Decompressor<R> {
    Plain(R),
    Gz(GzipDecoder<R>),
    Xz(XzDecoder<R>),
    Bz2(BzDecoder<R>),
}

impl<R: AsyncBufRead> Decompressor<R> {
    pub fn gz(reader: R) -> Self {
        Decompressor::Gz(GzipDecoder::new(reader))
    }

    pub fn xz(reader: R) -> Self {
        Decompressor::Xz(XzDecoder::new(reader))
    }

    pub fn bz2(reader: R) -> Self {
        let mut decoder = BzDecoder::new(reader);
        decoder.multiple_members(true);
        Decompressor::Bz2(decoder)
    }

    pub fn outer_label(&self) -> &'static str {
        match self {
            Decompressor::Plain(_) => "tar",
            Decompressor::Gz(_) => "gz(tar)",
            Decompressor::Xz(_) => "xz(tar)",
            Decompressor::Bz2(_) => "bz2(tar)",
        }
    }

    pub fn into_inner(self) -> R {
        match self {
            Decompressor::Plain(r) => r,
            Decompressor::Gz(r) => r.into_inner(),
            Decompressor::Xz(r) => r.into_inner(),
            Decompressor::Bz2(r) => r.into_inner(),
        }
    }
}

impl<R: AsyncBufRead + Unpin> AsyncRead for Decompressor<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Decompressor::Plain(r) => Pin::new(r).poll_read(cx, buf),
            Decompressor::Gz(r) => Pin::new(r).poll_read(cx, buf),
            Decompressor::Xz(r) => Pin::new(r).poll_read(cx, buf),
            Decompressor::Bz2(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}
