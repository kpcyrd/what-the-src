use crate::args;
use crate::chksums::{Checksums, Hasher};
use crate::db;
use crate::errors::*;
use async_compression::tokio::bufread::{BzDecoder, GzipDecoder, XzDecoder};
use std::pin::Pin;
use std::result;
use std::task::Poll;
use tokio::io;
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

enum Decompressor<R> {
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
        Decompressor::Bz2(BzDecoder::new(reader))
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
    ) -> Poll<result::Result<(), std::io::Error>> {
        match self.get_mut() {
            Decompressor::Plain(r) => Pin::new(r).poll_read(cx, buf),
            Decompressor::Gz(r) => Pin::new(r).poll_read(cx, buf),
            Decompressor::Xz(r) => Pin::new(r).poll_read(cx, buf),
            Decompressor::Bz2(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

pub async fn stream_data<R: AsyncRead + Unpin>(
    reader: R,
    compression: Option<&str>,
) -> Result<(Checksums, Checksums)> {
    let stdin = io::BufReader::new(Hasher::new(reader));
    let stream = match compression {
        Some("gz") => Decompressor::gz(stdin),
        Some("xz") => Decompressor::xz(stdin),
        Some("bz2") => Decompressor::bz2(stdin),
        None => Decompressor::Plain(stdin),
        unknown => panic!("Unknown compression algorithm: {unknown:?}"),
    };
    let mut stream = Hasher::new(stream);

    // consume any data
    io::copy(&mut stream, &mut io::sink()).await?;

    let (stream, inner_digest) = stream.digests();
    info!("Found digest for inner .tar: {inner_digest:?}");
    let stream = stream.into_inner().into_inner();

    let (_stream, outer_digest) = stream.digests();
    info!("Found digests for outer compressed tar: {outer_digest:?}");

    Ok((inner_digest, outer_digest))
}

pub async fn run(args: &args::Alias) -> Result<()> {
    let db = db::Client::create().await?;

    let (inner_digest, outer_digest) =
        stream_data(io::stdin(), args.compression.as_deref()).await?;
    let inner_digest = inner_digest.sha256;
    let outer_digest = outer_digest.sha256;

    if inner_digest != outer_digest {
        db.insert_alias_from_to(&outer_digest, &inner_digest)
            .await?;
    }

    db.insert_ref(&db::Ref {
        chksum: outer_digest.clone(),
        vendor: args.vendor.clone(),
        package: args.package.clone(),
        version: args.version.clone(),
        filename: args.filename.clone(),
    })
    .await?;

    Ok(())
}
