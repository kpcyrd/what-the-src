use crate::args;
use crate::chksums::Hasher;
use crate::db;
use crate::errors::*;
use async_compression::tokio::bufread::GzipDecoder;
use std::pin::Pin;
use std::result;
use std::task::Poll;
use tokio::io;
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

enum Decompressor<R> {
    Plain(R),
    Gz(GzipDecoder<R>),
}

impl<R: AsyncBufRead> Decompressor<R> {
    pub fn gz(reader: R) -> Self {
        Decompressor::Gz(GzipDecoder::new(reader))
    }

    pub fn into_inner(self) -> R {
        match self {
            Decompressor::Plain(r) => r,
            Decompressor::Gz(r) => r.into_inner(),
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
        }
    }
}

pub async fn run(args: &args::Alias) -> Result<()> {
    let db = db::Client::create().await?;

    let stdin = io::BufReader::new(Hasher::new(io::stdin()));
    let stream = match args.compression.as_deref() {
        Some("gz") => Decompressor::gz(stdin),
        None => Decompressor::Plain(stdin),
        unknown => panic!("Unknown compression algorithm: {unknown:?}"),
    };
    let mut stream = Hasher::new(stream);

    // consume any data
    io::copy(&mut stream, &mut io::sink()).await?;

    let (stream, digests) = stream.digests();
    info!("Found digest for inner .tar: {digests:?}");
    let inner_digest = digests.sha256;
    let stream = stream.into_inner().into_inner();

    let (_stream, digests) = stream.digests();
    info!("Found digests for outer compressed tar: {digests:?}");
    let outer_digest = digests.sha256;

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
