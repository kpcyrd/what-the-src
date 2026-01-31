use crate::adapters::readahead::ReadAhead;
use crate::errors::*;
use async_compression::tokio::bufread::{BzDecoder, GzipDecoder, XzDecoder, ZstdDecoder};
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
    } else if magic.starts_with(b"\x28\xB5\x2F\xFD") {
        let reader = io::BufReader::new(reader);
        Decompressor::zstd(reader)
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
    Zstd(ZstdDecoder<R>),
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

    pub fn zstd(reader: R) -> Self {
        Decompressor::Zstd(ZstdDecoder::new(reader))
    }

    pub fn outer_label(&self) -> &'static str {
        match self {
            Decompressor::Plain(_) => "tar",
            Decompressor::Gz(_) => "gz(tar)",
            Decompressor::Xz(_) => "xz(tar)",
            Decompressor::Bz2(_) => "bz2(tar)",
            Decompressor::Zstd(_) => "zstd(tar)",
        }
    }

    pub fn into_inner(self) -> R {
        match self {
            Decompressor::Plain(r) => r,
            Decompressor::Gz(r) => r.into_inner(),
            Decompressor::Xz(r) => r.into_inner(),
            Decompressor::Bz2(r) => r.into_inner(),
            Decompressor::Zstd(r) => r.into_inner(),
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
            Decompressor::Zstd(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ingest::tar::{self, TarSummary},
        s3::UploadClient,
    };

    #[tokio::test]
    async fn test_zstd() {
        let data = [
            0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x60, 0x95, 0x02, 0x00, 0x94, 0x03, 0x6f, 0x68, 0x61,
            0x69, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x30, 0x30, 0x30, 0x30, 0x36, 0x34, 0x34, 0x00,
            0x30, 0x30, 0x30, 0x32, 0x32, 0x37, 0x33, 0x36, 0x30, 0x00, 0x20, 0x30, 0x00, 0x75,
            0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00, 0x6f, 0x68, 0x61, 0x69, 0x20, 0x77, 0x6f,
            0x72, 0x6c, 0x64, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x21, 0x0a, 0x00, 0x08, 0x00,
            0xd5, 0x0b, 0xe0, 0x03, 0x1d, 0x50, 0x11, 0xe0, 0x52, 0xec, 0x14, 0xeb, 0x65, 0xcb,
            0x15, 0x14, 0xc0, 0x70, 0x70, 0x02, 0x47, 0xdb, 0x69, 0xc0, 0xc3,
        ];
        let reader = auto(&data[..]).await.unwrap();
        let tar = tar::stream_data(None, &UploadClient::disabled(), reader)
            .await
            .unwrap();
        assert_eq!(
            tar,
            TarSummary {
                inner_digests: tar.inner_digests.clone(),
                outer_digests: tar.inner_digests.clone(),
                files: vec![tar::Entry {
                    path: "ohai.txt".to_string(),
                    digest: Some(
                        "sha256:b864ea91e021d101ffd4bec4ddcf550ca117ffcb98eff1358494a6ea5780c955"
                            .to_string()
                    ),
                    metadata: tar::Metadata {
                        mode: Some("0o644".to_string()),
                        links_to: None,
                        mtime: Some(0),
                        uid: Some(0),
                        username: Some("".to_string()),
                        gid: Some(0),
                        groupname: Some("".to_string()),
                    }
                },],
                sbom_refs: vec![],
            }
        );
    }
}
