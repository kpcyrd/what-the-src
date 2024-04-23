use crate::args;
use crate::chksums::{Checksums, Hasher};
use crate::compression::Decompressor;
use crate::db;
use crate::errors::*;
use digest::Digest;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{self, AsyncRead, AsyncReadExt};
use tokio_tar::{Archive, EntryType};

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links_to: Option<LinksTo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinksTo {
    Hard(String),
    Symbolic(String),
}

pub async fn stream_data<R: AsyncRead + Unpin>(
    reader: R,
    compression: Option<&str>,
) -> Result<(Checksums, Checksums, Vec<Entry>)> {
    // Setup decompressor
    let reader = io::BufReader::new(Hasher::new(reader));
    let reader = match compression {
        Some("gz") => Decompressor::gz(reader),
        Some("xz") => Decompressor::xz(reader),
        Some("bz2") => Decompressor::bz2(reader),
        None => Decompressor::Plain(reader),
        unknown => panic!("Unknown compression algorithm: {unknown:?}"),
    };
    let reader = Hasher::new(reader);

    // Open archive
    let mut tar = Archive::new(reader);
    let mut files = Vec::new();
    {
        let mut entries = tar.entries()?;
        while let Some(entry) = entries.next().await {
            let mut entry = entry?;
            let (path, is_file, links_to) = {
                let header = entry.header();
                let (is_file, links_to) = match header.entry_type() {
                    EntryType::XGlobalHeader => continue,
                    EntryType::Regular => (true, None),
                    EntryType::Symlink => {
                        let link = entry.link_name()?.map(|path| {
                            let path = path.to_string_lossy();
                            LinksTo::Symbolic(path.into_owned())
                        });
                        (false, link)
                    }
                    EntryType::Link => {
                        let link = entry.link_name()?.map(|path| {
                            let path = path.to_string_lossy();
                            LinksTo::Hard(path.into_owned())
                        });
                        (false, link)
                    }
                    _ => (false, None),
                };
                let path = header.path()?;
                let path = path.to_string_lossy();
                (path.into_owned(), is_file, links_to)
            };

            let digest = if is_file {
                let mut buf = [0; 4096];
                let mut sha256 = Sha256::new();
                loop {
                    let n = entry.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    let buf = &buf[..n];
                    sha256.update(buf);
                }
                let digest = format!("sha256:{}", hex::encode(sha256.finalize()));
                Some(digest)
            } else {
                None
            };

            let entry = Entry {
                path,
                digest,
                links_to,
            };
            debug!("Found entry={entry:?}");

            files.push(entry);
        }
    }
    let Ok(mut reader) = tar.into_inner() else {
        panic!("can't get hasher from tar reader")
    };

    // Consume any remaining data
    io::copy(&mut reader, &mut io::sink()).await?;

    // Determine hashes
    let (reader, inner_digest) = reader.digests();
    info!("Found digest for inner .tar: {inner_digest:?}");
    let reader = reader.into_inner().into_inner();

    let (_stream, outer_digest) = reader.digests();
    info!("Found digests for outer compressed tar: {outer_digest:?}");

    Ok((inner_digest, outer_digest, files))
}

pub async fn run(args: &args::Ingest) -> Result<()> {
    let db = db::Client::create().await?;

    let (inner_digests, outer_digests, files) =
        stream_data(io::stdin(), args.compression.as_deref()).await?;

    info!("digests={inner_digests:?}");

    db.insert_artifact(&inner_digests.sha256, &files).await?;
    db.register_chksums_aliases(&inner_digests, &inner_digests.sha256)
        .await?;
    db.register_chksums_aliases(&outer_digests, &inner_digests.sha256)
        .await?;

    Ok(())
}
