use crate::args;
use crate::chksums::Hasher;
use crate::db;
use crate::errors::*;
use digest::Digest;
use futures::stream::StreamExt;
use serde::Serialize;
use sha2::Sha256;
use std::path::PathBuf;
use tokio::io::{self, AsyncRead, AsyncReadExt};
use tokio_tar::{Archive, EntryType};

#[derive(Debug, Serialize)]
pub struct Entry {
    path: PathBuf,
    digest: Option<String>,
}

pub async fn stream_data<R: AsyncRead + Unpin>(reader: R) -> Result<(Hasher<R>, Vec<Entry>)> {
    let mut tar = Archive::new(Hasher::new(reader));
    let mut files = Vec::new();
    {
        let mut entries = tar.entries()?;
        while let Some(entry) = entries.next().await {
            let mut entry = entry?;
            let (path, is_file) = {
                let header = entry.header();
                let is_file = match header.entry_type() {
                    EntryType::XGlobalHeader => continue,
                    EntryType::Regular => true,
                    _ => false,
                };
                let path = header.path()?;
                (PathBuf::from(path), is_file)
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

            if let Some(digest) = &digest {
                debug!("Found entry={path:?}, digest={digest:?}");
            } else {
                debug!("Found entry={path:?}");
            }

            files.push(Entry { path, digest });
        }
    }
    let Ok(mut hasher) = tar.into_inner() else {
        panic!("can't get hasher from tar reader")
    };

    // consume any remaining data
    io::copy(&mut hasher, &mut io::sink()).await?;

    Ok((hasher, files))
}

pub async fn run(_args: &args::Ingest) -> Result<()> {
    let db = db::Client::create().await?;

    let (hasher, files) = stream_data(io::stdin()).await?;

    let (_, digests) = hasher.digests();
    println!("digests={digests:?}");

    db.insert_artifact(&digests.sha256, &files).await?;
    db.register_chksums_aliases(&digests, &digests.sha256).await?;

    Ok(())
}
