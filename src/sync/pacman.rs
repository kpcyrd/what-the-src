use crate::args;
use crate::db;
use crate::errors::*;
use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
use futures::TryStreamExt;
use std::path::Path;
use tokio::fs;
use tokio::io;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_tar::{Archive, EntryType};
use tokio_util::io::StreamReader;

fn matches_repo(path: &Path, repos: &[String]) -> bool {
    let Ok(path) = path.strip_prefix("state-main") else {
        return false;
    };
    for repo in repos {
        if path.starts_with(&repo) {
            return true;
        }
    }
    false
}

pub async fn run(args: &args::SyncPacman) -> Result<()> {
    let db = db::Client::create().await?;
    let buf;

    let reader: Box<dyn AsyncRead + Unpin> = if args.fetch {
        let resp = reqwest::get(&args.file).await?.error_for_status()?;
        let stream = resp.bytes_stream();
        let stream = StreamReader::new(
            stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
        );
        Box::new(stream)
    } else {
        buf = fs::read(&args.file).await?;
        Box::new(&buf[..])
    };

    let reader = io::BufReader::new(reader);
    let reader = GzipDecoder::new(reader);
    let mut tar = Archive::new(reader);

    let mut entries = tar.entries()?;
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        let header = entry.header();
        if header.entry_type() != EntryType::Regular {
            continue;
        }

        if !matches_repo(&entry.path()?, &args.repos) {
            continue;
        }

        // dbg!(&entry);

        let mut buf = String::new();
        entry.read_to_string(&mut buf).await?;
        debug!("Found data in state repo: {buf:?}");

        let mut chunker = buf.split(' ');
        let Some(pkgbase) = chunker.next() else {
            continue;
        };
        let Some(_version) = chunker.next() else {
            continue;
        };
        let Some(tag) = chunker.next() else { continue };

        println!("https://gitlab.archlinux.org/archlinux/packaging/packages/{pkgbase}/-/archive/{tag}/{pkgbase}-{tag}.tar.gz");
    }

    Ok(())
}
