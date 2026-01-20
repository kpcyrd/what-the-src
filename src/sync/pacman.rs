use crate::args;
use crate::db;
use crate::errors::*;
use crate::utils;
use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
use std::path::Path;
use tokio::io::{self, AsyncReadExt};
use tokio_tar::{Archive, EntryType};

fn matches_repo(path: &Path, repos: &[String]) -> bool {
    let Ok(path) = path.strip_prefix("state-main") else {
        return false;
    };
    for repo in repos {
        if path.starts_with(repo) {
            return true;
        }
    }
    false
}

pub async fn run(args: &args::SyncPacman) -> Result<()> {
    let db = db::Client::create().await?;
    let vendor = &args.vendor;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
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

        let mut buf = String::new();
        entry.read_to_string(&mut buf).await?;
        debug!("Found data in state repo: {buf:?}");

        let mut chunker = buf.split(' ');
        let Some(pkgbase) = chunker.next() else {
            continue;
        };
        let Some(version) = chunker.next() else {
            continue;
        };
        let Some(tag) = chunker.next() else { continue };

        // mark all refs known for this package as "last_seen now"
        db.bump_named_refs(vendor, pkgbase, version).await?;

        // check if package already imported
        if db.get_package(vendor, pkgbase, version).await?.is_some() {
            debug!(
                "Package is already imported: vendor={vendor:?} package={pkgbase:?} version={version:?}"
            );
            continue;
        }

        // queue for import
        info!("package={pkgbase:?} version={version:?} tag={tag:?}");
        db.insert_task(&db::Task::new(
            format!("pacman-git-snapshot:{pkgbase}:{tag}"),
            &db::TaskData::PacmanGitSnapshot {
                vendor: vendor.to_string(),
                package: pkgbase.to_string(),
                version: version.to_string(),
                tag: tag.to_string(),
            },
        )?)
        .await?;
    }

    Ok(())
}
