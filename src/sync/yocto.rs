use crate::args;
use crate::db;
use crate::errors::*;
use crate::parsers::yocto;
use crate::utils;
use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
use std::path::Path;
use tokio::io::{self, AsyncReadExt};
use tokio_tar::Archive;

fn metadata_from_path(path: &Path) -> Option<(&str, &str)> {
    let path = path.to_str()?;
    let (_, path) = path.split_once("/recipes")?;
    let (_, path) = path.split_once('/')?;

    let (_parent, filename) = path.split_once('/')?;
    let release = filename.strip_suffix(".bb")?;

    let (package, version) = release.rsplit_once('_')?;

    Some((package, version))
}

pub async fn run(args: &args::SyncYocto) -> Result<()> {
    let db = db::Client::create().await?;
    let vendor = &args.vendor;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let reader = io::BufReader::new(reader);
    let reader = GzipDecoder::new(reader);
    let mut tar = Archive::new(reader);

    let mut entries = tar.entries()?;
    let mut errors = 0;
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }

        let path = entry.path()?;
        let Some((package, version)) = metadata_from_path(&path) else {
            continue;
        };

        let package = package.to_string();
        let version = version.to_string();

        let mut buf = String::new();
        entry.read_to_string(&mut buf).await?;

        let pkg = match yocto::parse(&buf, Some(package.clone()), Some(version.clone())) {
            Ok(pkg) => pkg,
            Err(err) => {
                error!("Failed to parse package={package:?} version={version:?}: {err:#}");
                errors += 1;
                continue;
            }
        };

        let artifacts = match pkg.artifacts() {
            Ok(list) => list,
            Err(err) => {
                error!("Failed to parse package={package:?} version={version:?}: {err:#}");
                errors += 1;
                continue;
            }
        };

        for artifact in artifacts {
            let (chksum, url) = match (artifact.sha256, artifact.commit) {
                (Some(sha256), _) => (format!("sha256:{sha256}"), artifact.src),
                (_, Some(commit)) => (
                    format!("git:{commit}"),
                    format!("{}#commit={commit}", artifact.src),
                ),
                _ => continue,
            };

            let task = if db.resolve_artifact(&chksum).await?.is_none() {
                utils::task_for_url(&url)
            } else {
                None
            };

            let r = db::Ref::new(
                chksum,
                vendor.to_string(),
                package.to_string(),
                version.to_string(),
                Some(url),
            );
            debug!("insert: {r:?}");
            db.insert_ref(&r).await?;

            if let Some(task) = task {
                info!("Adding task: {task:?}");
                db.insert_task(&task).await?;
            }
        }
    }

    if errors > 0 {
        warn!("Encounted {errors} errors while processing snapshot");
    }

    Ok(())
}
