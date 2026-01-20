use crate::args;
use crate::db;
use crate::errors::*;
use crate::utils;
use async_compression::tokio::bufread::ZstdDecoder;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::io::{self, AsyncReadExt};
use tokio_tar::{Archive, EntryType};

pub type PackageList = HashMap<String, Package>;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Package {
    pkgver: String,
    source_revisions: String,
}

pub async fn run(args: &args::SyncVoid) -> Result<()> {
    let db = db::Client::create().await?;
    let vendor = &args.vendor;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let reader = io::BufReader::new(reader);
    let reader = ZstdDecoder::new(reader);
    let mut tar = Archive::new(reader);

    let mut entries = tar.entries()?;
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        {
            let header = entry.header();
            if header.entry_type() != EntryType::Regular {
                continue;
            }
            if header.path()? != Path::new("index.plist") {
                continue;
            }
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).await?;

        let plist = plist::from_bytes::<PackageList>(&buf)?;
        for (pkgname, pkg) in plist {
            debug!("Found in plist: key={pkgname:?} pkg={pkg:?}");
            let version = pkg
                .pkgver
                .strip_prefix(&pkgname)
                .unwrap()
                .strip_prefix('-')
                .unwrap();
            let Some((srcpkg, commit)) = pkg.source_revisions.split_once(':') else {
                return Err(Error::InvalidData);
            };

            // mark all refs known for this package as "last_seen now"
            db.bump_named_refs(vendor, &pkgname, version).await?;

            // check if package already imported
            if db.get_package(vendor, &pkgname, version).await?.is_some() {
                debug!(
                    "Package is already imported: srcpkg={srcpkg:?} commit={commit:?} package={pkgname:?} version={version:?}"
                );
                continue;
            }

            // queue for import
            info!("srcpkg={srcpkg:?} commit={commit:?} package={pkgname:?} version={version:?}");
            db.insert_task(&db::Task::new(
                format!("void-linux-git:{srcpkg}:{commit}:{pkgname}:{version}"),
                &db::TaskData::VoidLinuxGit {
                    vendor: vendor.to_string(),
                    srcpkg: srcpkg.to_string(),
                    commit: commit.to_string(),
                    package: pkgname.to_string(),
                    version: version.to_string(),
                },
            )?)
            .await?;
        }
    }

    Ok(())
}
