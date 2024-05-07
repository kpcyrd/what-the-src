use crate::args;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::utils;
use serde::Deserialize;
use tokio::io::AsyncReadExt;

#[derive(Debug, Deserialize)]
pub struct Formula {
    name: String,
    versions: Versions,
    urls: SourceSet,
    revision: u16,
}

#[derive(Debug, Deserialize)]
pub struct Versions {
    stable: String,
}

#[derive(Debug, Deserialize)]
pub struct SourceSet {
    stable: SourceUrl,
}

#[derive(Debug, Deserialize)]
pub struct SourceUrl {
    url: String,
    tag: Option<String>,
    revision: Option<String>,
    checksum: Option<String>,
}

pub async fn run(args: &args::SyncHomebrew) -> Result<()> {
    let db = db::Client::create().await?;
    let vendor = &args.vendor;

    let mut reader = utils::fetch_or_open(&args.file, args.fetch).await?;

    let mut buf = String::new();
    reader.read_to_string(&mut buf).await?;

    let formulas = serde_json::from_str::<Vec<Formula>>(&buf)?;
    for formula in formulas {
        debug!("formula={formula:?}");

        let package = formula.name;
        let version = format!("{}-{}", formula.versions.stable, formula.revision);
        let url = formula.urls.stable.url;

        let (url, chksum) = if let Some(checksum) = formula.urls.stable.checksum {
            (url, format!("sha256:{checksum}"))
        } else if let Some(revision) = &formula.urls.stable.revision {
            let tag = formula.urls.stable.tag.as_ref().unwrap_or(revision);
            let url = format!("git+{url}#tag={tag}");
            (url, format!("git:{revision}"))
        } else {
            continue;
        };

        if db.resolve_artifact(&chksum).await?.is_none() {
            if url.starts_with("https://") || url.starts_with("http://") {
                info!("Found tarball url: {url:?}");
                db.insert_task(&Task::new(
                    format!("fetch:{url}"),
                    &TaskData::FetchTar {
                        url: url.to_string(),
                    },
                )?)
                .await?;
            } else if url.starts_with("git+https://") {
                info!("Found git remote: {url:?}");
                db.insert_task(&Task::new(
                    format!("git-clone:{url}"),
                    &TaskData::GitSnapshot {
                        url: url.to_string(),
                    },
                )?)
                .await?;
            }
        }

        debug!("package={package:?} version={version:?} url={url:?} ({chksum})");
        let obj = db::Ref {
            chksum,
            vendor: vendor.to_string(),
            package,
            version,
            filename: Some(url),
        };
        db.insert_ref(&obj).await?;
    }

    Ok(())
}
