use crate::apt;
use crate::args;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use tokio::fs;

pub async fn run(args: &args::SyncApt) -> Result<()> {
    let db = db::Client::create().await?;

    let buf = fs::read(&args.file).await?;
    let sources = apt::SourcesIndex::parse(&buf)?;

    for pkg in &sources.pkgs {
        debug!("pkg={pkg:?}");
        pkg.version.as_ref().unwrap();
        pkg.directory.as_ref().unwrap();

        for entry in &pkg.checksums_sha256 {
            let name = entry.filename.clone();
            if name.ends_with(".orig.tar.xz")
                || name.ends_with(".orig.tar.gz")
                || name.ends_with(".orig.tar.bz2")
            {
                let chksum = format!("sha256:{}", entry.hash);
                let package = pkg.package.to_string();
                let version = pkg.version.clone().unwrap();
                info!("digest={chksum:?} package={package:?} version={version:?} name={name:?}");
                let obj = db::Ref {
                    chksum,
                    vendor: args.vendor.to_string(),
                    package,
                    version,
                    filename: Some(name.clone()),
                };
                db.insert_ref(&obj).await?;

                if db.resolve_artifact(&obj.chksum).await?.is_none() {
                    let directory = pkg.directory.as_ref().unwrap();
                    let url = format!(
                        "https://ftp.halifax.rwth-aachen.de/debian/{}/{}",
                        directory, name
                    );
                    info!("url={url:?}");
                    db.insert_task(&Task::new(
                        format!("fetch:{url}"),
                        &TaskData::FetchTar { url },
                    )?)
                    .await?;
                }
            }
        }
    }

    Ok(())
}
