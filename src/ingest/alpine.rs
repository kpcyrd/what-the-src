use crate::apkbuild;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::utils;
use tokio::io::{AsyncRead, AsyncReadExt};

pub async fn stream_data<R: AsyncRead + Unpin>(
    db: &db::Client,
    mut reader: R,
    vendor: &str,
    package: &str,
    version: &str,
) -> Result<()> {
    let mut buf = String::new();
    reader.read_to_string(&mut buf).await?;

    info!("Parsing APKBUILD");
    let apkbuild = apkbuild::parse(&buf)?;

    for i in 0..apkbuild.source.len() {
        let Some(url) = apkbuild.source.get(i) else {
            continue;
        };
        let Some(sha512) = apkbuild.sha512sums.get(i) else {
            continue;
        };

        if !utils::is_possible_tar_artifact(url) {
            continue;
        }

        let chksum = format!("sha512:{sha512}");

        // check if already known
        if db.resolve_artifact(&chksum).await?.is_none() {
            db.insert_task(&Task::new(
                format!("fetch:{url}"),
                &TaskData::FetchTar {
                    url: url.to_string(),
                    compression: None,
                    success_ref: None,
                },
            )?)
            .await?;
        }

        let r = db::Ref {
            chksum,
            vendor: vendor.to_string(),
            package: package.to_string(),
            version: version.to_string(),
            filename: Some(url.to_string()),
        };
        info!("insert: {r:?}");
        db.insert_ref(&r).await?;
    }

    Ok(())
}
