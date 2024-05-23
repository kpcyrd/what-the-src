use crate::args;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::utils;
use crate::void_template;
use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
use tokio::io::{self, AsyncRead, AsyncReadExt};
use tokio_tar::Archive;

pub async fn extract_template<R: AsyncRead + Unpin>(
    reader: R,
    srcpkg: &str,
) -> Result<Option<String>> {
    let reader = io::BufReader::new(reader);
    let reader = GzipDecoder::new(reader);
    let mut tar = Archive::new(reader);

    let mut entries = tar.entries()?;
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        let path = entry.path()?;
        let Some(path) = path.to_str() else { continue };
        let Some((_, path)) = path.split_once("/srcpkgs/") else {
            continue;
        };
        let Some(path) = path.strip_suffix("/template") else {
            continue;
        };

        if path != srcpkg {
            continue;
        }

        let mut buf = String::new();
        entry.read_to_string(&mut buf).await?;
        return Ok(Some(buf));
    }

    Ok(None)
}

pub async fn stream_data<R: AsyncRead + Unpin>(
    db: &db::Client,
    reader: R,
    vendor: &str,
    srcpkg: &str,
    package: &str,
    version: &str,
) -> Result<()> {
    let Some(template) = extract_template(reader, srcpkg).await? else {
        return Ok(());
    };
    let template = void_template::parse(&template)?;
    debug!("Found Void Linux template: {template:?}");

    for i in 0..template.distfiles.len() {
        let Some(url) = template.distfiles.get(i) else {
            continue;
        };
        let Some(sha256) = template.checksum.get(i) else {
            continue;
        };

        if sha256.len() != 64 {
            warn!("Unexpected checksum length for Void Linux: {sha256:?}");
            continue;
        }
        let chksum = format!("sha256:{sha256}");

        if !utils::is_possible_tar_artifact(url) {
            continue;
        }

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

pub async fn run(args: &args::IngestVoid) -> Result<()> {
    let db = db::Client::create().await?;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    stream_data(
        &db,
        reader,
        &args.vendor,
        &args.srcpkg,
        &args.package,
        &args.version,
    )
    .await?;

    Ok(())
}
