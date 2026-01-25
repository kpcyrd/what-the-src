use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;
use crate::s3::UploadClient;
use crate::utils;
use futures::StreamExt;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{self, AsyncRead};
use tokio::process::Command;
use tokio_tar::{Archive, EntryType};

pub async fn read_routine<R: AsyncRead + Unpin>(
    db: &db::Client,
    upload: &UploadClient,
    reader: R,
    vendor: String,
    package: String,
    version: String,
) -> Result<()> {
    let mut tar = Archive::new(reader);
    let mut entries = tar.entries()?;

    while let Some(entry) = entries.next().await {
        let entry = entry?;
        let filename = {
            let path = entry.path()?;
            debug!("Found entry in .rpm: {:?}", path);

            if entry.header().entry_type() != EntryType::Regular {
                continue;
            }

            let Some(filename) = path.file_name() else {
                continue;
            };
            let Some(filename) = filename.to_str() else {
                continue;
            };

            filename.to_string()
        };

        // TODO: find a better solution for this, can we just autodetect all regardless of file name?
        let compression = if filename.ends_with(".tar.gz")
            || filename.ends_with(".tgz")
            || filename.ends_with(".crate")
        {
            Some("gz")
        } else if filename.ends_with(".tar.xz") {
            Some("xz")
        } else if filename.ends_with(".tar.bz2") {
            Some("bz2")
        } else if filename.ends_with(".tar") {
            None
        } else {
            continue;
        };

        // in case of chromium, calculate the checksum but do not import
        let (tar_db, upload) = if filename.starts_with("chromium-") {
            (None, &UploadClient::disabled())
        } else {
            (Some(db), upload)
        };
        let summary = ingest::tar::stream_data(tar_db, upload, entry, compression).await?;

        let r = db::Ref {
            chksum: summary.outer_digests.sha256.clone(),
            vendor: vendor.to_string(),
            package: package.to_string(),
            version: version.to_string(),
            filename: Some(filename.to_string()),
        };
        info!("insert ref: {r:?}");
        db.insert_ref(&r).await?;
    }
    Ok(())
}

pub async fn stream_data<R: AsyncRead + Unpin>(
    db: Arc<db::Client>,
    upload: &UploadClient,
    mut reader: R,
    vendor: String,
    package: String,
    version: String,
) -> Result<()> {
    let mut child = Command::new("bsdtar")
        .args(["-c", "@-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdin = child.stdin.take().unwrap();
    let writer = async {
        let n = io::copy(&mut reader, &mut stdin).await;
        drop(stdin);
        n
    };

    let stdout = child.stdout.take().unwrap();
    let upload = upload.clone();
    let reader =
        tokio::spawn(
            async move { read_routine(&db, &upload, stdout, vendor, package, version).await },
        );

    let (reader, writer) = tokio::join!(reader, writer);
    debug!("Sent {} bytes to child process", writer?);
    let status = child.wait().await?;
    if !status.success() {
        return Err(Error::ChildExit(status));
    }
    debug!("Finished processing .rpm");
    reader?
}

pub async fn run(args: &args::IngestRpm) -> Result<()> {
    let db = db::Client::create().await?;
    let db = Arc::new(db);

    // TODO: upload_config from args(?)
    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    stream_data(
        db.clone(),
        &UploadClient::disabled(),
        reader,
        args.vendor.to_string(),
        args.package.to_string(),
        args.version.to_string(),
    )
    .await?;

    Ok(())
}
