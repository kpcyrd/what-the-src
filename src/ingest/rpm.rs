use crate::args;
use crate::chksums::Checksums;
use crate::db;
use crate::errors::*;
use crate::ingest;
use crate::utils;
use futures::StreamExt;
use std::process::Stdio;
use tokio::io::{self, AsyncRead};
use tokio::process::Command;
use tokio_tar::{Archive, EntryType};

pub type Item = (db::Ref, Checksums, Checksums, Vec<ingest::tar::Entry>);

pub async fn read_routine<R: AsyncRead + Unpin>(
    reader: R,
    vendor: String,
    package: String,
    version: String,
) -> Result<Vec<Item>> {
    let mut tar = Archive::new(reader);
    let mut entries = tar.entries()?;

    let mut out = Vec::new();
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

        // TODO: find a better solution for this
        let compression = if filename.ends_with(".tar.gz") {
            Some("gz")
        } else if filename.ends_with(".tar.xz") {
            Some("xz")
        } else if filename.ends_with(".tar.bz2") {
            Some("bz2")
        } else {
            continue;
        };

        let (inner_digests, outer_digests, files) =
            ingest::tar::stream_data(entry, compression).await?;

        out.push((
            db::Ref {
                chksum: outer_digests.sha256.clone(),
                vendor: vendor.to_string(),
                package: package.to_string(),
                version: version.to_string(),
                filename: Some(filename.to_string()),
            },
            inner_digests,
            outer_digests,
            files,
        ));
    }
    Ok(out)
}

pub async fn stream_data<R: AsyncRead + Unpin>(
    mut reader: R,
    vendor: String,
    package: String,
    version: String,
) -> Result<Vec<Item>> {
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
    let reader = tokio::spawn(async move { read_routine(stdout, vendor, package, version).await });

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

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let items = stream_data(
        reader,
        args.vendor.to_string(),
        args.package.to_string(),
        args.version.to_string(),
    )
    .await?;

    for (r, inner_digests, outer_digests, files) in items {
        info!("insert artifact: {:?}", inner_digests.sha256);
        db.insert_artifact(&inner_digests.sha256, &files).await?;
        db.register_chksums_aliases(&inner_digests, &inner_digests.sha256)
            .await?;
        db.register_chksums_aliases(&outer_digests, &inner_digests.sha256)
            .await?;

        info!("insert ref: {r:?}");
        db.insert_ref(&r).await?;
    }

    Ok(())
}
