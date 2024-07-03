use crate::args;
use crate::chksums::Hasher;
use crate::db;
use crate::errors::*;
use crate::ingest;
use crate::sbom;
use crate::utils;
use futures::StreamExt;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{self, AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio_tar::{Archive, EntryType};

pub async fn read_routine<R: AsyncRead + Unpin>(
    db: &db::Client,
    reader: R,
) -> Result<Vec<ingest::tar::Entry>> {
    let mut tar = Archive::new(reader);
    let mut entries = tar.entries()?;
    let mut files = Vec::new();

    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
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
        let (metadata, _) = ingest::tar::Metadata::from_tar_header(&entry)?.unwrap();

        // TODO: find a better solution for this, can we just autodetect all regardless of file name?
        let archive_w_compression = if filename.ends_with(".tar.gz")
            || filename.ends_with(".tgz")
            || filename.ends_with(".crate")
        {
            Some(Some("gz"))
        } else if filename.ends_with(".tar.xz") {
            Some(Some("xz"))
        } else if filename.ends_with(".tar.bz2") {
            Some(Some("bz2"))
        } else if filename.ends_with(".tar") {
            Some(None)
        } else {
            None
        };

        let chksum = match archive_w_compression {
            Some(compression) => {
                // in case of chromium, calculate the checksum but do not import
                let tar_db = if filename.starts_with("chromium-") {
                    None
                } else {
                    Some(db)
                };
                let summary = ingest::tar::stream_data(tar_db, entry, compression).await?;
                summary.outer_digests.sha256.clone()
            }
            None => {
                if let Some(strain) = sbom::detect_from_filename(Some(&filename)) {
                    let mut buf = String::new();
                    entry.read_to_string(&mut buf).await?;

                    let sbom = sbom::Sbom::new(strain, buf)?;
                    let chksum = db.insert_sbom(&sbom).await?;
                    let strain = sbom.strain();
                    info!("Inserted sbom {strain:?}: {chksum:?}");
                    db.insert_task(&db::Task::new(
                        format!("sbom:{strain}:{chksum}"),
                        &db::TaskData::IndexSbom {
                            strain: Some(strain.to_string()),
                            chksum: chksum.clone(),
                        },
                    )?)
                    .await?;
                    chksum
                } else {
                    let (_, checksum) = Hasher::new(entry).digests();
                    checksum.sha256.clone()
                }
            }
        };

        let file = ingest::tar::Entry {
            path: filename.to_string(),
            digest: Some(chksum),
            metadata,
        };
        files.push(file);
    }
    Ok(files)
}

pub async fn stream_data<R: AsyncRead + Unpin>(
    db: Arc<db::Client>,
    reader: R,
    vendor: String,
    package: String,
    version: String,
) -> Result<()> {
    let mut reader_hash = Hasher::new(reader);

    let mut child = Command::new("bsdtar")
        .args(["-c", "@-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdin = child.stdin.take().unwrap();
    let writer = async {
        let n = io::copy(&mut reader_hash, &mut stdin).await;
        drop(stdin);
        n
    };

    let stdout = child.stdout.take().unwrap();
    let adb = db.clone();
    let reader = tokio::spawn(async move { read_routine(&adb, stdout).await });

    let (reader, writer) = tokio::join!(reader, writer);
    debug!("Sent {} bytes to child process", writer?);
    let status = child.wait().await?;
    if !status.success() {
        return Err(Error::ChildExit(status));
    }
    let files = reader??;
    let (_, digests) = reader_hash.digests();
    let r = db::Ref {
        chksum: digests.sha256.clone(),
        vendor: vendor.to_string(),
        package: package.to_string(),
        version: version.to_string(),
        filename: Some(format!("{}-{}.src.rpm", package, version)),
    };
    info!("insert ref: {r:?}");
    db.insert_ref(&r).await?;
    db.insert_artifact(&digests.sha256.clone(), &files).await?;
    debug!("Finished processing .rpm");
    Ok(())
}

pub async fn run(args: &args::IngestRpm) -> Result<()> {
    let db = db::Client::create().await?;
    let db = Arc::new(db);

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    stream_data(
        db.clone(),
        reader,
        args.vendor.to_string(),
        args.package.to_string(),
        args.version.to_string(),
    )
    .await?;

    Ok(())
}
