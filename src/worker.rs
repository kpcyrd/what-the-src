use crate::alias;
use crate::args;
use crate::db;
use crate::db::{Task, TaskData};
use crate::errors::*;
use crate::ingest;
use async_compression::tokio::bufread::{BzDecoder, GzipDecoder, XzDecoder};
use std::borrow::Cow;
use tokio::io::AsyncReadExt;
use tokio::time::{self, Duration};

pub async fn do_task(db: &db::Client, task: &Task) -> Result<()> {
    let data = task.data()?;

    match data {
        TaskData::FetchTar { url } => {
            info!("Fetching tar: {url:?}");
            let req = reqwest::get(&url).await?.error_for_status()?;
            let body = req.bytes().await?;

            // TODO: do this stuff on the fly
            let (compression, decompressed) = if url.ends_with(".gz") {
                let mut reader = GzipDecoder::new(&body[..]);
                let mut buf = Vec::new();
                reader.read_to_end(&mut buf).await?;
                (Some("gz"), Cow::Owned(buf))
            } else if url.ends_with(".xz") {
                let mut reader = XzDecoder::new(&body[..]);
                let mut buf = Vec::new();
                reader.read_to_end(&mut buf).await?;
                (Some("xz"), Cow::Owned(buf))
            } else if url.ends_with(".bz2") {
                let mut reader = BzDecoder::new(&body[..]);
                let mut buf = Vec::new();
                reader.read_to_end(&mut buf).await?;
                (Some("bz2"), Cow::Owned(buf))
            } else {
                (None, Cow::Borrowed(&body[..]))
            };

            let (hasher, files) = ingest::stream_data(&decompressed[..]).await?;
            let (_, digests) = hasher.digests();
            println!("digest={:?}", digests.sha256);
            db.insert_artifact(&digests.sha256, &files).await?;

            // TODO: do this on the fly together with the other thing
            let (inner_digest, outer_digest) = alias::stream_data(&body[..], compression).await?;
            let inner_digest = inner_digest.sha256;
            let outer_digest = outer_digest.sha256;

            if inner_digest != outer_digest {
                db.insert_alias_from_to(&outer_digest, &inner_digest)
                    .await?;
            }
        }
    }

    Ok(())
}

pub async fn run(_args: &args::Worker) -> Result<()> {
    let db = db::Client::create().await?;

    loop {
        if let Some(task) = db.get_random_task().await? {
            info!("task={task:?}");
            if let Err(err) = do_task(&db, &task).await {
                error!("Failed to process task: {err:#}");
            } else {
                db.delete_task(&task).await?;
            }
        } else {
            time::sleep(Duration::from_secs(60)).await;
        }
        time::sleep(Duration::from_millis(50)).await;
    }
}
