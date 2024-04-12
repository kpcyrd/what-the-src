use crate::args;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::ingest;
use tokio::time::{self, Duration};

pub async fn do_task(db: &db::Client, task: &Task) -> Result<()> {
    let data = task.data()?;

    match data {
        TaskData::FetchTar { url } => {
            info!("Fetching tar: {url:?}");
            let req = reqwest::get(&url).await?.error_for_status()?;
            let body = req.bytes().await?;

            // TODO: do this stuff on the fly
            let compression = if url.ends_with(".gz") {
                Some("gz")
            } else if url.ends_with(".xz") {
                Some("xz")
            } else if url.ends_with(".bz2") {
                Some("bz2")
            } else {
                None
            };

            let (inner_digests, outer_digests, files) =
                ingest::stream_data(&body[..], compression).await?;

            println!("digests={:?}", inner_digests);
            db.insert_artifact(&inner_digests.sha256, &files).await?;
            db.register_chksums_aliases(&inner_digests, &inner_digests.sha256)
                .await?;
            db.register_chksums_aliases(&outer_digests, &inner_digests.sha256)
                .await?;
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
