use crate::args;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::ingest;
use futures::TryStreamExt;
use tokio::io;
use tokio::time::{self, Duration};
use tokio_util::io::StreamReader;

pub async fn do_task(db: &db::Client, client: &reqwest::Client, task: &Task) -> Result<()> {
    let data = task.data()?;

    match data {
        TaskData::FetchTar { url } => {
            info!("Fetching tar: {url:?}");
            let req = client.get(&url).send().await?.error_for_status()?;
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
                ingest::tar::stream_data(&body[..], compression).await?;

            println!("digests={:?}", inner_digests);
            db.insert_artifact(&inner_digests.sha256, &files).await?;
            db.register_chksums_aliases(&inner_digests, &inner_digests.sha256)
                .await?;
            db.register_chksums_aliases(&outer_digests, &inner_digests.sha256)
                .await?;
        }
        TaskData::PacmanGitSnapshot {
            vendor,
            package,
            version,
            tag,
        } => {
            let url = format!("https://gitlab.archlinux.org/archlinux/packaging/packages/{package}/-/archive/{tag}/{package}-{tag}.tar.gz");

            let resp = client.get(&url).send().await?.error_for_status()?;
            let stream = resp.bytes_stream();
            let reader =
                StreamReader::new(stream.map_err(|e| io::Error::new(io::ErrorKind::Other, e)));
            let refs =
                ingest::pacman::stream_data(reader, &vendor, &package, &version, false).await?;

            for r in refs {
                info!("insert: {r:?}");
                db.insert_ref(&r).await?;
            }
        }
    }

    Ok(())
}

pub async fn run(args: &args::Worker) -> Result<()> {
    let db = db::Client::create().await?;

    let mut client = reqwest::ClientBuilder::new();
    if let Some(socks5) = &args.socks5 {
        client = client.proxy(reqwest::Proxy::all(socks5)?);
    }
    let client = client.build()?;
    loop {
        if let Some(task) = db.get_random_task().await? {
            info!("task={task:?}");
            if let Err(err) = do_task(&db, &client, &task).await {
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
