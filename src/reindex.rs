use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;
use crate::sbom;
use futures::StreamExt;
use sqlx::types::chrono::Utc;

pub async fn run_url(args: &args::ReindexUrl) -> Result<()> {
    let db = db::Client::create().await?;

    let mut scheduled = 0;
    let now = Utc::now();

    let stream = db.get_all_artifacts_by_age();
    tokio::pin!(stream);
    while let Some(artifact) = stream.next().await {
        let artifact = artifact?;

        if let Some(limit) = &args.limit {
            if scheduled >= *limit {
                info!("Reached schedule limit of {limit} items, exiting");
                break;
            }
        }

        if let Some(age) = &args.age {
            let delta = now.signed_duration_since(artifact.last_imported);
            if delta.num_days() < *age {
                // since we sort by age, no further artifact will match
                break;
            }
        }

        let refs = db.get_all_refs_for(&artifact.chksum).await?;

        let mut refs = refs
            .into_iter()
            .flat_map(|r| r.filename)
            .filter(|filename| {
                if let Some(filter) = &args.filter {
                    filename.contains(filter)
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();
        fastrand::shuffle(&mut refs);

        let Some(filename) = refs.into_iter().next() else {
            continue;
        };

        if let Some(task) = ingest::pacman::task_for_url(&filename) {
            info!("Inserting task: {task:?}");
            db.insert_task(&task).await?;
            scheduled += 1;
        }
    }

    Ok(())
}

pub async fn run_sbom(args: &args::ReindexSbom) -> Result<()> {
    let db = db::Client::create().await?;

    let mut scheduled = 0;
    let stream = db.get_all_sboms();
    tokio::pin!(stream);
    while let Some(sbom) = stream.next().await {
        let sbom = sbom?;

        if let Some(strain) = &args.strain {
            if *strain != sbom.strain {
                continue;
            }
        }

        if let Some(limit) = &args.limit {
            if scheduled >= *limit {
                info!("Reached schedule limit of {limit} items, exiting");
                break;
            }
        }

        let chksum = &sbom.chksum;
        let sbom = match sbom::Sbom::try_from(&sbom) {
            Ok(sbom) => sbom,
            Err(err) => {
                error!("Failed to parse sbom: {err:#}");
                continue;
            }
        };

        let strain = sbom.strain();
        info!("Indexing sbom ({strain}: {chksum:?}");
        if let Err(err) = sbom::index(&db, &sbom).await {
            error!("Failed to index sbom: {err:#}");
            continue;
        }
        scheduled += 1;
    }

    Ok(())
}
