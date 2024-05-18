use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;
use crate::sbom;
use sqlx::types::chrono::Utc;

pub async fn run_url(args: &args::ReindexUrl) -> Result<()> {
    let db = db::Client::create().await?;

    let refs = db.get_all_refs().await?;
    let mut scheduled = 0;
    let now = Utc::now();
    for r in refs {
        let Some(filename) = &r.filename else {
            continue;
        };

        if let Some(filter) = &args.filter {
            if !filename.contains(filter) {
                continue;
            }
        }

        if let Some(limit) = &args.limit {
            if scheduled >= *limit {
                info!("Reached schedule limit of {limit} items, exiting");
                break;
            }
        }

        if let Some(age) = &args.age {
            if let Some(artifact) = db.resolve_artifact(&r.chksum).await? {
                let delta = now.signed_duration_since(artifact.last_imported);
                if delta.num_days() < *age {
                    continue;
                }
            }
        }

        if let Some(task) = ingest::pacman::task_for_url(filename) {
            info!("Inserting task: {task:?}");
            db.insert_task(&task).await?;
            scheduled += 1;
        }
    }

    Ok(())
}

pub async fn run_sbom(args: &args::ReindexSbom) -> Result<()> {
    let db = db::Client::create().await?;

    let sboms = db.get_all_sboms().await?;
    let mut scheduled = 0;
    for sbom in sboms {
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
