use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;
use sqlx::types::chrono::Utc;

pub async fn run(args: &args::Reindex) -> Result<()> {
    let db = db::Client::create().await?;

    let refs = db.get_all_refs().await?;
    let mut scheduled = 0;
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
                let delta = Utc::now().signed_duration_since(artifact.last_imported);
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
