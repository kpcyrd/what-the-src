use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;

pub async fn run(args: &args::Reindex) -> Result<()> {
    let db = db::Client::create().await?;

    let refs = db.get_all_refs().await?;
    for r in refs {
        let Some(filename) = &r.filename else {
            continue;
        };
        if let Some(filter) = &args.filter {
            if !filename.contains(filter) {
                continue;
            }
        }

        if let Some(task) = ingest::pacman::task_for_url(filename) {
            info!("Inserting task: {task:?}");
            db.insert_task(&task).await?;
        }
    }

    Ok(())
}
