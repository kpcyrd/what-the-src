use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;
use crate::s3::UploadClient;
use tokio::io;

pub async fn run(args: &args::AddRef) -> Result<()> {
    let db = db::Client::create().await?;
    let upload = UploadClient::disabled();

    let summary = ingest::tar::stream_data(Some(&db), &upload, io::stdin()).await?;
    let chksum = summary.outer_digests.sha256;

    db.insert_ref(&db::Ref::new(
        chksum,
        args.vendor.clone(),
        args.package.clone(),
        args.version.clone(),
        args.filename.clone(),
    ))
    .await?;

    Ok(())
}
