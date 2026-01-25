use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;
use crate::s3::UploadClient;
use tokio::io;

pub async fn run(args: &args::AddRef) -> Result<()> {
    let db = db::Client::create().await?;

    let summary =
        ingest::tar::stream_data(Some(&db), &UploadClient::disabled(), io::stdin(), None).await?;
    let chksum = summary.outer_digests.sha256;

    db.insert_ref(&db::Ref {
        chksum,
        vendor: args.vendor.clone(),
        package: args.package.clone(),
        version: args.version.clone(),
        filename: args.filename.clone(),
    })
    .await?;

    Ok(())
}
