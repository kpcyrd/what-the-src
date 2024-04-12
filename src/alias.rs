use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;
use tokio::io;

pub async fn run(args: &args::AddRef) -> Result<()> {
    let db = db::Client::create().await?;

    let (_inner_digests, outer_digests, _files) = ingest::stream_data(io::stdin(), None).await?;
    let chksum = outer_digests.sha256;

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
