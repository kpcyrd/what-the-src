use crate::args;
use crate::db;
use crate::errors::*;
use crate::utils;
use async_compression::tokio::bufread::GzipDecoder;
use futures::{StreamExt, TryStreamExt};
use tokio::io::{self, AsyncRead, AsyncReadExt};

pub async fn stream_data<R: AsyncRead + Unpin>(
    mut reader: R,
    vendor: &str,
    package: &str,
    version: &str,
) -> Result<Vec<db::Ref>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await?;

    let rpm = rpm::Package::parse(&mut &buf[..])?;
    for entry in rpm.metadata.get_file_entries()? {
        let Some(file_name) = entry.path.file_name() else {
            continue;
        };
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        println!("path={file_name:?}");

        /*
        let reader = std::io::BufReader::new(entry)?;
        autocompress::autodetect_buf_reader(reader)?;

        if file_name.ends_with(".tar.gz") {
            println!("tgz={file_name:?}");
        }
        */
    }

    todo!()
}

pub async fn run(args: &args::IngestRpm) -> Result<()> {
    let db = db::Client::create().await?;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let refs = stream_data(reader, &args.vendor, &args.package, &args.version).await?;

    for r in refs {
        info!("insert: {r:?}");
        db.insert_ref(&r).await?;
    }

    Ok(())
}
