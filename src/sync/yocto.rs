use crate::args;
// use crate::db;
use crate::errors::*;
use crate::utils;
// use crate::yocto;
use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
// use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
use std::path::Path;
use tokio::io::{self, AsyncReadExt};
use tokio_tar::Archive;

fn metadata_from_path(path: &Path) -> Option<(&str, &str)> {
    let path = path.to_str()?;
    println!("path={path:?}");
    let (_, path) = path.split_once("/recipes")?;
    let (_, path) = path.split_once('/')?;

    let (_parent, filename) = path.split_once('/')?;
    let release = filename.strip_suffix(".bb")?;

    let (package, version) = release.rsplit_once('_')?;

    Some((package, version))
}

pub async fn run(args: &args::SyncYocto) -> Result<()> {
    // let db = db::Client::create().await?;
    // let vendor = &args.vendor;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let reader = io::BufReader::new(reader);
    let reader = GzipDecoder::new(reader);
    let mut tar = Archive::new(reader);

    let mut entries = tar.entries()?;
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }

        let path = entry.path()?;
        let Some((package, version)) = metadata_from_path(&path) else {
            continue;
        };

        println!("package={package:?} version={version:?}");

        let mut buf = String::new();
        entry.read_to_string(&mut buf).await?;

        if !buf.contains("PV = ") {
            continue;
        };

        println!("buf={buf:?}");

        // let bitbake = yocto::parse(&buf)?;
        // println!("bitbake={bitbake:?}");
    }

    Ok(())
}
