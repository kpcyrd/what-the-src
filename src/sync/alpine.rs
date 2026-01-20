use crate::args;
use crate::db;
use crate::errors::*;
use crate::utils;
use async_compression::tokio::bufread::GzipDecoder;
use futures::{Stream, StreamExt};
use std::collections::HashMap;
use std::mem;
use tokio::io::{self, AsyncBufReadExt, AsyncRead};
use tokio_tar::{Archive, EntryType};

#[derive(Debug, PartialEq)]
pub struct Pkg {
    package: String,
    // This field is always set in Alpine, but sometimes missing in wolfi
    origin: Option<String>,
    version: String,
    // In wolfi this field is sometimes missing
    // We are going to ignore packages with no commit tho
    commit: Option<String>,
}

impl TryFrom<HashMap<String, String>> for Pkg {
    type Error = Error;

    fn try_from(mut map: HashMap<String, String>) -> Result<Pkg> {
        let package = map.remove("P").ok_or(Error::ApkMissingField("P"))?;
        let origin = map.remove("o");
        let version = map.remove("V").ok_or(Error::ApkMissingField("V"))?;
        let commit = map.remove("c");

        Ok(Pkg {
            package,
            origin,
            version,
            commit,
        })
    }
}

fn parse<R: AsyncRead + Unpin>(reader: R) -> impl Stream<Item = Result<Pkg>> {
    async_stream::stream! {
        let reader = io::BufReader::new(reader);
        let mut lines = reader.lines();
        let mut pkg = HashMap::new();
        while let Some(line) = lines.next_line().await? {
            if line.is_empty() {
                let pkg = mem::take(&mut pkg);
                let pkg = Pkg::try_from(pkg)?;
                yield Ok(pkg);
            } else if let Some((key, value)) = line.split_once(':') {
                pkg.insert(key.to_string(), value.to_string());
            }
        }
    }
}

pub async fn run(args: &args::SyncAlpine) -> Result<()> {
    let db = db::Client::create().await?;
    let vendor = &args.vendor;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let mut reader = io::BufReader::new(reader);
    {
        // discard first part of apkv2
        let mut reader = GzipDecoder::new(&mut reader);
        io::copy(&mut reader, &mut io::sink()).await?;
    }
    let reader = GzipDecoder::new(reader);
    let mut tar = Archive::new(reader);

    let mut entries = tar.entries()?;
    while let Some(entry) = entries.next().await {
        let entry = entry?;
        let header = entry.header();
        if header.entry_type() != EntryType::Regular {
            continue;
        }

        let path = entry.path()?;
        if path.to_str() != Some("APKINDEX") {
            continue;
        }

        let stream = parse(entry);
        tokio::pin!(stream);
        while let Some(pkg) = stream.next().await {
            let pkg = pkg?;
            debug!("Found package: {pkg:?}");

            let origin = pkg.origin.unwrap_or(pkg.package);
            let version = pkg.version;
            let Some(commit) = pkg.commit else { continue };

            // mark all refs known for this package as "last_seen now"
            db.bump_named_refs(vendor, &origin, &version).await?;

            // check if package already imported
            if db.get_package(vendor, &origin, &commit).await?.is_some() {
                debug!(
                    "Package is already imported: vendor={vendor:?} origin={origin:?} commit={commit:?}"
                );
                continue;
            }

            // queue for import
            info!("Inserting task: vendor={vendor:?} origin={origin:?} commit={commit:?}");
            db.insert_task(&db::Task::new(
                format!("{vendor}-apkbuild:{origin}:{commit}"),
                &db::TaskData::ApkbuildGit {
                    vendor: vendor.clone(),
                    repo: args.repo.clone(),
                    origin,
                    version,
                    commit,
                },
            )?)
            .await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_apkindex() {
        let data = "C:Q19qUyV9TFS+tErPDBnvqG7VqyvyM=
P:7zip-doc
V:23.01-r0
A:x86_64
S:38269
I:155648
T:File archiver with a high compression ratio (documentation)
U:https://7-zip.org/
L:LGPL-2.0-only
o:7zip
m:Alex Xu (Hello71) <alex_y_xu@yahoo.ca>
t:1688146859
c:da4780262417a9446b7d13fe9bb7e83c54edb53d
k:100
i:docs 7zip=23.01-r0

C:Q13kfUUaHQXJ5h+wwmkL6GXbVcbj8=
P:aaudit
V:0.7.2-r3
A:x86_64
S:3392
I:49152
T:Alpine Auditor
U:https://alpinelinux.org
L:Unknown
o:aaudit
m:Timo Teräs <timo.teras@iki.fi>
t:1659792088
c:0714a84b7f79009ae8b96aef50216ed72f54b885
D:lua5.2 lua5.2-posix lua5.2-cjson lua5.2-pc lua5.2-socket
p:cmd:aaudit=0.7.2-r3

";
        let mut out = vec![];
        let stream = parse(data.as_bytes());
        tokio::pin!(stream);
        while let Some(item) = stream.next().await {
            out.push(item.unwrap());
        }
        assert_eq!(
            &out[..],
            &[
                Pkg {
                    package: "7zip-doc".to_string(),
                    origin: Some("7zip".to_string()),
                    version: "23.01-r0".to_string(),
                    commit: Some("da4780262417a9446b7d13fe9bb7e83c54edb53d".to_string()),
                },
                Pkg {
                    package: "aaudit".to_string(),
                    origin: Some("aaudit".to_string()),
                    version: "0.7.2-r3".to_string(),
                    commit: Some("0714a84b7f79009ae8b96aef50216ed72f54b885".to_string()),
                },
            ][..]
        );
    }
}
