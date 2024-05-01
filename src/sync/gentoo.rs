use crate::args;
use crate::db;
use crate::errors::*;
use crate::utils;
use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
use std::collections::BTreeMap;
// use futures::TryStreamExt;
// use serde::Deserialize;
use tokio::io::{self, AsyncBufReadExt, AsyncRead, AsyncReadExt};
use tokio_tar::{Archive, EntryType};
// use tokio_util::io::StreamReader;

#[derive(Debug, PartialEq, Default)]
pub struct ManifestEntry {
    pub filename: String,
    pub size: u64,
    pub blake2b: Option<String>,
    pub sha512: Option<String>,
}

#[derive(Debug, PartialEq, Default)]
pub struct Package {
    pub manifest: Vec<ManifestEntry>,
    pub ebuilds: BTreeMap<String, String>,
}

fn parse_manifest_entry(line: &str) -> Result<ManifestEntry> {
    let Some(line) = line.strip_prefix("DIST ") else {
        return Err(Error::InvalidData);
    };
    let Some((filename, line)) = line.split_once(' ') else {
        return Err(Error::InvalidData);
    };
    let Some((size, line)) = line.split_once(' ') else {
        return Err(Error::InvalidData);
    };

    let mut entry = ManifestEntry {
        filename: filename.to_string(),
        size: size.parse()?,
        ..Default::default()
    };

    let mut remaining = line;
    while !remaining.is_empty() {
        let Some((key, line)) = remaining.split_once(' ') else {
            break;
        };
        let (value, line) = line.split_once(' ').unwrap_or((line, ""));
        remaining = line;
        match key {
            "BLAKE2B" => entry.blake2b = Some(value.to_string()),
            "SHA512" => entry.sha512 = Some(value.to_string()),
            _ => (),
        }
    }

    Ok(entry)
}

pub async fn run(args: &args::SyncGentoo) -> Result<()> {
    let db = db::Client::create().await?;
    let vendor = &args.vendor;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let reader = io::BufReader::new(reader);
    let reader = GzipDecoder::new(reader);
    let mut tar = Archive::new(reader);

    let mut index = BTreeMap::<_, Package>::new();

    let mut entries = tar.entries()?;
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        let path = {
            let header = entry.header();
            if header.entry_type() != EntryType::Regular {
                continue;
            }
            header.path()?.into_owned()
        };

        if path.starts_with("metadata/md5-cache") {
            continue;
        }

        let Some(parent) = path.parent() else {
            continue;
        };
        let parent = parent.strip_prefix("gentoo-master").unwrap_or(parent);
        let Some(filename) = path.file_name() else {
            continue;
        };
        let Some(filename) = filename.to_str() else {
            continue;
        };

        debug!("Found file in git: parent={parent:?} file={filename:?}");

        if filename == "Manifest" {
            debug!("Found package manifest: {parent:?}");
            let pkg = index.entry(parent.to_owned()).or_default();

            let reader = io::BufReader::new(entry);
            let mut lines = reader.lines();
            while let Some(line) = lines.next_line().await? {
                let entry = parse_manifest_entry(&line)?;
                pkg.manifest.push(entry);
            }
        } else if filename.ends_with(".ebuild") {
            debug!("Found ebuild: {filename:?}");
            let pkg = index.entry(parent.to_owned()).or_default();

            let mut buf = String::new();
            entry.read_to_string(&mut buf).await?;

            pkg.ebuilds.insert(filename.to_string(), buf);
        }
    }

    for (pkg, data) in index {
        for (ebuild, buf) in data.ebuilds {
            println!(
                "pkg={pkg:?} ebuild={ebuild:?} artifacts={:?}",
                data.manifest.len()
            );
        }
    }
    // println!("index={index:?}");

    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest() {
        let line = "DIST aho-corasick-1.1.2.crate 183136 BLAKE2B 2d4306d8968061b9f7e50190be6a92b3f668169ba1b9f9691de08a57c96185f7a4288d20c64cb8488a260eb18d3ed4b0e8358b0cca47aa44759b2e448049cbaa SHA512 61ef5092673ab5a60bec4e92df28a91fe6171ba59d5829ffe41fc55aff3bfb755533a4ad53dc7bf827a0b789fcce593b17e69d1fcfb3694f06ed3b1bd535d40c";
        let entry = parse_manifest_entry(line).unwrap();
        assert_eq!(
            entry,
            ManifestEntry {
                filename: "aho-corasick-1.1.2.crate".to_string(),
                size: 183136,
                blake2b: Some("2d4306d8968061b9f7e50190be6a92b3f668169ba1b9f9691de08a57c96185f7a4288d20c64cb8488a260eb18d3ed4b0e8358b0cca47aa44759b2e448049cbaa".to_string()),
                sha512: Some("61ef5092673ab5a60bec4e92df28a91fe6171ba59d5829ffe41fc55aff3bfb755533a4ad53dc7bf827a0b789fcce593b17e69d1fcfb3694f06ed3b1bd535d40c".to_string()),
            }
        );
    }
}
