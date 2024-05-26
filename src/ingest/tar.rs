use crate::args;
use crate::chksums::{Checksums, Hasher};
use crate::compression::Decompressor;
use crate::db;
use crate::errors::*;
use crate::sbom;
use digest::Digest;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::fs::File;
use tokio::io::{self, AsyncRead, AsyncReadExt};
use tokio_tar::{Archive, EntryType};

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(flatten)]
    pub metadata: Metadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links_to: Option<LinksTo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groupname: Option<String>,
}

impl Metadata {
    fn from_tar_header<R: AsyncRead + Unpin>(
        entry: &tokio_tar::Entry<R>,
    ) -> Result<Option<(Self, bool)>> {
        let header = entry.header();
        let (is_file, links_to) = match header.entry_type() {
            EntryType::XGlobalHeader => return Ok(None),
            EntryType::Regular => (true, None),
            EntryType::Symlink => {
                let link = entry.link_name()?.map(|path| {
                    let path = path.to_string_lossy();
                    LinksTo::Symbolic(path.into_owned())
                });
                (false, link)
            }
            EntryType::Link => {
                let link = entry.link_name()?.map(|path| {
                    let path = path.to_string_lossy();
                    LinksTo::Hard(path.into_owned())
                });
                (false, link)
            }
            _ => (false, None),
        };

        let metadata = Metadata {
            mode: header.mode().ok().map(|mode| format!("0o{mode:o}")),
            links_to,
            mtime: header.mtime().ok(),
            uid: header.uid().ok(),
            username: header.username().ok().flatten().map(String::from),
            gid: header.gid().ok(),
            groupname: header.groupname().ok().flatten().map(String::from),
        };
        Ok(Some((metadata, is_file)))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinksTo {
    Hard(String),
    Symbolic(String),
}

pub struct TarSummary {
    pub inner_digests: Checksums,
    pub outer_digests: Checksums,
    pub files: Vec<Entry>,
    pub sbom_refs: Vec<sbom::Ref>,
}

pub async fn stream_data<R: AsyncRead + Unpin>(
    db: &db::Client,
    reader: R,
    compression: Option<&str>,
) -> Result<TarSummary> {
    // Setup decompressor
    let reader = io::BufReader::new(Hasher::new(reader));
    let (reader, outer_label) = match compression {
        Some("gz") => (Decompressor::gz(reader), "gz(tar)"),
        Some("xz") => (Decompressor::xz(reader), "xz(tar)"),
        Some("bz2") => (Decompressor::bz2(reader), "bz2(tar)"),
        None => (Decompressor::Plain(reader), "tar"),
        unknown => panic!("Unknown compression algorithm: {unknown:?}"),
    };
    let reader = Hasher::new(reader);

    // Open archive
    let mut tar = Archive::new(reader);
    let mut files = Vec::new();
    let mut sbom_refs = Vec::new();
    {
        let mut entries = tar.entries()?;
        while let Some(entry) = entries.next().await {
            let mut entry = entry?;
            let Some((metadata, is_file)) = Metadata::from_tar_header(&entry)? else {
                continue;
            };

            let path = entry.path()?;
            let filename = path.file_name().and_then(|f| f.to_str()).map(String::from);
            let path = path.to_string_lossy().into_owned();

            let digest = if is_file {
                let sbom = sbom::detect_from_filename(filename.as_deref());

                let mut buf = [0; 4096];
                let mut data = Vec::<u8>::new();
                let mut sha256 = Sha256::new();
                loop {
                    let n = entry.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    let buf = &buf[..n];
                    sha256.update(buf);
                    if sbom.is_some() {
                        data.extend(buf);
                    }
                }

                let digest = format!("sha256:{}", hex::encode(sha256.finalize()));

                if let Some(sbom) = sbom {
                    if let Ok(data) = String::from_utf8(data) {
                        let sbom = sbom::Sbom::new(sbom, data)?;
                        let chksum = db.insert_sbom(&sbom).await?;
                        let strain = sbom.strain();
                        info!("Inserted sbom {strain:?}: {digest:?}");
                        sbom_refs.push(sbom::Ref {
                            strain,
                            chksum: chksum.clone(),
                            path: path.clone(),
                        });
                        db.insert_task(&db::Task::new(
                            format!("sbom:{strain}:{chksum}"),
                            &db::TaskData::IndexSbom {
                                strain: Some(strain.to_string()),
                                chksum,
                            },
                        )?)
                        .await?;
                    }
                }

                Some(digest)
            } else {
                None
            };

            let entry = Entry {
                path: path.to_string(),
                digest,
                metadata,
            };
            debug!("Found entry={entry:?}");

            files.push(entry);
        }
    }
    let Ok(mut reader) = tar.into_inner() else {
        panic!("can't get hasher from tar reader")
    };

    // Consume any remaining data
    io::copy(&mut reader, &mut io::sink()).await?;

    // Determine hashes
    let (reader, inner_digests) = reader.digests();
    info!("Found digest for inner .tar: {inner_digests:?}");
    let reader = reader.into_inner().into_inner();

    let (_stream, outer_digests) = reader.digests();
    info!("Found digests for outer compressed tar: {outer_digests:?}");

    // Insert into database
    db.insert_artifact(&inner_digests.sha256, &files).await?;
    db.register_chksums_aliases(&inner_digests, &inner_digests.sha256, "tar")
        .await?;
    db.register_chksums_aliases(&outer_digests, &inner_digests.sha256, outer_label)
        .await?;

    for sbom in &sbom_refs {
        db.insert_sbom_ref(&inner_digests.sha256, sbom.strain, &sbom.chksum, &sbom.path)
            .await?;
    }

    Ok(TarSummary {
        inner_digests,
        outer_digests,
        files,
        sbom_refs,
    })
}

pub async fn run(args: &args::IngestTar) -> Result<()> {
    let db = db::Client::create().await?;

    let input: Box<dyn AsyncRead + Unpin> = if let Some(path) = &args.file {
        Box::new(File::open(path).await?)
    } else {
        Box::new(io::stdin())
    };

    stream_data(&db, input, args.compression.as_deref()).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_json_format() {
        let txt = serde_json::to_string_pretty(&Entry {
            path: "foo-1.0/".to_string(),
            digest: None,
            metadata: Metadata {
                mode: Some("0o775".to_string()),
                links_to: None,
                mtime: Some(1337),
                uid: Some(0),
                username: None,
                gid: Some(0),
                groupname: None,
            },
        })
        .unwrap();
        assert_eq!(
            txt,
            r#"{
  "path": "foo-1.0/",
  "mode": "0o775",
  "mtime": 1337,
  "uid": 0,
  "gid": 0
}"#
        );
    }

    #[test]
    fn test_regular_json_format() {
        let txt = serde_json::to_string_pretty(&Entry {
            path: "foo-1.0/original_file".to_string(),
            digest: None,
            metadata: Metadata {
                mode: Some("0o775".to_string()),
                links_to: None,
                mtime: Some(1337),
                uid: Some(1000),
                username: Some("user".to_string()),
                gid: Some(1000),
                groupname: Some("user".to_string()),
            },
        })
        .unwrap();
        assert_eq!(
            txt,
            r#"{
  "path": "foo-1.0/original_file",
  "mode": "0o775",
  "mtime": 1337,
  "uid": 1000,
  "username": "user",
  "gid": 1000,
  "groupname": "user"
}"#
        );
    }
}
