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
use std::path::Path;
use tokio::fs::File;
use tokio::io::{self, AsyncRead, AsyncReadExt};
use tokio_tar::{Archive, EntryType};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(flatten)]
    pub metadata: Metadata,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinksTo {
    Hard(String),
    Symbolic(String),
}

#[derive(Debug, PartialEq)]
pub struct TarSummary {
    pub inner_digests: Checksums,
    pub outer_digests: Checksums,
    pub files: Vec<Entry>,
    pub sbom_refs: Vec<sbom::Ref>,
}

/// The processed entry key of a tar archive
struct TarEntryKey {
    path: String,
    filename: Option<String>,
}

impl TarEntryKey {
    fn new(path: &Path) -> Self {
        let filename = path.file_name().and_then(|f| f.to_str()).map(String::from);
        let path = path.to_string_lossy().into_owned();
        Self { path, filename }
    }
}

async fn stream_entry_content<R: AsyncRead + Unpin>(
    mut entry: R,
    mut data: Option<&mut Vec<u8>>,
) -> Result<String> {
    let mut buf = [0; 4096];
    let mut sha256 = Sha256::new();

    loop {
        let n = entry.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let buf = &buf[..n];
        sha256.update(buf);
        if let Some(data) = &mut data {
            data.extend(buf);
        }
    }

    let digest = format!("sha256:{}", hex::encode(sha256.finalize()));
    Ok(digest)
}

#[derive(Default)]
struct TarSummaryBuilder {
    files: Vec<Entry>,
    sbom_refs: Vec<sbom::Ref>,
}

impl TarSummaryBuilder {
    async fn stream_entry<R: AsyncRead + Unpin>(
        &mut self,
        db: Option<&db::Client>,
        mut entry: R,
        entry_key: &TarEntryKey,
    ) -> Result<String> {
        let sbom = sbom::detect_from_filename(entry_key.filename.as_deref());

        let mut data = Vec::<u8>::new();
        let digest = stream_entry_content(&mut entry, sbom.is_some().then_some(&mut data)).await?;

        if let Some(sbom) = sbom
            && let Some(db) = db
            && let Ok(data) = String::from_utf8(data)
        {
            let sbom = sbom::Sbom::new(sbom, data)?;
            let chksum = db.insert_sbom(&sbom).await?;
            let strain = sbom.strain();
            info!("Inserted sbom {strain:?}: {digest:?}");
            self.sbom_refs.push(sbom::Ref {
                strain,
                chksum: chksum.clone(),
                path: entry_key.path.clone(),
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

        Ok(digest)
    }
}

pub async fn stream_data<R: AsyncRead + Unpin>(
    db: Option<&db::Client>,
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
    let mut builder = TarSummaryBuilder::default();
    {
        let mut entries = tar.entries()?;
        while let Some(entry) = entries.next().await {
            let mut entry = entry?;
            let Some((metadata, is_file)) = Metadata::from_tar_header(&entry)? else {
                continue;
            };

            let entry_key = TarEntryKey::new(&entry.path()?);

            let digest = if is_file {
                let digest = builder.stream_entry(db, &mut entry, &entry_key).await?;
                Some(digest)
            } else {
                None
            };

            let entry = Entry {
                path: entry_key.path,
                digest,
                metadata,
            };
            debug!("Found entry={entry:?}");

            builder.files.push(entry);
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

    if let Some(db) = db {
        // Insert into database
        db.insert_artifact(&inner_digests.sha256, &builder.files)
            .await?;
        db.register_chksums_aliases(&inner_digests, &inner_digests.sha256, "tar")
            .await?;
        db.register_chksums_aliases(&outer_digests, &inner_digests.sha256, outer_label)
            .await?;

        for sbom in &builder.sbom_refs {
            db.insert_sbom_ref(&inner_digests.sha256, sbom.strain, &sbom.chksum, &sbom.path)
                .await?;
        }
    }

    Ok(TarSummary {
        inner_digests,
        outer_digests,
        files: builder.files,
        sbom_refs: builder.sbom_refs,
    })
}

pub async fn run(args: &args::IngestTar) -> Result<()> {
    let db = db::Client::create().await?;

    let input: Box<dyn AsyncRead + Unpin> = if let Some(path) = &args.file {
        Box::new(File::open(path).await?)
    } else {
        Box::new(io::stdin())
    };

    stream_data(Some(&db), input, args.compression.as_deref()).await?;

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

    #[tokio::test]
    async fn test_ingest_tar() {
        let data = [
            0x1f, 0x8b, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0xed, 0xd5, 0xed, 0xa, 0x82, 0x30,
            0x14, 0x6, 0xe0, 0xfd, 0xee, 0x2a, 0x76, 0x3, 0xd9, 0xbe, 0x77, 0x23, 0xfd, 0xf, 0x21,
            0xcd, 0x91, 0x29, 0xa8, 0xfd, 0xe8, 0xee, 0x9b, 0xd4, 0x20, 0xfa, 0x10, 0x2, 0xa7,
            0x94, 0xef, 0x83, 0x30, 0x50, 0xc1, 0xc3, 0xde, 0x9d, 0x63, 0x5e, 0xd7, 0x6b, 0x9e,
            0xb0, 0xd, 0x89, 0x88, 0x79, 0x56, 0xeb, 0x7e, 0xe5, 0x56, 0xb3, 0xc7, 0x35, 0x20,
            0x5c, 0x19, 0xee, 0x6f, 0x5a, 0x61, 0x2c, 0x61, 0x9c, 0x19, 0x2b, 0x9, 0xd5, 0x31,
            0x8b, 0xa, 0xce, 0x6d, 0x97, 0x36, 0x94, 0xfa, 0x35, 0x6b, 0x86, 0xdf, 0x1b, 0x7e,
            0xfe, 0xa3, 0xf2, 0x7b, 0xfe, 0x75, 0xe3, 0xe, 0xae, 0x4a, 0xcb, 0x5d, 0xee, 0xca,
            0x6c, 0xe4, 0x6f, 0xf4, 0x1, 0x1b, 0xa5, 0x3e, 0xe7, 0x2f, 0xe5, 0x53, 0xfe, 0x52,
            0x71, 0x4d, 0x28, 0x1b, 0xb9, 0x8e, 0xb7, 0x16, 0x9e, 0xff, 0xb6, 0x70, 0x2d, 0xf5,
            0x57, 0x57, 0x64, 0x34, 0x9c, 0x1, 0xda, 0x9f, 0x81, 0x64, 0x35, 0x77, 0x69, 0x30,
            0x81, 0xd0, 0xff, 0x45, 0xda, 0xec, 0x4b, 0x57, 0x1d, 0x67, 0xe9, 0xff, 0x97, 0xf9,
            0x6f, 0x5, 0xf3, 0xf3, 0x9f, 0x4f, 0x31, 0x9c, 0x16, 0xde, 0xff, 0x61, 0x8b, 0xdb,
            0xcb, 0x29, 0x56, 0xfc, 0xb7, 0xff, 0xbf, 0xb5, 0x5f, 0xe4, 0x6f, 0x98, 0x30, 0x84,
            0x8a, 0x98, 0xb9, 0x7, 0xb, 0xcf, 0x1f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xc3, 0x15, 0xdc, 0x23, 0xbf, 0x4f, 0x0, 0x28, 0x0, 0x0,
        ];

        let summary = stream_data(None, &data[..], Some("gz")).await.unwrap();
        assert_eq!(summary, TarSummary {
            inner_digests: Checksums {
                sha256: "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0".to_string(),
                sha512: "sha512:d2d14d47a23f20ef522b76765b9feb80d6d66f06b97d8ba8cbabebdee483880d31cf0522eb318613d94a808cde4e8ef8860733f8bde41dd7c4fca3b82cd354eb".to_string(),
                blake2b: "blake2b:601ba064ff937c07e0695408111694230af5eeef97bd3d783d619d88dcb4a434cebb38d2eb6fc7a3b9b36e9e76676c18ba237c3eea922fe7cf41d61bcf86f65a".to_string(),
            },
            outer_digests: Checksums {
                sha256: "sha256:9390fb29874d4e70ae4e8379aa7fc396e0a44cacf8256aa8d87fdec9b56261d4".to_string(),
                sha512: "sha512:8b981a89ec6735f0c1de0f7d58cbd30921b9fdf645b68330ab1080b2d563410acb3ae77881a2817438ca6405eaafbb62f131a371f0f0e5fcb91727310fb7a370".to_string(),
                blake2b: "blake2b:47e872432ce32b7cecc554cc9c67d12553e62fed8f42768a43e64f16ca72e9679b0f539e7f47bf89ffe658be7b3a29f857d4ce244523dce181587c42ec4c7533".to_string(),
            },
            files: vec![
                Entry {
                    path: "foo-1.0/".to_string(),
                    digest: None,
                    metadata: Metadata {
                        mode: Some("0o755".to_string()),
                        links_to: None,
                        mtime: Some(1713888951),
                        uid: Some(1000),
                        username: Some("user".to_string()),
                        gid: Some(1000),
                        groupname: Some("user".to_string()),
                    }
                },
                Entry {
                    path: "foo-1.0/original_file".to_string(),
                    digest: Some("sha256:56d9fc4585da4f39bbc5c8ec953fb7962188fa5ed70b2dd5a19dc82df997ba5e".to_string()),
                    metadata: Metadata {
                        mode: Some("0o644".to_string()),
                        links_to: None,
                        mtime: Some(1713888951),
                        uid: Some(1000),
                        username: Some("user".to_string()),
                        gid: Some(1000),
                        groupname: Some("user".to_string()),
                    }
                },
                Entry {
                    path: "foo-1.0/hardlink_file".to_string(),
                    digest: None,
                    metadata: Metadata {
                        mode: Some("0o644".to_string()),
                        links_to: Some(LinksTo::Hard("foo-1.0/original_file".to_string())),
                        mtime: Some(1713888951),
                        uid: Some(1000),
                        username: Some("user".to_string()),
                        gid: Some(1000),
                        groupname: Some("user".to_string()),
                    }
                },
                Entry {
                    path: "foo-1.0/symlink_file".to_string(),
                    digest: None,
                    metadata: Metadata {
                        mode: Some("0o777".to_string()),
                        links_to: Some(LinksTo::Symbolic("original_file".to_string())),
                        mtime: Some(1713888951),
                        uid: Some(1000),
                        username: Some("user".to_string()),
                        gid: Some(1000),
                        groupname: Some("user".to_string()),
                    }
                },
            ],
            sbom_refs: vec![],
        });
    }
}
