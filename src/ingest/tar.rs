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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links_to: Option<LinksTo>,
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
    let reader = match compression {
        Some("gz") => Decompressor::gz(reader),
        Some("xz") => Decompressor::xz(reader),
        Some("bz2") => Decompressor::bz2(reader),
        None => Decompressor::Plain(reader),
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
            let (path, filename, is_file, links_to) = {
                let header = entry.header();
                let (is_file, links_to) = match header.entry_type() {
                    EntryType::XGlobalHeader => continue,
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

                let path = header.path()?;
                let filename = path.file_name().and_then(|f| f.to_str()).map(String::from);

                let path = path.to_string_lossy();
                (path.into_owned(), filename, is_file, links_to)
            };

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
                        info!("Inserting sbom {:?}: {digest:?}", sbom.strain());
                        let chksum = db.insert_sbom(&sbom).await?;
                        sbom_refs.push(sbom::Ref {
                            strain: sbom.strain(),
                            chksum: chksum.clone(),
                            path: path.clone(),
                        });
                        db.insert_task(&db::Task::new(
                            format!("sbom:{chksum}"),
                            &db::TaskData::IndexSbom { chksum },
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
                links_to,
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
    db.register_chksums_aliases(&inner_digests, &inner_digests.sha256)
        .await?;
    db.register_chksums_aliases(&outer_digests, &inner_digests.sha256)
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
