use crate::args;
use crate::db;
use crate::errors::*;
use crate::pkgbuild;
use crate::sbom;
use crate::utils;
use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
use srcinfo::Srcinfo;
use tokio::io::{self, AsyncRead, AsyncReadExt};
use tokio_tar::Archive;

#[derive(Debug)]
pub struct Snapshot {
    pkgbuild: String,
    srcinfo: Option<String>,
}

impl Snapshot {
    pub async fn parse_from_tgz<R: AsyncRead + Unpin>(
        db: &db::Client,
        reader: R,
    ) -> Result<Snapshot> {
        let reader = io::BufReader::new(reader);
        let reader = GzipDecoder::new(reader);
        let mut tar = Archive::new(reader);

        let mut pkgbuild = None;
        let mut srcinfo = None;

        let mut entries = tar.entries()?;
        while let Some(entry) = entries.next().await {
            let mut entry = entry?;
            let path = entry.path()?;
            let Some(file_name) = path.file_name() else {
                continue;
            };
            match file_name.to_str() {
                Some(".SRCINFO") => {
                    let mut buf = String::new();
                    entry.read_to_string(&mut buf).await?;
                    srcinfo = Some(buf);
                }
                Some("PKGBUILD") => {
                    let mut buf = String::new();
                    entry.read_to_string(&mut buf).await?;
                    pkgbuild = Some(buf);
                }
                filename => {
                    if let Some(strain) = sbom::detect_from_filename(filename) {
                        let mut buf = String::new();
                        entry.read_to_string(&mut buf).await?;

                        let sbom = sbom::Sbom::new(strain, buf)?;
                        let chksum = db.insert_sbom(&sbom).await?;
                        let strain = sbom.strain();
                        info!("Inserted sbom {strain:?}: {chksum:?}");
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
            }
        }

        Ok(Snapshot {
            pkgbuild: pkgbuild.ok_or(Error::InvalidData)?,
            srcinfo,
        })
    }

    fn get_from_archvec(vec: &srcinfo::ArchVecs) -> &[String] {
        let Some(vec) = vec.get_any() else {
            return &[];
        };
        vec.values()
    }

    fn source_entries_from_lists(
        max: usize,
        sources: &[String],
        sha256sums: &[String],
        sha512sums: &[String],
        b2sums: &[String],
    ) -> Vec<SourceEntry> {
        let mut out = Vec::new();
        for i in 0..max {
            let url = sources.get(i).map(|url| {
                url.split_once("::")
                    .map(|(_filename, url)| url)
                    .unwrap_or(url)
                    .to_string()
            });

            // Skip entries that we know for sure are not urls
            if let Some(url) = &url
                && !url.contains("://")
            {
                continue;
            }

            out.push(SourceEntry {
                url,
                sha256: Self::filter_skip(sha256sums.get(i)),
                sha512: Self::filter_skip(sha512sums.get(i)),
                blake2b: Self::filter_skip(b2sums.get(i)),
            });
        }
        out
    }

    fn filter_skip(v: Option<&String>) -> Option<String> {
        v.filter(|v| *v != "SKIP").cloned()
    }

    pub fn source_entries(&self) -> Result<Vec<SourceEntry>> {
        if let Some(srcinfo) = &self.srcinfo {
            let srcinfo = Srcinfo::from_buf(srcinfo.as_bytes())?;
            let sources = Self::get_from_archvec(&srcinfo.base.source);
            let sha256sums = Self::get_from_archvec(&srcinfo.base.sha256sums);
            let sha512sums = Self::get_from_archvec(&srcinfo.base.sha512sums);
            let b2sums = Self::get_from_archvec(&srcinfo.base.b2sums);

            Ok(Self::source_entries_from_lists(
                sources.len(),
                sources,
                sha256sums,
                sha512sums,
                b2sums,
            ))
        } else {
            let pkgbuild = pkgbuild::parse(self.pkgbuild.as_bytes())?;

            let max = [
                pkgbuild.sha256sums.len(),
                pkgbuild.sha512sums.len(),
                pkgbuild.b2sums.len(),
            ]
            .into_iter()
            .max()
            .unwrap_or(0);

            Ok(Self::source_entries_from_lists(
                max,
                &[],
                &pkgbuild.sha256sums,
                &pkgbuild.sha512sums,
                &pkgbuild.b2sums,
            ))
        }
    }
}

#[derive(Debug)]
pub struct SourceEntry {
    url: Option<String>,
    sha256: Option<String>,
    sha512: Option<String>,
    blake2b: Option<String>,
}

impl SourceEntry {
    pub fn preferred_chksum(&self) -> Option<String> {
        match (&self.sha256, &self.sha512, &self.blake2b) {
            (Some(sha256), _, _) => Some(format!("sha256:{sha256}")),
            (None, Some(sha512), _) => Some(format!("sha512:{sha512}")),
            (None, None, Some(blake2b)) => Some(format!("blake2b:{blake2b}")),
            (None, None, None) => None,
        }
    }
}

pub async fn stream_data<R: AsyncRead + Unpin>(
    db: &db::Client,
    reader: R,
    vendor: &str,
    package: &str,
    version: &str,
    prefer_pkgbuild: bool,
) -> Result<()> {
    let mut snapshot = Snapshot::parse_from_tgz(db, reader).await?;
    if prefer_pkgbuild {
        snapshot.srcinfo = None;
    }

    for entry in snapshot.source_entries()? {
        debug!("Found source entry: {entry:?}");
        let Some(chksum) = entry.preferred_chksum() else {
            continue;
        };

        // TODO: check if already known
        if let Some(url) = &entry.url
            && let Some(task) = utils::task_for_url(url)
        {
            db.insert_task(&task).await?;
        }

        let r = db::Ref {
            chksum,
            vendor: vendor.to_string(),
            package: package.to_string(),
            version: version.to_string(),
            filename: entry.url,
        };
        info!("insert: {r:?}");
        db.insert_ref(&r).await?;
    }

    Ok(())
}

pub async fn run(args: &args::IngestPacmanSnapshot) -> Result<()> {
    let db = db::Client::create().await?;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    stream_data(
        &db,
        reader,
        &args.vendor,
        &args.package,
        &args.version,
        args.prefer_pkgbuild,
    )
    .await?;

    Ok(())
}
