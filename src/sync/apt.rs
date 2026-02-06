use crate::args;
use crate::compression::Decompressor;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::parsers::apt;
use crate::utils;
use apt_parser::Release;
use tokio::io::{self, AsyncReadExt};

async fn find_source_index_path(
    http: &utils::HttpClient,
    url: &str,
    suite: &str,
) -> Result<(String, &'static str)> {
    let mut reader = http.fetch(url).await?;

    let mut buf = String::new();
    reader.read_to_string(&mut buf).await?;
    let release = Release::from(&buf)?;

    for file in release.sha256sum.into_iter().flatten() {
        let name = file.filename;

        match name.strip_prefix(suite) {
            Some("/source/Sources.xz") => return Ok((name, "xz")),
            Some("/source/Sources.gz") => return Ok((name, "gz")),
            _ => (),
        }
    }

    Err(Error::AptIndexMissingSources)
}

pub async fn run(args: &args::SyncApt) -> Result<()> {
    let base_url = args.url.strip_suffix('/').unwrap_or(&args.url);

    let db = db::Client::create().await?;
    let http = utils::http_client(None)?;

    for release in &args.releases {
        for suite in &args.suites {
            let url = format!("{base_url}/dists/{release}/Release");
            info!("Fetching Release file: url={url:?}");
            let (filename, compression) = find_source_index_path(&http, &url, suite).await?;

            let url = format!("{base_url}/dists/{release}/{filename}");
            info!("Fetching Sources index: url={url:?}");
            let reader = http.fetch(&url).await?;
            let reader = io::BufReader::new(reader);
            let mut reader = match compression {
                "gz" => Decompressor::gz(reader),
                "xz" => Decompressor::xz(reader),
                unknown => panic!("Unknown compression algorithm: {unknown:?}"),
            };

            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).await?;

            let sources = apt::SourcesIndex::parse(&buf)?;

            for pkg in &sources.pkgs {
                debug!("pkg={pkg:?}");
                pkg.version.as_ref().unwrap();
                pkg.directory.as_ref().unwrap();

                for entry in &pkg.checksums_sha256 {
                    let name = entry.filename.clone();
                    if name.ends_with(".orig.tar.xz")
                        || name.ends_with(".orig.tar.gz")
                        || name.ends_with(".orig.tar.bz2")
                    {
                        let chksum = format!("sha256:{}", entry.hash);
                        let package = pkg.package.to_string();
                        let version = pkg.version.clone().unwrap();
                        debug!(
                            "digest={chksum:?} package={package:?} version={version:?} name={name:?}"
                        );
                        let obj = db::Ref {
                            chksum,
                            vendor: args.vendor.to_string(),
                            package,
                            version,
                            filename: Some(name.clone()),
                            protocol: None,
                            host: None,
                        };
                        db.insert_ref(&obj).await?;

                        if name.starts_with("chromium_") {
                            continue;
                        }

                        if args.reindex || db.resolve_artifact(&obj.chksum).await?.is_none() {
                            let directory = pkg.directory.as_ref().unwrap();
                            let url = format!("{base_url}/{directory}/{name}");
                            info!("Found new tarball, url={url:?}");
                            db.insert_task(&Task::new(
                                format!("fetch:{url}"),
                                &TaskData::FetchTar {
                                    url,
                                    success_ref: None,
                                },
                            )?)
                            .await?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
