use crate::args;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::ingest;
use crate::sbom;
use crate::utils;
use std::sync::Arc;
use tokio::time::{self, Duration};

fn normalize_archlinux_gitlab_names(package: &str) -> String {
    if package == "tree" {
        return "unix-tree".to_string();
    }

    let mut iter = package.chars();
    let mut out = String::new();
    while let Some(ch) = iter.next() {
        if ch != '+' {
            out.push(ch);
        } else if iter.clone().any(|c| c != '+') {
            out.push('-');
        } else {
            out.push_str("plus");
        }
    }
    out
}

pub struct Worker {
    db: Arc<db::Client>,
    http: utils::HttpClient,
    git_tmp: String,
}

impl Worker {
    pub async fn do_task(&self, task: &Task) -> Result<()> {
        let data = task.data()?;

        match data {
            TaskData::FetchTar {
                url,
                compression,
                success_ref,
            } => {
                // After importing entire distros, this is the only software I struggle with.
                // This clown browser:
                //  - has >1 million source files
                //    - 2.8x of Firefox
                //    - 12x of the Linux kernel
                //  - the compressed tarball is 3.5GB large
                //    - 6x of Firefox
                //    - 24x of the Linux kernel
                //  - processing this makes my vps go OOM
                //    - even though I already process the http response as a stream
                //    - holding the xz state for decompression takes 2gb of ram
                // I don't have time for this. Tech layoffs should've started sooner.
                if url.starts_with(
                    "https://commondatastorage.googleapis.com/chromium-browser-official/chromium-",
                ) {
                    info!("Detected chromium, skipping 🤡: {url:?}");
                    return Ok(());
                }

                info!("Fetching tar: {url:?}");
                let reader = self.http.fetch(&url).await?;

                // TODO: do this stuff on the fly
                let compression = if let Some(compression) = &compression {
                    Some(compression.as_str())
                } else if url.ends_with(".gz") || url.ends_with(".tgz") {
                    Some("gz")
                } else if url.ends_with(".xz") {
                    Some("xz")
                } else if url.ends_with(".bz2") {
                    Some("bz2")
                } else {
                    None
                };

                // If there's an "on success" hook, insert it
                let summary = ingest::tar::stream_data(Some(&self.db), reader, compression).await?;
                if let Some(pkg) = success_ref {
                    let r = db::Ref {
                        chksum: summary.outer_digests.sha256,
                        vendor: pkg.vendor,
                        package: pkg.package,
                        version: pkg.version,
                        filename: Some(url),
                    };
                    info!("insert: {r:?}");
                    self.db.insert_ref(&r).await?;
                }
            }
            TaskData::PacmanGitSnapshot {
                vendor,
                package,
                version,
                tag,
            } => {
                let repo = normalize_archlinux_gitlab_names(&package);
                let url = format!("https://gitlab.archlinux.org/archlinux/packaging/packages/{repo}/-/archive/{tag}/{repo}-{tag}.tar.gz");

                info!("Downloading pacman git snapshot: {url:?}");
                let reader = self.http.fetch(&url).await?;
                ingest::pacman::stream_data(&self.db, reader, &vendor, &package, &version, false)
                    .await?;

                self.db
                    .insert_package(&db::Package {
                        vendor,
                        package,
                        version,
                    })
                    .await?;
            }
            TaskData::SourceRpm {
                vendor,
                package,
                version,
                url,
            } => {
                info!("Downloading source rpm: {url:?}");
                let reader = self.http.fetch(&url).await?;

                ingest::rpm::stream_data(
                    self.db.clone(),
                    reader,
                    vendor.to_string(),
                    package.to_string(),
                    version.to_string(),
                )
                .await?;

                self.db
                    .insert_package(&db::Package {
                        vendor,
                        package,
                        version,
                    })
                    .await?;
            }
            TaskData::ApkbuildGit {
                vendor,
                repo,
                origin,
                version,
                commit,
            } => {
                match vendor.as_str() {
                    "alpine" => {
                        let Some(repo) = repo else {
                            return Err(Error::AlpineMissingRepo);
                        };
                        let url = format!("https://gitlab.alpinelinux.org/alpine/aports/-/raw/{commit}/{repo}/{origin}/APKBUILD");
                        info!("Fetching APKBUILD: {url:?}");
                        let reader = self.http.fetch(&url).await?;

                        ingest::alpine::stream_data(&self.db, reader, &vendor, &origin, &version)
                            .await?;
                    }
                    "wolfi" => {
                        let url =
                            format!("https://github.com/wolfi-dev/os/raw/{commit}/{origin}.yaml");

                        info!("Fetching wolfi yaml: {url:?}");
                        let reader = self.http.fetch(&url).await?;

                        ingest::wolfi::stream_data(&self.db, reader, &vendor, &origin, &version)
                            .await?;
                    }
                    _ => return Err(Error::UnrecognizedApkVendor(vendor)),
                }

                self.db
                    .insert_package(&db::Package {
                        vendor,
                        package: origin,
                        version: commit,
                    })
                    .await?;
            }
            TaskData::GitSnapshot { url } => {
                let git = url.parse::<ingest::git::GitUrl>()?;
                ingest::git::take_snapshot(&self.db, &git, &self.git_tmp).await?;
            }
            TaskData::IndexSbom { strain, chksum } => {
                // Support old sbom task format
                let sbom = if let Some(strain) = strain {
                    self.db.get_sbom_with_strain(&chksum, &strain).await?
                } else {
                    self.db.get_sbom(&chksum).await?
                };

                // If sbom was found
                if let Some(sbom) = sbom {
                    let sbom = sbom::Sbom::try_from(&sbom)?;
                    sbom::index(&self.db, &sbom).await?;
                }
            }
            TaskData::VoidLinuxGit {
                vendor,
                srcpkg,
                commit,
                package,
                version,
            } => {
                debug!("Void Linux: vendor={vendor:?} srcpkg={srcpkg:?} commit={commit:?} package={package:?} version={version:?}");
                let url =
                    format!("https://github.com/void-linux/void-packages/archive/{commit}.tar.gz");

                info!("Downloading Void Linux git snapshot: {url:?}");
                let reader = self.http.fetch(&url).await?;
                ingest::void::stream_data(&self.db, reader, &vendor, &srcpkg, &package, &version)
                    .await?;

                self.db
                    .insert_package(&db::Package {
                        vendor,
                        package,
                        version,
                    })
                    .await?;
            }
        }

        Ok(())
    }
}

pub async fn run(args: &args::Worker) -> Result<()> {
    let db = db::Client::create().await?;
    let http = utils::http_client(args.socks5.as_deref())?;

    let worker = Worker {
        db: Arc::new(db),
        http,
        git_tmp: args.git_tmp.to_string(),
    };

    loop {
        if let Some(task) = worker.db.get_random_task().await? {
            info!("task={task:?}");
            if let Err(err) = worker.do_task(&task).await {
                error!("Failed to process task ({:?}: {:#}", task.key, err);
                worker
                    .db
                    .bump_task_error_counter(&task, &format!("{err:#}"))
                    .await?;
            } else {
                worker.db.delete_task(&task).await?;
            }
        } else {
            time::sleep(Duration::from_secs(60)).await;
        }
        time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_gtk2_extra() {
        let repo = normalize_archlinux_gitlab_names("gtk2+extra");
        assert_eq!(repo, "gtk2-extra");
    }

    #[test]
    fn test_normalize_mysqlplusplus() {
        let repo = normalize_archlinux_gitlab_names("mysql++");
        assert_eq!(repo, "mysqlplusplus");
    }

    #[test]
    fn test_normalize_tree() {
        let repo = normalize_archlinux_gitlab_names("tree");
        assert_eq!(repo, "unix-tree");
    }
}
