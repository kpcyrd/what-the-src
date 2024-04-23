use crate::apkbuild;
use crate::args;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::git;
use crate::ingest;
use futures::TryStreamExt;
use tokio::io;
use tokio::time::{self, Duration};
use tokio_util::io::StreamReader;

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
    db: db::Client,
    http: reqwest::Client,
    git_tmp: String,
}

impl Worker {
    pub async fn do_task(&self, task: &Task) -> Result<()> {
        let data = task.data()?;

        match data {
            TaskData::FetchTar { url } => {
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
                let req = self.http.get(&url).send().await?.error_for_status()?;
                let body = req.bytes().await?;

                // TODO: do this stuff on the fly
                let compression = if url.ends_with(".gz") || url.ends_with(".tgz") {
                    Some("gz")
                } else if url.ends_with(".xz") {
                    Some("xz")
                } else if url.ends_with(".bz2") {
                    Some("bz2")
                } else {
                    None
                };

                let (inner_digests, outer_digests, files) =
                    ingest::tar::stream_data(&body[..], compression).await?;

                info!("digests={:?}", inner_digests);
                self.db
                    .insert_artifact(&inner_digests.sha256, &files)
                    .await?;
                self.db
                    .register_chksums_aliases(&inner_digests, &inner_digests.sha256)
                    .await?;
                self.db
                    .register_chksums_aliases(&outer_digests, &inner_digests.sha256)
                    .await?;
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
                let resp = self.http.get(&url).send().await?.error_for_status()?;
                let stream = resp.bytes_stream();
                let reader =
                    StreamReader::new(stream.map_err(|e| io::Error::new(io::ErrorKind::Other, e)));
                let (refs, tasks) =
                    ingest::pacman::stream_data(reader, &vendor, &package, &version, false).await?;

                for task in tasks {
                    self.db.insert_task(&task).await?;
                }

                for r in refs {
                    info!("insert: {r:?}");
                    self.db.insert_ref(&r).await?;
                }

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
                let stream = self
                    .http
                    .get(&url)
                    .send()
                    .await?
                    .error_for_status()?
                    .bytes_stream();

                let reader =
                    StreamReader::new(stream.map_err(|e| io::Error::new(io::ErrorKind::Other, e)));

                let items = ingest::rpm::stream_data(
                    reader,
                    vendor.to_string(),
                    package.to_string(),
                    version.to_string(),
                )
                .await?;

                for (r, inner_digests, outer_digests, files) in items {
                    info!("insert artifact: {:?}", inner_digests.sha256);
                    self.db
                        .insert_artifact(&inner_digests.sha256, &files)
                        .await?;
                    self.db
                        .register_chksums_aliases(&inner_digests, &inner_digests.sha256)
                        .await?;
                    self.db
                        .register_chksums_aliases(&outer_digests, &inner_digests.sha256)
                        .await?;

                    info!("insert ref: {r:?}");
                    self.db.insert_ref(&r).await?;
                }

                self.db
                    .insert_package(&db::Package {
                        vendor,
                        package,
                        version,
                    })
                    .await?;
            }
            TaskData::AlpineGitApkbuild {
                vendor,
                repo,
                origin,
                version,
                commit,
            } => {
                let url = format!("https://gitlab.alpinelinux.org/alpine/aports/-/raw/{commit}/{repo}/{origin}/APKBUILD");
                info!("Fetching APKBUILD: {url:?}");
                let req = self.http.get(&url).send().await?.error_for_status()?;
                let body = req.text().await?;

                info!("Parsing APKBUILD");
                let apkbuild = apkbuild::parse(&body)?;

                for i in 0..apkbuild.source.len() {
                    let Some(url) = apkbuild.source.get(i) else {
                        continue;
                    };
                    let Some(sha512) = apkbuild.sha512sums.get(i) else {
                        continue;
                    };

                    if !url.starts_with("https://") && !url.starts_with("http://") {
                        continue;
                    }

                    if !url.contains(".tar") && !url.ends_with(".crate") && !url.ends_with(".tgz") {
                        continue;
                    }

                    self.db
                        .insert_task(&Task::new(
                            format!("fetch:{url}"),
                            &TaskData::FetchTar {
                                url: url.to_string(),
                            },
                        )?)
                        .await?;

                    let r = db::Ref {
                        chksum: format!("sha512:{sha512}"),
                        vendor: vendor.to_string(),
                        package: origin.to_string(),
                        version: version.to_string(),
                        filename: Some(url.to_string()),
                    };
                    info!("insert: {r:?}");
                    self.db.insert_ref(&r).await?;
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
                let git = url.parse::<git::GitUrl>()?;

                let (chksums, files) = git::take_snapshot(&git, &self.git_tmp).await?;
                info!("digests={chksums:?}");

                self.db.insert_artifact(&chksums.sha256, &files).await?;
                self.db
                    .register_chksums_aliases(&chksums, &chksums.sha256)
                    .await?;
            }
        }

        Ok(())
    }
}

pub async fn run(args: &args::Worker) -> Result<()> {
    let db = db::Client::create().await?;

    let mut http = reqwest::ClientBuilder::new();
    if let Some(socks5) = &args.socks5 {
        http = http.proxy(reqwest::Proxy::all(socks5)?);
    }
    let http = http.build()?;

    let worker = Worker {
        db,
        http,
        git_tmp: args.git_tmp.to_string(),
    };

    loop {
        if let Some(task) = worker.db.get_random_task().await? {
            info!("task={task:?}");
            if let Err(err) = worker.do_task(&task).await {
                error!("Failed to process task: {err:#}");
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
