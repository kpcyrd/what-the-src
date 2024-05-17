use crate::args;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::utils;
use async_compression::tokio::bufread::GzipDecoder;
use data_encoding::BASE64;
use serde::Deserialize;
use tokio::io;
use tokio::io::AsyncReadExt;

#[derive(Debug, PartialEq, Deserialize)]
pub struct Package {
    name: String,
    version: String,
    #[serde(default)]
    source: Vec<serde_json::Value>,
}

#[derive(Debug, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Source {
    Url(UrlSource),
    Git(GitSource),
    Hg(HgSource),
    Svn(SvnSource),
}

impl Source {
    fn integrity(&self) -> &Integrity {
        match self {
            Source::Url(source) => &source.integrity,
            Source::Git(source) => &source.integrity,
            Source::Hg(source) => &source.integrity,
            Source::Svn(source) => &source.integrity,
        }
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Integrity {
    #[serde(rename = "integrity")]
    pub hash: String,
    #[serde(rename = "outputHashAlgo")]
    pub output_hash_algo: String,
    #[serde(rename = "outputHashMode")]
    pub output_hash_mode: String,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct UrlSource {
    pub urls: Vec<String>,
    #[serde(flatten)]
    pub integrity: Integrity,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct GitSource {
    pub git_url: String,
    #[serde(flatten)]
    pub integrity: Integrity,
    pub git_ref: String,
    #[serde(default)]
    pub submodule: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct HgSource {
    #[serde(flatten)]
    pub integrity: Integrity,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct SvnSource {
    #[serde(flatten)]
    pub integrity: Integrity,
}

pub async fn run(args: &args::SyncGuix) -> Result<()> {
    let db = db::Client::create().await?;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let reader = io::BufReader::new(reader);
    let mut reader = GzipDecoder::new(reader);

    let mut buf = String::new();
    reader.read_to_string(&mut buf).await?;

    let packages = serde_json::from_str::<Vec<Package>>(&buf)?;
    for package in packages {
        debug!("package={:?} version={:?}", package.name, package.version);
        for source in package.source {
            let Ok(source) = serde_json::from_value::<Source>(source) else {
                continue;
            };

            let integrity = source.integrity();
            if integrity.output_hash_mode != "flat" {
                continue;
            }

            let Some(hash) = integrity.hash.strip_prefix("sha256-") else {
                continue;
            };
            let digest = hex::encode(BASE64.decode(hash.as_bytes())?);
            let chksum = format!("sha256:{digest}");

            if let Source::Url(source) = &source {
                let Some(url) = source.urls.first() else {
                    continue;
                };
                debug!("chksum={chksum:?} url={url:?}");

                if !utils::is_possible_tar_artifact(url) {
                    continue;
                }

                let obj = db::Ref {
                    chksum: chksum.to_string(),
                    vendor: args.vendor.to_string(),
                    package: package.name.to_string(),
                    version: package.version.to_string(),
                    filename: Some(url.to_string()),
                };
                info!("insert: {obj:?}");
                db.insert_ref(&obj).await?;

                if db.resolve_artifact(&chksum).await?.is_none() {
                    info!("Adding download task: url={url:?}");
                    db.insert_task(&Task::new(
                        format!("fetch:{url}"),
                        &TaskData::FetchTar {
                            url: url.to_string(),
                            compression: None,
                        },
                    )?)
                    .await?;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_git_source() {
        let data = r#"
{
  "name": "zig",
  "version": "0.9.1",
  "variable_name": "zig-0.9",
  "source": [
    {
      "type": "git",
      "git_url": "https://github.com/ziglang/zig.git",
      "integrity": "sha256-x2c4c9RSrNWGqEngio4ArW7dJjW0gg+8nqBwPcR721k=",
      "outputHashAlgo": "sha256",
      "outputHashMode": "recursive",
      "git_ref": "0.9.1"
    }
  ],
  "synopsis": "General purpose programming language and toolchain",
  "homepage": "https://github.com/ziglang/zig",
  "location": "gnu/packages/zig.scm:36"
}
"#;
        let mut pkg = serde_json::from_str::<Package>(data).unwrap();
        let source = pkg
            .source
            .drain(..)
            .flat_map(serde_json::from_value)
            .collect::<Vec<Source>>();
        assert_eq!(
            pkg,
            Package {
                name: "zig".to_string(),
                version: "0.9.1".to_string(),
                source: vec![],
            }
        );
        assert_eq!(
            source,
            vec![Source::Git(GitSource {
                git_url: "https://github.com/ziglang/zig.git".to_string(),
                integrity: Integrity {
                    hash: "sha256-x2c4c9RSrNWGqEngio4ArW7dJjW0gg+8nqBwPcR721k=".to_string(),
                    output_hash_algo: "sha256".to_string(),
                    output_hash_mode: "recursive".to_string(),
                },
                git_ref: "0.9.1".to_string(),
                submodule: false,
            })]
        );
    }

    #[test]
    fn test_parse_url_source() {
        let data = r#"
{
  "name": "xdialog",
  "version": "2.3.1",
  "variable_name": "xdialog",
  "source": [
    {
      "type": "url",
      "urls": [
        "http://xdialog.free.fr/Xdialog-2.3.1.tar.bz2",
        "https://bordeaux.guix.gnu.org/file/Xdialog-2.3.1.tar.bz2/sha256/16jqparb33lfq4cvd9l3jgd7fq86fk9gv2ixc8vgqibid6cnhi0x",
        "https://ci.guix.gnu.org/file/Xdialog-2.3.1.tar.bz2/sha256/16jqparb33lfq4cvd9l3jgd7fq86fk9gv2ixc8vgqibid6cnhi0x",
        "https://tarballs.nixos.org/sha256/16jqparb33lfq4cvd9l3jgd7fq86fk9gv2ixc8vgqibid6cnhi0x"
      ],
      "integrity": "sha256-HURomWlxRfw2Yj2K/dJ0BmF32pODprYZwY6OsbK6WJo=",
      "outputHashAlgo": "sha256",
      "outputHashMode": "flat"
    }
  ],
  "synopsis": "Convert a terminal program into a program with an X interface",
  "homepage": "http://xdialog.free.fr/",
  "location": "gnu/packages/xorg.scm:6640"
}
"#;
        let mut pkg = serde_json::from_str::<Package>(data).unwrap();
        let source = pkg
            .source
            .drain(..)
            .flat_map(serde_json::from_value)
            .collect::<Vec<Source>>();
        assert_eq!(
            pkg,
            Package {
                name: "xdialog".to_string(),
                version: "2.3.1".to_string(),
                source: vec![],
            }
        );
        assert_eq!(source, vec![
            Source::Url(UrlSource {
                urls: vec![
                    "http://xdialog.free.fr/Xdialog-2.3.1.tar.bz2".to_string(),
                    "https://bordeaux.guix.gnu.org/file/Xdialog-2.3.1.tar.bz2/sha256/16jqparb33lfq4cvd9l3jgd7fq86fk9gv2ixc8vgqibid6cnhi0x".to_string(),
                    "https://ci.guix.gnu.org/file/Xdialog-2.3.1.tar.bz2/sha256/16jqparb33lfq4cvd9l3jgd7fq86fk9gv2ixc8vgqibid6cnhi0x".to_string(),
                    "https://tarballs.nixos.org/sha256/16jqparb33lfq4cvd9l3jgd7fq86fk9gv2ixc8vgqibid6cnhi0x".to_string(),
                ],
                integrity: Integrity {
                    hash: "sha256-HURomWlxRfw2Yj2K/dJ0BmF32pODprYZwY6OsbK6WJo=".to_string(),
                    output_hash_algo: "sha256".to_string(),
                    output_hash_mode: "flat".to_string(),
                },
            })
        ]);
    }
}
