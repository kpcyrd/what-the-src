use crate::args;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::utils;
use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
use serde::Deserialize;
use std::collections::BTreeMap;
use tokio::io::{self, AsyncReadExt};
use tokio_tar::{Archive, EntryType};

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub package: Package,
    #[serde(default)]
    pub sources: BTreeMap<String, Source>,
}

impl Manifest {
    pub fn parse(toml: &str) -> Result<Self> {
        let toml = toml::from_str(toml)?;
        Ok(toml)
    }

    fn optional_value(&self, key: &str, value: Option<&str>, source: &Source) -> Result<String> {
        let Some(value) = value else {
            return Err(Error::StagexUndefinedVariable(key.to_string()));
        };
        self.interpolate(value, source)
    }

    fn version(&self, source: &Source) -> Result<String> {
        self.optional_value("version", self.package.version.as_deref(), source)
    }

    pub fn interpolate(&self, text: &str, source: &Source) -> Result<String> {
        let mut current = text;
        let mut out = String::new();
        loop {
            let Some((before, after)) = current.split_once('{') else {
                out.push_str(current);
                break;
            };
            out.push_str(before);
            let Some((key, after)) = after.split_once('}') else {
                return Err(Error::StagexUnclosedInterpolate(text.to_string()));
            };

            let value = match key {
                "version" => self.version(source)?,
                "format" => self.optional_value(key, source.format.as_deref(), source)?,
                "file" => self.optional_value(key, source.file.as_deref(), source)?,
                "version_dash" => {
                    let version = self.version(source)?;
                    version.replace('.', "-")
                }
                "version_under" => {
                    let version = self.version(source)?;
                    version.replace('.', "_")
                }
                "version_major" => {
                    let version = self.version(source)?;
                    version.split('.').next().unwrap_or("").to_string()
                }
                "version_major_minor" => {
                    let version = self.version(source)?;
                    let parts: Vec<&str> = version.split('.').collect();
                    if parts.len() >= 2 {
                        format!("{}.{}", parts[0], parts[1])
                    } else {
                        version.to_string()
                    }
                }
                "version_strip_suffix" => {
                    let version = self.version(source)?;
                    version
                        .rsplit_once('-')
                        .map(|(x, _)| x)
                        .unwrap_or(&version)
                        .to_string()
                }
                _ => return Err(Error::StagexUndefinedVariable(key.to_string())),
            };
            out.push_str(&value);

            current = after;
        }
        Ok(out)
    }

    pub fn resolve_refs(&self, vendor: &str) -> Result<Vec<db::Ref>> {
        let Some(version) = &self.package.version else {
            return Ok(Vec::new());
        };
        self.sources
            .values()
            .map(|source| {
                let mirror = source
                    .mirrors
                    .first()
                    .ok_or_else(|| Error::StagexMissingMirrors(source.clone()))?;

                Ok(db::Ref {
                    chksum: format!("sha256:{}", source.hash),
                    vendor: vendor.to_string(),
                    package: self.package.name.to_string(),
                    version: version.to_string(),
                    filename: Some(self.interpolate(mirror, source)?),
                })
            })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Source {
    pub hash: String,
    pub format: Option<String>,
    pub file: Option<String>,
    pub mirrors: Vec<String>,
}

pub async fn run(args: &args::SyncStagex) -> Result<()> {
    let db = db::Client::create().await?;
    let vendor = &args.vendor;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let reader = io::BufReader::new(reader);
    let reader = GzipDecoder::new(reader);
    let mut tar = Archive::new(reader);

    let mut entries = tar.entries()?;
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        let header = entry.header();
        if header.entry_type() != EntryType::Regular {
            continue;
        }

        let path = entry.path()?;
        let Some(filename) = path.file_name() else {
            continue;
        };
        if filename.to_str() != Some("package.toml") {
            continue;
        }

        info!("Found stagex package.toml: {path:?}");

        let mut buf = String::new();
        entry.read_to_string(&mut buf).await?;

        let manifest = Manifest::parse(&buf)?;
        debug!("Parsed stagex package.toml: {manifest:?}");

        let refs = manifest.resolve_refs(vendor)?;
        for obj in &refs {
            let chksum = &obj.chksum;
            let Some(url) = &obj.filename else {
                continue;
            };
            debug!("chksum={chksum:?} url={url:?}");

            if !utils::is_possible_tar_artifact(url) {
                continue;
            }

            debug!("insert: {obj:?}");
            db.insert_ref(obj).await?;

            if db.resolve_artifact(chksum).await?.is_none() {
                info!("Adding download task: url={url:?}");
                db.insert_task(&Task::new(
                    format!("fetch:{url}"),
                    &TaskData::FetchTar {
                        url: url.to_string(),
                        success_ref: None,
                    },
                )?)
                .await?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_binutils() {
        let data = r#"
[package]
name = "binutils"
version = "2.43.1"
description = "TODO"

[sources.binutils]
hash = "13f74202a3c4c51118b797a39ea4200d3f6cfbe224da6d1d95bb938480132dfd"
format = "tar.xz"
file = "binutils-{version}.{format}"
mirrors = [ "https://ftp.gnu.org/gnu/binutils/{file}",]
"#;
        let manifest = Manifest::parse(data).unwrap();
        let refs = manifest.resolve_refs("stagex").unwrap();
        assert_eq!(
            refs,
            &[db::Ref {
                chksum: "sha256:13f74202a3c4c51118b797a39ea4200d3f6cfbe224da6d1d95bb938480132dfd"
                    .to_string(),
                vendor: "stagex".to_string(),
                package: "binutils".to_string(),
                version: "2.43.1".to_string(),
                filename: Some(
                    "https://ftp.gnu.org/gnu/binutils/binutils-2.43.1.tar.xz".to_string()
                )
            }]
        );
    }

    #[test]
    fn test_parse_icu() {
        let data = r#"
[package]
name = "icu"
version = "74.2"
description = "TODO"

[sources.icu]
hash = "68db082212a96d6f53e35d60f47d38b962e9f9d207a74cfac78029ae8ff5e08c"
mirrors = ["https://github.com/unicode-org/icu/releases/download/release-{version_dash}/icu4c-{version_under}-src.tgz",]

[sources.icudata]
hash = "c28c3ca5f4ba3384781797138a294ca360988d4322674ad4d51e52f5d9b0a2b6"
mirrors = ["https://github.com/unicode-org/icu/releases/download/release-{version_dash}/icu4c-{version_under}-data.zip",]

[sources.icudatab]
hash = "42a12ebfb1a82f80bb0005d9b6e018382ccaa2462f0d086a8c69ae736fdded3e"
mirrors = ["https://github.com/unicode-org/icu/releases/download/release-{version_dash}/icu4c-{version_under}-data-bin-b.zip",]

[sources.icudatal]
hash = "2acdb1b982228040963d183b2dd9d321252c613e0f4db213d4bbc10417cde569"
mirrors = ["https://github.com/unicode-org/icu/releases/download/release-{version_dash}/icu4c-{version_under}-data-bin-l.zip",]
"#;
        let manifest = Manifest::parse(data).unwrap();
        let refs = manifest.resolve_refs("stagex").unwrap();
        assert_eq!(
            refs, &[
                db::Ref {
                    chksum: "sha256:68db082212a96d6f53e35d60f47d38b962e9f9d207a74cfac78029ae8ff5e08c".to_string(),
                    vendor: "stagex".to_string(),
                    package: "icu".to_string(),
                    version: "74.2".to_string(),
                    filename: Some("https://github.com/unicode-org/icu/releases/download/release-74-2/icu4c-74_2-src.tgz".to_string()),
                },
                db::Ref {
                    chksum: "sha256:c28c3ca5f4ba3384781797138a294ca360988d4322674ad4d51e52f5d9b0a2b6".to_string(),
                    vendor: "stagex".to_string(),
                    package: "icu".to_string(),
                    version: "74.2".to_string(),
                    filename: Some("https://github.com/unicode-org/icu/releases/download/release-74-2/icu4c-74_2-data.zip".to_string()),
                },
                db::Ref {
                    chksum: "sha256:42a12ebfb1a82f80bb0005d9b6e018382ccaa2462f0d086a8c69ae736fdded3e".to_string(),
                    vendor: "stagex".to_string(),
                    package: "icu".to_string(),
                    version: "74.2".to_string(),
                    filename: Some("https://github.com/unicode-org/icu/releases/download/release-74-2/icu4c-74_2-data-bin-b.zip".to_string()),
                },
                db::Ref {
                    chksum: "sha256:2acdb1b982228040963d183b2dd9d321252c613e0f4db213d4bbc10417cde569".to_string(),
                    vendor: "stagex".to_string(),
                    package: "icu".to_string(),
                    version: "74.2".to_string(),
                    filename: Some("https://github.com/unicode-org/icu/releases/download/release-74-2/icu4c-74_2-data-bin-l.zip".to_string()),
                },


            ]
        );
    }

    #[test]
    fn test_parse_zip() {
        let data = r#"
[package]
name = "zip"
version = "30"
description = "TODO"

[sources.zip]
hash = "f0e8bb1f9b7eb0b01285495a2699df3a4b766784c1765a8f1aeedf63c0806369"
format = "tar.gz"
file = "zip-{version}.{format}"
mirrors = [ "https://fossies.org/linux/misc/zip{version}.{format}",]
"#;
        let manifest = Manifest::parse(data).unwrap();
        let refs = manifest.resolve_refs("stagex").unwrap();
        assert_eq!(
            refs,
            &[db::Ref {
                chksum: "sha256:f0e8bb1f9b7eb0b01285495a2699df3a4b766784c1765a8f1aeedf63c0806369"
                    .to_string(),
                vendor: "stagex".to_string(),
                package: "zip".to_string(),
                version: "30".to_string(),
                filename: Some("https://fossies.org/linux/misc/zip30.tar.gz".to_string()),
            }]
        );
    }
}
