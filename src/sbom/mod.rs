pub mod cargo;
pub mod composer;
pub mod go;
pub mod npm;
pub mod yarn;

use crate::args;
use crate::chksums;
use crate::db;
use crate::errors::*;
use serde::Serialize;
use tokio::fs;

#[derive(Debug, PartialEq)]
pub enum Sbom {
    Cargo(cargo::CargoLock),
    Composer(composer::ComposerLock),
    Go(go::GoSum),
    Npm(npm::PackageLockJson),
    Yarn(yarn::YarnLock),
}

impl TryFrom<&db::Sbom> for Sbom {
    type Error = Error;

    fn try_from(sbom: &db::Sbom) -> Result<Self> {
        Sbom::new(&sbom.strain, sbom.data.clone())
    }
}

impl Sbom {
    pub fn new(strain: &str, data: String) -> Result<Sbom> {
        match strain {
            cargo::STRAIN => Ok(Sbom::Cargo(cargo::CargoLock { data })),
            composer::STRAIN => Ok(Sbom::Composer(composer::ComposerLock { data })),
            go::STRAIN => Ok(Sbom::Go(go::GoSum { data })),
            npm::STRAIN => Ok(Sbom::Npm(npm::PackageLockJson { data })),
            yarn::STRAIN => Ok(Sbom::Yarn(yarn::YarnLock { data })),
            _ => Err(Error::UnknownSbomStrain(strain.to_string())),
        }
    }

    pub fn strain(&self) -> &'static str {
        match self {
            Sbom::Cargo(_) => cargo::STRAIN,
            Sbom::Composer(_) => composer::STRAIN,
            Sbom::Go(_) => go::STRAIN,
            Sbom::Npm(_) => npm::STRAIN,
            Sbom::Yarn(_) => yarn::STRAIN,
        }
    }

    pub fn data(&self) -> &str {
        match self {
            Sbom::Cargo(sbom) => &sbom.data,
            Sbom::Composer(sbom) => &sbom.data,
            Sbom::Go(sbom) => &sbom.data,
            Sbom::Npm(sbom) => &sbom.data,
            Sbom::Yarn(sbom) => &sbom.data,
        }
    }

    pub async fn ingest<'a>(&'a self, db: &db::Client) -> Result<HashedSbom<'a>> {
        let hashed = HashedSbom::new(self);
        hashed.ingest(db).await?;
        Ok(hashed)
    }

    pub fn to_packages(&self) -> Result<Vec<Package>> {
        match self {
            Sbom::Cargo(sbom) => {
                let sbom = sbom.parse()?;
                sbom.collect::<Result<Vec<_>>>()
            }
            Sbom::Composer(sbom) => {
                let sbom = sbom.parse()?;
                sbom.collect::<Result<Vec<_>>>()
            }
            Sbom::Yarn(sbom) => {
                let sbom = sbom.parse()?;
                Ok(sbom.collect::<Vec<_>>())
            }
            _ => Ok(vec![]),
        }
    }
}

pub struct HashedSbom<'a> {
    pub sbom: &'a Sbom,
    pub chksum: String,
}

impl<'a> HashedSbom<'a> {
    pub fn new(sbom: &'a Sbom) -> Self {
        let chksum = chksums::sha256(sbom.data().as_bytes());
        Self { sbom, chksum }
    }

    pub async fn ingest(&'a self, db: &db::Client) -> Result<&'a Self> {
        let strain = self.sbom.strain();
        let chksum = &self.chksum;
        debug!("Checking for existing sbom {strain:?}: {chksum:?}");

        if db.get_sbom_with_strain(chksum, strain).await?.is_none() {
            db.insert_sbom(self).await?;
            info!("Inserted new sbom {strain:?}: {chksum:?}");
            db.insert_task(&db::Task::new(
                format!("sbom:{strain}:{chksum}"),
                &db::TaskData::IndexSbom {
                    strain: Some(strain.to_string()),
                    chksum: chksum.to_string(),
                },
            )?)
            .await?;
        }

        Ok(self)
    }

    pub fn into_ref(self, path: String) -> Ref {
        Ref {
            strain: self.sbom.strain(),
            chksum: self.chksum,
            path,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub url: Option<String>,
    pub checksum: Option<String>,
    pub official_registry: bool,
}

#[derive(Debug, PartialEq)]
pub struct Ref {
    pub strain: &'static str,
    pub chksum: String,
    pub path: String,
}

pub fn detect_from_filename(filename: Option<&str>) -> Option<&'static str> {
    match filename {
        Some("Cargo.lock") => Some(cargo::STRAIN),
        Some("package-lock.json") => Some(npm::STRAIN),
        Some("yarn.lock") => Some(yarn::STRAIN),
        Some("composer.lock") => Some(composer::STRAIN),
        Some("go.sum") => Some(go::STRAIN),
        _ => None,
    }
}

pub async fn index(db: &db::Client, sbom: &Sbom) -> Result<()> {
    match sbom.strain() {
        cargo::STRAIN => {
            for pkg in sbom.to_packages()? {
                let Some(chksum) = pkg.checksum else { continue };

                let Some(url) = pkg.url else {
                    continue;
                };

                let (has_artifact, has_ref) = tokio::join!(
                    db.resolve_artifact(&chksum),
                    db.get_ref(&chksum, cargo::VENDOR, &pkg.name, &pkg.version),
                );
                if has_artifact?.is_some() && has_ref?.is_some() {
                    debug!(
                        "Skipping because known cargo reference (package={:?} version={:?} chksum={:?})",
                        pkg.name, pkg.version, chksum
                    );
                    continue;
                }

                info!("Adding download task url={url:?}");
                db.insert_task(&db::Task::new(
                    format!("fetch:{url}"),
                    &db::TaskData::FetchTar {
                        url,
                        success_ref: Some(db::DownloadRef {
                            vendor: cargo::VENDOR.to_string(),
                            package: pkg.name.to_string(),
                            version: pkg.version.to_string(),
                        }),
                    },
                )?)
                .await?;
            }
        }
        composer::STRAIN => {
            for pkg in sbom.to_packages()? {
                let Some(chksum) = pkg.checksum else {
                    continue;
                };
                let Some(url) = pkg.url else {
                    continue;
                };

                let has_artifact = db.resolve_artifact(&chksum).await?;
                if has_artifact.is_some() {
                    debug!(
                        "Skipping because known composer reference (package={:?} version={:?} chksum={:?})",
                        pkg.name, pkg.version, chksum
                    );
                    continue;
                }

                let Some(commit) = chksum.strip_prefix("git:") else {
                    continue;
                };
                let git_url = format!("git+{url}#commit={commit}");

                info!("Adding git remote: {git_url:?}");
                db.insert_task(&db::Task::new(
                    format!("git-clone:{git_url}"),
                    &db::TaskData::GitSnapshot { url: git_url },
                )?)
                .await?;
            }
        }
        yarn::STRAIN => {
            for pkg in sbom.to_packages()? {
                let Some(url) = pkg.url else {
                    continue;
                };

                let Some(chksum) = pkg.checksum else {
                    info!(
                        "Refusing yarn reference without checksum (package={:?} version={:?})",
                        pkg.name, pkg.version
                    );
                    continue;
                };

                if chksum.starts_with("sha1:") {
                    info!(
                        "Refusing yarn reference with weak checksum (sha1) (package={:?} version={:?} chksum={:?})",
                        pkg.name, pkg.version, chksum
                    );
                    continue;
                }

                let (has_artifact, has_ref) = tokio::join!(
                    db.resolve_artifact(&chksum),
                    db.get_ref(&chksum, yarn::VENDOR, &pkg.name, &pkg.version),
                );
                if has_artifact?.is_some() && has_ref?.is_some() {
                    debug!(
                        "Skipping because known yarn reference (package={:?} version={:?} chksum={:?})",
                        pkg.name, pkg.version, chksum
                    );
                    continue;
                }

                info!("Adding download task url={url:?}");
                db.insert_task(&db::Task::new(
                    format!("fetch:{url}"),
                    &db::TaskData::FetchTar {
                        url,
                        success_ref: Some(db::DownloadRef {
                            vendor: yarn::VENDOR.to_string(),
                            package: pkg.name.to_string(),
                            version: pkg.version.to_string(),
                        }),
                    },
                )?)
                .await?;
            }
        }
        _ => (),
    }
    Ok(())
}

pub async fn run(args: &args::IngestSbom) -> Result<()> {
    let db = db::Client::create().await?;

    let data = fs::read_to_string(&args.file).await?;
    let sbom = Sbom::new(&args.strain, data)?;
    let hashed = HashedSbom::new(&sbom);

    db.insert_sbom(&hashed).await?;
    index(&db, &sbom).await?;

    Ok(())
}
