pub mod cargo;
pub mod composer;
pub mod go;
pub mod npm;
pub mod yarn;

use crate::args;
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

    pub fn to_packages(&self) -> Result<Vec<Package>> {
        match self {
            Sbom::Cargo(sbom) => {
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

#[derive(Debug, PartialEq, Serialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub checksum: Option<String>,
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

pub async fn run(args: &args::IngestSbom) -> Result<()> {
    let db = db::Client::create().await?;

    let data = fs::read_to_string(&args.file).await?;
    let sbom = Sbom::new(&args.strain, data)?;

    db.insert_sbom(&sbom).await?;

    Ok(())
}