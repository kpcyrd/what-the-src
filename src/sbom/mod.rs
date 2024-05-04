pub mod cargo;
pub mod composer;
pub mod npm;
pub mod yarn;

use crate::args;
use crate::db;
use crate::errors::*;
use tokio::fs;

#[derive(Debug, PartialEq)]
pub enum Sbom {
    Cargo(cargo::CargoLock),
    Composer(composer::ComposerLock),
    Npm(npm::PackageLockJson),
    Yarn(yarn::YarnLock),
}

impl Sbom {
    pub fn new(strain: &str, data: String) -> Result<Sbom> {
        match strain {
            cargo::STRAIN => Ok(Sbom::Cargo(cargo::CargoLock { data })),
            composer::STRAIN => Ok(Sbom::Composer(composer::ComposerLock { data })),
            npm::STRAIN => Ok(Sbom::Npm(npm::PackageLockJson { data })),
            yarn::STRAIN => Ok(Sbom::Yarn(yarn::YarnLock { data })),
            _ => Err(Error::UnknownSbomStrain(strain.to_string())),
        }
    }

    pub fn strain(&self) -> &'static str {
        match self {
            Sbom::Cargo(_) => cargo::STRAIN,
            Sbom::Composer(_) => composer::STRAIN,
            Sbom::Npm(_) => npm::STRAIN,
            Sbom::Yarn(_) => yarn::STRAIN,
        }
    }

    pub fn data(&self) -> &str {
        match self {
            Sbom::Cargo(sbom) => &sbom.data,
            Sbom::Composer(sbom) => &sbom.data,
            Sbom::Npm(sbom) => &sbom.data,
            Sbom::Yarn(sbom) => &sbom.data,
        }
    }
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
