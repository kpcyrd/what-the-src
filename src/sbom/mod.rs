pub mod cargo;

use crate::args;
use crate::db;
use crate::errors::*;
use tokio::fs;

#[derive(Debug, PartialEq)]
pub enum Sbom {
    Cargo(cargo::CargoLock),
}

impl Sbom {
    pub fn new(strain: &str, data: String) -> Result<Sbom> {
        match strain {
            cargo::STRAIN => Ok(Sbom::Cargo(cargo::CargoLock { data })),
            _ => Err(Error::UnknownSbomStrain(strain.to_string())),
        }
    }

    pub fn strain(&self) -> &'static str {
        match self {
            Sbom::Cargo(_) => cargo::STRAIN,
        }
    }

    pub fn data(&self) -> &str {
        match self {
            Sbom::Cargo(sbom) => &sbom.data,
        }
    }
}

pub async fn run(args: &args::IngestSbom) -> Result<()> {
    let db = db::Client::create().await?;

    let data = fs::read_to_string(&args.file).await?;
    let sbom = Sbom::new(&args.strain, data)?;

    db.insert_sbom(&sbom).await?;

    Ok(())
}
