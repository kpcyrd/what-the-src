pub mod alias;
pub mod apkbuild;
pub mod apt;
pub mod args;
pub mod chksums;
pub mod compression;
pub mod db;
pub mod errors;
pub mod git;
pub mod ingest;
pub mod pkgbuild;
pub mod reindex;
pub mod sbom;
pub mod sync;
pub mod utils;
pub mod web;
pub mod worker;

use crate::args::{Args, Plumbing, SubCommand};
use crate::errors::*;
use clap::Parser;
use env_logger::Env;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let log_level = match args.verbose {
        0 => "what_the_src=info",
        1 => "info,what_the_src=debug",
        2 => "debug",
        3 => "debug,what_the_src=trace",
        _ => "trace",
    };
    env_logger::Builder::from_env(Env::default().default_filter_or(log_level)).init();

    dotenvy::dotenv().ok();

    match args.subcommand {
        SubCommand::Web(args) => web::run(&args).await,
        SubCommand::Worker(args) => worker::run(&args).await,
        SubCommand::Plumbing(Plumbing::IngestTar(args)) => ingest::tar::run(&args).await,
        SubCommand::Plumbing(Plumbing::IngestPacmanSnapshot(args)) => {
            ingest::pacman::run(&args).await
        }
        SubCommand::Plumbing(Plumbing::IngestRpm(args)) => ingest::rpm::run(&args).await,
        SubCommand::Plumbing(Plumbing::IngestSbom(args)) => sbom::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncAlpine(args)) => sync::alpine::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncApt(args)) => sync::apt::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncPacman(args)) => sync::pacman::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncRpm(args)) => sync::rpm::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncGentoo(args)) => sync::gentoo::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncHomebrew(args)) => sync::homebrew::run(&args).await,
        SubCommand::Plumbing(Plumbing::AddRef(args)) => alias::run(&args).await,
        SubCommand::Plumbing(Plumbing::GitArchive(args)) => git::run(&args).await,
        SubCommand::Plumbing(Plumbing::Reindex(args)) => reindex::run(&args).await,
    }
}
