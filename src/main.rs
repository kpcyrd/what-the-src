pub mod alias;
pub mod apt;
pub mod args;
pub mod chksums;
pub mod compression;
pub mod daemon;
pub mod db;
pub mod errors;
pub mod ingest;
pub mod sync;
pub mod worker;

use crate::args::{Args, Plumbing, SubCommand};
use crate::errors::*;
use clap::Parser;
use env_logger::Env;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let log_level = match args.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(Env::default().default_filter_or(log_level)).init();

    dotenvy::dotenv().ok();

    match args.subcommand {
        SubCommand::Daemon(args) => daemon::run(&args).await,
        SubCommand::Worker(args) => worker::run(&args).await,
        SubCommand::Plumbing(Plumbing::Ingest(args)) => ingest::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncApt(args)) => sync::apt::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncPacman(args)) => sync::pacman::run(&args).await,
        SubCommand::Plumbing(Plumbing::AddRef(args)) => alias::run(&args).await,
    }
}
