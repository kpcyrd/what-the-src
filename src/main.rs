pub mod alias;
pub mod apt;
pub mod args;
pub mod chksums;
pub mod daemon;
pub mod db;
pub mod errors;
pub mod import;
pub mod ingest;
pub mod worker;

use crate::args::{Args, SubCommand};
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
        SubCommand::Ingest(args) => ingest::run(&args).await,
        SubCommand::Import(args) => import::run(&args).await,
        SubCommand::Worker(args) => worker::run(&args).await,
        SubCommand::Alias(args) => alias::run(&args).await,
    }
}
