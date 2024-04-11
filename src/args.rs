use clap::{ArgAction, Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    /// Increase logging output (can be used multiple times)
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    #[command(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Subcommand)]
pub enum SubCommand {
    Daemon(Daemon),
    Worker(Worker),
    #[command(subcommand)]
    Plumbing(Plumbing),
}

/// Run the web server daemon
#[derive(Debug, Parser)]
pub struct Daemon {
    #[arg(short = 'B', long, env)]
    pub bind_addr: SocketAddr,
}

/// Run worker for background jobs
#[derive(Debug, Parser)]
pub struct Worker {}

#[derive(Debug, Subcommand)]
pub enum Plumbing {
    Ingest(Ingest),
    SyncApt(SyncApt),
    Decompress(Decompress),
    AddRef(AddRef),
}

/// Ingest a .tar into the archive
#[derive(Debug, Parser)]
pub struct Ingest {}

/// Start an import of a software vendor
#[derive(Debug, Parser)]
pub struct SyncApt {
    #[arg(long)]
    pub vendor: String,
    pub file: PathBuf,
}

/// Ingest a .tar into the archive
#[derive(Debug, Parser)]
pub struct Decompress {
    #[arg(short, long)]
    pub compression: Option<String>,
}

/// This command should merge into Ingest eventually
#[derive(Debug, Parser)]
pub struct AddRef {
    #[arg(long)]
    pub vendor: String,
    #[arg(long)]
    pub package: String,
    #[arg(long)]
    pub version: String,
    #[arg(long)]
    pub filename: Option<String>,
}
