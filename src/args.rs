use clap::{ArgAction, Parser, Subcommand};
use std::net::SocketAddr;

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
    SyncPacman(SyncPacman),
    AddRef(AddRef),
}

/// Ingest a .tar into the archive
#[derive(Debug, Parser)]
pub struct Ingest {
    #[arg(short, long)]
    pub compression: Option<String>,
}

/// Start an import of a software vendor (apt)
#[derive(Debug, Parser)]
pub struct SyncApt {
    #[arg(long)]
    pub vendor: String,
    #[arg(long)]
    pub fetch: bool,
    pub file: String,
}

/// Start an import of a software vendor (pacman)
#[derive(Debug, Parser)]
pub struct SyncPacman {
    #[arg(long)]
    pub vendor: String,
    #[arg(long)]
    pub fetch: bool,
    /// The repositories to ingest e.g. `core-x86_64` or `extra-x86_64`
    #[arg(short, long = "repo", required = true)]
    pub repos: Vec<String>,
    pub file: String,
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
