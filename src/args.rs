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
    Ingest(Ingest),
    Alias(Alias),
}

/// Run the web server daemon
#[derive(Debug, Parser)]
pub struct Daemon {
    #[arg(short = 'B', long, env)]
    pub bind_addr: SocketAddr,
}

/// Ingest a .tar into the archive
#[derive(Debug, Parser)]
pub struct Ingest {}

/// This command should merge into Ingest eventually
#[derive(Debug, Parser)]
pub struct Alias {
    #[arg(short, long)]
    pub compression: Option<String>,
    #[arg(long)]
    pub vendor: String,
    #[arg(long)]
    pub package: String,
    #[arg(long)]
    pub version: String,
    #[arg(long)]
    pub filename: Option<String>,
}
