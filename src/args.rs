use crate::git;
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
    #[command(alias = "daemon")]
    Web(Web),
    Worker(Worker),
    #[command(subcommand)]
    Plumbing(Plumbing),
}

/// Run the web server daemon
#[derive(Debug, Parser)]
pub struct Web {
    #[arg(short = 'B', long, env)]
    pub bind_addr: SocketAddr,
}

/// Run worker for background jobs
#[derive(Debug, Parser)]
pub struct Worker {
    /// Request through a proxy to evade rate limits
    #[arg(long)]
    pub socks5: Option<String>,
    /// Path to use for temporary git clone operations
    #[arg(long, env = "WHATSRC_GIT_TMP")]
    pub git_tmp: String,
}

#[derive(Debug, Subcommand)]
pub enum Plumbing {
    IngestTar(IngestTar),
    IngestPacmanSnapshot(IngestPacmanSnapshot),
    IngestRpm(IngestRpm),
    IngestSbom(IngestSbom),
    SyncAlpine(SyncAlpine),
    SyncApt(SyncApt),
    SyncPacman(SyncPacman),
    SyncRpm(SyncRpm),
    SyncGentoo(SyncGentoo),
    SyncHomebrew(SyncHomebrew),
    AddRef(AddRef),
    GitArchive(GitArchive),
    Reindex(Reindex),
}

/// Ingest a .tar into the archive
#[derive(Debug, Parser)]
pub struct IngestTar {
    #[arg(short, long)]
    pub compression: Option<String>,
    pub file: Option<String>,
}

/// Ingest a pacman git .tar.gz
#[derive(Debug, Parser)]
pub struct IngestPacmanSnapshot {
    #[arg(long)]
    pub vendor: String,
    #[arg(long)]
    pub package: String,
    #[arg(long)]
    pub version: String,
    /// Ignore .SRCINFO even if present
    #[arg(long)]
    pub prefer_pkgbuild: bool,
    #[arg(long)]
    pub fetch: bool,
    pub file: String,
}

/// Ingest a .src.rpm
#[derive(Debug, Parser)]
pub struct IngestRpm {
    #[arg(long)]
    pub vendor: String,
    #[arg(long)]
    pub package: String,
    #[arg(long)]
    pub version: String,
    #[arg(long)]
    pub fetch: bool,
    pub file: String,
}

/// Ingest a dependency lockfile
#[derive(Debug, Parser)]
pub struct IngestSbom {
    #[arg(long)]
    pub strain: String,
    pub file: String,
}

/// Start an import of a software vendor (alpine)
#[derive(Debug, Parser)]
pub struct SyncAlpine {
    #[arg(long)]
    pub vendor: String,
    #[arg(long)]
    pub repo: String,
    #[arg(long)]
    pub fetch: bool,
    pub file: String,
}

/// Start an import of a software vendor (apt)
#[derive(Debug, Parser)]
pub struct SyncApt {
    #[arg(long)]
    pub vendor: String,
    /// The release name to import, e.g. `sid`, `stable` or `stable-security`
    #[arg(long)]
    pub release: String,
    /// The suite name to import, e.g. `main`, `contrib` or `non-free`
    #[arg(long, default_value = "main")]
    pub suite: String,
    pub url: String,
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

/// Start an import of a software vendor (pacman)
#[derive(Debug, Parser)]
pub struct SyncRpm {
    #[arg(long)]
    pub vendor: String,
    pub url: String,
}

/// Start an import of a software vendor (gentoo)
#[derive(Debug, Parser)]
pub struct SyncGentoo {
    #[arg(long)]
    pub vendor: String,
    #[arg(long)]
    pub fetch: bool,
    pub file: String,
}

/// Start an import of a software vendor (homebrew)
#[derive(Debug, Parser)]
pub struct SyncHomebrew {
    #[arg(long)]
    pub vendor: String,
    #[arg(long)]
    pub fetch: bool,
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

/// Create a `git archive` of a git ref
#[derive(Debug, Parser)]
pub struct GitArchive {
    /// The directory to clone into
    #[arg(long)]
    pub tmp: String,
    /// The url to clone from, including tag information
    pub git: git::GitUrl,
}

/// Requeue all known urls
#[derive(Debug, Parser)]
pub struct Reindex {
    /// Only queue urls containing this string
    #[arg(long)]
    pub filter: Option<String>,
    /// Upper limit of tasks to schedule
    #[arg(long)]
    pub limit: Option<usize>,
    /// Only reindex items that haven't been imported the last X days
    #[arg(long)]
    pub age: Option<i64>,
}
