pub mod adapters;
pub mod alias;
pub mod apkbuild;
pub mod apt;
pub mod args;
pub mod chksums;
pub mod compression;
pub mod db;
pub mod errors;
pub mod ingest;
pub mod pkgbuild;
pub mod reindex;
pub mod s3;
pub mod sbom;
pub mod sync;
pub mod utils;
pub mod void_template;
pub mod web;
pub mod worker;
pub mod yocto;

use crate::adapters::tee::{self, TeeStream};
use crate::args::{Args, Plumbing, SubCommand};
use crate::chksums::Hasher;
use crate::errors::*;
use async_tempfile::TempFile;
use chrono::Utc;
use clap::Parser;
use env_logger::Env;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{self, AsyncReadExt, ReadBuf};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let args = Args::parse();
    let log_level = match args.verbose {
        0 => "what_the_src=info",
        1 => "info,what_the_src=debug",
        2 => "debug",
        3 => "debug,what_the_src=trace",
        _ => "trace",
    };
    env_logger::Builder::from_env(Env::default().default_filter_or(log_level)).init();

    match args.subcommand {
        SubCommand::Web(args) => web::run(&args).await,
        SubCommand::Worker(args) => worker::run(&args).await,
        SubCommand::Plumbing(Plumbing::Fetch(args)) => {
            let mut reader = utils::http_client(args.socks5.as_deref())?
                .fetch(&args.url)
                .await?;
            let mut stdout = io::stdout();
            io::copy(&mut reader, &mut stdout).await?;
            Ok(())
        }
        SubCommand::Plumbing(Plumbing::IngestTar(args)) => ingest::tar::run(&args).await,
        SubCommand::Plumbing(Plumbing::IngestGit(args)) => ingest::git::run(&args).await,
        SubCommand::Plumbing(Plumbing::IngestPacmanSnapshot(args)) => {
            ingest::pacman::run(&args).await
        }
        SubCommand::Plumbing(Plumbing::IngestRpm(args)) => ingest::rpm::run(&args).await,
        SubCommand::Plumbing(Plumbing::IngestWolfi(args)) => ingest::wolfi::run(&args).await,
        SubCommand::Plumbing(Plumbing::IngestVoid(args)) => ingest::void::run(&args).await,
        SubCommand::Plumbing(Plumbing::IngestSbom(args)) => sbom::run(&args).await,
        SubCommand::Plumbing(Plumbing::ParsePkgbuild(_args)) => {
            let mut bytes = Vec::new();
            let mut stdin = io::stdin();
            stdin.read_to_end(&mut bytes).await?;

            let pkgbuild = pkgbuild::parse(&bytes)?;
            println!("pkgbuild={pkgbuild:?}");
            Ok(())
        }
        SubCommand::Plumbing(Plumbing::SyncAlpine(args)) => sync::alpine::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncApt(args)) => sync::apt::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncPacman(args)) => sync::pacman::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncLiveBootstrap(args)) => {
            sync::live_bootstrap::run(&args).await
        }
        SubCommand::Plumbing(Plumbing::SyncRpm(args)) => sync::rpm::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncGentoo(args)) => sync::gentoo::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncHomebrew(args)) => sync::homebrew::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncGuix(args)) => sync::guix::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncVoid(args)) => sync::void::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncYocto(args)) => sync::yocto::run(&args).await,
        SubCommand::Plumbing(Plumbing::SyncStagex(args)) => sync::stagex::run(&args).await,
        SubCommand::Plumbing(Plumbing::AddRef(args)) => alias::run(&args).await,
        SubCommand::Plumbing(Plumbing::ReindexUrl(args)) => reindex::run_url(&args).await,
        SubCommand::Plumbing(Plumbing::ReindexSbom(args)) => reindex::run_sbom(&args).await,
        SubCommand::Plumbing(Plumbing::S3Presign(args)) => {
            let creds = args.s3.creds();
            let bucket = args.s3.bucket()?;
            let now = Utc::now();
            let url = s3::sign_put_url(&creds, &bucket, &args.key, &now)?;
            println!("{url}");
            Ok(())
        }
        SubCommand::Plumbing(Plumbing::Upload(args)) => {
            let creds = args.s3.creds();
            let bucket = args.s3.bucket()?;

            let reader = File::open(args.file).await?;
            let reader = Hasher::new(reader);

            let writer = TempFile::new_in(Path::new(&args.tmp.path)).await?;
            let writer = s3::FsBuffer::new(writer);

            let mut buf = tee::buf();
            let mut stream = TeeStream::new(reader, writer, ReadBuf::uninit(&mut buf));

            let n = io::copy(&mut stream, &mut io::sink()).await?;
            info!("Streamed {n} bytes");

            let (reader, writer) = stream.into_inner();
            let (_file, chksums) = reader.digests();
            info!("Computed hash: {}", chksums.sha256);

            // Finalize compression
            let writer = writer.finish_rewind().await?;

            // Upload data
            let http = utils::http_client(None)?;
            s3::upload(&http, &creds, &bucket, &chksums, writer).await?;

            Ok(())
        }
    }
}
