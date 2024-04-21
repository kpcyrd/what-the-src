use crate::args;
use crate::chksums::Checksums;
use crate::db;
use crate::errors::*;
use crate::ingest;
use fd_lock::RwLock;
use std::process::Stdio;
use std::str::FromStr;
use tokio::fs;
use tokio::process;
use tokio::time::{self, Duration};

/// Do not tolerate occupying more than 20min of our time
pub const CLONE_TIMEOUT: Duration = Duration::from_secs(20 * 60);

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GitUrl {
    url: String,
    tag: Option<String>,
    commit: Option<String>,
}

impl FromStr for GitUrl {
    type Err = Error;

    fn from_str(full_url: &str) -> Result<GitUrl> {
        let url = full_url.strip_prefix("git+").unwrap_or(full_url);
        let url = url.trim_end_matches("?signed");

        let (url, info) = url
            .rsplit_once('#')
            .map(|(url, info)| (url, Some(info)))
            .unwrap_or((url, None));

        let mut git = GitUrl {
            url: url.trim_end_matches("?signed").to_string(),
            ..Default::default()
        };

        if let Some(info) = info {
            match info.split_once('=') {
                Some(("tag", value)) => git.tag = Some(value.to_string()),
                Some(("commit", value)) => git.commit = Some(value.to_string()),
                _ => return Err(Error::UnknownGitRef(info.to_string())),
            };
        }

        Ok(git)
    }
}

pub async fn take_snapshot(
    git: &GitUrl,
    tmp: &str,
) -> Result<(Checksums, Vec<ingest::tar::Entry>)> {
    fs::create_dir_all(tmp).await?;
    let dir = fs::File::open(tmp).await?;
    info!("Getting lock on filesystem git workdir...");
    let mut lock = RwLock::new(dir.into_std().await);
    let _lock = lock.write();
    debug!("Acquired lock");

    let reference = if let Some(tag) = &git.tag {
        tag
    } else if let Some(commit) = &git.commit {
        commit
    } else {
        return Err(Error::InvalidGitRef(git.clone()));
    };

    let path = format!("{}/git", tmp.strip_suffix('/').unwrap_or(tmp));
    if fs::metadata(&path).await.is_ok() {
        debug!("Running cleanup of temporary git repository");
        fs::remove_dir_all(&path).await?;
    }

    // run git clone
    info!("Setting up git repository");
    let status = process::Command::new("git")
        .args(["init", "-qb", "main", &path])
        .status()
        .await?;
    if !status.success() {
        return Err(Error::GitError(status));
    }

    let status = process::Command::new("git")
        .args(["-C", &path, "remote", "add", "origin", &git.url])
        .status()
        .await?;
    if !status.success() {
        return Err(Error::GitError(status));
    }

    info!("Fetching git VCS tree-ish reference: {reference:?}");
    let child = process::Command::new("git")
        .args(["-C", &path, "fetch", "origin", &reference])
        .status();
    let Ok(status) = time::timeout(CLONE_TIMEOUT, child).await else {
        return Err(Error::GitFetchTimeout);
    };
    let status = status?;
    if !status.success() {
        return Err(Error::GitFetchError(status));
    }

    info!("Taking `git archive` snapshot: {reference:?}");
    let mut child = process::Command::new("git")
        .args([
            "-C",
            &path,
            "-c",
            "core.abbrev=no",
            "archive",
            "--format",
            "tar",
            &reference,
        ])
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().unwrap();

    let (chksums, _chksums, files) = ingest::tar::stream_data(stdout, None).await?;

    Ok((chksums, files))
}

pub async fn run(args: &args::GitArchive) -> Result<()> {
    let db = db::Client::create().await?;

    let (chksums, files) = take_snapshot(&args.git, &args.tmp).await?;
    info!("digests={chksums:?}");

    db.insert_artifact(&chksums.sha256, &files).await?;
    db.register_chksums_aliases(&chksums, &chksums.sha256)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_git_url() {
        let url = "git+https://github.com/curl/curl.git?signed";
        let git = url.parse::<GitUrl>().unwrap();
        assert_eq!(
            git,
            GitUrl {
                url: "https://github.com/curl/curl.git".to_string(),
                tag: None,
                commit: None,
            }
        );
    }

    #[test]
    fn parse_git_url_tag() {
        let url = "git+https://github.com/curl/curl.git#tag=curl-8_7_1?signed";
        let git = url.parse::<GitUrl>().unwrap();
        assert_eq!(
            git,
            GitUrl {
                url: "https://github.com/curl/curl.git".to_string(),
                tag: Some("curl-8_7_1".to_string()),
                commit: None,
            }
        );
    }

    #[test]
    fn parse_git_url_commit() {
        let url = "git+https://github.com/rapid7/metasploit-framework.git?signed#commit=77fb7ae14f17fd7f4851bca87e0c28c704797591";
        let git = url.parse::<GitUrl>().unwrap();
        assert_eq!(
            git,
            GitUrl {
                url: "https://github.com/rapid7/metasploit-framework.git".to_string(),
                tag: None,
                commit: Some("77fb7ae14f17fd7f4851bca87e0c28c704797591".to_string()),
            }
        );
    }
}
