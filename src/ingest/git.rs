use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;
use crate::s3::UploadClient;
use fd_lock::RwLock;
use std::io::BufRead;
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
    db: &db::Client,
    upload: &UploadClient,
    git: &GitUrl,
    tmp: &str,
) -> Result<()> {
    fs::create_dir_all(tmp).await?;
    let dir = fs::File::open(tmp).await?;
    info!("Getting lock on filesystem git workdir...");
    let mut lock = RwLock::new(dir.into_std().await);
    // The `.write()` function can return an error if interrupted, so we loop until we get the lock
    let lock = loop {
        if let Ok(lock) = lock.write() {
            break lock;
        }
    };
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

    // Checking out a single commit occupies 40GB disk
    if [
        "https://chromium.googlesource.com/chromium/src.git",
        "https://github.com/chromium/chromium.git",
    ]
    .contains(&git.url.as_str())
    {
        info!("Detected chromium, skipping 🤡: {:?}", git.url);
        return Ok(());
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

    // https://gitlab.archlinux.org/pacman/pacman/-/commit/0828a085c146601f21d5e4afb5f396f00de2963b
    debug!("Setting up .git/info/attributes to disable .gitattributes");
    fs::write(
        format!("{path}/.git/info/attributes"),
        b"* -export-subst -export-ignore\n",
    )
    .await?;

    debug!("Adding git remote: {:?}", git.url);
    let status = process::Command::new("git")
        .args(["-C", &path, "remote", "add", "origin", &git.url])
        .status()
        .await?;
    if !status.success() {
        return Err(Error::GitError(status));
    }

    info!(
        "Fetching git VCS tree-ish reference from {:?}: {:?}",
        git.url, reference
    );
    let child = process::Command::new("git")
        .args(["-C", &path, "fetch", "origin", reference])
        .status();
    let Ok(status) = time::timeout(CLONE_TIMEOUT, child).await else {
        return Err(Error::GitFetchTimeout);
    };
    let status = status?;
    if !status.success() {
        return Err(Error::GitFetchError(status));
    }

    info!("Resolving FETCH_HEAD git ref");
    let output = process::Command::new("git")
        .args(["-C", &path, "rev-list", "-n1", "FETCH_HEAD"])
        .output()
        .await?;
    if !output.status.success() {
        return Err(Error::GitFetchError(status));
    }
    let Some(Ok(commit)) = output.stdout.lines().next() else {
        let output = String::from_utf8_lossy(&output.stdout).into_owned();
        return Err(Error::GitRevParseError(output));
    };
    info!("Resolved ref FETCH_HEAD to git commit: {commit:?}");

    info!("Taking `git archive` snapshot of FETCH_HEAD");
    let mut child = process::Command::new("git")
        .args([
            "-C",
            &path,
            "-c",
            "core.abbrev=no",
            "archive",
            "--format",
            "tar",
            "FETCH_HEAD",
        ])
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    let summary = ingest::tar::stream_data(Some(db), upload, stdout).await?;

    let status = child.wait().await?;
    if !status.success() {
        return Err(Error::GitFetchError(status));
    }

    db.insert_alias_from_to(
        &format!("git:{commit}"),
        &summary.inner_digests.sha256,
        "git-archive",
    )
    .await?;

    // Explicitly keep the lock held until here
    drop(lock);

    Ok(())
}

pub async fn run(args: &args::IngestGit) -> Result<()> {
    let db = db::Client::create().await?;
    let upload = UploadClient::new(args.s3.clone(), Some(&args.tmp))?;

    take_snapshot(&db, &upload, &args.git, &args.tmp).await?;

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
