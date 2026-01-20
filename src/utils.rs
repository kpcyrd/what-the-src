use crate::db::{Task, TaskData};
use crate::errors::*;
use futures::TryStreamExt;
use std::time::Duration;
use tokio::fs;
use tokio::io::{self, AsyncRead};
use tokio_util::io::StreamReader;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);
// do not immediately give away who we are, version string is from Debian trixie
pub const USER_AGENT: &str = "curl/8.14.1";

pub fn http_client(socks5: Option<&str>) -> Result<HttpClient> {
    let mut http = reqwest::ClientBuilder::new();
    if let Some(socks5) = socks5 {
        http = http.proxy(reqwest::Proxy::all(socks5)?);
    }
    let http = http
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .build()?;
    Ok(HttpClient { reqwest: http })
}

pub struct HttpClient {
    reqwest: reqwest::Client,
}

impl HttpClient {
    pub async fn fetch(&self, url: &str) -> Result<Box<dyn AsyncRead + Unpin>> {
        let resp = self.reqwest.get(url).send().await?.error_for_status()?;
        let stream = resp.bytes_stream();
        let stream = StreamReader::new(stream.map_err(io::Error::other));
        Ok(Box::new(stream))
    }
}

pub async fn fetch_or_open(path: &str, should_fetch: bool) -> Result<Box<dyn AsyncRead + Unpin>> {
    if should_fetch {
        http_client(None)?.fetch(path).await
    } else {
        let file = fs::File::open(path).await?;
        Ok(Box::new(file))
    }
}

pub fn is_possible_tar_artifact(url: &str) -> bool {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        false
    } else {
        url.contains(".tar") || url.ends_with(".crate") || url.ends_with(".tgz")
    }
}

pub fn task_for_url(url: &str) -> Option<Task> {
    match url.split_once("://") {
        Some(("https" | "http", _)) => {
            if is_possible_tar_artifact(url) {
                debug!("Found possible tar remote: {url:?}");
                Task::new(
                    format!("fetch:{url}"),
                    &TaskData::FetchTar {
                        url: url.to_string(),
                        compression: None,
                        success_ref: None,
                    },
                )
                .ok()
            } else {
                None
            }
        }
        Some((schema, _)) if schema.starts_with("git+") => {
            debug!("Found git remote: {url:?}");
            Task::new(
                format!("git-clone:{url}"),
                &TaskData::GitSnapshot {
                    url: url.to_string(),
                },
            )
            .ok()
        }
        _ => None,
    }
}
