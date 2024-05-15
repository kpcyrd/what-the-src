use crate::errors::*;
use futures::TryStreamExt;
use tokio::fs;
use tokio::io::{self, AsyncRead};
use tokio_util::io::StreamReader;

pub fn http_client(socks5: Option<&String>) -> Result<HttpClient> {
    let mut http = reqwest::ClientBuilder::new();
    if let Some(socks5) = socks5 {
        http = http.proxy(reqwest::Proxy::all(socks5)?);
    }
    // do not immediately give away who we are, version string is from Debian bookworm
    http = http.user_agent("curl/7.88.1");
    let http = http.build()?;
    Ok(HttpClient { reqwest: http })
}

pub struct HttpClient {
    reqwest: reqwest::Client,
}

impl HttpClient {
    pub async fn fetch(&self, url: &str) -> Result<Box<dyn AsyncRead + Unpin>> {
        let resp = self.reqwest.get(url).send().await?.error_for_status()?;
        let stream = resp.bytes_stream();
        let stream = StreamReader::new(stream.map_err(|e| io::Error::new(io::ErrorKind::Other, e)));
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
