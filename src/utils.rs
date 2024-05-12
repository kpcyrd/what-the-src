use crate::errors::*;
use futures::TryStreamExt;
use tokio::fs;
use tokio::io::{self, AsyncRead};
use tokio_util::io::StreamReader;

pub async fn fetch(url: &str) -> Result<Box<dyn AsyncRead + Unpin>> {
    let resp = reqwest::get(url).await?.error_for_status()?;
    let stream = resp.bytes_stream();
    let stream = StreamReader::new(stream.map_err(|e| io::Error::new(io::ErrorKind::Other, e)));
    Ok(Box::new(stream))
}

pub async fn fetch_or_open(path: &str, should_fetch: bool) -> Result<Box<dyn AsyncRead + Unpin>> {
    if should_fetch {
        fetch(path).await
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
