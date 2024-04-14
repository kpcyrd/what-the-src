use crate::errors::*;
use futures::TryStreamExt;
use tokio::fs;
use tokio::io::{self, AsyncRead};
use tokio_util::io::StreamReader;

pub async fn fetch_or_open(path: &str, fetch: bool) -> Result<Box<dyn AsyncRead + Unpin>> {
    if fetch {
        let resp = reqwest::get(path).await?.error_for_status()?;
        let stream = resp.bytes_stream();
        let stream = StreamReader::new(stream.map_err(|e| io::Error::new(io::ErrorKind::Other, e)));
        Ok(Box::new(stream))
    } else {
        let file = fs::File::open(path).await?;
        Ok(Box::new(file))
    }
}
