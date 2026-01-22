use crate::errors::*;
use async_compression::tokio::write::ZstdEncoder;
use chrono::{DateTime, Utc};
use reqwest::Url;
use s3_presign::Credentials;
use std::pin::Pin;
use tokio::io::{AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

const EXPIRATION: u64 = 900; // 15 minutes
const METHOD: &str = "PUT";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
const SERVICE: &str = "s3";

#[derive(Debug, Clone)]
pub struct Bucket {
    pub region: String,
    pub bucket: String,
    pub host: Url,
}

impl Bucket {
    pub fn url<I>(&self, key: I) -> Result<Url>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut url = self.host.clone();

        // Create a scope so `path` is dropped before returning `url`
        {
            let Ok(mut path) = url.path_segments_mut() else {
                return Err(Error::UrlCannotBeBase(url));
            };

            path.pop_if_empty();
            path.push(&self.bucket);
            path.extend(key);
        }

        Ok(url)
    }
}

pub fn put<I>(creds: &Credentials, bucket: &Bucket, key: I, now: &DateTime<Utc>) -> Result<String>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let url = bucket.url(key)?;
    let extra_headers = vec![];

    let Some(url) = s3_presign::presigned_url(
        creds,
        EXPIRATION,
        &url,
        METHOD,
        UNSIGNED_PAYLOAD,
        &bucket.region,
        now,
        SERVICE,
        extra_headers,
    ) else {
        return Err(Error::S3PresignError);
    };

    Ok(url)
}

pub struct FsBuffer<W: AsyncWrite> {
    writer: ZstdEncoder<W>,
}

impl<W: AsyncWrite + AsyncSeek + Unpin> FsBuffer<W> {
    pub fn new(writer: W) -> Self {
        let writer = ZstdEncoder::new(writer);
        Self { writer }
    }

    pub async fn finish_rewind(mut self) -> Result<W> {
        self.writer.shutdown().await?;
        let mut writer = self.writer.into_inner();
        writer.rewind().await?;
        Ok(writer)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for FsBuffer<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_url() {
        let bucket = Bucket {
            region: "eu-south-1".to_string(),
            bucket: "my-bucket".to_string(),
            host: Url::parse("https://s3.eu-south-1.wasabisys.com").unwrap(),
        };
        let url = bucket.url(["path", "to", "object.txt"]).unwrap();
        assert_eq!(
            url.as_str(),
            "https://s3.eu-south-1.wasabisys.com/my-bucket/path/to/object.txt"
        );
    }

    #[test]
    fn test_signed_put() {
        let creds = Credentials::new("abc", "xyz", None);
        let bucket = Bucket {
            region: "eu-south-1".to_string(),
            bucket: "my-bucket".to_string(),
            host: Url::parse("https://s3.eu-south-1.wasabisys.com").unwrap(),
        };
        let now = DateTime::parse_from_rfc3339("2026-01-22T13:37:00+01:00").unwrap();
        let url = put(&creds, &bucket, ["path", "to", "object.txt"], &now.to_utc()).unwrap();
        assert_eq!(
            url.as_str(),
            "https://s3.eu-south-1.wasabisys.com/my-bucket/path/to/object.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=abc%2F20260122%2Feu-south-1%2Fs3%2Faws4_request&X-Amz-Date=20260122T123700Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=7d151ccbcb19938b7e37d01c08f343e3acdcfe9bb976daa3590d867bd31e11f7"
        );
    }
}
