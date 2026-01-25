use crate::chksums::Checksums;
use crate::errors::*;
use crate::s3_presign::{self, Credentials};
use crate::utils::HttpClient;
use async_compression::{Level, tokio::write::ZstdEncoder};
use chrono::{DateTime, Utc};
use reqwest::{
    Url,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use std::iter;
use std::pin::Pin;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

const EXPIRATION: u64 = 900; // 15 minutes
const METHOD: &str = "PUT";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
const SERVICE: &str = "s3";

const SHARD_LEVEL1: usize = 9;
const SHARD_LEVEL2: usize = 2;

#[derive(Debug, Clone)]
pub struct Bucket {
    pub region: String,
    pub bucket: String,
    pub host: Url,
}

impl Bucket {
    pub fn url(&self, key: &str) -> Result<Url> {
        let mut url = self.host.clone();
        let mut path = url.path().to_string();

        // Append all segments to the path
        for segment in iter::once(self.bucket.as_str()).chain(key.split('/')) {
            if !path.ends_with('/') {
                path.push('/');
            }
            let segment = url_escape::encode(segment, url_escape::COMPONENT);
            path.push_str(&segment);
        }

        // Finalize the url
        url.set_path(&path);
        Ok(url)
    }
}

fn shard_key(key: &str) -> impl Iterator<Item = char> + '_ {
    key.chars()
        .enumerate()
        .flat_map(|(idx, ch)| {
            if idx == SHARD_LEVEL1 || idx == SHARD_LEVEL1 + SHARD_LEVEL2 {
                [Some('/'), Some(ch)]
            } else {
                [Some(ch), None]
            }
        })
        .flatten()
        .map(|c| if c == ':' { '-' } else { c })
}

pub fn sign_put_url(
    creds: &Credentials,
    bucket: &Bucket,
    headers: &HeaderMap,
    key: &str,
    now: &DateTime<Utc>,
) -> Result<String> {
    let url = bucket.url(key)?;

    let extra_headers = headers
        .iter()
        .map(|(k, v)| Ok((k.to_string(), v.to_str()?.to_string())))
        .collect::<Result<_>>()?;

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
        let writer = ZstdEncoder::with_quality(writer, Level::Best);
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

pub async fn upload<R: AsyncRead + Unpin + Send + 'static>(
    http: &HttpClient,
    creds: &Credentials,
    bucket: &Bucket,
    chksums: &Checksums,
    reader: R,
) -> Result<()> {
    let key = shard_key(&chksums.sha256).collect::<String>();

    let headers = HeaderMap::from_iter([
        (
            HeaderName::from_static("content-disposition"),
            HeaderValue::from_str(&format!("attachment; filename={}.tar.zst", &chksums.sha256))
                .expect("content-disposition header invalid"),
        ),
        (
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/zstd"),
        ),
    ]);

    let now = Utc::now();
    let url = sign_put_url(creds, bucket, &headers, &key, &now)?;

    info!("Starting s3 upload for {key}");
    let start = Instant::now();

    http.put(&url, headers, reader).await?;
    let duration = start.elapsed();
    info!(
        "Successfully uploaded {key} in {:.2?}s",
        duration.as_secs_f64()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sharded_key() {
        let key = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let sharded = shard_key(key).collect::<String>();
        assert_eq!(
            sharded,
            "sha256-e3/b0/c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn test_sharded_key_short1() {
        let key_level1 = "sha256:e";
        let sharded = shard_key(key_level1).collect::<String>();
        assert_eq!(sharded, "sha256-e");
    }

    #[test]
    fn test_sharded_key_short2() {
        let key_level1 = "sha256:e3b";
        let sharded = shard_key(key_level1).collect::<String>();
        assert_eq!(sharded, "sha256-e3/b");
    }

    #[test]
    fn test_sharded_key_short_on_boundary() {
        let key_level1 = "sha256:e3";
        let sharded = shard_key(key_level1).collect::<String>();
        assert_eq!(sharded, "sha256-e3");
    }


    #[test]
    fn test_bucket_url() {
        let bucket = Bucket {
            region: "eu-south-1".to_string(),
            bucket: "my-bucket".to_string(),
            host: Url::parse("https://s3.eu-south-1.wasabisys.com").unwrap(),
        };
        let url = bucket.url("sha256:of/my/object.txt").unwrap();
        assert_eq!(
            url.as_str(),
            "https://s3.eu-south-1.wasabisys.com/my-bucket/sha256%3Aof/my/object.txt"
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
        let url = sign_put_url(
            &creds,
            &bucket,
            &HeaderMap::new(),
            "path/to/object.txt",
            &now.to_utc(),
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://s3.eu-south-1.wasabisys.com/my-bucket/path/to/object.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=abc%2F20260122%2Feu-south-1%2Fs3%2Faws4_request&X-Amz-Date=20260122T123700Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=7d151ccbcb19938b7e37d01c08f343e3acdcfe9bb976daa3590d867bd31e11f7"
        );
    }

    #[test]
    fn test_signed_put_disposition() {
        let creds = Credentials::new("abc", "xyz", None);
        let bucket = Bucket {
            region: "eu-south-1".to_string(),
            bucket: "my-bucket".to_string(),
            host: Url::parse("https://s3.eu-south-1.wasabisys.com").unwrap(),
        };

        let headers = HeaderMap::from_iter([(
            HeaderName::from_static("content-disposition"),
            HeaderValue::from_static("attachment; filename=ohai.tar.zst"),
        )]);

        let now = DateTime::parse_from_rfc3339("2026-01-22T13:37:00+01:00").unwrap();
        let url = sign_put_url(
            &creds,
            &bucket,
            &headers,
            "path/to/object.txt",
            &now.to_utc(),
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://s3.eu-south-1.wasabisys.com/my-bucket/path/to/object.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=abc%2F20260122%2Feu-south-1%2Fs3%2Faws4_request&X-Amz-Date=20260122T123700Z&X-Amz-Expires=900&X-Amz-SignedHeaders=content-disposition%3Bhost&X-Amz-Signature=057cf16aafd20446c5ecdb72ff0c31fb7999a3b7adeeef0957925fe31014647f"
        );
    }
}
