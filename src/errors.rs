use crate::ingest;
use crate::sync::stagex;
pub use log::{debug, error, info, trace, warn};
use reqwest::Url;
use std::process::ExitStatus;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    TemplateError(#[from] handlebars::TemplateError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    RenderError(#[from] handlebars::RenderError),
    #[error(transparent)]
    Tempfile(#[from] async_tempfile::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Xml(#[from] serde_xml_rs::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    Plist(#[from] plist::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Lz4(#[from] lz4_flex::frame::Error),
    #[error(transparent)]
    AptError(#[from] apt_parser::errors::APTError),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    ReqwestToString(#[from] reqwest::header::ToStrError),
    #[error("S3 upload failed({0}): {1:?}")]
    S3PutError(u16, String),
    #[error(transparent)]
    Srcinfo(#[from] srcinfo::Error),
    #[error(transparent)]
    Rpm(#[from] rpm::Error),
    #[error(transparent)]
    YarnLock(#[from] yarn_lock_parser::YarnLockError),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    Base64(#[from] data_encoding::DecodeError),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
    #[error(transparent)]
    Regex(#[from] regex::Error),
    #[error(transparent)]
    InvalidUri(#[from] warp::http::uri::InvalidUri),
    #[error(transparent)]
    SerdeUrl(#[from] serde_urlencoded::ser::Error),
    #[error("URL cannot be used as base: {0}")]
    UrlCannotBeBase(Url),
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    #[error(transparent)]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Child process has exited with error: {0}")]
    ChildExit(std::process::ExitStatus),
    #[error("Failed to sign s3 url")]
    S3PresignError,
    #[error("Parser encountered invalid data")]
    InvalidData,
    #[error("Parser encountered unknown variable: ${0}")]
    UnknownVariable(String),
    #[error("Parser encountered invalid PKGBUILD: {0}")]
    InvalidPkgbuild(String),
    #[error("Rpm is missing a `primary` data entry")]
    RpmMissingPrimary,
    #[error("Unknown git reference string: {0:?}")]
    UnknownGitRef(String),
    #[error("Invalid git reference: {0:?}")]
    InvalidGitRef(ingest::git::GitUrl),
    #[error("Error in git operation")]
    GitError(ExitStatus),
    #[error("Timeout of git fetch operation")]
    GitFetchTimeout,
    #[error("Error in git fetch operation")]
    GitFetchError(ExitStatus),
    #[error("Failed to parse git rev-parse output")]
    GitRevParseError(String),
    #[error("Failed to determine filename for Sources index")]
    AptIndexMissingSources,
    #[error("Unknown sbom strain: {0:?}")]
    UnknownSbomStrain(String),
    #[error("Task is missing mandatory repo field")]
    AlpineMissingRepo,
    #[error("APKINDEX is missing mandatory field: {0:?}")]
    ApkMissingField(&'static str),
    #[error("Unrecognized apk vendor: {0:?}")]
    UnrecognizedApkVendor(String),
    #[error("Failed to detect artifact checksum in wolfi package: {0:?}")]
    WolfiMissingChecksum(ingest::wolfi::Step),
    #[error("Unrecognized substitute in wolfi package: {0:?}")]
    WolfiUnknownSubstitute(String),
    #[error("String is poisoned, failed to interpolate: {0:?}")]
    YoctoPoisonedStr(String),
    #[error("Stagex package has no mirrors for source: {0:?}")]
    StagexMissingMirrors(stagex::Source),
    #[error("Stagex interpolate expression is never closed: {0:?}")]
    StagexUnclosedInterpolate(String),
    #[error("Stagex interpolate expression references undefined variable: {0:?}")]
    StagexUndefinedVariable(String),
}

// TODO: consider fixing this
impl warp::reject::Reject for Error {}

pub type Result<T> = std::result::Result<T, Error>;
