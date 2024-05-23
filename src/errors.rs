use crate::ingest;
pub use log::{debug, error, info, trace, warn};
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
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Xml(#[from] serde_xml_rs::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    AptError(#[from] apt_parser::errors::APTError),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
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
    #[error(transparent)]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Child process has exited with error: {0}")]
    ChildExit(std::process::ExitStatus),
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
}

// TODO: consider fixing this
impl warp::reject::Reject for Error {}

pub type Result<T> = std::result::Result<T, Error>;
