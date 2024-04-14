pub use log::{debug, error, info, trace};

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
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    AptError(#[from] apt_parser::errors::APTError),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Srcinfo(#[from] srcinfo::Error),
    #[error("Parser encountered invalid data")]
    InvalidData,
    #[error("Parser encountered invalid PKGBUILD: {0}")]
    InvalidPkgbuild(String),
}

// TODO: consider fixing this
impl warp::reject::Reject for Error {}

pub type Result<T> = std::result::Result<T, Error>;
