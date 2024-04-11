pub use log::{error, info};

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
}

// TODO: consider fixing this
impl warp::reject::Reject for Error {}

pub type Result<T> = std::result::Result<T, Error>;
