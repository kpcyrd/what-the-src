use crate::errors::*;
use futures::TryStreamExt;
use serde::Serialize;
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::Pool;
use std::borrow::Cow;

// keep track if we may need to reprocess an entry
const DB_VERSION: i16 = 0;

#[derive(Debug)]
pub struct Client {
    pool: Pool<Postgres>,
}

impl Client {
    pub async fn create() -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect("postgres://postgres:postgres@localhost/what-the-src")
            .await?;

        // sqlx currently does not support just putting `migrations` here
        sqlx::migrate!("db/migrations").run(&pool).await?;

        Ok(Client { pool })
    }

    pub async fn insert_artifact(&self, chksum: &str, files: &serde_json::Value) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO artifacts (db_version, chksum, files)
            VALUES ($1, $2, $3)
            ON CONFLICT (chksum) DO UPDATE
            SET db_version = EXCLUDED.db_version, files = EXCLUDED.files",
        )
        .bind(DB_VERSION)
        .bind(chksum)
        .bind(files)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_artifact(&self, chksum: &str) -> Result<Option<Artifact>> {
        let result = sqlx::query_as::<_, Artifact>("SELECT * FROM artifacts WHERE chksum = $1")
            .bind(chksum)
            .fetch_optional(&self.pool)
            .await?;
        Ok(result)
    }

    pub async fn insert_alias_from_to(&self, alias_from: &str, alias_to: &str) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO aliases (alias_from, alias_to)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING",
        )
        .bind(alias_from)
        .bind(alias_to)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_artifact_alias(&self, chksum: &str) -> Result<Option<Alias>> {
        let result = sqlx::query_as::<_, Alias>(
            "SELECT *
            FROM aliases
            WHERE alias_from = $1",
        )
        .bind(chksum)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result)
    }

    pub async fn get_aliased_artifact(&self, chksum: &str) -> Result<Option<Artifact>> {
        let result = sqlx::query_as::<_, Artifact>(
            "SELECT *
            FROM artifacts a
            LEFT JOIN aliases x ON x.alias_to = a.chksum
            WHERE x.alias_from = $1",
        )
        .bind(chksum)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result)
    }

    pub async fn insert_ref(
        &self,
        chksum: &str,
        vendor: &str,
        package: &str,
        version: &str,
        filename: Option<&str>,
    ) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO refs (chksum, vendor, package, version, filename)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING",
        )
        .bind(chksum)
        .bind(vendor)
        .bind(package)
        .bind(version)
        .bind(filename)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_all_refs(&self, chksum: &str) -> Result<Vec<RefView>> {
        let mut result = sqlx::query_as::<_, Ref>(
            "SELECT *
            FROM (
                SELECT refs.*
                FROM refs
                WHERE chksum = $1
                UNION
                SELECT refs.*
                FROM refs
                LEFT JOIN aliases x ON x.alias_from = refs.chksum
                WHERE x.alias_to = $1
            ) t
            ORDER BY vendor ASC
            ",
        )
        .bind(chksum)
        .fetch(&self.pool);

        let mut rows = Vec::new();
        while let Some(row) = result.try_next().await? {
            rows.push(row.into());
        }
        Ok(rows)
    }
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct Artifact {
    pub db_version: i16,
    pub chksum: String,
    pub files: Option<serde_json::Value>,
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct Alias {
    pub alias_from: String,
    pub alias_to: String,
    pub reason: Option<String>,
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct Ref {
    pub chksum: String,
    pub vendor: String,
    pub package: String,
    pub version: String,
    pub filename: Option<String>,
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct RefView {
    pub chksum: String,
    pub vendor: String,
    pub display_vendor: Cow<'static, str>,
    pub package: String,
    pub version: String,
    pub filename: Option<String>,
    pub href: Option<String>,
}

impl From<Ref> for RefView {
    fn from(r: Ref) -> Self {
        let (display_vendor, href) = match r.vendor.as_str() {
            "archlinux" => {
                let href = format!("https://archlinux.org/packages/?q={}", r.package);
                (Cow::Borrowed("Arch Linux"), Some(href))
            }
            "debian" => {
                let href = format!("https://packages.debian.org/search?keywords={}", r.package);
                (Cow::Borrowed("Debian"), Some(href))
            }
            other => (Cow::Owned(other.to_owned()), None),
        };

        RefView {
            chksum: r.chksum,
            vendor: r.vendor,
            display_vendor,
            package: r.package,
            version: r.version,
            filename: r.filename,
            href,
        }
    }
}
