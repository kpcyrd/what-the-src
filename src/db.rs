use crate::chksums::Checksums;
use crate::errors::*;
use crate::ingest;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::Pool;
use std::borrow::Cow;
use std::env;

// keep track if we may need to reprocess an entry
const DB_VERSION: i16 = 0;

#[derive(Debug)]
pub struct Client {
    pool: Pool<Postgres>,
}

impl Client {
    pub async fn create() -> Result<Self> {
        let database_url = env::var("DATABASE_URL").unwrap();

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await?;

        // sqlx currently does not support just putting `migrations` here
        sqlx::migrate!("db/migrations").run(&pool).await?;

        Ok(Client { pool })
    }

    pub async fn insert_artifact(&self, chksum: &str, files: &[ingest::tar::Entry]) -> Result<()> {
        let files = serde_json::to_value(files)?;
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

    pub async fn register_chksums_aliases(&self, outer: &Checksums, canonical: &str) -> Result<()> {
        if outer.sha256 != canonical {
            self.insert_alias_from_to(&outer.sha256, canonical).await?;
        }
        self.insert_alias_from_to(&outer.sha512, canonical).await?;
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

    pub async fn resolve_artifact(&self, chksum: &str) -> Result<Option<Artifact>> {
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

    pub async fn insert_ref(&self, obj: &Ref) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO refs (chksum, vendor, package, version, filename)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (chksum, vendor, package, version) DO UPDATE
            SET filename = COALESCE(EXCLUDED.filename, refs.filename)",
        )
        .bind(&obj.chksum)
        .bind(&obj.vendor)
        .bind(&obj.package)
        .bind(&obj.version)
        .bind(&obj.filename)
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

    pub async fn insert_task(&self, task: &Task) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO tasks(key, data)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING",
        )
        .bind(&task.key)
        .bind(&task.data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_random_task(&self) -> Result<Option<Task>> {
        let result = sqlx::query_as(
            "SELECT *
                FROM tasks
                ORDER BY RANDOM()
                LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(result)
    }

    pub async fn delete_task(&self, task: &Task) -> Result<()> {
        let _result = sqlx::query(
            "DELETE FROM tasks
            WHERE key = $1",
        )
        .bind(&task.key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_package(&self, package: &Package) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO packages (vendor, package, version)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING",
        )
        .bind(&package.vendor)
        .bind(&package.package)
        .bind(&package.version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_package(
        &self,
        vendor: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<Package>> {
        let result = sqlx::query_as(
            "SELECT *
            FROM packages
            WHERE vendor = $1
            AND package = $2
            AND version = $3",
        )
        .bind(vendor)
        .bind(package)
        .bind(version)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result)
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

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct Task {
    pub id: i64,
    pub key: String,
    pub data: serde_json::Value,
}

impl Task {
    pub fn new(key: String, data: &TaskData) -> Result<Self> {
        let data = serde_json::to_value(data)?;
        Ok(Task { id: 0, key, data })
    }

    pub fn data(&self) -> Result<TaskData> {
        let data = serde_json::from_value(self.data.clone())?;
        Ok(data)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TaskData {
    FetchTar {
        url: String,
    },
    PacmanGitSnapshot {
        vendor: String,
        package: String,
        version: String,
        tag: String,
    },
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct Package {
    pub vendor: String,
    pub package: String,
    pub version: String,
}
