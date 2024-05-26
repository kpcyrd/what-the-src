use crate::chksums;
use crate::chksums::Checksums;
use crate::errors::*;
use crate::ingest;
use crate::sbom;
use futures::Stream;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::Pool;
use sqlx::Row;
use std::borrow::Cow;
use std::env;

const RETRY_LIMIT: i64 = 5;

#[derive(Debug)]
pub struct Client {
    pool: Pool<Postgres>,
}

impl Client {
    pub async fn create() -> Result<Self> {
        let database_url = env::var("DATABASE_URL").unwrap();

        debug!("Connecting to database...");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await?;

        // sqlx currently does not support just putting `migrations` here
        sqlx::migrate!("db/migrations").run(&pool).await?;
        debug!("Database has been setup");

        Ok(Client { pool })
    }

    pub async fn insert_artifact(&self, chksum: &str, files: &[ingest::tar::Entry]) -> Result<()> {
        let files = serde_json::to_value(files)?;
        let _result = sqlx::query(
            "INSERT INTO artifacts (chksum, last_imported, files)
            VALUES ($1, now(), $2)
            ON CONFLICT (chksum) DO UPDATE SET
            last_imported = EXCLUDED.last_imported,
            files = EXCLUDED.files
            ",
        )
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

    pub async fn register_chksums_aliases(
        &self,
        chksums: &Checksums,
        canonical: &str,
    ) -> Result<()> {
        if chksums.sha256 != canonical {
            self.insert_alias_from_to(&chksums.sha256, canonical)
                .await?;
        }
        self.insert_alias_from_to(&chksums.sha512, canonical)
            .await?;
        self.insert_alias_from_to(&chksums.blake2b, canonical)
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

    pub async fn resolve_artifact(&self, chksum: &str) -> Result<Option<Artifact>> {
        let result = sqlx::query_as::<_, Artifact>(
            "SELECT a.*
            FROM artifacts a
            LEFT JOIN aliases x ON x.alias_to = a.chksum
            WHERE x.alias_from = $1
            UNION ALL
            SELECT a.*
            FROM artifacts a
            WHERE a.chksum = $1",
        )
        .bind(chksum)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result)
    }

    pub async fn insert_ref(&self, obj: &Ref) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO refs (chksum, vendor, package, version, filename, last_seen)
            VALUES ($1, $2, $3, $4, $5, now())
            ON CONFLICT (chksum, vendor, package, version) DO UPDATE SET
            last_seen = EXCLUDED.last_seen,
            filename = COALESCE(EXCLUDED.filename, refs.filename)",
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

    pub async fn get_ref(
        &self,
        chksum: &str,
        vendor: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<Ref>> {
        let result = sqlx::query_as(
            "SELECT *
            FROM refs
            WHERE chksum = $1
            AND vendor = $2
            AND package = $3
            AND version = $4",
        )
        .bind(chksum)
        .bind(vendor)
        .bind(package)
        .bind(version)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result)
    }

    pub async fn get_named_ref(
        &self,
        vendor: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<Ref>> {
        let result = sqlx::query_as(
            "SELECT *
            FROM refs
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

    pub async fn get_all_refs_for(&self, chksum: &str) -> Result<Vec<RefView>> {
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

    pub fn get_all_artifacts_by_age(&self) -> impl Stream<Item = Result<Artifact>> {
        let pool = self.pool.clone();
        async_stream::stream! {
            let mut result = sqlx::query_as::<_, Artifact>(
                "SELECT *
                FROM artifacts
                ORDER BY last_imported ASC",
            )
            .fetch(&pool);

            while let Some(row) = result.try_next().await? {
                yield Ok(row);
            }
        }
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

    pub async fn bump_task_error_counter(&self, task: &Task, error: &str) -> Result<()> {
        let _result = sqlx::query(
            "UPDATE tasks
            SET retries = retries + 1,
            error = $2
            WHERE id = $1",
        )
        .bind(task.id)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_random_task(&self) -> Result<Option<Task>> {
        let result = sqlx::query_as(
            "SELECT *
                FROM tasks
                WHERE retries < $1
                ORDER BY RANDOM()
                LIMIT 1",
        )
        .bind(RETRY_LIMIT)
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

    pub async fn search(&self, search: &str, limit: usize) -> Result<Vec<RefView>> {
        let exact = search.strip_suffix('%').unwrap_or(search);

        // Search for exact matches first
        let mut result = sqlx::query_as::<_, Ref>(
            "SELECT *
            FROM refs
            WHERE package = $1
            ORDER BY id DESC
            LIMIT $2",
        )
        .bind(exact)
        .bind(limit as i64)
        .fetch(&self.pool);

        let mut rows = Vec::new();
        while let Some(row) = result.try_next().await? {
            rows.push(row.into());
        }

        // Fill remaining slots with prefix search
        let mut result = sqlx::query_as::<_, Ref>(
            "SELECT *
            FROM refs
            WHERE package LIKE $3 AND package != $1
            ORDER BY id DESC
            LIMIT $2",
        )
        .bind(exact)
        .bind(limit as i64)
        .bind(search)
        .fetch(&self.pool);

        while let Some(row) = result.try_next().await? {
            rows.push(row.into());
        }

        Ok(rows)
    }

    pub async fn insert_sbom(&self, sbom: &sbom::Sbom) -> Result<String> {
        let chksum = chksums::sha256(sbom.data().as_bytes());
        let _result = sqlx::query(
            "INSERT INTO sboms (strain, chksum, data)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING",
        )
        .bind(sbom.strain())
        .bind(&chksum)
        .bind(sbom.data())
        .execute(&self.pool)
        .await?;
        Ok(chksum)
    }

    pub async fn get_sbom(&self, chksum: &str) -> Result<Option<Sbom>> {
        let result = sqlx::query_as::<_, Sbom>("SELECT * FROM sboms WHERE chksum = $1")
            .bind(chksum)
            .fetch_optional(&self.pool)
            .await?;
        Ok(result)
    }

    pub async fn get_all_sboms(&self) -> Result<Vec<Sbom>> {
        let mut result = sqlx::query_as(
            "SELECT *
            FROM sboms",
        )
        .fetch(&self.pool);

        let mut rows = Vec::new();
        while let Some(row) = result.try_next().await? {
            rows.push(row);
        }
        Ok(rows)
    }

    pub async fn get_sbom_with_strain(&self, chksum: &str, strain: &str) -> Result<Option<Sbom>> {
        let result =
            sqlx::query_as::<_, Sbom>("SELECT * FROM sboms WHERE chksum = $1 AND strain = $2")
                .bind(chksum)
                .bind(strain)
                .fetch_optional(&self.pool)
                .await?;
        Ok(result)
    }

    pub async fn insert_sbom_ref(
        &self,
        archive_digest: &str,
        sbom_strain: &str,
        sbom_digest: &str,
        path: &str,
    ) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO sbom_refs (from_archive, sbom_strain, sbom_chksum, path)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT DO NOTHING",
        )
        .bind(archive_digest)
        .bind(sbom_strain)
        .bind(sbom_digest)
        .bind(path)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_sbom_refs_for_archive(&self, archive_digest: &str) -> Result<Vec<SbomRef>> {
        let mut result = sqlx::query_as::<_, SbomRef>(
            "SELECT *
            FROM sbom_refs
            WHERE from_archive = $1
            ORDER BY path ASC",
        )
        .bind(archive_digest)
        .fetch(&self.pool);

        let mut rows = Vec::new();
        while let Some(row) = result.try_next().await? {
            rows.push(row);
        }
        Ok(rows)
    }

    pub async fn get_sbom_refs_for_sbom(&self, sbom: &Sbom) -> Result<Vec<SbomRef>> {
        let mut result = sqlx::query_as::<_, SbomRef>(
            "SELECT *
            FROM sbom_refs
            WHERE sbom_strain = $1 AND sbom_chksum = $2
            ORDER BY from_archive ASC, path ASC",
        )
        .bind(&sbom.strain)
        .bind(&sbom.chksum)
        .fetch(&self.pool);

        let mut rows = Vec::new();
        while let Some(row) = result.try_next().await? {
            rows.push(row);
        }
        Ok(rows)
    }

    pub async fn get_stats(&self, sql: &str, param: Option<i64>) -> Result<Vec<(String, i64)>> {
        let mut result = sqlx::query(sql).bind(param.unwrap_or(0)).fetch(&self.pool);

        let mut rows = Vec::new();
        while let Some(row) = result.try_next().await? {
            let key = row.get(0);
            let num = row.get(1);
            rows.push((key, num));
        }
        Ok(rows)
    }

    pub async fn stats_estimated_artifacts(&self) -> Result<Vec<(String, i64)>> {
        self.get_stats(
            "SELECT '', reltuples::bigint
            FROM pg_class
            WHERE relname = 'artifacts'",
            None,
        )
        .await
    }

    pub async fn stats_import_dates(&self) -> Result<Vec<(String, i64)>> {
        self.get_stats(
            "SELECT to_date_char(last_imported) date, count(*) num
            FROM artifacts
            GROUP BY date
            ORDER by date",
            None,
        )
        .await
    }

    pub async fn stats_vendor_refs(&self) -> Result<Vec<(String, i64)>> {
        self.get_stats(
            "SELECT vendor, count(*)
            FROM refs
            GROUP BY vendor
            ORDER BY vendor",
            Some(RETRY_LIMIT),
        )
        .await
    }

    pub async fn stats_pending_tasks(&self) -> Result<Vec<(String, i64)>> {
        self.get_stats(
            "SELECT split_part(key, ':', 1) k, count(*) num
            FROM tasks
            WHERE retries < $1
            GROUP BY k
            ORDER BY k",
            Some(RETRY_LIMIT),
        )
        .await
    }
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct Artifact {
    pub chksum: String,
    #[serde(skip)]
    pub first_seen: DateTime<Utc>,
    #[serde(skip)]
    pub last_imported: DateTime<Utc>,
    pub files: Option<serde_json::Value>,
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct Alias {
    pub alias_from: String,
    pub alias_to: String,
    pub reason: Option<String>,
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct Sbom {
    pub chksum: String,
    pub strain: String,
    pub data: String,
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct SbomRef {
    pub from_archive: String,
    pub sbom_strain: String,
    pub sbom_chksum: String,
    pub path: String,
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
            "fedora" => {
                let href = format!("https://packages.fedoraproject.org/pkgs/{}/", r.package);
                (Cow::Borrowed("Fedora"), Some(href))
            }
            "alpine" => {
                let href = format!("https://pkgs.alpinelinux.org/packages?name={}", r.package);
                (Cow::Borrowed("Alpine"), Some(href))
            }
            "opensuse" => {
                let href = format!(
                    "https://build.opensuse.org/package/show/openSUSE:Factory/{}",
                    r.package
                );
                // alternative: https://src.opensuse.org/rpm/{} or https://code.opensuse.org/package/{}
                (Cow::Borrowed("openSUSE"), Some(href))
            }
            "kali" => {
                let href = format!("https://pkg.kali.org/pkg/{}", r.package);
                (Cow::Borrowed("Kali"), Some(href))
            }
            "gentoo" => {
                let href = format!("https://packages.gentoo.org/packages/{}", r.package);
                (Cow::Borrowed("Gentoo"), Some(href))
            }
            "homebrew" => {
                let href = format!("https://formulae.brew.sh/formula/{}", r.package);
                (Cow::Borrowed("Homebrew"), Some(href))
            }
            "wolfi" => {
                let href = format!(
                    "https://github.com/wolfi-dev/os/blob/main/{}.yaml",
                    r.package
                );
                (Cow::Borrowed("Wolfi OS"), Some(href))
            }
            "guix" => {
                let href = format!("https://packages.guix.gnu.org/packages/{}", r.package);
                (Cow::Borrowed("Guix"), Some(href))
            }
            "ubuntu" => {
                let href = format!(
                    "https://packages.ubuntu.com/search?suite=all&searchon=names&keywords={}",
                    r.package
                );
                (Cow::Borrowed("Ubuntu"), Some(href))
            }
            "void" => {
                let href = format!(
                    "https://voidlinux.org/packages/?arch=x86_64&q={}",
                    r.package
                );
                (Cow::Borrowed("Void Linux"), Some(href))
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
    pub retries: i16,
    pub error: Option<String>,
}

impl Task {
    pub fn new(key: String, data: &TaskData) -> Result<Self> {
        let data = serde_json::to_value(data)?;
        Ok(Task {
            id: 0,
            key,
            data,
            retries: 0,
            error: None,
        })
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
        compression: Option<String>,
        success_ref: Option<DownloadRef>,
    },
    PacmanGitSnapshot {
        vendor: String,
        package: String,
        version: String,
        tag: String,
    },
    SourceRpm {
        vendor: String,
        package: String,
        version: String,
        url: String,
    },
    #[serde(alias = "AlpineGitApkbuild")]
    ApkbuildGit {
        vendor: String,
        repo: Option<String>,
        origin: String,
        version: String,
        commit: String,
    },
    VoidLinuxGit {
        vendor: String,
        srcpkg: String,
        commit: String,
        package: String,
        version: String,
    },
    GitSnapshot {
        url: String,
    },
    IndexSbom {
        // support old task format
        strain: Option<String>,
        chksum: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadRef {
    pub vendor: String,
    pub package: String,
    pub version: String,
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct Package {
    pub vendor: String,
    pub package: String,
    pub version: String,
}
