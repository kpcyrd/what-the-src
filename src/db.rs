use crate::chksums::Checksums;
use crate::errors::*;
use crate::ingest;
use crate::sbom;
use futures::Stream;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::Pool;
use sqlx::Row;
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::types::chrono::{DateTime, Utc};
use std::borrow::Cow;
use std::env;
use std::io::{Read, Write};
use url::Url;

const RETRY_LIMIT: i64 = 5;

fn compress_json<W: Write, T: Serialize + ?Sized>(writer: W, obj: &T) -> Result<()> {
    let mut writer = lz4_flex::frame::FrameEncoder::new(writer);
    serde_json::to_writer(&mut writer, obj)?;
    writer.finish()?;
    Ok(())
}

fn decompress_json<R: Read, T: DeserializeOwned>(reader: R) -> Result<T> {
    let reader = lz4_flex::frame::FrameDecoder::new(reader);
    let obj = serde_json::from_reader(reader)?;
    Ok(obj)
}

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
        let mut buf = Vec::new();
        compress_json(&mut buf, files)?;

        let _result = sqlx::query(
            "INSERT INTO artifacts (chksum, last_imported, files_compressed)
            VALUES ($1, now(), $2)
            ON CONFLICT (chksum) DO UPDATE SET
            last_imported = EXCLUDED.last_imported,
            files = null,
            files_compressed = EXCLUDED.files_compressed
            ",
        )
        .bind(chksum)
        .bind(&buf)
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

    pub async fn insert_alias_from_to(
        &self,
        alias_from: &str,
        alias_to: &str,
        reason: &str,
    ) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO aliases (alias_from, alias_to, reason)
            VALUES ($1, $2, $3)
            ON CONFLICT (alias_from, alias_to) DO UPDATE SET
            reason = COALESCE(EXCLUDED.reason, aliases.reason)",
        )
        .bind(alias_from)
        .bind(alias_to)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn register_chksums_aliases(
        &self,
        chksums: &Checksums,
        canonical: &str,
        label: &str,
    ) -> Result<()> {
        if chksums.sha256 != canonical {
            self.insert_alias_from_to(&chksums.sha256, canonical, &format!("sha256({label})"))
                .await?;
        }
        self.insert_alias_from_to(&chksums.sha512, canonical, &format!("sha512({label})"))
            .await?;
        self.insert_alias_from_to(&chksums.blake2b, canonical, &format!("blake2b({label})"))
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

    pub async fn insert_ref_on<'a, E>(&self, exec: E, obj: &Ref) -> Result<()>
    where
        E: sqlx::Executor<'a, Database = Postgres>,
    {
        let _result = sqlx::query(
            "INSERT INTO refs (chksum, vendor, package, version, filename, last_seen, protocol, host)
            VALUES ($1, $2, $3, $4, $5, now(), $6, $7)
            ON CONFLICT (chksum, vendor, package, version) DO UPDATE SET
            last_seen = EXCLUDED.last_seen,
            filename = COALESCE(EXCLUDED.filename, refs.filename),
            protocol = COALESCE(EXCLUDED.protocol, refs.protocol),
            host = COALESCE(EXCLUDED.host, refs.host)",
        )
        .bind(&obj.chksum)
        .bind(&obj.vendor)
        .bind(&obj.package)
        .bind(&obj.version)
        .bind(&obj.filename)
        .bind(&obj.protocol)
        .bind(&obj.host)
        .execute(exec)
        .await?;
        Ok(())
    }

    pub async fn insert_ref(&self, obj: &Ref) -> Result<()> {
        self.insert_ref_on(&self.pool, obj).await
    }

    pub async fn batch_insert_refs(&self, batch: &[Ref]) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        for obj in batch {
            self.insert_ref_on(&mut *tx, obj).await?;
        }

        tx.commit().await?;
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

    pub async fn bump_named_refs(&self, vendor: &str, package: &str, version: &str) -> Result<()> {
        let _result = sqlx::query(
            "UPDATE refs
            SET last_seen = now()
            WHERE vendor = $1
            AND package = $2
            AND version = $3",
        )
        .bind(vendor)
        .bind(package)
        .bind(version)
        .execute(&self.pool)
        .await?;
        Ok(())
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

    pub fn get_all_remote_refs(&self) -> impl Stream<Item = Result<Ref>> {
        let pool = self.pool.clone();
        async_stream::stream! {
            let mut result = sqlx::query_as::<_, Ref>("SELECT * FROM refs WHERE filename LIKE '%://%'")
                .fetch(&pool);

            while let Some(row) = result.try_next().await? {
                yield Ok(row);
            }
        }
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

    pub async fn insert_sbom(&self, hashed: &sbom::HashedSbom<'_>) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO sboms (strain, chksum, data)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING",
        )
        .bind(hashed.sbom.strain())
        .bind(&hashed.chksum)
        .bind(hashed.sbom.data())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_sbom(&self, chksum: &str) -> Result<Option<Sbom>> {
        let result = sqlx::query_as::<_, Sbom>("SELECT * FROM sboms WHERE chksum = $1")
            .bind(chksum)
            .fetch_optional(&self.pool)
            .await?;
        Ok(result)
    }

    pub fn get_all_sboms(&self) -> impl Stream<Item = Result<Sbom>> {
        let pool = self.pool.clone();
        async_stream::stream! {
            let mut result = sqlx::query_as(
                "SELECT *
                FROM sboms",
            )
            .fetch(&pool);

            while let Some(row) = result.try_next().await? {
                yield Ok(row);
            }
        }
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

    pub async fn get_bucket_object(&self, key: &str) -> Result<Option<BucketObject>> {
        let result = sqlx::query_as::<_, BucketObject>(
            "SELECT *
            FROM bucket
            WHERE key = $1",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result)
    }

    pub async fn insert_bucket_object(
        &self,
        key: &str,
        compressed_size: i64,
        uncompressed_size: i64,
    ) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO bucket (key, compressed_size, uncompressed_size)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING",
        )
        .bind(key)
        .bind(compressed_size)
        .bind(uncompressed_size)
        .execute(&self.pool)
        .await?;
        Ok(())
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

    pub async fn stats_artifacts(&self) -> Result<(i64,)> {
        let sql = "SELECT count(*) FROM artifacts";
        let result = sqlx::query_as::<_, _>(sql).fetch_one(&self.pool).await?;
        Ok(result)
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
            None,
        )
        .await
    }

    pub async fn stats_sbom_strains(&self) -> Result<Vec<(String, i64)>> {
        self.get_stats(
            "SELECT strain, count(*)
            FROM sboms
            GROUP BY strain
            ORDER BY strain",
            None,
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

    pub async fn stats_archive(&self) -> Result<(i64, i64, i64)> {
        let sql = "SELECT
                count(*),
                coalesce(sum(compressed_size)::bigint, 0),
                coalesce(sum(uncompressed_size)::bigint, 0)
            FROM bucket";
        let result = sqlx::query_as::<_, _>(sql).fetch_one(&self.pool).await?;
        Ok(result)
    }

    pub async fn stats_refs_hosts(&self) -> Result<Vec<(String, i64)>> {
        self.get_stats(
            "SELECT host, COUNT(DISTINCT filename) AS num
            FROM refs
            WHERE host IS NOT NULL
                AND filename IS NOT NULL
            GROUP BY host",
            None,
        )
        .await
    }

    pub async fn stats_aliases_with_reason(&self) -> Result<Vec<(String, i64)>> {
        self.get_stats(
            "select '%', floor(100.0*(select count(*) from aliases where reason is not null)/(select count(*) from aliases))::bigint as percent",
            None,
        )
        .await
    }

    pub async fn stats_compressed_artifacts(&self) -> Result<Vec<(String, i64)>> {
        self.get_stats(
            "select '%', floor(100.0*(select count(*) from artifacts where files_compressed is not null)/(select count(*) from artifacts))::bigint as percent",
            None,
        )
        .await
    }

    pub async fn stats_postgres_dead_rows(&self) -> Result<Vec<(String, i64)>> {
        self.get_stats(
            "SELECT relname, n_dead_tup
                FROM pg_stat_user_tables",
            None,
        )
        .await
    }

    pub async fn stats_postgres_last_vacuum(&self) -> Result<Vec<(String, i64)>> {
        self.get_stats(
            "SELECT
                relname AS table_name,
                EXTRACT('epoch'
                    FROM NOW() - GREATEST(last_vacuum, last_autovacuum)
                )::bigint as elapsed_since
                FROM pg_stat_user_tables
                WHERE last_vacuum IS NOT NULL OR last_autovacuum IS NOT NULL
                ORDER BY relname ASC",
            None,
        )
        .await
    }

    pub async fn stats_postgres_active_vacuums(&self) -> Result<Vec<(String, i64)>> {
        // The following are also interesting (can all be null)
        // Does not fit the current concept `.get_stats(...) -> Vec<(String, i64)>` though
        //
        // phase
        // heap_blks_total
        // heap_blks_scanned
        // heap_blks_vacuumed
        // index_vacuum_count
        // max_dead_tuples
        // num_dead_tuples

        self.get_stats(
            "SELECT c.relname, count(1)
                FROM pg_stat_progress_vacuum v
                LEFT JOIN pg_class c
                    ON c.oid = v.relid
                WHERE c.relname IS NOT NULL
                GROUP BY c.relname",
            None,
        )
        .await
    }

    pub async fn dangling_artifacts(&self) -> Result<Vec<String>> {
        let mut result = sqlx::query(
            "select * from (
                select a.chksum, count(r.chksum) c
                from artifacts a
                left join aliases x on a.chksum = x.alias_to
                left join refs r on r.chksum = x.alias_from or r.chksum = a.chksum
                group by a.chksum
            ) where c = 0",
        )
        .fetch(&self.pool);

        let mut rows = Vec::new();
        while let Some(row) = result.try_next().await? {
            let chksum = row.get(0);
            rows.push(chksum);
        }
        Ok(rows)
    }
}

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct Artifact {
    pub chksum: String,
    #[serde(skip)]
    pub first_seen: DateTime<Utc>,
    #[serde(skip)]
    pub last_imported: DateTime<Utc>,
    #[serde(skip)]
    pub files: Option<serde_json::Value>,
    #[serde(skip)]
    pub files_compressed: Option<Vec<u8>>,
}

impl Artifact {
    pub fn get_files(&self) -> Result<Option<Vec<ingest::tar::Entry>>> {
        if let Some(files) = &self.files {
            let files = serde_json::from_value(files.clone())?;
            Ok(Some(files))
        } else if let Some(compressed) = &self.files_compressed {
            let files = decompress_json(&compressed[..])?;
            Ok(Some(files))
        } else {
            Ok(None)
        }
    }
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

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct Ref {
    pub chksum: String,
    pub vendor: String,
    pub package: String,
    pub version: String,
    pub filename: Option<String>,
    pub protocol: Option<String>,
    pub host: Option<String>,
}

impl Ref {
    pub fn new(
        chksum: String,
        vendor: String,
        package: String,
        version: String,
        filename: Option<String>,
    ) -> Self {
        let (protocol, host) = filename
            .as_deref()
            .and_then(|s| {
                let url = Url::parse(s).ok()?;
                let host = url.host_str()?;
                Some((Some(url.scheme().to_string()), Some(host.to_string())))
            })
            .unwrap_or((None, None));

        Ref {
            chksum,
            vendor,
            package,
            version,
            filename,
            protocol,
            host,
        }
    }
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
            "live-bootstrap" => {
                let href = format!(
                    "https://github.com/fosslinux/live-bootstrap/blob/master/steps/{}-{}",
                    r.package, r.version,
                );
                (Cow::Borrowed("live-bootstrap"), Some(href))
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
            "yocto" => {
                let href = format!(
                    "https://layers.openembedded.org/layerindex/branch/master/recipes/?q={}",
                    r.package
                );
                (Cow::Borrowed("Yocto Project"), Some(href))
            }
            "stagex" => {
                let href = format!("https://stagex.tools/packages/{}/", r.package);
                (Cow::Borrowed("stagex"), Some(href))
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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum TaskData {
    FetchTar {
        url: String,
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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct BucketObject {
    pub key: String,
    pub compressed_size: i64,
    pub uncompressed_size: i64,
    #[serde(skip)]
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_compression() {
        let obj = maplit::btreemap! {
            "hello".to_string() => "world".to_string(),
            "more1".to_string() => "hello hello this hopefully compresses well".to_string(),
            "more2".to_string() => "hello hello this hopefully compresses well".to_string(),
            "more3".to_string() => "hello hello this hopefully compresses well".to_string(),
        };

        // test compression and verify with expected size
        let mut buf = Vec::new();
        compress_json(&mut buf, &obj).unwrap();
        assert_eq!(buf.len(), 100);

        // document the uncompressed size for easier compare
        let uncompressed = serde_json::to_string(&obj).unwrap();
        assert_eq!(uncompressed.len(), 176);

        // test decompression
        let decompressed = decompress_json::<_, BTreeMap<String, String>>(&buf[..]).unwrap();
        assert_eq!(obj, decompressed);
    }

    #[test]
    fn test_parse_fetch_task() {
        let data = r#"
        {
            "FetchTar": {
                "url": "https://example.com/somefile.tar.gz"
            }
        }"#;
        let task_data: TaskData = serde_json::from_str(data).unwrap();
        assert_eq!(
            task_data,
            TaskData::FetchTar {
                url: "https://example.com/somefile.tar.gz".to_string(),
                success_ref: None,
            }
        );
    }

    #[test]
    fn test_parse_fetch_task_old_format() {
        // Still contains the compression key
        let data = r#"
        {
            "FetchTar": {
                "url": "https://example.com/somefile.tar.gz",
                "compression": "gz",
                "success_ref": {
                    "vendor": "examplevendor",
                    "package": "examplepackage",
                    "version": "1.0.0"
                }
            }
        }"#;
        let task_data: TaskData = serde_json::from_str(data).unwrap();
        assert_eq!(
            task_data,
            TaskData::FetchTar {
                url: "https://example.com/somefile.tar.gz".to_string(),
                success_ref: Some(DownloadRef {
                    vendor: "examplevendor".to_string(),
                    package: "examplepackage".to_string(),
                    version: "1.0.0".to_string(),
                }),
            }
        );
    }

    #[test]
    fn test_parse_ref_no_filename() {
        let r = Ref::new(
            "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0".to_string(),
            "vendor".to_string(),
            "package".to_string(),
            "version".to_string(),
            None,
        );
        assert_eq!(
            r,
            Ref {
                chksum: "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0"
                    .to_string(),
                vendor: "vendor".to_string(),
                package: "package".to_string(),
                version: "version".to_string(),
                filename: None,
                protocol: None,
                host: None,
            }
        );
    }

    #[test]
    fn test_parse_ref_simple_filename() {
        let r = Ref::new(
            "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0".to_string(),
            "vendor".to_string(),
            "package".to_string(),
            "version".to_string(),
            Some("foo-1.0.0.tar.gz".to_string()),
        );
        assert_eq!(
            r,
            Ref {
                chksum: "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0"
                    .to_string(),
                vendor: "vendor".to_string(),
                package: "package".to_string(),
                version: "version".to_string(),
                filename: Some("foo-1.0.0.tar.gz".to_string()),
                protocol: None,
                host: None,
            }
        );
    }

    #[test]
    fn test_parse_ref_unusual_filename_slashes() {
        let r = Ref::new(
            "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0".to_string(),
            "vendor".to_string(),
            "package".to_string(),
            "version".to_string(),
            Some("a/b/c://d/e/foo/bar-1.0.0.tar.gz".to_string()),
        );
        assert_eq!(
            r,
            Ref {
                chksum: "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0"
                    .to_string(),
                vendor: "vendor".to_string(),
                package: "package".to_string(),
                version: "version".to_string(),
                filename: Some("a/b/c://d/e/foo/bar-1.0.0.tar.gz".to_string()),
                protocol: None,
                host: None,
            }
        );
    }

    #[test]
    fn test_parse_ref_http_url() {
        let r = Ref::new(
            "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0".to_string(),
            "vendor".to_string(),
            "package".to_string(),
            "version".to_string(),
            Some("http://example.com/src/foo-1.0.0.tar.gz".to_string()),
        );
        assert_eq!(
            r,
            Ref {
                chksum: "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0"
                    .to_string(),
                vendor: "vendor".to_string(),
                package: "package".to_string(),
                version: "version".to_string(),
                filename: Some("http://example.com/src/foo-1.0.0.tar.gz".to_string()),
                protocol: Some("http".to_string()),
                host: Some("example.com".to_string()),
            }
        );
    }

    #[test]
    fn test_parse_ref_https_url() {
        let r = Ref::new(
            "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0".to_string(),
            "vendor".to_string(),
            "package".to_string(),
            "version".to_string(),
            Some("https://example.com/src/foo-1.0.0.tar.gz".to_string()),
        );
        assert_eq!(
            r,
            Ref {
                chksum: "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0"
                    .to_string(),
                vendor: "vendor".to_string(),
                package: "package".to_string(),
                version: "version".to_string(),
                filename: Some("https://example.com/src/foo-1.0.0.tar.gz".to_string()),
                protocol: Some("https".to_string()),
                host: Some("example.com".to_string()),
            }
        );
    }

    #[test]
    fn test_parse_ref_git_url() {
        let r = Ref::new(
            "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0".to_string(),
            "vendor".to_string(),
            "package".to_string(),
            "version".to_string(),
            Some("git+https://example.com/src/foo.git".to_string()),
        );
        assert_eq!(
            r,
            Ref {
                chksum: "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0"
                    .to_string(),
                vendor: "vendor".to_string(),
                package: "package".to_string(),
                version: "version".to_string(),
                filename: Some("git+https://example.com/src/foo.git".to_string()),
                protocol: Some("git+https".to_string()),
                host: Some("example.com".to_string()),
            }
        );
    }

    #[test]
    fn test_parse_ref_git_http_port_url() {
        let r = Ref::new(
            "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0".to_string(),
            "vendor".to_string(),
            "package".to_string(),
            "version".to_string(),
            Some("git+http://example.com:8080/src/foo.git".to_string()),
        );
        assert_eq!(
            r,
            Ref {
                chksum: "sha256:55f514c48ef9359b792e23abbad6ca8a1e999065ba8879d8717fecb52efc1ea0"
                    .to_string(),
                vendor: "vendor".to_string(),
                package: "package".to_string(),
                version: "version".to_string(),
                filename: Some("git+http://example.com:8080/src/foo.git".to_string()),
                protocol: Some("git+http".to_string()),
                host: Some("example.com".to_string()),
            }
        );
    }
}
