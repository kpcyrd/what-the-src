ALTER TABLE artifacts
DROP COLUMN first_seen,
DROP COLUMN last_imported,
ADD COLUMN db_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE refs
DROP COLUMN first_seen,
DROP COLUMN last_seen;
