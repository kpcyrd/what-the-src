-- Add timestamps to artifacts
ALTER TABLE artifacts
DROP COLUMN db_version,
ADD COLUMN first_seen timestamptz NOT NULL DEFAULT NOW(),
ADD COLUMN last_imported timestamptz;

UPDATE artifacts
SET last_imported = to_timestamp(0);

ALTER TABLE artifacts
ALTER COLUMN last_imported SET NOT NULL;

-- Add timestamps to refs
ALTER TABLE refs
ADD COLUMN first_seen timestamptz NOT NULL DEFAULT NOW(),
ADD COLUMN last_seen timestamptz NOT NULL DEFAULT NOW();

ALTER TABLE refs
ALTER COLUMN last_seen DROP DEFAULT;
