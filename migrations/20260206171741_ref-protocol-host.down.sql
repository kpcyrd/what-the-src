DROP INDEX refs_idx_host_filename;

ALTER TABLE refs
    DROP COLUMN protocol,
    DROP COLUMN host;
