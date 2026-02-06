ALTER TABLE refs
    ADD COLUMN protocol VARCHAR,
    ADD COLUMN host VARCHAR;

CREATE INDEX refs_idx_host_filename
    ON refs (host, filename)
    WHERE host IS NOT NULL AND filename IS NOT NULL;
