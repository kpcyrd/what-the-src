CREATE TABLE artifacts (
    chksum VARCHAR PRIMARY KEY,
    db_version SMALLINT NOT NULL,
    files JSON
);

CREATE TABLE aliases (
    alias_from VARCHAR PRIMARY KEY,
    alias_to VARCHAR NOT NULL,
    reason VARCHAR,

    CONSTRAINT fk_artifact
        FOREIGN KEY(alias_to)
        REFERENCES artifacts(chksum)
        ON DELETE CASCADE
);
CREATE INDEX aliases_idx_to ON aliases (alias_to);
CREATE INDEX aliases_idx_from ON aliases (alias_from);
CREATE UNIQUE INDEX aliases_idx_uniq ON aliases (alias_to);

CREATE TABLE refs (
    id bigserial PRIMARY KEY,
    chksum VARCHAR NOT NULL,
    vendor VARCHAR NOT NULL,
    package VARCHAR NOT NULL,
    version VARCHAR NOT NULL,
    filename VARCHAR
);
CREATE INDEX refs_idx_chksum ON refs (chksum);
CREATE UNIQUE INDEX refs_idx_uniq ON refs (chksum, vendor, package, version);
