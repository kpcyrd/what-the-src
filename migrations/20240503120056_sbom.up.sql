-- Add up migration script here
CREATE TABLE sboms (
    id bigserial PRIMARY KEY,
    chksum VARCHAR NOT NULL,
    strain VARCHAR NOT NULL,
    data VARCHAR NOT NULL
);

CREATE INDEX sboms_idx_strain ON sboms (strain);
CREATE INDEX sboms_idx_chksum ON sboms (chksum);
CREATE UNIQUE INDEX sboms_idx_uniq ON sboms (chksum, strain);

CREATE TABLE sbom_refs (
    from_archive VARCHAR NOT NULL,
    sbom_chksum VARCHAR NOT NULL,
    path VARCHAR NOT NULL,

    CONSTRAINT fk_from_archive
        FOREIGN KEY(from_archive)
        REFERENCES artifacts(chksum)
        ON DELETE CASCADE
);

CREATE INDEX sbom_refs_idx_from_archive ON sbom_refs (from_archive);
CREATE INDEX sbom_refs_idx_sbom_chksum ON sbom_refs (sbom_chksum);
CREATE UNIQUE INDEX sbom_refs_idx_uniq ON sbom_refs (from_archive, sbom_chksum, path);
