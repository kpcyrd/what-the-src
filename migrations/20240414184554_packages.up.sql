CREATE TABLE packages (
    id bigserial PRIMARY KEY,
    vendor VARCHAR NOT NULL,
    package VARCHAR NOT NULL,
    version VARCHAR NOT NULL
);
CREATE INDEX packages_idx_vendor ON packages (vendor);
CREATE INDEX packages_idx_package ON packages (package);
CREATE UNIQUE INDEX packages_idx_uniq ON packages (vendor, package, version);
