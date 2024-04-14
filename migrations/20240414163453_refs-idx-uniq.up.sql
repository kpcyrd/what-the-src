DROP INDEX refs_idx_uniq;
CREATE UNIQUE INDEX refs_idx_uniq ON refs (chksum, vendor, package, version);
