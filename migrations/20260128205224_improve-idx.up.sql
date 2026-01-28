CREATE INDEX sbom_refs_idx_from_archive_path ON sbom_refs (from_archive, path);
CREATE INDEX aliases_idx_to_from_forward ON aliases (alias_to, alias_from);
CREATE INDEX sbom_refs_idx_chksum_strain_from_path ON sbom_refs (sbom_chksum, sbom_strain, from_archive, path);
CREATE INDEX refs_idx_search_package_id_desc ON refs (package, id DESC);
