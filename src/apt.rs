use crate::errors::*;
use apt_parser::ReleaseHash;
use apt_parser::errors::{APTError, ParseError};
use std::str;

#[derive(Debug, PartialEq)]
pub struct SourcesIndex {
    pub pkgs: Vec<SourcePkg>,
}

impl SourcesIndex {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let sources = str::from_utf8(bytes)?;

        let mut pkgs = Vec::new();

        let mut package = None;
        let mut in_checksums_sha256_section = false;
        for line in sources.lines() {
            if let Some(value) = line.strip_prefix("Package: ") {
                package = Some(SourcePkg {
                    package: value.to_string(),
                    ..Default::default()
                });
            } else if let Some(value) = line.strip_prefix("Version: ") {
                let Some(package) = package.as_mut() else {
                    continue;
                };
                package.version = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("Directory: ") {
                let Some(package) = package.as_mut() else {
                    continue;
                };
                package.directory = Some(value.to_string());
            } else if line.is_empty() {
                if let Some(package) = package.take() {
                    pkgs.push(package);
                }
            } else if line.trim_end() == "Checksums-Sha256:" {
                in_checksums_sha256_section = true;
            } else if let Some(line) = line.strip_prefix(' ') {
                if !in_checksums_sha256_section {
                    continue;
                }

                let Some(package) = package.as_mut() else {
                    continue;
                };

                let (hash, line) = line
                    .split_once(' ')
                    .ok_or(APTError::ParseError(ParseError))?;

                let (size, filename) = line
                    .split_once(' ')
                    .ok_or(APTError::ParseError(ParseError))?;
                let size = size
                    .parse()
                    .map_err(|_err| APTError::ParseError(ParseError))?;

                package.checksums_sha256.push(ReleaseHash {
                    hash: hash.to_string(),
                    size,
                    filename: filename.to_string(),
                });
            } else {
                in_checksums_sha256_section = false;
            }
        }

        Ok(SourcesIndex { pkgs })
    }

    pub fn find_pkg_by_sha256(
        &self,
        filter_name: Option<&str>,
        filter_version: Option<&str>,
        sha256: &str,
    ) -> Result<&SourcePkg> {
        for pkg in &self.pkgs {
            trace!("Found package in sources index: {pkg:?}");

            if let Some(name) = filter_name
                && pkg.package != *name
            {
                trace!("Skipping due to package name mismatch");
                continue;
            }

            if let Some(version) = filter_version
                && pkg.version.as_deref() != Some(version)
            {
                trace!("Skipping due to package version mismatch");
                continue;
            }

            for chksum in &pkg.checksums_sha256 {
                if !chksum.filename.ends_with(".orig.tar.gz")
                    && !chksum.filename.ends_with(".orig.tar.xz")
                {
                    continue;
                }

                if chksum.hash == sha256 {
                    info!("File verified successfully");
                    return Ok(pkg);
                }
            }
        }

        Err(APTError::ParseError(ParseError).into())
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct SourcePkg {
    pub package: String,
    pub version: Option<String>,
    pub directory: Option<String>,
    pub checksums_sha256: Vec<ReleaseHash>,
}

pub struct Release {
    release: apt_parser::Release,
}

impl Release {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let release = str::from_utf8(bytes)?;
        let release = apt_parser::Release::from(release)?;
        Ok(Release { release })
    }

    pub fn find_source_entry_by_sha256(&self, sha256: &str) -> Result<&ReleaseHash> {
        let sha256sums = self
            .release
            .sha256sum
            .as_ref()
            .ok_or(APTError::ParseError(ParseError))?;

        let sources_entry = sha256sums
            .iter()
            .filter(|entry| entry.filename.contains("/source/Sources"))
            .find(|entry| {
                debug!("Found sha256sum entry for sources index: {entry:?}");
                entry.hash == sha256
            })
            .ok_or(APTError::ParseError(ParseError))?;

        Ok(sources_entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kali() {
        let data = br#"Package: sn0int
Format: 3.0 (quilt)
Binary: sn0int
Architecture: any
Version: 0.26.0-0kali3
Maintainer: Kali Developers <devel@kali.org>
Uploaders: Sophie Brun <sophie@offensive-security.com>
Homepage: https://github.com/kpcyrd/sn0int
Standards-Version: 4.6.2
Vcs-Browser: https://gitlab.com/kalilinux/packages/sn0int
Vcs-Git: https://gitlab.com/kalilinux/packages/sn0int.git
Build-Depends: bash-completion, ca-certificates, debhelper-compat (= 13), libseccomp-dev, libsodium-dev, libsqlite3-dev, pkg-config, publicsuffix, python3-sphinx, cargo
Package-List:
 sn0int deb net optional arch=any
Priority: optional
Section: net
Directory: pool/main/s/sn0int
Files: 
 a2f2a9f592c506b6a746dc9debd1cacd 1807 sn0int_0.26.0-0kali3.dsc
 5c5578537a0abe07b683f8b454af025d 1798079 sn0int_0.26.0.orig.tar.gz
 b103d74ae55843b0f87112988062be54 8648 sn0int_0.26.0-0kali3.debian.tar.xz
Checksums-Sha1: 
 0545bcbba1fcf73b6bd5ba830124ccec7abbf5f8 1807 sn0int_0.26.0-0kali3.dsc
 e0b7135bd653540cdc234e2aa334eb1d4bba27f6 1798079 sn0int_0.26.0.orig.tar.gz
 d02663536e05ffc292f139d3727a140886c21023 8648 sn0int_0.26.0-0kali3.debian.tar.xz
Checksums-Sha256: 
 6075e8c34b5a08aea77319e1346e42b846b7ee460d2c6ea2bb58e1ab6a651674 1807 sn0int_0.26.0-0kali3.dsc
 4ce71f69410a9c9470edf922c3c09b6a53bfbf41d154aa124859bbce8014cf13 1798079 sn0int_0.26.0.orig.tar.gz
 206f6f924a3b79f5495c512e965a0d44915c9b0a2b8c32feac7aac12f1ca1aa9 8648 sn0int_0.26.0-0kali3.debian.tar.xz

"#;
        let index = SourcesIndex::parse(data).unwrap();
        assert_eq!(
            index,
            SourcesIndex {
                pkgs: vec![SourcePkg {
                    package: "sn0int".to_string(),
                    version: Some("0.26.0-0kali3".to_string()),
                    directory: Some("pool/main/s/sn0int".to_string()),
                    checksums_sha256: vec![
                        ReleaseHash {
                            filename: "sn0int_0.26.0-0kali3.dsc".to_string(),
                            hash:
                                "6075e8c34b5a08aea77319e1346e42b846b7ee460d2c6ea2bb58e1ab6a651674"
                                    .to_string(),
                            size: 1807
                        },
                        ReleaseHash {
                            filename: "sn0int_0.26.0.orig.tar.gz".to_string(),
                            hash:
                                "4ce71f69410a9c9470edf922c3c09b6a53bfbf41d154aa124859bbce8014cf13"
                                    .to_string(),
                            size: 1798079
                        },
                        ReleaseHash {
                            filename: "sn0int_0.26.0-0kali3.debian.tar.xz".to_string(),
                            hash:
                                "206f6f924a3b79f5495c512e965a0d44915c9b0a2b8c32feac7aac12f1ca1aa9"
                                    .to_string(),
                            size: 8648
                        }
                    ],
                }]
            }
        );
    }
}
