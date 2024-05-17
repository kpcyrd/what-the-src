use crate::errors::*;
use crate::sbom::Package;
use data_encoding::BASE64;
use std::collections::VecDeque;

pub const STRAIN: &str = "yarn-lock";
pub const VENDOR: &str = "registry.yarnpkg.com";

#[derive(Debug, PartialEq)]
pub struct YarnLock {
    pub data: String,
}

impl YarnLock {
    pub fn parse(&self) -> Result<ParsedLock> {
        let yarn = yarn_lock_parser::parse_str(&self.data)?;
        let mut packages = VecDeque::new();
        for entry in yarn {
            let checksum = if let Some((family, value)) = entry.integrity.split_once('-') {
                let digest = hex::encode(BASE64.decode(value.as_bytes())?);
                Some(format!("{family}:{digest}"))
            } else {
                None
            };

            packages.push_back(Package {
                name: entry.name.to_string(),
                version: entry.version.to_string(),
                checksum,
                official_registry: false,
            });
        }
        Ok(ParsedLock { packages })
    }
}

#[derive(Debug, PartialEq)]
pub struct ParsedLock {
    packages: VecDeque<Package>,
}

impl Iterator for ParsedLock {
    type Item = Package;

    fn next(&mut self) -> Option<Self::Item> {
        self.packages.pop_front()
    }
}
