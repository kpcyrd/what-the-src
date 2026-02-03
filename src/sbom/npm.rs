use crate::errors::*;
use crate::sbom::{self, Package};
use data_encoding::BASE64;
use serde::Deserialize;
use std::collections::BTreeMap;

pub const STRAIN: &str = "package-lock-json";
pub const VENDOR: &str = "registry.npmjs.org";

#[derive(Debug, PartialEq)]
pub struct PackageLockJson {
    pub data: String,
}

impl PackageLockJson {
    pub fn parse(&self) -> Result<ParsedLock> {
        let json = serde_json::from_str(&self.data)?;
        Ok(json)
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct ParsedLock {
    #[serde(default)]
    packages: BTreeMap<String, NpmPackage>,
}

impl Iterator for ParsedLock {
    type Item = Package;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((name, package)) = self.packages.pop_first() {
            let Some(name) = package
                .name
                .as_deref()
                .or_else(|| name.strip_prefix("node_modules/"))
                .filter(|name| !name.is_empty())
            else {
                continue;
            };

            // Extract the checksum in our format (if possible)
            let checksum = package
                .integrity
                .as_deref()
                .and_then(|integrity| integrity.split_once('-'))
                .and_then(|(family, value)| Some((family, BASE64.decode(value.as_bytes()).ok()?)))
                .map(|(family, bytes)| {
                    let digest = hex::encode(bytes);
                    format!("{family}:{digest}")
                });

            let official_registry = package
                .resolved
                .as_deref()
                .and_then(|url| url.strip_prefix("https://registry.npmjs.org/"))
                .and_then(|url| url.strip_prefix(name))
                .and_then(|url| url.strip_prefix("/-/"))
                .is_some();

            return Some(sbom::Package {
                name: name.to_string(),
                version: package.version,
                url: package.resolved,
                checksum,
                official_registry,
            });
        }

        None
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct NpmPackage {
    pub name: Option<String>,
    pub version: String,
    pub resolved: Option<String>,
    pub integrity: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::sbom::{Package, Sbom};

    #[test]
    fn test_parse_package_lock_json() {
        let data = r#"
{
  "name": "@techaro/anubis",
  "version": "1.24.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "@techaro/anubis",
      "version": "1.24.0",
      "license": "ISC",
      "dependencies": {
        "@aws-crypto/sha256-js": "^5.2.0",
        "preact": "^10.28.2"
      },
      "devDependencies": {
        "cssnano": "^7.1.2",
        "cssnano-preset-advanced": "^7.0.10",
        "esbuild": "^0.27.2",
        "playwright": "^1.52.0",
        "postcss-cli": "^11.0.1",
        "postcss-import": "^16.1.1",
        "postcss-import-url": "^7.2.0",
        "postcss-url": "^10.1.3"
      }
    },
    "node_modules/@aws-crypto/sha256-js": {
      "version": "5.2.0",
      "resolved": "https://registry.npmjs.org/@aws-crypto/sha256-js/-/sha256-js-5.2.0.tgz",
      "integrity": "sha512-FFQQyu7edu4ufvIZ+OadFpHHOt+eSTBaYaki44c+akjg7qZg9oOQeLlk77F6tSYqjDAFClrHJk9tMf0HdVyOvA==",
      "license": "Apache-2.0",
      "dependencies": {
        "@aws-crypto/util": "^5.2.0",
        "@aws-sdk/types": "^3.222.0",
        "tslib": "^2.6.2"
      },
      "engines": {
        "node": ">=16.0.0"
      }
    },
    "node_modules/fs-extra": {
      "version": "11.3.1",
      "resolved": "https://registry.npmjs.org/fs-extra/-/fs-extra-11.3.1.tgz",
      "integrity": "sha512-eXvGGwZ5CL17ZSwHWd3bbgk7UUpF6IFHtP57NYYakPvHOs8GDgDe5KJI36jIJzDkJ6eJjuzRA8eBQb6SkKue0g==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "graceful-fs": "^4.2.0",
        "jsonfile": "^6.0.1",
        "universalify": "^2.0.0"
      },
      "engines": {
        "node": ">=14.14"
      }
    },
    "node_modules/fsevents": {
      "version": "2.3.2",
      "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.2.tgz",
      "integrity": "sha512-xiqMQR4xAeHTuB9uWm+fFRcIOgKBMiOBP+eXiyT7jsgVCq1bkVygt00oASowB7EdtpOHaaPgKt812P9ab+DDKA==",
      "dev": true,
      "hasInstallScript": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": "^8.16.0 || ^10.6.0 || >=11.0.0"
      }
    },
    "node_modules/tinyglobby": {
      "version": "0.2.15",
      "resolved": "https://registry.npmjs.org/tinyglobby/-/tinyglobby-0.2.15.tgz",
      "integrity": "sha512-j2Zq4NyQYG5XMST4cbs02Ak8iJUdxRM0XI5QyxXuZOzKOINmWurp3smXu3y5wDcJrptwpSjgXHzIQxR0omXljQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "fdir": "^6.5.0",
        "picomatch": "^4.0.3"
      },
      "engines": {
        "node": ">=12.0.0"
      },
      "funding": {
        "url": "https://github.com/sponsors/SuperchupuDev"
      }
    },
    "node_modules/tinyglobby/node_modules/fdir": {
      "version": "6.5.0",
      "resolved": "https://registry.npmjs.org/fdir/-/fdir-6.5.0.tgz",
      "integrity": "sha512-tIbYtZbucOs0BRGqPJkshJUYdL+SDH7dVM8gjy+ERp3WAUjLEFJE+02kanyHtwjWOnwrKYBiwAmM0p4kLJAnXg==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=12.0.0"
      },
      "peerDependencies": {
        "picomatch": "^3 || ^4"
      },
      "peerDependenciesMeta": {
        "picomatch": {
          "optional": true
        }
      }
    },
    "node_modules/tinyglobby/node_modules/picomatch": {
      "version": "4.0.3",
      "resolved": "https://registry.npmjs.org/picomatch/-/picomatch-4.0.3.tgz",
      "integrity": "sha512-5gTmgEY/sqK6gFXLIsQNH19lWb4ebPDLA4SdLP7dsWkIXHWlG66oPuVvXSGFPppYZz8ZDZq0dYYrbHfBCVUb1Q==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=12"
      },
      "funding": {
        "url": "https://github.com/sponsors/jonschlinkert"
      }
    }
  }
}
"#;
        let yarn = Sbom::new("package-lock-json", data.to_string()).unwrap();
        let list = yarn.to_packages().unwrap();
        assert_eq!(
            list,
            [
                Package {
                    name: "@techaro/anubis".to_string(),
                    version: "1.24.0".to_string(),
                    url: None,
                    checksum: None,
                    official_registry: false
                },
                Package {
                    name: "@aws-crypto/sha256-js".to_string(),
                    version: "5.2.0".to_string(),
                    url: Some(
                        "https://registry.npmjs.org/@aws-crypto/sha256-js/-/sha256-js-5.2.0.tgz".to_string()
                    ),
                    checksum: Some(
                        "sha512:145410caeede76ee2e7ef219f8e69d1691c73adf9e49305a61a922e3873e6a48e0eea660f6839078b964efb17ab5262a8c30050a5ac7264f6d31fd07755c8ebc".to_string()
                    ),
                    official_registry: true
                },
                Package {
                    name: "fs-extra".to_string(),
                    version: "11.3.1".to_string(),
                    url: Some(
                        "https://registry.npmjs.org/fs-extra/-/fs-extra-11.3.1.tgz".to_string()
                    ),
                    checksum: Some(
                        "sha512:797bc61b067908bd7b652c0759dddb6e093b514a45e88147b4fe7b35861a90fbc73acf060e00dee4a248dfa8c82730e427a7898eecd103c78141be9290ab9ed2".to_string()
                    ),
                    official_registry: true
                },
                Package {
                    name: "fsevents".to_string(),
                    version: "2.3.2".to_string(),
                    url: Some(
                        "https://registry.npmjs.org/fsevents/-/fsevents-2.3.2.tgz".to_string()
                    ),
                    checksum: Some(
                        "sha512:c62a8c411e3101e1d3b81f6e5a6f9f1517083a02813223813fe7978b24fb8ec8150aad5b915ca0b74d28012a3007b11db6938769a3e02adf35d8ff5a6fe0c328".to_string()
                    ),
                    official_registry: true
                },
                Package {
                    name: "tinyglobby".to_string(),
                    version: "0.2.15".to_string(),
                    url: Some(
                        "https://registry.npmjs.org/tinyglobby/-/tinyglobby-0.2.15.tgz".to_string()
                    ),
                    checksum: Some(
                        "sha512:8f666ae0dc90606e573124f871bb34d8093c88951dc513345c8e50cb15ee64ecca3883665aeae9dec997bb7cb9c03709ae9b70a528e05c7cc8431474a265e58d".to_string()
                    ),
                    official_registry: true
                },
                Package {
                    name: "tinyglobby/node_modules/fdir".to_string(),
                    version: "6.5.0".to_string(),
                    url: Some(
                        "https://registry.npmjs.org/fdir/-/fdir-6.5.0.tgz".to_string()
                    ),
                    checksum: Some(
                        "sha512:b486d8b596ee70eb340511aa3c992c84951874bf920c7edd54cf208f2f84469dd60148cb105244fb4da46a7c87b708d63a7c2b298062c0098cd29e242c90275e".to_string()
                    ),
                    official_registry: false
                },
                Package {
                    name: "tinyglobby/node_modules/picomatch".to_string(),
                    version: "4.0.3".to_string(),
                    url: Some(
                        "https://registry.npmjs.org/picomatch/-/picomatch-4.0.3.tgz".to_string()
                    ),
                    checksum: Some(
                        "sha512:e604e680463fb2a2ba8055cb22c40d1f5f6559be1e6cf0cb03849d2cfeddb169085c75a51baea83ee56f5d21853e9a58673f190d9ab475862b6c77c109551bd5".to_string()
                    ),
                    official_registry: false
                },
            ]
        );
    }
}
