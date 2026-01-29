use crate::errors::*;
use crate::sbom;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub const STRAIN: &str = "composer-lock";

#[derive(Debug, PartialEq)]
pub struct ComposerLock {
    pub data: String,
}

impl ComposerLock {
    pub fn parse(&self) -> Result<ParsedLock> {
        let lock = serde_json::from_str(&self.data)?;
        Ok(lock)
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct ParsedLock {
    packages: VecDeque<serde_json::Value>,
}

impl Iterator for ParsedLock {
    type Item = Result<sbom::Package>;

    fn next(&mut self) -> Option<Self::Item> {
        let package = self.packages.pop_front()?;
        match serde_json::from_value::<Package>(package) {
            Ok(pkg) => Some(Ok(pkg.into())),
            Err(err) => Some(Err(err.into())),
        }
    }
}

impl From<Package> for sbom::Package {
    fn from(sbom: Package) -> Self {
        let valid_git_ref =
            sbom.source.src_type == "git" && sbom.source.url.starts_with("https://");

        let url = valid_git_ref.then(|| sbom.source.url.clone());

        let checksum = valid_git_ref.then(|| format!("git:{}", sbom.source.reference));

        Self {
            name: sbom.name,
            version: sbom.version,
            checksum,
            url,
            official_registry: true,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: Source,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Source {
    #[serde(rename = "type")]
    pub src_type: String,
    pub url: String,
    pub reference: String,
}

#[cfg(test)]
mod tests {
    use crate::sbom::{Package, Sbom};

    #[test]
    fn test_parse_composer_lock() {
        let data = r#"
{
    "_readme": [
        "This file locks the dependencies of your project to a known state",
        "Read more about it at https://getcomposer.org/doc/01-basic-usage.md#installing-dependencies",
        "This file is @generated automatically"
    ],
    "content-hash": "79a1ca4e4dd21ebe94b6eafab28afb65",
    "packages": [
        {
            "name": "amphp/amp",
            "version": "v3.1.1",
            "source": {
                "type": "git",
                "url": "https://github.com/amphp/amp.git",
                "reference": "fa0ab33a6f47a82929c38d03ca47ebb71086a93f"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/amphp/amp/zipball/fa0ab33a6f47a82929c38d03ca47ebb71086a93f",
                "reference": "fa0ab33a6f47a82929c38d03ca47ebb71086a93f",
                "shasum": ""
            },
            "require": {
                "php": ">=8.1",
                "revolt/event-loop": "^1 || ^0.2"
            },
            "require-dev": {
                "amphp/php-cs-fixer-config": "^2",
                "phpunit/phpunit": "^9",
                "psalm/phar": "5.23.1"
            },
            "type": "library",
            "autoload": {
                "files": [
                    "src/functions.php",
                    "src/Future/functions.php",
                    "src/Internal/functions.php"
                ],
                "psr-4": {
                    "Amp\\": "src"
                }
            },
            "notification-url": "https://packagist.org/downloads/",
            "license": [
                "MIT"
            ],
            "authors": [
                {
                    "name": "Aaron Piotrowski",
                    "email": "aaron@trowski.com"
                },
                {
                    "name": "Bob Weinand",
                    "email": "bobwei9@hotmail.com"
                },
                {
                    "name": "Niklas Keller",
                    "email": "me@kelunik.com"
                },
                {
                    "name": "Daniel Lowrey",
                    "email": "rdlowrey@php.net"
                }
            ],
            "description": "A non-blocking concurrency framework for PHP applications.",
            "homepage": "https://amphp.org/amp",
            "keywords": [
                "async",
                "asynchronous",
                "awaitable",
                "concurrency",
                "event",
                "event-loop",
                "future",
                "non-blocking",
                "promise"
            ],
            "support": {
                "issues": "https://github.com/amphp/amp/issues",
                "source": "https://github.com/amphp/amp/tree/v3.1.1"
            },
            "funding": [
                {
                    "url": "https://github.com/amphp",
                    "type": "github"
                }
            ],
            "time": "2025-08-27T21:42:00+00:00"
        },
        {
            "name": "amphp/byte-stream",
            "version": "v2.1.2",
            "source": {
                "type": "git",
                "url": "https://github.com/amphp/byte-stream.git",
                "reference": "55a6bd071aec26fa2a3e002618c20c35e3df1b46"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/amphp/byte-stream/zipball/55a6bd071aec26fa2a3e002618c20c35e3df1b46",
                "reference": "55a6bd071aec26fa2a3e002618c20c35e3df1b46",
                "shasum": ""
            },
            "require": {
                "amphp/amp": "^3",
                "amphp/parser": "^1.1",
                "amphp/pipeline": "^1",
                "amphp/serialization": "^1",
                "amphp/sync": "^2",
                "php": ">=8.1",
                "revolt/event-loop": "^1 || ^0.2.3"
            },
            "require-dev": {
                "amphp/php-cs-fixer-config": "^2",
                "amphp/phpunit-util": "^3",
                "phpunit/phpunit": "^9",
                "psalm/phar": "5.22.1"
            },
            "type": "library",
            "autoload": {
                "files": [
                    "src/functions.php",
                    "src/Internal/functions.php"
                ],
                "psr-4": {
                    "Amp\\ByteStream\\": "src"
                }
            },
            "notification-url": "https://packagist.org/downloads/",
            "license": [
                "MIT"
            ],
            "authors": [
                {
                    "name": "Aaron Piotrowski",
                    "email": "aaron@trowski.com"
                },
                {
                    "name": "Niklas Keller",
                    "email": "me@kelunik.com"
                }
            ],
            "description": "A stream abstraction to make working with non-blocking I/O simple.",
            "homepage": "https://amphp.org/byte-stream",
            "keywords": [
                "amp",
                "amphp",
                "async",
                "io",
                "non-blocking",
                "stream"
            ],
            "support": {
                "issues": "https://github.com/amphp/byte-stream/issues",
                "source": "https://github.com/amphp/byte-stream/tree/v2.1.2"
            },
            "funding": [
                {
                    "url": "https://github.com/amphp",
                    "type": "github"
                }
            ],
            "time": "2025-03-16T17:10:27+00:00"
        },
        {
            "name": "psalm/plugin-mockery",
            "version": "1.2.1",
            "source": {
                "type": "git",
                "url": "https://github.com/psalm/psalm-plugin-mockery.git",
                "reference": "684e5b53f80b0879e92335301f612b006f0f73f4"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/psalm/psalm-plugin-mockery/zipball/684e5b53f80b0879e92335301f612b006f0f73f4",
                "reference": "684e5b53f80b0879e92335301f612b006f0f73f4",
                "shasum": ""
            },
            "require": {
                "composer/package-versions-deprecated": "^1.10",
                "composer/semver": "^1.4 || ^2.0 || ^3.0",
                "mockery/mockery": "^1.0",
                "php": ">=8.1",
                "vimeo/psalm": "dev-master || ^5.0 || ^6 || ^7"
            },
            "require-dev": {
                "codeception/codeception": "^4.1.9",
                "phpunit/phpunit": "^9.0",
                "squizlabs/php_codesniffer": "^3.3.1",
                "weirdan/codeception-psalm-module": "^0.13.1"
            },
            "type": "psalm-plugin",
            "extra": {
                "psalm": {
                    "pluginClass": "Psalm\\MockeryPlugin\\Plugin"
                }
            },
            "autoload": {
                "psr-4": {
                    "Psalm\\MockeryPlugin\\": [
                        "."
                    ]
                }
            },
            "notification-url": "https://packagist.org/downloads/",
            "license": [
                "MIT"
            ],
            "authors": [
                {
                    "name": "Matt Brown",
                    "email": "github@muglug.com"
                }
            ],
            "description": "Psalm plugin for Mockery",
            "support": {
                "issues": "https://github.com/psalm/psalm-plugin-mockery/issues",
                "source": "https://github.com/psalm/psalm-plugin-mockery/tree/1.2.1"
            },
            "time": "2025-03-20T10:51:18+00:00"
        },
        {
            "name": "psalm/plugin-phpunit",
            "version": "0.19.5",
            "source": {
                "type": "dummy",
                "url": "https://github.com/psalm/psalm-plugin-phpunit.git",
                "reference": "143f9d5e049fffcdbc0da3fbb99f6149f9d3e2dc"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/psalm/psalm-plugin-phpunit/zipball/143f9d5e049fffcdbc0da3fbb99f6149f9d3e2dc",
                "reference": "143f9d5e049fffcdbc0da3fbb99f6149f9d3e2dc",
                "shasum": ""
            },
            "require": {
                "ext-simplexml": "*",
                "php": ">=8.1",
                "vimeo/psalm": "dev-master || ^6.10.0"
            },
            "conflict": {
                "phpspec/prophecy": "<1.20.0",
                "phpspec/prophecy-phpunit": "<2.3.0",
                "phpunit/phpunit": "<8.5.1"
            },
            "require-dev": {
                "php": "^7.3 || ^8.0",
                "phpunit/phpunit": "^10.0 || ^11.0 || ^12.0",
                "squizlabs/php_codesniffer": "^3.3.1",
                "weirdan/prophecy-shim": "^1.0 || ^2.0"
            },
            "type": "psalm-plugin",
            "extra": {
                "psalm": {
                    "pluginClass": "Psalm\\PhpUnitPlugin\\Plugin"
                }
            },
            "autoload": {
                "psr-4": {
                    "Psalm\\PhpUnitPlugin\\": "src"
                }
            },
            "notification-url": "https://packagist.org/downloads/",
            "license": [
                "MIT"
            ],
            "authors": [
                {
                    "name": "Matt Brown",
                    "email": "github@muglug.com"
                }
            ],
            "description": "Psalm plugin for PHPUnit",
            "support": {
                "issues": "https://github.com/psalm/psalm-plugin-phpunit/issues",
                "source": "https://github.com/psalm/psalm-plugin-phpunit/tree/0.19.5"
            },
            "time": "2025-03-31T18:49:55+00:00"
        }
    ],
    "aliases": [],
    "minimum-stability": "dev",
    "stability-flags": {},
    "prefer-stable": true,
    "prefer-lowest": false,
    "platform": {
        "php": "~8.1.31 || ~8.2.27 || ~8.3.16 || ~8.4.3 || ~8.5.0",
        "ext-simplexml": "*",
        "ext-ctype": "*",
        "ext-dom": "*",
        "ext-json": "*",
        "ext-libxml": "*",
        "ext-mbstring": "*",
        "ext-tokenizer": "*",
        "composer-runtime-api": "^2"
    },
    "platform-dev": {
        "ext-curl": "*"
    },
    "plugin-api-version": "2.9.0"
}
"#;
        let composer = Sbom::new("composer-lock", data.to_string()).unwrap();
        let list = composer.to_packages().unwrap();
        assert_eq!(
            list,
            [
                Package {
                    name: "amphp/amp".to_string(),
                    version: "v3.1.1".to_string(),
                    checksum: Some("git:fa0ab33a6f47a82929c38d03ca47ebb71086a93f".to_string()),
                    url: Some("https://github.com/amphp/amp.git".to_string()),
                    official_registry: true
                },
                Package {
                    name: "amphp/byte-stream".to_string(),
                    version: "v2.1.2".to_string(),
                    checksum: Some("git:55a6bd071aec26fa2a3e002618c20c35e3df1b46".to_string()),
                    url: Some("https://github.com/amphp/byte-stream.git".to_string()),
                    official_registry: true
                },
                Package {
                    name: "psalm/plugin-mockery".to_string(),
                    version: "1.2.1".to_string(),
                    checksum: Some("git:684e5b53f80b0879e92335301f612b006f0f73f4".to_string()),
                    url: Some("https://github.com/psalm/psalm-plugin-mockery.git".to_string()),
                    official_registry: true
                },
                Package {
                    name: "psalm/plugin-phpunit".to_string(),
                    version: "0.19.5".to_string(),
                    checksum: None,
                    url: None,
                    official_registry: true
                }
            ]
        );
    }
}
