use crate::args;
use crate::db;
use crate::errors::*;
use crate::utils;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Build {
    pub package: Package,
    #[serde(default)]
    pub var_transforms: Vec<Transform>,
    pub pipeline: Vec<Step>,
}

impl Build {
    pub fn parse(yaml: &str) -> Result<Build> {
        let build = serde_yaml::from_str(yaml)?;
        Ok(build)
    }

    pub fn substitute_ref(&self, name: &str) -> Result<String> {
        if name == "package.version" {
            Ok(self.package.version.to_string())
        } else if let Some(name) = name.strip_prefix("vars.") {
            self.transform(name)
        } else {
            Err(Error::WolfiUnknownSubstitute(name.to_string()))
        }
    }

    pub fn transform(&self, name: &str) -> Result<String> {
        let Some(transform) = self.var_transforms.iter().find(|t| t.to == name) else {
            return Err(Error::WolfiUnknownSubstitute(name.to_string()));
        };
        let from = self.interpolate(&transform.from)?;
        let re = Regex::new(&transform.pattern)?;
        let value = re.replace_all(&from, &transform.replace);
        Ok(value.into_owned())
    }

    pub fn interpolate(&self, mut text: &str) -> Result<String> {
        let mut out = String::new();
        while !text.is_empty() {
            if let Some((before, after)) = text.split_once("${{") {
                out.push_str(before);
                let Some((name, after)) = after.split_once("}}") else {
                    break;
                };
                out.push_str(&self.substitute_ref(name)?);
                text = after;
            } else {
                out.push_str(text);
                text = "";
            }
        }
        Ok(out)
    }

    pub fn collect_sources(&self) -> Result<Vec<Source>> {
        let mut sources = Vec::new();
        for step in &self.pipeline {
            match step.uses.as_deref() {
                Some("fetch") => {
                    let Some(url) = step.with.get("uri") else {
                        continue;
                    };
                    let chksum = if let Some(value) = step.with.get("expected-sha256") {
                        format!("sha256:{value}")
                    } else if let Some(value) = step.with.get("expected-sha512") {
                        format!("sha512:{value}")
                    } else {
                        return Err(Error::WolfiMissingChecksum(step.clone()));
                    };
                    sources.push(Source {
                        url: self.interpolate(url)?,
                        chksum,
                    });
                }
                Some("git-checkout") => {
                    let Some(repository) = step.with.get("repository") else {
                        continue;
                    };
                    let Some(tag) = step.with.get("tag") else {
                        continue;
                    };
                    let Some(commit) = step.with.get("expected-commit") else {
                        continue;
                    };

                    let repository = self.interpolate(repository)?;
                    let tag = self.interpolate(tag)?;

                    let url = format!("git+{repository}#tag={tag}");
                    let chksum = format!("git:{commit}");

                    sources.push(Source { url, chksum });
                }
                _ => (),
            }
        }
        Ok(sources)
    }
}

#[derive(Debug, PartialEq)]
pub struct Source {
    pub url: String,
    pub chksum: String,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub epoch: u32,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Transform {
    pub from: String,
    #[serde(rename = "match")]
    pub pattern: String,
    pub replace: String,
    pub to: String,
}

#[derive(Debug, PartialEq, Clone, Deserialize)]
pub struct Step {
    pub uses: Option<String>,
    #[serde(default)]
    pub with: HashMap<String, String>,
}

pub async fn stream_data<R: AsyncRead + Unpin>(
    db: &db::Client,
    mut reader: R,
    vendor: &str,
    package: &str,
    version: &str,
) -> Result<()> {
    let mut buf = String::new();
    reader.read_to_string(&mut buf).await?;

    let build = Build::parse(&buf)?;
    for source in build.collect_sources()? {
        debug!("source={source:?}");
        let url = source.url;

        let Some(task) = utils::task_for_url(&url) else {
            continue;
        };
        db.insert_task(&task).await?;

        let r = db::Ref::new(
            source.chksum,
            vendor.to_string(),
            package.to_string(),
            version.to_string(),
            Some(url),
        );
        info!("insert: {r:?}");
        db.insert_ref(&r).await?;
    }

    Ok(())
}

pub async fn run(args: &args::IngestWolfi) -> Result<()> {
    let db = db::Client::create().await?;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    stream_data(&db, reader, &args.vendor, &args.package, &args.version).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bzip2() {
        let data = r#"
package:
  name: bzip2
  version: 1.0.8
  epoch: 4
  description: "a library implementing the bzip2 compression algorithms"
  copyright:
    - license: MPL-2.0 AND MIT
  dependencies:
    runtime:

environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/bootstrap/stage3
    keyring:
      - https://packages.wolfi.dev/bootstrap/stage3/wolfi-signing.rsa.pub
    packages:
      - wolfi-baselayout
      - busybox
      - ca-certificates-bundle
      - build-base
      - make

pipeline:
  - uses: fetch
    with:
      uri: https://sourceware.org/pub/bzip2/bzip2-${{package.version}}.tar.gz
      expected-sha256: ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269

  - uses: patch
    with:
      patches: bzip2-1.0.2-progress.patch

  - uses: patch
    with:
      patches: bzip2-1.0.3-no-test.patch

  - uses: patch
    with:
      patches: bzip2-1.0.4-makefile-CFLAGS.patch

  - uses: patch
    with:
      patches: bzip2-1.0.4-man-links.patch

  - uses: patch
    with:
      patches: saneso.patch

  - runs: |
      sed -i \
        -e 's:\$(PREFIX)/man:\$(PREFIX)/share/man:g' \
        -e 's:ln -s -f $(PREFIX)/bin/:ln -s :' \
        Makefile

      sed -i \
        -e "s:1\.0\.4:${{package.version}}:" \
        bzip2.1 bzip2.txt Makefile-libbz2_so manual.*

  - runs: |
      make -f Makefile-libbz2_so all
      make all

  - runs: |
      make PREFIX="${{targets.destdir}}/usr" install

      install -D libbz2.so.${{package.version}} "${{targets.destdir}}"/usr/lib/libbz2.so.${{package.version}}
      ln -s libbz2.so.${{package.version}} "${{targets.destdir}}"/usr/lib/libbz2.so
      ln -s libbz2.so.${{package.version}} "${{targets.destdir}}"/usr/lib/libbz2.so.1

  - uses: strip

subpackages:
  - name: "bzip2-dev"
    description: "bzip2 headers"
    pipeline:
      - uses: split/dev
    dependencies:
      runtime:
        - bzip2

update:
  enabled: true
  release-monitor:
    identifier: 237
"#;
        let build = Build::parse(data).unwrap();
        assert_eq!(
            build,
            Build {
                package: Package {
                    name: "bzip2".to_string(),
                    version: "1.0.8".to_string(),
                    epoch: 4,
                },
                var_transforms: vec![],
                pipeline: vec![
                    Step {
                        uses: Some("fetch".to_string()),
                        with: maplit::hashmap! {
                            "uri".to_string() => "https://sourceware.org/pub/bzip2/bzip2-${{package.version}}.tar.gz".to_string(),
                            "expected-sha256".to_string() => "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269".to_string(),
                        }
                    },
                    Step {
                        uses: Some("patch".to_string()),
                        with: maplit::hashmap! {"patches".to_string() => "bzip2-1.0.2-progress.patch".to_string() }
                    },
                    Step {
                        uses: Some("patch".to_string()),
                        with: maplit::hashmap! {"patches".to_string() => "bzip2-1.0.3-no-test.patch".to_string() }
                    },
                    Step {
                        uses: Some("patch".to_string()),
                        with: maplit::hashmap! {"patches".to_string() => "bzip2-1.0.4-makefile-CFLAGS.patch".to_string() }
                    },
                    Step {
                        uses: Some("patch".to_string()),
                        with: maplit::hashmap! {"patches".to_string() => "bzip2-1.0.4-man-links.patch".to_string() }
                    },
                    Step {
                        uses: Some("patch".to_string()),
                        with: maplit::hashmap! {"patches".to_string() => "saneso.patch".to_string() }
                    },
                    Step {
                        uses: None,
                        with: HashMap::new()
                    },
                    Step {
                        uses: None,
                        with: HashMap::new()
                    },
                    Step {
                        uses: None,
                        with: HashMap::new()
                    },
                    Step {
                        uses: Some("strip".to_string()),
                        with: HashMap::new()
                    },
                ],
            }
        );
        let sources = build.collect_sources().unwrap();
        assert_eq!(
            sources,
            &[Source {
                url: "https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz".to_string(),
                chksum: "sha256:ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269"
                    .to_string(),
            }]
        );
    }

    #[test]
    fn test_7zip() {
        let data = r#"
package:
  name: 7zip
  version: 22.01
  epoch: 0
  description: "File archiver with a high compression ratio"
  copyright:
    - license: LGPL-2.0-only

environment:
  contents:
    packages:
      - busybox
      - ca-certificates-bundle
      - build-base

var-transforms:
  - from: ${{package.version}}
    match: \.
    replace: ''
    to: mangled-package-version

pipeline:
  - uses: fetch
    with:
      uri: https://7-zip.org/a/7z${{vars.mangled-package-version}}-src.tar.xz
      expected-sha512: 3f391b1bd65a0654eb5b31b50f1d400f0ec38ab191d88e15849a6e4d164b7bf2ce4a6d70ec8b6e27bde1b83bb2d45b65c03129499334669e05ee025784be455a
      strip-components: 0

  - name: Configure and build
    runs: |
      cd CPP/7zip/Bundles/Alone2
      mkdir -p b/g
      make -f ../../cmpl_gcc.mak \
      	CC="${CC:-cc} $CFLAGS $LDFLAGS" \
      	CXX="${CXX:-c++} $CXXFLAGS $LDFLAGS" \
      	DISABLE_RAR=1

  - runs: |
      install -Dm755 CPP/7zip/Bundles/Alone2/b/g/7zz "${{targets.destdir}}"/usr/bin/7zz
      ln -s "${{targets.destdir}}"/usr/bin/7zz "${{targets.destdir}}"/usr/bin/7z
      install -Dm644 DOC/* -t "${{targets.destdir}}"/usr/share/doc/7zip

  - uses: strip

subpackages:
  - name: "7zip-doc"
    description: "7zip documentation"
    pipeline:
      - uses: split/manpages
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/usr/share
          mv "${{targets.destdir}}"/usr/share/doc/7zip "${{targets.subpkgdir}}"/usr/share

update:
  enabled: true
  release-monitor:
    identifier: 265148
"#;
        let build = Build::parse(data).unwrap();
        assert_eq!(
            build,
            Build {
                package: Package {
                    name: "7zip".to_string(),
                    version: "22.01".to_string(),
                    epoch: 0,
                },
                var_transforms: vec![Transform {
                    from: "${{package.version}}".to_string(),
                    pattern: "\\.".to_string(),
                    replace: "".to_string(),
                    to: "mangled-package-version".to_string(),
                }],
                pipeline: vec![
                    Step {
                        uses: Some("fetch".to_string()),
                        with: maplit::hashmap! {
                            "expected-sha512".to_string() => "3f391b1bd65a0654eb5b31b50f1d400f0ec38ab191d88e15849a6e4d164b7bf2ce4a6d70ec8b6e27bde1b83bb2d45b65c03129499334669e05ee025784be455a".to_string(),
                            "uri".to_string() => "https://7-zip.org/a/7z${{vars.mangled-package-version}}-src.tar.xz".to_string(),
                            "strip-components".to_string() => "0".to_string()
                        }
                    },
                    Step {
                        uses: None,
                        with: HashMap::new()
                    },
                    Step {
                        uses: None,
                        with: HashMap::new()
                    },
                    Step {
                        uses: Some("strip".to_string()),
                        with: HashMap::new()
                    }
                ]
            }
        );
        let sources = build.collect_sources().unwrap();
        assert_eq!(sources, &[
            Source {
                url: "https://7-zip.org/a/7z2201-src.tar.xz".to_string(),
                chksum: "sha512:3f391b1bd65a0654eb5b31b50f1d400f0ec38ab191d88e15849a6e4d164b7bf2ce4a6d70ec8b6e27bde1b83bb2d45b65c03129499334669e05ee025784be455a".to_string(),
            }
        ]);
    }

    #[test]
    fn test_apko() {
        let data = r#"
package:
  name: apko
  version: 0.14.1
  epoch: 0
  description: Build OCI images using APK directly without Dockerfile
  copyright:
    - license: Apache-2.0
  dependencies:
    runtime:
      - ca-certificates-bundle

environment:
  contents:
    packages:
      - build-base
      - busybox
      - ca-certificates-bundle
      - go

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/chainguard-dev/apko
      tag: v${{package.version}}
      expected-commit: 91e5c5e1baf31e19f6d3af3b0b6b81f849ce81da

  - runs: |
      make apko
      install -m755 -D ./apko "${{targets.destdir}}"/usr/bin/apko

  - uses: strip

update:
  enabled: true
  github:
    identifier: chainguard-dev/apko
    strip-prefix: v
    use-tag: true
"#;
        let build = Build::parse(data).unwrap();
        assert_eq!(
            build,
            Build {
                package: Package {
                    name: "apko".to_string(),
                    version: "0.14.1".to_string(),
                    epoch: 0,
                },
                var_transforms: vec![],
                pipeline: vec![
                    Step {
                        uses: Some("git-checkout".to_string()),
                        with: maplit::hashmap! {
                            "tag".to_string() => "v${{package.version}}".to_string(),
                            "expected-commit".to_string() => "91e5c5e1baf31e19f6d3af3b0b6b81f849ce81da".to_string(),
                            "repository".to_string() => "https://github.com/chainguard-dev/apko".to_string(),
                        }
                    },
                    Step {
                        uses: None,
                        with: HashMap::new()
                    },
                    Step {
                        uses: Some("strip".to_string()),
                        with: HashMap::new()
                    }
                ]
            }
        );
        let sources = build.collect_sources().unwrap();
        assert_eq!(
            sources,
            &[Source {
                url: "git+https://github.com/chainguard-dev/apko#tag=v0.14.1".to_string(),
                chksum: "git:91e5c5e1baf31e19f6d3af3b0b6b81f849ce81da".to_string(),
            }]
        );
    }
}
