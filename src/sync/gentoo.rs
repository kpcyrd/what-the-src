use crate::args;
use crate::db::{self, Task, TaskData};
use crate::errors::*;
use crate::utils;
use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
use std::collections::BTreeMap;
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt};
use tokio_tar::{Archive, EntryType};

#[derive(Debug, PartialEq, Default)]
pub struct ManifestEntry {
    pub size: u64,
    pub blake2b: Option<String>,
    pub sha512: Option<String>,
}

#[derive(Debug, PartialEq, Default)]
pub struct Package {
    pub artifacts: BTreeMap<String, ManifestEntry>,
    pub metadata: BTreeMap<String, Metadata>,
}

fn parse_manifest_entry(line: &str) -> Result<(String, ManifestEntry)> {
    let Some(line) = line.strip_prefix("DIST ") else {
        return Err(Error::InvalidData);
    };
    let Some((filename, line)) = line.split_once(' ') else {
        return Err(Error::InvalidData);
    };
    let Some((size, line)) = line.split_once(' ') else {
        return Err(Error::InvalidData);
    };

    let mut entry = ManifestEntry {
        size: size.parse()?,
        ..Default::default()
    };

    let mut remaining = line;
    while !remaining.is_empty() {
        let Some((key, line)) = remaining.split_once(' ') else {
            break;
        };
        let (value, line) = line.split_once(' ').unwrap_or((line, ""));
        remaining = line;
        match key {
            "BLAKE2B" => entry.blake2b = Some(value.to_string()),
            "SHA512" => entry.sha512 = Some(value.to_string()),
            _ => (),
        }
    }

    Ok((filename.to_string(), entry))
}

#[derive(Debug, PartialEq, Default)]
pub struct Metadata {
    pub inputs: BTreeMap<String, String>,
}

fn parse_metadata(data: &str) -> Result<Metadata> {
    let mut metadata = Metadata::default();

    let mut value = data
        .lines()
        .filter_map(|line| line.strip_prefix("SRC_URI="))
        .next()
        .unwrap_or("");

    while !value.is_empty() {
        let (url, remaining) = value.split_once(' ').unwrap_or((value, ""));

        let (filename, remaining) = if let Some(remaining) = remaining.strip_prefix("-> ") {
            remaining.split_once(' ').unwrap_or((remaining, ""))
        } else {
            let (_, filename) = url.rsplit_once('/').unwrap_or(("", url));
            (filename, remaining)
        };

        let remaining = remaining.strip_prefix("verify-sig? ").unwrap_or(remaining);

        let remaining = if remaining.starts_with('(') {
            remaining
                .split_once(')')
                .map(|(_options, remaining)| remaining)
                .unwrap_or(remaining)
        } else {
            remaining
        };

        metadata
            .inputs
            .insert(filename.to_string(), url.to_string());

        value = remaining;
    }

    Ok(metadata)
}

pub fn parse_pkgname_version(filename: &str) -> Result<(&str, &str)> {
    let Some(idx) = filename.rfind('-') else {
        return Err(Error::InvalidData);
    };
    let pkgname = &filename[..idx];
    let version = &filename[idx + 1..];

    if version.starts_with('r') {
        let Some(idx) = pkgname.rfind('-') else {
            return Err(Error::InvalidData);
        };
        let pkgname = &filename[..idx];
        let version = &filename[idx + 1..];
        Ok((pkgname, version))
    } else {
        Ok((pkgname, version))
    }
}

pub async fn run(args: &args::SyncGentoo) -> Result<()> {
    let db = db::Client::create().await?;
    let vendor = &args.vendor;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let reader = io::BufReader::new(reader);
    let reader = GzipDecoder::new(reader);
    let mut tar = Archive::new(reader);

    let mut index = BTreeMap::<_, Package>::new();

    let mut entries = tar.entries()?;
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        let path = {
            let header = entry.header();
            if header.entry_type() != EntryType::Regular {
                continue;
            }
            header.path()?.into_owned()
        };

        let Some(parent) = path.parent() else {
            continue;
        };
        let parent = parent.strip_prefix("gentoo-master").unwrap_or(parent);
        let Some(filename) = path.file_name() else {
            continue;
        };
        let Some(filename) = filename.to_str() else {
            continue;
        };

        debug!("Found file in git: parent={parent:?} file={filename:?}");

        if filename == "Manifest" {
            let Some(parent) = parent.to_str() else {
                continue;
            };

            debug!("Found package manifest: {parent:?}");
            let pkg = index.entry(parent.to_owned()).or_default();

            let reader = io::BufReader::new(entry);
            let mut lines = reader.lines();
            while let Some(line) = lines.next_line().await? {
                let (filename, entry) = parse_manifest_entry(&line)?;
                pkg.artifacts.insert(filename, entry);
            }
        } else if let Ok(parent) = parent.strip_prefix("metadata/md5-cache") {
            let Some(parent) = parent.to_str() else {
                continue;
            };

            let Ok((pkgname, version)) = parse_pkgname_version(filename) else {
                continue;
            };

            let fullname = format!("{parent}/{pkgname}");
            let pkg = index.entry(fullname).or_default();

            let mut buf = String::new();
            entry.read_to_string(&mut buf).await?;

            let metadata = parse_metadata(&buf)?;
            pkg.metadata.insert(version.to_string(), metadata);
        }
    }

    for (pkg, data) in index {
        for (version, metadata) in data.metadata {
            debug!(
                "Found package: pkg={pkg:?} version={version:?} inputs={:?} known_hashes={:?}",
                metadata.inputs.len(),
                data.artifacts.len()
            );

            for (filename, url) in &metadata.inputs {
                match url.split_once("://") {
                    Some(("http", _)) => (),
                    Some(("https", _)) => (),
                    _ => continue,
                }

                if !utils::is_possible_tar_artifact(url) {
                    continue;
                }

                let Some(artifact) = data.artifacts.get(filename) else {
                    continue;
                };

                let Some(blake2b) = &artifact.blake2b else {
                    continue;
                };

                let blake2b = format!("blake2b:{blake2b}");
                let already_imported = db.resolve_artifact(&blake2b).await?.is_some();

                let r = db::Ref {
                    chksum: blake2b,
                    vendor: vendor.to_string(),
                    package: pkg.to_string(),
                    version: version.to_string(),
                    filename: Some(url.to_string()),
                };
                debug!("insert: {r:?}");
                db.insert_ref(&r).await?;

                if already_imported {
                    continue;
                };

                info!("Adding download task: url={url:?}");
                db.insert_task(&Task::new(
                    format!("fetch:{url}"),
                    &TaskData::FetchTar {
                        url: url.to_string(),
                        success_ref: None,
                    },
                )?)
                .await?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest() {
        let line = "DIST aho-corasick-1.1.2.crate 183136 BLAKE2B 2d4306d8968061b9f7e50190be6a92b3f668169ba1b9f9691de08a57c96185f7a4288d20c64cb8488a260eb18d3ed4b0e8358b0cca47aa44759b2e448049cbaa SHA512 61ef5092673ab5a60bec4e92df28a91fe6171ba59d5829ffe41fc55aff3bfb755533a4ad53dc7bf827a0b789fcce593b17e69d1fcfb3694f06ed3b1bd535d40c";
        let entry = parse_manifest_entry(line).unwrap();
        assert_eq!(
            entry,
            ("aho-corasick-1.1.2.crate".to_string(), ManifestEntry {
                size: 183136,
                blake2b: Some("2d4306d8968061b9f7e50190be6a92b3f668169ba1b9f9691de08a57c96185f7a4288d20c64cb8488a260eb18d3ed4b0e8358b0cca47aa44759b2e448049cbaa".to_string()),
                sha512: Some("61ef5092673ab5a60bec4e92df28a91fe6171ba59d5829ffe41fc55aff3bfb755533a4ad53dc7bf827a0b789fcce593b17e69d1fcfb3694f06ed3b1bd535d40c".to_string()),
            })
        );
    }

    #[test]
    fn test_parse_metadata_without_srcuri() {
        let data = "DEFINED_PHASES=install preinst pretend
DESCRIPTION=A group for sys-process/systemd-cron failure emails
EAPI=8
INHERIT=acct-group
KEYWORDS=~alpha amd64 arm arm64 hppa ~ia64 ~loong ~m68k ~mips ppc ppc64 ~riscv ~s390 sparc x86 ~amd64-linux ~x86-linux ~arm64-macos ~ppc-macos ~x64-macos ~x64-solaris
SLOT=0
_eclasses_=user-info	9951b1a0e4f026d16c33a001fd2d5cdf	acct-group	1ba28b31fccef7f4ff1cebfad243a633
_md5_=9afd57413fd5681377f8d62f3721190d
";
        let metadata = parse_metadata(data).unwrap();
        assert_eq!(metadata, Metadata::default());
    }

    #[test]
    fn test_parse_metadata_with_srcuri() {
        let data = r#"BDEPEND=>=virtual/rust-1.72 virtual/pkgconfig >=virtual/rust-1.53
DEFINED_PHASES=compile configure install prepare test unpack
DEPEND=pcre? ( dev-libs/libpcre2:= )
DESCRIPTION=Search tool that combines the usability of ag with the raw speed of grep
EAPI=8
HOMEPAGE=https://github.com/BurntSushi/ripgrep
INHERIT=cargo bash-completion-r1
IUSE=+pcre debug
KEYWORDS=amd64 arm64 ~loong ppc64 ~riscv x86
LICENSE=Apache-2.0 BSD MIT Unicode-DFS-2016 || ( Apache-2.0 Boost-1.0 )
RDEPEND=pcre? ( dev-libs/libpcre2:= )
SLOT=0
SRC_URI=https://github.com/BurntSushi/ripgrep/archive/14.1.0.tar.gz -> ripgrep-14.1.0.tar.gz https://crates.io/api/v1/crates/aho-corasick/1.1.2/download -> aho-corasick-1.1.2.crate https://crates.io/api/v1/crates/anyhow/1.0.79/download -> anyhow-1.0.79.crate https://crates.io/api/v1/crates/autocfg/1.1.0/download -> autocfg-1.1.0.crate https://crates.io/api/v1/crates/bstr/1.9.0/download -> bstr-1.9.0.crate https://crates.io/api/v1/crates/cc/1.0.83/download -> cc-1.0.83.crate https://crates.io/api/v1/crates/cfg-if/1.0.0/download -> cfg-if-1.0.0.crate https://crates.io/api/v1/crates/crossbeam-channel/0.5.10/download -> crossbeam-channel-0.5.10.crate https://crates.io/api/v1/crates/crossbeam-deque/0.8.4/download -> crossbeam-deque-0.8.4.crate https://crates.io/api/v1/crates/crossbeam-epoch/0.9.17/download -> crossbeam-epoch-0.9.17.crate https://crates.io/api/v1/crates/crossbeam-utils/0.8.18/download -> crossbeam-utils-0.8.18.crate https://crates.io/api/v1/crates/encoding_rs/0.8.33/download -> encoding_rs-0.8.33.crate https://crates.io/api/v1/crates/encoding_rs_io/0.1.7/download -> encoding_rs_io-0.1.7.crate https://crates.io/api/v1/crates/glob/0.3.1/download -> glob-0.3.1.crate https://crates.io/api/v1/crates/itoa/1.0.10/download -> itoa-1.0.10.crate https://crates.io/api/v1/crates/jemalloc-sys/0.5.4+5.3.0-patched/download -> jemalloc-sys-0.5.4+5.3.0-patched.crate https://crates.io/api/v1/crates/jemallocator/0.5.4/download -> jemallocator-0.5.4.crate https://crates.io/api/v1/crates/jobserver/0.1.27/download -> jobserver-0.1.27.crate https://crates.io/api/v1/crates/lexopt/0.3.0/download -> lexopt-0.3.0.crate https://crates.io/api/v1/crates/libc/0.2.151/download -> libc-0.2.151.crate https://crates.io/api/v1/crates/libm/0.2.8/download -> libm-0.2.8.crate https://crates.io/api/v1/crates/log/0.4.20/download -> log-0.4.20.crate https://crates.io/api/v1/crates/memchr/2.7.1/download -> memchr-2.7.1.crate https://crates.io/api/v1/crates/memmap2/0.9.3/download -> memmap2-0.9.3.crate https://crates.io/api/v1/crates/num-traits/0.2.17/download -> num-traits-0.2.17.crate https://crates.io/api/v1/crates/packed_simd/0.3.9/download -> packed_simd-0.3.9.crate https://crates.io/api/v1/crates/pcre2-sys/0.2.8/download -> pcre2-sys-0.2.8.crate https://crates.io/api/v1/crates/pcre2/0.2.6/download -> pcre2-0.2.6.crate https://crates.io/api/v1/crates/pkg-config/0.3.28/download -> pkg-config-0.3.28.crate https://crates.io/api/v1/crates/proc-macro2/1.0.76/download -> proc-macro2-1.0.76.crate https://crates.io/api/v1/crates/quote/1.0.35/download -> quote-1.0.35.crate https://crates.io/api/v1/crates/regex-automata/0.4.3/download -> regex-automata-0.4.3.crate https://crates.io/api/v1/crates/regex-syntax/0.8.2/download -> regex-syntax-0.8.2.crate https://crates.io/api/v1/crates/regex/1.10.2/download -> regex-1.10.2.crate https://crates.io/api/v1/crates/ryu/1.0.16/download -> ryu-1.0.16.crate https://crates.io/api/v1/crates/same-file/1.0.6/download -> same-file-1.0.6.crate https://crates.io/api/v1/crates/serde/1.0.195/download -> serde-1.0.195.crate https://crates.io/api/v1/crates/serde_derive/1.0.195/download -> serde_derive-1.0.195.crate https://crates.io/api/v1/crates/serde_json/1.0.111/download -> serde_json-1.0.111.crate https://crates.io/api/v1/crates/syn/2.0.48/download -> syn-2.0.48.crate https://crates.io/api/v1/crates/termcolor/1.4.0/download -> termcolor-1.4.0.crate https://crates.io/api/v1/crates/textwrap/0.16.0/download -> textwrap-0.16.0.crate https://crates.io/api/v1/crates/unicode-ident/1.0.12/download -> unicode-ident-1.0.12.crate https://crates.io/api/v1/crates/walkdir/2.4.0/download -> walkdir-2.4.0.crate https://crates.io/api/v1/crates/winapi-i686-pc-windows-gnu/0.4.0/download -> winapi-i686-pc-windows-gnu-0.4.0.crate https://crates.io/api/v1/crates/winapi-util/0.1.6/download -> winapi-util-0.1.6.crate https://crates.io/api/v1/crates/winapi-x86_64-pc-windows-gnu/0.4.0/download -> winapi-x86_64-pc-windows-gnu-0.4.0.crate https://crates.io/api/v1/crates/winapi/0.3.9/download -> winapi-0.3.9.crate
_eclasses_=toolchain-funcs	e56c7649b804f051623c8bc1a1c44084	multilib	c19072c3cd7ac5cb21de013f7e9832e0	flag-o-matic	288c54efeb5e2aa70775e39032695ad4	multiprocessing	30ead54fa2e2b5f9cd4e612ffc34d0fe	cargo	4dede41d64d595673f6da62ab5540fa0	bash-completion-r1	f5e7a020fd9c741740756aac61bf75ff
_md5_=d75164470205c1da99423c839b00916a
"#;
        let metadata = parse_metadata(data).unwrap();
        assert_eq!(
            metadata,
            Metadata {
                inputs: [
                    ("aho-corasick-1.1.2.crate", "https://crates.io/api/v1/crates/aho-corasick/1.1.2/download"),
                    ("anyhow-1.0.79.crate", "https://crates.io/api/v1/crates/anyhow/1.0.79/download"),
                    ("autocfg-1.1.0.crate", "https://crates.io/api/v1/crates/autocfg/1.1.0/download"),
                    ("bstr-1.9.0.crate", "https://crates.io/api/v1/crates/bstr/1.9.0/download"),
                    ("cc-1.0.83.crate", "https://crates.io/api/v1/crates/cc/1.0.83/download"),
                    ("cfg-if-1.0.0.crate", "https://crates.io/api/v1/crates/cfg-if/1.0.0/download"),
                    ("crossbeam-channel-0.5.10.crate", "https://crates.io/api/v1/crates/crossbeam-channel/0.5.10/download"),
                    ("crossbeam-deque-0.8.4.crate", "https://crates.io/api/v1/crates/crossbeam-deque/0.8.4/download"),
                    ("crossbeam-epoch-0.9.17.crate", "https://crates.io/api/v1/crates/crossbeam-epoch/0.9.17/download"),
                    ("crossbeam-utils-0.8.18.crate", "https://crates.io/api/v1/crates/crossbeam-utils/0.8.18/download"),
                    ("encoding_rs-0.8.33.crate", "https://crates.io/api/v1/crates/encoding_rs/0.8.33/download"),
                    ("encoding_rs_io-0.1.7.crate", "https://crates.io/api/v1/crates/encoding_rs_io/0.1.7/download"),
                    ("glob-0.3.1.crate", "https://crates.io/api/v1/crates/glob/0.3.1/download"),
                    ("itoa-1.0.10.crate", "https://crates.io/api/v1/crates/itoa/1.0.10/download"),
                    ("jemalloc-sys-0.5.4+5.3.0-patched.crate", "https://crates.io/api/v1/crates/jemalloc-sys/0.5.4+5.3.0-patched/download"),
                    ("jemallocator-0.5.4.crate", "https://crates.io/api/v1/crates/jemallocator/0.5.4/download"),
                    ("jobserver-0.1.27.crate", "https://crates.io/api/v1/crates/jobserver/0.1.27/download"),
                    ("lexopt-0.3.0.crate", "https://crates.io/api/v1/crates/lexopt/0.3.0/download"),
                    ("libc-0.2.151.crate", "https://crates.io/api/v1/crates/libc/0.2.151/download"),
                    ("libm-0.2.8.crate", "https://crates.io/api/v1/crates/libm/0.2.8/download"),
                    ("log-0.4.20.crate", "https://crates.io/api/v1/crates/log/0.4.20/download"),
                    ("memchr-2.7.1.crate", "https://crates.io/api/v1/crates/memchr/2.7.1/download"),
                    ("memmap2-0.9.3.crate", "https://crates.io/api/v1/crates/memmap2/0.9.3/download"),
                    ("num-traits-0.2.17.crate", "https://crates.io/api/v1/crates/num-traits/0.2.17/download"),
                    ("packed_simd-0.3.9.crate", "https://crates.io/api/v1/crates/packed_simd/0.3.9/download"),
                    ("pcre2-0.2.6.crate", "https://crates.io/api/v1/crates/pcre2/0.2.6/download"),
                    ("pcre2-sys-0.2.8.crate", "https://crates.io/api/v1/crates/pcre2-sys/0.2.8/download"),
                    ("pkg-config-0.3.28.crate", "https://crates.io/api/v1/crates/pkg-config/0.3.28/download"),
                    ("proc-macro2-1.0.76.crate", "https://crates.io/api/v1/crates/proc-macro2/1.0.76/download"),
                    ("quote-1.0.35.crate", "https://crates.io/api/v1/crates/quote/1.0.35/download"),
                    ("regex-1.10.2.crate", "https://crates.io/api/v1/crates/regex/1.10.2/download"),
                    ("regex-automata-0.4.3.crate", "https://crates.io/api/v1/crates/regex-automata/0.4.3/download"),
                    ("regex-syntax-0.8.2.crate", "https://crates.io/api/v1/crates/regex-syntax/0.8.2/download"),
                    ("ripgrep-14.1.0.tar.gz", "https://github.com/BurntSushi/ripgrep/archive/14.1.0.tar.gz"),
                    ("ryu-1.0.16.crate", "https://crates.io/api/v1/crates/ryu/1.0.16/download"),
                    ("same-file-1.0.6.crate", "https://crates.io/api/v1/crates/same-file/1.0.6/download"),
                    ("serde-1.0.195.crate", "https://crates.io/api/v1/crates/serde/1.0.195/download"),
                    ("serde_derive-1.0.195.crate", "https://crates.io/api/v1/crates/serde_derive/1.0.195/download"),
                    ("serde_json-1.0.111.crate", "https://crates.io/api/v1/crates/serde_json/1.0.111/download"),
                    ("syn-2.0.48.crate", "https://crates.io/api/v1/crates/syn/2.0.48/download"),
                    ("termcolor-1.4.0.crate", "https://crates.io/api/v1/crates/termcolor/1.4.0/download"),
                    ("textwrap-0.16.0.crate", "https://crates.io/api/v1/crates/textwrap/0.16.0/download"),
                    ("unicode-ident-1.0.12.crate", "https://crates.io/api/v1/crates/unicode-ident/1.0.12/download"),
                    ("walkdir-2.4.0.crate", "https://crates.io/api/v1/crates/walkdir/2.4.0/download"),
                    ("winapi-0.3.9.crate", "https://crates.io/api/v1/crates/winapi/0.3.9/download"),
                    ("winapi-i686-pc-windows-gnu-0.4.0.crate", "https://crates.io/api/v1/crates/winapi-i686-pc-windows-gnu/0.4.0/download"),
                    ("winapi-util-0.1.6.crate", "https://crates.io/api/v1/crates/winapi-util/0.1.6/download"),
                    ("winapi-x86_64-pc-windows-gnu-0.4.0.crate", "https://crates.io/api/v1/crates/winapi-x86_64-pc-windows-gnu/0.4.0/download"),
                ]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
            }
        );
    }

    #[test]
    fn test_parse_metadata_verify_sig() {
        let data = "BDEPEND=verify-sig? ( >=sec-keys/openpgp-keys-thomasdickey-20240114 ) verify-sig? ( app-crypt/gnupg >=app-portage/gemato-20 )
DEFINED_PHASES=configure install postinst postrm unpack
DESCRIPTION=An (often faster than gawk) awk-interpreter
EAPI=8
HOMEPAGE=https://invisible-island.net/mawk/mawk.html
INHERIT=toolchain-funcs verify-sig
IUSE=verify-sig
KEYWORDS=~alpha amd64 arm arm64 hppa ~ia64 ~loong ~m68k ~mips ppc ppc64 ~riscv ~s390 sparc x86 ~amd64-linux ~x86-linux
LICENSE=GPL-2
SLOT=0
SRC_URI=https://invisible-mirror.net/archives/mawk/mawk-1.3.4-20240123.tgz verify-sig? ( https://invisible-island.net/archives/mawk/mawk-1.3.4-20240123.tgz.asc )
_eclasses_=toolchain-funcs	e56c7649b804f051623c8bc1a1c44084	multilib	c19072c3cd7ac5cb21de013f7e9832e0	verify-sig	a79ba011daaf532d71a219182474d150
_md5_=b977a58ded16b7cd6e10cde4e52ed083
";
        let metadata = parse_metadata(data).unwrap();
        assert_eq!(
            metadata,
            Metadata {
                inputs: [(
                    "mawk-1.3.4-20240123.tgz",
                    "https://invisible-mirror.net/archives/mawk/mawk-1.3.4-20240123.tgz"
                )]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
            }
        );
    }

    #[test]
    fn test_parse_pkgname_version() {
        let split = parse_pkgname_version("apparmor-3.0.10").unwrap();
        assert_eq!(split, ("apparmor", "3.0.10"));
        let split = parse_pkgname_version("apparmor-utils-3.0.10-r1").unwrap();
        assert_eq!(split, ("apparmor-utils", "3.0.10-r1"));
    }
}
