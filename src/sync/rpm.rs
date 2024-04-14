use crate::args;
use crate::db;
use crate::errors::*;
use async_compression::tokio::bufread::GzipDecoder;
use futures::TryStreamExt;
use serde::Deserialize;
use tokio::io::{self, AsyncReadExt};
use tokio_util::io::StreamReader;

#[derive(Debug, PartialEq, Deserialize)]
pub struct Metadata {
    #[serde(rename = "package")]
    packages: Vec<Package>,
}

impl Metadata {
    pub fn from_xml(xml: &str) -> Result<Self> {
        let xml = serde_xml_rs::from_str(xml)?;
        Ok(xml)
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Package {
    name: String,
    version: Version,
    location: Location,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Version {
    ver: String,
    rel: String,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Location {
    href: String,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct RepoMd {
    data: Vec<Data>,
}

impl RepoMd {
    pub fn from_xml(xml: &str) -> Result<Self> {
        let xml = serde_xml_rs::from_str(xml)?;
        Ok(xml)
    }

    pub fn find_primary_location(&self) -> Result<&str> {
        let href = self
            .data
            .iter()
            .find(|e| e.data_type == "primary")
            .ok_or(Error::RpmMissingPrimary)?
            .location
            .href
            .as_str();
        Ok(href)
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Data {
    #[serde(rename = "type")]
    data_type: String,
    location: Location,
}

pub async fn run(args: &args::SyncRpm) -> Result<()> {
    let db = db::Client::create().await?;
    let base_url = args.url.strip_suffix('/').unwrap_or(&args.url);
    let vendor = &args.vendor;

    let client = reqwest::ClientBuilder::new();
    let client = client.build()?;

    let url = format!("{base_url}/repodata/repomd.xml");
    info!("Downloading url: {url:?}");
    let text = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let repomd = RepoMd::from_xml(&text)?;
    let url = format!("{base_url}/{}", repomd.find_primary_location()?);
    info!("Downloading url: {url:?}");
    let stream = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes_stream();

    let reader = StreamReader::new(stream.map_err(|e| io::Error::new(io::ErrorKind::Other, e)));
    let reader = io::BufReader::new(reader);
    let mut reader = GzipDecoder::new(reader);

    let mut buf = String::new();
    reader.read_to_string(&mut buf).await?;

    info!("Processing xml");
    let md = Metadata::from_xml(&buf)?;
    for pkg in md.packages {
        let package = pkg.name;
        let version = format!("{}-{}", pkg.version.ver, pkg.version.rel);

        if db.get_package(vendor, &package, &version).await?.is_some() {
            debug!("Package is already imported: vendor={vendor:?} package={package:?} version={version:?}");
            continue;
        }

        let url = format!("{base_url}/{}", pkg.location.href);

        info!("package={package:?} version={version:?} url={url:?}");
        db.insert_task(&db::Task::new(
            format!("source-rpm:{package}:{version}"),
            &db::TaskData::SourceRpm {
                vendor: vendor.to_string(),
                package: package.to_string(),
                version: version.to_string(),
                url,
            },
        )?)
        .await?;
    }

    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_primary_xml() {
        let data = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="23891">
<package type="rpm">
  <name>0ad</name>
  <arch>src</arch>
  <version epoch="0" ver="0.0.26" rel="21.fc41"/>
  <checksum type="sha256" pkgid="YES">2368bc4da6effe91983f4136e651834cc3b547cecafaed3bf06bf2fcfdc53848</checksum>
  <summary>Cross-Platform RTS Game of Ancient Warfare</summary>
  <description>0 A.D. (pronounced "zero ey-dee") is a free, open-source, cross-platform
real-time strategy (RTS) game of ancient warfare. In short, it is a
historically-based war/economy game that allows players to relive or rewrite
the history of Western civilizations, focusing on the years between 500 B.C.
and 500 A.D. The project is highly ambitious, involving state-of-the-art 3D
graphics, detailed artwork, sound, and a flexible and powerful custom-built
game engine.

The game has been in development by Wildfire Games (WFG), a group of volunteer,
hobbyist game developers, since 2001.</description>
  <packager>Fedora Project</packager>
  <url>http://play0ad.com</url>
  <time file="1710852923" build="1710842313"/>
  <size package="80972827" installed="83795861" archive="83797864"/>
  <location href="Packages/0/0ad-0.0.26-21.fc41.src.rpm"/>
  <format>
    <rpm:license>GPLv2+ and BSD and MIT and IBM and MPLv2.0</rpm:license>
    <rpm:vendor>Fedora Project</rpm:vendor>
    <rpm:group>Unspecified</rpm:group>
    <rpm:buildhost>buildhw-x86-15.iad2.fedoraproject.org</rpm:buildhost>
    <rpm:sourcerpm></rpm:sourcerpm>
    <rpm:header-range start="4504" end="41809"/>
    <rpm:provides>
      <rpm:entry name="0ad" flags="EQ" epoch="0" ver="0.0.26" rel="21.fc41"/>
      <rpm:entry name="0ad-debuginfo" flags="EQ" epoch="0" ver="0.0.26" rel="21.fc41"/>
      <rpm:entry name="0ad-debugsource" flags="EQ" epoch="0" ver="0.0.26" rel="21.fc41"/>
    </rpm:provides>
    <rpm:requires>
      <rpm:entry name="/usr/bin/appstream-util"/>
      <rpm:entry name="/usr/bin/zip"/>
      <rpm:entry name="SDL2-devel"/>
      <rpm:entry name="boost-devel"/>
      <rpm:entry name="cargo"/>
      <rpm:entry name="cmake"/>
      <rpm:entry name="desktop-file-utils"/>
      <rpm:entry name="enet-devel"/>
      <rpm:entry name="fmt-devel"/>
      <rpm:entry name="gcc-c++"/>
      <rpm:entry name="git-core"/>
      <rpm:entry name="gloox-devel"/>
      <rpm:entry name="libcurl-devel"/>
      <rpm:entry name="libdnet-devel"/>
      <rpm:entry name="libicu-devel"/>
      <rpm:entry name="libjpeg-turbo-devel"/>
      <rpm:entry name="libpng-devel"/>
      <rpm:entry name="libsodium-devel"/>
      <rpm:entry name="libvorbis-devel"/>
      <rpm:entry name="libxml2-devel"/>
      <rpm:entry name="libzip-devel"/>
      <rpm:entry name="make"/>
      <rpm:entry name="miniupnpc-devel"/>
      <rpm:entry name="nvidia-texture-tools-devel"/>
      <rpm:entry name="openal-soft-devel"/>
      <rpm:entry name="perl-devel"/>
      <rpm:entry name="pkgconfig"/>
      <rpm:entry name="pkgconfig(libffi)"/>
      <rpm:entry name="pkgconfig(nspr)"/>
      <rpm:entry name="pkgconfig(zlib)"/>
      <rpm:entry name="python3.11-devel"/>
      <rpm:entry name="readline-devel"/>
      <rpm:entry name="rustc"/>
      <rpm:entry name="subversion"/>
      <rpm:entry name="valgrind-devel"/>
      <rpm:entry name="wxGTK-devel"/>
    </rpm:requires>
  </format>
</package>
</metadata>
"#;
        let md = Metadata::from_xml(data).unwrap();
        assert_eq!(
            md,
            Metadata {
                packages: vec![Package {
                    name: "0ad".to_string(),
                    version: Version {
                        ver: "0.0.26".to_string(),
                        rel: "21.fc41".to_string(),
                    },
                    location: Location {
                        href: "Packages/0/0ad-0.0.26-21.fc41.src.rpm".to_string()
                    },
                }]
            }
        );
    }

    #[test]
    fn test_parse_repomd() {
        let data = r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
  <revision>1712990641</revision>
  <data type="primary">
    <checksum type="sha256">fa72c03d43e9ffe131633347045c0c56fbeacbd3281b2b03a6351f487218a158</checksum>
    <open-checksum type="sha256">259d84fce5ecb46226a21765561539eb992fff76356df088f9ed3d1d3d44cd28</open-checksum>
    <location href="repodata/fa72c03d43e9ffe131633347045c0c56fbeacbd3281b2b03a6351f487218a158-primary.xml.gz"/>
    <timestamp>1712990625</timestamp>
    <size>7587566</size>
    <open-size>49907129</open-size>
  </data>
  <data type="filelists">
    <checksum type="sha256">caf9e9202dbd97fcf4da6ca3f228fd459505f0b17d37fb387240b03c8dc0e84a</checksum>
    <open-checksum type="sha256">a35a9e10b149715434f405d3b5f3a895699d9a2939adb3435358337194bad323</open-checksum>
    <location href="repodata/caf9e9202dbd97fcf4da6ca3f228fd459505f0b17d37fb387240b03c8dc0e84a-filelists.xml.gz"/>
    <timestamp>1712990625</timestamp>
    <size>2013585</size>
    <open-size>7783810</open-size>
  </data>
</repomd>
"#;
        let md = RepoMd::from_xml(data).unwrap();
        assert_eq!(
            md,
            RepoMd {
                data: vec![
                    Data {
                        data_type: "primary".to_string(),
                        location: Location {
                            href: "repodata/fa72c03d43e9ffe131633347045c0c56fbeacbd3281b2b03a6351f487218a158-primary.xml.gz".to_string()
                        }
                    },
                    Data {
                        data_type: "filelists".to_string(),
                        location: Location {
                            href: "repodata/caf9e9202dbd97fcf4da6ca3f228fd459505f0b17d37fb387240b03c8dc0e84a-filelists.xml.gz".to_string()
                        }
                    }
                ],
            }
        );
    }
}
