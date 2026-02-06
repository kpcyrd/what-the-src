use crate::args;
use crate::db;
use crate::errors::*;
use crate::utils;
use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
use std::path::Path;
use tokio::io::{self, AsyncReadExt};
use tokio_tar::Archive;

fn metadata_from_path(path: &Path) -> Option<(&str, &str)> {
    let path = path.to_str()?;
    let path = path.strip_suffix("/sources")?;
    let (_, filename) = path.rsplit_once('/')?;
    let (package, version) = filename.rsplit_once('-')?;
    Some((package, version))
}

fn input_from_lines(content: &str) -> Vec<(&str, &str)> {
    let mut inputs = Vec::new();
    for line in content.lines() {
        let Some((url, sha256)) = line.rsplit_once(' ') else {
            continue;
        };
        let (url, sha256) = if let Some(data) = url.rsplit_once(' ') {
            data
        } else {
            (url, sha256)
        };
        inputs.push((url, sha256));
    }
    inputs
}

pub async fn run(args: &args::SyncLiveBootstrap) -> Result<()> {
    let db = db::Client::create().await?;
    let vendor = &args.vendor;

    let reader = utils::fetch_or_open(&args.file, args.fetch).await?;
    let reader = io::BufReader::new(reader);
    let reader = GzipDecoder::new(reader);
    let mut tar = Archive::new(reader);

    let mut entries = tar.entries()?;
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }

        let path = entry.path()?;

        let Some((package, version)) = metadata_from_path(&path) else {
            trace!("Skipping path in git snapshot: {path:?}");
            continue;
        };
        let package = package.to_string();
        let version = version.to_string();

        debug!("Found package in export: package={package:?} version={version:?}");

        let mut buf = String::new();
        entry.read_to_string(&mut buf).await?;

        for (url, sha256) in input_from_lines(&buf) {
            if !utils::is_possible_tar_artifact(url) {
                continue;
            }

            let chksum = format!("sha256:{sha256}");
            debug!("Found artifact for package: url={url:?} chksum={chksum:?}");

            let task = if db.resolve_artifact(&chksum).await?.is_none() {
                utils::task_for_url(url)
            } else {
                None
            };

            let r = db::Ref::new(
                chksum,
                vendor.to_string(),
                package.to_string(),
                version.to_string(),
                Some(url.to_string()),
            );
            debug!("insert: {r:?}");
            db.insert_ref(&r).await?;

            if let Some(task) = task {
                info!("Adding task: {task:?}");
                db.insert_task(&task).await?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path_package_version() {
        let path = Path::new("live-bootstrap-master/steps/pkg-config-0.29.2/sources");
        let md = metadata_from_path(path);
        assert_eq!(md, Some(("pkg-config", "0.29.2")));
    }

    #[test]
    fn test_parse_sources() {
        // most sources files are very simple, this is one of the more complex ones
        let buf = "http://git.savannah.gnu.org/cgit/coreutils.git/snapshot/coreutils-9.4.tar.xz 8fb56810310253300b3d6f84e68dc97eb2d74e1f4f78e05776831d9d82e4f2d7\nhttps://files.bootstrapping.world/coreutils-9.4.tar.xz 8fb56810310253300b3d6f84e68dc97eb2d74e1f4f78e05776831d9d82e4f2d7\nhttp://git.savannah.gnu.org/cgit/gnulib.git/snapshot/gnulib-bb5bb43.tar.gz b8aa1ac1b18c67f081486069e6a7a5564f20431c2313a94c20a46dcfb904be2a\nhttps://files.bootstrapping.world/gnulib-bb5bb43.tar.gz b8aa1ac1b18c67f081486069e6a7a5564f20431c2313a94c20a46dcfb904be2a\nhttp://ftp.unicode.org/Public/15.0.0/ucd/UnicodeData.txt 806e9aed65037197f1ec85e12be6e8cd870fc5608b4de0fffd990f689f376a73 UnicodeData-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/PropList.txt e05c0a2811d113dae4abd832884199a3ea8d187ee1b872d8240a788a96540bfd PropList-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/DerivedCoreProperties.txt d367290bc0867e6b484c68370530bdd1a08b6b32404601b8c7accaf83e05628d DerivedCoreProperties-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/emoji/emoji-data.txt 29071dba22c72c27783a73016afb8ffaeb025866740791f9c2d0b55cc45a3470 emoji-data-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/ArabicShaping.txt eb840f36e0a7446293578c684a54c6d83d249abde7bdd4dfa89794af1d7fe9e9 ArabicShaping-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/Scripts.txt cca85d830f46aece2e7c1459ef1249993dca8f2e46d51e869255be140d7ea4b0 Scripts-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/Blocks.txt 529dc5d0f6386d52f2f56e004bbfab48ce2d587eea9d38ba546c4052491bd820 Blocks-15.0.0.txt\nhttp://ftp.unicode.org/Public/3.0-Update1/PropList-3.0.1.txt 909eef4adbeddbdddcd9487c856fe8cdbb8912aa8eb315ed7885b6ef65f4dc4c\nhttp://ftp.unicode.org/Public/15.0.0/ucd/EastAsianWidth.txt 743e7bc435c04ab1a8459710b1c3cad56eedced5b806b4659b6e69b85d0adf2a EastAsianWidth-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/LineBreak.txt 012bca868e2c4e59a5a10a7546baf0c6fb1b2ef458c277f054915c8a49d292bf LineBreak-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/auxiliary/WordBreakProperty.txt 5188a56e91593467c2e912601ebc78750e6adc9b04541b8c5becb5441e388ce2 WordBreakProperty-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/auxiliary/GraphemeBreakProperty.txt 5a0f8748575432f8ff95e1dd5bfaa27bda1a844809e17d6939ee912bba6568a1 GraphemeBreakProperty-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/CompositionExclusions.txt 3b019c0a33c3140cbc920c078f4f9af2680ba4f71869c8d4de5190667c70b6a3 CompositionExclusions-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/SpecialCasing.txt 78b29c64b5840d25c11a9f31b665ee551b8a499eca6c70d770fcad7dd710f494 SpecialCasing-15.0.0.txt\nhttp://ftp.unicode.org/Public/15.0.0/ucd/CaseFolding.txt cdd49e55eae3bbf1f0a3f6580c974a0263cb86a6a08daa10fbf705b4808a56f7 CaseFolding-15.0.0.txt\n";
        let inputs = input_from_lines(buf);
        assert_eq!(
            inputs,
            [
                (
                    "http://git.savannah.gnu.org/cgit/coreutils.git/snapshot/coreutils-9.4.tar.xz",
                    "8fb56810310253300b3d6f84e68dc97eb2d74e1f4f78e05776831d9d82e4f2d7"
                ),
                (
                    "https://files.bootstrapping.world/coreutils-9.4.tar.xz",
                    "8fb56810310253300b3d6f84e68dc97eb2d74e1f4f78e05776831d9d82e4f2d7"
                ),
                (
                    "http://git.savannah.gnu.org/cgit/gnulib.git/snapshot/gnulib-bb5bb43.tar.gz",
                    "b8aa1ac1b18c67f081486069e6a7a5564f20431c2313a94c20a46dcfb904be2a"
                ),
                (
                    "https://files.bootstrapping.world/gnulib-bb5bb43.tar.gz",
                    "b8aa1ac1b18c67f081486069e6a7a5564f20431c2313a94c20a46dcfb904be2a"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/UnicodeData.txt",
                    "806e9aed65037197f1ec85e12be6e8cd870fc5608b4de0fffd990f689f376a73"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/PropList.txt",
                    "e05c0a2811d113dae4abd832884199a3ea8d187ee1b872d8240a788a96540bfd"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/DerivedCoreProperties.txt",
                    "d367290bc0867e6b484c68370530bdd1a08b6b32404601b8c7accaf83e05628d"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/emoji/emoji-data.txt",
                    "29071dba22c72c27783a73016afb8ffaeb025866740791f9c2d0b55cc45a3470"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/ArabicShaping.txt",
                    "eb840f36e0a7446293578c684a54c6d83d249abde7bdd4dfa89794af1d7fe9e9"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/Scripts.txt",
                    "cca85d830f46aece2e7c1459ef1249993dca8f2e46d51e869255be140d7ea4b0"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/Blocks.txt",
                    "529dc5d0f6386d52f2f56e004bbfab48ce2d587eea9d38ba546c4052491bd820"
                ),
                (
                    "http://ftp.unicode.org/Public/3.0-Update1/PropList-3.0.1.txt",
                    "909eef4adbeddbdddcd9487c856fe8cdbb8912aa8eb315ed7885b6ef65f4dc4c"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/EastAsianWidth.txt",
                    "743e7bc435c04ab1a8459710b1c3cad56eedced5b806b4659b6e69b85d0adf2a"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/LineBreak.txt",
                    "012bca868e2c4e59a5a10a7546baf0c6fb1b2ef458c277f054915c8a49d292bf"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/auxiliary/WordBreakProperty.txt",
                    "5188a56e91593467c2e912601ebc78750e6adc9b04541b8c5becb5441e388ce2"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/auxiliary/GraphemeBreakProperty.txt",
                    "5a0f8748575432f8ff95e1dd5bfaa27bda1a844809e17d6939ee912bba6568a1"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/CompositionExclusions.txt",
                    "3b019c0a33c3140cbc920c078f4f9af2680ba4f71869c8d4de5190667c70b6a3"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/SpecialCasing.txt",
                    "78b29c64b5840d25c11a9f31b665ee551b8a499eca6c70d770fcad7dd710f494"
                ),
                (
                    "http://ftp.unicode.org/Public/15.0.0/ucd/CaseFolding.txt",
                    "cdd49e55eae3bbf1f0a3f6580c974a0263cb86a6a08daa10fbf705b4808a56f7"
                ),
            ]
        );
    }
}
