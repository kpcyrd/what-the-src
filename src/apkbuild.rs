use crate::errors::*;
use yash_syntax::syntax::{self, Unquote, Value};

#[derive(Debug, Default, PartialEq)]
pub struct Apkbuild {
    pub pkgname: Option<String>,
    pub pkgver: Option<String>,
    pub _pkgver: Option<String>,
    pub url: Option<String>,

    pub source: Vec<String>,
    pub sha512sums: Vec<String>,
}

impl Apkbuild {
    pub fn resolve_vars(&self, mut text: &str) -> Result<String> {
        let mut out = String::new();

        'outer: while !text.is_empty() {
            if let Some((before, after)) = text.split_once('$') {
                let vars = [
                    ("pkgname", &self.pkgname),
                    ("pkgver", &self.pkgver),
                    ("_pkgver", &self._pkgver),
                    ("url", &self.url),
                ];

                out.push_str(before);
                for (name, value) in vars {
                    if let Some(after) = after.strip_prefix(name) {
                        let Some(value) = value else {
                            return Err(Error::UnknownVariable(name.to_string()));
                        };
                        out.push_str(value);
                        text = after;
                        continue 'outer;
                    }
                }

                return Err(Error::UnknownVariable(after.to_string()));
            } else {
                out.push_str(text);
                break;
            }
        }

        Ok(out)
    }
}

pub fn parse(script: &str) -> Result<Apkbuild> {
    let parsed: syntax::List = script
        .parse()
        .map_err(|err| Error::InvalidPkgbuild(format!("{err:#?}")))?;

    let mut apkbuild = Apkbuild::default();

    for item in &parsed.0 {
        for cmd in &item.and_or.first.commands {
            let syntax::Command::Simple(cmd) = cmd.as_ref() else {
                continue;
            };

            for assign in &cmd.assigns {
                let name = assign.name.as_str();

                let Value::Scalar(value) = &assign.value else {
                    continue;
                };
                let (value, _) = value.unquote();

                debug!("Found variable in APKBUILD: key={name:?} value={value:?}");
                let value = apkbuild.resolve_vars(&value);

                match name {
                    "pkgname" => {
                        apkbuild.pkgname = Some(value?);
                    }
                    "pkgver" => {
                        apkbuild.pkgver = Some(value?);
                    }
                    "_pkgver" => {
                        apkbuild._pkgver = Some(value?);
                    }
                    "url" => {
                        apkbuild.url = Some(value?);
                    }
                    "source" => {
                        apkbuild.source = value?
                            .trim()
                            .split('\n')
                            .map(|line| line.trim())
                            .map(|line| line.split_once("::").map(|x| x.1).unwrap_or(line))
                            .map(String::from)
                            .collect();
                    }
                    "sha512sums" => {
                        apkbuild.sha512sums = value?
                            .trim()
                            .split('\n')
                            .map(|line| line.split_once("  ").map(|x| x.0).unwrap_or(line))
                            .map(String::from)
                            .collect();
                    }
                    _ => (),
                }
            }
        }
    }

    Ok(apkbuild)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_parse_cmatrix() {
        init();

        let data = br#"# Contributor: alpterry <alpterry@protonmail.com>
# Maintainer: alpterry <alpterry@protonmail.com>
pkgname=cmatrix
pkgver=2.0
pkgrel=2
pkgdesc="Terminal based 'The Matrix' like implementation"
url="https://github.com/abishekvashok/cmatrix"
arch="all"
license="GPL-3.0-or-later"
makedepends="ncurses-dev kbd autoconf automake"
subpackages="$pkgname-doc"
options="!check" # no test suite
source="$pkgname-$pkgver.tar.gz::https://github.com/abishekvashok/cmatrix/archive/v$pkgver.tar.gz"

prepare() {
	default_prepare
	autoreconf -i
}

build() {
	./configure \
		--build=$CBUILD \
		--host=$CHOST \
		--prefix=/usr \
		--sysconfdir=/etc \
		--mandir=/usr/share/man \
		--localstatedir=/var
	make
}

package() {
	make DESTDIR="$pkgdir" install
}

sha512sums="1aeecd8e8abb6f87fc54f88a8c25478f69d42d450af782e73c0fca7f051669a415c0505ca61c904f960b46bbddf98cfb3dd1f9b18917b0b39e95d8c899889530  cmatrix-2.0.tar.gz"
"#;
        let apkbuild = parse(data).unwrap();
        assert_eq!(apkbuild, Apkbuild {
            pkgname: Some("cmatrix".to_string()),
            pkgver: Some("2.0".to_string()),
            url: Some("https://github.com/abishekvashok/cmatrix".to_string()),

            source: vec![
                "https://github.com/abishekvashok/cmatrix/archive/v2.0.tar.gz".to_string(),
            ],
            sha512sums: vec![
                "1aeecd8e8abb6f87fc54f88a8c25478f69d42d450af782e73c0fca7f051669a415c0505ca61c904f960b46bbddf98cfb3dd1f9b18917b0b39e95d8c899889530".to_string(),
            ],
        });
    }

    #[test]
    fn test_parse_7zip() {
        init();

        let data = br#"# Maintainer: Alex Xu (Hello71) <alex_y_xu@yahoo.ca>
pkgname=7zip
pkgver=23.01
#_pkgver=${pkgver//./} # Can't parse this and don't support _pkgver
_pkgver=2301
pkgrel=0
pkgdesc="File archiver with a high compression ratio"
url="https://7-zip.org/"
arch="all"
license="LGPL-2.0-only"
subpackages="$pkgname-doc"
source="https://7-zip.org/a/7z$_pkgver-src.tar.xz
	armv7.patch
	7-zip-flags.patch
	7-zip-musl.patch
	"
builddir="$srcdir"

provides="7zip-virtual p7zip=$pkgver-r$pkgrel"
replaces="p7zip"
provider_priority=100

build() {
	cd CPP/7zip/Bundles/Alone2
	mkdir -p b/g
	# TODO: enable asm (requires jwasm or uasm)
	# DISABLE_RAR: RAR codec is non-free
	# -D_GNU_SOURCE: broken sched.h defines
	make -f ../../cmpl_gcc.mak \
		CC="${CC:-cc} $CFLAGS $LDFLAGS -D_GNU_SOURCE" \
		CXX="${CXX:-c++} $CXXFLAGS $LDFLAGS -D_GNU_SOURCE" \
		DISABLE_RAR=1
}

check() {
	# no proper test suite so just try to compress and decompress some files
	mkdir tmp
	CPP/7zip/Bundles/Alone2/b/g/7zz a tmp/7z$_pkgver-src.7z Asm C CPP DOC
	cd tmp
	../CPP/7zip/Bundles/Alone2/b/g/7zz x 7z$_pkgver-src.7z
	# TODO: check if extracted result is identical
}

package() {
	install -Dm755 CPP/7zip/Bundles/Alone2/b/g/7zz "$pkgdir"/usr/bin/7zz
	ln -s 7zz "$pkgdir"/usr/bin/7z

	install -Dm644 "$builddir"/DOC/* -t "$pkgdir"/usr/share/doc/$pkgname/
}

sha512sums="
e39f660c023aa65e55388be225b5591fe2a5c9138693f3c9107e2eb4ce97fafde118d3375e01ada99d29de9633f56221b5b3d640c982178884670cd84c8aa986  7z2301-src.tar.xz
e52e542709a23ced76b651adf54609efae705801e940e74310ae4e67070bdb3841da5b801362aa0329b77993cdc3f6cd63ac2802240b16cde865f9d01bb1936d  armv7.patch
dfecb69861d00ee47311d83930adf80321b3c95ae01ce325677bde7aee6aa880a1979b0aa2909d9acb7a88ff31f910ac545ac218a0b5fd9e1270df2276b46d44  7-zip-flags.patch
c652a87ad95f61901820adb61f3d1ceacedcb8aeaf9e89b2b728b7372eff67d9669eb363d5b2d2fb848ff2d8c5a727134fe13cc77d1215df7b2d32fe87711ebf  7-zip-musl.patch
"

"#;
        let apkbuild = parse(data).unwrap();
        assert_eq!(
            apkbuild,
            Apkbuild {
                pkgname: Some("7zip".to_string()),
                pkgver: Some("23.01".to_string()),
                url: Some("https://7-zip.org/".to_string()),

                source: vec![
                    "https://7-zip.org/a/7z23.01-src.tar.xz".to_string(),
                    "armv7.patch".to_string(),
                    "7-zip-flags.patch".to_string(),
                    "7-zip-musl.patch".to_string()
                ],
                sha512sums: vec![
                    "e39f660c023aa65e55388be225b5591fe2a5c9138693f3c9107e2eb4ce97fafde118d3375e01ada99d29de9633f56221b5b3d640c982178884670cd84c8aa986".to_string(),
                    "e52e542709a23ced76b651adf54609efae705801e940e74310ae4e67070bdb3841da5b801362aa0329b77993cdc3f6cd63ac2802240b16cde865f9d01bb1936d".to_string(),
                    "dfecb69861d00ee47311d83930adf80321b3c95ae01ce325677bde7aee6aa880a1979b0aa2909d9acb7a88ff31f910ac545ac218a0b5fd9e1270df2276b46d44".to_string(),
                    "c652a87ad95f61901820adb61f3d1ceacedcb8aeaf9e89b2b728b7372eff67d9669eb363d5b2d2fb848ff2d8c5a727134fe13cc77d1215df7b2d32fe87711ebf".to_string(),
                ],
            }
        );
    }
}
