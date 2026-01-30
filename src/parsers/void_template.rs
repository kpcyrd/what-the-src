use crate::errors::*;
use std::collections::HashMap;
use yash_syntax::syntax::{self, Unquote, Value};

/// Variables we keep track of for interpolation but nothing else
const TRACKED_VARIABLES: &[&str] = &["_pkgname", "_pkgver", "_gitrev", "_commit", "url"];

#[derive(Debug, Default, PartialEq)]
pub struct Template {
    pub pkgname: Option<String>,
    pub version: Option<String>,
    pub extra: HashMap<&'static str, String>,

    pub distfiles: Vec<String>,
    pub checksum: Vec<String>,
}

impl Template {
    pub fn resolve_vars(&self, mut text: &str) -> Result<String> {
        let mut out = String::new();

        'outer: while !text.is_empty() {
            if let Some((before, after)) = text.split_once('$') {
                let vars = [
                    ("pkgname", self.pkgname.as_deref()),
                    ("version", self.version.as_deref()),
                    // https://github.com/void-linux/void-packages/blob/master/common/environment/setup/misc.sh
                    (
                        "SOURCEFORGE_SITE",
                        Some("https://downloads.sourceforge.net/sourceforge"),
                    ),
                    (
                        "NONGNU_SITE",
                        Some("https://download.savannah.nongnu.org/releases"),
                    ),
                    ("UBUNTU_SITE", Some("http://archive.ubuntu.com/ubuntu/pool")),
                    ("XORG_SITE", Some("https://www.x.org/releases/individual")),
                    ("DEBIAN_SITE", Some("https://ftp.debian.org/debian/pool")),
                    ("GNOME_SITE", Some("https://download.gnome.org/sources")),
                    ("KERNEL_SITE", Some("https://www.kernel.org/pub/linux")),
                    ("CPAN_SITE", Some("https://www.cpan.org/modules/by-module")),
                    (
                        "PYPI_SITE",
                        Some("https://files.pythonhosted.org/packages/source"),
                    ),
                    ("MOZILLA_SITE", Some("https://ftp.mozilla.org/pub")),
                    ("GNU_SITE", Some("https://ftp.gnu.org/gnu")),
                    ("FREEDESKTOP_SITE", Some("https://freedesktop.org/software")),
                    ("KDE_SITE", Some("https://download.kde.org/stable")),
                    (
                        "VIDEOLAN_SITE",
                        Some("https://download.videolan.org/pub/videolan"),
                    ),
                ]
                .into_iter()
                .chain(
                    self.extra
                        .iter()
                        .map(|(key, value)| (*key, Some(value.as_str()))),
                );

                out.push_str(before);
                let (after, curly) = after
                    .strip_prefix('{')
                    .map(|x| (x, true))
                    .unwrap_or((after, false));

                for (name, value) in vars {
                    if let Some(after) = after.strip_prefix(name) {
                        let Some(value) = value else {
                            return Err(Error::UnknownVariable(name.to_string()));
                        };
                        out.push_str(value);
                        text = if curly {
                            after.strip_prefix('}').ok_or_else(|| {
                                Error::InvalidPkgbuild("Missing closing }".to_string())
                            })?
                        } else {
                            after
                        };
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

    pub fn register_var(&mut self, key: &'static str, value: String) {
        self.extra.insert(key, value);
    }
}

pub fn parse(script: &str) -> Result<Template> {
    let parsed: syntax::List = script
        .parse()
        .map_err(|err| Error::InvalidPkgbuild(format!("{err:#?}")))?;

    let mut template = Template::default();

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
                let value = template.resolve_vars(&value);

                match name {
                    "pkgname" => {
                        template.pkgname = Some(value?);
                    }
                    "version" => {
                        template.version = Some(value?);
                    }
                    "distfiles" => {
                        template.distfiles = value?
                            .trim()
                            .split('\n')
                            .map(|line| line.trim())
                            .map(|line| line.strip_prefix('"').unwrap_or(line))
                            .map(|line| line.strip_suffix('"').unwrap_or(line))
                            .map(String::from)
                            .collect();
                    }
                    "checksum" => {
                        template.checksum = value?
                            .trim()
                            .split('\n')
                            .map(|line| line.split_once("  ").map(|x| x.0).unwrap_or(line))
                            .map(String::from)
                            .collect();
                    }
                    _ => {
                        if let Some(name) = TRACKED_VARIABLES.iter().find(|x| **x == name) {
                            template.register_var(name, value?);
                        }
                    }
                }
            }
        }
    }

    Ok(template)
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

        let data = r#"# Template file for 'kirc'
pkgname=kirc
version=0.3.1
revision=1
build_style=gnu-makefile
short_desc=\"Tiny IRC client written in POSIX C99\"
maintainer=\"Orphaned <orphan@voidlinux.org>\"
license=\"MIT\"

mepage=\"http://kirc.io\"
distfiles=\"https://github.com/mcpcpc/${pkgname}/archive/refs/tags/${version}.tar.gz\"
checksum=19bb058a9845eb5b2febe6e8d658dcd06c194b58669f37837dbdf37627c7d7dd

post_install() {
    \tvlicense LICENSE
}
"#;

        let template = parse(data).unwrap();
        assert_eq!(
            template,
            Template {
                pkgname: Some("kirc".to_string()),
                version: Some("0.3.1".to_string()),
                extra: [].into_iter().collect(),

                distfiles: vec![
                    "https://github.com/mcpcpc/kirc/archive/refs/tags/0.3.1.tar.gz".to_string(),
                ],
                checksum: vec![
                    "19bb058a9845eb5b2febe6e8d658dcd06c194b58669f37837dbdf37627c7d7dd".to_string(),
                ],
            }
        );
    }
}
