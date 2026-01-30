use crate::errors::*;
use std::collections::BTreeMap;
use std::mem;
use std::str::Lines;

const DEFAULTS: &[(&str, &str)] = &[
    ("APACHE_MIRROR", "https://archive.apache.org/dist"),
    ("CPAN_MIRROR", "https://search.cpan.org/CPAN"),
    ("DEBIAN_MIRROR", "http://ftp.debian.org/debian/pool"),
    ("GNOME_MIRROR", "https://download.gnome.org/sources"),
    ("GNUPG_MIRROR", "https://www.gnupg.org/ftp/gcrypt"),
    ("GNU_MIRROR", "https://ftp.gnu.org/gnu"),
    ("KERNELORG_MIRROR", "https://cdn.kernel.org/pub"),
    ("MLPREFIX", ""),
    (
        "SAVANNAH_GNU_MIRROR",
        "https://download.savannah.gnu.org/releases",
    ),
    (
        "SAVANNAH_NONGNU_MIRROR",
        "http://download-mirror.savannah.nongnu.org/releases",
    ),
    ("SOURCEFORGE_MIRROR", "https://downloads.sourceforge.net"),
    ("TARGET_ARCH", "x86_64"),
    ("WORKDIR", "."),
    ("XORG_MIRROR", "https://www.x.org/releases"),
];

#[derive(Debug, PartialEq)]
pub struct Artifact {
    pub src: String,
    pub commit: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum Value {
    Valid(String),
    Poisoned(String),
}

impl Default for Value {
    fn default() -> Self {
        Self::Valid(String::new())
    }
}

impl Value {
    pub fn maybe_poisoned(&self) -> &str {
        match self {
            Self::Valid(s) => s,
            Self::Poisoned(s) => s,
        }
    }

    pub fn push(&mut self, c: char) {
        match self {
            Self::Valid(s) => s.push(c),
            Self::Poisoned(s) => s.push(c),
        }
    }

    pub fn push_value(&mut self, other: &Value) {
        *self = match (mem::take(self), other) {
            (Self::Valid(s), Self::Valid(other)) => Self::Valid(s + other),
            (Self::Valid(s), Self::Poisoned(other)) => Self::Poisoned(s + other),
            (Self::Poisoned(s), other) => Self::Poisoned(s + other.maybe_poisoned()),
        };
    }

    pub fn to_string(&self) -> Result<String> {
        match self {
            Self::Valid(s) => Ok(s.to_string()),
            Self::Poisoned(s) => Err(Error::YoctoPoisonedStr(s.clone())),
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct BitBake {
    vars: BTreeMap<String, Value>,
    src_uri: Vec<String>,
}

impl BitBake {
    fn populate(&mut self) {
        for (key, value) in DEFAULTS {
            self.assign(*key, *value);
        }
    }

    fn depopulate(&mut self) {
        for (key, _value) in DEFAULTS {
            self.vars.remove(*key);
        }
        self.vars.remove("GITHUB_BASE_URI");
    }

    fn assign<I: Into<String>, J: Into<String>>(&mut self, key: I, value: J) {
        self.vars.insert(key.into(), Value::Valid(value.into()));
    }

    fn assign_value<I: Into<String>>(&mut self, key: I, value: Value) {
        self.vars.insert(key.into(), value);
    }

    fn get_var<I: Into<String>>(&self, key: I) -> Result<Option<String>> {
        let key = key.into();
        let Some(value) = self.vars.get(&key) else {
            return Ok(None);
        };
        Ok(Some(value.to_string()?))
    }

    pub fn artifacts(&self) -> Result<Vec<Artifact>> {
        let mut out = Vec::new();

        let Some(value) = self.get_var("SRC_URI")? else {
            return Ok(out);
        };

        for line in value.lines() {
            let mut iter = line.trim().split(';');
            let Some(src) = iter.next() else { continue };
            let name = iter.flat_map(|x| x.strip_prefix("name=")).next();

            match src.split_once("://") {
                Some(("http" | "https", _)) => {
                    let sha256 = self.get_var(if let Some(name) = name {
                        format!("SRC_URI[{name}.sha256sum]")
                    } else {
                        "SRC_URI[sha256sum]".to_string()
                    })?;

                    out.push(Artifact {
                        src: src.to_string(),
                        commit: None,
                        sha256,
                    });
                }
                Some(("git", tail)) => {
                    let commit = self.get_var(if let Some(name) = name {
                        format!("SRCREV_{name}")
                    } else {
                        "SRCREV".to_string()
                    })?;

                    out.push(Artifact {
                        src: format!("git+https://{tail}"),
                        commit,
                        sha256: None,
                    });
                }
                _ => (),
            }
        }
        Ok(out)
    }

    fn tokenize(&self, lines: &mut Lines) -> Option<Vec<Value>> {
        let line = lines.next()?;

        let mut out = Vec::new();

        let mut chars = line.chars().peekable();
        let mut token: Option<Value> = None;
        let mut quoted = false;
        let mut var: Option<String> = None;

        loop {
            match (&mut var, chars.next()) {
                (var, Some('}')) if var.is_some() => {
                    if let Some(var) = var {
                        let token = token.get_or_insert_with(Value::default);
                        if let Some(value) = self.vars.get(var) {
                            token.push_value(value);
                        } else {
                            token.push_value(&Value::Poisoned(format!("${{{var}}}")));
                        }
                    }
                    *var = None;
                }
                (Some(var), Some(c)) => var.push(c),

                (_, Some(' ')) if !quoted => {
                    if let Some(token) = token.take() {
                        out.push(token);
                    }
                }
                (_, Some('\"')) => {
                    token.get_or_insert_with(Value::default);
                    quoted = !quoted;
                }
                (_, Some('\\')) => match chars.next() {
                    Some(c) => token.get_or_insert_with(Value::default).push(c),
                    None => {
                        if let Some(line) = lines.next() {
                            token.get_or_insert_with(Value::default).push('\n');
                            chars = line.chars().peekable();
                        } else {
                            break;
                        }
                    }
                },
                (_, Some('$')) => {
                    if chars.next_if_eq(&'{').is_some() {
                        var = Some(String::new());
                    } else {
                        token.get_or_insert_with(Value::default).push('$');
                    }
                }
                (_, Some(c)) => token.get_or_insert_with(Value::default).push(c),
                (_, None) => {
                    if let Some(token) = token {
                        out.push(token);
                    }
                    break;
                }
            }
        }

        Some(out)
    }
}

pub fn parse(script: &str, package: Option<String>, version: Option<String>) -> Result<BitBake> {
    let mut bb = BitBake::default();
    bb.populate();
    if let Some(package) = package {
        bb.assign("PN", package.clone());

        let mut bpn = package.as_str();
        for suffix in [
            "-native",
            "-cross",
            "-initial",
            "-intermediate",
            "-crosssdk",
            "-cross-canadian",
        ] {
            bpn = bpn.strip_suffix(suffix).unwrap_or(bpn);
        }

        bb.assign("BPN", bpn);
        bb.assign(
            "GITHUB_BASE_URI",
            format!("https://github.com/{bpn}/{bpn}/releases"),
        );

        if let Some(version) = &version {
            bb.assign("BP", format!("{bpn}-{version}"));
        }
    }
    if let Some(version) = version {
        bb.assign("PV", version);
    }

    let mut in_function = false;
    let mut lines = script.lines();
    while let Some(line) = bb.tokenize(&mut lines) {
        let mut iter = line.into_iter().peekable();
        iter.next_if(|x| x.maybe_poisoned() == "export");

        let value = iter.next();
        let var = match value.as_ref().map(|x| x.maybe_poisoned()) {
            Some(var) if var.starts_with('#') => continue,
            Some(var) if var.ends_with("()") => {
                in_function = true;
                continue;
            }
            Some("}") if in_function => {
                in_function = false;
                continue;
            }
            Some(var) if !in_function => var,
            _ => continue,
        };

        let Some(op) = iter.next() else { continue };
        let Some(value) = iter.next() else { continue };

        match op.maybe_poisoned() {
            "=" => bb.assign_value(var, value),
            "?=" => bb.assign_value(var, value),
            ".=" => {
                bb.vars.entry(var.into()).or_default().push_value(&value);
            }
            // we don't need this operation
            // "+=" => (),
            _ => continue,
        }
    }

    bb.depopulate();
    Ok(bb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libmpc_without_pv() {
        let data = r#"require libmpc.inc

DEPENDS = "gmp mpfr"

LIC_FILES_CHKSUM = "file://COPYING.LESSER;md5=e6a600fd5e1d9cbde2d983680233ad02"
SRC_URI = "${GNU_MIRROR}/mpc/mpc-${PV}.tar.gz"

SRC_URI[sha256sum] = "ab642492f5cf882b74aa0cb730cd410a81edcdbec895183ce930e706c1c759b8"

S = "${WORKDIR}/mpc-${PV}"
BBCLASSEXTEND = "native nativesdk"
"#;
        let bb = parse(data, Some("libmpc".to_string()), Some("1.3.1".to_string())).unwrap();
        assert_eq!(
            bb,
            BitBake {
                vars: maplit::btreemap! {
                    "BBCLASSEXTEND".to_string() => Value::Valid("native nativesdk".to_string()),
                    "BP".to_string() => Value::Valid("libmpc-1.3.1".to_string()),
                    "BPN".to_string() => Value::Valid("libmpc".to_string()),
                    "DEPENDS".to_string() => Value::Valid("gmp mpfr".to_string()),
                    "LIC_FILES_CHKSUM".to_string() => Value::Valid("file://COPYING.LESSER;md5=e6a600fd5e1d9cbde2d983680233ad02".to_string()),
                    "PN".to_string() => Value::Valid("libmpc".to_string()),
                    "PV".to_string() => Value::Valid("1.3.1".to_string()),
                    "S".to_string() => Value::Valid("./mpc-1.3.1".to_string()),
                    "SRC_URI".to_string() => Value::Valid("https://ftp.gnu.org/gnu/mpc/mpc-1.3.1.tar.gz".to_string()),
                    "SRC_URI[sha256sum]".to_string() => Value::Valid("ab642492f5cf882b74aa0cb730cd410a81edcdbec895183ce930e706c1c759b8".to_string()),
                },
                src_uri: vec![],
            }
        );
        let artifacts = bb.artifacts().unwrap();
        assert_eq!(
            artifacts,
            &[Artifact {
                src: "https://ftp.gnu.org/gnu/mpc/mpc-1.3.1.tar.gz".to_string(),
                commit: None,
                sha256: Some(
                    "ab642492f5cf882b74aa0cb730cd410a81edcdbec895183ce930e706c1c759b8".to_string()
                ),
            }]
        );
    }

    #[test]
    fn test_linux_yocto_tiny_with_pv() {
        let data = r#"KBRANCH ?= "v6.6/standard/tiny/base"

LINUX_KERNEL_TYPE = "tiny"
KCONFIG_MODE = "--allnoconfig"

require recipes-kernel/linux/linux-yocto.inc

# CVE exclusions
include recipes-kernel/linux/cve-exclusion_6.6.inc

LINUX_VERSION ?= "6.6.32"
LIC_FILES_CHKSUM = "file://COPYING;md5=6bc538ed5bd9a7fc9398086aedcd7e46"

DEPENDS += "${@bb.utils.contains('ARCH', 'x86', 'elfutils-native', '', d)}"
DEPENDS += "openssl-native util-linux-native"

KMETA = "kernel-meta"
KCONF_BSP_AUDIT_LEVEL = "2"

SRCREV_machine ?= "9576b5b9f8e3c78e6c315f475def18e5c29e475a"
SRCREV_meta ?= "66bebb6789d02e775d4c93d7ca4bf79c2ead4b28"

PV = "${LINUX_VERSION}+git"

SRC_URI = "git://git.yoctoproject.org/linux-yocto.git;branch=${KBRANCH};name=machine;protocol=https \
           git://git.yoctoproject.org/yocto-kernel-cache;type=kmeta;name=meta;branch=yocto-6.6;destsuffix=${KMETA};protocol=https"

COMPATIBLE_MACHINE = "^(qemux86|qemux86-64|qemuarm64|qemuarm|qemuarmv5)$"

# Functionality flags
KERNEL_FEATURES = ""

KERNEL_DEVICETREE:qemuarmv5 = "arm/versatile-pb.dtb"
"#;
        let bb = parse(
            data,
            Some("linux-yocto-tiny".to_string()),
            Some("6.6".to_string()),
        )
        .unwrap();
        assert_eq!(
            bb,
            BitBake {
                vars: maplit::btreemap! {
                    "BP".to_string() => Value::Valid("linux-yocto-tiny-6.6".to_string()),
                    "BPN".to_string() => Value::Valid("linux-yocto-tiny".to_string()),
                    "COMPATIBLE_MACHINE".to_string() => Value::Valid("^(qemux86|qemux86-64|qemuarm64|qemuarm|qemuarmv5)$".to_string()),
                    "KBRANCH".to_string() => Value::Valid("v6.6/standard/tiny/base".to_string()),
                    "KCONFIG_MODE".to_string() => Value::Valid("--allnoconfig".to_string()),
                    "KCONF_BSP_AUDIT_LEVEL".to_string() => Value::Valid("2".to_string()),
                    "KERNEL_DEVICETREE:qemuarmv5".to_string() => Value::Valid("arm/versatile-pb.dtb".to_string()),
                    "KERNEL_FEATURES".to_string() => Value::Valid("".to_string()),
                    "KMETA".to_string() => Value::Valid("kernel-meta".to_string()),
                    "LIC_FILES_CHKSUM".to_string() => Value::Valid("file://COPYING;md5=6bc538ed5bd9a7fc9398086aedcd7e46".to_string()),
                    "LINUX_KERNEL_TYPE".to_string() => Value::Valid("tiny".to_string()),
                    "LINUX_VERSION".to_string() => Value::Valid("6.6.32".to_string()),
                    "PN".to_string() => Value::Valid("linux-yocto-tiny".to_string()),
                    "PV".to_string() => Value::Valid("6.6.32+git".to_string()),
                    "SRCREV_machine".to_string() => Value::Valid("9576b5b9f8e3c78e6c315f475def18e5c29e475a".to_string()),
                    "SRCREV_meta".to_string() => Value::Valid("66bebb6789d02e775d4c93d7ca4bf79c2ead4b28".to_string()),
                    "SRC_URI".to_string() => Value::Valid("git://git.yoctoproject.org/linux-yocto.git;branch=v6.6/standard/tiny/base;name=machine;protocol=https \n           git://git.yoctoproject.org/yocto-kernel-cache;type=kmeta;name=meta;branch=yocto-6.6;destsuffix=kernel-meta;protocol=https".to_string()),
                },
                src_uri: vec![],
            }
        );
        let artifacts = bb.artifacts().unwrap();
        assert_eq!(
            artifacts,
            &[
                Artifact {
                    src: "git+https://git.yoctoproject.org/linux-yocto.git".to_string(),
                    commit: Some("9576b5b9f8e3c78e6c315f475def18e5c29e475a".to_string()),
                    sha256: None
                },
                Artifact {
                    src: "git+https://git.yoctoproject.org/yocto-kernel-cache".to_string(),
                    commit: Some("66bebb6789d02e775d4c93d7ca4bf79c2ead4b28".to_string()),
                    sha256: None
                }
            ]
        );
    }

    #[test]
    fn test_efivar() {
        let data = r#"SUMMARY = "Tools to manipulate UEFI variables"
DESCRIPTION = "efivar provides a simple command line interface to the UEFI variable facility"
HOMEPAGE = "https://github.com/rhboot/efivar"

LICENSE = "LGPL-2.1-or-later"
LIC_FILES_CHKSUM = "file://COPYING;md5=6626bb1e20189cfa95f2c508ba286393"

COMPATIBLE_HOST = "(i.86|x86_64|arm|aarch64).*-linux"

SRC_URI = "git://github.com/rhinstaller/efivar.git;branch=main;protocol=https \
           file://0001-docs-do-not-build-efisecdb-manpage.patch \
           "
SRCREV = "c47820c37ac26286559ec004de07d48d05f3308c"
PV .= "+39+git"

S = "${WORKDIR}/git"

inherit pkgconfig

export CCLD_FOR_BUILD = "${BUILD_CCLD}"

do_compile() {
    oe_runmake ERRORS= HOST_CFLAGS="${BUILD_CFLAGS}" HOST_LDFLAGS="${BUILD_LDFLAGS}"
}

do_install() {
    oe_runmake install DESTDIR=${D}
}

BBCLASSEXTEND = "native"

RRECOMMENDS:${PN}:class-target = "kernel-module-efivarfs"

CLEANBROKEN = "1"
"#;
        let bb = parse(data, Some("efivar".to_string()), Some("39".to_string())).unwrap();
        assert_eq!(
            bb,
            BitBake {
                vars: maplit::btreemap! {
                    "BBCLASSEXTEND".to_string() => Value::Valid("native".to_string()),
                    "BP".to_string() => Value::Valid("efivar-39".to_string()),
                    "BPN".to_string() => Value::Valid("efivar".to_string()),
                    "CCLD_FOR_BUILD".to_string() => Value::Poisoned("${BUILD_CCLD}".to_string()),
                    "CLEANBROKEN".to_string() => Value::Valid("1".to_string()),
                    "COMPATIBLE_HOST".to_string() => Value::Valid("(i.86|x86_64|arm|aarch64).*-linux".to_string()),
                    "DESCRIPTION".to_string() => Value::Valid("efivar provides a simple command line interface to the UEFI variable facility".to_string()),
                    "HOMEPAGE".to_string() => Value::Valid("https://github.com/rhboot/efivar".to_string()),
                    "LICENSE".to_string() => Value::Valid("LGPL-2.1-or-later".to_string()),
                    "LIC_FILES_CHKSUM".to_string() => Value::Valid("file://COPYING;md5=6626bb1e20189cfa95f2c508ba286393".to_string()),
                    "PN".to_string() => Value::Valid("efivar".to_string()),
                    "PV".to_string() => Value::Valid("39+39+git".to_string()),
                    "RRECOMMENDS:efivar:class-target".to_string() => Value::Valid("kernel-module-efivarfs".to_string()),
                    "S".to_string() => Value::Valid("./git".to_string()),
                    "SRCREV".to_string() => Value::Valid("c47820c37ac26286559ec004de07d48d05f3308c".to_string()),
                    "SRC_URI".to_string() => Value::Valid("git://github.com/rhinstaller/efivar.git;branch=main;protocol=https \n           file://0001-docs-do-not-build-efisecdb-manpage.patch \n           ".to_string()),
                    "SUMMARY".to_string() => Value::Valid("Tools to manipulate UEFI variables".to_string()),
                },
                src_uri: vec![],
            }
        );
        let artifacts = bb.artifacts().unwrap();
        assert_eq!(
            artifacts,
            &[Artifact {
                src: "git+https://github.com/rhinstaller/efivar.git".to_string(),
                commit: Some("c47820c37ac26286559ec004de07d48d05f3308c".to_string()),
                sha256: None,
            }]
        );
    }

    #[test]
    fn test_go_binary_native() {
        let data = r#"# This recipe is for bootstrapping our go-cross from a prebuilt binary of Go from golang.org.

SUMMARY = "Go programming language compiler (upstream binary for bootstrap)"
HOMEPAGE = " http://golang.org/"
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://LICENSE;md5=5d4950ecb7b26d2c5e4e7b4e0dd74707"

PROVIDES = "go-native"

# Checksums available at https://go.dev/dl/
SRC_URI = "https://dl.google.com/go/go${PV}.${BUILD_GOOS}-${BUILD_GOARCH}.tar.gz;name=go_${BUILD_GOTUPLE}"
SRC_URI[go_linux_amd64.sha256sum] = "8920ea521bad8f6b7bc377b4824982e011c19af27df88a815e3586ea895f1b36"
SRC_URI[go_linux_arm64.sha256sum] = "6c33e52a5b26e7aa021b94475587fce80043a727a54ceb0eee2f9fc160646434"
SRC_URI[go_linux_ppc64le.sha256sum] = "04b7b05283de30dd2da20bf3114b2e22cc727938aed3148babaf35cc951051ac"

UPSTREAM_CHECK_URI = "https://golang.org/dl/"
UPSTREAM_CHECK_REGEX = "go(?P<pver>\d+(\.\d+)+)\.linux"

CVE_PRODUCT = "golang:go"

S = "${WORKDIR}/go"

inherit goarch native

do_compile() {
    :
}

make_wrapper() {
	rm -f ${D}${bindir}/$1
	cat <<END >${D}${bindir}/$1
#!/bin/bash
here=\`dirname \$0\`
export GOROOT="${GOROOT:-\`readlink -f \$here/../lib/go\`}"
\$here/../lib/go/bin/$1 "\$@"
END
	chmod +x ${D}${bindir}/$1
}

do_install() {
    find ${S} -depth -type d -name testdata -exec rm -rf {} +

	install -d ${D}${bindir} ${D}${libdir}/go
	cp --preserve=mode,timestamps -R ${S}/ ${D}${libdir}/

	for f in ${S}/bin/*
	do
	  	make_wrapper `basename $f`
	done
}
"#;
        let bb = parse(
            data,
            Some("go-binary-native".to_string()),
            Some("1.22.3".to_string()),
        )
        .unwrap();
        assert_eq!(
            bb,
            BitBake {
                vars: maplit::btreemap! {
                    "BP".to_string() => Value::Valid("go-binary-1.22.3".to_string()),
                    "BPN".to_string() => Value::Valid("go-binary".to_string()),
                    "CVE_PRODUCT".to_string() => Value::Valid("golang:go".to_string()),
                    "HOMEPAGE".to_string() => Value::Valid(" http://golang.org/".to_string()),
                    "LICENSE".to_string() => Value::Valid("BSD-3-Clause".to_string()),
                    "LIC_FILES_CHKSUM".to_string() => Value::Valid("file://LICENSE;md5=5d4950ecb7b26d2c5e4e7b4e0dd74707".to_string()),
                    "PN".to_string() => Value::Valid("go-binary-native".to_string()),
                    "PROVIDES".to_string() => Value::Valid("go-native".to_string()),
                    "PV".to_string() => Value::Valid("1.22.3".to_string()),
                    "S".to_string() => Value::Valid("./go".to_string()),
                    "SRC_URI".to_string() => Value::Poisoned("https://dl.google.com/go/go1.22.3.${BUILD_GOOS}-${BUILD_GOARCH}.tar.gz;name=go_${BUILD_GOTUPLE}".to_string()),
                    "SRC_URI[go_linux_amd64.sha256sum]".to_string() => Value::Valid("8920ea521bad8f6b7bc377b4824982e011c19af27df88a815e3586ea895f1b36".to_string()),
                    "SRC_URI[go_linux_arm64.sha256sum]".to_string() => Value::Valid("6c33e52a5b26e7aa021b94475587fce80043a727a54ceb0eee2f9fc160646434".to_string()),
                    "SRC_URI[go_linux_ppc64le.sha256sum]".to_string() => Value::Valid("04b7b05283de30dd2da20bf3114b2e22cc727938aed3148babaf35cc951051ac".to_string()),
                    "SUMMARY".to_string() => Value::Valid("Go programming language compiler (upstream binary for bootstrap)".to_string()),
                    "UPSTREAM_CHECK_REGEX".to_string() => Value::Valid("go(?P<pver>d+(.d+)+).linux".to_string()),
                    "UPSTREAM_CHECK_URI".to_string() => Value::Valid("https://golang.org/dl/".to_string()),
                },
                src_uri: vec![],
            }
        );
        let err = bb.artifacts();
        let Err(Error::YoctoPoisonedStr(err)) = err else {
            panic!("Did not get expected error: {err:?}")
        };
        assert_eq!(
            err,
            "https://dl.google.com/go/go1.22.3.${BUILD_GOOS}-${BUILD_GOARCH}.tar.gz;name=go_${BUILD_GOTUPLE}"
        );
    }

    #[test]
    fn test_lex_assignment() {
        let bb = BitBake::default();
        let line = bb
            .tokenize(&mut r#"LINUX_KERNEL_TYPE = "tiny""#.lines())
            .unwrap();
        assert_eq!(
            line,
            &[
                Value::Valid(String::from("LINUX_KERNEL_TYPE")),
                Value::Valid(String::from("=")),
                Value::Valid(String::from("tiny")),
            ]
        );
    }

    #[test]
    fn test_lex_assignment_multi_line() {
        let mut bb = BitBake::default();
        bb.assign("KBRANCH", "v6.6/standard/tiny/base");
        bb.assign("KMETA", "kernel-meta");
        let line = bb.tokenize(&mut r#"SRC_URI = "git://git.yoctoproject.org/linux-yocto.git;branch=${KBRANCH};name=machine;protocol=https \
                   git://git.yoctoproject.org/yocto-kernel-cache;type=kmeta;name=meta;branch=yocto-6.6;destsuffix=${KMETA};protocol=https""#.lines()).unwrap();
        assert_eq!(
            line,
            &[
                Value::Valid(String::from("SRC_URI")),
                Value::Valid(String::from("=")),
                Value::Valid(String::from(
                    "git://git.yoctoproject.org/linux-yocto.git;branch=v6.6/standard/tiny/base;name=machine;protocol=https \n                   git://git.yoctoproject.org/yocto-kernel-cache;type=kmeta;name=meta;branch=yocto-6.6;destsuffix=kernel-meta;protocol=https"
                )),
            ]
        );
    }

    #[test]
    fn test_lex_assignment_empty_str() {
        let bb = BitBake::default();
        let line = bb.tokenize(&mut r#"KERNEL_FEATURES = """#.lines()).unwrap();
        assert_eq!(
            line,
            &[
                Value::Valid(String::from("KERNEL_FEATURES")),
                Value::Valid(String::from("=")),
                Value::Valid(String::from("")),
            ]
        );
    }

    #[test]
    fn test_literal_dollar() {
        let bb = BitBake::default();
        let line = bb
            .tokenize(
                &mut r#"COMPATIBLE_MACHINE = "^(qemux86|qemux86-64|qemuarm64|qemuarm|qemuarmv5)$""#
                    .lines(),
            )
            .unwrap();
        assert_eq!(
            line,
            &[
                Value::Valid(String::from("COMPATIBLE_MACHINE")),
                Value::Valid(String::from("=")),
                Value::Valid(String::from(
                    "^(qemux86|qemux86-64|qemuarm64|qemuarm|qemuarmv5)$"
                )),
            ]
        );
    }
}
