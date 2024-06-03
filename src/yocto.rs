use crate::errors::*;
use std::collections::BTreeMap;
use std::str::Lines;

const DEFAULTS: &[(&str, &str)] = &[
    ("GNU_MIRROR", "https://ftp.gnu.org/gnu"),
    ("TARGET_ARCH", "x86_64"),
    ("WORKDIR", "."),
];

#[derive(Debug, PartialEq)]
pub struct Artifact {
    src: String,
    commit: Option<String>,
    sha256: Option<String>,
}

#[derive(Debug, Default, PartialEq)]
pub struct BitBake {
    vars: BTreeMap<String, String>,
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
    }

    fn assign<I: Into<String>, J: Into<String>>(&mut self, key: I, value: J) {
        self.vars.insert(key.into(), value.into());
    }

    pub fn artifacts(&self) -> Vec<Artifact> {
        let mut out = Vec::new();

        let Some(value) = self.vars.get("SRC_URI") else {
            return out;
        };

        for line in value.lines() {
            let mut iter = line.trim().split(';');
            let Some(src) = iter.next() else { continue };
            let name = iter.flat_map(|x| x.strip_prefix("name=")).next();

            match src.split_once("://") {
                Some(("http" | "https", _)) => {
                    let sha256 = self
                        .vars
                        .get(&if let Some(name) = name {
                            format!("SRC_URI[{name}.sha256sum]")
                        } else {
                            "SRC_URI[sha256sum]".to_string()
                        })
                        .cloned();

                    out.push(Artifact {
                        src: src.to_string(),
                        commit: None,
                        sha256,
                    });
                }
                Some(("git", tail)) => {
                    let commit = self
                        .vars
                        .get(&if let Some(name) = name {
                            format!("SRCREV_{name}")
                        } else {
                            "SRCREV".to_string()
                        })
                        .cloned();

                    out.push(Artifact {
                        src: format!("git+https://{tail}"),
                        commit,
                        sha256: None,
                    });
                }
                _ => (),
            }
        }
        out
    }

    fn tokenize(&self, lines: &mut Lines) -> Option<Vec<String>> {
        let Some(line) = lines.next() else {
            return None;
        };

        let mut out = Vec::new();

        let mut chars = line.chars().peekable();
        let mut token: Option<String> = None;
        let mut quoted = false;
        let mut var: Option<String> = None;

        loop {
            match (&mut var, chars.next()) {
                (var, Some('}')) if var.is_some() => {
                    if let Some(var) = var {
                        if let Some(value) = self.vars.get(var) {
                            token.get_or_insert_with(String::new).push_str(value);
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
                    token.get_or_insert_with(String::new);
                    quoted = !quoted;
                }
                (_, Some('\\')) => match chars.next() {
                    Some(c) => token.get_or_insert_with(String::new).push(c),
                    None => {
                        if let Some(line) = lines.next() {
                            token.get_or_insert_with(String::new).push('\n');
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
                        token.get_or_insert_with(String::new).push('$');
                    }
                }
                (_, Some(c)) => token.get_or_insert_with(String::new).push(c),
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
        bb.assign("PN", package);
    }
    if let Some(version) = version {
        bb.assign("PV", version);
    }

    let mut in_function = false;
    let mut lines = script.lines();
    while let Some(line) = bb.tokenize(&mut lines) {
        let mut iter = line.iter().peekable();
        iter.next_if(|x| *x == "export");

        let var = match iter.next().map(|x| x.as_str()) {
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
        if let Some(trailing) = iter.next() {
            todo!("trailing data: {trailing:?}");
        };

        match op.as_str() {
            "=" => bb.assign(var, value),
            "?=" => bb.assign(var, value),
            ".=" => {
                bb.vars.entry(var.into()).or_default().push_str(value);
            }
            // we don't need this operation
            // "+=" => (),
            _ => continue,
        }

        println!("line={line:?}");
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
                    "BBCLASSEXTEND".to_string() => "native nativesdk".to_string(),
                    "DEPENDS".to_string() => "gmp mpfr".to_string(),
                    "LIC_FILES_CHKSUM".to_string() => "file://COPYING.LESSER;md5=e6a600fd5e1d9cbde2d983680233ad02".to_string(),
                    "PN".to_string() => "libmpc".to_string(),
                    "PV".to_string() => "1.3.1".to_string(),
                    "S".to_string() => "./mpc-1.3.1".to_string(),
                    "SRC_URI".to_string() => "https://ftp.gnu.org/gnu/mpc/mpc-1.3.1.tar.gz".to_string(),
                    "SRC_URI[sha256sum]".to_string() => "ab642492f5cf882b74aa0cb730cd410a81edcdbec895183ce930e706c1c759b8".to_string(),
                },
                src_uri: vec![],
            }
        );
        let artifacts = bb.artifacts();
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
                    "COMPATIBLE_MACHINE".to_string() => "^(qemux86|qemux86-64|qemuarm64|qemuarm|qemuarmv5)$".to_string(),
                    "KBRANCH".to_string() => "v6.6/standard/tiny/base".to_string(),
                    "KCONFIG_MODE".to_string() => "--allnoconfig".to_string(),
                    "KCONF_BSP_AUDIT_LEVEL".to_string() => "2".to_string(),
                    "KERNEL_DEVICETREE:qemuarmv5".to_string() => "arm/versatile-pb.dtb".to_string(),
                    "KERNEL_FEATURES".to_string() => "".to_string(),
                    "KMETA".to_string() => "kernel-meta".to_string(),
                    "LIC_FILES_CHKSUM".to_string() => "file://COPYING;md5=6bc538ed5bd9a7fc9398086aedcd7e46".to_string(),
                    "LINUX_KERNEL_TYPE".to_string() => "tiny".to_string(),
                    "LINUX_VERSION".to_string() => "6.6.32".to_string(),
                    "PN".to_string() => "linux-yocto-tiny".to_string(),
                    "PV".to_string() => "6.6.32+git".to_string(),
                    "SRCREV_machine".to_string() => "9576b5b9f8e3c78e6c315f475def18e5c29e475a".to_string(),
                    "SRCREV_meta".to_string() => "66bebb6789d02e775d4c93d7ca4bf79c2ead4b28".to_string(),
                    "SRC_URI".to_string() => "git://git.yoctoproject.org/linux-yocto.git;branch=v6.6/standard/tiny/base;name=machine;protocol=https \n           git://git.yoctoproject.org/yocto-kernel-cache;type=kmeta;name=meta;branch=yocto-6.6;destsuffix=kernel-meta;protocol=https".to_string(),
                },
                src_uri: vec![],
            }
        );
        let artifacts = bb.artifacts();
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
                    "BBCLASSEXTEND".to_string() => "native".to_string(),
                    "CCLD_FOR_BUILD".to_string() => "".to_string(),
                    "CLEANBROKEN".to_string() => "1".to_string(),
                    "COMPATIBLE_HOST".to_string() => "(i.86|x86_64|arm|aarch64).*-linux".to_string(),
                    "DESCRIPTION".to_string() => "efivar provides a simple command line interface to the UEFI variable facility".to_string(),
                    "HOMEPAGE".to_string() => "https://github.com/rhboot/efivar".to_string(),
                    "LICENSE".to_string() => "LGPL-2.1-or-later".to_string(),
                    "LIC_FILES_CHKSUM".to_string() => "file://COPYING;md5=6626bb1e20189cfa95f2c508ba286393".to_string(),
                    "PN".to_string() => "efivar".to_string(),
                    "PV".to_string() => "39+39+git".to_string(),
                    "RRECOMMENDS:efivar:class-target".to_string() => "kernel-module-efivarfs".to_string(),
                    "S".to_string() => "./git".to_string(),
                    "SRCREV".to_string() => "c47820c37ac26286559ec004de07d48d05f3308c".to_string(),
                    "SRC_URI".to_string() => "git://github.com/rhinstaller/efivar.git;branch=main;protocol=https \n           file://0001-docs-do-not-build-efisecdb-manpage.patch \n           ".to_string(),
                    "SUMMARY".to_string() => "Tools to manipulate UEFI variables".to_string(),
                },
                src_uri: vec![],
            }
        );
        let artifacts = bb.artifacts();
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
                    "CVE_PRODUCT".to_string() => "golang:go".to_string(),
                    "HOMEPAGE".to_string() => " http://golang.org/".to_string(),
                    "LICENSE".to_string() => "BSD-3-Clause".to_string(),
                    "LIC_FILES_CHKSUM".to_string() => "file://LICENSE;md5=5d4950ecb7b26d2c5e4e7b4e0dd74707".to_string(),
                    "PN".to_string() => "go-binary-native".to_string(),
                    "PROVIDES".to_string() => "go-native".to_string(),
                    "PV".to_string() => "1.22.3".to_string(),
                    "S".to_string() => "./go".to_string(),
                    "SRC_URI".to_string() => "https://dl.google.com/go/go1.22.3.-.tar.gz;name=go_".to_string(),
                    "SRC_URI[go_linux_amd64.sha256sum]".to_string() => "8920ea521bad8f6b7bc377b4824982e011c19af27df88a815e3586ea895f1b36".to_string(),
                    "SRC_URI[go_linux_arm64.sha256sum]".to_string() => "6c33e52a5b26e7aa021b94475587fce80043a727a54ceb0eee2f9fc160646434".to_string(),
                    "SRC_URI[go_linux_ppc64le.sha256sum]".to_string() => "04b7b05283de30dd2da20bf3114b2e22cc727938aed3148babaf35cc951051ac".to_string(),
                    "SUMMARY".to_string() => "Go programming language compiler (upstream binary for bootstrap)".to_string(),
                    "UPSTREAM_CHECK_REGEX".to_string() => "go(?P<pver>d+(.d+)+).linux".to_string(),
                    "UPSTREAM_CHECK_URI".to_string() => "https://golang.org/dl/".to_string(),
                },
                src_uri: vec![],
            }
        );
        let artifacts = bb.artifacts();
        assert_eq!(artifacts, &[]);
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
                String::from("LINUX_KERNEL_TYPE"),
                String::from("="),
                String::from("tiny"),
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
        assert_eq!(line, &[
            String::from("SRC_URI"),
            String::from("="),
            String::from("git://git.yoctoproject.org/linux-yocto.git;branch=v6.6/standard/tiny/base;name=machine;protocol=https \n                   git://git.yoctoproject.org/yocto-kernel-cache;type=kmeta;name=meta;branch=yocto-6.6;destsuffix=kernel-meta;protocol=https"),
        ]);
    }

    #[test]
    fn test_lex_assignment_empty_str() {
        let bb = BitBake::default();
        let line = bb.tokenize(&mut r#"KERNEL_FEATURES = """#.lines()).unwrap();
        assert_eq!(
            line,
            &[
                String::from("KERNEL_FEATURES"),
                String::from("="),
                String::from(""),
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
                String::from("COMPATIBLE_MACHINE"),
                String::from("="),
                String::from("^(qemux86|qemux86-64|qemuarm64|qemuarm|qemuarmv5)$"),
            ]
        );
    }
}
