use crate::errors::*;
use crate::sbom;
use data_encoding::BASE64;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const STRAIN: &str = "bun-lock";

#[derive(Debug, PartialEq)]
pub struct BunLock {
    pub data: String,
}

impl BunLock {
    pub fn parse(&self) -> Result<ParsedLock> {
        let json = serde_json5::from_str(&self.data)?;
        Ok(json)
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct ParsedLock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: u32,
    packages: BTreeMap<String, serde_json::Value>,
    #[serde(skip)]
    whatsrc_dedup: BTreeSet<sbom::Package>,
}

impl Iterator for ParsedLock {
    type Item = Result<sbom::Package>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((_key, value)) = self.packages.pop_first() {
            let Ok((id, url, _meta, integrity)) =
                serde_json::from_value::<(String, String, serde_json::Value, String)>(value)
            else {
                continue;
            };

            let Some((pkgname, pkgver)) = id.rsplit_once('@') else {
                continue;
            };
            let unnamespaced = pkgname.split('/').last().unwrap_or(pkgname);

            // Extract the checksum in our format (if possible)
            let checksum = integrity
                .split_once('-')
                .and_then(|(family, value)| Some((family, BASE64.decode(value.as_bytes()).ok()?)))
                .map(|(family, value)| {
                    let digest = hex::encode(value);
                    format!("{family}:{digest}")
                });

            let official_registry = url.is_empty();

            let url = if official_registry {
                format!("https://registry.npmjs.org/{pkgname}/-/{unnamespaced}-{pkgver}.tgz")
            } else {
                url
            };

            let pkg = sbom::Package {
                name: pkgname.to_string(),
                version: pkgver.to_string(),
                url: Some(url),
                checksum,
                official_registry,
            };

            if self.whatsrc_dedup.insert(pkg.clone()) {
                return Some(Ok(pkg));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::sbom::{Package, Sbom};

    /*
    #[test]
    fn test_parse_bun_lock_v0_reference() {
        let data = r#"
{
  "lockfileVersion": 0,
  "workspaces": {
    "": {
      "dependencies": {
        "uWebSocket.js": "uNetworking/uWebSockets.js#v20.51.0",
      },
    },
  },
  "packages": {
    "uWebSocket.js": ["uWebSockets.js@github:uNetworking/uWebSockets.js#6609a88", {}, "uNetworking-uWebSockets.js-6609a88"],
  }
}
"#;
        let bun = Sbom::new("bun-lock", data.to_string()).unwrap();
        let list = bun.to_packages().unwrap();
        assert_eq!(
            list,
            [
                Package {
                    name: "attrs".to_string(),
                    version: "25.4.0".to_string(),
                    url: Some(
                        "https://files.pythonhosted.org/packages/6b/5c/685e6633917e101e5dcb62b9dd76946cbb57c26e133bae9e0cd36033c0a9/attrs-25.4.0.tar.gz".to_string()
                    ),
                    checksum: Some(
                        "sha256:16d5969b87f0859ef33a48b35d55ac1be6e42ae49d5e853b597db70c35c57e11".to_string()
                    ),
                    official_registry: true,
                },
            ]
        );
    }
    */

    #[test]
    fn test_parse_bun_lock() {
        let data = r#"
{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "clawhub",
      "dependencies": {
        "@auth/core": "^0.37.4",
        "@convex-dev/auth": "^0.0.90",
        "@fontsource/bricolage-grotesque": "^5.2.10",
        "@fontsource/ibm-plex-mono": "^5.2.7",
        "@fontsource/manrope": "^5.2.8",
        "@monaco-editor/react": "^4.7.0",
        "@radix-ui/react-dropdown-menu": "^2.1.16",
        "@radix-ui/react-toggle-group": "^1.1.11",
        "@resvg/resvg-wasm": "^2.6.2",
        "@tailwindcss/vite": "^4.1.18",
        "@tanstack/react-devtools": "^0.9.4",
        "@tanstack/react-router": "^1.157.18",
        "@tanstack/react-router-devtools": "^1.157.18",
        "@tanstack/react-start": "^1.157.18",
        "@tanstack/router-plugin": "^1.157.18",
        "@vercel/analytics": "^1.6.1",
        "clawhub-schema": "workspace:*",
        "clsx": "^2.1.1",
        "convex": "^1.31.7",
        "fflate": "^0.8.2",
        "h3": "2.0.1-rc.11",
        "lucide-react": "^0.563.0",
        "monaco-editor": "^0.55.1",
        "nitro": "^3.0.1-alpha.2",
        "react": "^19.2.4",
        "react-dom": "^19.2.4",
        "react-markdown": "^10.1.0",
        "remark-gfm": "^4.0.1",
        "semver": "^7.7.3",
        "tailwind-merge": "^3.4.0",
        "tailwindcss": "^4.1.18",
        "vite-tsconfig-paths": "^6.0.5",
        "yaml": "^2.8.2",
      },
      "devDependencies": {
        "@playwright/test": "^1.58.1",
        "@tanstack/devtools-vite": "^0.5.0",
        "@testing-library/dom": "^10.4.1",
        "@testing-library/react": "^16.3.2",
        "@types/node": "^25.2.0",
        "@types/react": "^19.2.10",
        "@types/react-dom": "^19.2.3",
        "@types/semver": "^7.7.1",
        "@vitejs/plugin-react": "^5.1.2",
        "@vitest/coverage-v8": "^4.0.18",
        "jsdom": "^28.0.0",
        "only-allow": "^1.2.2",
        "oxfmt": "0.32.0",
        "oxlint": "^1.42.0",
        "oxlint-tsgolint": "^0.11.4",
        "typescript": "^5.9.3",
        "undici": "^7.19.2",
        "vite": "^7.3.1",
        "vitest": "^4.0.18",
      },
    },
    "packages/clawdhub": {
      "name": "clawhub",
      "version": "0.7.0",
      "bin": {
        "clawhub": "bin/clawdhub.js",
        "clawdhub": "bin/clawdhub.js",
      },
      "dependencies": {
        "@clack/prompts": "^0.11.0",
        "arktype": "^2.1.29",
        "commander": "^14.0.2",
        "fflate": "^0.8.2",
        "ignore": "^7.0.5",
        "json5": "^2.2.3",
        "mime": "^4.1.0",
        "ora": "^9.0.0",
        "p-retry": "^7.1.1",
        "semver": "^7.7.3",
        "undici": "^7.16.0",
      },
      "devDependencies": {
        "@types/node": "^25.0.9",
        "typescript": "^5.9.3",
      },
    },
    "packages/schema": {
      "name": "clawhub-schema",
      "version": "0.0.2",
      "dependencies": {
        "arktype": "^2.1.29",
      },
      "devDependencies": {
        "typescript": "^5.9.3",
      },
    },
  },
  "packages": {
    "@acemir/cssom": ["@acemir/cssom@0.9.31", "", {}, "sha512-ZnR3GSaH+/vJ0YlHau21FjfLYjMpYVIzTD8M8vIEQvIGxeOXyXdzCI140rrCY862p/C/BbzWsjc1dgnM9mkoTA=="],

    "@auth/core": ["@auth/core@0.37.4", "", { "dependencies": { "@panva/hkdf": "^1.2.1", "jose": "^5.9.6", "oauth4webapi": "^3.1.1", "preact": "10.24.3", "preact-render-to-string": "6.5.11" }, "peerDependencies": { "@simplewebauthn/browser": "^9.0.1", "@simplewebauthn/server": "^9.0.2", "nodemailer": "^6.8.0" }, "optionalPeers": ["@simplewebauthn/browser", "@simplewebauthn/server", "nodemailer"] }, "sha512-HOXJwXWXQRhbBDHlMU0K/6FT1v+wjtzdKhsNg0ZN7/gne6XPsIrjZ4daMcFnbq0Z/vsAbYBinQhhua0d77v7qw=="],

    "clawhub": ["clawhub@workspace:packages/clawdhub"],

    "clawhub-schema": ["clawhub-schema@workspace:packages/schema"],

    "h3": ["h3@2.0.1-rc.11", "", { "dependencies": { "rou3": "^0.7.12", "srvx": "^0.10.1" }, "peerDependencies": { "crossws": "^0.4.1" }, "optionalPeers": ["crossws"] }, "sha512-2myzjCqy32c1As9TjZW9fNZXtLqNedjFSrdFy2AjFBQQ3LzrnGoDdFDYfC0tV2e4vcyfJ2Sfo/F6NQhO2Ly/Mw=="],

    "h3-v2": ["h3@2.0.1-rc.11", "", { "dependencies": { "rou3": "^0.7.12", "srvx": "^0.10.1" }, "peerDependencies": { "crossws": "^0.4.1" }, "optionalPeers": ["crossws"] }, "sha512-2myzjCqy32c1As9TjZW9fNZXtLqNedjFSrdFy2AjFBQQ3LzrnGoDdFDYfC0tV2e4vcyfJ2Sfo/F6NQhO2Ly/Mw=="],

    "parse5-htmlparser2-tree-adapter": ["parse5-htmlparser2-tree-adapter@7.1.0", "", { "dependencies": { "domhandler": "^5.0.3", "parse5": "^7.0.0" } }, "sha512-ruw5xyKs6lrpo9x9rCZqZZnIUntICjQAd0Wsmp396Ul9lN/h+ifgVV1x1gZHi8euej6wTfpqX8j+BFQxF0NS/g=="],

    "zod": ["zod@3.25.76", "", {}, "sha512-gzUt/qt81nXsFGKIFcC3YnfEAx5NkunCfnDlvuBSSFS02bcXu4Lmea0AFIUwbLWxWPx3d9p8S5QoaujKcNQxcQ=="],

    "@babel/core/semver": ["semver@6.3.1", "", { "bin": { "semver": "bin/semver.js" } }, "sha512-BR7VvDCVHO+q2xBEWskxS6DJE1qRnb7DxzUrogb71CWoSficBxYsiAGd+Kl0mmq/MprG9yArRkyrQxTO6XjMzA=="],

    "@babel/helper-compilation-targets/lru-cache": ["lru-cache@5.1.1", "", { "dependencies": { "yallist": "^3.0.2" } }, "sha512-KpNARQA3Iwv+jTA0utUVVbrh+Jlrr1Fv0e56GGzAFOXN7dk/FviaDW8LHmK52DlcH4WP2n6gI8vN1aesBFgo9w=="],

    "@babel/helper-compilation-targets/semver": ["semver@6.3.1", "", { "bin": { "semver": "bin/semver.js" } }, "sha512-BR7VvDCVHO+q2xBEWskxS6DJE1qRnb7DxzUrogb71CWoSficBxYsiAGd+Kl0mmq/MprG9yArRkyrQxTO6XjMzA=="],

    "@tailwindcss/oxide-wasm32-wasi/@emnapi/core": ["@emnapi/core@1.8.1", "", { "dependencies": { "@emnapi/wasi-threads": "1.1.0", "tslib": "^2.4.0" }, "bundled": true }, "sha512-AvT9QFpxK0Zd8J0jopedNm+w/2fIzvtPKPjqyw9jwvBaReTTqPBk9Hixaz7KbjimP+QNz605/XnjFcDAL2pqBg=="],

    "@tanstack/start-plugin-core/@rolldown/pluginutils": ["@rolldown/pluginutils@1.0.0-beta.40", "", {}, "sha512-s3GeJKSQOwBlzdUrj4ISjJj5SfSh+aqn0wjOar4Bx95iV1ETI7F6S/5hLcfAxZ9kXDcyrAkxPlqmd1ZITttf+w=="],

    "html-encoding-sniffer/@exodus/bytes": ["@exodus/bytes@1.10.0", "", { "peerDependencies": { "@noble/hashes": "^1.8.0 || ^2.0.0" }, "optionalPeers": ["@noble/hashes"] }, "sha512-tf8YdcbirXdPnJ+Nd4UN1EXnz+IP2DI45YVEr3vvzcVTOyrApkmIB4zvOQVd3XPr7RXnfBtAx+PXImXOIU0Ajg=="],
  }
}
"#;
        let bun = Sbom::new("bun-lock", data.to_string()).unwrap();
        let list = bun.to_packages().unwrap();
        assert_eq!(
            list,
            [
                Package {
                    name: "@acemir/cssom".to_string(),
                    version: "0.9.31".to_string(),
                    url: Some("https://registry.npmjs.org/@acemir/cssom/-/cssom-0.9.31.tgz".to_string()),
                    checksum: Some("sha512:667477192687fbfbc9d189476aedb51637cb6233296152334c3f0cf2f20442f206c5e397c97773088d78d2bac263ceb6a7f0bf05bcd6b237357609ccf669284c".to_string()),
                    official_registry: true,
                },
                Package {
                    name: "@auth/core".to_string(),
                    version: "0.37.4".to_string(),
                    url: Some("https://registry.npmjs.org/@auth/core/-/core-0.37.4.tgz".to_string()),
                    checksum: Some("sha512:1ce5c9c1759741185b0431e5314d0affa153d6ffb08edcdd2a1b0d83464deff8277ba5cfb08ae367875a31c1676ead19fefb006d80629d0861b9ad1defbbfbab".to_string()),
                    official_registry: true,
                },
                Package {
                    name: "semver".to_string(),
                    version: "6.3.1".to_string(),
                    url: Some("https://registry.npmjs.org/semver/-/semver-6.3.1.tgz".to_string()),
                    checksum: Some("sha512:051ed5bc30951cefaadb10445ac9314ba0c9135a919dbec3c7352ba206fbd425a849f89c07162c88019df8a9749a6abf329ac6f7202b464cab4314cee978cccc".to_string()),
                    official_registry: true,
                },
                Package {
                    name: "lru-cache".to_string(),
                    version: "5.1.1".to_string(),
                    url: Some("https://registry.npmjs.org/lru-cache/-/lru-cache-5.1.1.tgz".to_string()),
                    checksum: Some("sha512:2a9340450037230bfe8d3034bad51555bae1f8996baf516fd1ee7a186cc014e5cdedd93f16f89a0d6f0b1e62b9d8395c1f858fda7ea023cbcdd5a7ac045828f7".to_string()),
                    official_registry: true,
                },
                Package {
                    name: "@emnapi/core".to_string(),
                    version: "1.8.1".to_string(),
                    url: Some("https://registry.npmjs.org/@emnapi/core/-/core-1.8.1.tgz".to_string()),
                    checksum: Some("sha512:02f4fd405a712b465df09d23a2979d366fb0ff67c8cefb4f28f8eacb0f63c2f05a45e4d3a8f064f478b16b3eca6e38a63fe40dcfad39fd79e315c0c02f6a6a06".to_string()),
                    official_registry: true,
                },
                Package {
                    name: "@rolldown/pluginutils".to_string(),
                    version: "1.0.0-beta.40".to_string(),
                    url: Some("https://registry.npmjs.org/@rolldown/pluginutils/-/pluginutils-1.0.0-beta.40.tgz".to_string()),
                    checksum: Some("sha512:b3719e24a4903b0065cdd52b8f82128c98f949f4a1f9aaa7d308ce6abe01c7de6257511323b17a4bfe612dc7c0c59f645c3732ac09313e5aa67756484edb5ffb".to_string()),
                    official_registry: true,
                },
                Package {
                    name: "h3".to_string(),
                    version: "2.0.1-rc.11".to_string(),
                    url: Some("https://registry.npmjs.org/h3/-/h3-2.0.1-rc.11.tgz".to_string()),
                    checksum: Some("sha512:da6cb38c2ab2df673502cf538d95bd7cd657b4ba8d79d8c54ab745cb6023141410dcbceb9c6a037450d87c2d2d5767b8bdcc9f27649fa3f17a35084ed8bcbf33".to_string()),
                    official_registry: true,
                },
                Package {
                    name: "@exodus/bytes".to_string(),
                    version: "1.10.0".to_string(),
                    url: Some("https://registry.npmjs.org/@exodus/bytes/-/bytes-1.10.0.tgz".to_string()),
                    checksum: Some("sha512:b5ff1875c6e2ad774f9c9f8d77850dd445e7cfe20fd83238e58544af7befcdc5533b2ac0a64988078cef39055ddd73ebed15e77c1b40c7e3d72265ce214d008e".to_string()),
                    official_registry: true,
                },
                Package {
                    name: "parse5-htmlparser2-tree-adapter".to_string(),
                    version: "7.1.0".to_string(),
                    url: Some("https://registry.npmjs.org/parse5-htmlparser2-tree-adapter/-/parse5-htmlparser2-tree-adapter-7.1.0.tgz".to_string()),
                    checksum: Some("sha512:aeec39c722acea5ae9a3dc7dac266a6599c8527b480a34007745ac9a9dfde9497d94dfe1fa27e0555d71d606478bc7ae7a3eb04dfa6a5fc8fe045431174352fe".to_string()),
                    official_registry: true,
                },
                Package {
                    name: "zod".to_string(),
                    version: "3.25.76".to_string(),
                    url: Some("https://registry.npmjs.org/zod/-/zod-3.25.76.tgz".to_string()),
                    checksum: Some("sha512:83352dfeab7cd675ec14628815c0b76277c4031e4d92e9c27e70e5bee0524854b4d9b717bb82e679ad001485306cb5b158fc7777da7c4b94286ae8ca70d43171".to_string()),
                    official_registry: true,
                },
            ]
        );
    }
}
