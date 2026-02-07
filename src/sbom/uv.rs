use crate::errors::*;
use crate::sbom;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub const STRAIN: &str = "uv-lock";
pub const VENDOR: &str = "files.pythonhosted.org";

#[derive(Debug, PartialEq)]
pub struct UvLock {
    pub data: String,
}

impl UvLock {
    pub fn parse(&self) -> Result<ParsedLock> {
        let toml = toml::from_str(&self.data)?;
        Ok(toml)
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct ParsedLock {
    #[serde(default, rename = "package")]
    packages: VecDeque<serde_json::Value>,
}

impl Iterator for ParsedLock {
    type Item = Result<sbom::Package>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(pkg) = self.packages.pop_front() {
            let pkg = match serde_json::from_value::<Packagev1_3>(pkg) {
                Ok(pkg) => pkg,
                Err(err) => return Some(Err(err.into())),
            };

            let Some(version) = pkg.version else {
                continue;
            };

            let registry = pkg.source.and_then(|src| src.registry);
            let sdist = pkg.sdist;

            let mut pkg = sbom::Package {
                name: pkg.name,
                version,
                url: None,
                checksum: None,
                official_registry: registry.as_deref() == Some("https://pypi.org/simple"),
            };

            if let Some(sdist) = sdist {
                // Clear `official_registry` if the sdist url doesn't match the official pattern
                if !sdist
                    .url
                    .starts_with("https://files.pythonhosted.org/packages/")
                {
                    pkg.official_registry = false;
                }

                // Set url and checksum
                pkg.url = Some(sdist.url);
                pkg.checksum = Some(sdist.hash);
            }

            return Some(Ok(pkg));
        }

        None
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Packagev1_3 {
    pub name: String,
    pub version: Option<String>,
    pub source: Option<Source>,
    pub sdist: Option<SDist>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Source {
    registry: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SDist {
    url: String,
    hash: String,
}

#[cfg(test)]
mod tests {
    use crate::sbom::{Package, Sbom};

    #[test]
    fn test_parse_uv_lock() {
        let data = r#"version = 1
revision = 3
requires-python = ">=3.12"
resolution-markers = [
    "python_full_version >= '3.14'",
    "python_full_version < '3.14'",
]

[[package]]
name = "attrs"
version = "25.4.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/6b/5c/685e6633917e101e5dcb62b9dd76946cbb57c26e133bae9e0cd36033c0a9/attrs-25.4.0.tar.gz", hash = "sha256:16d5969b87f0859ef33a48b35d55ac1be6e42ae49d5e853b597db70c35c57e11", size = 934251, upload-time = "2025-10-06T13:54:44.725Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/3a/2a/7cc015f5b9f5db42b7d48157e23356022889fc354a2813c15934b7cb5c0e/attrs-25.4.0-py3-none-any.whl", hash = "sha256:adcf7e2a1fb3b36ac48d97835bb6d8ade15b8dcce26aba8bf1d14847b57a3373", size = 67615, upload-time = "2025-10-06T13:54:43.17Z" },
]

[[package]]
name = "bcrypt"
version = "5.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/d4/36/3329e2518d70ad8e2e5817d5a4cac6bba05a47767ec416c7d020a965f408/bcrypt-5.0.0.tar.gz", hash = "sha256:f748f7c2d6fd375cc93d3fba7ef4a9e3a092421b8dbf34d8d4dc06be9492dfdd", size = 25386, upload-time = "2025-09-25T19:50:47.829Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/13/85/3e65e01985fddf25b64ca67275bb5bdb4040bd1a53b66d355c6c37c8a680/bcrypt-5.0.0-cp313-cp313t-macosx_10_12_universal2.whl", hash = "sha256:f3c08197f3039bec79cee59a606d62b96b16669cff3949f21e74796b6e3cd2be", size = 481806, upload-time = "2025-09-25T19:49:05.102Z" },
    { url = "https://files.pythonhosted.org/packages/44/dc/01eb79f12b177017a726cbf78330eb0eb442fae0e7b3dfd84ea2849552f3/bcrypt-5.0.0-cp313-cp313t-manylinux2014_aarch64.manylinux_2_17_aarch64.whl", hash = "sha256:200af71bc25f22006f4069060c88ed36f8aa4ff7f53e67ff04d2ab3f1e79a5b2", size = 268626, upload-time = "2025-09-25T19:49:06.723Z" },
    { url = "https://files.pythonhosted.org/packages/8c/cf/e82388ad5959c40d6afd94fb4743cc077129d45b952d46bdc3180310e2df/bcrypt-5.0.0-cp313-cp313t-manylinux2014_x86_64.manylinux_2_17_x86_64.whl", hash = "sha256:baade0a5657654c2984468efb7d6c110db87ea63ef5a4b54732e7e337253e44f", size = 271853, upload-time = "2025-09-25T19:49:08.028Z" },
    { url = "https://files.pythonhosted.org/packages/ec/86/7134b9dae7cf0efa85671651341f6afa695857fae172615e960fb6a466fa/bcrypt-5.0.0-cp313-cp313t-manylinux_2_28_aarch64.whl", hash = "sha256:c58b56cdfb03202b3bcc9fd8daee8e8e9b6d7e3163aa97c631dfcfcc24d36c86", size = 269793, upload-time = "2025-09-25T19:49:09.727Z" },
    { url = "https://files.pythonhosted.org/packages/cc/82/6296688ac1b9e503d034e7d0614d56e80c5d1a08402ff856a4549cb59207/bcrypt-5.0.0-cp313-cp313t-manylinux_2_28_armv7l.manylinux_2_31_armv7l.whl", hash = "sha256:4bfd2a34de661f34d0bda43c3e4e79df586e4716ef401fe31ea39d69d581ef23", size = 289930, upload-time = "2025-09-25T19:49:11.204Z" },
    { url = "https://files.pythonhosted.org/packages/d1/18/884a44aa47f2a3b88dd09bc05a1e40b57878ecd111d17e5bba6f09f8bb77/bcrypt-5.0.0-cp313-cp313t-manylinux_2_28_x86_64.whl", hash = "sha256:ed2e1365e31fc73f1825fa830f1c8f8917ca1b3ca6185773b349c20fd606cec2", size = 272194, upload-time = "2025-09-25T19:49:12.524Z" },
    { url = "https://files.pythonhosted.org/packages/0e/8f/371a3ab33c6982070b674f1788e05b656cfbf5685894acbfef0c65483a59/bcrypt-5.0.0-cp313-cp313t-manylinux_2_34_aarch64.whl", hash = "sha256:83e787d7a84dbbfba6f250dd7a5efd689e935f03dd83b0f919d39349e1f23f83", size = 269381, upload-time = "2025-09-25T19:49:14.308Z" },
    { url = "https://files.pythonhosted.org/packages/b1/34/7e4e6abb7a8778db6422e88b1f06eb07c47682313997ee8a8f9352e5a6f1/bcrypt-5.0.0-cp313-cp313t-manylinux_2_34_x86_64.whl", hash = "sha256:137c5156524328a24b9fac1cb5db0ba618bc97d11970b39184c1d87dc4bf1746", size = 271750, upload-time = "2025-09-25T19:49:15.584Z" },
    { url = "https://files.pythonhosted.org/packages/c0/1b/54f416be2499bd72123c70d98d36c6cd61a4e33d9b89562c22481c81bb30/bcrypt-5.0.0-cp313-cp313t-musllinux_1_1_aarch64.whl", hash = "sha256:38cac74101777a6a7d3b3e3cfefa57089b5ada650dce2baf0cbdd9d65db22a9e", size = 303757, upload-time = "2025-09-25T19:49:17.244Z" },
    { url = "https://files.pythonhosted.org/packages/13/62/062c24c7bcf9d2826a1a843d0d605c65a755bc98002923d01fd61270705a/bcrypt-5.0.0-cp313-cp313t-musllinux_1_1_x86_64.whl", hash = "sha256:d8d65b564ec849643d9f7ea05c6d9f0cd7ca23bdd4ac0c2dbef1104ab504543d", size = 306740, upload-time = "2025-09-25T19:49:18.693Z" },
    { url = "https://files.pythonhosted.org/packages/d5/c8/1fdbfc8c0f20875b6b4020f3c7dc447b8de60aa0be5faaf009d24242aec9/bcrypt-5.0.0-cp313-cp313t-musllinux_1_2_aarch64.whl", hash = "sha256:741449132f64b3524e95cd30e5cd3343006ce146088f074f31ab26b94e6c75ba", size = 334197, upload-time = "2025-09-25T19:49:20.523Z" },
    { url = "https://files.pythonhosted.org/packages/a6/c1/8b84545382d75bef226fbc6588af0f7b7d095f7cd6a670b42a86243183cd/bcrypt-5.0.0-cp313-cp313t-musllinux_1_2_x86_64.whl", hash = "sha256:212139484ab3207b1f0c00633d3be92fef3c5f0af17cad155679d03ff2ee1e41", size = 352974, upload-time = "2025-09-25T19:49:22.254Z" },
    { url = "https://files.pythonhosted.org/packages/10/a6/ffb49d4254ed085e62e3e5dd05982b4393e32fe1e49bb1130186617c29cd/bcrypt-5.0.0-cp313-cp313t-win32.whl", hash = "sha256:9d52ed507c2488eddd6a95bccee4e808d3234fa78dd370e24bac65a21212b861", size = 148498, upload-time = "2025-09-25T19:49:24.134Z" },
    { url = "https://files.pythonhosted.org/packages/48/a9/259559edc85258b6d5fc5471a62a3299a6aa37a6611a169756bf4689323c/bcrypt-5.0.0-cp313-cp313t-win_amd64.whl", hash = "sha256:f6984a24db30548fd39a44360532898c33528b74aedf81c26cf29c51ee47057e", size = 145853, upload-time = "2025-09-25T19:49:25.702Z" },
    { url = "https://files.pythonhosted.org/packages/2d/df/9714173403c7e8b245acf8e4be8876aac64a209d1b392af457c79e60492e/bcrypt-5.0.0-cp313-cp313t-win_arm64.whl", hash = "sha256:9fffdb387abe6aa775af36ef16f55e318dcda4194ddbf82007a6f21da29de8f5", size = 139626, upload-time = "2025-09-25T19:49:26.928Z" },
    { url = "https://files.pythonhosted.org/packages/f8/14/c18006f91816606a4abe294ccc5d1e6f0e42304df5a33710e9e8e95416e1/bcrypt-5.0.0-cp314-cp314t-macosx_10_12_universal2.whl", hash = "sha256:4870a52610537037adb382444fefd3706d96d663ac44cbb2f37e3919dca3d7ef", size = 481862, upload-time = "2025-09-25T19:49:28.365Z" },
    { url = "https://files.pythonhosted.org/packages/67/49/dd074d831f00e589537e07a0725cf0e220d1f0d5d8e85ad5bbff251c45aa/bcrypt-5.0.0-cp314-cp314t-manylinux2014_aarch64.manylinux_2_17_aarch64.whl", hash = "sha256:48f753100931605686f74e27a7b49238122aa761a9aefe9373265b8b7aa43ea4", size = 268544, upload-time = "2025-09-25T19:49:30.39Z" },
    { url = "https://files.pythonhosted.org/packages/f5/91/50ccba088b8c474545b034a1424d05195d9fcbaaf802ab8bfe2be5a4e0d7/bcrypt-5.0.0-cp314-cp314t-manylinux2014_x86_64.manylinux_2_17_x86_64.whl", hash = "sha256:f70aadb7a809305226daedf75d90379c397b094755a710d7014b8b117df1ebbf", size = 271787, upload-time = "2025-09-25T19:49:32.144Z" },
    { url = "https://files.pythonhosted.org/packages/aa/e7/d7dba133e02abcda3b52087a7eea8c0d4f64d3e593b4fffc10c31b7061f3/bcrypt-5.0.0-cp314-cp314t-manylinux_2_28_aarch64.whl", hash = "sha256:744d3c6b164caa658adcb72cb8cc9ad9b4b75c7db507ab4bc2480474a51989da", size = 269753, upload-time = "2025-09-25T19:49:33.885Z" },
    { url = "https://files.pythonhosted.org/packages/33/fc/5b145673c4b8d01018307b5c2c1fc87a6f5a436f0ad56607aee389de8ee3/bcrypt-5.0.0-cp314-cp314t-manylinux_2_28_armv7l.manylinux_2_31_armv7l.whl", hash = "sha256:a28bc05039bdf3289d757f49d616ab3efe8cf40d8e8001ccdd621cd4f98f4fc9", size = 289587, upload-time = "2025-09-25T19:49:35.144Z" },
    { url = "https://files.pythonhosted.org/packages/27/d7/1ff22703ec6d4f90e62f1a5654b8867ef96bafb8e8102c2288333e1a6ca6/bcrypt-5.0.0-cp314-cp314t-manylinux_2_28_x86_64.whl", hash = "sha256:7f277a4b3390ab4bebe597800a90da0edae882c6196d3038a73adf446c4f969f", size = 272178, upload-time = "2025-09-25T19:49:36.793Z" },
    { url = "https://files.pythonhosted.org/packages/c8/88/815b6d558a1e4d40ece04a2f84865b0fef233513bd85fd0e40c294272d62/bcrypt-5.0.0-cp314-cp314t-manylinux_2_34_aarch64.whl", hash = "sha256:79cfa161eda8d2ddf29acad370356b47f02387153b11d46042e93a0a95127493", size = 269295, upload-time = "2025-09-25T19:49:38.164Z" },
    { url = "https://files.pythonhosted.org/packages/51/8c/e0db387c79ab4931fc89827d37608c31cc57b6edc08ccd2386139028dc0d/bcrypt-5.0.0-cp314-cp314t-manylinux_2_34_x86_64.whl", hash = "sha256:a5393eae5722bcef046a990b84dff02b954904c36a194f6cfc817d7dca6c6f0b", size = 271700, upload-time = "2025-09-25T19:49:39.917Z" },
    { url = "https://files.pythonhosted.org/packages/06/83/1570edddd150f572dbe9fc00f6203a89fc7d4226821f67328a85c330f239/bcrypt-5.0.0-cp314-cp314t-musllinux_1_2_aarch64.whl", hash = "sha256:7f4c94dec1b5ab5d522750cb059bb9409ea8872d4494fd152b53cca99f1ddd8c", size = 334034, upload-time = "2025-09-25T19:49:41.227Z" },
    { url = "https://files.pythonhosted.org/packages/c9/f2/ea64e51a65e56ae7a8a4ec236c2bfbdd4b23008abd50ac33fbb2d1d15424/bcrypt-5.0.0-cp314-cp314t-musllinux_1_2_x86_64.whl", hash = "sha256:0cae4cb350934dfd74c020525eeae0a5f79257e8a201c0c176f4b84fdbf2a4b4", size = 352766, upload-time = "2025-09-25T19:49:43.08Z" },
    { url = "https://files.pythonhosted.org/packages/d7/d4/1a388d21ee66876f27d1a1f41287897d0c0f1712ef97d395d708ba93004c/bcrypt-5.0.0-cp314-cp314t-win32.whl", hash = "sha256:b17366316c654e1ad0306a6858e189fc835eca39f7eb2cafd6aaca8ce0c40a2e", size = 152449, upload-time = "2025-09-25T19:49:44.971Z" },
    { url = "https://files.pythonhosted.org/packages/3f/61/3291c2243ae0229e5bca5d19f4032cecad5dfb05a2557169d3a69dc0ba91/bcrypt-5.0.0-cp314-cp314t-win_amd64.whl", hash = "sha256:92864f54fb48b4c718fc92a32825d0e42265a627f956bc0361fe869f1adc3e7d", size = 149310, upload-time = "2025-09-25T19:49:46.162Z" },
    { url = "https://files.pythonhosted.org/packages/3e/89/4b01c52ae0c1a681d4021e5dd3e45b111a8fb47254a274fa9a378d8d834b/bcrypt-5.0.0-cp314-cp314t-win_arm64.whl", hash = "sha256:dd19cf5184a90c873009244586396a6a884d591a5323f0e8a5922560718d4993", size = 143761, upload-time = "2025-09-25T19:49:47.345Z" },
    { url = "https://files.pythonhosted.org/packages/84/29/6237f151fbfe295fe3e074ecc6d44228faa1e842a81f6d34a02937ee1736/bcrypt-5.0.0-cp38-abi3-macosx_10_12_universal2.whl", hash = "sha256:fc746432b951e92b58317af8e0ca746efe93e66555f1b40888865ef5bf56446b", size = 494553, upload-time = "2025-09-25T19:49:49.006Z" },
    { url = "https://files.pythonhosted.org/packages/45/b6/4c1205dde5e464ea3bd88e8742e19f899c16fa8916fb8510a851fae985b5/bcrypt-5.0.0-cp38-abi3-manylinux2014_aarch64.manylinux_2_17_aarch64.whl", hash = "sha256:c2388ca94ffee269b6038d48747f4ce8df0ffbea43f31abfa18ac72f0218effb", size = 275009, upload-time = "2025-09-25T19:49:50.581Z" },
    { url = "https://files.pythonhosted.org/packages/3b/71/427945e6ead72ccffe77894b2655b695ccf14ae1866cd977e185d606dd2f/bcrypt-5.0.0-cp38-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl", hash = "sha256:560ddb6ec730386e7b3b26b8b4c88197aaed924430e7b74666a586ac997249ef", size = 278029, upload-time = "2025-09-25T19:49:52.533Z" },
    { url = "https://files.pythonhosted.org/packages/17/72/c344825e3b83c5389a369c8a8e58ffe1480b8a699f46c127c34580c4666b/bcrypt-5.0.0-cp38-abi3-manylinux_2_28_aarch64.whl", hash = "sha256:d79e5c65dcc9af213594d6f7f1fa2c98ad3fc10431e7aa53c176b441943efbdd", size = 275907, upload-time = "2025-09-25T19:49:54.709Z" },
    { url = "https://files.pythonhosted.org/packages/0b/7e/d4e47d2df1641a36d1212e5c0514f5291e1a956a7749f1e595c07a972038/bcrypt-5.0.0-cp38-abi3-manylinux_2_28_armv7l.manylinux_2_31_armv7l.whl", hash = "sha256:2b732e7d388fa22d48920baa267ba5d97cca38070b69c0e2d37087b381c681fd", size = 296500, upload-time = "2025-09-25T19:49:56.013Z" },
    { url = "https://files.pythonhosted.org/packages/0f/c3/0ae57a68be2039287ec28bc463b82e4b8dc23f9d12c0be331f4782e19108/bcrypt-5.0.0-cp38-abi3-manylinux_2_28_x86_64.whl", hash = "sha256:0c8e093ea2532601a6f686edbc2c6b2ec24131ff5c52f7610dd64fa4553b5464", size = 278412, upload-time = "2025-09-25T19:49:57.356Z" },
    { url = "https://files.pythonhosted.org/packages/45/2b/77424511adb11e6a99e3a00dcc7745034bee89036ad7d7e255a7e47be7d8/bcrypt-5.0.0-cp38-abi3-manylinux_2_34_aarch64.whl", hash = "sha256:5b1589f4839a0899c146e8892efe320c0fa096568abd9b95593efac50a87cb75", size = 275486, upload-time = "2025-09-25T19:49:59.116Z" },
    { url = "https://files.pythonhosted.org/packages/43/0a/405c753f6158e0f3f14b00b462d8bca31296f7ecfc8fc8bc7919c0c7d73a/bcrypt-5.0.0-cp38-abi3-manylinux_2_34_x86_64.whl", hash = "sha256:89042e61b5e808b67daf24a434d89bab164d4de1746b37a8d173b6b14f3db9ff", size = 277940, upload-time = "2025-09-25T19:50:00.869Z" },
    { url = "https://files.pythonhosted.org/packages/62/83/b3efc285d4aadc1fa83db385ec64dcfa1707e890eb42f03b127d66ac1b7b/bcrypt-5.0.0-cp38-abi3-musllinux_1_1_aarch64.whl", hash = "sha256:e3cf5b2560c7b5a142286f69bde914494b6d8f901aaa71e453078388a50881c4", size = 310776, upload-time = "2025-09-25T19:50:02.393Z" },
    { url = "https://files.pythonhosted.org/packages/95/7d/47ee337dacecde6d234890fe929936cb03ebc4c3a7460854bbd9c97780b8/bcrypt-5.0.0-cp38-abi3-musllinux_1_1_x86_64.whl", hash = "sha256:f632fd56fc4e61564f78b46a2269153122db34988e78b6be8b32d28507b7eaeb", size = 312922, upload-time = "2025-09-25T19:50:04.232Z" },
    { url = "https://files.pythonhosted.org/packages/d6/3a/43d494dfb728f55f4e1cf8fd435d50c16a2d75493225b54c8d06122523c6/bcrypt-5.0.0-cp38-abi3-musllinux_1_2_aarch64.whl", hash = "sha256:801cad5ccb6b87d1b430f183269b94c24f248dddbbc5c1f78b6ed231743e001c", size = 341367, upload-time = "2025-09-25T19:50:05.559Z" },
    { url = "https://files.pythonhosted.org/packages/55/ab/a0727a4547e383e2e22a630e0f908113db37904f58719dc48d4622139b5c/bcrypt-5.0.0-cp38-abi3-musllinux_1_2_x86_64.whl", hash = "sha256:3cf67a804fc66fc217e6914a5635000259fbbbb12e78a99488e4d5ba445a71eb", size = 359187, upload-time = "2025-09-25T19:50:06.916Z" },
    { url = "https://files.pythonhosted.org/packages/1b/bb/461f352fdca663524b4643d8b09e8435b4990f17fbf4fea6bc2a90aa0cc7/bcrypt-5.0.0-cp38-abi3-win32.whl", hash = "sha256:3abeb543874b2c0524ff40c57a4e14e5d3a66ff33fb423529c88f180fd756538", size = 153752, upload-time = "2025-09-25T19:50:08.515Z" },
    { url = "https://files.pythonhosted.org/packages/41/aa/4190e60921927b7056820291f56fc57d00d04757c8b316b2d3c0d1d6da2c/bcrypt-5.0.0-cp38-abi3-win_amd64.whl", hash = "sha256:35a77ec55b541e5e583eb3436ffbbf53b0ffa1fa16ca6782279daf95d146dcd9", size = 150881, upload-time = "2025-09-25T19:50:09.742Z" },
    { url = "https://files.pythonhosted.org/packages/54/12/cd77221719d0b39ac0b55dbd39358db1cd1246e0282e104366ebbfb8266a/bcrypt-5.0.0-cp38-abi3-win_arm64.whl", hash = "sha256:cde08734f12c6a4e28dc6755cd11d3bdfea608d93d958fffbe95a7026ebe4980", size = 144931, upload-time = "2025-09-25T19:50:11.016Z" },
    { url = "https://files.pythonhosted.org/packages/5d/ba/2af136406e1c3839aea9ecadc2f6be2bcd1eff255bd451dd39bcf302c47a/bcrypt-5.0.0-cp39-abi3-macosx_10_12_universal2.whl", hash = "sha256:0c418ca99fd47e9c59a301744d63328f17798b5947b0f791e9af3c1c499c2d0a", size = 495313, upload-time = "2025-09-25T19:50:12.309Z" },
    { url = "https://files.pythonhosted.org/packages/ac/ee/2f4985dbad090ace5ad1f7dd8ff94477fe089b5fab2040bd784a3d5f187b/bcrypt-5.0.0-cp39-abi3-manylinux2014_aarch64.manylinux_2_17_aarch64.whl", hash = "sha256:ddb4e1500f6efdd402218ffe34d040a1196c072e07929b9820f363a1fd1f4191", size = 275290, upload-time = "2025-09-25T19:50:13.673Z" },
    { url = "https://files.pythonhosted.org/packages/e4/6e/b77ade812672d15cf50842e167eead80ac3514f3beacac8902915417f8b7/bcrypt-5.0.0-cp39-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl", hash = "sha256:7aeef54b60ceddb6f30ee3db090351ecf0d40ec6e2abf41430997407a46d2254", size = 278253, upload-time = "2025-09-25T19:50:15.089Z" },
    { url = "https://files.pythonhosted.org/packages/36/c4/ed00ed32f1040f7990dac7115f82273e3c03da1e1a1587a778d8cea496d8/bcrypt-5.0.0-cp39-abi3-manylinux_2_28_aarch64.whl", hash = "sha256:f0ce778135f60799d89c9693b9b398819d15f1921ba15fe719acb3178215a7db", size = 276084, upload-time = "2025-09-25T19:50:16.699Z" },
    { url = "https://files.pythonhosted.org/packages/e7/c4/fa6e16145e145e87f1fa351bbd54b429354fd72145cd3d4e0c5157cf4c70/bcrypt-5.0.0-cp39-abi3-manylinux_2_28_armv7l.manylinux_2_31_armv7l.whl", hash = "sha256:a71f70ee269671460b37a449f5ff26982a6f2ba493b3eabdd687b4bf35f875ac", size = 297185, upload-time = "2025-09-25T19:50:18.525Z" },
    { url = "https://files.pythonhosted.org/packages/24/b4/11f8a31d8b67cca3371e046db49baa7c0594d71eb40ac8121e2fc0888db0/bcrypt-5.0.0-cp39-abi3-manylinux_2_28_x86_64.whl", hash = "sha256:f8429e1c410b4073944f03bd778a9e066e7fad723564a52ff91841d278dfc822", size = 278656, upload-time = "2025-09-25T19:50:19.809Z" },
    { url = "https://files.pythonhosted.org/packages/ac/31/79f11865f8078e192847d2cb526e3fa27c200933c982c5b2869720fa5fce/bcrypt-5.0.0-cp39-abi3-manylinux_2_34_aarch64.whl", hash = "sha256:edfcdcedd0d0f05850c52ba3127b1fce70b9f89e0fe5ff16517df7e81fa3cbb8", size = 275662, upload-time = "2025-09-25T19:50:21.567Z" },
    { url = "https://files.pythonhosted.org/packages/d4/8d/5e43d9584b3b3591a6f9b68f755a4da879a59712981ef5ad2a0ac1379f7a/bcrypt-5.0.0-cp39-abi3-manylinux_2_34_x86_64.whl", hash = "sha256:611f0a17aa4a25a69362dcc299fda5c8a3d4f160e2abb3831041feb77393a14a", size = 278240, upload-time = "2025-09-25T19:50:23.305Z" },
    { url = "https://files.pythonhosted.org/packages/89/48/44590e3fc158620f680a978aafe8f87a4c4320da81ed11552f0323aa9a57/bcrypt-5.0.0-cp39-abi3-musllinux_1_1_aarch64.whl", hash = "sha256:db99dca3b1fdc3db87d7c57eac0c82281242d1eabf19dcb8a6b10eb29a2e72d1", size = 311152, upload-time = "2025-09-25T19:50:24.597Z" },
    { url = "https://files.pythonhosted.org/packages/5f/85/e4fbfc46f14f47b0d20493669a625da5827d07e8a88ee460af6cd9768b44/bcrypt-5.0.0-cp39-abi3-musllinux_1_1_x86_64.whl", hash = "sha256:5feebf85a9cefda32966d8171f5db7e3ba964b77fdfe31919622256f80f9cf42", size = 313284, upload-time = "2025-09-25T19:50:26.268Z" },
    { url = "https://files.pythonhosted.org/packages/25/ae/479f81d3f4594456a01ea2f05b132a519eff9ab5768a70430fa1132384b1/bcrypt-5.0.0-cp39-abi3-musllinux_1_2_aarch64.whl", hash = "sha256:3ca8a166b1140436e058298a34d88032ab62f15aae1c598580333dc21d27ef10", size = 341643, upload-time = "2025-09-25T19:50:28.02Z" },
    { url = "https://files.pythonhosted.org/packages/df/d2/36a086dee1473b14276cd6ea7f61aef3b2648710b5d7f1c9e032c29b859f/bcrypt-5.0.0-cp39-abi3-musllinux_1_2_x86_64.whl", hash = "sha256:61afc381250c3182d9078551e3ac3a41da14154fbff647ddf52a769f588c4172", size = 359698, upload-time = "2025-09-25T19:50:31.347Z" },
    { url = "https://files.pythonhosted.org/packages/c0/f6/688d2cd64bfd0b14d805ddb8a565e11ca1fb0fd6817175d58b10052b6d88/bcrypt-5.0.0-cp39-abi3-win32.whl", hash = "sha256:64d7ce196203e468c457c37ec22390f1a61c85c6f0b8160fd752940ccfb3a683", size = 153725, upload-time = "2025-09-25T19:50:34.384Z" },
    { url = "https://files.pythonhosted.org/packages/9f/b9/9d9a641194a730bda138b3dfe53f584d61c58cd5230e37566e83ec2ffa0d/bcrypt-5.0.0-cp39-abi3-win_amd64.whl", hash = "sha256:64ee8434b0da054d830fa8e89e1c8bf30061d539044a39524ff7dec90481e5c2", size = 150912, upload-time = "2025-09-25T19:50:35.69Z" },
    { url = "https://files.pythonhosted.org/packages/27/44/d2ef5e87509158ad2187f4dd0852df80695bb1ee0cfe0a684727b01a69e0/bcrypt-5.0.0-cp39-abi3-win_arm64.whl", hash = "sha256:f2347d3534e76bf50bca5500989d6c1d05ed64b440408057a37673282c654927", size = 144953, upload-time = "2025-09-25T19:50:37.32Z" },
]

[[package]]
name = "build"
version = "1.3.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "colorama", marker = "os_name == 'nt'" },
    { name = "packaging" },
    { name = "pyproject-hooks" },
]
sdist = { url = "https://files.pythonhosted.org/packages/25/1c/23e33405a7c9eac261dff640926b8b5adaed6a6eb3e1767d441ed611d0c0/build-1.3.0.tar.gz", hash = "sha256:698edd0ea270bde950f53aed21f3a0135672206f3911e0176261a31e0e07b397", size = 48544, upload-time = "2025-08-01T21:27:09.268Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/cb/8c/2b30c12155ad8de0cf641d76a8b396a16d2c36bc6d50b621a62b7c4567c1/build-1.3.0-py3-none-any.whl", hash = "sha256:7145f0b5061ba90a1500d60bd1b13ca0a8a4cebdd0cc16ed8adf1c0e739f43b4", size = 23382, upload-time = "2025-08-01T21:27:07.844Z" },
]

[[package]]
name = "mitmproxy"
source = { editable = "." }
dependencies = [
    { name = "aioquic" },
    { name = "argon2-cffi" },
    { name = "asgiref" },
    { name = "bcrypt" },
    { name = "brotli" },
    { name = "certifi" },
    { name = "cryptography" },
    { name = "flask" },
    { name = "h11" },
    { name = "h2" },
    { name = "hyperframe" },
    { name = "kaitaistruct" },
    { name = "ldap3" },
    { name = "mitmproxy-rs" },
    { name = "msgpack" },
    { name = "publicsuffix2" },
    { name = "pydivert", marker = "sys_platform == 'win32'" },
    { name = "pyopenssl" },
    { name = "pyparsing" },
    { name = "pyperclip" },
    { name = "ruamel-yaml" },
    { name = "sortedcontainers" },
    { name = "tornado" },
    { name = "typing-extensions", marker = "python_full_version < '3.13'" },
    { name = "urwid" },
    { name = "wsproto" },
    { name = "zstandard" },
]

[package.dev-dependencies]
deploy = [
    { name = "awscli" },
    { name = "twine" },
]
dev = [
    { name = "build" },
    { name = "click" },
    { name = "hypothesis" },
    { name = "maturin" },
    { name = "mypy" },
    { name = "pdoc" },
    { name = "pyinstaller" },
    { name = "pyinstaller-hooks-contrib" },
    { name = "pytest" },
    { name = "pytest-asyncio" },
    { name = "pytest-cov" },
    { name = "pytest-timeout" },
    { name = "pytest-xdist" },
    { name = "requests" },
    { name = "ruff" },
    { name = "tox" },
    { name = "tox-uv" },
    { name = "types-requests" },
    { name = "wheel" },
]
ruff = [
    { name = "ruff" },
]
tox = [
    { name = "tox" },
    { name = "tox-uv" },
]

[package.metadata]
requires-dist = [
    { name = "aioquic", specifier = "<=1.2.0,>=1.2.0" },
    { name = "argon2-cffi", specifier = ">=23.1.0,<=25.1.0" },
    { name = "asgiref", specifier = ">=3.2.10,<=3.10.0" },
    { name = "bcrypt", specifier = "<=5.0.0,>=5.0.0" },
    { name = "brotli", specifier = ">=1.0,<=1.2.0" },
    { name = "certifi", specifier = ">=2019.9.11" },
    { name = "cryptography", specifier = ">=42.0,<=46.1" },
    { name = "flask", specifier = ">=3.0,<=3.1.2" },
    { name = "h11", specifier = "<=0.16.0,>=0.16.0" },
    { name = "h2", specifier = "<=4.3.0,>=4.3.0" },
    { name = "hyperframe", specifier = ">=6.0,<=6.1.0" },
    { name = "kaitaistruct", specifier = ">=0.10,<=0.11" },
    { name = "ldap3", specifier = ">=2.8,<=2.9.1" },
    { name = "mitmproxy-rs", specifier = ">=0.12.6,<0.13" },
    { name = "msgpack", specifier = ">=1.0.0,<=1.1.2" },
    { name = "publicsuffix2", specifier = ">=2.20190812,<=2.20191221" },
    { name = "pydivert", marker = "sys_platform == 'win32'", specifier = ">=2.0.3,<=2.1.0" },
    { name = "pyopenssl", specifier = ">=24.3,<=25.3.0" },
    { name = "pyparsing", specifier = ">=2.4.2,<=3.2.5" },
    { name = "pyperclip", specifier = ">=1.9.0,<=1.11.0" },
    { name = "ruamel-yaml", specifier = ">=0.18.10,<=0.18.16" },
    { name = "sortedcontainers", specifier = ">=2.3,<=2.4.0" },
    { name = "tornado", specifier = ">=6.5.0,<=6.5.2" },
    { name = "typing-extensions", marker = "python_full_version < '3.13'", specifier = ">=4.13.2,<=4.14" },
    { name = "urwid", specifier = ">=2.6.14,<=3.0.3" },
    { name = "wsproto", specifier = ">=1.0,<=1.2.0" },
    { name = "zstandard", specifier = "<=0.25.0,>=0.25" },
]

[package.metadata.requires-dev]
deploy = [
    { name = "awscli", specifier = "==1.42.64" },
    { name = "twine", specifier = "==6.2.0" },
]
dev = [
    { name = "build", specifier = "==1.3.0" },
    { name = "click", specifier = "==8.3.0" },
    { name = "hypothesis", specifier = "==6.130.6" },
    { name = "maturin", specifier = "==1.9.6" },
    { name = "mypy", specifier = "==1.18.2" },
    { name = "pdoc", specifier = "==16.0.0" },
    { name = "pyinstaller", specifier = "==6.16.0" },
    { name = "pyinstaller-hooks-contrib", specifier = "==2025.9" },
    { name = "pytest", specifier = "==8.4.2" },
    { name = "pytest-asyncio", specifier = "==1.2.0" },
    { name = "pytest-cov", specifier = "==7.0.0" },
    { name = "pytest-timeout", specifier = "==2.4.0" },
    { name = "pytest-xdist", specifier = "==3.8.0" },
    { name = "requests", specifier = "==2.32.5" },
    { name = "ruff", specifier = "==0.14.3" },
    { name = "tox", specifier = "==4.32.0" },
    { name = "tox-uv", specifier = "==1.29.0" },
    { name = "types-requests", specifier = "==2.32.4.20250913" },
    { name = "wheel", specifier = "==0.45.1" },
]
ruff = [{ name = "ruff", specifier = "==0.14.3" }]
tox = [
    { name = "tox", specifier = "==4.32.0" },
    { name = "tox-uv", specifier = "==1.29.0" },
]

[[package]]
name = "mitmproxy-linux"
version = "0.12.8"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/0a/57/09eeeb490708b67c0cb4145d3b115f0144fa1e400f4fcc3874fd22398765/mitmproxy_linux-0.12.8.tar.gz", hash = "sha256:0bea9353c71ebfd2174f6730b3fd0fdff3adea1aa15450035bed3b83e36ef455", size = 1287560, upload-time = "2025-11-24T17:48:17.871Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/af/02/836c31072cc7fa2b2d25a072f935a72faee7a64207a11940f9b22dee8ffb/mitmproxy_linux-0.12.8-py3-none-manylinux_2_17_aarch64.manylinux2014_aarch64.whl", hash = "sha256:2238455e65970382825baed2e998601ea82d8dcaae51bd8ee0859d596524a822", size = 952974, upload-time = "2025-11-24T17:48:05.672Z" },
    { url = "https://files.pythonhosted.org/packages/76/a8/0fa9fe5fe10e7410a21959c5438e596a92677b49d331a3dcb2dde14af446/mitmproxy_linux-0.12.8-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", hash = "sha256:fbcb25316e95d0b2b5ced4e0cc3d90fdb1b7169300a005cc79339894d665363a", size = 1039276, upload-time = "2025-11-24T17:48:07.171Z" },
]

[[package]]
name = "mitmproxy-macos"
version = "0.12.8"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/79/c1/195f8de930dbdce0e2c0ec3097447d0e879d576e3671c8f5592b84f29d50/mitmproxy_macos-0.12.8-py3-none-any.whl", hash = "sha256:6da01f118e2110ddf038489c804e77818ef5217d34dc9605cb265a349ed4f140", size = 2569703, upload-time = "2025-11-24T17:48:08.402Z" },
]

[[package]]
name = "mitmproxy-rs"
version = "0.12.8"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "mitmproxy-linux", marker = "sys_platform == 'linux'" },
    { name = "mitmproxy-macos", marker = "sys_platform == 'darwin'" },
    { name = "mitmproxy-windows", marker = "os_name == 'nt'" },
]
sdist = { url = "https://files.pythonhosted.org/packages/09/a5/1b380d9156553dee489a7c616971e47653066d4c5551ce4226862f32abca/mitmproxy_rs-0.12.8.tar.gz", hash = "sha256:16afd0fc1a00d586ffe2027d217908c3e0389d7d0897eccda6e59fda991e89ba", size = 1320939, upload-time = "2025-11-24T17:48:19.079Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/5b/02/218e277de1e1dd978ac325129a18d047c21129c87990c1768be1bbe96b65/mitmproxy_rs-0.12.8-cp312-abi3-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl", hash = "sha256:c5b0799808a4de0ee60e8f350043820ad56eea738ce3ce25d5c6faaa245b6c9a", size = 7060242, upload-time = "2025-11-24T17:48:10.2Z" },
    { url = "https://files.pythonhosted.org/packages/0a/03/6082ad61435c4a102ccd48e63fa3a7bf6df50dffd40f33f9225848f8d6e0/mitmproxy_rs-0.12.8-cp312-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl", hash = "sha256:739591f696cf29913302a72fa9644cf97228774604304a2ea3987fe5588d231c", size = 3015729, upload-time = "2025-11-24T17:48:11.763Z" },
    { url = "https://files.pythonhosted.org/packages/d1/87/ea3b0050724b700d6fbb26c05be9a6e4b2c9c928218d48dacabe2ed56f03/mitmproxy_rs-0.12.8-cp312-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", hash = "sha256:14ea236d0950ab35d667b78b5fe15d43e7345e166e22144624a1283edc78443e", size = 3215202, upload-time = "2025-11-24T17:48:13.434Z" },
    { url = "https://files.pythonhosted.org/packages/d3/cc/15a96208f07dfc693490361db40d61997074f0a74a0f717f7f60b77f6639/mitmproxy_rs-0.12.8-cp312-abi3-win_amd64.whl", hash = "sha256:b0ead519f5a4ab019e7912544c0642f28f8336036ef1480e42a772a8cc947550", size = 3232490, upload-time = "2025-11-24T17:48:15.243Z" },
]

[[package]]
name = "mitmproxy-windows"
version = "0.12.8"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/b0/61/a37124ccc16454c979e1ec9be5fd4aa81c82c29d81a92e97b023fa279b85/mitmproxy_windows-0.12.8-py3-none-any.whl", hash = "sha256:2dd727e2caed642ecfbbad1ca4d07d28fca0c5ab1b0be9dc62ccecbdb2257dce", size = 476563, upload-time = "2025-11-24T17:48:16.377Z" },
]
"#;
        let uv = Sbom::new("uv-lock", data.to_string()).unwrap();
        let list = uv.to_packages().unwrap();
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
                Package {
                    name: "bcrypt".to_string(),
                    version: "5.0.0".to_string(),
                    url: Some(
                        "https://files.pythonhosted.org/packages/d4/36/3329e2518d70ad8e2e5817d5a4cac6bba05a47767ec416c7d020a965f408/bcrypt-5.0.0.tar.gz".to_string()
                    ),
                    checksum: Some(
                        "sha256:f748f7c2d6fd375cc93d3fba7ef4a9e3a092421b8dbf34d8d4dc06be9492dfdd".to_string()
                    ),
                    official_registry: true,
                },
                Package {
                    name: "build".to_string(),
                    version: "1.3.0".to_string(),
                    url: Some(
                        "https://files.pythonhosted.org/packages/25/1c/23e33405a7c9eac261dff640926b8b5adaed6a6eb3e1767d441ed611d0c0/build-1.3.0.tar.gz".to_string()
                    ),
                    checksum: Some(
                        "sha256:698edd0ea270bde950f53aed21f3a0135672206f3911e0176261a31e0e07b397".to_string()
                    ),
                    official_registry: true,
                },
                Package {
                    name: "mitmproxy-linux".to_string(),
                    version: "0.12.8".to_string(),
                    url: Some(
                        "https://files.pythonhosted.org/packages/0a/57/09eeeb490708b67c0cb4145d3b115f0144fa1e400f4fcc3874fd22398765/mitmproxy_linux-0.12.8.tar.gz".to_string()
                    ),
                    checksum: Some(
                        "sha256:0bea9353c71ebfd2174f6730b3fd0fdff3adea1aa15450035bed3b83e36ef455".to_string()
                    ),
                    official_registry: true,
                },
                Package {
                    name: "mitmproxy-macos".to_string(),
                    version: "0.12.8".to_string(),
                    url: None,
                    checksum: None,
                    official_registry: true,
                },
                Package {
                    name: "mitmproxy-rs".to_string(),
                    version: "0.12.8".to_string(),
                    url: Some(
                        "https://files.pythonhosted.org/packages/09/a5/1b380d9156553dee489a7c616971e47653066d4c5551ce4226862f32abca/mitmproxy_rs-0.12.8.tar.gz".to_string()
                    ),
                    checksum: Some(
                        "sha256:16afd0fc1a00d586ffe2027d217908c3e0389d7d0897eccda6e59fda991e89ba".to_string()
                    ),
                    official_registry: true,
                },
                Package {
                    name: "mitmproxy-windows".to_string(),
                    version: "0.12.8".to_string(),
                    url: None,
                    checksum: None,
                    official_registry: true,
                },
            ]
        );
    }
}
