use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;
use crate::sbom;
use data_encoding::BASE64;
use diffy_fork_filenames as diffy;
use log::error;
use num_format::{Locale, ToFormattedString};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fmt;
use std::result;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::task::JoinSet;
use url_escape::percent_encoding::AsciiSet;
use warp::http::Uri;
use warp::reject;
use warp::{
    http::{header, HeaderValue, StatusCode},
    Filter,
};

const SEARCH_LIMIT: usize = 150;

#[allow(clippy::declare_interior_mutable_const)]
const CACHE_CONTROL_DEFAULT: HeaderValue =
    HeaderValue::from_static("max-age=600, stale-while-revalidate=300, stale-if-error=300");
#[allow(clippy::declare_interior_mutable_const)]
const CACHE_CONTROL_SHORT: HeaderValue =
    HeaderValue::from_static("max-age=10, stale-while-revalidate=20, stale-if-error=60");

fn download_srcs_hashset() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        let mut s = HashSet::new();
        s.insert(sbom::cargo::VENDOR);
        s.insert(sbom::yarn::VENDOR);
        s
    })
}

#[derive(RustEmbed)]
#[folder = "templates"]
#[include = "*.hbs"]
#[include = "*.css"]
struct Assets;

struct Handlebars<'a> {
    hbs: handlebars::Handlebars<'a>,
}

fn asset_name_css() -> String {
    let mut hasher = Sha256::new();
    if let Some(css) = Assets::get("style.css") {
        hasher.update(css.data);
    }
    let mut id = hex::encode(hasher.finalize());
    id.truncate(7);
    format!("style-{id}.css")
}

handlebars::handlebars_helper!(format_num: |v: i64, width: i64| {
    let v = v.to_formatted_string(&Locale::en);
    format!("{:>width$}", v, width=width as usize)
});

handlebars::handlebars_helper!(pad_right: |v: String, width: i64| {
    format!("{:<width$}", v, width=width as usize)
});

handlebars::handlebars_helper!(diff_toggle: |diff: Diff, key: String| {
    let mut diff = diff;
    match key.as_str() {
        "sorted" => diff.sorted ^= true,
        "trimmed" => {
            let trimmed = diff.trim_left || diff.trim_right;
            diff.trim_left = !trimmed;
            diff.trim_right = !trimmed;
        },
        "trim_left" => diff.trim_left ^= true,
        "trim_right" => diff.trim_right ^= true,
        _ => (),
    }
    diff.to_string()
});

handlebars::handlebars_helper!(diff_style: |line: String| {
    match line.chars().next() {
        Some('+') => "diff-add",
        Some('-') => "diff-rm",
        Some('@') => "diff-hunk",
        _ => "",
    }
});

impl<'a> Handlebars<'a> {
    fn new() -> Result<Handlebars<'a>> {
        let mut hbs = handlebars::Handlebars::new();
        hbs.set_prevent_indent(true);
        hbs.register_embed_templates::<Assets>()?;
        hbs.register_partial("asset_name_css", asset_name_css())?;
        hbs.register_helper("format_num", Box::new(format_num));
        hbs.register_helper("pad_right", Box::new(pad_right));
        hbs.register_helper("diff_toggle", Box::new(diff_toggle));
        hbs.register_helper("diff_style", Box::new(diff_style));
        Ok(Handlebars { hbs })
    }

    fn render<T>(&self, name: &str, data: &T) -> Result<String>
    where
        T: serde::Serialize,
    {
        let out = self.hbs.render(name, data)?;
        Ok(out)
    }

    fn render_archive(&self, files: Option<&[ingest::tar::Entry]>) -> Result<String> {
        let artifact = self.hbs.render(
            "archive.txt.hbs",
            &json!({
                "files": files,
            }),
        )?;
        Ok(artifact)
    }
}

fn cache_control(reply: impl warp::Reply, value: HeaderValue) -> impl warp::Reply {
    warp::reply::with_header(reply, header::CACHE_CONTROL, value)
}

async fn index(hbs: Arc<Handlebars<'_>>) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let html = hbs.render("index.html.hbs", &()).map_err(Error::from)?;
    Ok(Box::new(warp::reply::html(html)))
}

fn detect_autotools(files: Option<&[ingest::tar::Entry]>) -> bool {
    let Some(files) = files else {
        return false;
    };

    let mut configure = HashSet::new();
    let mut configure_ac = HashSet::new();

    for file in files {
        if let Some(folder) = file.path.strip_suffix("/configure") {
            if configure_ac.contains(folder) {
                return true;
            }
            configure.insert(folder);
        }
        if let Some(folder) = file.path.strip_suffix("/configure.ac") {
            if configure.contains(folder) {
                return true;
            }
            configure_ac.insert(folder);
        }
    }

    false
}

async fn artifact(
    hbs: Arc<Handlebars<'_>>,
    db: Arc<db::Client>,
    chksum: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let (chksum, json) = chksum
        .strip_suffix(".json")
        .map(|chksum| (chksum, true))
        .unwrap_or((chksum.as_str(), false));

    let alias = db.get_artifact_alias(chksum).await?;

    let resolved_chksum = alias
        .as_ref()
        .map(|a| a.alias_to.as_str())
        .unwrap_or(chksum);
    let Some(artifact) = db.get_artifact(resolved_chksum).await? else {
        return Err(reject::not_found());
    };

    let files = artifact.get_files()?;
    let sbom_refs = db.get_sbom_refs_for_archive(resolved_chksum).await?;

    if json {
        Ok(Box::new(warp::reply::json(&json!({
            "files": files,
            "sbom_refs": sbom_refs,
        }))))
    } else {
        let suspecting_autotools = detect_autotools(files.as_deref());

        let refs = db.get_all_refs_for(&artifact.chksum).await?;
        let files = hbs.render_archive(files.as_deref())?;

        let mut build_inputs = Vec::new();
        let mut found_at = Vec::new();

        let set = download_srcs_hashset();
        for r in refs {
            if set.contains(r.vendor.as_str()) {
                found_at.push(r);
            } else {
                build_inputs.push(r);
            }
        }

        let html = hbs
            .render(
                "artifact.html.hbs",
                &json!({
                    "artifact": artifact,
                    "chksum": chksum,
                    "alias": alias,
                    "refs": json!([{
                        "title": "Build input of",
                        "refs": build_inputs,
                    }, {
                        "title": "Found at",
                        "refs": found_at,
                    }]),
                    "sbom_refs": sbom_refs,
                    "files": files,
                    "suspecting_autotools": suspecting_autotools,
                }),
            )
            .map_err(Error::from)?;
        Ok(Box::new(warp::reply::html(html)))
    }
}

async fn sbom(
    hbs: Arc<Handlebars<'_>>,
    db: Arc<db::Client>,
    chksum: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let (chksum, txt) = chksum
        .strip_suffix(".txt")
        .map(|chksum| (chksum, true))
        .unwrap_or((chksum.as_str(), false));

    let Some(sbom) = db.get_sbom(chksum).await? else {
        return Err(reject::not_found());
    };

    let sbom_refs = db.get_sbom_refs_for_sbom(&sbom).await?;

    if txt {
        let mut res = warp::reply::Response::new(sbom.data.into());
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        Ok(Box::new(res))
    } else {
        let packages = match sbom::Sbom::try_from(&sbom).and_then(|sbom| sbom.to_packages()) {
            Ok(packages) => packages,
            Err(err) => {
                warn!("Failed to parse package lock: {err:#}");
                Vec::new()
            }
        };

        let html = hbs
            .render(
                "sbom.html.hbs",
                &json!({
                    "sbom": sbom,
                    "chksum": chksum,
                    "sbom_refs": sbom_refs,
                    "packages": packages,
                }),
            )
            .map_err(Error::from)?;
        Ok(Box::new(warp::reply::html(html)))
    }
}

fn detect_hash_search(txt: &str) -> Option<Cow<'_, str>> {
    if let Some(value) = txt.strip_prefix("sha256") {
        if let Some(value) = value.strip_prefix(':') {
            // search is in format sha256:<hex>
            (value.len() == 64).then_some(Cow::Borrowed(txt))
        } else if let Some(value) = value.strip_prefix('-') {
            // search is in format sha256-<base64> (NixOS)
            if let Ok(digest) = BASE64.decode(value.as_bytes()) {
                let digest = hex::encode(digest);
                Some(Cow::Owned(format!("sha256:{digest}")))
            } else {
                None
            }
        } else {
            None
        }
    } else if let Some(value) = txt.strip_prefix("sha512:") {
        // search is in format sha512:<hex>
        (value.len() == 128).then_some(Cow::Borrowed(txt))
    } else if let Some(value) = txt.strip_prefix("blake2b:") {
        // search is in format blake2b:<hex>
        (value.len() == 128).then_some(Cow::Borrowed(txt))
    } else if let Some(_value) = txt.strip_prefix("git:") {
        Some(Cow::Borrowed(txt))
    } else if let Ok(url) = txt.parse::<Uri>() {
        let path = url.path();
        path.strip_prefix("/artifact/")
            .filter(|x| !x.contains('/'))
            .map(|x| Cow::Owned(x.into()))
    } else {
        None
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SearchQuery {
    q: String,
}

async fn search(
    hbs: Arc<Handlebars<'_>>,
    db: Arc<db::Client>,
    search: SearchQuery,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let trimmed = search.q.trim();
    if trimmed.len() != search.q.len() {
        let query = serde_urlencoded::to_string(SearchQuery {
            q: trimmed.to_string(),
        })
        .map_err(Error::from)?;
        let uri = format!("/search?{query}")
            .parse::<Uri>()
            .map_err(Error::from)?;
        return Ok(Box::new(warp::redirect::found(uri)));
    }

    if let Some(artifact) = detect_hash_search(trimmed) {
        let uri = format!("/artifact/{}", url_encode_artifact(&artifact))
            .parse::<Uri>()
            .map_err(Error::from)?;
        return Ok(Box::new(warp::redirect::found(uri)));
    }

    let mut query = search.q.clone();
    query.retain(|c| !"%_".contains(c));
    query.push('%');

    let refs = db.search(&query, SEARCH_LIMIT).await?;

    let html = hbs
        .render(
            "search.html.hbs",
            &json!({
                "search": search.q,
                "refs": refs,
            }),
        )
        .map_err(Error::from)?;
    Ok(Box::new(warp::reply::html(html)))
}

#[derive(Debug, Deserialize)]
struct StatsQuery {
    #[serde(default)]
    dates: bool,
}

async fn stats(
    hbs: Arc<Handlebars<'_>>,
    db: Arc<db::Client>,
    stats: StatsQuery,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let mut set = JoinSet::new();
    if stats.dates {
        let db = db.clone();
        set.spawn(async move { ("import_dates", db.stats_import_dates().await) });
    } else {
        let db = db.clone();
        set.spawn(async move { ("total_artifacts", db.stats_estimated_artifacts().await) });
    }
    {
        let db = db.clone();
        set.spawn(async move { ("vendor_refs", db.stats_vendor_refs().await) });
    }
    {
        let db = db.clone();
        set.spawn(async move { ("pending_tasks", db.stats_pending_tasks().await) });
    }
    {
        let db = db.clone();
        set.spawn(async move { ("aliases_with_reason", db.stats_aliases_with_reason().await) });
    }
    set.spawn(async move {
        (
            "compressed_artifacts",
            db.stats_compressed_artifacts().await,
        )
    });

    let mut data = HashMap::new();
    while let Some(row) = set.join_next().await {
        let Ok((key, values)) = row else { continue };
        let values = values?;

        // for import_dates, also calculate and insert sum
        if key == "import_dates" {
            let sum = values.iter().map(|(_, v)| v).sum();
            data.insert("total_artifacts", vec![("".to_string(), sum)]);
        }

        // add regular data
        data.insert(key, values);
    }

    let html = hbs.render("stats.html.hbs", &data).map_err(Error::from)?;
    Ok(Box::new(warp::reply::html(html)))
}

fn process_files_list(
    list: Option<Vec<ingest::tar::Entry>>,
    sorted: bool,
    trimmed: bool,
) -> Result<Option<Vec<ingest::tar::Entry>>> {
    let Some(mut list) = list else {
        return Ok(None);
    };
    if trimmed {
        list = list
            .into_iter()
            .filter_map(|mut item| {
                item.path = item
                    .path
                    .split_once('/')
                    .map(|(_a, b)| b)
                    .unwrap_or(&item.path)
                    .to_string();
                (!item.path.is_empty()).then_some(item)
            })
            .collect();
    }
    if sorted {
        list.sort_by(|a, b| a.path.partial_cmp(&b.path).unwrap());
    }
    Ok(Some(list))
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Diff {
    trim_left: bool,
    trim_right: bool,
    sorted: bool,
}

impl FromStr for Diff {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Diff, ()> {
        let Some(s) = s.strip_prefix("diff") else {
            return Err(());
        };
        let mut diff = Diff::default();

        let s = s
            .strip_prefix("-sorted")
            .map(|s| {
                diff.sorted = true;
                s
            })
            .unwrap_or(s);

        match s {
            "" => (),
            "-trimmed" => {
                diff.trim_left = true;
                diff.trim_right = true;
            }
            "-left-trimmed" => {
                diff.trim_left = true;
            }
            "-right-trimmed" => {
                diff.trim_right = true;
            }
            _ => return Err(()),
        }

        Ok(diff)
    }
}

impl fmt::Display for Diff {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        w.write_str("diff")?;
        if self.sorted {
            w.write_str("-sorted")?;
        }
        match (self.trim_left, self.trim_right) {
            (true, true) => w.write_str("-trimmed")?,
            (true, false) => w.write_str("-left-trimmed")?,
            (false, true) => w.write_str("-right-trimmed")?,
            (false, false) => (),
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DiffRedirectQuery {
    diff_from: String,
    diff_to: String,
}

pub const ARTIFACT_SET: AsciiSet = url_escape::COMPONENT.remove(b':');

fn url_encode_artifact(txt: &str) -> Cow<'_, str> {
    url_escape::encode(txt, &ARTIFACT_SET)
}

async fn diff_redirect(
    query: DiffRedirectQuery,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    // diff_from comes from type=hidden so we expect a well-formatted identifier
    // diff_to comes from type=text so we try to do a fuzzy match to be user friendly
    let diff_to = detect_hash_search(&query.diff_to).unwrap_or(Cow::Borrowed(&query.diff_to));

    let uri = format!(
        "/diff/{}/{}",
        url_encode_artifact(&query.diff_from),
        url_encode_artifact(&diff_to)
    );
    let uri = uri.parse::<Uri>().map_err(Error::from)?;
    Ok(Box::new(warp::redirect::found(uri)))
}

async fn diff(
    hbs: Arc<Handlebars<'_>>,
    db: Arc<db::Client>,
    options: Diff,
    diff_from: String,
    diff_to: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let Some(artifact1) = db.resolve_artifact(&diff_from).await? else {
        return Err(reject::not_found());
    };

    let Some(artifact2) = db.resolve_artifact(&diff_to).await? else {
        return Err(reject::not_found());
    };

    let mut artifact_files1 = artifact1.get_files()?;
    let mut artifact_files2 = artifact2.get_files()?;

    if options != Diff::default() {
        artifact_files1 = process_files_list(artifact_files1, options.sorted, options.trim_left)?;
        artifact_files2 = process_files_list(artifact_files2, options.sorted, options.trim_right)?;
    }

    let artifact1 = hbs.render_archive(artifact_files1.as_deref())?;
    let artifact2 = hbs.render_archive(artifact_files2.as_deref())?;

    let diff = diffy::create_file_patch(&artifact1, &artifact2, &diff_from, &diff_to);
    let diff = diff.to_string();
    let diff_lines = diff.split('\n').collect::<Vec<_>>();

    let html = hbs
        .render(
            "diff.html.hbs",
            &json!({
                "diff": diff_lines,
                "diff_from": diff_from,
                "diff_to": diff_to,
                "options": options,
                "sorted": options.sorted,
                "trimmed": options.trim_left || options.trim_right,
                "trim_left": options.trim_left,
                "trim_right": options.trim_right,
            }),
        )
        .map_err(Error::from)?;
    Ok(Box::new(warp::reply::html(html)))
}

pub async fn rejection(err: warp::Rejection) -> result::Result<impl warp::Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "404 - file not found\n";
    } else {
        error!("unhandled rejection: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "server error\n";
    }

    Ok(warp::reply::with_status(message, code))
}

pub async fn run(args: &args::Web) -> Result<()> {
    let hbs = Arc::new(Handlebars::new()?);
    let hbs = warp::any().map(move || hbs.clone());

    let db = db::Client::create().await?;
    let db = Arc::new(db);
    let db = warp::any().map(move || db.clone());

    let index = warp::get()
        .and(hbs.clone())
        .and(warp::path::end())
        .and_then(index)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));
    let artifact = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("artifact"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(artifact)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));
    let sbom = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("sbom"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(sbom)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));
    let search = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("search"))
        .and(warp::path::end())
        .and(warp::query::<SearchQuery>())
        .and_then(search)
        .map(|r| cache_control(r, CACHE_CONTROL_SHORT));
    let stats = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("stats"))
        .and(warp::path::end())
        .and(warp::query::<StatsQuery>())
        .and_then(stats)
        .map(|r| cache_control(r, CACHE_CONTROL_SHORT));
    let diff_redirect = warp::get()
        .and(warp::path("diff"))
        .and(warp::path::end())
        .and(warp::query::<DiffRedirectQuery>())
        .and_then(diff_redirect)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));
    let diff = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path::param::<Diff>())
        .and(warp::path::param())
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(diff)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));
    let style = warp::get()
        .and(warp::path("assets"))
        .and(warp::path(asset_name_css()))
        .and(warp::path::end())
        .and(warp_embed::embed_one(&Assets, "style.css"))
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let routes = warp::any()
        .and(
            index
                .or(artifact)
                .or(sbom)
                .or(search)
                .or(stats)
                .or(diff_redirect)
                .or(diff)
                .or(style),
        )
        .recover(rejection);

    warp::serve(routes).run(args.bind_addr).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::tar::LinksTo;

    #[test]
    fn test_render_archive() {
        let hbs = Handlebars::new().unwrap();
        let out = hbs
            .render_archive(Some(&[
                ingest::tar::Entry {
                    path: "cmatrix-2.0/".to_string(),
                    digest: None,
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o775".to_string()),
                        links_to: None,
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
                ingest::tar::Entry {
                    path: "cmatrix-2.0/.gitignore".to_string(),
                    digest: Some(
                        "sha256:45705163f227f0b5c20dc79e3d3e41b4837cb968d1c3af60cc6301b577038984"
                            .to_string(),
                    ),
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o664".to_string()),
                        links_to: None,
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
                ingest::tar::Entry {
                    path: "cmatrix-2.0/data/".to_string(),
                    digest: None,
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o775".to_string()),
                        links_to: None,
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
                ingest::tar::Entry {
                    path: "cmatrix-2.0/data/img/".to_string(),
                    digest: None,
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o775".to_string()),
                        links_to: None,
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
                ingest::tar::Entry {
                    path: "cmatrix-2.0/data/img/capture_bold_font.png".to_string(),
                    digest: Some(
                        "sha256:ffa566a67628191d5450b7209d6f08c8867c12380d3ebc9e808dc4012e3aca58"
                            .to_string(),
                    ),
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o664".to_string()),
                        links_to: None,
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
            ]))
            .unwrap();
        assert_eq!(out, "                                                                         cmatrix-2.0/
sha256:45705163f227f0b5c20dc79e3d3e41b4837cb968d1c3af60cc6301b577038984  cmatrix-2.0/.gitignore
                                                                         cmatrix-2.0/data/
                                                                         cmatrix-2.0/data/img/
sha256:ffa566a67628191d5450b7209d6f08c8867c12380d3ebc9e808dc4012e3aca58  cmatrix-2.0/data/img/capture_bold_font.png
");
    }

    #[test]
    fn test_render_archive_symlink() {
        let hbs = Handlebars::new().unwrap();
        let out = hbs
            .render_archive(Some(&[
                ingest::tar::Entry {
                    path: "foo-1.0/".to_string(),
                    digest: None,
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o755".to_string()),
                        links_to: None,
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
                ingest::tar::Entry {
                    path: "foo-1.0/original_file".to_string(),
                    digest: Some(
                        "sha256:56d9fc4585da4f39bbc5c8ec953fb7962188fa5ed70b2dd5a19dc82df997ba5e"
                            .to_string(),
                    ),
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o644".to_string()),
                        links_to: None,
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
                ingest::tar::Entry {
                    path: "foo-1.0/symlink_file".to_string(),
                    digest: None,
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o777".to_string()),
                        links_to: Some(LinksTo::Symbolic("original_file".to_string())),
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
            ]))
            .unwrap();
        assert_eq!(
            out,
            "                                                                         foo-1.0/
sha256:56d9fc4585da4f39bbc5c8ec953fb7962188fa5ed70b2dd5a19dc82df997ba5e  foo-1.0/original_file
                                                                         foo-1.0/symlink_file -> original_file
"
        );
    }

    #[test]
    fn test_render_archive_hardlink() {
        let hbs = Handlebars::new().unwrap();
        let out = hbs
            .render_archive(Some(&[
                ingest::tar::Entry {
                    path: "foo-1.0/".to_string(),
                    digest: None,
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o644".to_string()),
                        links_to: None,
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
                ingest::tar::Entry {
                    path: "foo-1.0/original_file".to_string(),
                    digest: Some(
                        "sha256:56d9fc4585da4f39bbc5c8ec953fb7962188fa5ed70b2dd5a19dc82df997ba5e"
                            .to_string(),
                    ),
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o644".to_string()),
                        links_to: None,
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
                ingest::tar::Entry {
                    path: "foo-1.0/hardlink_file".to_string(),
                    digest: None,
                    metadata: ingest::tar::Metadata {
                        mode: Some("0o644".to_string()),
                        links_to: Some(LinksTo::Hard("foo-1.0/original_file".to_string())),
                        mtime: Some(1337),
                        uid: Some(0),
                        username: None,
                        gid: Some(0),
                        groupname: None,
                    },
                },
            ]))
            .unwrap();
        assert_eq!(
            out,
            "                                                                         foo-1.0/
sha256:56d9fc4585da4f39bbc5c8ec953fb7962188fa5ed70b2dd5a19dc82df997ba5e  foo-1.0/original_file
                                                                         foo-1.0/hardlink_file link to foo-1.0/original_file
"
        );
    }

    #[test]
    fn test_parse_diff_paths() {
        let diff = "diff".parse::<Diff>().unwrap();
        assert_eq!(diff, Diff::default());

        let diff = "diff-sorted".parse::<Diff>().unwrap();
        assert_eq!(
            diff,
            Diff {
                sorted: true,
                ..Default::default()
            }
        );

        let diff = "diff-sorted-trimmed".parse::<Diff>().unwrap();
        assert_eq!(
            diff,
            Diff {
                sorted: true,
                trim_left: true,
                trim_right: true,
            }
        );

        let diff = "diff-trimmed".parse::<Diff>().unwrap();
        assert_eq!(
            diff,
            Diff {
                sorted: false,
                trim_left: true,
                trim_right: true,
            }
        );

        let diff = "diff-left-trimmed".parse::<Diff>().unwrap();
        assert_eq!(
            diff,
            Diff {
                sorted: false,
                trim_left: true,
                trim_right: false,
            }
        );

        let diff = "diff-sorted-right-trimmed".parse::<Diff>().unwrap();
        assert_eq!(
            diff,
            Diff {
                sorted: true,
                trim_left: false,
                trim_right: true,
            }
        );
    }

    #[test]
    fn test_hash_search_detection() {
        let search = detect_hash_search("ripgrep");
        assert_eq!(search, None);

        // test sha256
        let search = detect_hash_search(
            "sha256:9390fb29874d4e70ae4e8379aa7fc396e0a44cacf8256aa8d87fdec9b56261d4",
        );
        assert_eq!(
            search.as_deref(),
            Some("sha256:9390fb29874d4e70ae4e8379aa7fc396e0a44cacf8256aa8d87fdec9b56261d4")
        );

        // test sha512
        let search = detect_hash_search(
            "sha512:8b981a89ec6735f0c1de0f7d58cbd30921b9fdf645b68330ab1080b2d563410acb3ae77881a2817438ca6405eaafbb62f131a371f0f0e5fcb91727310fb7a370",
        );
        assert_eq!(
            search.as_deref(),
            Some("sha512:8b981a89ec6735f0c1de0f7d58cbd30921b9fdf645b68330ab1080b2d563410acb3ae77881a2817438ca6405eaafbb62f131a371f0f0e5fcb91727310fb7a370"),
        );

        // test blake2b
        let search = detect_hash_search(
            "blake2b:47e872432ce32b7cecc554cc9c67d12553e62fed8f42768a43e64f16ca72e9679b0f539e7f47bf89ffe658be7b3a29f857d4ce244523dce181587c42ec4c7533",
        );
        assert_eq!(
            search.as_deref(),
            Some("blake2b:47e872432ce32b7cecc554cc9c67d12553e62fed8f42768a43e64f16ca72e9679b0f539e7f47bf89ffe658be7b3a29f857d4ce244523dce181587c42ec4c7533"),
        );

        // test git
        let search = detect_hash_search("git:7747534db4576db43eced4356859ef400351ca28");
        assert_eq!(
            search.as_deref(),
            Some("git:7747534db4576db43eced4356859ef400351ca28")
        );
    }

    #[test]
    fn test_hash_search_detection_invalid() {
        // test sha256
        let search = detect_hash_search(
            "sha256:8b981a89ec6735f0c1de0f7d58cbd30921b9fdf645b68330ab1080b2d563410acb3ae77881a2817438ca6405eaafbb62f131a371f0f0e5fcb91727310fb7a370",
        );
        assert_eq!(search, None);

        // test sha512
        let search = detect_hash_search(
            "sha512:9390fb29874d4e70ae4e8379aa7fc396e0a44cacf8256aa8d87fdec9b56261d4",
        );
        assert_eq!(search, None);

        // test blake2b
        let search = detect_hash_search(
            "blake2b:9390fb29874d4e70ae4e8379aa7fc396e0a44cacf8256aa8d87fdec9b56261d4",
        );
        assert_eq!(search, None);
    }

    #[test]
    fn test_hash_search_detection_nix() {
        // https://ftp.gnu.org/gnu/which/which-2.21.tar.gz
        let search = detect_hash_search("sha256-9KJFuUEks3fYtJZGv0IfkVXTaqdhS26/g3BdP/x26q0=");
        assert_eq!(
            search.as_deref(),
            Some("sha256:f4a245b94124b377d8b49646bf421f9155d36aa7614b6ebf83705d3ffc76eaad")
        );
    }

    #[test]
    fn test_hash_search_detection_link() {
        let search = detect_hash_search("https://whatsrc.org/artifact/sha256:981a75f8291020d9f6632c6160ee3651f376bdf354373bea00506a220e355134");
        assert_eq!(
            search.as_deref(),
            Some("sha256:981a75f8291020d9f6632c6160ee3651f376bdf354373bea00506a220e355134")
        );
    }

    #[test]
    fn test_url_encode_artifact() {
        let encoded = url_encode_artifact("sha256:abc/$<>&#xyz");
        assert_eq!(encoded, "sha256:abc%2F%24%3C%3E%26%23xyz");
    }
}
