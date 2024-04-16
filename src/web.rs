use crate::args;
use crate::db;
use crate::errors::*;
use crate::ingest;
use diffy_fork_filenames as diffy;
use handlebars::Handlebars;
use log::error;
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;
use std::result;
use std::sync::Arc;
use warp::reject;
use warp::{
    http::{header::CACHE_CONTROL, HeaderValue, StatusCode},
    Filter,
};

const SEARCH_LIMIT: usize = 150;

#[derive(RustEmbed)]
#[folder = "templates"]
#[include = "*.hbs"]
#[include = "*.css"]
struct Assets;

fn cache_control(reply: impl warp::Reply) -> impl warp::Reply {
    warp::reply::with_header(
        reply,
        CACHE_CONTROL,
        HeaderValue::from_static("max-age=600, stale-while-revalidate=300, stale-if-error=300"),
    )
}

async fn index(hbs: Arc<Handlebars<'_>>) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let html = hbs.render("index.html.hbs", &()).map_err(Error::from)?;
    Ok(Box::new(warp::reply::html(html)))
}

fn render_archive(hbs: &Handlebars, artifact: &db::Artifact) -> Result<String> {
    let artifact = hbs.render("archive.txt.hbs", artifact)?;
    Ok(artifact)
}

async fn artifact(
    hbs: Arc<Handlebars<'_>>,
    db: Arc<db::Client>,
    chksum: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let alias = db.get_artifact_alias(&chksum).await?;

    let resolved_chksum = alias.as_ref().map(|a| &a.alias_to).unwrap_or(&chksum);
    let Some(artifact) = db.get_artifact(resolved_chksum).await? else {
        return Err(reject::not_found());
    };

    let refs = db.get_all_refs(&artifact.chksum).await?;

    let files = render_archive(&hbs, &artifact)?;
    let html = hbs
        .render(
            "artifact.html.hbs",
            &json!({
                "artifact": artifact,
                "chksum": chksum,
                "alias": alias,
                "refs": refs,
                "files": files,
            }),
        )
        .map_err(Error::from)?;
    Ok(Box::new(warp::reply::html(html)))
}

#[derive(Debug, Deserialize)]
struct SearchQuery {
    q: String,
}

async fn search(
    hbs: Arc<Handlebars<'_>>,
    db: Arc<db::Client>,
    search: SearchQuery,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
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

fn process_files_list(
    value: Option<serde_json::Value>,
    trimmed: bool,
) -> Result<Option<serde_json::Value>> {
    let Some(value) = value else { return Ok(None) };
    let mut list = serde_json::from_value::<Vec<ingest::tar::Entry>>(value)?;
    if trimmed {
        for item in &mut list {
            item.path = item
                .path
                .split_once('/')
                .map(|(_a, b)| b)
                .unwrap_or(&item.path)
                .to_string();
        }
    }
    list.sort_by(|a, b| a.path.partial_cmp(&b.path).unwrap());
    let value = serde_json::to_value(&list)?;
    Ok(Some(value))
}

async fn diff(
    hbs: Arc<Handlebars<'_>>,
    db: Arc<db::Client>,
    diff_from: String,
    diff_to: String,
    sorted: bool,
    trimmed: bool,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let Some(mut artifact1) = db.resolve_artifact(&diff_from).await? else {
        return Err(reject::not_found());
    };

    let Some(mut artifact2) = db.resolve_artifact(&diff_to).await? else {
        return Err(reject::not_found());
    };

    if sorted {
        artifact1.files = process_files_list(artifact1.files, trimmed)?;
        artifact2.files = process_files_list(artifact2.files, trimmed)?;
    }

    let artifact1 = render_archive(&hbs, &artifact1)?;
    let artifact2 = render_archive(&hbs, &artifact2)?;

    let diff = diffy::create_file_patch(&artifact1, &artifact2, &diff_from, &diff_to);
    let diff = diff.to_string();

    let html = hbs
        .render(
            "diff.html.hbs",
            &json!({
                "diff": diff,
                "diff_from": diff_from,
                "diff_to": diff_to,
                "sorted": sorted,
                "trimmed": trimmed,
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
    let mut hbs = Handlebars::new();
    hbs.set_prevent_indent(true);
    hbs.register_embed_templates::<Assets>()?;

    let hbs = Arc::new(hbs);
    let hbs = warp::any().map(move || hbs.clone());

    let db = db::Client::create().await?;
    let db = Arc::new(db);
    let db = warp::any().map(move || db.clone());

    let index = warp::get()
        .and(hbs.clone())
        .and(warp::path::end())
        .and_then(index)
        .map(cache_control);
    let artifact = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("artifact"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(artifact)
        .map(cache_control);
    let search = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("search"))
        .and(warp::path::end())
        .and(warp::query::<SearchQuery>())
        .and_then(search);
    let diff_original = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("diff"))
        .and(warp::path::param())
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(|hbs, db, diff_from, diff_to| diff(hbs, db, diff_from, diff_to, false, false))
        .map(cache_control);
    let diff_sorted = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("diff-sorted"))
        .and(warp::path::param())
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(|hbs, db, diff_from, diff_to| diff(hbs, db, diff_from, diff_to, true, false))
        .map(cache_control);
    let diff_sorted_trimmed = warp::get()
        .and(hbs)
        .and(db)
        .and(warp::path("diff-sorted-trimmed"))
        .and(warp::path::param())
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(|hbs, db, diff_from, diff_to| diff(hbs, db, diff_from, diff_to, true, true))
        .map(cache_control);
    let style = warp::get()
        .and(warp::path("assets"))
        .and(warp::path("style.css"))
        .and(warp::path::end())
        .and(warp_embed::embed_one(&Assets, "style.css"))
        .map(cache_control);

    let routes = warp::any()
        .and(
            index
                .or(artifact)
                .or(search)
                .or(diff_original)
                .or(diff_sorted)
                .or(diff_sorted_trimmed)
                .or(style),
        )
        .recover(rejection);

    warp::serve(routes).run(args.bind_addr).await;

    Ok(())
}
