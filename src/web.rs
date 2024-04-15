use crate::args;
use crate::db;
use crate::errors::*;
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

    let html = hbs
        .render(
            "artifact.html.hbs",
            &json!({
                "artifact": artifact,
                "chksum": chksum,
                "alias": alias,
                "refs": refs,
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

    let refs = db.search(&query).await?;
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
        .and(hbs)
        .and(db)
        .and(warp::path("search"))
        .and(warp::path::end())
        .and(warp::query::<SearchQuery>())
        .and_then(search);
    let style = warp::get()
        .and(warp::path("assets"))
        .and(warp::path("style.css"))
        .and(warp::path::end())
        .and(warp_embed::embed_one(&Assets, "style.css"))
        .map(cache_control);

    let routes = warp::any()
        .and(index.or(artifact).or(search).or(style))
        .recover(rejection);

    warp::serve(routes).run(args.bind_addr).await;

    Ok(())
}
