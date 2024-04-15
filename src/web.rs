use crate::args;
use crate::db;
use crate::errors::*;
use handlebars::Handlebars;
use log::error;
use rust_embed::RustEmbed;
use serde_json::json;
use std::convert::Infallible;
use std::result;
use std::sync::Arc;
use warp::reject;
use warp::{http::StatusCode, Filter};

#[derive(RustEmbed)]
#[folder = "templates"]
#[include = "*.hbs"]
#[include = "*.css"]
struct Assets;

async fn index(hbs: Arc<Handlebars<'_>>) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let html = match hbs.render(
        "index.html.hbs",
        &json!({
            "foo": "bar",
        }),
    ) {
        Ok(html) => html,
        Err(err) => {
            error!("Failed to render template: {err:#}");
            return Ok(Box::new(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };
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

    let html = match hbs.render(
        "artifact.html.hbs",
        &json!({
            "artifact": artifact,
            "chksum": chksum,
            "alias": alias,
            "refs": refs,
        }),
    ) {
        Ok(html) => html,
        Err(err) => {
            error!("Failed to render template: {err:#}");
            return Ok(Box::new(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };
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
        .and_then(index);
    let artifact = warp::get()
        .and(hbs)
        .and(db)
        .and(warp::path("artifact"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(artifact);
    let style = warp::get()
        .and(warp::path("assets"))
        .and(warp::path("style.css"))
        .and(warp::path::end())
        .and(warp_embed::embed_one(&Assets, "style.css"));

    let routes = warp::any()
        .and(index.or(artifact).or(style))
        .recover(rejection);

    warp::serve(routes).run(args.bind_addr).await;

    Ok(())
}
