use crate::db;
use crate::errors::*;
use prometheus::{Encoder, IntGauge, Opts, Registry, TextEncoder};
use std::result;
use std::sync::Arc;
use tokio::task::JoinSet;

#[derive(Default)]
pub struct Metrics {
    reg: Registry,
}

impl Metrics {
    pub fn gauge(&self, opts: Opts, value: i64) {
        let counter = IntGauge::with_opts(opts).unwrap();
        counter.set(value);
        self.reg.register(Box::new(counter.clone())).unwrap();
    }

    pub fn encode(&self) -> String {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = self.reg.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        match String::from_utf8(buffer) {
            Ok(s) => s,
            Err(err) => {
                error!("Failed to convert metrics to UTF-8 string: {err:#}");
                String::new()
            }
        }
    }
}

pub async fn route(db: Arc<db::Client>) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let metrics = Metrics::default();
    let mut set = JoinSet::new();

    set.spawn({
        let db = db.clone();
        async move {
            let (count,) = db.stats_artifacts().await?;
            Ok(vec![(
                Opts::new("artifact_count", "Number of artifacts in the database"),
                count,
            )])
        }
    });

    set.spawn({
        let db = db.clone();
        async move {
            let (count, compressed, uncompressed) = db.stats_archive().await?;

            Ok(vec![
                (
                    Opts::new("archive_item_count", "Number of items in the archive"),
                    count,
                ),
                (
                    Opts::new("archive_size_bytes", "Total size of the archive in bytes")
                        .const_label("type", "compressed"),
                    compressed,
                ),
                (
                    Opts::new("archive_size_bytes", "Total size of the archive in bytes")
                        .const_label("type", "uncompressed"),
                    uncompressed,
                ),
            ])
        }
    });

    set.spawn({
        let db = db.clone();
        async move {
            db.stats_pending_tasks().await.map(|stats| {
                Vec::from_iter(stats.into_iter().map(|(task_type, count)| {
                    (
                        Opts::new("pending_tasks", "Number of pending tasks")
                            .const_label("task_type", &task_type),
                        count,
                    )
                }))
            })
        }
    });

    set.spawn({
        let db = db.clone();
        async move {
            db.stats_vendor_refs().await.map(|stats| {
                Vec::from_iter(stats.into_iter().map(|(vendor, count)| {
                    (
                        Opts::new("source_refs", "Number of refs to sources per vendor")
                            .const_label("vendor", &vendor),
                        count,
                    )
                }))
            })
        }
    });

    while let Some(stat) = set.join_next().await {
        let Ok(stat) = stat else {
            continue;
        };
        for (opts, count) in stat? {
            metrics.gauge(opts, count);
        }
    }

    // Encode the metrics
    let buffer = metrics.encode();
    Ok(Box::new(buffer))
}
