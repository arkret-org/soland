use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use parking_lot::Mutex;
use salvo::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::state::AppState;

/// Fixed latency buckets for `soland_request_duration_seconds`. Kept byte-for-byte
/// identical to the historical hand-rolled exposition so `prometheus-alerts.yml`
/// and the Grafana dashboard continue to match.
const DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// P5 (5.4 metrics cardinality cap) — soft cap on the number of distinct
/// `op` label values we will emit on `soland_request_total` /
/// `soland_request_duration_seconds`. Above this we still record (no
/// data loss) but emit a sticky warning so on-call can audit whether a
/// path normalizer regressed and started leaking an unbounded id segment
/// (e.g. forgot to fold `ak:...` ids in `normalize_path_for_metrics`).
const REQUEST_OP_LABEL_CARDINALITY_THRESHOLD: usize = 200;

// ─────────────────────────────────────────────────────────────────────────
// Metric names. The `metrics-exporter-prometheus` text exporter renders metric
// keys verbatim — it does NOT auto-append the `_total` counter suffix — so the
// full wire name (including `_total`) is registered here. These exact names are
// referenced by `examples/prometheus-alerts.yml` and
// `docs/grafana-operational-dashboard.json` and MUST stay byte-stable.
// ─────────────────────────────────────────────────────────────────────────
const REQUEST_COUNTER: &str = "soland_request_total";
const REQUEST_DURATION: &str = "soland_request_duration_seconds";
const AUDIT_APPEND_FAILURES: &str = "soland_audit_append_failures_total";
const FEDERATION_DLQ: &str = "soland_federation_outbox_dead_letter_total";
const EGRESS_DENIED: &str = "soland_egress_denied_total";
const DIGEST_MISMATCH: &str = "soland_digest_mismatch_total";
const FEDERATION_RETRY: &str = "soland_federation_retry_total";
const DB_POOL_IN_USE: &str = "soland_db_pool_in_use";
const FEDERATION_OUTBOX_DEPTH: &str = "soland_federation_outbox_depth";

static PROMETHEUS_HANDLE: OnceLock<Result<PrometheusHandle, String>> = OnceLock::new();

/// Cardinality tracker for the `op` label. The exporter does not surface the
/// live label-set count, so we track distinct `op` values here purely to drive
/// the P5 (5.4) sticky warning; this is observability bookkeeping, not the
/// metric store.
static OP_CARDINALITY: OnceLock<Mutex<OpCardinality>> = OnceLock::new();

#[derive(Default)]
struct OpCardinality {
    seen: BTreeSet<String>,
    warning_emitted: bool,
}

#[derive(Clone)]
pub struct MetricsMiddleware;

#[async_trait]
impl Handler for MetricsMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let op = request_op_label(req);
        let started = Instant::now();
        ctrl.call_next(req, depot, res).await;
        let status = res.status_code.unwrap_or(StatusCode::OK).as_u16();
        record_http_request(&op, status, started.elapsed());
    }
}

/// Install (idempotently) the global Prometheus recorder and register metric
/// descriptions + the fixed latency buckets. Returns a reference to the shared
/// [`PrometheusHandle`] used to render the exposition on scrape.
fn prometheus_handle() -> Result<&'static PrometheusHandle, String> {
    match PROMETHEUS_HANDLE.get_or_init(|| {
        let handle = PrometheusBuilder::new()
            .set_buckets_for_metric(
                Matcher::Full(REQUEST_DURATION.to_owned()),
                &DURATION_BUCKETS,
            )
            .map_err(|err| err.to_string())?
            .install_recorder()
            .map_err(|err| err.to_string())?;

        describe_counter!(REQUEST_COUNTER, "HTTP requests by operation and status.");
        describe_histogram!(REQUEST_DURATION, "HTTP request duration by operation.");
        describe_counter!(
            AUDIT_APPEND_FAILURES,
            "Audit-log append failures (spec C.3.7)."
        );
        describe_counter!(
            FEDERATION_DLQ,
            "Federation outbox rows moved to the dead-letter ledger."
        );
        describe_counter!(
            EGRESS_DENIED,
            "Outbound requests denied by the deployment egress policy."
        );
        describe_counter!(
            DIGEST_MISMATCH,
            "Payload digest mismatches rejected by admission paths."
        );
        describe_counter!(
            FEDERATION_RETRY,
            "Federation delivery retry state transitions."
        );
        describe_gauge!(
            DB_POOL_IN_USE,
            "PostgreSQL pool connections currently checked out."
        );
        describe_gauge!(
            FEDERATION_OUTBOX_DEPTH,
            "Undelivered federation outbox rows."
        );
        Ok(handle)
    }) {
        Ok(handle) => Ok(handle),
        Err(err) => Err(err.clone()),
    }
}

fn op_cardinality() -> &'static Mutex<OpCardinality> {
    OP_CARDINALITY.get_or_init(|| Mutex::new(OpCardinality::default()))
}

pub async fn spawn_metrics_server(
    state: AppState,
    bind: SocketAddr,
) -> anyhow::Result<JoinHandle<()>> {
    // Install the recorder eagerly so the very first request after startup
    // records into the global recorder rather than the no-op fallback.
    if let Err(error) = prometheus_handle() {
        tracing::error!(%error, "failed to install Prometheus metrics recorder");
    }
    let listener = TcpListener::bind(bind).await?;
    // Bound the number of concurrent in-flight scrape connections so a flood of
    // slow/zombie connections cannot leak unbounded tasks + socket handles
    // (SOL-02-005). A scrape endpoint never needs high concurrency.
    let connection_limit = std::sync::Arc::new(tokio::sync::Semaphore::new(
        METRICS_MAX_CONCURRENT_CONNECTIONS,
    ));
    Ok(tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::error!(%error, "metrics listener accept failed");
                    continue;
                }
            };
            // Acquire a permit before spawning; if all permits are held, drop the
            // connection rather than queueing unbounded work.
            let Ok(permit) = connection_limit.clone().try_acquire_owned() else {
                tracing::debug!(%remote_addr, "metrics scrape rejected: connection limit reached");
                drop(stream);
                continue;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let _permit = permit;
                // Cap total connection lifetime so a connection that never sends a
                // request (slowloris/zombie) cannot pin its task forever.
                match tokio::time::timeout(
                    METRICS_CONNECTION_TIMEOUT,
                    handle_metrics_connection(stream, state),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::debug!(%remote_addr, %error, "metrics scrape failed")
                    }
                    Err(_) => {
                        tracing::debug!(%remote_addr, "metrics scrape timed out")
                    }
                }
            });
        }
    }))
}

/// Upper bound on concurrent metrics scrape connections (SOL-02-005).
const METRICS_MAX_CONCURRENT_CONNECTIONS: usize = 64;
/// Maximum wall-clock lifetime for a single scrape connection (SOL-02-005).
const METRICS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

async fn handle_metrics_connection(mut stream: TcpStream, state: AppState) -> anyhow::Result<()> {
    let mut buffer = [0_u8; 2048];
    let read = stream.read(&mut buffer).await?;
    let request = std::str::from_utf8(&buffer[..read]).unwrap_or_default();
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    let (status, body) = if (method == "GET" || method == "HEAD") && path == "/metrics" {
        ("200 OK", render_metrics(&state).await)
    } else {
        ("404 Not Found", "not found\n".to_owned())
    };

    let include_body = method != "HEAD";
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    if include_body {
        stream.write_all(body.as_bytes()).await?;
    }
    Ok(())
}

/// Render the Prometheus exposition. Scrape-time gauges (DB pool depth,
/// federation outbox depth) are sampled from live [`AppState`] just before
/// the exposition is rendered, mirroring the pull semantics of the previous
/// hand-rolled endpoint.
pub async fn render_metrics(state: &AppState) -> String {
    // Sample scrape-time gauges into the recorder right before rendering.
    gauge!(DB_POOL_IN_USE).set(state.jobs().database_pool_in_use() as f64);
    gauge!(FEDERATION_OUTBOX_DEPTH).set(federation_outbox_depth(state).await as f64);

    match prometheus_handle() {
        Ok(handle) => handle.render(),
        Err(error) => {
            tracing::error!(%error, "metrics recorder unavailable");
            format!("# metrics recorder unavailable: {error}\n")
        }
    }
}

/// Increment the audit-append-failure counter. Called from
/// `routing::admin::audit::append_audit_log` when the persistence layer
/// rejects the append; the counter feeds the `soland_audit_append_failures_total`
/// metric for alerting. Spec: C.3.7.
pub fn record_audit_append_failure() {
    counter!(AUDIT_APPEND_FAILURES).increment(1);
}

/// P5 (5.4) — bump the federation-outbox dead-letter counter. Called
/// from `routing::federation::outbox::insert_dead_letter` immediately
/// after the persistence ledger write (regardless of write outcome —
/// we count the *decision* to give up on a row, not whether the row
/// landed in the ledger). Feeds
/// `soland_federation_outbox_dead_letter_total`.
pub fn record_federation_outbox_dead_letter() {
    counter!(FEDERATION_DLQ).increment(1);
}

pub fn record_egress_denied(reason: &str, target_class: &str) {
    counter!(
        EGRESS_DENIED,
        "reason" => normalize_label(reason),
        "target_class" => normalize_label(target_class)
    )
    .increment(1);
}

pub fn record_digest_mismatch(scope: &str) {
    counter!(DIGEST_MISMATCH, "scope" => normalize_label(scope)).increment(1);
}

pub fn record_federation_retry_state(state: &str) {
    counter!(FEDERATION_RETRY, "state" => normalize_label(state)).increment(1);
}

async fn federation_outbox_depth(state: &AppState) -> usize {
    state
        .federation()
        .deliveries()
        .await
        .map(|rows| rows.iter().filter(|row| row.delivered_at.is_none()).count())
        .unwrap_or(0)
}

fn record_http_request(op: &str, status: u16, duration: Duration) {
    counter!(
        REQUEST_COUNTER,
        "op" => op.to_owned(),
        "status" => status.to_string()
    )
    .increment(1);
    histogram!(REQUEST_DURATION, "op" => op.to_owned()).record(duration.as_secs_f64());

    // Cardinality cap: warn (sticky, once per crossing) when the unique `op`
    // label count crosses `REQUEST_OP_LABEL_CARDINALITY_THRESHOLD`. We do not
    // drop any labels here — the counter still records — but a sustained
    // upward drift typically means `normalize_path_for_metrics` failed to fold
    // an id segment and the time-series store is about to explode.
    let warning_payload = {
        let mut card = op_cardinality().lock();
        card.seen.insert(op.to_owned());
        let unique_ops = card.seen.len();
        if unique_ops > REQUEST_OP_LABEL_CARDINALITY_THRESHOLD && !card.warning_emitted {
            card.warning_emitted = true;
            Some(unique_ops)
        } else {
            None
        }
    };

    if let Some(unique_ops) = warning_payload {
        tracing::warn!(
            target: "metrics_cardinality",
            unique_op_labels = unique_ops,
            threshold = REQUEST_OP_LABEL_CARDINALITY_THRESHOLD,
            "soland_request_total operation label cardinality crossed the warning threshold; \
             audit normalize_path_for_metrics for an id segment that is not being folded"
        );
    }
}

fn request_op_label(req: &Request) -> String {
    format!(
        "{} {}",
        req.method(),
        normalize_path_for_metrics(req.uri().path())
    )
}

fn normalize_path_for_metrics(path: &str) -> String {
    if path == "/" {
        return "/".to_owned();
    }
    let segments = path
        .trim_start_matches('/')
        .split('/')
        .map(|segment| {
            if looks_like_path_id(segment) {
                "{id}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn looks_like_path_id(segment: &str) -> bool {
    segment.starts_with("ak:")
        || segment.starts_with("did:")
        || (segment.len() >= 16
            && segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == ':'))
}

fn normalize_label(value: &str) -> String {
    let normalized = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let normalized = normalized.trim_matches('_').to_owned();
    if normalized.is_empty() {
        "unknown".to_owned()
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render against the live global recorder. Tests share one process-wide
    /// recorder, so assertions check for substring presence (monotonic
    /// counters never decrease) rather than exact values.
    fn render() -> String {
        prometheus_handle().expect("recorder installs").render()
    }

    #[test]
    fn metrics_render_required_http_series() {
        // Recorder must be installed before any record, else metrics land in
        // the global no-op recorder (production installs it at startup via
        // `spawn_metrics_server`).
        let _ = prometheus_handle();
        let op = "GET /_arkret/self/events/{event_id}";
        record_http_request(op, 200, Duration::from_millis(25));
        let rendered = render();

        // Byte-stable wire names referenced by prometheus-alerts.yml + Grafana.
        assert!(rendered.contains("soland_request_total"));
        assert!(rendered.contains("status=\"200\""));
        assert!(rendered.contains("soland_request_duration_seconds_bucket"));
        assert!(rendered.contains("soland_request_duration_seconds_sum"));
        assert!(rendered.contains("soland_request_duration_seconds_count"));
        // Fixed bucket boundaries must survive the migration.
        assert!(rendered.contains("le=\"0.005\""));
        assert!(rendered.contains("le=\"10\"") || rendered.contains("le=\"10.0\""));
        assert!(rendered.contains("le=\"+Inf\""));
    }

    #[test]
    fn metrics_render_operational_counters() {
        let _ = prometheus_handle();
        record_egress_denied("blocked address", "federation outbox");
        record_digest_mismatch("blob upload");
        record_federation_retry_state("retry scheduled");
        record_audit_append_failure();
        record_federation_outbox_dead_letter();
        let rendered = render();

        // Byte-stable wire names (counters carry the exporter `_total` suffix).
        assert!(rendered.contains("soland_egress_denied_total"));
        assert!(rendered.contains("reason=\"blocked_address\""));
        assert!(rendered.contains("target_class=\"federation_outbox\""));
        assert!(rendered.contains("soland_digest_mismatch_total"));
        assert!(rendered.contains("scope=\"blob_upload\""));
        assert!(rendered.contains("soland_federation_retry_total"));
        assert!(rendered.contains("state=\"retry_scheduled\""));
        assert!(rendered.contains("soland_audit_append_failures_total"));
        assert!(rendered.contains("soland_federation_outbox_dead_letter_total"));
    }

    #[test]
    fn path_ids_are_normalized_for_operation_label() {
        assert_eq!(
            normalize_path_for_metrics(
                "/_soland/self/realms/ak:realm:01904100-0000-7000-8000-bbbbbbbbbbbb/events"
            ),
            "/_soland/self/realms/{id}/events"
        );
    }
}
