use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use salvo::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::state::AppState;

const DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// P5 (5.4 metrics cardinality cap) — soft cap on the number of distinct
/// `op` label values we will emit on `soland_request_total` /
/// `soland_request_duration_seconds`. Above this we still record (no
/// data loss) but emit a sticky warning so on-call can audit whether a
/// path normalizer regressed and started leaking an unbounded id segment
/// (e.g. forgot to fold `cx:...` ids in `normalize_path_for_metrics`).
const REQUEST_OP_LABEL_CARDINALITY_THRESHOLD: usize = 200;

static METRICS: OnceLock<Mutex<HttpMetrics>> = OnceLock::new();

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

pub async fn spawn_metrics_server(
    state: AppState,
    bind: SocketAddr,
) -> anyhow::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(bind).await?;
    Ok(tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::error!(%error, "metrics listener accept failed");
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_metrics_connection(stream, state).await {
                    tracing::debug!(%remote_addr, %error, "metrics scrape failed");
                }
            });
        }
    }))
}

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

pub async fn render_metrics(state: &AppState) -> String {
    let mut output = render_http_metrics();
    output.push_str(
        "# HELP soland_db_pool_in_use PostgreSQL pool connections currently checked out.\n",
    );
    output.push_str("# TYPE soland_db_pool_in_use gauge\n");
    output.push_str(&format!(
        "soland_db_pool_in_use {}\n",
        state.db.pool_in_use()
    ));
    output.push_str("# HELP soland_federation_outbox_depth Undelivered federation outbox rows.\n");
    output.push_str("# TYPE soland_federation_outbox_depth gauge\n");
    output.push_str(&format!(
        "soland_federation_outbox_depth {}\n",
        federation_outbox_depth(state).await
    ));
    output.push_str(
        "# HELP soland_audit_append_failures_total Audit-log append failures (spec C.3.7).\n",
    );
    output.push_str("# TYPE soland_audit_append_failures_total counter\n");
    output.push_str(&format!(
        "soland_audit_append_failures_total {}\n",
        audit_append_failures()
    ));
    // P5 (5.4) — federation outbox DLQ counter. The dispatcher
    // (`routing::federation::outbox`) bumps this every time a row is
    // moved to the dead-letter ledger (either `terminal_http_status` or
    // `retry_budget_exhausted`). The counter is a process-lifetime
    // monotonic; pair with `soland_federation_outbox_depth` for
    // queue-depth alerts.
    output.push_str(
        "# HELP soland_federation_outbox_dead_letter_total Federation outbox rows moved to the dead-letter ledger.\n",
    );
    output.push_str("# TYPE soland_federation_outbox_dead_letter_total counter\n");
    output.push_str(&format!(
        "soland_federation_outbox_dead_letter_total {}\n",
        federation_outbox_dead_letter_total()
    ));
    output
}

/// Increment the audit-append-failure counter. Called from
/// `routing::admin::audit::append_audit_log` when the persistence layer
/// rejects the append; the counter feeds the `soland_audit_append_failures_total`
/// metric for alerting. Spec: C.3.7.
pub fn record_audit_append_failure() {
    let mut metrics = metrics_state().lock().expect("metrics lock");
    metrics.audit_append_failures = metrics.audit_append_failures.saturating_add(1);
}

fn audit_append_failures() -> u64 {
    metrics_state()
        .lock()
        .expect("metrics lock")
        .audit_append_failures
}

/// P5 (5.4) — bump the federation-outbox dead-letter counter. Called
/// from `routing::federation::outbox::insert_dead_letter` immediately
/// after the persistence ledger write (regardless of write outcome —
/// we count the *decision* to give up on a row, not whether the row
/// landed in the ledger). Feeds
/// `soland_federation_outbox_dead_letter_total`.
pub fn record_federation_outbox_dead_letter() {
    let mut metrics = metrics_state().lock().expect("metrics lock");
    metrics.federation_outbox_dead_letters =
        metrics.federation_outbox_dead_letters.saturating_add(1);
}

fn federation_outbox_dead_letter_total() -> u64 {
    metrics_state()
        .lock()
        .expect("metrics lock")
        .federation_outbox_dead_letters
}

async fn federation_outbox_depth(state: &AppState) -> usize {
    state
        .persistence
        .federation_outbox()
        .snapshot_all().await
        .map(|rows| rows.iter().filter(|row| row.delivered_at.is_none()).count())
        .unwrap_or(0)
}

fn record_http_request(op: &str, status: u16, duration: Duration) {
    let (cardinality_warning_payload, warning_threshold) = {
        let mut metrics = metrics_state().lock().expect("metrics lock");
        *metrics
            .request_totals
            .entry((op.to_owned(), status))
            .or_insert(0) += 1;

        let seconds = duration.as_secs_f64();
        let histogram = metrics.request_durations.entry(op.to_owned()).or_default();
        histogram.count += 1;
        histogram.sum_seconds += seconds;
        for (index, bucket) in DURATION_BUCKETS.iter().enumerate() {
            if seconds <= *bucket {
                histogram.bucket_counts[index] += 1;
            }
        }

        // Cardinality cap: warn (sticky, once per crossing) when the
        // unique `op` label count crosses
        // `REQUEST_OP_LABEL_CARDINALITY_THRESHOLD`. We do not drop any
        // labels here — the counter still records — but a sustained
        // upward drift typically means `normalize_path_for_metrics`
        // failed to fold an id segment and the time-series store is
        // about to explode.
        let unique_ops = metrics.request_durations.len();
        let crossed = unique_ops > REQUEST_OP_LABEL_CARDINALITY_THRESHOLD
            && !metrics.cardinality_warning_emitted;
        if crossed {
            metrics.cardinality_warning_emitted = true;
            (Some(unique_ops), REQUEST_OP_LABEL_CARDINALITY_THRESHOLD)
        } else {
            (None, REQUEST_OP_LABEL_CARDINALITY_THRESHOLD)
        }
    };

    if let Some(unique_ops) = cardinality_warning_payload {
        tracing::warn!(
            target: "metrics_cardinality",
            unique_op_labels = unique_ops,
            threshold = warning_threshold,
            "soland_request_total operation label cardinality crossed the warning threshold; \
             audit normalize_path_for_metrics for an id segment that is not being folded"
        );
    }
}

fn render_http_metrics() -> String {
    let metrics = metrics_state().lock().expect("metrics lock").clone();
    let mut output = String::new();
    output.push_str("# HELP soland_request_total HTTP requests by operation and status.\n");
    output.push_str("# TYPE soland_request_total counter\n");
    for ((op, status), count) in &metrics.request_totals {
        output.push_str(&format!(
            "soland_request_total{{op=\"{}\",status=\"{}\"}} {}\n",
            escape_label(op),
            status,
            count
        ));
    }

    output.push_str("# HELP soland_request_duration_seconds HTTP request duration by operation.\n");
    output.push_str("# TYPE soland_request_duration_seconds histogram\n");
    for (op, histogram) in &metrics.request_durations {
        for (index, bucket) in DURATION_BUCKETS.iter().enumerate() {
            output.push_str(&format!(
                "soland_request_duration_seconds_bucket{{op=\"{}\",le=\"{}\"}} {}\n",
                escape_label(op),
                bucket,
                histogram.bucket_counts[index]
            ));
        }
        output.push_str(&format!(
            "soland_request_duration_seconds_bucket{{op=\"{}\",le=\"+Inf\"}} {}\n",
            escape_label(op),
            histogram.count
        ));
        output.push_str(&format!(
            "soland_request_duration_seconds_sum{{op=\"{}\"}} {:.6}\n",
            escape_label(op),
            histogram.sum_seconds
        ));
        output.push_str(&format!(
            "soland_request_duration_seconds_count{{op=\"{}\"}} {}\n",
            escape_label(op),
            histogram.count
        ));
    }
    output
}

fn metrics_state() -> &'static Mutex<HttpMetrics> {
    METRICS.get_or_init(|| Mutex::new(HttpMetrics::default()))
}

#[derive(Clone, Default)]
struct HttpMetrics {
    request_totals: BTreeMap<(String, u16), u64>,
    request_durations: BTreeMap<String, HistogramStats>,
    /// Audit-log append failures since process start. Spec: C.3.7 —
    /// every `append_audit_log` failure bumps this counter so on-call
    /// can alert on durable-audit drops.
    audit_append_failures: u64,
    /// P5 (5.4) — federation outbox dead-letter counter. Bumped from
    /// `routing::federation::outbox::insert_dead_letter` each time a
    /// row is moved to the DLQ ledger. Pairs with
    /// `soland_federation_outbox_depth` for queue alerting.
    federation_outbox_dead_letters: u64,
    /// P5 (5.4 metrics cardinality cap) — sticky one-shot flag so we
    /// emit the cardinality-threshold warning once per process even
    /// when the operator never lowers the cardinality back below the
    /// threshold. Reset only on process restart.
    cardinality_warning_emitted: bool,
}

#[derive(Clone)]
struct HistogramStats {
    count: u64,
    sum_seconds: f64,
    bucket_counts: [u64; DURATION_BUCKETS.len()],
}

impl Default for HistogramStats {
    fn default() -> Self {
        Self {
            count: 0,
            sum_seconds: 0.0,
            bucket_counts: [0; DURATION_BUCKETS.len()],
        }
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
    segment.starts_with("cx:")
        || segment.starts_with("did:")
        || (segment.len() >= 16
            && segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == ':'))
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_required_http_series() {
        let op = "GET /api/v1/events/{id}/metrics-test";
        record_http_request(op, 200, Duration::from_millis(25));
        let rendered = render_http_metrics();

        assert!(rendered.contains("soland_request_total"));
        assert!(rendered.contains("status=\"200\""));
        assert!(rendered.contains("soland_request_duration_seconds_bucket"));
        assert!(rendered.contains("soland_request_duration_seconds_sum"));
        assert!(rendered.contains("soland_request_duration_seconds_count"));
    }

    #[test]
    fn path_ids_are_normalized_for_operation_label() {
        assert_eq!(
            normalize_path_for_metrics(
                "/api/v1/realms/cx:realm:01904100-0000-7000-8000-bbbbbbbbbbbb/events"
            ),
            "/api/v1/realms/{id}/events"
        );
    }
}
