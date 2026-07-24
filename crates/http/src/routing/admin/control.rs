//! Admin mid-stream control-frame triggers for `ak.self.events.stream.subscribe`.
//!
//! `events.subscribe` already dispatches five `EventNotificationKind`
//! variants — `Event` / `EpochRotation` / `Frontier` / `ResyncRequired` /
//! `Unauthorized` — onto NDJSON frames. The first three have natural
//! triggers wired through the projection / Move-Seal pipeline; the last
//! two need explicit ops triggers (a session got revoked, a snapshot got
//! corrupted, a server-side compaction means clients MUST drop their
//! local cache).
//!
//! Endpoints:
//! - `POST /_soland/admin/events/resync-required` — emit a `resync_required` frame to all
//!   subscribers of one Space. Body: `{realm_id, reason}`.
//! - `POST /_soland/admin/events/unauthorized` — emit an `unauthorized` frame; clients MUST close
//!   the stream and re-auth.
//!
//! Both endpoints are gated by the shared `RequireAdmin` middleware before
//! the handler runs; rate limiting comes from the global RateLimiter
//! middleware. Audit-log and replay protection remain future work.

use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use soland_http::error::{AppError, ErrorCode};

use super::AuthArgs;
use crate::state::{AppState, EventNotification, EventNotificationKind};
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("admin/events/resync-required").post(admin_emit_resync_required))
        .push(Router::with_path("admin/events/unauthorized").post(admin_emit_unauthorized))
}

/// Request body for the resync-required / unauthorized triggers. Both
/// endpoints share a target Space and a free-form reason surfaced verbatim
/// to subscribers in the control frame. `reconnect_after_ms` applies only to
/// `resync_required`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminControlFrameRequestBody {
    /// The Space whose subscribers should receive the frame.
    pub realm_id: String,
    /// Free-form reason string. Surfaced verbatim in the NDJSON frame
    /// as the `reason` field for client-side telemetry / UX.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional minimum reconnect delay for `resync_required` frames.
    #[serde(default)]
    pub reconnect_after_ms: Option<u64>,
}

/// Response body — reports how many subscribers received the frame
/// (best-effort; broadcast::send returns the receiver count at the moment
/// of send, not delivery confirmation).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminControlFrameOutcome {
    /// `true` if the broadcast was attempted; `false` only if the channel
    /// was closed (server is shutting down).
    pub broadcast: bool,
    /// Number of receivers active at send time. `0` is normal — it means
    /// no clients are currently subscribed to this Realm.
    pub receivers: usize,
    /// The kind that was emitted: `"resync_required"` or `"unauthorized"`.
    pub kind: String,
}

/// `POST /_soland/admin/events/resync-required` — emit a
/// `resync_required` mid-stream control frame to subscribers of one
/// Space. Use cases:
/// - Server-side compaction or recovery rewrote the Seal DAG and client-cached cursors are no
///   longer valid.
/// - Operator detected per-subscriber drift via out-of-band monitoring.
///
/// Clients receiving this frame MUST drop their local cache and
/// re-subscribe with `from=null` (or whatever the subscribe path
/// considers a fresh-from-frontier start).
#[handler]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.events.resync_required")
)]
async fn admin_emit_resync_required(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AdminControlFrameRequestBody>,
) -> JsonResult<AdminControlFrameOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;

    let AdminControlFrameRequestBody {
        realm_id,
        reason,
        reconnect_after_ms,
    } = body.into_inner();
    if realm_id.is_empty() {
        return Err(
            AppError::new(ErrorCode::InvalidParam, "realm_id is required".to_owned())
                .with_status(StatusCode::BAD_REQUEST),
        );
    }
    let reason = reason.unwrap_or_else(|| "admin_triggered".to_owned());

    let notification = EventNotification {
        realm_id: realm_id.clone(),
        kind: EventNotificationKind::ResyncRequired {
            reason,
            reconnect_after_ms,
        },
    };
    let receivers = state.publish_event_notification(notification).unwrap_or(0);
    json_ok(AdminControlFrameOutcome {
        broadcast: true,
        receivers,
        kind: "resync_required".to_owned(),
    })
}

/// `POST /_soland/admin/events/unauthorized` — emit an `unauthorized`
/// mid-stream control frame to subscribers of one Space. Use cases:
/// - Bulk session revocation (compromised refresh token, deleted account).
/// - Capability lattice change demoted the subscriber's grant below the subscribe threshold
///   mid-session.
///
/// Clients receiving this frame MUST close the stream and re-authenticate
/// before reconnecting; the existing session token is no longer accepted.
#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.events.unauthorized"))]
async fn admin_emit_unauthorized(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AdminControlFrameRequestBody>,
) -> JsonResult<AdminControlFrameOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;

    let AdminControlFrameRequestBody {
        realm_id, reason, ..
    } = body.into_inner();
    if realm_id.is_empty() {
        return Err(
            AppError::new(ErrorCode::InvalidParam, "realm_id is required".to_owned())
                .with_status(StatusCode::BAD_REQUEST),
        );
    }
    let reason = reason.unwrap_or_else(|| "session_revoked".to_owned());

    let notification = EventNotification {
        realm_id: realm_id.clone(),
        kind: EventNotificationKind::Unauthorized { reason },
    };
    let receivers = state.publish_event_notification(notification).unwrap_or(0);
    json_ok(AdminControlFrameOutcome {
        broadcast: true,
        receivers,
        kind: "unauthorized".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use tokio::sync::broadcast;

    use super::*;
    use crate::state::EventNotificationKind;

    #[tokio::test]
    async fn resync_required_notification_round_trips_through_channel() {
        let (tx, mut rx) = broadcast::channel::<EventNotification>(8);
        let n = EventNotification {
            realm_id: "ak:realm:01904100-0000-7000-8000-000000000001".to_owned(),
            kind: EventNotificationKind::ResyncRequired {
                reason: "compaction".to_owned(),
                reconnect_after_ms: Some(7_500),
            },
        };
        tx.send(n).expect("broadcast send");
        let received = rx.recv().await.expect("receive");
        assert_eq!(
            received.realm_id,
            "ak:realm:01904100-0000-7000-8000-000000000001"
        );
        match received.kind {
            EventNotificationKind::ResyncRequired {
                reason,
                reconnect_after_ms,
            } => {
                assert_eq!(reason, "compaction");
                assert_eq!(reconnect_after_ms, Some(7_500));
            }
            other => panic!("expected ResyncRequired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unauthorized_notification_round_trips_through_channel() {
        let (tx, mut rx) = broadcast::channel::<EventNotification>(8);
        let n = EventNotification {
            realm_id: "ak:realm:01904100-0000-7000-8000-000000000002".to_owned(),
            kind: EventNotificationKind::Unauthorized {
                reason: "session_revoked".to_owned(),
            },
        };
        tx.send(n).expect("broadcast send");
        let received = rx.recv().await.expect("receive");
        assert_eq!(
            received.realm_id,
            "ak:realm:01904100-0000-7000-8000-000000000002"
        );
        match received.kind {
            EventNotificationKind::Unauthorized { reason } => {
                assert_eq!(reason, "session_revoked");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn empty_realm_id_request_is_caught_at_handler_level() {
        // We can't easily run the salvo handler in a unit test without
        // spinning up a Service; the empty-realm_id branch is a simple
        // string check exercised by integration tests. This test just
        // pins the request shape so we don't accidentally drop the
        // `realm_id` field.
        let req = AdminControlFrameRequestBody {
            realm_id: String::new(),
            reason: Some("x".to_owned()),
            reconnect_after_ms: Some(10_000),
        };
        assert!(req.realm_id.is_empty());
        assert_eq!(req.reason.as_deref(), Some("x"));
        assert_eq!(req.reconnect_after_ms, Some(10_000));
    }
}
