//! SEC-04 — receiver-side independent 24h inception-key online-window cap
//! (`identity/key-management.md` §5.0.1 step 5). These tests exercise the
//! gate directly against the locally hosted `did:webvh` entry-0
//! `versionTime` seal.
use super::proof_strictness_tests::make_state;
use super::*;
use crate::state::WebvhLogRecord;

const PRINCIPAL_DID: &str = "did:webvh:zScidExample0000000000000000000000:test.example:webvh:alice";

fn parsed(kind: &str) -> ValidatedEventEnvelope {
    ValidatedEventEnvelope {
        event_id: "ak:event:01904100-0000-7000-8000-a11ce0000001".to_owned(),
        actor_id: PRINCIPAL_DID.to_owned(),
        actor_seq: 1,
        realm_id: "ak:realm:01904100-0000-7000-8000-a11ce0000001".to_owned(),
        device_id: "ak:device:x".to_owned(),
        kind: kind.to_owned(),
        schema_id: "ck.schema.event.v1".to_owned(),
        prev_refs: Vec::new(),
        authorized_refs: Vec::new(),
        canonical_digest: format!("sha256:{}", "0".repeat(64)),
        canonical_bytes: Vec::new(),
    }
}

/// Inception-bootstrap self-authorization: a `ck.device.authorize` whose
/// envelope `refs[]` carries the `role="did_inception"` evidence ref.
fn inception_bootstrap_envelope() -> Value {
    json!({
        "event_id": "ak:event:01904100-0000-7000-8000-a11ce0000001",
        "kind": "ck.device.authorize",
        "actor_id": PRINCIPAL_DID,
        "refs": [
            {"id": "1-zEntryZeroVersionId", "role": "did_inception", "critical": true}
        ],
        "payload": {"principal_id": PRINCIPAL_DID, "device_id": "ak:device:x"}
    })
}

/// Post-bootstrap §5.1 device authorization: `authorized_by` an sealed
/// device, with NO `did_inception` ref.
fn sealed_device_envelope() -> Value {
    json!({
        "event_id": "ak:event:01904100-0000-7000-8000-a11ce0000002",
        "kind": "ck.device.authorize",
        "actor_id": PRINCIPAL_DID,
        "refs": [
            {"id": "ak:event:01904100-0000-7000-8000-a11ce0000001", "role": "authorized_by"}
        ],
        "payload": {"principal_id": PRINCIPAL_DID, "device_id": "ak:device:y"}
    })
}

async fn seed_entry_zero(state: &AppState, version_time: &str) {
    state
        .persistence
        .webvh()
        .append_log_event(WebvhLogRecord {
            event_digest: format!("sha256:{}", "1".repeat(64)),
            did: PRINCIPAL_DID.to_owned(),
            // did.rs writes the genesis entry with seq=1 (versionId "1-..");
            // the gate seals on the lowest-seq record regardless.
            seq: 1,
            operation: json!({
                "versionId": "1-zEntryZeroVersionId",
                "versionTime": version_time,
                "parameters": {"method": "did:webvh:1.0"},
                "state": {"id": PRINCIPAL_DID},
            }),
            created_at: now(),
        })
        .await
        .expect("seed entry-0");
}

#[tokio::test]
async fn rejects_when_self_reported_window_is_long_but_age_exceeds_24h() {
    // Seal entry-0 ~48h before "now"; the deployment may self-report a
    // longer window, but the receiver's independent 24h cap MUST reject.
    let state = make_state(true);
    let bootstrap = now() - chrono::Duration::hours(48);
    seed_entry_zero(&state, &bootstrap.to_rfc3339()).await;
    let err = enforce_inception_key_online_window(
        &state,
        &parsed("ck.device.authorize"),
        &inception_bootstrap_envelope(),
    )
    .await
    .expect_err("inception key older than 24h must be rejected");
    assert_eq!(
        err.code,
        crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED
    );
    assert_eq!(err.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admits_when_inception_key_age_under_24h() {
    let state = make_state(true);
    let bootstrap = now() - chrono::Duration::hours(1);
    seed_entry_zero(&state, &bootstrap.to_rfc3339()).await;
    enforce_inception_key_online_window(
        &state,
        &parsed("ck.device.authorize"),
        &inception_bootstrap_envelope(),
    )
    .await
    .expect("inception key under 24h must be admitted");
}

#[tokio::test]
async fn fails_closed_when_entry_zero_version_time_missing() {
    // Inception-bootstrap event but NO local entry-0 seal → conservative
    // reject, never silently admit.
    let state = make_state(true);
    let err = enforce_inception_key_online_window(
        &state,
        &parsed("ck.device.authorize"),
        &inception_bootstrap_envelope(),
    )
    .await
    .expect_err("missing entry-0 seal must fail closed");
    assert_eq!(
        err.code,
        crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED
    );
}

#[tokio::test]
async fn fails_closed_when_version_time_unparseable() {
    let state = make_state(true);
    seed_entry_zero(&state, "not-a-timestamp").await;
    let err = enforce_inception_key_online_window(
        &state,
        &parsed("ck.device.authorize"),
        &inception_bootstrap_envelope(),
    )
    .await
    .expect_err("unparseable versionTime must fail closed");
    assert_eq!(
        err.code,
        crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED
    );
}

#[tokio::test]
async fn sealed_device_authorize_is_not_gated() {
    // A post-bootstrap device.authorize (no did_inception ref) is NOT
    // subject to the inception-key window even when an old entry-0 exists.
    let state = make_state(true);
    let bootstrap = now() - chrono::Duration::hours(72);
    seed_entry_zero(&state, &bootstrap.to_rfc3339()).await;
    enforce_inception_key_online_window(
        &state,
        &parsed("ck.device.authorize"),
        &sealed_device_envelope(),
    )
    .await
    .expect("sealed-device authorize must not be gated by the inception window");
}

#[tokio::test]
async fn session_grant_signed_by_inception_key_is_gated() {
    let state = make_state(true);
    let bootstrap = now() - chrono::Duration::hours(48);
    seed_entry_zero(&state, &bootstrap.to_rfc3339()).await;
    let envelope = json!({
        "event_id": "ak:event:01904100-0000-7000-8000-a11ce0000003",
        "kind": "ck.session.grant",
        "actor_id": PRINCIPAL_DID,
        "refs": [
            {"id": "1-zEntryZeroVersionId", "role": "did_inception", "critical": true}
        ],
        "payload": {"subject": PRINCIPAL_DID}
    });
    let err = enforce_inception_key_online_window(&state, &parsed("ck.session.grant"), &envelope)
        .await
        .expect_err("inception-key-signed session.grant past 24h must be rejected");
    assert_eq!(
        err.code,
        crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED
    );
}

#[tokio::test]
async fn unrelated_kind_is_ignored() {
    let state = make_state(true);
    enforce_inception_key_online_window(
        &state,
        &parsed("ck.message.create"),
        &inception_bootstrap_envelope(),
    )
    .await
    .expect("non-control kinds are never gated");
}
