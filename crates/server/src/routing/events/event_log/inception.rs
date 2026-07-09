use super::*;

// Canonical-JSON digest converged to the single crate-root helper
// (delegates to SDK `canonical_sha256`); re-exported here so existing
// `event_log` call sites keep referencing `canonical_value_digest`.
pub(super) use crate::canonical_value_digest;

pub(super) fn require_object_field(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<(), EventValidationError> {
    match object.get(key) {
        Some(Value::Object(_)) => Ok(()),
        Some(_) => Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event payload must be a JSON object",
        )),
        None => Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event payload is required",
        )),
    }
}

pub(super) fn event_ref_list(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_len: usize,
) -> Result<Vec<String>, EventValidationError> {
    let Some(value) = object.get(key) else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event reference lists are required",
        ));
    };
    let Some(values) = value.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event reference lists must be arrays",
        ));
    };
    // scalability-constraints.md §2. `prev_refs` carries reason_code
    // `prev_refs_too_large` (which also covers the MUST-dedup rule); other ref
    // lists carry `refs_too_large`. Both are `schema_violation` reasons.
    let too_large_reason = if key == "prev_refs" {
        "prev_refs_too_large"
    } else {
        "refs_too_large"
    };
    let count_error = if key == "prev_refs" {
        cokret_sdk::validate_event_prev_ref_count(values.len()).is_err()
    } else {
        cokret_sdk::validate_event_ref_count(values.len()).is_err()
    };
    if values.len() > max_len || count_error {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            too_large_reason,
            "event reference list exceeds the v1 maximum entry count",
        ));
    }
    let mut seen = std::collections::HashSet::with_capacity(values.len());
    values
        .iter()
        .map(|value| {
            let Some(event_id) = value.as_str() else {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "event references must be strings",
                ));
            };
            if !is_valid_event_id(event_id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "event references must use the ck:event: typed prefix",
                ));
            }
            // scalability-constraints.md §2 — entries MUST be deduplicated.
            if !seen.insert(event_id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    too_large_reason,
                    "event reference list MUST NOT contain duplicate entries",
                ));
            }
            Ok(event_id.to_owned())
        })
        .collect()
}

/// SEC-04 — `did_inception` evidence ref roles. Inception-bootstrap
/// self-authorizations (`identity/key-management.md` §5.0.1 step 4) attach a
/// `refs[]` entry with `role="did_inception"` (`critical=true`) pointing at the
/// `did:webvh` entry-0 versionId. Its presence is what distinguishes an
/// inception-key-signed control event from the post-bootstrap §5.1 path (step 7
/// / §5.0.3: subsequent `ck.device.authorize` MUST be `authorized_by` an
/// already-sealed device and therefore carry no `did_inception` ref).
const DID_INCEPTION_REF_ROLE: &str = "did_inception";

/// SEC-04 — receiver-side independent enforcement of the 24h inception-key
/// online-window hard cap (`identity/key-management.md` §5.0.1 step 5,
/// receiver-side independent enforcement).
///
/// Only inception-key-signed control events are gated: a
/// `ck.device.authorize` / `ck.session.grant` whose envelope `refs[]` carries a
/// `role="did_inception"` evidence ref. For those, the receiver seals on the
/// `did:webvh` entry-0 `versionTime` (the verifiable bootstrap timestamp) and
/// computes the inception-key age against its own local clock via the SDK
/// [`cokret_sdk::models::inception_key_age_exceeded`]; an age past the 24h hard
/// cap is rejected with reason `inception_key_window_exceeded`, regardless of
/// any longer deployment-self-reported window.
///
/// **Conservative fail-closed (mirrors `webvh_validation` `versionTime`
/// handling):** when the gate applies but the entry-0 `versionTime` seal is
/// missing / unparseable / the local webvh log is absent, the event is rejected
/// rather than admitted. We never substitute `now` to "pass" the check.
///
/// **Honest scope boundary:** the seal is read from this server's *locally
/// hosted / cached* `did:webvh` log (`persistence.webvh().list_log_events`).
/// When this soland is the principal's webvh host (the v1-core
/// inception-bootstrap topology, since the genesis `ck.device.authorize` is
/// submitted to the same principal server that wrote entry-0) the seal is
/// available and the gate runs at submit time. When the principal's webvh log
/// is hosted elsewhere and not cached here, the gate fails closed (rejects the
/// inception-key-signed event), which is the conservative SEC-04 default — it
/// never silently admits.
pub(super) async fn enforce_inception_key_online_window(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) -> Result<(), SubmitOneError> {
    // Only inception-key-signed control events are subject to the 24h cap.
    if parsed.kind != "ck.device.authorize" && parsed.kind != "ck.session.grant" {
        return Ok(());
    }
    let Some(object) = envelope.as_object() else {
        return Ok(());
    };
    // Post-bootstrap §5.1 device authorizations carry no `did_inception` ref
    // (they are `authorized_by` an sealed device), so they are not gated.
    if !envelope_has_did_inception_ref(object) {
        return Ok(());
    }

    // Resolve the principal DID whose entry-0 seals the inception key. For an
    // inception-bootstrap self-authorization the `actor_id` IS the principal;
    // we also accept an explicit `payload.principal_id` / `payload.subject` for
    // session grants. Fail closed when no `did:webvh` principal can be derived.
    let principal_did = inception_principal_did(object, &parsed.actor_id);
    let Some(principal_did) = principal_did else {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED,
            "inception-key-signed control event lacks a resolvable did:webvh principal for the \
             entry-0 online-window seal",
        ));
    };

    // Seal on the locally hosted/cached entry-0 `versionTime`. Missing log,
    // missing entry-0, or an unparseable timestamp all fail closed.
    let seal = inception_bootstrap_seal(state, &principal_did).await;
    let Some(bootstrap_ts) = seal else {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED,
            "inception-bootstrap entry-0 versionTime seal is missing or unparseable; refusing to \
             admit an inception-key-signed control event without a verifiable online-window seal",
        ));
    };

    if cokret_sdk::models::inception_key_age_exceeded(bootstrap_ts, now()) {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED,
            "inception key online window exceeded the 24h protocol hard cap",
        ));
    }
    Ok(())
}

/// SEC-04 — `true` when the envelope `refs[]` carries a `role="did_inception"`
/// evidence ref (the inception-bootstrap self-authorization marker).
fn envelope_has_did_inception_ref(object: &serde_json::Map<String, Value>) -> bool {
    object
        .get("refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter().any(|reference| {
                reference
                    .get("role")
                    .and_then(Value::as_str)
                    .is_some_and(|role| role == DID_INCEPTION_REF_ROLE)
            })
        })
}

/// SEC-04 — derive the principal DID whose `did:webvh` entry-0 seals the
/// inception key, preferring an explicit `payload.principal_id` / `subject`,
/// falling back to the envelope `actor_id` (the self-authorization case). Only
/// `did:webvh` principals carry an entry-0 seal in this gate; other methods
/// return `None` (handled as fail-closed by the caller).
fn inception_principal_did(
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
) -> Option<String> {
    let payload = object.get("payload").and_then(Value::as_object);
    let candidate = payload
        .and_then(|payload| {
            payload
                .get("principal_id")
                .or_else(|| payload.get("subject"))
                .and_then(Value::as_str)
        })
        .unwrap_or(actor_id);
    candidate
        .starts_with("did:webvh:")
        .then(|| candidate.to_owned())
}

/// SEC-04 — read the verifiable inception-bootstrap timestamp: the `versionTime`
/// of the lowest-`seq` (entry-0 / genesis) record in this server's locally
/// hosted/cached `did:webvh` log for `did`. Returns `None` (fail-closed for the
/// caller) when the log is absent, has no genesis entry, or the genesis
/// `versionTime` is missing / not RFC3339.
async fn inception_bootstrap_seal(
    state: &AppState,
    did: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let events = state.persistence.webvh().list_log_events(did).await.ok()?;
    let genesis = events.iter().min_by_key(|record| record.seq)?;
    let version_time = genesis
        .operation
        .get("versionTime")
        .and_then(Value::as_str)?;
    chrono::DateTime::parse_from_rfc3339(version_time)
        .ok()
        .map(|parsed| parsed.with_timezone(&chrono::Utc))
}

#[cfg(test)]
mod prev_refs_limit_tests {
    use serde_json::json;

    use super::*;

    fn object(refs: serde_json::Value) -> serde_json::Map<String, Value> {
        json!({ "prev_refs": refs }).as_object().unwrap().clone()
    }

    // scalability-constraints.md §2 — prev_refs ≤ 128.
    #[test]
    fn prev_refs_over_max_rejected() {
        let refs: Vec<Value> = (0..(MAX_EVENT_PREV_REFS + 1))
            .map(|i| json!(format!("ck:event:e{i}")))
            .collect();
        let err =
            event_ref_list(&object(json!(refs)), "prev_refs", MAX_EVENT_PREV_REFS).unwrap_err();
        assert_eq!(err.code, "prev_refs_too_large");
    }

    // §2 — entries MUST be deduplicated (`prev_refs_too_large` covers dedup).
    #[test]
    fn duplicate_prev_refs_rejected() {
        let refs = json!(["ck:event:e1", "ck:event:e1"]);
        let err = event_ref_list(&object(refs), "prev_refs", MAX_EVENT_PREV_REFS).unwrap_err();
        assert_eq!(err.code, "prev_refs_too_large");
    }

    #[test]
    fn distinct_prev_refs_within_limit_ok() {
        let refs = json!(["ck:event:e1", "ck:event:e2"]);
        let out = event_ref_list(&object(refs), "prev_refs", MAX_EVENT_PREV_REFS).unwrap();
        assert_eq!(
            out,
            vec!["ck:event:e1".to_owned(), "ck:event:e2".to_owned()]
        );
    }
}
