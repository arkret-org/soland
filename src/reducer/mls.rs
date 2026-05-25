//! G3.S1 — MLS / E2EE lifecycle reducer helpers.
//!
//! Implements the scoped subset of the MLS event family:
//!
//! 1. **KeyPackage atomic claim** — `apply_keypackage_publish` /
//!    `apply_keypackage_claim`. The claim path is a compare-and-swap on
//!    the `claimed_by` slot so two concurrent Welcomes can't grab the
//!    same KeyPackage; the second claim returns
//!    `ProjectionEffect::Rejected { reason: "mls_keypackage_already_claimed" }`
//!    which the routing layer maps to HTTP 409 `cas_conflict`.
//!
//! 2. **Welcome to-device persistence** — `apply_welcome_enqueue`.
//!    Each accepted Welcome is appended to a per-`(recipient_actor_did,
//!    recipient_device_id)` queue inside `ProjectionState::mls_welcomes`.
//!    The recipient device drains its queue via the
//!    `GET /api/v1/mls/welcomes/pending` route, which marks delivered
//!    rows with `delivered_at = now()` so subsequent polls don't
//!    redeliver.
//!
//! 3. **group genesis** — `apply_group_genesis`. Installs epoch 0 for
//!    a new MLS group and initializes its covered-frontier accumulator.
//!
//! 4. **commit_epoch increment** — `apply_commit_epoch`. The reducer
//!    only accepts a commit whose `expected_prev_epoch` matches the
//!    group's current stored epoch (0 for a brand-new group). Stale /
//!    out-of-order commits are rejected with `mls_epoch_skew`. Accepted
//!    commits merge the attested governance frontier into the group's
//!    covered-frontier accumulator.
//!
//! Deferred (TODO(G3.S1-followup) markers below + in `routing/mls.rs`):
//!   - decryption_pending (deferred-decryption queue + retry)

use contrix_sdk::Operation;
use serde_json::{Map, Value};

use super::{
    KeyPackageLifetime, MlsCommitEpoch, MlsEffect, MlsKeyPackage, MlsWelcome, ProjectionState,
};

/// Reason code emitted when a `cx.mls.keypackage` event with
/// `payload.action == "claim"` targets a KeyPackage that has already
/// been claimed. Routing layer maps to HTTP 409 `cas_conflict`.
pub const REASON_KEYPACKAGE_ALREADY_CLAIMED: &str = "mls_keypackage_already_claimed";
/// Reason code emitted when a `cx.mls.keypackage` event with
/// `payload.action == "claim"` targets an unknown KeyPackage id.
pub const REASON_KEYPACKAGE_NOT_FOUND: &str = "mls_keypackage_not_found";
/// Reason code emitted when a published KeyPackage's lifetime window
/// is already past `not_after`. Mirrors RFC 9420 §10.
pub const REASON_KEYPACKAGE_EXPIRED: &str = "mls_keypackage_expired";
/// Reason code emitted when a commit's `expected_prev_epoch` does not
/// match the group's stored epoch (out-of-order / stale / replay).
pub const REASON_COMMIT_EPOCH_SKEW: &str = "mls_epoch_skew";
/// Reject code for Welcome payloads that try to carry plaintext sender,
/// profile, relationship, or device metadata outside the opaque MLS bytes.
pub const REASON_WELCOME_METADATA_LEAK: &str = "mls_welcome_metadata_leak";
/// Reject code for commits whose governance binding does not name an
/// attested frontier to add into the covered-frontier accumulator.
pub const REASON_COMMIT_COVERED_FRONTIER_MISSING: &str = "mls_covered_frontier_missing";
/// Reject code for a second genesis against an already initialized group.
pub const REASON_GENESIS_ALREADY_EXISTS: &str = "mls_genesis_already_exists";

/// G3.S1 — project a `cx.mls.keypackage` event with
/// `payload.action == "publish"`.
///
/// Payload shape (validated below):
/// ```json
/// {
///   "keypackage_id": "cx:mls_keypackage:<uuid>",
///   "actor_did": "did:web:alice.example",
///   "device_id": "cx:device:<uuid>",
///   "lifetime": { "not_before": <unix_secs>, "not_after": <unix_secs> },
///   "key_package_bytes_b64": "<base64url(opaque MLS KeyPackage)>"
/// }
/// ```
pub fn apply_keypackage_publish(
    state: &mut ProjectionState,
    op: &Operation,
) -> ProjectionEffectOut {
    let payload = &op.payload;
    let Some(id) = payload.get("keypackage_id").and_then(Value::as_str) else {
        return reject("mls_keypackage_id_missing");
    };
    let Some(actor_did) = payload.get("actor_did").and_then(Value::as_str) else {
        return reject("mls_keypackage_actor_missing");
    };
    let Some(device_id) = payload.get("device_id").and_then(Value::as_str) else {
        return reject("mls_keypackage_device_missing");
    };
    let lifetime = match parse_lifetime(payload.get("lifetime")) {
        Ok(l) => l,
        Err(reason) => return reject(reason),
    };
    if lifetime.not_after <= lifetime.not_before {
        return reject("mls_keypackage_lifetime_invalid");
    }
    let key_package_bytes = match payload
        .get("key_package_bytes_b64")
        .and_then(Value::as_str)
        .map(decode_base64_loose)
    {
        Some(Ok(bytes)) if !bytes.is_empty() => bytes,
        Some(Ok(_)) => return reject("mls_keypackage_bytes_empty"),
        Some(Err(_)) => return reject("mls_keypackage_bytes_invalid_b64"),
        None => return reject("mls_keypackage_bytes_missing"),
    };

    let created_at = op.created_at.timestamp();
    let row = MlsKeyPackage {
        id: id.to_owned(),
        actor_did: actor_did.to_owned(),
        device_id: device_id.to_owned(),
        lifetime,
        key_package_bytes,
        claimed_by: None,
        consumed_at: None,
        created_at,
    };

    // Insert is structural — duplicates of the same `keypackage_id`
    // replace in place (a republish of the same id by the same device
    // re-arms the row; the device is the sole source-of-truth for the
    // opaque bytes). Production deployments will route duplicate-id
    // detection through the wire validator before reaching here.
    state.mls_key_packages.insert(id.to_owned(), row);

    ProjectionEffectOut::Mls(MlsEffect::KeyPackagePublished {
        keypackage_id: id.to_owned(),
        actor_did: actor_did.to_owned(),
        device_id: device_id.to_owned(),
    })
}

/// G3.S1 — atomic CAS claim of a published KeyPackage.
///
/// Payload shape:
/// ```json
/// {
///   "keypackage_id": "cx:mls_keypackage:<uuid>",
///   "group_id":      "cx:mls_group:<uuid>"
/// }
/// ```
///
/// Concurrency contract: two concurrent claims against the same
/// `keypackage_id` MUST see exactly one `KeyPackageClaimed` effect; the
/// loser receives `Rejected { reason: mls_keypackage_already_claimed }`.
/// The HTTP layer maps that to 409 `cas_conflict`.
pub fn apply_keypackage_claim(state: &mut ProjectionState, op: &Operation) -> ProjectionEffectOut {
    let payload = &op.payload;
    let Some(id) = payload.get("keypackage_id").and_then(Value::as_str) else {
        return reject("mls_keypackage_id_missing");
    };
    let Some(group_id) = payload.get("group_id").and_then(Value::as_str) else {
        return reject("mls_keypackage_group_missing");
    };

    let consumed_at = op.created_at.timestamp();
    let Some(row) = state.mls_key_packages.get_mut(id) else {
        return reject(REASON_KEYPACKAGE_NOT_FOUND);
    };
    // CAS check — refuse if anyone has already claimed this row.
    if row.claimed_by.is_some() {
        return reject(REASON_KEYPACKAGE_ALREADY_CLAIMED);
    }
    // Lifetime check — RFC 9420 §10. Stale KeyPackages can't be claimed.
    if consumed_at >= row.lifetime.not_after {
        return reject(REASON_KEYPACKAGE_EXPIRED);
    }
    row.claimed_by = Some(group_id.to_owned());
    row.consumed_at = Some(consumed_at);

    ProjectionEffectOut::Mls(MlsEffect::KeyPackageClaimed {
        keypackage_id: id.to_owned(),
        group_id: group_id.to_owned(),
        consumed_at,
    })
}

/// G3.S1 — enqueue a Welcome envelope for a recipient device.
///
/// Payload shape:
/// ```json
/// {
///   "welcome_id":             "cx:mls_welcome:<uuid>",
///   "group_id":               "cx:mls_group:<uuid>",
///   "recipient_actor_did":    "did:web:bob.example",
///   "recipient_device_id":    "cx:device:<uuid>",
///   "welcome_bytes_b64":      "<base64url(opaque MLS Welcome)>",
///   "key_package_id":         "cx:mls_keypackage:<uuid>"
/// }
/// ```
///
/// The reducer intentionally stores only the routing tuple and opaque
/// Welcome bytes. Any plaintext sender/profile/relationship metadata in
/// the submitted envelope is rejected before the row is queued, which
/// keeps cross-domain forwarders from learning more than the delivery
/// key they need.
pub fn apply_welcome_enqueue(state: &mut ProjectionState, op: &Operation) -> ProjectionEffectOut {
    let payload = &op.payload;
    if welcome_payload_contains_forbidden_metadata(payload) {
        return reject(REASON_WELCOME_METADATA_LEAK);
    }
    let Some(welcome_id) = payload
        .get("welcome_id")
        .or_else(|| payload.get("welcome_ref"))
        .or_else(|| payload.get("encrypted_welcome_ref"))
        .or_else(|| payload.get("claim_id"))
        .and_then(Value::as_str)
    else {
        return reject("mls_welcome_id_missing");
    };
    let Some(group_id) = payload
        .get("group_id")
        .or_else(|| payload.get("mls_group_id"))
        .and_then(Value::as_str)
    else {
        return reject("mls_welcome_group_missing");
    };
    let Some(recipient_actor_did) = payload
        .get("recipient_actor_did")
        .or_else(|| payload.get("recipient_principal_id"))
        .and_then(Value::as_str)
    else {
        return reject("mls_welcome_recipient_actor_missing");
    };
    let Some(recipient_device_id) = payload.get("recipient_device_id").and_then(Value::as_str)
    else {
        return reject("mls_welcome_recipient_device_missing");
    };
    let Some(key_package_id) = payload
        .get("key_package_id")
        .or_else(|| payload.get("keypackage_ref"))
        .and_then(Value::as_str)
    else {
        return reject("mls_welcome_key_package_id_missing");
    };
    let welcome_bytes = match (
        payload.get("welcome_bytes_b64").and_then(Value::as_str),
        payload.get("ciphertext").and_then(Value::as_str),
    ) {
        (Some(encoded), _) => match decode_base64_loose(encoded) {
            Ok(bytes) if !bytes.is_empty() => bytes,
            Ok(_) => return reject("mls_welcome_bytes_empty"),
            Err(_) => return reject("mls_welcome_bytes_invalid_b64"),
        },
        (None, Some(ciphertext)) if !ciphertext.is_empty() => ciphertext.as_bytes().to_vec(),
        _ => return reject("mls_welcome_bytes_missing"),
    };

    let row = MlsWelcome {
        id: welcome_id.to_owned(),
        group_id: group_id.to_owned(),
        recipient_actor_did: recipient_actor_did.to_owned(),
        recipient_device_id: recipient_device_id.to_owned(),
        welcome_bytes,
        key_package_id: key_package_id.to_owned(),
        enqueued_at: op.created_at.timestamp(),
        delivered_at: None,
    };
    state
        .mls_welcomes
        .entry((
            recipient_actor_did.to_owned(),
            recipient_device_id.to_owned(),
        ))
        .or_default()
        .push(row);

    ProjectionEffectOut::Mls(MlsEffect::WelcomeEnqueued {
        welcome_id: welcome_id.to_owned(),
        recipient_actor_did: recipient_actor_did.to_owned(),
        recipient_device_id: recipient_device_id.to_owned(),
        group_id: group_id.to_owned(),
    })
}

/// G3.S1 — initialize a new MLS group at epoch 0.
///
/// The canonical payload is `mls_genesis_payload` from the spec
/// registry. The reducer stores the epoch and covered-frontier summary
/// only; opaque GroupInfo / ratchet tree material remains in the
/// durable event payload and object store references.
pub fn apply_group_genesis(state: &mut ProjectionState, op: &Operation) -> ProjectionEffectOut {
    let payload = &op.payload;
    let Some(group_id) = payload
        .get("group_id")
        .or_else(|| payload.get("mls_group_id"))
        .and_then(Value::as_str)
    else {
        return reject("mls_genesis_group_missing");
    };
    let epoch = payload.get("epoch").and_then(Value::as_u64).unwrap_or(0);
    if epoch != 0 {
        return reject("mls_genesis_epoch_invalid");
    }
    let Some(creator_actor_did) = payload
        .get("creator_actor_did")
        .or_else(|| payload.get("creator_principal_id"))
        .and_then(Value::as_str)
    else {
        return reject("mls_genesis_creator_missing");
    };
    if payload
        .get("governance_binding")
        .or_else(|| payload.get("mls_governance_binding"))
        .is_none()
    {
        return reject("mls_genesis_governance_binding_missing");
    }
    if state.mls_commit_epochs.contains_key(group_id) {
        return reject(REASON_GENESIS_ALREADY_EXISTS);
    }
    let covered_frontier = extract_covered_frontier(payload).unwrap_or_default();
    state.mls_commit_epochs.insert(
        group_id.to_owned(),
        MlsCommitEpoch {
            group_id: group_id.to_owned(),
            epoch: 0,
            leader_actor_did: creator_actor_did.to_owned(),
            covered_frontier: covered_frontier.clone(),
            committed_at: op.created_at.timestamp(),
        },
    );

    ProjectionEffectOut::Mls(MlsEffect::GroupGenesis {
        group_id: group_id.to_owned(),
        epoch: 0,
        creator_actor_did: creator_actor_did.to_owned(),
        covered_frontier,
    })
}

/// G3.S1 — bump an MLS group's commit epoch.
///
/// Payload shape:
/// ```json
/// {
///   "group_id":            "cx:mls_group:<uuid>",
///   "expected_prev_epoch": <u64>,
///   "leader_actor_did":    "did:web:alice.example",
///   "commit_bytes_b64":    "<base64url(opaque MLS Commit)>"
/// }
/// ```
///
/// The reducer accepts a commit IFF
/// `payload.expected_prev_epoch == current_stored_epoch` (defaulting to
/// `0` for a never-seen group). On success the stored epoch is set to
/// `expected_prev_epoch + 1`. Stale or out-of-order commits leave state
/// untouched and emit `ProjectionEffect::Rejected { reason:
/// "mls_epoch_skew" }`.
///
pub fn apply_commit_epoch(state: &mut ProjectionState, op: &Operation) -> ProjectionEffectOut {
    let payload = &op.payload;
    let Some(group_id) = payload
        .get("group_id")
        .or_else(|| payload.get("mls_group_id"))
        .and_then(Value::as_str)
    else {
        return reject("mls_commit_group_missing");
    };
    let expected_prev_epoch = match payload
        .get("expected_prev_epoch")
        .or_else(|| payload.get("base_epoch"))
        .and_then(Value::as_u64)
    {
        Some(v) => v,
        None => return reject("mls_commit_expected_prev_epoch_missing"),
    };
    let Some(leader_actor_did) = payload.get("leader_actor_did").and_then(Value::as_str) else {
        return reject("mls_commit_leader_missing");
    };
    // Body bytes are not validated at the reducer level beyond a
    // presence check; the routing layer logs the digest for audit.
    if !payload
        .get("commit_bytes_b64")
        .or_else(|| payload.get("commit_message_ref"))
        .or_else(|| payload.get("commit_digest"))
        .and_then(Value::as_str)
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        return reject("mls_commit_bytes_missing");
    }
    if let Err(reason) = crate::kinds::validate_mls_governance_binding(payload) {
        return reject(reason);
    }
    let covered_delta = match extract_covered_frontier(payload) {
        Some(frontier) => frontier,
        None => return reject(REASON_COMMIT_COVERED_FRONTIER_MISSING),
    };

    let current = state
        .mls_commit_epochs
        .get(group_id)
        .map(|e| e.epoch)
        .unwrap_or(0);
    if expected_prev_epoch != current {
        return reject(REASON_COMMIT_EPOCH_SKEW);
    }
    let new_epoch = current.saturating_add(1);
    let committed_at = op.created_at.timestamp();
    let mut covered_frontier = state
        .mls_commit_epochs
        .get(group_id)
        .map(|e| e.covered_frontier.clone())
        .unwrap_or_default();
    merge_frontier(&mut covered_frontier, &covered_delta);
    state.mls_commit_epochs.insert(
        group_id.to_owned(),
        MlsCommitEpoch {
            group_id: group_id.to_owned(),
            epoch: new_epoch,
            leader_actor_did: leader_actor_did.to_owned(),
            covered_frontier: covered_frontier.clone(),
            committed_at,
        },
    );

    ProjectionEffectOut::Mls(MlsEffect::CommitEpochAdvanced {
        group_id: group_id.to_owned(),
        previous_epoch: current,
        new_epoch,
        leader_actor_did: leader_actor_did.to_owned(),
        covered_frontier,
    })
}

// ── private helpers ───────────────────────────────────────────────────

/// Local type alias so the four `apply_*` helpers return a `ProjectionEffect`
/// without each call site importing the parent `super::` path. Concrete
/// type is the same `ProjectionEffect` defined in `reducer.rs`.
type ProjectionEffectOut = super::ProjectionEffect;

fn reject(reason: &str) -> ProjectionEffectOut {
    ProjectionEffectOut::Rejected {
        reason: reason.to_owned(),
    }
}

fn parse_lifetime(v: Option<&Value>) -> Result<KeyPackageLifetime, &'static str> {
    let obj = v.ok_or("mls_keypackage_lifetime_missing")?;
    let not_before = obj
        .get("not_before")
        .and_then(Value::as_i64)
        .ok_or("mls_keypackage_lifetime_not_before_invalid")?;
    let not_after = obj
        .get("not_after")
        .and_then(Value::as_i64)
        .ok_or("mls_keypackage_lifetime_not_after_invalid")?;
    Ok(KeyPackageLifetime {
        not_before,
        not_after,
    })
}

const WELCOME_FORBIDDEN_METADATA_KEYS: &[&str] = &[
    "actor_id",
    "principal_did",
    "principal_id",
    "sender_actor_did",
    "sender_device_id",
    "sender_display_name",
    "sender_handle",
    "sender_profile",
    "device_list",
    "relationship_graph",
    "member_list",
    "members",
    "profile",
    "identity_link",
    "identity_links",
    "delivery_binding",
];

fn welcome_payload_contains_forbidden_metadata(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    object
        .keys()
        .any(|key| WELCOME_FORBIDDEN_METADATA_KEYS.contains(&key.as_str()))
        || object
            .get("metadata")
            .and_then(Value::as_object)
            .is_some_and(metadata_object_contains_forbidden_key)
        || object
            .get("envelope_metadata")
            .and_then(Value::as_object)
            .is_some_and(metadata_object_contains_forbidden_key)
}

fn metadata_object_contains_forbidden_key(object: &Map<String, Value>) -> bool {
    object
        .keys()
        .any(|key| WELCOME_FORBIDDEN_METADATA_KEYS.contains(&key.as_str()))
}

fn extract_covered_frontier(payload: &Value) -> Option<Vec<String>> {
    let binding = payload
        .get("governance_binding")
        .or_else(|| payload.get("mls_governance_binding"))?;

    let mut frontier = Vec::new();
    push_frontier_values(binding.get("membership_frontier"), &mut frontier);
    push_frontier_values(binding.get("covered_frontier"), &mut frontier);
    push_frontier_values(
        binding.get("covered_frontier_cell").and_then(|cell| {
            cell.get("values")
                .or_else(|| cell.get("members"))
                .or_else(|| cell.get("anchors"))
        }),
        &mut frontier,
    );
    push_frontier_values(payload.get("covered_frontier"), &mut frontier);
    frontier.sort();
    frontier.dedup();
    (!frontier.is_empty()).then_some(frontier)
}

fn push_frontier_values(value: Option<&Value>, out: &mut Vec<String>) {
    match value {
        Some(Value::String(value)) if !value.trim().is_empty() => {
            out.push(value.to_owned());
        }
        Some(Value::Array(values)) => {
            for value in values {
                if let Some(value) = value.as_str().filter(|value| !value.trim().is_empty()) {
                    out.push(value.to_owned());
                }
            }
        }
        _ => {}
    }
}

fn merge_frontier(existing: &mut Vec<String>, delta: &[String]) {
    existing.extend(delta.iter().cloned());
    existing.sort();
    existing.dedup();
}

/// Best-effort base64url-loose decode. Accepts both `URL_SAFE_NO_PAD`
/// (canonical) and the padded `URL_SAFE` form so dev fixtures don't
/// have to be strict about padding.
fn decode_base64_loose(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    let engine_nopad = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let engine_pad = base64::engine::general_purpose::URL_SAFE;
    engine_nopad
        .decode(s.trim_end_matches('='))
        .or_else(|_| engine_pad.decode(s))
}

// ──────────────────────────── tests ───────────────────────────────────

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::{TimeZone, Utc};
    use contrix_sdk::{Operation, OperationId, RealmId};
    use serde_json::json;

    use super::*;
    use crate::reducer::{MlsEffect, ProjectionEffect, ProjectionState};

    fn op_at(secs: i64, object_type: &str, payload: serde_json::Value) -> Operation {
        let mut op = Operation::create(
            OperationId::new("cx:operation:0196419b-0000-7000-8000-000000000001")
                .expect("op id parses"),
            RealmId::new("cx:realm:0196419b-0000-7000-8000-000000000000").expect("realm id parses"),
            object_type,
            payload,
        );
        op.created_at = Utc.timestamp_opt(secs, 0).single().expect("ts in range");
        op
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn governance_binding(previous_epoch: u64) -> Value {
        json!({
            "previous_epoch": previous_epoch,
            "next_epoch": previous_epoch + 1,
            "membership_frontier": [
                format!("cx:event:frontier-{previous_epoch}")
            ],
            "threshold": {
                "k": 2,
                "n": 3,
                "signers": [
                    "did:web:alice.example",
                    "did:web:bob.example",
                    "did:web:carol.example"
                ]
            },
            "signatures": [
                {"signer_did": "did:web:alice.example", "signature_b64": "alice-partial"},
                {"signer_did": "did:web:bob.example", "signature_b64": "bob-partial"}
            ]
        })
    }

    fn publish_payload(id: &str, actor: &str, device: &str, not_after: i64) -> serde_json::Value {
        json!({
            "action": "publish",
            "keypackage_id": id,
            "actor_did": actor,
            "device_id": device,
            "lifetime": {"not_before": 1, "not_after": not_after},
            "key_package_bytes_b64": b64(b"opaque-keypackage-bytes"),
        })
    }

    #[test]
    fn keypackage_publish_then_claim_succeeds() {
        let mut state = ProjectionState::default();
        let publish = op_at(
            100,
            "cx.mls.keypackage",
            publish_payload(
                "cx:mls_keypackage:01",
                "did:web:alice.example",
                "cx:device:alice-desktop",
                1_000_000,
            ),
        );
        let effect = apply_keypackage_publish(&mut state, &publish);
        assert!(matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::KeyPackagePublished { ref keypackage_id, .. })
                if keypackage_id == "cx:mls_keypackage:01"
        ));
        assert!(
            state
                .mls_key_packages
                .get("cx:mls_keypackage:01")
                .unwrap()
                .claimed_by
                .is_none()
        );

        let claim = op_at(
            200,
            "cx.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "cx:mls_keypackage:01",
                "group_id": "cx:mls_group:abc"
            }),
        );
        let claim_effect = apply_keypackage_claim(&mut state, &claim);
        match claim_effect {
            ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
                keypackage_id,
                group_id,
                consumed_at,
            }) => {
                assert_eq!(keypackage_id, "cx:mls_keypackage:01");
                assert_eq!(group_id, "cx:mls_group:abc");
                assert_eq!(consumed_at, 200);
            }
            other => panic!("expected KeyPackageClaimed, got {other:?}"),
        }
        let row = state.mls_key_packages.get("cx:mls_keypackage:01").unwrap();
        assert_eq!(row.claimed_by.as_deref(), Some("cx:mls_group:abc"));
        assert_eq!(row.consumed_at, Some(200));
    }

    #[test]
    fn keypackage_claim_twice_second_fails() {
        let mut state = ProjectionState::default();
        let publish = op_at(
            100,
            "cx.mls.keypackage",
            publish_payload(
                "cx:mls_keypackage:02",
                "did:web:alice.example",
                "cx:device:alice-desktop",
                1_000_000,
            ),
        );
        let _ = apply_keypackage_publish(&mut state, &publish);

        // First claim — wins.
        let claim1 = op_at(
            200,
            "cx.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "cx:mls_keypackage:02",
                "group_id": "cx:mls_group:first"
            }),
        );
        let e1 = apply_keypackage_claim(&mut state, &claim1);
        assert!(matches!(
            e1,
            ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed { .. })
        ));

        // Second claim — must be rejected by the CAS.
        let claim2 = op_at(
            201,
            "cx.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "cx:mls_keypackage:02",
                "group_id": "cx:mls_group:second"
            }),
        );
        let e2 = apply_keypackage_claim(&mut state, &claim2);
        match e2 {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, REASON_KEYPACKAGE_ALREADY_CLAIMED);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        // First claim's group must still own the row — losers don't overwrite.
        let row = state.mls_key_packages.get("cx:mls_keypackage:02").unwrap();
        assert_eq!(row.claimed_by.as_deref(), Some("cx:mls_group:first"));
        assert_eq!(row.consumed_at, Some(200));
    }

    #[test]
    fn welcome_enqueue_then_fetch_marks_delivered() {
        let mut state = ProjectionState::default();
        let enqueue = op_at(
            300,
            "cx.mls.welcome",
            json!({
                "welcome_id": "cx:mls_welcome:w1",
                "group_id": "cx:mls_group:abc",
                "recipient_actor_did": "did:web:bob.example",
                "recipient_device_id": "cx:device:bob-phone",
                "welcome_bytes_b64": b64(b"opaque-welcome-bytes"),
                "key_package_id": "cx:mls_keypackage:01",
            }),
        );
        let effect = apply_welcome_enqueue(&mut state, &enqueue);
        assert!(matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
        ));

        let key = (
            "did:web:bob.example".to_owned(),
            "cx:device:bob-phone".to_owned(),
        );
        let queue = state.mls_welcomes.get(&key).unwrap();
        assert_eq!(queue.len(), 1);
        assert!(queue[0].delivered_at.is_none());

        // Simulate the route draining the queue: mark all undelivered rows.
        let now = 400_i64;
        let drained: Vec<MlsWelcome> = state
            .mls_welcomes
            .get_mut(&key)
            .unwrap()
            .iter_mut()
            .map(|row| {
                if row.delivered_at.is_none() {
                    row.delivered_at = Some(now);
                }
                row.clone()
            })
            .collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].delivered_at, Some(400));

        // A re-poll would skip these — already marked delivered.
        let still_pending: Vec<_> = state
            .mls_welcomes
            .get(&key)
            .unwrap()
            .iter()
            .filter(|r| r.delivered_at.is_none())
            .collect();
        assert!(still_pending.is_empty());
    }

    #[test]
    fn welcome_enqueue_rejects_plaintext_identity_metadata() {
        let mut state = ProjectionState::default();
        let enqueue = op_at(
            300,
            "cx.mls.welcome",
            json!({
                "welcome_id": "cx:mls_welcome:w-leaky",
                "group_id": "cx:mls_group:abc",
                "recipient_actor_did": "did:web:bob.example",
                "recipient_device_id": "cx:device:bob-phone",
                "welcome_bytes_b64": b64(b"opaque-welcome-bytes"),
                "key_package_id": "cx:mls_keypackage:01",
                "metadata": {
                    "sender_handle": "@alice",
                    "routing_hint": "ok"
                }
            }),
        );
        let effect = apply_welcome_enqueue(&mut state, &enqueue);
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { reason } if reason == REASON_WELCOME_METADATA_LEAK
        ));
        assert!(state.mls_welcomes.is_empty());
    }

    #[test]
    fn commit_epoch_in_order_succeeds() {
        let mut state = ProjectionState::default();
        // First commit on a brand-new group — expected_prev_epoch=0 → epoch=1.
        let c1 = op_at(
            500,
            "cx.mls.commit",
            json!({
                "group_id": "cx:mls_group:abc",
                "expected_prev_epoch": 0,
                "leader_actor_did": "did:web:alice.example",
                "commit_bytes_b64": b64(b"opaque-commit-1"),
                "governance_binding": governance_binding(0),
            }),
        );
        let e1 = apply_commit_epoch(&mut state, &c1);
        match e1 {
            ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced {
                previous_epoch,
                new_epoch,
                ref covered_frontier,
                ..
            }) => {
                assert_eq!(previous_epoch, 0);
                assert_eq!(new_epoch, 1);
                assert_eq!(covered_frontier, &vec!["cx:event:frontier-0".to_owned()]);
            }
            other => panic!("expected CommitEpochAdvanced, got {other:?}"),
        }

        // Second commit — expected_prev_epoch=1 → epoch=2.
        let c2 = op_at(
            501,
            "cx.mls.commit",
            json!({
                "group_id": "cx:mls_group:abc",
                "expected_prev_epoch": 1,
                "leader_actor_did": "did:web:alice.example",
                "commit_bytes_b64": b64(b"opaque-commit-2"),
                "governance_binding": governance_binding(1),
            }),
        );
        let e2 = apply_commit_epoch(&mut state, &c2);
        assert!(matches!(
            e2,
            ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 2, .. })
        ));
        assert_eq!(
            state.mls_commit_epochs.get("cx:mls_group:abc").unwrap(),
            &MlsCommitEpoch {
                group_id: "cx:mls_group:abc".to_owned(),
                epoch: 2,
                leader_actor_did: "did:web:alice.example".to_owned(),
                covered_frontier: vec![
                    "cx:event:frontier-0".to_owned(),
                    "cx:event:frontier-1".to_owned()
                ],
                committed_at: 501,
            }
        );
    }

    #[test]
    fn commit_epoch_requires_covered_frontier() {
        let mut state = ProjectionState::default();
        let effect = apply_commit_epoch(
            &mut state,
            &op_at(
                500,
                "cx.mls.commit",
                json!({
                    "group_id": "cx:mls_group:abc",
                    "expected_prev_epoch": 0,
                    "leader_actor_did": "did:web:alice.example",
                    "commit_bytes_b64": b64(b"opaque-commit-1"),
                    "governance_binding": {
                        "previous_epoch": 0,
                        "next_epoch": 1,
                        "threshold": {
                            "k": 1,
                            "n": 1,
                            "signers": ["did:web:alice.example"]
                        },
                        "signatures": [
                            {"signer_did": "did:web:alice.example", "signature_b64": "alice-partial"}
                        ]
                    },
                }),
            ),
        );
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { reason } if reason == REASON_COMMIT_COVERED_FRONTIER_MISSING
        ));
        assert!(state.mls_commit_epochs.is_empty());
    }

    #[test]
    fn commit_epoch_stale_rejected() {
        let mut state = ProjectionState::default();
        // Land epoch 1 first.
        let _ = apply_commit_epoch(
            &mut state,
            &op_at(
                600,
                "cx.mls.commit",
                json!({
                    "group_id": "cx:mls_group:abc",
                    "expected_prev_epoch": 0,
                    "leader_actor_did": "did:web:alice.example",
                    "commit_bytes_b64": b64(b"first"),
                    "governance_binding": governance_binding(0),
                }),
            ),
        );

        // Replay the same commit (expected_prev_epoch=0) — must be rejected.
        let replay = apply_commit_epoch(
            &mut state,
            &op_at(
                601,
                "cx.mls.commit",
                json!({
                    "group_id": "cx:mls_group:abc",
                    "expected_prev_epoch": 0,
                    "leader_actor_did": "did:web:alice.example",
                    "commit_bytes_b64": b64(b"replay"),
                    "governance_binding": governance_binding(0),
                }),
            ),
        );
        match replay {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, REASON_COMMIT_EPOCH_SKEW);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        // Stored epoch must still be 1 — the rejected replay didn't clobber it.
        assert_eq!(
            state
                .mls_commit_epochs
                .get("cx:mls_group:abc")
                .unwrap()
                .epoch,
            1
        );

        // A future-epoch commit (expected_prev_epoch=5) is also rejected.
        let leap = apply_commit_epoch(
            &mut state,
            &op_at(
                602,
                "cx.mls.commit",
                json!({
                    "group_id": "cx:mls_group:abc",
                    "expected_prev_epoch": 5,
                    "leader_actor_did": "did:web:alice.example",
                    "commit_bytes_b64": b64(b"leap"),
                    "governance_binding": governance_binding(5),
                }),
            ),
        );
        assert!(
            matches!(leap, ProjectionEffect::Rejected { reason } if reason == REASON_COMMIT_EPOCH_SKEW)
        );
        assert_eq!(
            state
                .mls_commit_epochs
                .get("cx:mls_group:abc")
                .unwrap()
                .epoch,
            1
        );
    }
}
