//! G3.S1 — MLS / E2EE lifecycle reducer helpers.
//!
//! Implements the scoped subset of the MLS event family:
//!
//! 1. **KeyPackage atomic claim** — `apply_keypackage_publish` / `apply_keypackage_claim`. The
//!    claim path is a compare-and-swap on the `claimed_by` slot so two concurrent Welcomes can't
//!    grab the same KeyPackage; the second claim returns `ProjectionEffect::Rejected { reason:
//!    "mls_keypackage_already_claimed" }` which the routing layer maps to HTTP 409 `cas_conflict`.
//!
//! 2. **Welcome to-device persistence** — `apply_welcome_enqueue`. Each accepted Welcome is
//!    appended to a per-`(recipient_actor_id, recipient_device_id)` queue inside
//!    `ProjectionState::mls_welcomes`. The recipient device drains its queue via the `GET
//!    /_soland/self/keys/keypackages/welcomes/pending` route, which marks delivered rows with
//!    `delivered_at = now()` so subsequent polls don't redeliver.
//!
//! 3. **group genesis** — `apply_group_genesis`. Installs epoch 0 for a new MLS group and
//!    initializes its covered_seals accumulator.
//!
//! 4. **commit_epoch increment** — `apply_commit_epoch`. The reducer only accepts a commit whose
//!    `expected_prev_epoch` matches the group's current stored epoch (0 for a brand-new group).
//!    Stale / out-of-order commits are rejected with `mls_epoch_skew`. Accepted commits merge the
//!    attested governance Seal set into the group's covered_seals accumulator.
//!
//! Deferred (TODO(G3.S1-followup) markers below + in `routing/mls.rs`):
//!   - decryption_pending (deferred-decryption queue + retry)

use cokret_sdk::Operation;
use serde_json::{Map, Value};

use super::{
    KeyPackageLifetime, MlsCommitEpoch, MlsCommitEpochKey, MlsEffect, MlsKeyPackage, MlsWelcome,
    MlsWelcomeQueueKey, ProjectionState,
};

/// Reason code emitted when a `ck.mls.keypackage` event with
/// `payload.action == "claim"` targets a KeyPackage that has already
/// been claimed. Routing layer maps to HTTP 409 `cas_conflict`.
pub const REASON_KEYPACKAGE_ALREADY_CLAIMED: &str = "mls_keypackage_already_claimed";
/// Reason code emitted when a `ck.mls.keypackage` event with
/// `payload.action == "claim"` targets an unknown KeyPackage id.
pub const REASON_KEYPACKAGE_NOT_FOUND: &str = "mls_keypackage_not_found";
/// Reason code emitted when a published KeyPackage's lifetime window
/// is already past `not_after`. Mirrors RFC 9420 §10.
pub const REASON_KEYPACKAGE_EXPIRED: &str = "mls_keypackage_expired";
/// Reason code emitted when a KeyPackage publish/claim is missing the
/// accepted cross-signing generation or attempts to consume an older one.
pub const REASON_KEYPACKAGE_CLAIM_GENERATION_MISMATCH: &str = "claim_generation_mismatch";
pub const REASON_KEYPACKAGE_REALM_MISMATCH: &str = "mls_keypackage_realm_mismatch";
/// Reason code emitted when a commit's `expected_prev_epoch` does not
/// match the group's stored epoch (out-of-order / stale / replay).
pub const REASON_COMMIT_EPOCH_SKEW: &str = "mls_epoch_skew";
/// Reject code for Welcome payloads that try to carry plaintext sender,
/// profile, relationship, or device metadata outside the opaque MLS bytes.
pub const REASON_WELCOME_METADATA_LEAK: &str = "mls_welcome_metadata_leak";
/// Reject code for MLS Welcome payloads whose KeyPackage claim transcript
/// is missing or does not bind the Welcome bytes to the recipient realm.
pub const REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH: &str =
    cokret_sdk::error::REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH;
/// Reject code for commits whose governance binding does not name an
/// attested governance Seal set to add into the covered_seals accumulator.
pub const REASON_COMMIT_COVERED_SEALS_MISSING: &str = "mls_covered_seals_missing";
/// Reject code for a second genesis against an already initialized group.
pub const REASON_GENESIS_ALREADY_EXISTS: &str = "mls_genesis_already_exists";
/// Reject code for a commit whose `governance_binding.policy_root` does not
/// match the policy root the MLS group's epoch chain was genesis-locked to
/// (encryption-and-audit.md §2.5.1). On a federation push the ingest pipeline
/// maps it to a 412 whole-batch reject.
pub const REASON_GOVERNANCE_BINDING_MISMATCH: &str =
    cokret_sdk::error::REASON_MLS_GOVERNANCE_BINDING_MISMATCH;
/// Reject code emitted while a group's `covered_frontier_cell` is `⊥`
/// (concurrent commits, encryption-and-audit.md §2.5.2). Sends / decrypts on
/// the contested epoch stay fail-closed until a resolving commit advances it.
pub const REASON_DECRYPTION_PENDING: &str = cokret_sdk::error::REASON_MLS_DECRYPTION_PENDING;

/// G3.S1 — project a `ck.mls.keypackage` event with
/// `payload.action == "publish"`.
///
/// Payload shape (validated below):
/// ```json
/// {
///   "keypackage_id": "ck:mls_keypackage:<uuid>",
///   "actor_id": "did:web:alice.example",
///   "device_id": "ck:device:<uuid>",
///   "lifetime": { "not_before": <unix_secs>, "not_after": <unix_secs> },
///   "key_package_bytes_b64": "<base64url(opaque MLS KeyPackage)>"
/// }
/// ```
pub fn apply_keypackage_publish(
    state: &mut ProjectionState,
    op: &Operation,
) -> ProjectionEffectOut {
    let payload = &op.payload;
    let Some(id) = payload
        .get("keypackage_id")
        .or_else(|| payload.get("keypackage_ref"))
        .and_then(Value::as_str)
    else {
        return reject("mls_keypackage_id_missing");
    };
    let Some(actor_id) = payload
        .get("actor_id")
        .or_else(|| payload.get("principal_id"))
        .and_then(Value::as_str)
    else {
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
    let keypackage_ref = payload
        .get("keypackage_ref")
        .and_then(Value::as_str)
        .unwrap_or(id)
        .to_owned();
    let computed_keypackage_digest = cokret_sdk::canonical::sha256_digest(&key_package_bytes);
    let keypackage_digest = payload
        .get("keypackage_digest")
        .and_then(Value::as_str)
        .unwrap_or(computed_keypackage_digest.as_str())
        .to_owned();
    if keypackage_digest != computed_keypackage_digest {
        return reject("mls_keypackage_digest_mismatch");
    }
    let capabilities = string_array(payload.get("capabilities"));
    let capabilities_digest = match cokret_sdk::canonical::canonical_json_bytes(&capabilities) {
        Ok(bytes) => cokret_sdk::canonical::sha256_digest(bytes),
        Err(_) => return reject("mls_keypackage_capabilities_digest_failed"),
    };
    if let Some(published_digest) = payload.get("capabilities_digest").and_then(Value::as_str)
        && published_digest != capabilities_digest
    {
        return reject("mls_keypackage_capabilities_digest_mismatch");
    }
    let device_signature = payload
        .get("device_signature")
        .cloned()
        .unwrap_or(Value::Null);
    let last_resort = payload
        .get("last_resort")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let last_resort_realm_id = payload
        .get("last_resort_realm_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let created_at =
        parse_timestamp(payload.get("created_at")).unwrap_or_else(|| op.created_at.timestamp());
    let trust_binding = match keypackage_claim_trust_binding(payload) {
        Ok(binding) => binding,
        Err(reason) => return reject(reason),
    };
    let row = MlsKeyPackage {
        id: id.to_owned(),
        keypackage_ref,
        keypackage_digest,
        actor_id: actor_id.to_owned(),
        device_id: device_id.to_owned(),
        lifetime,
        key_package_bytes,
        capabilities,
        capabilities_digest,
        device_signature,
        last_resort,
        last_resort_realm_id,
        claimed_by: None,
        ssk_generation: trust_binding.ssk_generation,
        device_authorize_event_id: trust_binding.device_authorize_event_id,
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
        actor_id: actor_id.to_owned(),
        device_id: device_id.to_owned(),
    })
}

/// G3.S1 — atomic CAS claim of a published KeyPackage.
///
/// Payload shape:
/// ```json
/// {
///   "keypackage_id": "ck:mls_keypackage:<uuid>",
///   "group_id":      "ck:mls_group:<uuid>"
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
    if !row.last_resort && row.claimed_by.is_some() {
        return reject(REASON_KEYPACKAGE_ALREADY_CLAIMED);
    }
    // Lifetime check — RFC 9420 §10. Stale KeyPackages can't be claimed.
    if consumed_at >= row.lifetime.not_after {
        return reject(REASON_KEYPACKAGE_EXPIRED);
    }
    let trust_binding = match keypackage_claim_trust_binding(payload) {
        Ok(binding) => binding,
        Err(reason) => return reject(reason),
    };
    if row.ssk_generation != trust_binding.ssk_generation
        || row.device_authorize_event_id != trust_binding.device_authorize_event_id
    {
        return reject(REASON_KEYPACKAGE_CLAIM_GENERATION_MISMATCH);
    }
    let intended_realm_id = payload
        .get("intended_realm_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if row.last_resort {
        let Some(realm_id) = intended_realm_id.as_deref() else {
            return reject(REASON_KEYPACKAGE_REALM_MISMATCH);
        };
        if row
            .last_resort_realm_id
            .as_deref()
            .is_some_and(|bound_realm_id| bound_realm_id != realm_id)
        {
            return reject(REASON_KEYPACKAGE_REALM_MISMATCH);
        }
        if row.last_resort_realm_id.is_none() {
            row.last_resort_realm_id = Some(realm_id.to_owned());
        }
    } else {
        row.claimed_by = Some(group_id.to_owned());
        row.consumed_at = Some(consumed_at);
    }

    ProjectionEffectOut::Mls(MlsEffect::KeyPackageClaimed {
        keypackage_id: id.to_owned(),
        group_id: group_id.to_owned(),
        intended_realm_id,
        last_resort: row.last_resort,
        consumed_at,
    })
}

/// G3.S1 — enqueue a Welcome envelope for a recipient device.
///
/// Payload shape:
/// ```json
/// {
///   "welcome_id":             "ck:mls_welcome:<uuid>",
///   "group_id":               "ck:mls_group:<uuid>",
///   "recipient_actor_id":     "did:web:bob.example",
///   "recipient_device_id":    "ck:device:<uuid>",
///   "ciphertext":             "<base64url(opaque MLS Welcome)>",
///   "key_package_id":         "ck:mls_keypackage:<uuid>"
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
    let Some(recipient_actor_id) = payload
        .get("recipient_actor_id")
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
        (None, Some(ciphertext)) if !ciphertext.is_empty() => match decode_base64_loose(ciphertext)
        {
            Ok(bytes) if !bytes.is_empty() => bytes,
            _ => ciphertext.as_bytes().to_vec(),
        },
        _ => return reject("mls_welcome_bytes_missing"),
    };
    if let Err(reason) = validate_welcome_trust_binding(
        op,
        group_id,
        recipient_actor_id,
        key_package_id,
        &welcome_bytes,
        payload,
    ) {
        return reject(reason);
    }

    let row = MlsWelcome {
        id: welcome_id.to_owned(),
        group_id: group_id.to_owned(),
        recipient_actor_id: recipient_actor_id.to_owned(),
        recipient_device_id: recipient_device_id.to_owned(),
        welcome_bytes,
        key_package_id: key_package_id.to_owned(),
        enqueued_at: op.created_at.timestamp(),
        delivered_at: None,
    };
    state
        .mls_welcomes
        .entry(MlsWelcomeQueueKey::new(
            recipient_actor_id,
            recipient_device_id,
        ))
        .or_default()
        .push(row);

    ProjectionEffectOut::Mls(MlsEffect::WelcomeEnqueued {
        welcome_id: welcome_id.to_owned(),
        recipient_actor_id: recipient_actor_id.to_owned(),
        recipient_device_id: recipient_device_id.to_owned(),
        group_id: group_id.to_owned(),
    })
}

/// G3.S1 — initialize a new MLS group at epoch 0.
///
/// The canonical payload is `mls_genesis_payload` from the spec
/// registry. The reducer stores the epoch and covered_seals summary
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
    let Some(creator_actor_id) = payload
        .get("creator_actor_id")
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
    let effective_scope = match genesis_effective_scope(payload) {
        Ok(scope) => scope,
        Err(reason) => return reject(reason),
    };
    if let Err(reason) = validate_genesis_governance_binding(payload, group_id, &effective_scope) {
        return reject(reason);
    }
    let epoch_key = match mls_epoch_key(&effective_scope, group_id) {
        Ok(key) => key,
        Err(reason) => return reject(reason),
    };
    if state.mls_commit_epochs.contains_key(&epoch_key) {
        return reject(REASON_GENESIS_ALREADY_EXISTS);
    }
    let covered_seals = extract_covered_seals(payload).unwrap_or_default();
    let policy_root = binding_policy_root(payload).unwrap_or_default();
    state.mls_commit_epochs.insert(
        epoch_key,
        MlsCommitEpoch {
            group_id: group_id.to_owned(),
            effective_scope: effective_scope.clone(),
            epoch: 0,
            leader_actor_id: creator_actor_id.to_owned(),
            covered_seals: covered_seals.clone(),
            committed_at: op.created_at.timestamp(),
            policy_root,
            accepted_commit_digest: None,
            accepted_from_epoch: None,
            frontier_contested: false,
        },
    );

    ProjectionEffectOut::Mls(MlsEffect::GroupGenesis {
        group_id: group_id.to_owned(),
        effective_scope,
        epoch: 0,
        creator_actor_id: creator_actor_id.to_owned(),
        covered_seals,
    })
}

/// G3.S1 — bump an MLS group's commit epoch.
///
/// Payload shape:
/// ```json
/// {
///   "group_id":            "ck:mls_group:<uuid>",
///   "expected_prev_epoch": <u64>,
///   "leader_actor_id":     "did:web:alice.example",
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
    let Some(leader_actor_id) = payload
        .get("leader_actor_id")
        .or_else(|| payload.get("sender"))
        .and_then(Value::as_str)
    else {
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
    let effective_scope = match commit_effective_scope(payload) {
        Ok(scope) => scope,
        Err(reason) => return reject(reason),
    };
    let epoch_key = match mls_epoch_key(&effective_scope, group_id) {
        Ok(key) => key,
        Err(reason) => return reject(reason),
    };
    let covered_delta = match extract_covered_seals(payload) {
        Some(frontier) => frontier,
        None => return reject(REASON_COMMIT_COVERED_SEALS_MISSING),
    };
    let commit_digest = match commit_digest_value(payload) {
        Some(digest) => digest,
        None => return reject("mls_commit_bytes_missing"),
    };

    let Some(existing) = state.mls_commit_epochs.get(&epoch_key) else {
        return reject("mls_genesis_missing");
    };
    let current = existing.epoch;
    let locked_policy_root = existing.policy_root.clone();
    let accepted_digest = existing.accepted_commit_digest.clone();
    let accepted_from_epoch = existing.accepted_from_epoch;
    let prior_contested = existing.frontier_contested;
    let mut covered_seals = existing.covered_seals.clone();

    // §2.5.1 — the commit binding MUST stay bound to the policy_root the
    // group's epoch chain was genesis-locked to. A forged / stale binding is
    // rejected with `governance_binding_mismatch` (and, on a federation push,
    // bubbles up as the whole-batch reject the ingest pipeline maps to 412).
    if !locked_policy_root.is_empty() {
        let commit_policy_root = binding_policy_root(payload).unwrap_or_default();
        if commit_policy_root != locked_policy_root {
            return reject(REASON_GOVERNANCE_BINDING_MISMATCH);
        }
    }

    // §2.5.2 — concurrent commit detection. Two commits attesting the *same*
    // base epoch with *different* commit material drive `covered_frontier_cell`
    // to `⊥`. Because the reducer applies commits sequentially, the first
    // already advanced the epoch and recorded `(accepted_from_epoch,
    // accepted_commit_digest)`; the racing second still attests
    // `accepted_from_epoch` but carries a different digest. A genuine race is
    // distinguished from a plain stale replay (which stays `mls_epoch_skew`) by
    // the committer explicitly attesting the same base via `base_epoch_ref` of
    // the accepted commit — i.e. the payload declares it forked from the live
    // frontier, not from a long-superseded epoch. The fork is signalled by
    // `concurrent_commit == true`; without it a non-matching base is skew.
    let declares_concurrent = payload
        .get("concurrent_commit")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let is_contention = declares_concurrent
        && accepted_from_epoch == Some(expected_prev_epoch)
        && accepted_digest
            .as_deref()
            .is_some_and(|digest| digest != commit_digest);
    if is_contention {
        if prior_contested {
            // The frontier is already `⊥` and another racing commit attests the
            // contested base: stay fail-closed with the wire-visible
            // `decryption_pending` reject until a resolving commit advances the
            // epoch. (A reject never reaches persistence, so it does not need a
            // mirror.)
            return reject(REASON_DECRYPTION_PENDING);
        }
        // First racing commit at this base: drive `covered_frontier_cell` to
        // `⊥`. The accepted `CommitFrontierContested` effect flips the marker on
        // the real projection and is mirrored durably onto the epoch row; the
        // epoch itself is left untouched.
        if let Some(entry) = state.mls_commit_epochs.get_mut(&epoch_key) {
            entry.frontier_contested = true;
        }
        return ProjectionEffectOut::Mls(MlsEffect::CommitFrontierContested {
            group_id: group_id.to_owned(),
            effective_scope,
            epoch: current,
        });
    }

    if expected_prev_epoch != current {
        return reject(REASON_COMMIT_EPOCH_SKEW);
    }

    // Reaching here with `expected_prev_epoch == current` is a forward advance.
    // When the frontier was `⊥`, this is the resolving commit: the insert below
    // both bumps the epoch and resets `frontier_contested = false`.

    let new_epoch = current.saturating_add(1);
    let committed_at = op.created_at.timestamp();
    merge_frontier(&mut covered_seals, &covered_delta);
    state.mls_commit_epochs.insert(
        epoch_key,
        MlsCommitEpoch {
            group_id: group_id.to_owned(),
            effective_scope: effective_scope.clone(),
            epoch: new_epoch,
            leader_actor_id: leader_actor_id.to_owned(),
            covered_seals: covered_seals.clone(),
            committed_at,
            policy_root: locked_policy_root,
            accepted_commit_digest: Some(commit_digest),
            accepted_from_epoch: Some(expected_prev_epoch),
            frontier_contested: false,
        },
    );

    ProjectionEffectOut::Mls(MlsEffect::CommitEpochAdvanced {
        group_id: group_id.to_owned(),
        effective_scope,
        previous_epoch: current,
        new_epoch,
        leader_actor_id: leader_actor_id.to_owned(),
        covered_seals,
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

fn mls_epoch_key(
    effective_scope: &Value,
    group_id: &str,
) -> Result<MlsCommitEpochKey, &'static str> {
    validate_effective_scope(effective_scope)?;
    Ok(MlsCommitEpochKey::new(
        effective_scope_key(effective_scope)?,
        group_id,
    ))
}

pub(crate) fn effective_scope_key(scope: &Value) -> Result<String, &'static str> {
    let object = scope.as_object().ok_or("mls_effective_scope_invalid")?;
    let realm_id = object
        .get("realm_id")
        .and_then(Value::as_str)
        .ok_or("mls_effective_scope_invalid")?;
    match object.get("kind").and_then(Value::as_str) {
        Some("realm") => Ok(format!("realm\0{realm_id}")),
        Some("circle") => {
            let circle_id = object
                .get("circle_id")
                .and_then(Value::as_str)
                .ok_or("mls_effective_scope_invalid")?;
            Ok(format!("circle\0{realm_id}\0{circle_id}"))
        }
        _ => Err("mls_effective_scope_invalid"),
    }
}

fn genesis_effective_scope(payload: &Value) -> Result<Value, &'static str> {
    let scope = payload
        .get("effective_scope")
        .ok_or("mls_genesis_effective_scope_missing")?;
    validate_effective_scope(scope)?;
    let binding_scope = payload
        .get("governance_binding")
        .or_else(|| payload.get("mls_governance_binding"))
        .and_then(|binding| binding.get("effective_scope"))
        .ok_or("mls_governance_binding_scope_missing")?;
    validate_effective_scope(binding_scope)?;
    if scope != binding_scope {
        return Err("mls_governance_binding_scope_mismatch");
    }
    Ok(scope.clone())
}

fn validate_genesis_governance_binding(
    payload: &Value,
    group_id: &str,
    effective_scope: &Value,
) -> Result<(), &'static str> {
    let binding = payload
        .get("governance_binding")
        .or_else(|| payload.get("mls_governance_binding"))
        .ok_or("mls_genesis_governance_binding_missing")?;
    if binding.get("binding_version").and_then(Value::as_u64) != Some(1) {
        return Err("mls_governance_binding_version_invalid");
    }
    if binding.get("encoding_profile").and_then(Value::as_str)
        != Some("cbor-deterministic-rfc8949-v1")
    {
        return Err("mls_governance_binding_encoding_profile_invalid");
    }
    validate_binding_profiles(binding)?;
    if binding.get("mls_group_id").and_then(Value::as_str) != Some(group_id) {
        return Err("mls_governance_binding_group_mismatch");
    }
    if binding.get("previous_epoch").and_then(Value::as_u64) != Some(0) {
        return Err("mls_governance_binding_previous_epoch_mismatch");
    }
    if binding.get("next_epoch").and_then(Value::as_u64) != Some(0) {
        return Err("mls_governance_binding_next_epoch_mismatch");
    }
    validate_binding_scope(binding, effective_scope)?;
    validate_binding_frontier_and_policy(binding)
}

fn commit_effective_scope(payload: &Value) -> Result<Value, &'static str> {
    let scope = payload
        .get("governance_binding")
        .or_else(|| payload.get("mls_governance_binding"))
        .and_then(|binding| binding.get("effective_scope"))
        .ok_or("mls_governance_binding_scope_missing")?;
    validate_effective_scope(scope)?;
    Ok(scope.clone())
}

fn validate_binding_scope(binding: &Value, effective_scope: &Value) -> Result<(), &'static str> {
    let Some(realm_id) = binding.get("realm_id").and_then(Value::as_str) else {
        return Err("mls_governance_binding_realm_missing");
    };
    let Some(scope) = effective_scope.as_object() else {
        return Err("mls_governance_binding_scope_missing");
    };
    if scope.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return Err("mls_governance_binding_scope_mismatch");
    }
    match scope.get("kind").and_then(Value::as_str) {
        Some("realm") => {
            if binding.get("circle_id").is_some() {
                return Err("mls_governance_binding_scope_mismatch");
            }
        }
        Some("circle") => {
            let Some(circle_id) = scope.get("circle_id").and_then(Value::as_str) else {
                return Err("mls_governance_binding_scope_mismatch");
            };
            if binding.get("circle_id").and_then(Value::as_str) != Some(circle_id) {
                return Err("mls_governance_binding_scope_mismatch");
            }
        }
        _ => return Err("mls_governance_binding_scope_missing"),
    }
    Ok(())
}

fn validate_binding_frontier_and_policy(binding: &Value) -> Result<(), &'static str> {
    let Some(frontier) = binding.get("membership_frontier").and_then(Value::as_array) else {
        return Err("mls_governance_binding_membership_frontier_missing");
    };
    if frontier.is_empty()
        || frontier
            .iter()
            .any(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err("mls_governance_binding_membership_frontier_missing");
    }
    if binding
        .get("policy_root")
        .and_then(Value::as_str)
        .is_none_or(|value| !value.starts_with("sha256:"))
    {
        return Err("mls_governance_binding_policy_root_missing");
    }
    Ok(())
}

fn validate_binding_profiles(binding: &Value) -> Result<(), &'static str> {
    if binding.get("binding_profile").and_then(Value::as_str)
        != Some(crate::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE)
    {
        return Err("mls_governance_binding_profile_invalid");
    }
    if binding.get("reducer_profile").and_then(Value::as_str)
        != Some(crate::kinds::MLS_REDUCER_PROFILE_V1)
    {
        return Err("mls_governance_binding_reducer_profile_invalid");
    }
    Ok(())
}

fn validate_welcome_trust_binding(
    op: &Operation,
    group_id: &str,
    recipient_actor_id: &str,
    key_package_id: &str,
    welcome_bytes: &[u8],
    payload: &Value,
) -> Result<(), &'static str> {
    let binding = payload
        .get("governance_binding")
        .or_else(|| payload.get("mls_governance_binding"))
        .ok_or("mls_welcome_governance_binding_missing")?;
    let effective_scope = binding
        .get("effective_scope")
        .ok_or("mls_governance_binding_scope_missing")?;
    validate_welcome_governance_binding(binding, group_id, op.realm_id.as_str(), effective_scope)?;

    let claim_id = payload
        .get("claim_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let keypackage_ref = payload
        .get("keypackage_ref")
        .and_then(Value::as_str)
        .unwrap_or(key_package_id);
    if keypackage_ref != key_package_id {
        return Err(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    let keypackage_digest = payload
        .get("keypackage_digest")
        .and_then(Value::as_str)
        .filter(|value| is_sha256_digest(value))
        .ok_or(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let claim_ref = payload
        .get("claim_ref")
        .and_then(Value::as_object)
        .ok_or(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let claim_trust_binding = keypackage_claim_trust_binding_object(claim_ref)
        .map_err(|_| REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    if claim_ref.get("claim_id").and_then(Value::as_str) != Some(claim_id)
        || claim_ref.get("keypackage_ref").and_then(Value::as_str) != Some(keypackage_ref)
        || claim_ref.get("keypackage_digest").and_then(Value::as_str) != Some(keypackage_digest)
        || claim_ref
            .get("capabilities_digest")
            .and_then(Value::as_str)
            .is_none_or(|value| !is_sha256_digest(value))
    {
        return Err(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }

    let envelope = payload
        .get("claim_envelope")
        .and_then(Value::as_object)
        .ok_or(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let expected_welcome_digest = cokret_sdk::canonical::sha256_digest(welcome_bytes);
    if envelope.get("claim_id").and_then(Value::as_str) != Some(claim_id)
        || envelope.get("keypackage_ref").and_then(Value::as_str) != Some(keypackage_ref)
        || envelope.get("keypackage_digest").and_then(Value::as_str) != Some(keypackage_digest)
        || envelope.get("intended_realm_id").and_then(Value::as_str) != Some(op.realm_id.as_str())
        || envelope.get("welcome_digest").and_then(Value::as_str)
            != Some(expected_welcome_digest.as_str())
        || envelope
            .get("nonce")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || envelope
            .get("created_at")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || envelope
            .get("requester_did")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    let envelope_signing_binding = welcome_requester_signature_binding(envelope)?;
    if envelope_signing_binding.ssk_generation.is_some() {
        // Cross-signing requester path: the cryptographic preflight verifies
        // the accepted requester SSK generation.
    } else if let Some(requester_device_id) =
        envelope_signing_binding.requester_device_id.as_deref()
        && let Some(sender_device_id) = payload
            .get("sender_device_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        && sender_device_id != requester_device_id
    {
        return Err(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    if claim_ref.get("ssk_generation").and_then(Value::as_u64) != claim_trust_binding.ssk_generation
        || claim_ref
            .get("device_authorize_event_id")
            .and_then(Value::as_str)
            != claim_trust_binding.device_authorize_event_id.as_deref()
    {
        return Err(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    validate_welcome_claim_signature(envelope)?;
    validate_welcome_recipient_binding(payload, recipient_actor_id)
}

fn validate_welcome_governance_binding(
    binding: &Value,
    group_id: &str,
    realm_id: &str,
    effective_scope: &Value,
) -> Result<(), &'static str> {
    if binding.get("binding_version").and_then(Value::as_u64) != Some(1) {
        return Err("mls_governance_binding_version_invalid");
    }
    if binding.get("encoding_profile").and_then(Value::as_str)
        != Some("cbor-deterministic-rfc8949-v1")
    {
        return Err("mls_governance_binding_encoding_profile_invalid");
    }
    validate_binding_profiles(binding)?;
    if binding.get("mls_group_id").and_then(Value::as_str) != Some(group_id) {
        return Err("mls_governance_binding_group_mismatch");
    }
    if binding.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return Err("mls_governance_binding_realm_mismatch");
    }
    validate_effective_scope(effective_scope)?;
    validate_binding_scope(binding, effective_scope)?;
    validate_binding_frontier_and_policy(binding)
}

fn validate_welcome_claim_signature(envelope: &Map<String, Value>) -> Result<(), &'static str> {
    let signature = envelope
        .get("signature")
        .and_then(Value::as_object)
        .ok_or(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let kid = signature
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    if kid.is_empty()
        || signature
            .get("sig")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    Ok(())
}

fn validate_welcome_recipient_binding(
    payload: &Value,
    recipient_actor_id: &str,
) -> Result<(), &'static str> {
    let Some(bound_recipient) = payload
        .get("recipient_principal_id")
        .or_else(|| payload.get("recipient_actor_id"))
        .and_then(Value::as_str)
    else {
        return Err(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    };
    if bound_recipient == recipient_actor_id {
        Ok(())
    } else {
        Err(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:") && cokret_sdk::Hash::new(value.to_owned()).is_ok()
}

fn validate_effective_scope(scope: &Value) -> Result<(), &'static str> {
    let Some(object) = scope.as_object() else {
        return Err("mls_effective_scope_invalid");
    };
    let Some(kind) = object.get("kind").and_then(Value::as_str) else {
        return Err("mls_effective_scope_invalid");
    };
    let Some(realm_id) = object.get("realm_id").and_then(Value::as_str) else {
        return Err("mls_effective_scope_invalid");
    };
    if realm_id.is_empty() {
        return Err("mls_effective_scope_invalid");
    }
    match kind {
        "realm" => {
            if object.len() == 2 && !object.contains_key("circle_id") {
                Ok(())
            } else {
                Err("mls_effective_scope_invalid")
            }
        }
        "circle" => {
            let Some(circle_id) = object.get("circle_id").and_then(Value::as_str) else {
                return Err("mls_effective_scope_invalid");
            };
            if !circle_id.is_empty() && object.len() == 3 {
                Ok(())
            } else {
                Err("mls_effective_scope_invalid")
            }
        }
        _ => Err("mls_effective_scope_invalid"),
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct KeyPackageTrustBinding {
    ssk_generation: Option<u64>,
    device_authorize_event_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WelcomeRequesterSignatureBinding {
    ssk_generation: Option<u64>,
    requester_device_id: Option<String>,
}

fn keypackage_claim_trust_binding(payload: &Value) -> Result<KeyPackageTrustBinding, &'static str> {
    let object = payload
        .as_object()
        .ok_or(REASON_KEYPACKAGE_CLAIM_GENERATION_MISMATCH)?;
    keypackage_claim_trust_binding_object(object)
}

fn keypackage_claim_trust_binding_object(
    object: &Map<String, Value>,
) -> Result<KeyPackageTrustBinding, &'static str> {
    let ssk_generation = object
        .get("ssk_generation")
        .and_then(Value::as_u64)
        .filter(|generation| *generation >= 1);
    let device_authorize_event_id = object
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    match (ssk_generation, device_authorize_event_id) {
        (Some(ssk_generation), None) => Ok(KeyPackageTrustBinding {
            ssk_generation: Some(ssk_generation),
            device_authorize_event_id: None,
        }),
        (None, Some(device_authorize_event_id)) => Ok(KeyPackageTrustBinding {
            ssk_generation: None,
            device_authorize_event_id: Some(device_authorize_event_id),
        }),
        _ => Err(REASON_KEYPACKAGE_CLAIM_GENERATION_MISMATCH),
    }
}

fn welcome_requester_signature_binding(
    object: &Map<String, Value>,
) -> Result<WelcomeRequesterSignatureBinding, &'static str> {
    let ssk_generation = object
        .get("ssk_generation")
        .and_then(Value::as_u64)
        .filter(|generation| *generation >= 1);
    let requester_device_id = object
        .get("requester_device_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    match (ssk_generation, requester_device_id) {
        (Some(ssk_generation), None) => Ok(WelcomeRequesterSignatureBinding {
            ssk_generation: Some(ssk_generation),
            requester_device_id: None,
        }),
        (None, Some(requester_device_id)) => Ok(WelcomeRequesterSignatureBinding {
            ssk_generation: None,
            requester_device_id: Some(requester_device_id),
        }),
        _ => Err(REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH),
    }
}

fn parse_timestamp(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) => number.as_i64(),
        Some(Value::String(value)) => chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|timestamp| timestamp.timestamp()),
        _ => None,
    }
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

const WELCOME_FORBIDDEN_METADATA_KEYS: &[&str] = &[
    "actor_id",
    "principal_did",
    "principal_id",
    "sender_actor_id",
    "sender_actor_id",
    "sender_actor_display_name",
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

fn extract_covered_seals(payload: &Value) -> Option<Vec<String>> {
    let binding = payload
        .get("governance_binding")
        .or_else(|| payload.get("mls_governance_binding"))?;

    let mut frontier = Vec::new();
    push_frontier_values(binding.get("membership_frontier"), &mut frontier);
    push_frontier_values(binding.get("covered_seals"), &mut frontier);
    push_frontier_values(
        binding.get("covered_seals_cell").and_then(|cell| {
            cell.get("values")
                .or_else(|| cell.get("members"))
                .or_else(|| cell.get("seals"))
        }),
        &mut frontier,
    );
    push_frontier_values(payload.get("covered_seals"), &mut frontier);
    frontier.sort();
    frontier.dedup();
    (!frontier.is_empty()).then_some(frontier)
}

/// Read `governance_binding.policy_root` from a genesis / commit payload. The
/// genesis locks this value onto the group; later commits MUST match it.
fn binding_policy_root(payload: &Value) -> Option<String> {
    payload
        .get("governance_binding")
        .or_else(|| payload.get("mls_governance_binding"))
        .and_then(|binding| binding.get("policy_root"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// Read the opaque commit material identity used to detect concurrent commits
/// at the same base epoch. Accepts the canonical `commit_digest`, or falls back
/// to the opaque `commit_bytes_b64` / `commit_message_ref` the presence check
/// above already required.
fn commit_digest_value(payload: &Value) -> Option<String> {
    payload
        .get("commit_digest")
        .or_else(|| payload.get("commit_bytes_b64"))
        .or_else(|| payload.get("commit_message_ref"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
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
    use cokret_sdk::{Operation, OperationId, RealmId};
    use serde_json::json;

    use super::*;
    use crate::reducer::{MlsEffect, ProjectionEffect, ProjectionState};

    fn op_at(secs: i64, object_type: &str, payload: serde_json::Value) -> Operation {
        let mut op = Operation::create(
            OperationId::new("ck:operation:0196419b-0000-7000-8000-000000000001")
                .expect("op id parses"),
            RealmId::new("ck:realm:0196419b-0000-7000-8000-000000000000").expect("realm id parses"),
            object_type,
            payload,
        );
        op.created_at = Utc.timestamp_opt(secs, 0).single().expect("ts in range");
        op
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn realm_scope() -> Value {
        json!({
            "kind": "realm",
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000"
        })
    }

    fn circle_scope(circle_id: &str) -> Value {
        json!({
            "kind": "circle",
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
            "circle_id": circle_id
        })
    }

    fn governance_binding_for_scope(
        previous_epoch: u64,
        group_id: &str,
        effective_scope: Value,
    ) -> Value {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
        let frontier = format!("ck:event:0196419b-0000-7000-8000-{previous_epoch:012x}");
        let mut binding = json!({
            "binding_version": 1,
            "encoding_profile": "cbor-deterministic-rfc8949-v1",
            "realm_id": realm_id,
            "effective_scope": effective_scope,
            "mls_group_id": group_id,
            "previous_epoch": previous_epoch,
            "next_epoch": previous_epoch + 1,
            "membership_frontier": [
                frontier
            ],
            "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "binding_profile": crate::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "reducer_profile": crate::kinds::MLS_REDUCER_PROFILE_V1
        });
        if let Some(circle_id) = binding["effective_scope"]
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        {
            binding["circle_id"] = Value::String(circle_id);
        }
        binding
    }

    fn governance_binding(previous_epoch: u64) -> Value {
        governance_binding_for_scope(previous_epoch, "ck:mls_group:abc", realm_scope())
    }

    fn welcome_payload(welcome_id: &str) -> Value {
        let keypackage_ref = "ck:mls_keypackage:01";
        let keypackage_digest =
            "sha256:5555555555555555555555555555555555555555555555555555555555555555";
        json!({
            "welcome_id": welcome_id,
            "group_id": "ck:mls_group:abc",
            "recipient_actor_id": "did:web:bob.example",
            "recipient_device_id": "ck:device:bob-phone",
            "welcome_bytes_b64": b64(b"opaque-welcome-bytes"),
            "key_package_id": keypackage_ref,
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": keypackage_digest,
            "claim_id": "claim-01",
            "claim_ref": {
                "claim_id": "claim-01",
                "keypackage_ref": keypackage_ref,
                "keypackage_digest": keypackage_digest,
                "capabilities_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
                "ssk_generation": 7
            },
            "claim_envelope": {
                "keypackage_ref": keypackage_ref,
                "keypackage_digest": keypackage_digest,
                "intended_realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "claim_id": "claim-01",
                "requester_did": "did:web:alice.example",
                "ssk_generation": 7,
                "nonce": b64(b"welcome-claim-nonce-01-128-bit"),
                "welcome_digest": cokret_sdk::canonical::sha256_digest(b"opaque-welcome-bytes"),
                "created_at": "2026-05-25T00:00:02Z",
                "signature": {
                    "kid": "did:web:alice.example#self-signing",
                    "alg": "EdDSA",
                    "sig": b64(b"welcome-claim-envelope-signature")
                }
            },
            "governance_binding": governance_binding(0)
        })
    }

    fn genesis_binding(group_id: &str, effective_scope: Value) -> Value {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
        let mut binding = json!({
            "binding_version": 1,
            "encoding_profile": "cbor-deterministic-rfc8949-v1",
            "realm_id": realm_id,
            "effective_scope": effective_scope,
            "mls_group_id": group_id,
            "previous_epoch": 0,
            "next_epoch": 0,
            "membership_frontier": [
                "ck:event:0196419b-0000-7000-8000-000000000000"
            ],
            "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "binding_profile": crate::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "reducer_profile": crate::kinds::MLS_REDUCER_PROFILE_V1
        });
        if let Some(circle_id) = binding["effective_scope"]
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        {
            binding["circle_id"] = Value::String(circle_id);
        }
        binding
    }

    fn genesis_payload(group_id: &str, effective_scope: Value) -> Value {
        json!({
            "mls_group_id": group_id,
            "effective_scope": effective_scope.clone(),
            "epoch": 0,
            "creator_principal_id": "did:web:alice.example",
            "creator_device_id": "ck:device:alice-desktop",
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "ratchet_tree_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "governance_binding": genesis_binding(group_id, effective_scope),
            "created_at": "2026-05-25T00:00:00Z"
        })
    }

    fn initialize_genesis(state: &mut ProjectionState) {
        let genesis = op_at(
            499,
            "ck.mls.genesis",
            genesis_payload("ck:mls_group:abc", realm_scope()),
        );
        let effect = apply_group_genesis(state, &genesis);
        assert!(matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::GroupGenesis { .. })
        ));
    }

    fn publish_payload(id: &str, actor: &str, device: &str, not_after: i64) -> serde_json::Value {
        json!({
            "action": "publish",
            "keypackage_id": id,
            "actor_id": actor,
            "device_id": device,
            "lifetime": {"not_before": 1, "not_after": not_after},
            "ssk_generation": 7,
            "key_package_bytes_b64": b64(b"opaque-keypackage-bytes"),
        })
    }

    #[test]
    fn keypackage_publish_then_claim_succeeds() {
        let mut state = ProjectionState::default();
        let publish = op_at(
            100,
            "ck.mls.keypackage",
            publish_payload(
                "ck:mls_keypackage:01",
                "did:web:alice.example",
                "ck:device:alice-desktop",
                1_000_000,
            ),
        );
        let effect = apply_keypackage_publish(&mut state, &publish);
        assert!(matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::KeyPackagePublished { ref keypackage_id, .. })
                if keypackage_id == "ck:mls_keypackage:01"
        ));
        assert!(
            state
                .mls_key_packages
                .get("ck:mls_keypackage:01")
                .unwrap()
                .claimed_by
                .is_none()
        );

        let claim = op_at(
            200,
            "ck.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "ck:mls_keypackage:01",
                "group_id": "ck:mls_group:abc",
                "ssk_generation": 7
            }),
        );
        let claim_effect = apply_keypackage_claim(&mut state, &claim);
        match claim_effect {
            ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
                keypackage_id,
                group_id,
                consumed_at,
                ..
            }) => {
                assert_eq!(keypackage_id, "ck:mls_keypackage:01");
                assert_eq!(group_id, "ck:mls_group:abc");
                assert_eq!(consumed_at, 200);
            }
            other => panic!("expected KeyPackageClaimed, got {other:?}"),
        }
        let row = state.mls_key_packages.get("ck:mls_keypackage:01").unwrap();
        assert_eq!(row.claimed_by.as_deref(), Some("ck:mls_group:abc"));
        assert_eq!(row.consumed_at, Some(200));
    }

    #[test]
    fn keypackage_claim_twice_second_fails() {
        let mut state = ProjectionState::default();
        let publish = op_at(
            100,
            "ck.mls.keypackage",
            publish_payload(
                "ck:mls_keypackage:02",
                "did:web:alice.example",
                "ck:device:alice-desktop",
                1_000_000,
            ),
        );
        let _ = apply_keypackage_publish(&mut state, &publish);

        // First claim — wins.
        let claim1 = op_at(
            200,
            "ck.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "ck:mls_keypackage:02",
                "group_id": "ck:mls_group:first",
                "ssk_generation": 7
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
            "ck.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "ck:mls_keypackage:02",
                "group_id": "ck:mls_group:second",
                "ssk_generation": 7
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
        let row = state.mls_key_packages.get("ck:mls_keypackage:02").unwrap();
        assert_eq!(row.claimed_by.as_deref(), Some("ck:mls_group:first"));
        assert_eq!(row.consumed_at, Some(200));
    }

    #[test]
    fn last_resort_keypackage_reuses_within_realm_only() {
        let mut state = ProjectionState::default();
        let mut payload = publish_payload(
            "ck:mls_keypackage:last-resort",
            "did:web:alice.example",
            "ck:device:alice-desktop",
            1_000_000,
        );
        payload["last_resort"] = json!(true);
        let publish = op_at(100, "ck.mls.keypackage", payload);
        let _ = apply_keypackage_publish(&mut state, &publish);

        for group_id in ["ck:mls_group:first", "ck:mls_group:second"] {
            let claim = op_at(
                200,
                "ck.mls.keypackage",
                json!({
                    "action": "claim",
                    "keypackage_id": "ck:mls_keypackage:last-resort",
                    "group_id": group_id,
                    "intended_realm_id": "ck:realm:alpha",
                    "ssk_generation": 7
                }),
            );
            assert!(matches!(
                apply_keypackage_claim(&mut state, &claim),
                ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
                    last_resort: true,
                    ..
                })
            ));
        }

        let row = state
            .mls_key_packages
            .get("ck:mls_keypackage:last-resort")
            .unwrap();
        assert!(row.claimed_by.is_none());
        assert!(row.consumed_at.is_none());
        assert_eq!(row.last_resort_realm_id.as_deref(), Some("ck:realm:alpha"));

        let cross_realm = op_at(
            201,
            "ck.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "ck:mls_keypackage:last-resort",
                "group_id": "ck:mls_group:other",
                "intended_realm_id": "ck:realm:beta",
                "ssk_generation": 7
            }),
        );
        match apply_keypackage_claim(&mut state, &cross_realm) {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, REASON_KEYPACKAGE_REALM_MISMATCH);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn keypackage_claim_rejects_stale_cross_signing_generation() {
        let mut state = ProjectionState::default();
        let publish = op_at(
            100,
            "ck.mls.keypackage",
            publish_payload(
                "ck:mls_keypackage:03",
                "did:web:alice.example",
                "ck:device:alice-desktop",
                1_000_000,
            ),
        );
        let _ = apply_keypackage_publish(&mut state, &publish);

        let claim = op_at(
            200,
            "ck.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "ck:mls_keypackage:03",
                "group_id": "ck:mls_group:abc",
                "ssk_generation": 8
            }),
        );
        let effect = apply_keypackage_claim(&mut state, &claim);
        match effect {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, REASON_KEYPACKAGE_CLAIM_GENERATION_MISMATCH);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        let row = state.mls_key_packages.get("ck:mls_keypackage:03").unwrap();
        assert!(row.claimed_by.is_none());
        assert_eq!(row.ssk_generation, Some(7));
    }

    #[test]
    fn welcome_enqueue_then_fetch_marks_delivered() {
        let mut state = ProjectionState::default();
        let enqueue = op_at(300, "ck.mls.welcome", welcome_payload("ck:mls_welcome:w1"));
        let effect = apply_welcome_enqueue(&mut state, &enqueue);
        assert!(matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
        ));

        let key = MlsWelcomeQueueKey::new("did:web:bob.example", "ck:device:bob-phone");
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
    fn welcome_enqueue_accepts_requester_device_envelope_without_sender_device_id() {
        let mut state = ProjectionState::default();
        let mut payload = welcome_payload("ck:mls_welcome:w-device");
        let claim_ref = payload
            .get_mut("claim_ref")
            .and_then(Value::as_object_mut)
            .unwrap();
        claim_ref.remove("ssk_generation");
        claim_ref.insert(
            "device_authorize_event_id".to_owned(),
            json!("ck:event:01904100-0000-7000-8000-00000000d001"),
        );
        let claim_envelope = payload
            .get_mut("claim_envelope")
            .and_then(Value::as_object_mut)
            .unwrap();
        claim_envelope.remove("ssk_generation");
        claim_envelope.insert(
            "requester_device_id".to_owned(),
            json!("ck:device:alice-desktop"),
        );
        claim_envelope["signature"]["kid"] = json!("did:key:z6MkRequesterDevice#device");
        assert!(payload.get("sender_device_id").is_none());

        let enqueue = op_at(300, "ck.mls.welcome", payload);
        let effect = apply_welcome_enqueue(&mut state, &enqueue);

        assert!(matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
        ));
    }

    #[test]
    fn welcome_enqueue_rejects_mismatched_sender_device_id_when_present() {
        let mut state = ProjectionState::default();
        let mut payload = welcome_payload("ck:mls_welcome:w-device-mismatch");
        let claim_ref = payload
            .get_mut("claim_ref")
            .and_then(Value::as_object_mut)
            .unwrap();
        claim_ref.remove("ssk_generation");
        claim_ref.insert(
            "device_authorize_event_id".to_owned(),
            json!("ck:event:01904100-0000-7000-8000-00000000d001"),
        );
        let claim_envelope = payload
            .get_mut("claim_envelope")
            .and_then(Value::as_object_mut)
            .unwrap();
        claim_envelope.remove("ssk_generation");
        claim_envelope.insert(
            "requester_device_id".to_owned(),
            json!("ck:device:alice-desktop"),
        );
        claim_envelope["signature"]["kid"] = json!("did:key:z6MkRequesterDevice#device");
        payload["sender_device_id"] = json!("ck:device:other");

        let enqueue = op_at(300, "ck.mls.welcome", payload);
        let effect = apply_welcome_enqueue(&mut state, &enqueue);

        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { reason }
                if reason == REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH
        ));
    }

    #[test]
    fn welcome_enqueue_decodes_schema_ciphertext_base64_to_raw_welcome_bytes() {
        let mut state = ProjectionState::default();
        let raw_welcome = b"real-openmls-welcome-bytes";
        let mut payload = welcome_payload("ck:mls_welcome:w-ciphertext");
        let object = payload.as_object_mut().unwrap();
        object.remove("welcome_bytes_b64");
        object.remove("key_package_id");
        object.insert("ciphertext".to_owned(), Value::String(b64(raw_welcome)));
        payload["claim_envelope"]["welcome_digest"] =
            Value::String(cokret_sdk::canonical::sha256_digest(raw_welcome));

        let enqueue = op_at(300, "ck.mls.welcome", payload);
        let effect = apply_welcome_enqueue(&mut state, &enqueue);

        assert!(matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
        ));
        let key = MlsWelcomeQueueKey::new("did:web:bob.example", "ck:device:bob-phone");
        let queue = state.mls_welcomes.get(&key).unwrap();
        assert_eq!(queue[0].welcome_bytes, raw_welcome);
        assert_eq!(queue[0].key_package_id, "ck:mls_keypackage:01");
    }

    #[test]
    fn welcome_enqueue_rejects_plaintext_identity_metadata() {
        let mut state = ProjectionState::default();
        let mut payload = welcome_payload("ck:mls_welcome:w-leaky");
        payload["metadata"] = json!({
            "sender_handle": "@alice",
            "routing_hint": "ok"
        });
        let enqueue = op_at(300, "ck.mls.welcome", payload);
        let effect = apply_welcome_enqueue(&mut state, &enqueue);
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { reason } if reason == REASON_WELCOME_METADATA_LEAK
        ));
        assert!(state.mls_welcomes.is_empty());
    }

    #[test]
    fn welcome_enqueue_rejects_missing_claim_envelope() {
        let mut state = ProjectionState::default();
        let mut payload = welcome_payload("ck:mls_welcome:w-unbound");
        payload.as_object_mut().unwrap().remove("claim_envelope");
        let enqueue = op_at(300, "ck.mls.welcome", payload);
        let effect = apply_welcome_enqueue(&mut state, &enqueue);
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { reason }
                if reason == REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH
        ));
        assert!(state.mls_welcomes.is_empty());
    }

    #[test]
    fn commit_epoch_in_order_succeeds() {
        let mut state = ProjectionState::default();
        initialize_genesis(&mut state);

        // First commit after genesis — expected_prev_epoch=0 → epoch=1.
        let c1 = op_at(
            500,
            "ck.mls.commit",
            json!({
                "group_id": "ck:mls_group:abc",
                "expected_prev_epoch": 0,
                "next_epoch": 1,
                "leader_actor_id": "did:web:alice.example",
                "commit_bytes_b64": b64(b"opaque-commit-1"),
                "governance_binding": governance_binding(0),
            }),
        );
        let e1 = apply_commit_epoch(&mut state, &c1);
        match e1 {
            ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced {
                previous_epoch,
                new_epoch,
                ref covered_seals,
                ..
            }) => {
                assert_eq!(previous_epoch, 0);
                assert_eq!(new_epoch, 1);
                assert_eq!(
                    covered_seals,
                    &vec!["ck:event:0196419b-0000-7000-8000-000000000000".to_owned()]
                );
            }
            other => panic!("expected CommitEpochAdvanced, got {other:?}"),
        }

        // Second commit — expected_prev_epoch=1 → epoch=2.
        let c2 = op_at(
            501,
            "ck.mls.commit",
            json!({
                "group_id": "ck:mls_group:abc",
                "expected_prev_epoch": 1,
                "next_epoch": 2,
                "leader_actor_id": "did:web:alice.example",
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
            state
                .mls_commit_epochs
                .get(&mls_epoch_key(&realm_scope(), "ck:mls_group:abc").unwrap())
                .unwrap(),
            &MlsCommitEpoch {
                group_id: "ck:mls_group:abc".to_owned(),
                effective_scope: realm_scope(),
                epoch: 2,
                leader_actor_id: "did:web:alice.example".to_owned(),
                covered_seals: vec![
                    "ck:event:0196419b-0000-7000-8000-000000000000".to_owned(),
                    "ck:event:0196419b-0000-7000-8000-000000000001".to_owned()
                ],
                committed_at: 501,
                policy_root:
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
                accepted_commit_digest: Some(b64(b"opaque-commit-2")),
                accepted_from_epoch: Some(1),
                frontier_contested: false,
            }
        );
    }

    #[test]
    fn commit_epoch_requires_covered_seals() {
        let mut state = ProjectionState::default();
        let effect = apply_commit_epoch(
            &mut state,
            &op_at(
                500,
                "ck.mls.commit",
                json!({
                    "group_id": "ck:mls_group:abc",
                    "expected_prev_epoch": 0,
                    "next_epoch": 1,
                    "leader_actor_id": "did:web:alice.example",
                    "commit_bytes_b64": b64(b"opaque-commit-1"),
                    "governance_binding": {
                        "binding_version": 1,
                        "encoding_profile": "cbor-deterministic-rfc8949-v1",
                        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                        "effective_scope": {
                            "kind": "realm",
                            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000"
                        },
                        "mls_group_id": "ck:mls_group:abc",
                        "previous_epoch": 0,
                        "next_epoch": 1,
                        "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                        "binding_profile": crate::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                        "reducer_profile": crate::kinds::MLS_REDUCER_PROFILE_V1
                    },
                }),
            ),
        );
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { reason } if reason == "mls_governance_binding_membership_frontier_missing"
        ));
        assert!(state.mls_commit_epochs.is_empty());
    }

    #[test]
    fn commit_epoch_requires_effective_genesis() {
        let mut state = ProjectionState::default();
        let effect = apply_commit_epoch(
            &mut state,
            &op_at(
                500,
                "ck.mls.commit",
                json!({
                    "group_id": "ck:mls_group:abc",
                    "expected_prev_epoch": 0,
                    "next_epoch": 1,
                    "leader_actor_id": "did:web:alice.example",
                    "commit_bytes_b64": b64(b"opaque-commit-1"),
                    "governance_binding": governance_binding(0),
                }),
            ),
        );
        assert!(
            matches!(effect, ProjectionEffect::Rejected { reason } if reason == "mls_genesis_missing")
        );
        assert!(state.mls_commit_epochs.is_empty());
    }

    #[test]
    fn same_group_id_is_independent_across_effective_scopes() {
        let mut state = ProjectionState::default();
        let realm_scope = realm_scope();
        let circle_scope = circle_scope("ck:circle:0196419b-0000-7000-8000-000000000123");
        let realm_genesis = op_at(
            500,
            "ck.mls.genesis",
            genesis_payload("ck:mls_group:abc", realm_scope.clone()),
        );
        let circle_genesis = op_at(
            501,
            "ck.mls.genesis",
            genesis_payload("ck:mls_group:abc", circle_scope.clone()),
        );
        assert!(matches!(
            apply_group_genesis(&mut state, &realm_genesis),
            ProjectionEffect::Mls(MlsEffect::GroupGenesis { .. })
        ));
        assert!(matches!(
            apply_group_genesis(&mut state, &circle_genesis),
            ProjectionEffect::Mls(MlsEffect::GroupGenesis { .. })
        ));

        let realm_commit = op_at(
            502,
            "ck.mls.commit",
            json!({
                "group_id": "ck:mls_group:abc",
                "expected_prev_epoch": 0,
                "next_epoch": 1,
                "leader_actor_id": "did:web:alice.example",
                "commit_bytes_b64": b64(b"realm-commit"),
                "governance_binding": governance_binding_for_scope(
                    0,
                    "ck:mls_group:abc",
                    realm_scope.clone()
                ),
            }),
        );
        assert!(matches!(
            apply_commit_epoch(&mut state, &realm_commit),
            ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 1, .. })
        ));

        assert_eq!(
            state
                .mls_commit_epochs
                .get(&mls_epoch_key(&realm_scope, "ck:mls_group:abc").unwrap())
                .unwrap()
                .epoch,
            1
        );
        assert_eq!(
            state
                .mls_commit_epochs
                .get(&mls_epoch_key(&circle_scope, "ck:mls_group:abc").unwrap())
                .unwrap()
                .epoch,
            0
        );
        assert_eq!(state.mls_commit_epochs.len(), 2);
    }

    #[test]
    fn commit_epoch_stale_rejected() {
        let mut state = ProjectionState::default();
        initialize_genesis(&mut state);
        // Land epoch 1 first.
        let _ = apply_commit_epoch(
            &mut state,
            &op_at(
                600,
                "ck.mls.commit",
                json!({
                    "group_id": "ck:mls_group:abc",
                    "expected_prev_epoch": 0,
                    "next_epoch": 1,
                    "leader_actor_id": "did:web:alice.example",
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
                "ck.mls.commit",
                json!({
                    "group_id": "ck:mls_group:abc",
                    "expected_prev_epoch": 0,
                    "next_epoch": 1,
                    "leader_actor_id": "did:web:alice.example",
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
                .get(&mls_epoch_key(&realm_scope(), "ck:mls_group:abc").unwrap())
                .unwrap()
                .epoch,
            1
        );

        // A future-epoch commit (expected_prev_epoch=5) is also rejected.
        let leap = apply_commit_epoch(
            &mut state,
            &op_at(
                602,
                "ck.mls.commit",
                json!({
                    "group_id": "ck:mls_group:abc",
                    "expected_prev_epoch": 5,
                    "next_epoch": 6,
                    "leader_actor_id": "did:web:alice.example",
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
                .get(&mls_epoch_key(&realm_scope(), "ck:mls_group:abc").unwrap())
                .unwrap()
                .epoch,
            1
        );
    }

    fn commit_op(secs: i64, label: &[u8], extra: Value) -> Operation {
        let mut payload = json!({
            "group_id": "ck:mls_group:abc",
            "expected_prev_epoch": 0,
            "next_epoch": 1,
            "leader_actor_id": "did:web:alice.example",
            "commit_bytes_b64": b64(label),
            "governance_binding": governance_binding(0),
        });
        if let (Some(object), Some(extra)) = (payload.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                object.insert(key.clone(), value.clone());
            }
        }
        op_at(secs, "ck.mls.commit", payload)
    }

    #[test]
    fn commit_rejects_policy_root_mismatch() {
        let mut state = ProjectionState::default();
        initialize_genesis(&mut state);
        // A commit whose governance_binding.policy_root differs from the
        // genesis-locked root is rejected with governance_binding_mismatch.
        let mut binding = governance_binding(0);
        binding["policy_root"] =
            json!("sha256:9999999999999999999999999999999999999999999999999999999999999999");
        let effect = apply_commit_epoch(
            &mut state,
            &commit_op(
                500,
                b"forged-binding",
                json!({ "governance_binding": binding }),
            ),
        );
        match effect {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, REASON_GOVERNANCE_BINDING_MISMATCH);
            }
            other => panic!("expected governance_binding_mismatch, got {other:?}"),
        }
        // The epoch is untouched.
        assert_eq!(
            state
                .mls_commit_epochs
                .get(&mls_epoch_key(&realm_scope(), "ck:mls_group:abc").unwrap())
                .unwrap()
                .epoch,
            0
        );
    }

    #[test]
    fn concurrent_commits_contend_then_resolve() {
        let mut state = ProjectionState::default();
        initialize_genesis(&mut state);
        let epoch_key = mls_epoch_key(&realm_scope(), "ck:mls_group:abc").unwrap();

        // First commit at base epoch 0 lands → epoch 1.
        assert!(matches!(
            apply_commit_epoch(&mut state, &commit_op(500, b"commit-a", json!({}))),
            ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 1, .. })
        ));

        // A racing commit that explicitly forks base epoch 0 with different
        // material drives covered_frontier_cell to ⊥ (CommitFrontierContested).
        let contended = apply_commit_epoch(
            &mut state,
            &commit_op(501, b"commit-b", json!({ "concurrent_commit": true })),
        );
        assert!(matches!(
            contended,
            ProjectionEffect::Mls(MlsEffect::CommitFrontierContested { epoch: 0, .. })
        ));
        assert!(
            state
                .mls_commit_epochs
                .get(&epoch_key)
                .unwrap()
                .frontier_contested
        );
        // Epoch unchanged while contested.
        assert_eq!(state.mls_commit_epochs.get(&epoch_key).unwrap().epoch, 1);

        // A further racing commit at the contested base fails closed as
        // decryption_pending.
        let pending = apply_commit_epoch(
            &mut state,
            &commit_op(502, b"commit-c", json!({ "concurrent_commit": true })),
        );
        assert!(matches!(
            pending,
            ProjectionEffect::Rejected { reason } if reason == REASON_DECRYPTION_PENDING
        ));

        // A resolving commit at the current epoch advances and clears ⊥.
        let resolve = apply_commit_epoch(
            &mut state,
            &commit_op(
                503,
                b"commit-resolve",
                json!({ "expected_prev_epoch": 1, "next_epoch": 2 }),
            ),
        );
        assert!(matches!(
            resolve,
            ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 2, .. })
        ));
        let row = state.mls_commit_epochs.get(&epoch_key).unwrap();
        assert_eq!(row.epoch, 2);
        assert!(!row.frontier_contested);
    }
}
