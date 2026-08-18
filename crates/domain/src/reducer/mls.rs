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
//!    appended to a per-`(recipient_actor_id, recipient_device_id)` binding projection while the
//!    standard durable device-message stream carries delivery.
//!
//! 3. **group genesis** — `apply_group_genesis`. Installs epoch 0 for a new MLS group.
//!
//! 4. **commit_epoch increment** — `apply_commit_epoch`. The reducer only accepts a commit whose
//!    `expected_prev_epoch` matches the group's current stored epoch (0 for a brand-new group).
//!    Stale / out-of-order commits are rejected with `mls_epoch_skew`.
//!
//! Deferred (TODO(G3.S1-followup) markers below + in `routing/mls.rs`):
//!   - decryption_pending (deferred-decryption queue + retry)

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_wire::{CORE_REDUCER_PROFILE, ProfileId};
use serde_json::{Map, Value};

use super::{
    KeyPackageLifetime, MlsCommitEpoch, MlsCommitEpochKey, MlsEffect, MlsKeyPackage,
    MlsRemoveObligation, MlsRemoveProposal, MlsWelcome, MlsWelcomeQueueKey, ProjectionState,
};

/// Reason code emitted when a `ak.mls.keypackage` event with
/// `payload.action == "claim"` targets a KeyPackage that has already
/// been claimed. Routing layer maps to HTTP 409 `cas_conflict`.
pub const REASON_KEYPACKAGE_ALREADY_CLAIMED: &str = "mls_keypackage_already_claimed";
/// Reason code emitted when a `ak.mls.keypackage` event with
/// `payload.action == "claim"` targets an unknown KeyPackage id.
pub const REASON_KEYPACKAGE_NOT_FOUND: &str = "mls_keypackage_not_found";
/// Reason code emitted when a published KeyPackage's lifetime window
/// is already past `not_after`. Mirrors RFC 9420 §10.
/// Reason code emitted when a KeyPackage publish/claim carries a Realm mismatch.
pub const REASON_KEYPACKAGE_REALM_MISMATCH: &str = "mls_keypackage_realm_mismatch";
/// Reason code emitted when a commit's `expected_prev_epoch` does not
/// match the group's stored epoch (out-of-order / stale / replay).
const REASON_COMMIT_EPOCH_SKEW: &str = "mls_epoch_skew";
/// Reject code for Welcome payloads that try to carry plaintext sender,
/// profile, relationship, or device metadata outside the opaque MLS bytes.
const REASON_WELCOME_METADATA_LEAK: &str = "mls_welcome_metadata_leak";
/// Reject code for MLS Welcome payloads whose KeyPackage claim transcript
/// is missing or does not bind the Welcome bytes to the recipient realm.
/// Reject code for a second genesis against an already initialized group.
const REASON_GENESIS_ALREADY_EXISTS: &str = "mls_genesis_already_exists";
/// Reject code emitted while a group's active generation is contested.
/// Sends / decrypts on
/// the contested epoch stay fail-closed until a resolving commit advances it.
/// Reject code for a commit that advances while a remove obligation is pending
/// but does not reference a matching `ak.mls.proposal{proposal_type="remove"}`.
const REASON_REMOVE_PROPOSAL_MISSING: &str = "mls_remove_proposal_missing";

#[derive(Clone, Debug)]
pub enum MlsKeyPackagePublishTrustAnchor {
    DeviceAuthorize(String),
    AgentKeyAuthorize(String),
}

/// Strongly typed local projection input for a KeyPackage upload.
///
/// This is not an Arkret Event payload. KeyPackage upload is an HTTP/storage
/// workflow, so it must not manufacture a `ProjectedEventOperation` merely to
/// reuse reducer code.
#[derive(Clone, Debug)]
pub struct MlsKeyPackagePublishProjection {
    pub keypackage_id: String,
    pub keypackage_ref: String,
    pub keypackage_digest: String,
    pub actor_id: String,
    pub device_id: String,
    pub lifetime: KeyPackageLifetime,
    pub key_package_bytes: Vec<u8>,
    pub capabilities: Vec<String>,
    pub device_signature: arkret_models_crypto::KeyOperationSignature,
    pub last_resort: bool,
    pub trust_anchor: MlsKeyPackagePublishTrustAnchor,
    pub created_at: i64,
}

pub fn apply_keypackage_upload_projection(
    state: &mut ProjectionState,
    projection: &MlsKeyPackagePublishProjection,
) -> ProjectionEffectOut {
    if projection.keypackage_id.is_empty() {
        return reject("mls_keypackage_id_missing");
    }
    if projection.actor_id.is_empty() {
        return reject("mls_keypackage_actor_missing");
    }
    if projection.device_id.is_empty() {
        return reject("mls_keypackage_device_missing");
    }
    if projection.lifetime.not_after <= projection.lifetime.not_before {
        return reject("mls_keypackage_lifetime_invalid");
    }
    if projection.key_package_bytes.is_empty() {
        return reject("mls_keypackage_bytes_empty");
    }
    let computed_keypackage_digest = arkret_canonical::sha256_digest(&projection.key_package_bytes);
    if projection.keypackage_digest != computed_keypackage_digest {
        return reject("mls_keypackage_digest_mismatch");
    }
    let capabilities_digest = match arkret_canonical::canonical_json_bytes(&projection.capabilities)
    {
        Ok(bytes) => arkret_canonical::sha256_digest(bytes),
        Err(_) => return reject("mls_keypackage_capabilities_digest_failed"),
    };
    let device_signature = match serde_json::to_value(&projection.device_signature) {
        Ok(value) => value,
        Err(_) => return reject("mls_keypackage_device_signature_invalid"),
    };
    let (device_authorize_event_id, agent_key_authorize_event_id) = match &projection.trust_anchor {
        MlsKeyPackagePublishTrustAnchor::DeviceAuthorize(event_id) => {
            (Some(event_id.clone()), None)
        }
        MlsKeyPackagePublishTrustAnchor::AgentKeyAuthorize(event_id) => {
            (None, Some(event_id.clone()))
        }
    };
    let row = MlsKeyPackage {
        id: projection.keypackage_id.clone(),
        keypackage_ref: projection.keypackage_ref.clone(),
        keypackage_digest: projection.keypackage_digest.clone(),
        actor_id: projection.actor_id.clone(),
        device_id: projection.device_id.clone(),
        lifetime: projection.lifetime.clone(),
        key_package_bytes: projection.key_package_bytes.clone(),
        capabilities: projection.capabilities.clone(),
        capabilities_digest,
        device_signature,
        last_resort: projection.last_resort,
        last_resort_realm_id: None,
        claimed_by: None,
        device_authorize_event_id,
        agent_key_authorize_event_id,
        claimed_at: None,
        claim_expires_at_unix_ms: None,
        consumed_at: None,
        created_at: projection.created_at,
    };

    // Insert is structural — duplicates of the same `keypackage_id`
    // replace in place (a republish of the same id by the same device
    // re-arms the row; the device is the sole source-of-truth for the
    // opaque bytes). Production deployments will route duplicate-id
    // detection through the wire validator before reaching here.
    state
        .mls_key_packages
        .insert(projection.keypackage_id.clone(), row);

    ProjectionEffectOut::Mls(MlsEffect::KeyPackagePublished {
        keypackage_id: projection.keypackage_id.clone(),
        actor_id: projection.actor_id.clone(),
        device_id: projection.device_id.clone(),
    })
}

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
    let Some(actor_id) = payload.get("principal_id").and_then(Value::as_str) else {
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
    let computed_keypackage_digest = arkret_canonical::sha256_digest(&key_package_bytes);
    let keypackage_digest = payload
        .get("keypackage_digest")
        .and_then(Value::as_str)
        .unwrap_or(computed_keypackage_digest.as_str())
        .to_owned();
    if keypackage_digest != computed_keypackage_digest {
        return reject("mls_keypackage_digest_mismatch");
    }
    let capabilities = string_array(payload.get("capabilities"));
    let capabilities_digest = match arkret_canonical::canonical_json_bytes(&capabilities) {
        Ok(bytes) => arkret_canonical::sha256_digest(bytes),
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
        device_authorize_event_id: trust_binding.device_authorize_event_id,
        agent_key_authorize_event_id: trust_binding.agent_key_authorize_event_id,
        claimed_at: None,
        claim_expires_at_unix_ms: None,
        consumed_at: None,
        created_at,
    };
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
///   "keypackage_id": "keypackage-<uuid>",
///   "group_id":      "mls-group-<uuid>"
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

    let claimed_at = op.created_at.timestamp();
    let Some(row) = state.mls_key_packages.get_mut(id) else {
        return reject(REASON_KEYPACKAGE_NOT_FOUND);
    };
    if row.claimed_by.as_deref() == Some("revoked") {
        return reject(REASON_KEYPACKAGE_NOT_FOUND);
    }
    // CAS check — refuse if a *different* group has already claimed this row.
    // A repeat claim by the same MLS group is idempotent renewal: a resolver
    // whose materialization was interrupted retries with the same reserved
    // group id after the claim window lapsed. The Welcome target is unchanged,
    // so renewal cannot create cross-group init-key reuse.
    if !row.last_resort
        && row
            .claimed_by
            .as_deref()
            .is_some_and(|claimed| claimed != group_id)
    {
        return reject(REASON_KEYPACKAGE_ALREADY_CLAIMED);
    }
    // Lifetime check — RFC 9420 §10. Stale KeyPackages can't be claimed.
    if claimed_at >= row.lifetime.not_after {
        return reject(arkret_wire::ReasonCode::KEYPACKAGE_EXPIRED);
    }
    let trust_binding = match keypackage_claim_trust_binding(payload) {
        Ok(binding) => binding,
        Err(reason) => return reject(reason),
    };
    if row.device_authorize_event_id != trust_binding.device_authorize_event_id
        || row.agent_key_authorize_event_id != trust_binding.agent_key_authorize_event_id
    {
        return reject(arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH);
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
        let claim_expires_at_unix_ms = payload
            .get("claim_expires_at_unix_ms")
            .and_then(Value::as_i64)
            .unwrap_or_else(|| row.lifetime.not_after.saturating_mul(1000));
        if claim_expires_at_unix_ms <= claimed_at.saturating_mul(1000)
            || claim_expires_at_unix_ms > row.lifetime.not_after.saturating_mul(1000)
        {
            return reject(arkret_wire::ReasonCode::KEYPACKAGE_EXPIRED);
        }
        row.claimed_by = Some(group_id.to_owned());
        row.claimed_at = Some(claimed_at);
        row.claim_expires_at_unix_ms = Some(claim_expires_at_unix_ms);
        row.consumed_at = None;
    }

    ProjectionEffectOut::Mls(MlsEffect::KeyPackageClaimed {
        keypackage_id: id.to_owned(),
        group_id: group_id.to_owned(),
        intended_realm_id,
        last_resort: row.last_resort,
        claimed_at,
    })
}

/// G3.S1 — enqueue a Welcome envelope for a recipient device.
///
/// Payload shape:
/// ```json
/// {
///   "welcome_ref":            "ak:mls_welcome:<uuid>",
///   "mls_group_id":           "mls-group-<uuid>",
///   "recipient_principal_id": "ak:did_core:web:bob.example",
///   "recipient_device_id":    "ak:device:<uuid>",
///   "ciphertext":             "<base64url(opaque MLS Welcome)>",
///   "keypackage_ref":         "keypackage-<uuid>"
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
        .get("welcome_ref")
        .or_else(|| payload.get("encrypted_welcome_ref"))
        .or_else(|| payload.get("claim_id"))
        .and_then(Value::as_str)
    else {
        return reject("mls_welcome_id_missing");
    };
    let Some(group_id) = payload.get("mls_group_id").and_then(Value::as_str) else {
        return reject("mls_welcome_group_missing");
    };
    let Some(recipient_actor_id) = payload
        .get("recipient_principal_id")
        .and_then(Value::as_str)
    else {
        return reject("mls_welcome_recipient_actor_missing");
    };
    let Some(recipient_device_id) = payload.get("recipient_device_id").and_then(Value::as_str)
    else {
        return reject("mls_welcome_recipient_device_missing");
    };
    let Some(key_package_id) = payload.get("keypackage_ref").and_then(Value::as_str) else {
        return reject("mls_welcome_key_package_id_missing");
    };
    let Some(epoch) = payload.get("epoch").and_then(Value::as_u64) else {
        return reject("mls_welcome_epoch_missing");
    };
    let commit_ref = payload
        .get("commit_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let Some(governance_binding) = payload.get("governance_binding").cloned() else {
        return reject("mls_welcome_governance_binding_missing");
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
        state,
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
        epoch,
        commit_ref,
        governance_binding,
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
/// registry. The reducer stores the epoch and accepted governance binding;
/// opaque GroupInfo / ratchet tree material remains in the
/// durable event payload and object store references.
/// Record a `ak.mls.proposal{proposal_type="remove"}` so a later commit can
/// prove it is consuming a pending remove obligation.
pub fn apply_remove_proposal(state: &mut ProjectionState, op: &Operation) -> ProjectionEffectOut {
    let payload = &op.payload;
    if payload.get("proposal_type").and_then(Value::as_str) != Some("remove") {
        return ProjectionEffectOut::Ignored;
    }
    let Some(group_id) = payload.get("mls_group_id").and_then(Value::as_str) else {
        return reject("mls_proposal_group_missing");
    };
    let Some(base_epoch) = payload.get("base_epoch").and_then(Value::as_u64) else {
        return reject("mls_proposal_base_epoch_missing");
    };
    let Some(target_actor_id) = payload
        .get("target_principal_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return reject("mls_remove_proposal_target_missing");
    };
    let effective_scope = match proposal_effective_scope(state, payload, group_id, base_epoch) {
        Ok(scope) => scope,
        Err(reason) => return reject(reason),
    };
    let proposal_ref = op.context.event_id.to_string();
    let target_device_id = payload
        .get("target_device_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned);
    state.mls_remove_proposals.insert(
        proposal_ref.clone(),
        MlsRemoveProposal {
            proposal_ref: proposal_ref.clone(),
            group_id: group_id.to_owned(),
            effective_scope: effective_scope.clone(),
            base_epoch,
            target_actor_id: target_actor_id.to_owned(),
            target_device_id: target_device_id.clone(),
            created_at: op.created_at.timestamp(),
        },
    );

    ProjectionEffectOut::Mls(MlsEffect::RemoveProposalRecorded {
        proposal_ref,
        group_id: group_id.to_owned(),
        effective_scope,
        target_actor_id: target_actor_id.to_owned(),
        target_device_id,
    })
}

pub fn apply_group_genesis(state: &mut ProjectionState, op: &Operation) -> ProjectionEffectOut {
    let payload = &op.payload;
    let Some(group_id) = payload.get("mls_group_id").and_then(Value::as_str) else {
        return reject("mls_genesis_group_missing");
    };
    let epoch = payload.get("epoch").and_then(Value::as_u64).unwrap_or(0);
    if epoch != 0 {
        return reject("mls_genesis_epoch_invalid");
    }
    let Some(creator_actor_id) = payload.get("creator_principal_id").and_then(Value::as_str) else {
        return reject("mls_genesis_creator_missing");
    };
    let Some(creator_device_id) = payload
        .get("creator_device_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return reject("mls_genesis_creator_device_missing");
    };
    let genesis_event_ref = op.context.event_id.to_string();
    let Some(governance_binding) = payload.get("governance_binding").cloned() else {
        return reject("mls_genesis_governance_binding_missing");
    };
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
    state.mls_commit_epochs.insert(
        epoch_key,
        MlsCommitEpoch {
            group_id: group_id.to_owned(),
            effective_scope: effective_scope.clone(),
            epoch: 0,
            leader_actor_id: creator_actor_id.to_owned(),
            creator_device_id: creator_device_id.to_owned(),
            genesis_event_ref,
            committed_at: op.created_at.timestamp(),
            governance_binding,
            accepted_commit_digest: None,
            accepted_commit_ref: None,
            accepted_from_epoch: None,
            frontier_contested: false,
        },
    );

    ProjectionEffectOut::Mls(MlsEffect::GroupGenesis {
        group_id: group_id.to_owned(),
        effective_scope,
        epoch: 0,
        creator_actor_id: creator_actor_id.to_owned(),
        creator_device_id: creator_device_id.to_owned(),
    })
}

/// G3.S1 — bump an MLS group's commit epoch.
///
/// Payload shape (`event-payload.schema.json#/$defs/mls_commit_payload`, a
/// closed object):
/// ```json
/// {
///   "mls_group_id":     "mls-group-<uuid>",
///   "base_epoch":       <u64>,
///   "base_epoch_ref":   "ak:event:<token>",
///   "proposal_refs":    ["ak:event:<token>"],
///   "next_epoch":       <u64>,
///   "commit_bytes_b64": "<base64url(opaque MLS Commit)>",
///   "commit_digest":    "sha256:<hex>",
///   "governance_binding": { … }
/// }
/// ```
///
/// The committer is **not** a payload field. `encryption-and-audit.md` §5.6
/// lets any member holding the scope's `ak.mls.commit` capability author a
/// Commit, so the committing identity is the Event envelope author and the
/// closed payload schema has no slot for it to be restated in.
///
/// The reducer accepts a commit IFF
/// `payload.base_epoch == current_stored_epoch` (defaulting to
/// `0` for a never-seen group). On success the stored epoch is set to
/// `base_epoch + 1`. Stale or out-of-order commits leave state
/// untouched and emit `ProjectionEffect::Rejected { reason:
/// "mls_epoch_skew" }`.
pub fn apply_commit_epoch(state: &mut ProjectionState, op: &Operation) -> ProjectionEffectOut {
    let payload = &op.payload;
    let Some(group_id) = payload.get("mls_group_id").and_then(Value::as_str) else {
        return reject("mls_commit_group_missing");
    };
    let expected_prev_epoch = match payload.get("base_epoch").and_then(Value::as_u64) {
        Some(v) => v,
        None => return reject("mls_commit_expected_prev_epoch_missing"),
    };
    // The committing member is the signed Event author; the registered commit
    // payload is closed and carries no committer field.
    let committer_actor_id = op.context.sender.as_str();
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
    let commit_digest = match commit_digest_value(payload) {
        Some(digest) => digest,
        None => return reject("mls_commit_bytes_missing"),
    };

    let Some(existing) = state.mls_commit_epochs.get(&epoch_key) else {
        return reject("mls_genesis_missing");
    };
    let current = existing.epoch;
    let governance_binding = payload
        .get("governance_binding")
        .cloned()
        .unwrap_or(Value::Null);
    let accepted_digest = existing.accepted_commit_digest.clone();
    let creator_device_id = existing.creator_device_id.clone();
    let genesis_event_ref = existing.genesis_event_ref.clone();
    let accepted_from_epoch = existing.accepted_from_epoch;
    let prior_contested = existing.frontier_contested;

    // §2.5.2 — concurrent commit detection. Two commits attesting the *same*
    // base epoch with *different* commit material drive `covered_frontier_cell`
    // to `⊥`. Because the reducer applies commits sequentially, the first
    // already advanced the epoch and recorded `(accepted_from_epoch,
    // accepted_commit_digest)`; the racing second still attests
    // `accepted_from_epoch` but carries a different digest. A genuine race is
    // distinguished from an unrelated stale replay by its attested base epoch:
    // it names the same epoch from which the currently accepted commit
    // advanced. No private wire marker is needed (or permitted by the
    // registered `ak.mls.commit` payload schema).
    let is_contention = accepted_from_epoch == Some(expected_prev_epoch)
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
            return reject(arkret_wire::ReasonCode::DECRYPTION_PENDING);
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

    let proposal_refs = string_array(payload.get("proposal_refs"));
    let pending_removals = matching_pending_remove_obligations(state, &effective_scope, group_id);
    if pending_removals.iter().any(|obligation| {
        !commit_references_matching_remove_proposal(
            state,
            &proposal_refs,
            group_id,
            expected_prev_epoch,
            &effective_scope,
            obligation,
        )
    }) {
        return reject(REASON_REMOVE_PROPOSAL_MISSING);
    }

    // Reaching here with `expected_prev_epoch == current` is a forward advance.
    // When the frontier was `⊥`, this is the resolving commit: the insert below
    // both bumps the epoch and resets `frontier_contested = false`.

    let new_epoch = current.saturating_add(1);
    let committed_at = op.created_at.timestamp();
    let accepted_commit_ref = op.context.event_id.to_string();
    state.mls_commit_epochs.insert(
        epoch_key,
        MlsCommitEpoch {
            group_id: group_id.to_owned(),
            effective_scope: effective_scope.clone(),
            epoch: new_epoch,
            leader_actor_id: committer_actor_id.to_owned(),
            creator_device_id,
            genesis_event_ref,
            committed_at,
            governance_binding,
            accepted_commit_digest: Some(commit_digest),
            accepted_commit_ref: Some(accepted_commit_ref.clone()),
            accepted_from_epoch: Some(expected_prev_epoch),
            frontier_contested: false,
        },
    );
    state.accepted_mls_commit_refs.insert(accepted_commit_ref);
    if !pending_removals.is_empty() {
        state
            .pending_mls_removals
            .retain(|obligation| !pending_removals.iter().any(|landed| landed == obligation));
    }

    ProjectionEffectOut::Mls(MlsEffect::CommitEpochAdvanced {
        group_id: group_id.to_owned(),
        effective_scope,
        previous_epoch: current,
        new_epoch,
        leader_actor_id: committer_actor_id.to_owned(),
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

pub fn effective_scope_key(scope: &Value) -> Result<String, &'static str> {
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

fn proposal_effective_scope(
    state: &ProjectionState,
    payload: &Value,
    group_id: &str,
    base_epoch: u64,
) -> Result<Value, &'static str> {
    if let Some(binding) = payload.get("governance_binding") {
        if binding.get("mls_group_id").and_then(Value::as_str) != Some(group_id) {
            return Err("mls_governance_binding_group_mismatch");
        }
        if binding.get("previous_epoch").and_then(Value::as_u64) != Some(base_epoch) {
            return Err("mls_governance_binding_previous_epoch_mismatch");
        }
        let scope = binding
            .get("effective_scope")
            .ok_or("mls_governance_binding_scope_missing")?;
        validate_effective_scope(scope)?;
        return Ok(scope.clone());
    }

    let mut matches = state
        .mls_commit_epochs
        .values()
        .filter(|row| row.group_id == group_id && row.epoch == base_epoch);
    let Some(row) = matches.next() else {
        return Err("mls_proposal_group_epoch_missing");
    };
    if matches.next().is_some() {
        return Err("mls_proposal_scope_ambiguous");
    }
    Ok(row.effective_scope.clone())
}

fn matching_pending_remove_obligations(
    state: &ProjectionState,
    effective_scope: &Value,
    group_id: &str,
) -> Vec<MlsRemoveObligation> {
    let Some((realm_id, circle_id)) = effective_scope_parts(effective_scope) else {
        return Vec::new();
    };
    state
        .pending_mls_removals
        .iter()
        .filter(|obligation| {
            obligation.realm_id == realm_id
                && obligation.circle_id.as_deref() == circle_id.as_deref()
                && obligation
                    .mls_group_ref
                    .as_deref()
                    .is_none_or(|expected| expected == group_id)
        })
        .cloned()
        .collect()
}

fn effective_scope_parts(effective_scope: &Value) -> Option<(String, Option<String>)> {
    let object = effective_scope.as_object()?;
    let realm_id = object.get("realm_id").and_then(Value::as_str)?.to_owned();
    match object.get("kind").and_then(Value::as_str) {
        Some("realm") => Some((realm_id, None)),
        Some("circle") => Some((
            realm_id,
            Some(object.get("circle_id").and_then(Value::as_str)?.to_owned()),
        )),
        _ => None,
    }
}

fn commit_references_matching_remove_proposal(
    state: &ProjectionState,
    proposal_refs: &[String],
    group_id: &str,
    base_epoch: u64,
    effective_scope: &Value,
    obligation: &MlsRemoveObligation,
) -> bool {
    proposal_refs.iter().any(|proposal_ref| {
        state
            .mls_remove_proposals
            .get(proposal_ref)
            .is_some_and(|proposal| {
                proposal.group_id == group_id
                    && proposal.base_epoch == base_epoch
                    && proposal.target_actor_id == obligation.actor_id
                    && obligation.device_id.as_deref().is_none_or(|device_id| {
                        proposal.target_device_id.as_deref() == Some(device_id)
                    })
                    && proposal.effective_scope.eq(effective_scope)
            })
    })
}

fn genesis_effective_scope(payload: &Value) -> Result<Value, &'static str> {
    let scope = payload
        .get("effective_scope")
        .ok_or("mls_genesis_effective_scope_missing")?;
    validate_effective_scope(scope)?;
    let binding_scope = payload
        .get("governance_binding")
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
    let parsed = serde_json::from_value::<arkret_models_crypto::MlsGovernanceBindingPayload>(
        binding.clone(),
    )
    .map_err(|_| "mls_governance_binding_invalid")?;
    parsed
        .validate()
        .map_err(|_| "mls_governance_binding_invalid")
}

fn validate_binding_profiles(binding: &Value) -> Result<(), &'static str> {
    if binding.get("binding_profile").and_then(Value::as_str)
        != Some(ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1)
    {
        return Err("mls_governance_binding_profile_invalid");
    }
    if binding.get("reducer_profile").and_then(Value::as_str) != Some(CORE_REDUCER_PROFILE) {
        return Err("mls_governance_binding_reducer_profile_invalid");
    }
    Ok(())
}

fn validate_welcome_trust_binding(
    state: &ProjectionState,
    op: &Operation,
    group_id: &str,
    recipient_actor_id: &str,
    key_package_id: &str,
    welcome_bytes: &[u8],
    payload: &Value,
) -> Result<(), &'static str> {
    let binding = payload
        .get("governance_binding")
        .ok_or("mls_welcome_governance_binding_missing")?;
    let effective_scope = binding
        .get("effective_scope")
        .ok_or("mls_governance_binding_scope_missing")?;
    validate_welcome_governance_binding(binding, group_id, op.realm_id.as_str(), effective_scope)?;

    let claim_id = payload
        .get("claim_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let keypackage_ref = payload
        .get("keypackage_ref")
        .and_then(Value::as_str)
        .unwrap_or(key_package_id);
    if keypackage_ref != key_package_id {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    let keypackage_digest = payload
        .get("keypackage_digest")
        .and_then(Value::as_str)
        .filter(|value| is_sha256_digest(value))
        .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let claim_ref = payload
        .get("claim_ref")
        .and_then(Value::as_object)
        .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let claim_trust_binding = keypackage_claim_trust_binding_object(claim_ref)
        .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    if let Some(agent_authorize_event_id) =
        claim_trust_binding.agent_key_authorize_event_id.as_deref()
        && !state
            .active_agent_key_authorizations(recipient_actor_id)
            .into_iter()
            .any(|(_, event_id)| event_id == agent_authorize_event_id)
    {
        return Err(arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH);
    }
    if claim_ref.get("claim_id").and_then(Value::as_str) != Some(claim_id)
        || claim_ref.get("keypackage_ref").and_then(Value::as_str) != Some(keypackage_ref)
        || claim_ref.get("keypackage_digest").and_then(Value::as_str) != Some(keypackage_digest)
        || claim_ref
            .get("capabilities_digest")
            .and_then(Value::as_str)
            .is_none_or(|value| !is_sha256_digest(value))
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }

    let envelope = payload
        .get("claim_envelope")
        .and_then(Value::as_object)
        .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let expected_welcome_digest = arkret_canonical::sha256_digest(welcome_bytes);
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
            .get("requester_actor_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    let envelope_signing_binding = welcome_requester_signature_binding(envelope)?;
    if let Some(requester_device_id) = envelope_signing_binding.requester_device_id.as_deref()
        && let Some(sender_device_id) = payload
            .get("sender_device_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        && sender_device_id != requester_device_id
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    if claim_ref
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        != claim_trust_binding.device_authorize_event_id.as_deref()
        || claim_ref
            .get("agent_key_authorize_event_id")
            .and_then(Value::as_str)
            != claim_trust_binding.agent_key_authorize_event_id.as_deref()
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
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
        .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let kid = signature
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    if kid.is_empty()
        || signature
            .get("sig")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    Ok(())
}

fn validate_welcome_recipient_binding(
    payload: &Value,
    recipient_actor_id: &str,
) -> Result<(), &'static str> {
    let Some(bound_recipient) = payload
        .get("recipient_principal_id")
        .and_then(Value::as_str)
    else {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    };
    if bound_recipient == recipient_actor_id {
        Ok(())
    } else {
        Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:") && arkret_identifiers::Hash::new(value.to_owned()).is_ok()
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
    device_authorize_event_id: Option<String>,
    agent_key_authorize_event_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WelcomeRequesterSignatureBinding {
    requester_device_id: Option<String>,
}

fn keypackage_claim_trust_binding(payload: &Value) -> Result<KeyPackageTrustBinding, &'static str> {
    let object = payload
        .as_object()
        .ok_or(arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH)?;
    keypackage_claim_trust_binding_object(object)
}

fn keypackage_claim_trust_binding_object(
    object: &Map<String, Value>,
) -> Result<KeyPackageTrustBinding, &'static str> {
    let device_authorize_event_id = object
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let agent_key_authorize_event_id = object
        .get("agent_key_authorize_event_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    match (device_authorize_event_id, agent_key_authorize_event_id) {
        (Some(device_authorize_event_id), None) => Ok(KeyPackageTrustBinding {
            device_authorize_event_id: Some(device_authorize_event_id),
            agent_key_authorize_event_id: None,
        }),
        (None, Some(agent_key_authorize_event_id)) => Ok(KeyPackageTrustBinding {
            device_authorize_event_id: None,
            agent_key_authorize_event_id: Some(agent_key_authorize_event_id),
        }),
        _ => Err(arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH),
    }
}

fn welcome_requester_signature_binding(
    object: &Map<String, Value>,
) -> Result<WelcomeRequesterSignatureBinding, &'static str> {
    let requester_device_id = object
        .get("requester_device_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    match requester_device_id {
        Some(requester_device_id) => Ok(WelcomeRequesterSignatureBinding {
            requester_device_id: Some(requester_device_id),
        }),
        _ => Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH),
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
mod tests;
