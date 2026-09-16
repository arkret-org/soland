//! MLS lifecycle reducer helpers.
//!
//! Two Event kinds reach the reducer:
//!
//! 1. **group genesis** — `apply_group_genesis`. Installs epoch 0 for a new MLS group and flips the
//!    scope from plaintext to standard RFC 9420 protection.
//!
//! 2. **commit_epoch increment** — `apply_commit_epoch`. The reducer only accepts a commit whose
//!    governance binding's `previous_epoch` matches the group's current stored epoch. Stale /
//!    out-of-order commits are rejected with `mls_epoch_skew`.
//!
//! KeyPackage publication is not an Event: `apply_keypackage_upload_projection` maintains the
//! dedicated KeyPackage ledger projection that `/_arkret/self/keys/keypackages/*` writes through.

use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;

use super::{
    KeyPackageLifetimeProjection, MlsCommitEpoch, MlsCommitEpochKey, MlsEffect,
    MlsKeyPackageProjection, MlsRemoveObligation, ProjectionEffect, ProjectionState,
};

/// Reason code emitted when a KeyPackage ledger claim targets a KeyPackage that has already been
/// claimed. Routing layer maps to HTTP 409 `cas_conflict`.
pub const REASON_KEYPACKAGE_ALREADY_CLAIMED: &str = "mls_keypackage_already_claimed";
/// Reason code emitted when a KeyPackage ledger claim targets an unknown KeyPackage id.
pub const REASON_KEYPACKAGE_NOT_FOUND: &str = "mls_keypackage_not_found";
/// Reason code emitted when a KeyPackage publish/claim carries a Realm mismatch.
pub const REASON_KEYPACKAGE_REALM_MISMATCH: &str = "mls_keypackage_realm_mismatch";
/// Reason code emitted when a commit's governance binding `previous_epoch` does not match the
/// group's stored epoch (out-of-order / stale / replay).
const REASON_COMMIT_EPOCH_SKEW: &str = "mls_epoch_skew";

#[derive(Clone, Debug)]
pub enum MlsKeyPackagePublishTrustAnchor {
    DeviceAuthorize(String),
    AgentKeyAuthorize {
        event_id: String,
        verification_method: String,
    },
    MinimalMetadataPairwise {
        verification_method: String,
        intended_realm_id: String,
    },
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
    /// Local `accounts.pk`; never part of a KeyPackage wire object.
    pub owner_account_pk: i64,
    pub actor_id: String,
    pub device_id: Option<String>,
    pub lifetime: KeyPackageLifetimeProjection,
    pub key_package_bytes: Vec<u8>,
    pub capabilities: Vec<String>,
    pub last_resort: bool,
    pub trust_anchor: MlsKeyPackagePublishTrustAnchor,
    pub created_at: i64,
}

pub fn apply_keypackage_upload_projection(
    state: &mut ProjectionState,
    projection: &MlsKeyPackagePublishProjection,
) -> ProjectionEffect {
    if projection.keypackage_id.is_empty() {
        return reject("mls_keypackage_id_missing");
    }
    if projection.actor_id.is_empty() {
        return reject("mls_keypackage_actor_missing");
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
    let (
        device_authorize_event_id,
        agent_key_authorize_event_id,
        endpoint_verification_method,
        intended_realm_id,
    ) = match &projection.trust_anchor {
        MlsKeyPackagePublishTrustAnchor::DeviceAuthorize(event_id) => {
            if projection.device_id.is_none() {
                return reject("mls_keypackage_device_missing");
            }
            (Some(event_id.clone()), None, None, None)
        }
        MlsKeyPackagePublishTrustAnchor::AgentKeyAuthorize {
            event_id,
            verification_method,
        } => (
            None,
            Some(event_id.clone()),
            Some(verification_method.clone()),
            None,
        ),
        MlsKeyPackagePublishTrustAnchor::MinimalMetadataPairwise {
            verification_method,
            intended_realm_id,
        } => (
            None,
            None,
            Some(verification_method.clone()),
            Some(intended_realm_id.clone()),
        ),
    };
    let row = MlsKeyPackageProjection {
        id: projection.keypackage_id.clone(),
        keypackage_ref: projection.keypackage_ref.clone(),
        keypackage_digest: projection.keypackage_digest.clone(),
        owner_account_pk: projection.owner_account_pk,
        actor_id: projection.actor_id.clone(),
        device_id: projection.device_id.clone(),
        endpoint_verification_method,
        intended_realm_id,
        lifetime: projection.lifetime.clone(),
        key_package_bytes: projection.key_package_bytes.clone(),
        capabilities: projection.capabilities.clone(),
        capabilities_digest,
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

    ProjectionEffect::Mls(MlsEffect::KeyPackagePublished {
        keypackage_id: projection.keypackage_id.clone(),
        actor_id: projection.actor_id.clone(),
        device_id: projection.device_id.clone(),
    })
}

/// Strongly typed local projection input for a KeyPackage claim.
///
/// Claiming is not an Arkret Event either: it is the compare-and-swap step of
/// the dedicated KeyPackage ledger that `/_arkret/self/keys/keypackages/*`
/// writes through. Keeping it typed is what stops a caller from reaching the
/// CAS with a hand-built `ProjectedEventOperation`.
#[derive(Clone, Debug)]
pub struct MlsKeyPackageClaimProjection {
    pub keypackage_id: String,
    /// MLS group reserving this KeyPackage. Two concurrent claims for
    /// different groups must resolve to exactly one winner.
    pub group_id: String,
    /// Realm a last-resort KeyPackage is bound to on first claim.
    pub intended_realm_id: Option<String>,
    pub trust_binding: KeyPackageTrustBinding,
    /// Reservation deadline. `None` means "as long as the KeyPackage lives".
    pub claim_expires_at_unix_ms: Option<i64>,
    pub claimed_at: i64,
}

/// Atomic compare-and-swap claim of a published KeyPackage.
///
/// Concurrency contract: two concurrent claims against the same
/// `keypackage_id` MUST produce exactly one `KeyPackageClaimed` effect; the
/// loser receives `Rejected { reason: mls_keypackage_already_claimed }`, which
/// the routing layer maps to HTTP 409 `cas_conflict`. Without it two Welcomes
/// could target the same init key.
pub fn apply_keypackage_claim_projection(
    state: &mut ProjectionState,
    projection: &MlsKeyPackageClaimProjection,
) -> ProjectionEffect {
    if projection.keypackage_id.is_empty() {
        return reject("mls_keypackage_id_missing");
    }
    if projection.group_id.is_empty() {
        return reject("mls_keypackage_group_missing");
    }
    let claimed_at = projection.claimed_at;
    let group_id = projection.group_id.as_str();
    let Some(row) = state.mls_key_packages.get_mut(&projection.keypackage_id) else {
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
    // Lifetime check — RFC 9420 §10. Stale KeyPackages cannot be claimed.
    if claimed_at >= row.lifetime.not_after {
        return reject(arkret_wire::ReasonCode::KEYPACKAGE_EXPIRED);
    }
    if row.device_authorize_event_id != projection.trust_binding.device_authorize_event_id
        || row.agent_key_authorize_event_id
            != projection.trust_binding.agent_key_authorize_event_id
    {
        return reject(arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH);
    }
    let intended_realm_id = projection
        .intended_realm_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if row.last_resort {
        // A last-resort KeyPackage is never consumed, so it carries no claim
        // window; it binds to one Realm on first claim and stays there.
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
        let claim_expires_at_unix_ms = projection
            .claim_expires_at_unix_ms
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

    ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
        keypackage_id: projection.keypackage_id.clone(),
        group_id: projection.group_id.clone(),
        intended_realm_id,
        last_resort: row.last_resort,
        claimed_at,
    })
}

/// Initialize a new MLS group at epoch 0 and irreversibly activate its scope.
///
/// A Realm, Circle or Sidecar scope is plaintext until its own `ak.mls.genesis` is accepted; that
/// acceptance activates it as standard RFC 9420 and there is no protocol path back
/// (realm-and-space.md 2.3, circle.md 7). The reducer stores the epoch and the accepted governance
/// binding and stamps the scope's canonical MLS group id onto the Circle projection, which is the
/// indicator every later plaintext check reads. Opaque GroupInfo / ratchet-tree material stays in
/// the durable Event payload and its object-store references.
pub fn apply_group_genesis(state: &mut ProjectionState, op: &Operation) -> ProjectionEffect {
    let payload = &op.payload;
    let validated = match serde_json::from_value::<
        arkret_models_collaboration::events_payloads::MlsGenesisPayload,
    >(payload.clone())
    {
        Ok(payload) => payload,
        Err(_) => return reject("mls_genesis_payload_invalid"),
    };
    let group_id = match validated.mls_group_id() {
        Ok(group_id) => group_id,
        Err(_) => return reject("mls_genesis_payload_invalid"),
    };
    let group_id = group_id.as_str();
    let creator_actor_id = op.context.sender.to_string();
    let Some(creator_device_id) = op.context.producer_device_id.as_ref() else {
        return reject("schema_violation");
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
        return reject(arkret_wire::ReasonCode::MLS_ACTIVATION_IRREVERSIBLE);
    }
    // circle.md 7 / realm-and-space.md 2.3: the governance Station accepts a scope's first
    // `ak.mls.genesis` only while its current history_access is `since_join`, because an activated
    // scope can no longer widen its history window.
    if let Some(circle_id) = scope_circle_id(&effective_scope) {
        let Some(circle) = state.circles.get(circle_id) else {
            return reject("circle_not_found");
        };
        if circle.history_access != "since_join" {
            return reject("history_access_requires_history_capable_scheme");
        }
    }
    state.mls_commit_epochs.insert(
        epoch_key,
        MlsCommitEpoch {
            group_id: group_id.to_owned(),
            effective_scope: effective_scope.clone(),
            epoch: 0,
            leader_actor_id: creator_actor_id.clone(),
            creator_device_id: creator_device_id.as_str().to_owned(),
            genesis_event_ref,
            committed_at: op.created_at.timestamp(),
            governance_binding,
            accepted_commit_digest: None,
            accepted_commit_ref: None,
        },
    );
    if let Some(circle_id) = scope_circle_id(&effective_scope)
        && let Some(circle) = state.circles.get_mut(circle_id)
    {
        circle.mls_group_ref = Some(group_id.to_owned());
    }

    ProjectionEffect::Mls(MlsEffect::GroupGenesis {
        group_id: group_id.to_owned(),
        effective_scope,
        epoch: 0,
        creator_actor_id,
        creator_device_id: creator_device_id.as_str().to_owned(),
    })
}

/// Bump an MLS group's commit epoch.
///
/// The canonical payload is `MlsCommitPayload`; Proposals travel inline in the opaque Commit body.
///
/// The committer is **not** a payload field. Any member holding the scope's `ak.mls.commit`
/// capability may author a Commit, so the committing identity is the Event envelope author and the
/// closed payload schema has no slot for it to be restated in.
///
/// The reducer accepts a commit IFF
/// `governance_binding.previous_epoch == current_stored_epoch`.
/// A Genesis must already exist. On success the stored epoch is set to
/// `base_epoch + 1`. Stale or out-of-order commits leave state
/// untouched and emit `ProjectionEffect::Rejected { reason:
/// "mls_epoch_skew" }`.
pub fn apply_commit_epoch(state: &mut ProjectionState, op: &Operation) -> ProjectionEffect {
    let payload = &op.payload;
    let validated =
        match serde_json::from_value::<arkret_models_crypto::MlsCommitPayload>(payload.clone()) {
            Ok(payload) => payload,
            Err(_) => return reject("mls_commit_payload_invalid"),
        };
    let group_id = match validated.mls_group_id() {
        Ok(group_id) => group_id,
        Err(_) => return reject("mls_commit_payload_invalid"),
    };
    let group_id = group_id.as_str();
    let expected_prev_epoch = validated.base_epoch();
    // The committing member is the signed Event author; the registered commit
    // payload is closed and carries no committer field.
    let committer_actor_id = op.context.sender.to_string();
    // Body bytes are not semantically parsed at reducer level; the routing
    // layer has already validated the typed payload and content-addressed ref.
    if !payload
        .get("commit_bytes_b64")
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
    let creator_device_id = existing.creator_device_id.clone();
    let genesis_event_ref = existing.genesis_event_ref.clone();
    if expected_prev_epoch != current {
        return reject(REASON_COMMIT_EPOCH_SKEW);
    }

    // Remove Proposals are carried inside the opaque Commit body, so a Commit that advances the
    // scope's epoch is what discharges the pending removal obligations recorded for that scope.
    let pending_removals = matching_pending_remove_obligations(state, &effective_scope, group_id);

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
        },
    );
    state.accepted_mls_commit_refs.insert(accepted_commit_ref);
    if !pending_removals.is_empty() {
        state
            .pending_mls_removals
            .retain(|obligation| !pending_removals.iter().any(|landed| landed == obligation));
    }

    ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced {
        group_id: group_id.to_owned(),
        effective_scope,
        previous_epoch: current,
        new_epoch,
        leader_actor_id: committer_actor_id.to_owned(),
    })
}

// ── private helpers ───────────────────────────────────────────────────

fn reject(reason: &str) -> ProjectionEffect {
    ProjectionEffect::Rejected {
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
    let scope = serde_json::from_value::<arkret_wire::ScopeRef>(scope.clone())
        .map_err(|_| "mls_effective_scope_invalid")?;
    let key = scope
        .canonical_effective_scope_key_bytes()
        .map_err(|_| "mls_effective_scope_invalid")?;
    String::from_utf8(key).map_err(|_| "mls_effective_scope_invalid")
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

/// The Circle id of a `{kind: "circle", ...}` effective scope, if that is the scope's shape.
fn scope_circle_id(effective_scope: &Value) -> Option<&str> {
    let object = effective_scope.as_object()?;
    (object.get("kind").and_then(Value::as_str) == Some("circle"))
        .then(|| object.get("circle_id").and_then(Value::as_str))
        .flatten()
}

fn genesis_effective_scope(payload: &Value) -> Result<Value, &'static str> {
    commit_effective_scope(payload)
}

fn validate_genesis_governance_binding(
    payload: &Value,
    group_id: &str,
    effective_scope: &Value,
) -> Result<(), &'static str> {
    let binding = payload
        .get("governance_binding")
        .ok_or("mls_genesis_governance_binding_missing")?;
    if parsed_binding(binding)?
        .mls_group_id()
        .map_err(|_| arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH)?
        != group_id
    {
        return Err(arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH);
    }
    if binding.get("previous_epoch").and_then(Value::as_u64) != Some(0) {
        return Err(arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH);
    }
    if binding.get("next_epoch").and_then(Value::as_u64) != Some(0) {
        return Err(arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH);
    }
    validate_binding_scope(binding, effective_scope)?;
    validate_binding_frontier_and_policy(binding)
}

fn commit_effective_scope(payload: &Value) -> Result<Value, &'static str> {
    let scope = payload
        .get("governance_binding")
        .and_then(|binding| binding.get("effective_scope"))
        .ok_or(arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH)?;
    validate_effective_scope(scope)?;
    Ok(scope.clone())
}

fn parsed_binding(
    binding: &Value,
) -> Result<arkret_models_crypto::MlsGovernanceBindingPayload, &'static str> {
    serde_json::from_value(binding.clone())
        .map_err(|_| arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH)
}

fn validate_binding_scope(binding: &Value, effective_scope: &Value) -> Result<(), &'static str> {
    let parsed = parsed_binding(binding)?;
    let scope: arkret_wire::ScopeRef = serde_json::from_value(effective_scope.clone())
        .map_err(|_| arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH)?;
    if parsed.effective_scope() != &scope {
        return Err(arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH);
    }
    Ok(())
}

fn validate_binding_frontier_and_policy(binding: &Value) -> Result<(), &'static str> {
    let parsed = serde_json::from_value::<arkret_models_crypto::MlsGovernanceBindingPayload>(
        binding.clone(),
    )
    .map_err(|_| arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH)?;
    parsed
        .validate()
        .map_err(|_| arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH)
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

/// Exactly-one-of trust binding carried by every KeyPackage publication and
/// claim: device authorization, Agent key authorization, or a minimal-metadata
/// pairwise actor/method pair.
///
/// Owned here because the reducer validates it off the wire payload and the
/// `/keys/keypackages/*` routing layer validates the same shape off the stored
/// row; both surfaces must enforce one closed set and one
/// `claim_generation_mismatch` reason code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackageTrustBinding {
    pub device_authorize_event_id: Option<String>,
    pub agent_key_authorize_event_id: Option<String>,
    pub pairwise_actor_id: Option<String>,
    pub pairwise_verification_method: Option<String>,
}

impl KeyPackageTrustBinding {
    pub fn device_authorize(device_authorize_event_id: String) -> Self {
        Self {
            device_authorize_event_id: Some(device_authorize_event_id),
            agent_key_authorize_event_id: None,
            pairwise_actor_id: None,
            pairwise_verification_method: None,
        }
    }

    pub fn agent_key_authorize(agent_key_authorize_event_id: String) -> Self {
        Self {
            device_authorize_event_id: None,
            agent_key_authorize_event_id: Some(agent_key_authorize_event_id),
            pairwise_actor_id: None,
            pairwise_verification_method: None,
        }
    }

    pub fn minimal_metadata_pairwise(actor_id: String, verification_method: String) -> Self {
        Self {
            device_authorize_event_id: None,
            agent_key_authorize_event_id: None,
            pairwise_actor_id: Some(actor_id),
            pairwise_verification_method: Some(verification_method),
        }
    }

    /// Enforce the exactly-one-of rule. Absent, empty and whitespace-only ids
    /// all count as absent; accepted ids are stored trimmed so the reducer and
    /// the routing layer compare identical bytes.
    pub fn from_parts(
        device_authorize_event_id: Option<String>,
        agent_key_authorize_event_id: Option<String>,
        pairwise_actor_id: Option<String>,
        pairwise_verification_method: Option<String>,
    ) -> Result<Self, &'static str> {
        let device_authorize_event_id = non_empty_trimmed(device_authorize_event_id);
        let agent_key_authorize_event_id = non_empty_trimmed(agent_key_authorize_event_id);
        let pairwise_actor_id = non_empty_trimmed(pairwise_actor_id);
        let pairwise_verification_method = non_empty_trimmed(pairwise_verification_method);
        match (
            device_authorize_event_id,
            agent_key_authorize_event_id,
            pairwise_actor_id,
            pairwise_verification_method,
        ) {
            (Some(event_id), None, None, None) => Ok(Self::device_authorize(event_id)),
            (None, Some(event_id), None, None) => Ok(Self::agent_key_authorize(event_id)),
            (None, None, Some(actor_id), Some(method)) => {
                let actor = actor_id
                    .parse::<arkret_identifiers::DidCoreId>()
                    .map_err(|_| arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH)?;
                let method_id = arkret_wire::DidUrl::new(method.clone())
                    .map_err(|_| arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH)?;
                arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
                    actor, method_id,
                )
                .map_err(|_| arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH)?;
                Ok(Self::minimal_metadata_pairwise(actor_id, method))
            }
            _ => Err(arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH),
        }
    }
}

fn non_empty_trimmed(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}


/// Derive the private commit-material identity used to detect concurrent
/// commits. The wire payload carries the bytes and may carry a content-addressed
/// Blob ref, but never a sibling `commit_digest`.
fn commit_digest_value(payload: &Value) -> Option<String> {
    let encoded = payload.get("commit_bytes_b64")?.as_str()?.trim();
    if encoded.is_empty() {
        return None;
    }
    let bytes = arkret_canonical::base64url_decode(encoded).ok()?;
    Some(arkret_canonical::sha256_digest(bytes))
}

// ──────────────────────────── tests ───────────────────────────────────

#[cfg(test)]
mod tests;
