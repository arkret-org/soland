use super::*;

pub(super) fn validate_pin_scope_safety(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !kinds::canonical_kind_for_operation(operation)
        .is_some_and(arkret_wire::events::kinds::is_pin_kind)
    {
        return Ok(());
    }
    let projection = state.projections().snapshot();
    projection.check_pin_scope_safety(operation)
}

pub(super) async fn validate_accountability_profile_policy(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kinds::canonical_kind_string(operation).as_str(),
        "ak.profile.create" | "ak.profile.update"
    ) {
        return Ok(());
    }
    let accountable_principal_ids = profile_accountable_principal_ids(operation);
    if accountable_principal_ids.is_empty() {
        return Ok(());
    }
    let Some(principal_id) = profile_principal_id(operation) else {
        return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
    };
    let frozen_at = operation.created_at;
    let mut grants = accountability_grants_at_frozen_basis(state, operation).await?;
    merge_atomic_accountability_grants(&mut grants, operations, operation.realm_id.as_str());
    for issuer in accountable_principal_ids {
        let active = grants.values().any(|grant| {
            grant.issuer.as_str() == issuer
                && grant.subject.as_str() == principal_id
                && grant.validate_lifecycle_at(frozen_at).is_ok()
        });
        if !active {
            return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
        }
    }
    Ok(())
}

type AccountabilityGrantKey = (String, String, String);
type AccountabilityGrant =
    arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;

async fn accountability_grants_at_frozen_basis(
    state: &AppState,
    operation: &Operation,
) -> Result<std::collections::BTreeMap<AccountabilityGrantKey, AccountabilityGrant>, &'static str> {
    let realm = operation.realm_id.clone();
    let basis = accountability_seal_basis(operation)?;
    if !basis.is_empty() {
        let frozen = state
            .projections()
            .effective_state_at(&basis, &realm)
            .map_err(|_| "accountability grant frozen basis unavailable")?;
        let mut grants = std::collections::BTreeMap::new();
        for (cell_ref, cell_state) in frozen {
            if !cell_ref
                .as_str()
                .starts_with("ak:cell:ak.component.identity.accountability.v1:")
            {
                continue;
            }
            let arkret_state::lattice::CellState::Value(value) = cell_state else {
                continue;
            };
            if let Some(grant) = parse_accountability_grant(&value)
                && let Some(key) = accountability_grant_key(&grant)
            {
                grants.insert(key, grant);
            }
        }
        return Ok(grants);
    }

    // Test/support callers that construct Operations directly have no CBA
    // envelope context. Keep that path deterministic by folding accepted grant
    // events by event id and the profile Event's signed created_at. Production
    // Control Moves always take the sealed-cell path above.
    let mut records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|_| "accountability grant frozen basis unavailable")?;
    records.sort_by(|left, right| left.event_id.as_bytes().cmp(right.event_id.as_bytes()));
    let mut grants = std::collections::BTreeMap::new();
    for record in records {
        if record.kind != arkret_wire::EventKind::IDENTITY_ACCOUNTABILITY_GRANT
            || record.realm_id.as_deref() != Some(operation.realm_id.as_str())
        {
            continue;
        }
        let payload = record.envelope.get("payload").unwrap_or(&record.envelope);
        let Some(grant) = parse_accountability_grant(payload) else {
            continue;
        };
        if !accountability_grant_envelope_signed_by(&record, grant.issuer.as_str())
            || grant.proof.created_at > operation.created_at
        {
            continue;
        }
        if let Some(key) = accountability_grant_key(&grant) {
            insert_accountability_grant_revoke_wins(&mut grants, key, grant);
        }
    }
    Ok(grants)
}

fn accountability_seal_basis(
    operation: &Operation,
) -> Result<Vec<arkret_identifiers::SealId>, &'static str> {
    let mut ids = Vec::new();
    if let Some(seal_ref) = operation.payload.get("seal_ref").and_then(Value::as_str) {
        ids.push(
            arkret_identifiers::SealId::new(seal_ref.to_owned())
                .map_err(|_| "accountability grant seal_ref is invalid")?,
        );
    }
    if let Some(seal_basis) = operation.payload.get("seal_basis") {
        if let Some(seal_ref) = seal_basis.as_str() {
            ids.push(
                arkret_identifiers::SealId::new(seal_ref.to_owned())
                    .map_err(|_| "accountability grant seal_basis is invalid")?,
            );
        }
        if let Some(leaves) = seal_basis.get("leaves").and_then(Value::as_array) {
            for leaf in leaves {
                let seal_ref = leaf
                    .as_str()
                    .ok_or("accountability grant seal_basis leaf is invalid")?;
                ids.push(
                    arkret_identifiers::SealId::new(seal_ref.to_owned())
                        .map_err(|_| "accountability grant seal_basis leaf is invalid")?,
                );
            }
        }
    }
    ids.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    ids.dedup();
    Ok(ids)
}

fn merge_atomic_accountability_grants(
    grants: &mut std::collections::BTreeMap<AccountabilityGrantKey, AccountabilityGrant>,
    operations: &[Operation],
    realm_id: &str,
) {
    for operation in operations {
        if kinds::canonical_kind_string(operation)
            != arkret_wire::EventKind::IDENTITY_ACCOUNTABILITY_GRANT
            || operation.realm_id.as_str() != realm_id
        {
            continue;
        }
        let Some(grant) = parse_accountability_grant(&operation.payload) else {
            continue;
        };
        if !accountability_grant_operation_signed_by(operation, grant.issuer.as_str()) {
            continue;
        }
        if let Some(key) = accountability_grant_key(&grant) {
            insert_accountability_grant_revoke_wins(grants, key, grant);
        }
    }
}

fn insert_accountability_grant_revoke_wins(
    grants: &mut std::collections::BTreeMap<AccountabilityGrantKey, AccountabilityGrant>,
    key: AccountabilityGrantKey,
    grant: AccountabilityGrant,
) {
    use arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus;
    if grants
        .get(&key)
        .is_some_and(|current| current.grant_status == AccountabilityGrantStatus::Revoked)
        && grant.grant_status == AccountabilityGrantStatus::Active
    {
        return;
    }
    grants.insert(key, grant);
}

fn accountability_grant_key(grant: &AccountabilityGrant) -> Option<AccountabilityGrantKey> {
    Some((
        grant.issuer.as_str().to_owned(),
        grant.subject.as_str().to_owned(),
        grant.accountability_scope.scope_set_component().ok()?,
    ))
}

fn parse_accountability_grant(value: &Value) -> Option<AccountabilityGrant> {
    let mut grant_value = value.clone();
    if let Some(object) = grant_value.as_object_mut() {
        for field in [
            "event_id",
            "sender",
            "hlc",
            "executed_by",
            "authorization_ref",
            "seal_basis",
            "seal_ref",
            "preconditions",
            "effects",
            "accepted_event_id",
            "query_grade",
        ] {
            object.remove(field);
        }
    }
    serde_json::from_value(grant_value).ok()
}

pub(super) fn profile_body_value(operation: &Operation) -> &Value {
    operation
        .payload
        .get("profile")
        .or_else(|| operation.payload.get("object"))
        .or_else(|| operation.payload.get("value"))
        .unwrap_or(&operation.payload)
}

pub(super) fn profile_principal_id(operation: &Operation) -> Option<String> {
    let body = profile_body_value(operation);
    body.get("principal_id")
        .or_else(|| body.get("actor_id"))
        .or_else(|| operation.payload.get("principal_id"))
        .or_else(|| operation.payload.get("actor_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn profile_accountable_principal_ids(operation: &Operation) -> Vec<String> {
    let body = profile_body_value(operation);
    body.get("accountable_principal_ids")
        .or_else(|| operation.payload.get("accountable_principal_ids"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn accountability_grant_operation_signed_by(
    operation: &Operation,
    issuer: &str,
) -> bool {
    operation
        .payload
        .get("executed_by")
        .or_else(|| operation.payload.get("sender"))
        .and_then(Value::as_str)
        == Some(issuer)
}

pub(super) fn accountability_grant_envelope_signed_by(
    record: &soland_services::events::CanonicalEventRecord,
    issuer: &str,
) -> bool {
    record
        .envelope
        .get("executed_by")
        .and_then(Value::as_str)
        .unwrap_or(record.actor_id.as_str())
        == issuer
}

pub(super) fn accountability_grant_value_active_for(
    value: &Value,
    issuer: &str,
    subject: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(grant) = parse_accountability_grant(value) else {
        return false;
    };
    grant.issuer.as_str() == issuer
        && grant.subject.as_str() == subject
        && grant.validate_lifecycle_at(now).is_ok()
}

/// SEC-08 — server-side defence-in-depth for `ak.profile.mls.minimal_metadata_realm.v1`
/// Realms (`crypto-media/encryption-and-audit.md` §2.9).
///
/// For a Realm that has declared the minimal-metadata profile, an encrypted
/// `ak.message.create` / reaction envelope MUST set
/// `aad_visibility_event_id="hidden"`; any other value (or an absent
/// discriminator on an encrypted envelope) is rejected so message-id exposure
/// cannot widen reaction-frequency correlation from per-`target_ref` to
/// per-message. The fail-closed decision is delegated to the SDK helper
/// [`arkret_policy::enforce_minimal_metadata_aad`] so the wire enum mapping
/// stays single-sourced.
///
/// Scope notes (honest boundary): soland holds no MLS group key and is not the
/// committer, so the §2.9 `epoch lifetime MUST ≤ 1h` obligation stays a client /
/// committer duty (SDK `minimal_metadata_epoch_overdue`). This gate only
/// enforces the aad-visibility half, and only when soland can observe the
/// profile declaration in projected Realm meta and the discriminator on the
/// encrypted envelope; plaintext operations are unaffected.
pub(super) async fn validate_minimal_metadata_aad_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind_for_operation(operation);
    let is_message_or_reaction = matches!(
        kind,
        Some(
            arkret_wire::EventKind::MESSAGE_CREATE
                | arkret_wire::EventKind::REACTION_ADD
                | arkret_wire::EventKind::REACTION_REMOVE
        )
    );
    if !is_message_or_reaction {
        return Ok(());
    }
    // Only encrypted envelopes carry an aad-visibility discriminator; plaintext
    // operations are governed by other policy gates.
    let Some(envelope) = operation.payload.get("encrypted_content") else {
        return Ok(());
    };
    // Fail closed only for Realms we can positively confirm declared the
    // minimal-metadata profile; absent meta (target realm unknown) leaves the
    // obligation to the committer / client.
    let is_minimal = state
        .realms()
        .realm_metadata(operation.realm_id.as_str())
        .await
        .ok()
        .flatten()
        .is_some_and(|record| record.minimal_metadata_realm);
    if !is_minimal {
        return Ok(());
    }
    let Some(visibility) = minimal_metadata_aad_visibility(envelope) else {
        // Minimal-metadata Realm + encrypted envelope with no / unrecognised
        // discriminator → cannot prove it is `hidden`, so fail closed.
        return Err(
            "minimal_metadata_realm encrypted envelope requires aad_visibility_event_id=hidden",
        );
    };
    arkret_policy::enforce_minimal_metadata_aad(&visibility, true)
        .map_err(|_| "minimal_metadata_realm requires aad_visibility_event_id=hidden")
}

/// `encryption-and-audit.md` §§2.3.2 / 2.8 — reject an encrypted envelope that
/// declares an `aad_visibility_event_id` wider than the Realm ceiling.
///
/// This is the Realm-policy gate, orthogonal to the minimal-metadata profile
/// gate above: that one pins `hidden` for one profile, this one enforces
/// whatever ceiling the Realm declared through the `aad_visibility` component
/// of `ak.realm.policy_bundle`. An undeclared component is the `hidden`
/// ceiling, so `routing_digest` and `opaque_id` are only reachable once the
/// Realm declares them.
///
/// The judgement itself is [`arkret_models_crypto::AadVisibilityCeiling`], the
/// shared entry clients use, so the two sides cannot disagree about which
/// envelopes are admissible.
///
/// **MUST NOT** downgrade: an over-wide envelope is rejected with
/// `aad_visibility_policy_violation`, never rewritten to `hidden` and routed on.
/// A silent downgrade would leave the sender believing its disclosure level took
/// effect and the receiver believing the policy held — both wrong, and neither
/// observable.
pub(super) async fn validate_aad_visibility_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(envelope) = encrypted_envelope_of(operation) else {
        return Ok(());
    };
    let Ok(Some(record)) = state
        .realms()
        .realm_metadata(operation.realm_id.as_str())
        .await
    else {
        // Unknown Realm: this gate has no accepted bundle to read, and the
        // admission path rejects the operation on its own grounds.
        return Ok(());
    };
    let ceiling = arkret_models_crypto::AadVisibilityCeiling::from_declared(Some(
        record.aad_visibility_ceiling,
    ));
    let Some(visibility) = minimal_metadata_aad_visibility(envelope) else {
        // An encrypted envelope whose discriminator is absent or unrecognised
        // cannot be proven to sit under the ceiling.
        return Err(arkret_wire::ReasonCode::AAD_VISIBILITY_POLICY_VIOLATION);
    };
    ceiling
        .check(visibility)
        .map_err(|_| arkret_wire::ReasonCode::AAD_VISIBILITY_POLICY_VIOLATION)
}

/// The encrypted envelope an operation carries, if any.
///
/// Kept separate from the message/reaction narrowing of the minimal-metadata
/// gate: the aad_visibility ceiling governs **every** encrypted envelope this
/// service ingests or fans out, not one kind family.
fn encrypted_envelope_of(operation: &Operation) -> Option<&Value> {
    let envelope = operation
        .payload
        .get("encrypted_content")
        .or_else(|| operation.payload.get("encrypted_payload"))?;
    // Account Data has a separate, closed AEAD envelope and AAD transcript
    // (`models/account-data.md` section 3). It intentionally has no
    // `aad_visibility_event_id`: that discriminator belongs to the canonical
    // Realm E2EE content envelope from `encryption-and-audit.md` section 2.3.
    // Treating both domains as the same envelope makes every valid encrypted
    // Account Data value fail the Realm disclosure ceiling.
    if envelope.get("schema").and_then(Value::as_str)
        == Some("ak.schema.account_data_encrypted_value.v1")
    {
        return None;
    }
    Some(envelope)
}

/// SEC-08 — map the wire `aad_visibility_event_id` discriminator on an encrypted
/// envelope to the SDK [`arkret_models_crypto::encrypted_envelope::EncryptedEnvelopeAadVisibility`]
/// enum. Returns `None` when the field is missing or carries an unknown value, which the caller
/// treats as fail-closed for a minimal-metadata Realm.
pub(super) fn validate_disappearing_message_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !kinds::operation_is_message_create(operation) || operation.payload.get("expiry").is_none() {
        return Ok(());
    }
    validate_message_expiry_payload(operation)?;
    let expiry = operation
        .payload
        .get("expiry")
        .and_then(Value::as_object)
        .ok_or("disappearing_expiry_invalid")?;
    let ttl_ms = expiry
        .get("ttl_ms")
        .and_then(Value::as_u64)
        .ok_or("disappearing_expiry_ttl_missing")?;
    let trigger = expiry
        .get("trigger")
        .and_then(Value::as_str)
        .ok_or("disappearing_expiry_trigger_missing")?;
    let policy = {
        let projection = state.projections().snapshot();
        {
            projection
                .realm_disappearing_policy_cell_value(operation.realm_id.as_str())
                .cloned()
        }
    }
    .ok_or("disappearing_policy_unset")?;
    if !policy
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("disappearing_policy_disabled");
    }
    let max_ttl_ms = policy
        .get("max_ttl_ms")
        .and_then(Value::as_u64)
        .ok_or("disappearing_policy_max_ttl_missing")?;
    if ttl_ms > max_ttl_ms {
        return Err("disappearing_ttl_exceeds_policy");
    }
    let trigger_allowed = policy
        .get("allowed_triggers")
        .and_then(Value::as_array)
        .is_some_and(|triggers| triggers.iter().any(|value| value.as_str() == Some(trigger)));
    if !trigger_allowed {
        return Err("disappearing_trigger_not_allowed");
    }
    if !message_operation_is_encrypted(operation)
        && !policy
            .get("plaintext_realms_allowed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err("disappearing_plaintext_realm_not_allowed");
    }
    Ok(())
}

pub(in crate::routing::events::operations) fn minimal_metadata_aad_visibility(
    envelope: &Value,
) -> Option<arkret_models_crypto::encrypted_envelope::EncryptedEnvelopeAadVisibility> {
    use arkret_models_crypto::encrypted_envelope::EncryptedEnvelopeAadVisibility;
    // The discriminator lives at the envelope root; tolerate a nested
    // `envelope` wrapper as shown in the spec wire example.
    let raw = envelope
        .pointer("/aad_visibility_event_id")
        .or_else(|| envelope.pointer("/envelope/aad_visibility_event_id"))
        .and_then(Value::as_str)?;
    match raw {
        "hidden" => Some(EncryptedEnvelopeAadVisibility::Hidden),
        "routing_digest" => Some(EncryptedEnvelopeAadVisibility::RoutingDigest),
        "opaque_id" => Some(EncryptedEnvelopeAadVisibility::OpaqueId),
        _ => None,
    }
}
