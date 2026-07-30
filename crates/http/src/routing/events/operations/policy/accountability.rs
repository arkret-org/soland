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
    let frozen_basis = accountability_frozen_basis(state, operation)?;
    for issuer in accountable_principal_ids {
        let matching_batch = operations
            .iter()
            .filter(|candidate| {
                kinds::canonical_kind_string(candidate) == "ak.identity.accountability_grant"
                    && candidate.realm_id == operation.realm_id
                    && accountability_grant_operation_signed_by(candidate, &issuer)
                    && accountability_grant_matches(&candidate.payload, &issuer, &principal_id)
            })
            .collect::<Vec<_>>();
        // Security-barrier reduction is revoke-wins inside an atomic unit:
        // an active historical/batch value can never mask a matching terminal
        // value submitted alongside the profile.
        if matching_batch.iter().any(|candidate| {
            candidate
                .payload
                .get("grant_status")
                .and_then(Value::as_str)
                != Some("active")
        }) {
            return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
        }
        let batch_active = matching_batch.iter().any(|candidate| {
            let verification_time = frozen_basis
                .as_ref()
                .map(|(_, time)| *time)
                .or_else(|| accountability_grant_proof_time(&candidate.payload));
            verification_time.is_some_and(|time| {
                accountability_grant_value_active_for(
                    &candidate.payload,
                    &issuer,
                    &principal_id,
                    time,
                )
            })
        });
        let basis_active = frozen_basis.as_ref().is_some_and(|(basis, time)| {
            basis.values().any(|cell| {
                let arkret_state::lattice::CellState::Value(value) = cell else {
                    return false;
                };
                accountability_grant_value_active_for(value, &issuer, &principal_id, *time)
            })
        });
        if !batch_active && !basis_active {
            return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
        }
    }
    Ok(())
}

type FrozenAccountabilityBasis = (
    std::collections::BTreeMap<arkret_identifiers::CellRef, arkret_state::lattice::CellState>,
    chrono::DateTime<chrono::Utc>,
);

fn accountability_frozen_basis(
    state: &AppState,
    operation: &Operation,
) -> Result<Option<FrozenAccountabilityBasis>, &'static str> {
    let Some(leaves) = operation
        .payload
        .pointer("/seal_basis/leaves")
        .and_then(Value::as_array)
    else {
        return Ok(None);
    };
    if leaves.is_empty() {
        return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
    }
    let realm = arkret_identifiers::RealmId::new(operation.realm_id.to_string())
        .map_err(|_| arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING)?;
    let mut seal_ids = Vec::with_capacity(leaves.len());
    let mut verification_time: Option<chrono::DateTime<chrono::Utc>> = None;
    for leaf in leaves {
        let seal_id = leaf
            .as_str()
            .and_then(|value| arkret_identifiers::SealId::new(value.to_owned()).ok())
            .ok_or(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING)?;
        let seal = state
            .projections()
            .seal_by_id(&seal_id)
            .map_err(|_| arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING)?
            .ok_or(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING)?;
        if seal.realm_id != realm {
            return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
        }
        verification_time =
            Some(verification_time.map_or(seal.sealed_at, |at| at.max(seal.sealed_at)));
        seal_ids.push(seal_id);
    }
    let resolved = state
        .projections()
        .effective_state_at(&seal_ids, &realm)
        .map_err(|_| arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING)?;
    Ok(Some((
        resolved,
        verification_time.ok_or(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING)?,
    )))
}

fn accountability_grant_matches(value: &Value, issuer: &str, subject: &str) -> bool {
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
        ] {
            object.remove(field);
        }
    }
    serde_json::from_value::<
        arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload,
    >(grant_value)
    .is_ok_and(|grant| grant.issuer.as_str() == issuer && grant.subject.as_str() == subject)
}

fn accountability_grant_proof_time(value: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    value
        .pointer("/proof/created_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
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

pub(super) fn accountability_grant_value_active_for(
    value: &Value,
    issuer: &str,
    subject: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let mut grant_value = value.clone();
    if let Some(object) = grant_value.as_object_mut() {
        // Projection operations carry trusted envelope metadata beside the
        // schema-closed payload. Strip that transport context before decoding
        // the accountability grant itself, including for a grant and profile
        // admitted atomically in the same batch.
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
        ] {
            object.remove(field);
        }
    }
    let Ok(grant) = serde_json::from_value::<
        arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload,
    >(grant_value) else {
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
            arkret_wire::events::EventKind::MESSAGE_CREATE
                | arkret_wire::events::EventKind::REACTION_ADD
                | arkret_wire::events::EventKind::REACTION_REMOVE
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
