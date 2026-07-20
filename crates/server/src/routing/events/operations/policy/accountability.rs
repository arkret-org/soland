use super::*;

pub(super) fn validate_pin_scope_safety(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !kinds::canonical_kind_for_operation(operation)
        .is_some_and(arkret_core::events::kinds::is_pin_kind)
    {
        return Ok(());
    }
    let projection = state.projection.lock();
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
        return Err(arkret_core::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
    };
    let now = chrono::Utc::now();
    let accepted_events = state
        .events_store()
        .snapshot_all()
        .await
        .unwrap_or_default();
    for issuer in accountable_principal_ids {
        let in_batch = operations.iter().any(|candidate| {
            accountability_grant_operation_active_for(
                candidate,
                operation.realm_id.as_str(),
                &issuer,
                &principal_id,
                now,
            )
        });
        let accepted = accepted_events.iter().any(|record| {
            if record.kind != "ak.identity.accountability_grant" {
                return false;
            }
            if record.realm_id.as_deref() != Some(operation.realm_id.as_str()) {
                return false;
            }
            if !accountability_grant_envelope_signed_by(record, &issuer) {
                return false;
            }
            let payload = record.envelope.get("payload").unwrap_or(&record.envelope);
            accountability_grant_value_active_for(payload, &issuer, &principal_id, now)
        });
        if !in_batch && !accepted {
            return Err(arkret_core::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
        }
    }
    Ok(())
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

pub(super) fn accountability_grant_operation_active_for(
    operation: &Operation,
    realm_id: &str,
    issuer: &str,
    subject: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    kinds::canonical_kind_string(operation) == "ak.identity.accountability_grant"
        && operation.realm_id.as_str() == realm_id
        && accountability_grant_operation_signed_by(operation, issuer)
        && accountability_grant_value_active_for(&operation.payload, issuer, subject, now)
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
    record: &soland_storage::CanonicalEventRecord,
    issuer: &str,
) -> bool {
    record
        .envelope
        .get("executed_by")
        .and_then(Value::as_str)
        .unwrap_or(record.actor_id.as_str())
        == issuer
}

pub(super) fn accountability_grant_body(value: &Value) -> &Value {
    value
        .get("grant")
        .filter(|grant| grant.is_object())
        .or_else(|| value.get("value").filter(|grant| grant.is_object()))
        .or_else(|| value.get("object").filter(|grant| grant.is_object()))
        .unwrap_or(value)
}

pub(super) fn accountability_grant_value_active_for(
    value: &Value,
    issuer: &str,
    subject: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let body = accountability_grant_body(value);
    if body.get("issuer").and_then(Value::as_str) != Some(issuer) {
        return false;
    }
    if body
        .get("subject")
        .or_else(|| body.get("subject_id"))
        .or_else(|| body.get("principal_id"))
        .and_then(Value::as_str)
        != Some(subject)
    {
        return false;
    }
    if body
        .get("grant_status")
        .or_else(|| body.get("status"))
        .and_then(Value::as_str)
        .is_some_and(|status| !matches!(status, "active" | "granted"))
    {
        return false;
    }
    let Some(not_before) = accountability_grant_time(body, "not_before")
        .or_else(|| accountability_grant_time(body, "issued_at"))
    else {
        return false;
    };
    let Some(expires_at) = accountability_grant_time(body, "expires_at") else {
        return false;
    };
    not_before <= now && now <= expires_at
}

pub(super) fn accountability_grant_time(
    value: &Value,
    field: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|parsed| parsed.with_timezone(&chrono::Utc))
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
            arkret_core::events::EventKind::MESSAGE_CREATE
                | arkret_core::events::EventKind::REACTION_ADD
                | arkret_core::events::EventKind::REACTION_REMOVE
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
        .realm_meta_store()
        .get(operation.realm_id.as_str())
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
/// envelope to the SDK [`arkret_core::EncryptedEnvelopeAadVisibility`] enum. Returns `None`
/// when the field is missing or carries an unknown value, which the caller
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
        let projection = state.projection.lock();
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
            .get("allow_plaintext_realms")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err("disappearing_plaintext_realm_not_allowed");
    }
    Ok(())
}

pub(in crate::routing::events::operations) fn minimal_metadata_aad_visibility(
    envelope: &Value,
) -> Option<arkret_core::EncryptedEnvelopeAadVisibility> {
    use arkret_core::EncryptedEnvelopeAadVisibility;
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
