use arkret_event_draft::Operation;
use arkret_models_collaboration::governance::membership_invite::{
    InviteCreatePayload, validate_invite_create_wire_keys,
};
use arkret_schema::event_payload_validator_catalog;
use serde_json::Value;

use super::*;

pub(crate) fn validate_invite_create_payload(operation: &Operation) -> Result<(), &'static str> {
    let wire_payload = invite_create_wire_payload(&operation.payload);
    event_payload_validator_catalog()
        .map_err(|_| "operation payload validator catalog is unavailable")?
        .validate_payload("ak.invite.create", &wire_payload)
        .map_err(|_| "operation payload violates SDK artifact schema")?;
    validate_invite_create_wire_keys(&wire_payload)
        .map_err(|_| "operation payload carries unsupported fields")?;
    let payload: InviteCreatePayload = serde_json::from_value(wire_payload)
        .map_err(|_| "operation payload violates SDK artifact schema")?;
    payload
        .invite_delivery_target
        .validate()
        .map_err(|_| "invite_delivery_target is invalid")?;
    Ok(())
}

fn invite_create_wire_payload(payload: &Value) -> Value {
    projection_context_stripped_payload(payload)
}

pub(crate) fn projection_context_stripped_payload(payload: &Value) -> Value {
    let mut wire_payload = payload.clone();
    if let Some(object) = wire_payload.as_object_mut() {
        for field in [
            "event_id",
            "sender",
            "hlc",
            "executed_by",
            "authorization_ref",
            "seal_ref",
            "seal_basis",
            "preconditions",
            "effects",
            "accepted_event_id",
            "envelope_causal_refs",
            "canonical_event_digest",
        ] {
            object.remove(field);
        }
    }
    wire_payload
}

pub(crate) fn validate_key_backup_active_series_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    serde_json::from_value::<arkret_models_collaboration::events_payloads::KeyBackupActiveSeries>(
        projection_context_stripped_payload(&operation.payload),
    )
    .map(|_| ())
    .map_err(|_| "ak.key_backup.active_series payload violates SDK artifact schema")
}

pub(crate) fn validate_invite_third_party_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let payload = operation
        .payload
        .as_object()
        .ok_or("ak.invite.third_party payload must be an object")?;
    let invite = payload.get("invite").and_then(Value::as_object);
    let invite_id = invite_field(payload, invite, "invite_id", "id")
        .ok_or("ak.invite.third_party requires invite_id")?;
    if arkret_identifiers::InviteId::new(invite_id).is_err() {
        return Err("ak.invite.third_party invite_id must be ak:invite:<uuidv7>");
    }
    let realm_id = invite_field(payload, invite, "realm_id", "realm_id")
        .unwrap_or_else(|| operation.realm_id.to_string());
    if realm_id != operation.realm_id.as_str() {
        return Err("ak.invite.third_party realm_id must match envelope realm_id");
    }
    let inviter = invite_field(payload, invite, "inviter", "inviter")
        .ok_or("ak.invite.third_party requires inviter")?;
    if arkret_identifiers::Did::new(inviter).is_err() {
        return Err("ak.invite.third_party inviter must be a DID");
    }
    let third_party_id = invite_value(payload, invite, "third_party_id")
        .and_then(Value::as_object)
        .ok_or("ak.invite.third_party third_party_id must be an object")?;
    for forbidden in ["token", "plaintext_token", "email", "phone", "address"] {
        if third_party_id.contains_key(forbidden) {
            return Err("ak.invite.third_party must not carry plaintext token or 3PID");
        }
    }
    let service_id = third_party_id
        .get("verification_service_id")
        .and_then(Value::as_str)
        .ok_or("third_party_id.verification_service_id is required")?;
    if arkret_identifiers::Did::new(service_id.to_owned()).is_err() {
        return Err("third_party_id.verification_service_id must be a DID");
    }
    if third_party_id
        .get("verification_public_key")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err("third_party_id.verification_public_key is required");
    }
    if let Some(token_commitment) = third_party_id
        .get("token_commitment")
        .and_then(Value::as_str)
        && arkret_identifiers::Hash::new(token_commitment.to_owned()).is_err()
    {
        return Err("third_party_id.token_commitment must be a hash");
    }
    if third_party_id.get("lookup_table_ref").is_none()
        && third_party_id.get("token_commitment").is_none()
    {
        return Err("third_party_id requires token_commitment or lookup_table_ref");
    }
    let expires_at = invite_field(payload, invite, "expires_at", "expires_at")
        .ok_or("ak.invite.third_party requires expires_at")?;
    if arkret_canonical::validate_timestamp_canonical(&expires_at).is_err() {
        return Err("ak.invite.third_party expires_at must be a canonical timestamp");
    }
    Ok(())
}

pub(crate) fn validate_invite_claim_payload(operation: &Operation) -> Result<(), &'static str> {
    let payload = operation
        .payload
        .as_object()
        .ok_or("ak.invite.claim payload must be an object")?;
    let invite_id =
        payload_string(payload, "invite_id").ok_or("ak.invite.claim requires invite_id")?;
    if arkret_identifiers::InviteId::new(invite_id).is_err() {
        return Err("ak.invite.claim invite_id must be ak:invite:<uuidv7>");
    }
    let subject_id =
        payload_string(payload, "subject_id").ok_or("ak.invite.claim requires subject_id")?;
    if arkret_identifiers::Did::new(subject_id.clone()).is_err() {
        return Err("ak.invite.claim subject_id must be a DID");
    }
    let token_commitment = payload_string(payload, "token_commitment")
        .ok_or("ak.invite.claim requires token_commitment")?;
    if arkret_identifiers::Hash::new(token_commitment).is_err() {
        return Err("ak.invite.claim token_commitment must be a hash");
    }
    let claim_nonce =
        payload_string(payload, "claim_nonce").ok_or("ak.invite.claim requires claim_nonce")?;
    let binding: arkret_models_collaboration::governance::membership_invite::InviteClaimBindingProof = serde_json::from_value(
        payload
            .get("binding_proof")
            .cloned()
            .ok_or("ak.invite.claim binding_proof is required")?,
    )
    .map_err(|_| "ak.invite.claim binding_proof is invalid")?;
    binding
        .validate()
        .map_err(|_| "ak.invite.claim binding_proof is invalid")?;
    if binding.subject_id.as_str() != subject_id {
        return Err("binding_proof.subject_id must match subject_id");
    }
    if binding.realm_id != operation.realm_id {
        return Err("binding_proof.realm_id must match envelope realm_id");
    }
    if binding.audience
        != arkret_models_collaboration::governance::membership_invite::INVITE_CLAIM_AUDIENCE
    {
        return Err("binding_proof.audience must be arkret.invite.claim");
    }
    if binding.claim_nonce != claim_nonce {
        return Err("binding_proof.claim_nonce must match claim_nonce");
    }
    let subject_proof: arkret_models_collaboration::governance::membership_invite::InviteSubjectProof = serde_json::from_value(
        payload
            .get("subject_proof")
            .cloned()
            .ok_or("ak.invite.claim subject_proof is required")?,
    )
    .map_err(|_| "ak.invite.claim subject_proof is invalid")?;
    subject_proof
        .validate()
        .map_err(|_| "ak.invite.claim subject_proof is invalid")?;
    Ok(())
}

pub(crate) fn validate_invite_ref_payload(operation: &Operation) -> Result<(), &'static str> {
    let payload = operation
        .payload
        .as_object()
        .ok_or("invite reference payload must be an object")?;
    let invite_id =
        payload_string(payload, "invite_id").ok_or("invite reference requires invite_id")?;
    if arkret_identifiers::InviteId::new(invite_id).is_err() {
        return Err("invite reference invite_id must be ak:invite:<uuidv7>");
    }
    if let Some(reason) = payload.get("reason")
        && !reason.is_string()
    {
        return Err("invite reference reason must be a string");
    }
    validate_operation_payload_against_sdk_artifact(operation)?;
    Ok(())
}

fn invite_field(
    payload: &serde_json::Map<String, Value>,
    invite: Option<&serde_json::Map<String, Value>>,
    payload_field: &str,
    invite_field: &str,
) -> Option<String> {
    invite
        .and_then(|object| object.get(invite_field))
        .or_else(|| payload.get(payload_field))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn invite_value<'a>(
    payload: &'a serde_json::Map<String, Value>,
    invite: Option<&'a serde_json::Map<String, Value>>,
    field: &str,
) -> Option<&'a Value> {
    invite
        .and_then(|object| object.get(field))
        .or_else(|| payload.get(field))
}

fn payload_string(payload: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn validate_message_operation_payload(operation: &Operation) -> Result<(), &'static str> {
    if soland_services::operation_semantics::operation_is_message_create(operation) {
        if operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err("message create requires strand_id");
        }
        let track_name = operation
            .payload
            .get("track_name")
            .and_then(Value::as_str)
            .ok_or("message create requires track_name")?;
        validate_read_scope_track(track_name)?;
        validate_message_expiry_payload(operation)?;
    }
    let encrypted = operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || operation.payload.get("encrypted_content").is_some();
    if encrypted {
        // The encrypted content envelope SHAPE is owned by the registered spec schema
        // `ak.schema.encrypted_envelope.v1` (referenced from
        // `message_create_payload` and enforced via
        // `event_payload_validator_catalog()?.validate_payload`). The spec
        // schema is the single source of truth — we only assert presence here
        // and never re-derive a divergent hand-written envelope shape.
        if operation.payload.get("encrypted_content").is_none()
            && operation.payload.get("content").is_none()
        {
            return Err("encrypted message operation requires content envelope");
        }
    } else if let Some(content) = operation.payload.get("content") {
        validate_content_blocks(content)?;
        validate_mentions(content)?;
        validate_audience_mentions(content)?;
    }
    Ok(())
}

pub(crate) fn validate_message_expiry_payload(operation: &Operation) -> Result<(), &'static str> {
    let Some(expiry) = operation.payload.get("expiry") else {
        return Ok(());
    };
    let Some(object) = expiry.as_object() else {
        return Err("ak.message.create.payload.expiry must be an object");
    };
    for key in object.keys() {
        if !["ttl_ms", "trigger", "grace_ms"].contains(&key.as_str()) {
            return Err("ak.message.create.payload.expiry has unknown field");
        }
    }
    if object
        .get("ttl_ms")
        .and_then(Value::as_u64)
        .is_none_or(|value| value == 0)
    {
        return Err("ak.message.create.payload.expiry requires positive ttl_ms");
    }
    match object.get("trigger").and_then(Value::as_str) {
        Some("on_send" | "on_first_read" | "on_last_read") => {}
        _ => return Err("ak.message.create.payload.expiry trigger is invalid"),
    }
    if object
        .get("grace_ms")
        .is_some_and(|value| value.as_u64().is_none())
    {
        return Err("ak.message.create.payload.expiry grace_ms must be an integer");
    }
    Ok(())
}

pub(crate) fn validate_account_data_set_payload(operation: &Operation) -> Result<(), &'static str> {
    let key = operation
        .payload
        .get("key")
        .and_then(Value::as_str)
        .ok_or("account_data.set requires key")?;
    crate::routing::account_data_encryption::validate_encrypted_account_data_key(key)
        .map_err(|error| error.message())?;
    if operation.payload.get("tombstone").is_some() {
        return Ok(());
    }
    let owner = operation
        .payload
        .get("owner")
        .and_then(Value::as_str)
        .ok_or("account_data.set requires owner")?;
    crate::routing::account_data_encryption::validate_encrypted_account_data_value_for_actor(
        key,
        &operation.payload,
        Some(owner),
    )
    .map_err(|error| error.message())
}

pub(crate) fn validate_read_receipt_policy_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let wire_payload = projection_context_stripped_payload(&operation.payload);
    let payload = wire_payload
        .as_object()
        .ok_or("ak.realm.read_receipt_policy payload must be an object")?;
    if payload.is_empty() {
        return Err("ak.realm.read_receipt_policy payload must set at least one field");
    }
    serde_json::from_value::<arkret_models_collaboration::objects::read_receipts::ReadReceiptPolicy>(wire_payload)
        .map_err(|_| "ak.realm.read_receipt_policy payload violates SDK artifact schema")?;
    Ok(())
}

pub(crate) fn validate_realm_inheritance_policy_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let wire_payload = projection_context_stripped_payload(&operation.payload);
    let payload: arkret_models_collaboration::events_payloads::RealmInheritancePolicyPayload =
        serde_json::from_value(wire_payload)
            .map_err(|_| "ak.realm.inheritance_policy payload violates SDK artifact schema")?;
    if payload.mode != "narrow_only" {
        return Err("ak.realm.inheritance_policy mode must be narrow_only");
    }
    let has_inherits = payload.inherits.membership.is_some()
        || payload.inherits.capability_bundles.is_some()
        || payload.inherits.policy_rules.is_some()
        || payload.inherits.notification_defaults.is_some();
    if !has_inherits {
        return Err("ak.realm.inheritance_policy inherits must not be empty");
    }
    validate_unique_non_empty_strings(
        payload.inherits.capability_bundles.as_deref(),
        "ak.realm.inheritance_policy capability_bundles must be unique non-empty strings",
    )?;
    validate_unique_non_empty_strings(
        payload.inherits.policy_rules.as_deref(),
        "ak.realm.inheritance_policy policy_rules must be unique non-empty strings",
    )?;
    if let Some(max_depth) = payload.max_depth {
        if max_depth == 0 {
            return Err("ak.realm.inheritance_policy max_depth must be >= 1");
        }
        if max_depth > u64::from(arkret_models_collaboration::governance::realm_governance::RealmInheritancePolicy::MAX_DEPTH_CAP) {
            return Err("ak.realm.inheritance_policy max_depth exceeds v1 cap");
        }
    }
    Ok(())
}

fn validate_unique_non_empty_strings(
    values: Option<&[String]>,
    message: &'static str,
) -> Result<(), &'static str> {
    let Some(values) = values else {
        return Ok(());
    };
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if value.trim().is_empty() || !seen.insert(value) {
            return Err(message);
        }
    }
    Ok(())
}

pub(crate) fn validate_read_marker_payload(operation: &Operation) -> Result<(), &'static str> {
    let read_scope = operation
        .payload
        .get("read_scope")
        .and_then(|value| value.as_object())
        .ok_or("read marker read_scope must be an object")?;
    for key in read_scope.keys() {
        if !["kind", "container_ref", "track_name"].contains(&key.as_str()) {
            return Err("read marker read_scope has unknown field");
        }
    }
    let kind = read_scope
        .get("kind")
        .and_then(|value| value.as_str())
        .ok_or("read marker read_scope.kind is required")?;
    match kind {
        "realm" => {
            if read_scope
                .get("container_ref")
                .is_some_and(|value| !value.is_null())
            {
                return Err("read marker read_scope.container_ref must be omitted for realm");
            }
            if read_scope
                .get("track_name")
                .is_some_and(|value| !value.is_null())
            {
                return Err("read marker read_scope.track_name requires kind strand");
            }
        }
        "circle" | "space" | "strand" | "thread" => {
            let reference = read_scope
                .get("container_ref")
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or("read marker read_scope.container_ref is required")?;
            let expected_prefix = match kind {
                "circle" => "ak:circle:",
                "space" => "ak:space:",
                "strand" => "ak:strand:",
                "thread" => "ak:message:",
                _ => unreachable!(),
            };
            if !reference.starts_with(expected_prefix) {
                return Err("read marker read_scope.ref has invalid typed id kind");
            }
            if kind != "strand"
                && read_scope
                    .get("track_name")
                    .is_some_and(|value| !value.is_null())
            {
                return Err("read marker read_scope.track_name requires kind strand");
            }
        }
        "view" | "message" | "morph" => {
            return Err("read marker read_scope.kind is receipt-only");
        }
        "strand_discussion" | "strand_synthesis" => {
            return Err("read marker read_scope.kind removed; use strand plus track_name");
        }
        _ => return Err("read marker read_scope.kind is invalid"),
    }
    if let Some(track) = read_scope
        .get("track_name")
        .and_then(|value| value.as_str())
    {
        if kind != "strand" {
            return Err("read marker read_scope.track_name requires kind strand");
        }
        validate_read_scope_track(track)?;
    }
    let position = operation
        .payload
        .get("position")
        .and_then(|value| value.as_object())
        .ok_or("read marker position must be an object")?;
    if position
        .get("event_id")
        .and_then(|value| value.as_str())
        .is_none_or(|value| !value.starts_with("ak:event:"))
    {
        return Err("read marker position.event_id is invalid");
    }
    let hlc = position
        .get("hlc")
        .and_then(|value| value.as_str())
        .ok_or("read marker position.hlc is required")?;
    validate_read_cursor_hlc(hlc)?;
    Ok(())
}

pub(crate) fn validate_history_visibility_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let value = operation
        .payload
        .get("value")
        .and_then(Value::as_str)
        .ok_or("ak.realm.history_visibility requires string value")?;
    match value {
        "world_readable" | "shared" | "invited" | "joined" => Ok(()),
        "restricted" => {
            if operation
                .payload
                .get("restricted_policy_digest")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest.starts_with("sha256:"))
            {
                Ok(())
            } else {
                Err("history_sharing_policy_missing")
            }
        }
        _ => Err("ak.realm.history_visibility value is unknown"),
    }
}

pub(crate) fn validate_observed_dots_payload(operation: &Operation) -> Result<(), &'static str> {
    if operation
        .payload
        .get("observed_dots")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|dots| !dots.is_empty())
    {
        Ok(())
    } else {
        Err("consent revoke observed_dots must be a non-empty array")
    }
}

pub(crate) fn validate_conflict_repair_payload(operation: &Operation) -> Result<(), &'static str> {
    let cell_id = operation
        .payload
        .get("cell_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("conflict repair requires cell_id")?;
    if arkret_identifiers::CellRef::new(cell_id.to_owned()).is_err() {
        return Err(
            "conflict repair cell_id must use canonical ak:cell:ak.component.*.v<n>:<subject> form",
        );
    }
    let heads = operation
        .payload
        .get("conflict_heads")
        .and_then(serde_json::Value::as_array)
        .ok_or("conflict repair requires conflict_heads")?;
    if heads.len() < 2 {
        return Err("conflict repair requires at least two conflict_heads");
    }
    if heads
        .iter()
        .any(|head| head.as_str().is_none_or(|value| value.trim().is_empty()))
    {
        return Err("conflict repair heads must be non-empty strings");
    }
    let recovery = operation
        .payload
        .get("recovery_capability_ref")
        .and_then(serde_json::Value::as_str)
        .ok_or("conflict repair requires recovery_capability_ref")?;
    if recovery.trim().is_empty() {
        return Err("conflict repair recovery_capability_ref must be non-empty");
    }
    let witness = operation
        .payload
        .get("state_witness_ref")
        .or_else(|| operation.payload.get("state_witness"))
        .and_then(serde_json::Value::as_str)
        .ok_or("conflict repair requires state_witness_ref")?;
    if witness.trim().is_empty() {
        return Err("conflict repair state_witness_ref must be non-empty");
    }
    if operation.payload.get("winner_value").is_none() {
        return Err("conflict repair requires winner_value");
    }
    Ok(())
}

pub(crate) fn validate_read_scope_track(track: &str) -> Result<(), &'static str> {
    let mut bytes = track.bytes();
    let Some(first) = bytes.next() else {
        return Err("read marker read_scope.track_name is invalid");
    };
    if !first.is_ascii_lowercase()
        || track.len() > 64
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("read marker read_scope.track_name is invalid");
    }
    Ok(())
}

fn validate_read_cursor_hlc(hlc: &str) -> Result<(), &'static str> {
    let parts = hlc.split('-').collect::<Vec<_>>();
    if parts.len() != 3
        || parts[0].len() != 12
        || parts[1].len() != 4
        || parts[2].len() != 8
        || !parts.iter().all(|part| {
            part.bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    {
        return Err("read marker position.hlc is invalid");
    }
    Ok(())
}
/// `relation.md` admission guard for `ak.relation.create` / `.update` /
/// `.tombstone`, covering two reducer-managed invariants:
///
/// 1. **`effective_scope` is reducer-stamped** (§2 table): the actor MUST NOT submit it; the
///    reducer materialises it from `scope_circle_id`. Any actor-supplied `effective_scope` is
///    `schema_violation` (`effective_scope_reducer_managed`).
/// 2. **derived-edge single-source** (§3.2): `watches` (truth source
///    `ak.component.strand.watch.v1`, write path `ak.strand.watch.set`) and Board/List `contains`
///    (truth source `ak.space.parent` / `ak.strand.move`) are derived projections; a direct
///    `ak.relation.*` on them MUST `schema_violation`. The container `contains` shape is identified
///    by a Space `from_ref` (`ak:space:…`); a `Strand -> Strand` `contains` stays a
///    directly-writable weak relation (§3.2 line 85) and is not blocked.
pub(crate) fn validate_relation_operation_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    if operation.payload.get("effective_scope").is_some()
        || operation
            .payload
            .get("relation")
            .and_then(Value::as_object)
            .is_some_and(|relation| relation.contains_key("effective_scope"))
    {
        return Err("effective_scope_reducer_managed");
    }
    let relation_kind = ["relation_kind", "kind"]
        .iter()
        .find_map(|field| operation.payload.get(*field).and_then(Value::as_str));
    let Some(relation_kind) = relation_kind else {
        return Ok(());
    };
    let from_ref = ["from_ref", "from"]
        .iter()
        .find_map(|field| operation.payload.get(*field).and_then(Value::as_str));
    arkret_models_collaboration::objects::relation::validate_relation_direct_write(
        relation_kind,
        from_ref,
    )
}

pub(crate) fn validate_morph_update_payload(operation: &Operation) -> Result<(), &'static str> {
    let Some(patch) = operation.payload.get("patch").and_then(Value::as_object) else {
        return Ok(());
    };
    if patch.contains_key("content") && patch.contains_key("encrypted_content") {
        return Err("morph_content_carrier_conflict");
    }
    if patch.contains_key("metadata") && patch.contains_key("encrypted_metadata") {
        return Err("morph_metadata_carrier_conflict");
    }
    if patch.contains_key("schema_refs") {
        return Err("morph_schema_refs_evolution_unauthorized");
    }
    reject_forbidden_morph_update_patch(patch)?;
    Ok(())
}

/// `morph.md` §2 / §4 forbidden-wire guard for `ak.morph.update`:
/// - `morph_kind` is immutable after `ak.morph.create` (`morph_kind_immutable`).
/// - the stage axis (`stage` / `stage_changed_at`) changes only via `ak.morph.stage.set`; writing
///   it through an update patch is `schema_violation`.
/// - the reserved business-field set (`fields.stage` / `fields.lifecycle` / `fields.progress_state`
///   / `fields.stage_reason`) is forbidden-wire in any representation (dotted `fields.<name>` path
///   or whole-`fields` object replace).
fn reject_forbidden_morph_update_patch(
    patch: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    const FORBIDDEN_FIELD: &[&str] = &["stage", "lifecycle", "progress_state", "stage_reason"];
    for (path, value) in patch {
        if path == "morph_kind" {
            return Err("morph_kind_immutable");
        }
        if path == "stage" || path == "stage_changed_at" {
            return Err("morph_stage_patch_forbidden");
        }
        if let Some(field) = path.strip_prefix("fields.")
            && FORBIDDEN_FIELD.contains(&field)
        {
            return Err("morph_forbidden_field_patch");
        }
        if path == "fields"
            && let Some(map) = patch_set_value(value).and_then(Value::as_object)
            && FORBIDDEN_FIELD.iter().any(|field| map.contains_key(*field))
        {
            return Err("morph_forbidden_field_patch");
        }
    }
    Ok(())
}

/// Decode a field-patch entry to the value it sets, or `None` for unset /
/// unknown ops. Mirrors the reducer's `patch_action`: a bare value (no `$op`
/// envelope) is itself the set value; `{"$op":"set"|"add","value":…}` carries
/// it explicitly; `unset`/`remove`/unknown set nothing. Kept inline so the
/// admission layer does not depend on reducer-internal helpers.
fn patch_set_value(value: &Value) -> Option<&Value> {
    match value
        .as_object()
        .and_then(|object| object.get("$op").and_then(Value::as_str))
    {
        None => Some(value),
        Some("set" | "add") => value.get("value"),
        Some(_) => None,
    }
}

pub(crate) fn validate_morph_create_payload(operation: &Operation) -> Result<(), &'static str> {
    let Some(object) = operation.payload.get("object").and_then(Value::as_object) else {
        return Err("morph_create_object_invalid");
    };
    if object.contains_key("content") && object.contains_key("encrypted_content") {
        return Err("morph_content_carrier_conflict");
    }
    if object.contains_key("metadata") && object.contains_key("encrypted_metadata") {
        return Err("morph_metadata_carrier_conflict");
    }
    if let Some(metadata) = object.get("metadata").and_then(Value::as_object) {
        reject_morph_metadata_business_fields(metadata)?;
    }
    Ok(())
}

/// Current-v1 View definitions removed presentation-local write policy and
/// make lifecycle timestamps reducer-owned. Admission rejects the retired
/// fields instead of silently preserving them in generic JSON maps.
pub(crate) fn validate_view_payload(operation: &Operation) -> Result<(), &'static str> {
    fn contains_retired_field(value: &Value) -> bool {
        match value {
            Value::Object(fields) => fields.iter().any(|(key, value)| {
                matches!(
                    key.as_str(),
                    "selection_policy" | "page_size" | "wip_limit_enforcement" | "state_changed_at"
                ) || contains_retired_field(value)
            }),
            Value::Array(values) => values.iter().any(contains_retired_field),
            _ => false,
        }
    }

    for field in ["object", "definition", "patch"] {
        if let Some(value) = operation.payload.get(field) {
            if contains_retired_field(value) {
                return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
            }
            if let Some(state) = value.get("state")
                && !matches!(state.as_str(), Some("active" | "tombstoned"))
            {
                return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
            }
        }
    }
    Ok(())
}

fn reject_morph_metadata_business_fields(
    metadata: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    for field in [
        "id",
        "schema",
        "realm_id",
        "scope_circle_id",
        "schema_refs",
        "morph_kind",
        "facets",
        "fields",
        "stage",
        "stage_changed_at",
        "state",
        "state_changed_at",
        "created_by",
        "created_at",
        "updated_by",
        "updated_at",
        "content",
        "encrypted_content",
        "encrypted_payload",
    ] {
        if metadata.contains_key(field) {
            return Err("morph_metadata_business_field");
        }
    }
    Ok(())
}

pub(crate) fn validate_morph_schema_migrate_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let from_schema_refs = collect_nonempty_unique_string_array(
        operation.payload.get("from_schema_refs"),
        "from_schema_refs",
    )?;
    let to_schema_refs = collect_nonempty_unique_string_array(
        operation.payload.get("to_schema_refs"),
        "to_schema_refs",
    )?;
    match operation
        .payload
        .get("compatibility_class")
        .and_then(serde_json::Value::as_str)
    {
        Some("additive") => {
            let empty_fields =
                arkret_models_collaboration::events_payloads::MorphSchemaFieldSet::new();
            arkret_models_collaboration::events_payloads::morph_schema_refs_additive_only(
                &from_schema_refs,
                &to_schema_refs,
                &empty_fields,
                &empty_fields,
            )
            .map_err(|_| "morph_schema_refs_transformation_unsupported")
        }
        // `morph.md` §4.1 S3 — breaking / transformation are NOT statically
        // rejected here: whether they are admissible depends on the Realm
        // declaring `ak.profile.morph.schema_migration_transformations.v1`,
        // which is only visible to the state-aware preflight
        // (`ProjectionState::check_morph_schema_migrate`). The static layer
        // only checks shape: a transformation migration MUST carry a
        // non-empty `transformation_rules[]`.
        Some("breaking") => Ok(()),
        Some("transformation") => {
            let has_rules = operation
                .payload
                .get("transformation_rules")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|rules| !rules.is_empty());
            if has_rules {
                Ok(())
            } else {
                Err("unsupported_transformation_rule")
            }
        }
        _ => Err("morph schema_migrate compatibility_class is invalid"),
    }
}

fn collect_nonempty_unique_string_array(
    value: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<Vec<String>, &'static str> {
    let Some(items) = value.and_then(serde_json::Value::as_array) else {
        return Err(match field {
            "from_schema_refs" => "from_schema_refs must be a non-empty string array",
            "to_schema_refs" => "to_schema_refs must be a non-empty string array",
            _ => "field must be a non-empty string array",
        });
    };
    if items.is_empty() {
        return Err(match field {
            "from_schema_refs" => "from_schema_refs must be a non-empty string array",
            "to_schema_refs" => "to_schema_refs must be a non-empty string array",
            _ => "field must be a non-empty string array",
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        let Some(text) = item.as_str().filter(|text| !text.trim().is_empty()) else {
            return Err(match field {
                "from_schema_refs" => "from_schema_refs must contain only non-empty strings",
                "to_schema_refs" => "to_schema_refs must contain only non-empty strings",
                _ => "field must contain only non-empty strings",
            });
        };
        if !seen.insert(text) {
            return Err(match field {
                "from_schema_refs" => "from_schema_refs must be unique",
                "to_schema_refs" => "to_schema_refs must be unique",
                _ => "field must be unique",
            });
        }
        values.push(text.to_owned());
    }
    Ok(values)
}

pub(crate) fn validate_cross_signing_reset_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let reset: arkret_models_identity::CrossSigningResetPayload =
        serde_json::from_value(projection_context_stripped_payload(&operation.payload))
            .map_err(|_| "cross_signing reset payload violates reset profile")?;
    reset
        .validate_structure()
        .map_err(|_| "cross_signing reset payload violates reset profile")?;
    let now = chrono::Utc::now();
    let skew = (now - *reset.issued_at()).num_seconds().abs();
    if skew > CROSS_SIGNING_RESET_MAX_CLOCK_SKEW_SECONDS {
        return Err("cross_signing_reset_clock_skew_exceeded");
    }
    Ok(())
}

pub(crate) fn validate_device_authorize_payload(operation: &Operation) -> Result<(), &'static str> {
    let payload: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload =
        serde_json::from_value(device_authorize_wire_payload(&operation.payload))
            .map_err(|_| "ak.device.authorize payload violates SDK artifact schema")?;
    payload.validate_authorization_binding_one_of()
}

fn device_authorize_wire_payload(payload: &Value) -> Value {
    projection_context_stripped_payload(payload)
}

pub(crate) fn validate_cross_signing_reset_replay_batch(
    operations: &[Operation],
) -> Result<(), &'static str> {
    let mut seen = std::collections::BTreeSet::new();
    for operation in operations {
        if kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::events::EventKind::CROSS_SIGNING_RESET)
        {
            continue;
        }
        let Some(principal_id) = operation
            .payload
            .get("principal_id")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let Some(previous_generation) = operation
            .payload
            .get("previous_generation")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        if !seen.insert((principal_id, previous_generation)) {
            return Err("cross_signing_reset_replay");
        }
    }
    Ok(())
}

pub fn validate_encrypted_payload_envelope(
    content: &serde_json::Value,
) -> Result<(), &'static str> {
    arkret_models_crypto::parse_and_validate_encrypted_envelope(content.clone())
        .map(|_| ())
        .map_err(|_| "encrypted content envelope violates SDK schema")
}

#[cfg(test)]
mod tests {
    use arkret_event_draft::Operation;
    use serde_json::json;

    use super::{
        projection_context_stripped_payload, validate_encrypted_payload_envelope,
        validate_invite_create_payload, validate_message_expiry_payload,
    };

    fn message_operation(expiry: serde_json::Value) -> Operation {
        Operation::create(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-0000000000e1".to_owned(),
            )
            .unwrap(),
            arkret_identifiers::RealmId::new("ak:realm:01904100-0000-7000-8000-cfc039892036")
                .unwrap(),
            arkret_wire::events::EventKind::MESSAGE_CREATE,
            json!({
                "content": {"kind": "ak.content.text", "body": "secret"},
                "expiry": expiry
            }),
        )
    }

    #[test]
    fn message_expiry_accepts_current_wire_shape() {
        let operation = message_operation(json!({
            "ttl_ms": 60_000,
            "trigger": "on_send",
            "grace_ms": 1_000
        }));

        assert_eq!(validate_message_expiry_payload(&operation), Ok(()));
    }

    #[test]
    fn message_expiry_rejects_removed_seal_hlc() {
        let operation = message_operation(json!({
            "ttl_ms": 60_000,
            "trigger": "on_send",
            "grace_ms": 1_000,
            "seal_hlc": "019041000000-0001-00000001"
        }));

        assert_eq!(
            validate_message_expiry_payload(&operation),
            Err("ak.message.create.payload.expiry has unknown field")
        );
    }

    #[test]
    fn invite_create_validation_ignores_projection_context() {
        let operation = Operation::create(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-0000000000e2".to_owned(),
            )
            .unwrap(),
            arkret_identifiers::RealmId::new("ak:realm:01904100-0000-7000-8000-cfc039892036")
                .unwrap(),
            arkret_wire::events::EventKind::INVITE_CREATE,
            json!({
                "invite_id": "ak:invite:01904100-0000-7000-8000-0000000000e2",
                "invitee": "did:web:bob.example",
                "invite_delivery_target": {
                    "recipient_service_id": "did:webvh:z6mkfixture:bob.example"
                },
                "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "expires_at": "2026-07-20T00:00:00.000Z",
                "event_id": "ak:event:01904100-0000-7000-8000-0000000000e2",
                "sender": "did:web:alice.example",
                "hlc": "019041000000-0001-00000001",
                "preconditions": {"expected_state": "pending"},
                "effects": {"transition": "created"},
                "accepted_event_id": "ak:event:01904100-0000-7000-8000-0000000000e2"
            }),
        );

        assert_eq!(validate_invite_create_payload(&operation), Ok(()));
        assert_eq!(
            projection_context_stripped_payload(&operation.payload),
            json!({
                "invite_id": "ak:invite:01904100-0000-7000-8000-0000000000e2",
                "invitee": "did:web:bob.example",
                "invite_delivery_target": {
                    "recipient_service_id": "did:webvh:z6mkfixture:bob.example"
                },
                "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "expires_at": "2026-07-20T00:00:00.000Z"
            })
        );
    }

    #[test]
    fn causal_projection_context_is_not_revalidated_as_wire_payload() {
        let payload = json!({
            "event_ref": "ak:strand:01904100-0000-7000-8000-0000000000e3",
            "occurrence": null,
            "entry": {
                "schedule_basis_refs": [
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                ],
                "response": {"status": "accepted"}
            },
            "envelope_causal_refs": [
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            ],
            "canonical_event_digest":
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        });

        assert_eq!(
            projection_context_stripped_payload(&payload),
            json!({
                "event_ref": "ak:strand:01904100-0000-7000-8000-0000000000e3",
                "occurrence": null,
                "entry": {
                    "schedule_basis_refs": [
                        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    ],
                    "response": {"status": "accepted"}
                }
            })
        );
    }

    #[test]
    fn encrypted_payload_envelope_accepts_exporter_aead_scheme_binding() {
        let envelope = json!({
            "scheme": "mls_exporter_aead_v1",
            "version": "1.0",
            "group_id": "Z3JvdXA",
            "epoch": 7u64,
            "content_type": "application/json",
            "ciphertext": "Y2lwaGVydGV4dA",
            "aad_visibility_event_id": "hidden",
            "aad": {
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
                "event_kind": "ak.message.create"
            },
            "key_ref": {
                "algorithm": "MLS-EXPORTER-AEAD",
                "group_state_ref": "ak:event:01904100-0000-7000-8000-000000000001"
            },
            // Required for `mls_exporter_aead_v1` and forbidden for
            // `mls_rfc9420` (`encryption-and-audit.md` §2.10.2). `aead_profile`
            // is the `canonical_id` of the suite the group negotiated, taken
            // from `mls-ciphersuite-registry.json`.
            "purpose": "mls_exporter_aead_content",
            "aead_profile": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "aad_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "payload_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        });

        assert_eq!(validate_encrypted_payload_envelope(&envelope), Ok(()));

        let mut mismatched = envelope.clone();
        mismatched["key_ref"]["algorithm"] = json!("MLS");
        assert_eq!(
            validate_encrypted_payload_envelope(&mismatched),
            Err("encrypted content envelope violates SDK schema")
        );

        // The two AEAD header members are load-bearing, not decorative: a
        // receiver that cannot read the negotiated suite off the envelope
        // cannot rebuild `aead_aad_bytes`, so dropping either one MUST fail.
        for dropped in ["purpose", "aead_profile"] {
            let mut incomplete = envelope.clone();
            incomplete
                .as_object_mut()
                .expect("envelope is an object")
                .remove(dropped);
            assert_eq!(
                validate_encrypted_payload_envelope(&incomplete),
                Err("encrypted content envelope violates SDK schema"),
                "{dropped} is required for mls_exporter_aead_v1"
            );
        }
    }
}
