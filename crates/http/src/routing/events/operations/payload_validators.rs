use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::governance::membership_invite::validate_invite_create_wire_keys;
use arkret_schema::event_payload_validator_catalog;
use serde_json::Value;

use super::*;

pub(crate) fn validate_invite_create_payload(operation: &Operation) -> Result<(), &'static str> {
    let wire_payload = operation.payload.clone();
    event_payload_validator_catalog()
        .map_err(|_| "operation payload validator catalog is unavailable")?
        .validate_payload(arkret_wire::event_kind_str::INVITE_CREATE, &wire_payload)
        .map_err(|_| "operation payload violates SDK artifact schema")?;
    validate_invite_create_wire_keys(&wire_payload)
        .map_err(|_| "operation payload carries unsupported fields")?;
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::InviteCreate>()
        .map_err(|_| "operation payload violates SDK artifact schema")?;
    payload
        .invite_delivery_target
        .validate()
        .map_err(|_| "invite_delivery_target is invalid")?;
    Ok(())
}

pub(crate) fn validate_invite_third_party_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    event_payload_validator_catalog()
        .map_err(|_| "operation payload validator catalog is unavailable")?
        .validate_payload(
            arkret_wire::event_kind_str::INVITE_THIRD_PARTY,
            &operation.payload,
        )
        .map_err(|_| "operation payload violates SDK artifact schema")?;
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::InviteThirdParty>()
        .map_err(|_| "operation payload violates SDK artifact schema")?;
    payload
        .validate()
        .map_err(|_| "ak.invite.third_party payload is invalid")?;
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
    if arkret_identifiers::DidCoreId::new(subject_id.clone()).is_err() {
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
        .get("holder_id")
        .and_then(Value::as_str)
        .ok_or("account_data.set requires holder_id")?;
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
    let payload_value = &operation.payload;
    let payload = payload_value
        .as_object()
        .ok_or("ak.realm.read_receipt_policy payload must be an object")?;
    if payload.is_empty() {
        return Err("ak.realm.read_receipt_policy payload must set at least one field");
    }
    operation
        .typed_payload::<arkret_wire::event_spec::RealmReadReceiptPolicy>()
        .map_err(|_| "ak.realm.read_receipt_policy payload violates SDK artifact schema")?;
    Ok(())
}

pub(crate) fn validate_realm_inheritance_policy_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::RealmInheritancePolicy>()
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

pub(crate) fn validate_history_access_payload(operation: &Operation) -> Result<(), &'static str> {
    let from = operation.payload.get("from").and_then(Value::as_str);
    let to = operation
        .payload
        .get("to")
        .and_then(Value::as_str)
        .ok_or("ak.realm.history_access requires to")?;
    if !matches!(
        (from, to),
        (None, "all_history_for_current_members" | "since_join")
            | (Some("all_history_for_current_members"), "since_join")
            | (Some("since_join"), "since_join")
    ) {
        return Err("history_access_widening_forbidden");
    }
    Ok(())
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
/// `relation.md` §2 stateless admission guard for `ak.relation.update`.
///
/// The create side is gone from this layer on purpose:
/// `event-payload.schema.json#/$defs/relation_create_object` now reuses
/// `relation.schema.json` and additionally forbids `id`, `type` and
/// `effective_scope`, so the SDK artifact schema that runs immediately before
/// this validator already rejects an actor-supplied `effective_scope` on
/// `payload.relation`. Re-checking it here would be a second, drifting copy of
/// a criterion the schema owns.
///
/// The update side stays because `payload.patch` is the generic
/// `ak.schema.patch.v1` document, which cannot express a per-object forbidden
/// set. The set is read from the SDK projection of
/// `registry/reducer-managed-path-registry.json`; this module never spells its
/// own list.
///
/// Derived-edge admission (`watches`, container `contains`), endpoint scope and
/// every tombstone decision need the Relation pre-state, so they live solely in
/// `ProjectionState::check_relation_invariants`, which submit calls before any
/// persistent effect.
pub(crate) fn validate_relation_operation_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(patch) = operation.payload.get("patch").and_then(Value::as_object) else {
        return Ok(());
    };
    for path in patch.keys() {
        if let Some(reason) = arkret_wire::patch::reducer_managed_patch_reason("relation", path) {
            return Err(reason);
        }
    }
    Ok(())
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
    reject_forbidden_morph_update_patch(patch)?;
    Ok(())
}

/// `morph.md` §2 / §4 forbidden-wire guard for `ak.morph.update`:
/// - `morph_kind` and `schema_refs` are immutable after `ak.morph.create`.
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
        if path == "schema_refs" {
            return Err("morph update cannot modify create-locked schema_refs");
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
            if value.get("visibility").and_then(Value::as_str) == Some("private") {
                return Err("private_view_requires_account_data");
            }
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
    if operation.payload.get("visibility").and_then(Value::as_str) == Some("private") {
        return Err("private_view_requires_account_data");
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

pub(crate) fn validate_device_authorize_payload(operation: &Operation) -> Result<(), &'static str> {
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|_| "ak.device.authorize payload violates SDK artifact schema")?;
    payload.validate_wire_constraints()
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
    use serde_json::json;

    use super::validate_encrypted_payload_envelope;

    #[test]
    fn encrypted_payload_envelope_accepts_only_the_minimal_closed_wire() {
        let envelope = json!({
            "version": "1.0",
            "content_type": "application/json",
            "encryption_context": {
                "epoch": 7u64,
                "group_state_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "counter": 9u64,
            },
            "ciphertext": "Y2lwaGVydGV4dA",
        });

        assert_eq!(validate_encrypted_payload_envelope(&envelope), Ok(()));

        for forbidden in ["scheme", "group_id", "aad", "payload_digest"] {
            let mut widened = envelope.clone();
            widened[forbidden] = json!("forbidden");
            assert_eq!(
                validate_encrypted_payload_envelope(&widened),
                Err("encrypted content envelope violates SDK schema"),
                "{forbidden} must not be duplicated on the wire"
            );
        }
    }
}
