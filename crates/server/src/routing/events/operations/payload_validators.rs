use cokret_sdk::Operation;
use serde_json::Value;

use super::*;

pub(crate) fn validate_invite_create_payload(operation: &Operation) -> Result<(), &'static str> {
    let wire_payload = invite_create_wire_payload(&operation.payload);
    validate_invite_create_known_fields(&wire_payload)?;
    let invite_id = operation
        .payload
        .get("invite_id")
        .and_then(Value::as_str)
        .ok_or("ck.invite.create operation requires invite_id")?;
    if cokret_sdk::InviteId::new(invite_id.to_owned()).is_err() {
        return Err("ck.invite.create invite_id must be ck:invite:<uuidv7>");
    }
    let target = operation
        .payload
        .get("invite_delivery_target")
        .and_then(Value::as_object)
        .ok_or("invite_delivery_target must be an object")?;
    let recipient_service_did = target
        .get("recipient_service_did")
        .and_then(Value::as_str)
        .ok_or("invite_delivery_target.recipient_service_did is required")?;
    if cokret_sdk::Did::new(recipient_service_did.to_owned()).is_err() {
        return Err("invite_delivery_target.recipient_service_did must be a DID");
    }
    if let Some(service_type) = target.get("recipient_service_type").and_then(Value::as_str)
        && service_type != "principal_server"
    {
        return Err("invite_delivery_target.recipient_service_type must be principal_server");
    }
    let digest = operation
        .payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        .ok_or("introduction_evidence_digest is required")?;
    if cokret_sdk::Hash::new(digest.to_owned()).is_err() {
        return Err("introduction_evidence_digest must be a hash");
    }
    let expires_at = operation
        .payload
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or("expires_at is required")?;
    if cokret_sdk::canonical::validate_timestamp_canonical(expires_at).is_err() {
        return Err("expires_at must be a canonical timestamp");
    }
    cokret_sdk::InviteCreatePayload::from_wire_value(&wire_payload)
        .map_err(|_| "operation payload violates SDK artifact schema")?;
    Ok(())
}

fn invite_create_wire_payload(payload: &Value) -> Value {
    let mut wire_payload = payload.clone();
    if let Some(object) = wire_payload.as_object_mut() {
        object.remove("event_id");
        object.remove("sender");
        object.remove("hlc");
        object.remove("executed_by");
        object.remove("authorization_ref");
        object.remove("seal_ref");
        object.remove("seal_basis");
    }
    wire_payload
}

fn validate_invite_create_known_fields(payload: &Value) -> Result<(), &'static str> {
    let object = payload
        .as_object()
        .ok_or("ck.invite.create payload must be an object")?;
    for field in object.keys() {
        if field.starts_with("x_") {
            continue;
        }
        match field.as_str() {
            "invite_id"
            | "invitee"
            | "invite_delivery_target"
            | "introduction_evidence_digest"
            | "expires_at"
            | "reason" => {}
            "inviter" => {
                return Err(
                    "ck.invite.create payload must not carry inviter; use envelope.actor_id",
                );
            }
            "invite_token" => {
                return Err("ck.invite.create payload must not carry invite_token");
            }
            "state" => {
                return Err("ck.invite.create payload must not carry state");
            }
            "role" => {
                return Err("ck.invite.create payload role must use x_role");
            }
            _ => return Err("ck.invite.create payload carries unsupported field"),
        }
    }
    Ok(())
}

pub(crate) fn validate_invite_third_party_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let payload = operation
        .payload
        .as_object()
        .ok_or("ck.invite.third_party payload must be an object")?;
    let invite = payload.get("invite").and_then(Value::as_object);
    let invite_id = invite_field(payload, invite, "invite_id", "id")
        .ok_or("ck.invite.third_party requires invite_id")?;
    if cokret_sdk::InviteId::new(invite_id).is_err() {
        return Err("ck.invite.third_party invite_id must be ck:invite:<uuidv7>");
    }
    let realm_id = invite_field(payload, invite, "realm_id", "realm_id")
        .unwrap_or_else(|| operation.realm_id.to_string());
    if realm_id != operation.realm_id.as_str() {
        return Err("ck.invite.third_party realm_id must match envelope realm_id");
    }
    let inviter = invite_field(payload, invite, "inviter", "inviter")
        .ok_or("ck.invite.third_party requires inviter")?;
    if cokret_sdk::Did::new(inviter).is_err() {
        return Err("ck.invite.third_party inviter must be a DID");
    }
    let third_party_id = invite_value(payload, invite, "third_party_id")
        .and_then(Value::as_object)
        .ok_or("ck.invite.third_party third_party_id must be an object")?;
    for forbidden in ["token", "plaintext_token", "email", "phone", "address"] {
        if third_party_id.contains_key(forbidden) {
            return Err("ck.invite.third_party must not carry plaintext token or 3PID");
        }
    }
    let service_did = third_party_id
        .get("verification_service_did")
        .and_then(Value::as_str)
        .ok_or("third_party_id.verification_service_did is required")?;
    if cokret_sdk::Did::new(service_did.to_owned()).is_err() {
        return Err("third_party_id.verification_service_did must be a DID");
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
        && cokret_sdk::Hash::new(token_commitment.to_owned()).is_err()
    {
        return Err("third_party_id.token_commitment must be a hash");
    }
    if third_party_id.get("lookup_table_ref").is_none()
        && third_party_id.get("token_commitment").is_none()
    {
        return Err("third_party_id requires token_commitment or lookup_table_ref");
    }
    let expires_at = invite_field(payload, invite, "expires_at", "expires_at")
        .ok_or("ck.invite.third_party requires expires_at")?;
    if cokret_sdk::canonical::validate_timestamp_canonical(&expires_at).is_err() {
        return Err("ck.invite.third_party expires_at must be a canonical timestamp");
    }
    Ok(())
}

pub(crate) fn validate_invite_claim_payload(operation: &Operation) -> Result<(), &'static str> {
    let payload = operation
        .payload
        .as_object()
        .ok_or("ck.invite.claim payload must be an object")?;
    let invite_id =
        payload_string(payload, "invite_id").ok_or("ck.invite.claim requires invite_id")?;
    if cokret_sdk::InviteId::new(invite_id).is_err() {
        return Err("ck.invite.claim invite_id must be ck:invite:<uuidv7>");
    }
    let subject_id =
        payload_string(payload, "subject_id").ok_or("ck.invite.claim requires subject_id")?;
    if cokret_sdk::Did::new(subject_id.clone()).is_err() {
        return Err("ck.invite.claim subject_id must be a DID");
    }
    let token_commitment = payload_string(payload, "token_commitment")
        .ok_or("ck.invite.claim requires token_commitment")?;
    if cokret_sdk::Hash::new(token_commitment).is_err() {
        return Err("ck.invite.claim token_commitment must be a hash");
    }
    let claim_nonce =
        payload_string(payload, "claim_nonce").ok_or("ck.invite.claim requires claim_nonce")?;
    let binding = payload
        .get("binding_proof")
        .and_then(Value::as_object)
        .ok_or("ck.invite.claim binding_proof must be an object")?;
    let binding_subject = binding
        .get("subject_id")
        .and_then(Value::as_str)
        .ok_or("binding_proof.subject_id is required")?;
    if binding_subject != subject_id {
        return Err("binding_proof.subject_id must match subject_id");
    }
    if binding.get("realm_id").and_then(Value::as_str) != Some(operation.realm_id.as_str()) {
        return Err("binding_proof.realm_id must match envelope realm_id");
    }
    if binding.get("audience").and_then(Value::as_str) != Some("cokret.invite.claim") {
        return Err("binding_proof.audience must be cokret.invite.claim");
    }
    if binding.get("claim_nonce").and_then(Value::as_str) != Some(claim_nonce.as_str()) {
        return Err("binding_proof.claim_nonce must match claim_nonce");
    }
    let service_did = binding
        .get("verification_service_did")
        .and_then(Value::as_str)
        .ok_or("binding_proof.verification_service_did is required")?;
    if cokret_sdk::Did::new(service_did.to_owned()).is_err() {
        return Err("binding_proof.verification_service_did must be a DID");
    }
    if binding
        .get("verification_method")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err("binding_proof.verification_method is required");
    }
    let expires_at = binding
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or("binding_proof.expires_at is required")?;
    if cokret_sdk::canonical::validate_timestamp_canonical(expires_at).is_err() {
        return Err("binding_proof.expires_at must be a canonical timestamp");
    }
    if binding.get("signature").is_none() && binding.get("sig").is_none() {
        return Err("binding_proof.signature is required");
    }
    if payload
        .get("subject_proof")
        .and_then(Value::as_object)
        .is_none()
    {
        return Err("ck.invite.claim subject_proof must be an object");
    }
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
    if crate::kinds::operation_is_message_create(operation) {
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
        // `ck.schema.encrypted_envelope.v1` (referenced from
        // `message_create_payload` and enforced via
        // `event_payload_validator_catalog().validate_payload`). The spec
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
        return Err("ck.message.create.payload.expiry must be an object");
    };
    for key in object.keys() {
        if !["ttl_ms", "trigger", "seal_hlc", "grace_ms"].contains(&key.as_str()) {
            return Err("ck.message.create.payload.expiry has unknown field");
        }
    }
    if object
        .get("ttl_ms")
        .and_then(Value::as_u64)
        .is_none_or(|value| value == 0)
    {
        return Err("ck.message.create.payload.expiry requires positive ttl_ms");
    }
    match object.get("trigger").and_then(Value::as_str) {
        Some("on_send" | "on_first_read" | "on_last_read") => {}
        _ => return Err("ck.message.create.payload.expiry trigger is invalid"),
    }
    if object
        .get("seal_hlc")
        .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err("ck.message.create.payload.expiry seal_hlc must be non-empty");
    }
    if object
        .get("grace_ms")
        .is_some_and(|value| value.as_u64().is_none())
    {
        return Err("ck.message.create.payload.expiry grace_ms must be an integer");
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
    crate::routing::account_data_encryption::validate_encrypted_account_data_value(
        key,
        &operation.payload,
    )
    .map_err(|error| error.message())
}

pub(crate) fn validate_read_receipt_policy_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let payload = operation
        .payload
        .as_object()
        .ok_or("ck.realm.read_receipt_policy payload must be an object")?;
    if payload.is_empty() {
        return Err("ck.realm.read_receipt_policy payload must set at least one field");
    }
    for field in payload.keys() {
        match field.as_str() {
            "disclosure"
            | "visibility"
            | "scope_overrides_allowed"
            | "allow_child_privacy_tightening_against_required"
            | "allow_public_receipts_on_world_readable"
            | "allow_forced_public_world_readable_receipts" => {}
            _ => return Err("ck.realm.read_receipt_policy payload has unknown field"),
        }
    }
    if let Some(disclosure) = payload.get("disclosure") {
        match disclosure.as_str() {
            Some("required" | "optional" | "disabled") => {}
            _ => return Err("ck.realm.read_receipt_policy.disclosure is invalid"),
        }
    }
    if let Some(visibility) = payload.get("visibility") {
        match visibility.as_str() {
            Some("public" | "members" | "private") => {}
            _ => return Err("ck.realm.read_receipt_policy.visibility is invalid"),
        }
    }
    for field in [
        "scope_overrides_allowed",
        "allow_child_privacy_tightening_against_required",
        "allow_public_receipts_on_world_readable",
        "allow_forced_public_world_readable_receipts",
    ] {
        if payload.get(field).is_some_and(|value| !value.is_boolean()) {
            return Err("ck.realm.read_receipt_policy boolean field is invalid");
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
        if !["kind", "ref", "track_name"].contains(&key.as_str()) {
            return Err("read marker read_scope has unknown field");
        }
    }
    let kind = read_scope
        .get("kind")
        .and_then(|value| value.as_str())
        .ok_or("read marker read_scope.kind is required")?;
    match kind {
        "realm" => {
            if read_scope.get("ref").is_some_and(|value| !value.is_null()) {
                return Err("read marker read_scope.ref must be omitted for realm");
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
                .get("ref")
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or("read marker read_scope.ref is required")?;
            let expected_prefix = match kind {
                "circle" => "ck:circle:",
                "space" => "ck:space:",
                "strand" => "ck:strand:",
                "thread" => "ck:message:",
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
        .is_none_or(|value| !value.starts_with("ck:event:"))
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
        .ok_or("ck.realm.history_visibility requires string value")?;
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
        _ => Err("ck.realm.history_visibility value is unknown"),
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
    if !cell_id.starts_with("ck:cell:") {
        return Err("conflict repair cell_id must use ck:cell:");
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
/// `relation.md` admission guard for `ck.relation.create` / `.update` /
/// `.tombstone`, covering two reducer-managed invariants:
///
/// 1. **`effective_scope` is reducer-stamped** (§2 table): the actor MUST NOT submit it; the
///    reducer materialises it from `scope_circle_id`. Any actor-supplied `effective_scope` is
///    `schema_violation` (`effective_scope_reducer_managed`).
/// 2. **derived-edge single-source** (§3.2): `watches` (truth source
///    `ck.component.strand.watch.v1`, write path `ck.strand.watch.set`) and Board/List `contains`
///    (truth source `ck.space.parent` / `ck.strand.move`) are derived projections; a direct
///    `ck.relation.*` on them MUST `schema_violation`. The container `contains` shape is identified
///    by a Space `from_ref` (`ck:space:…`); a `Strand -> Strand` `contains` stays a
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
    match relation_kind {
        "watches" => Err("relation_kind_watches_derived"),
        "contains" => {
            let from_ref = ["from_ref", "from"]
                .iter()
                .find_map(|field| operation.payload.get(*field).and_then(Value::as_str))
                .unwrap_or_default();
            if from_ref.starts_with("ck:space:") {
                Err("relation_kind_contains_derived")
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
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

/// `morph.md` §2 / §4 forbidden-wire guard for `ck.morph.update`:
/// - `morph_type` is immutable after `ck.morph.create` (`morph_type_immutable`).
/// - the stage axis (`stage` / `stage_changed_at`) changes only via `ck.morph.stage.set`; writing
///   it through an update patch is `schema_violation`.
/// - the reserved business-field set (`fields.stage` / `fields.lifecycle` / `fields.progress_state`
///   / `fields.stage_reason`) is forbidden-wire in any representation (dotted `fields.<name>` path
///   or whole-`fields` object replace).
fn reject_forbidden_morph_update_patch(
    patch: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    const FORBIDDEN_FIELD: &[&str] = &["stage", "lifecycle", "progress_state", "stage_reason"];
    for (path, value) in patch {
        if path == "morph_type" {
            return Err("morph_type_immutable");
        }
        if path == "stage" || path == "stage_changed_at" {
            return Err("morph_stage_patch_forbidden");
        }
        if let Some(field) = path.strip_prefix("fields.") {
            if FORBIDDEN_FIELD.contains(&field) {
                return Err("morph_forbidden_field_patch");
            }
        }
        if path == "fields" {
            if let Some(map) = patch_set_value(value).and_then(Value::as_object) {
                if FORBIDDEN_FIELD.iter().any(|field| map.contains_key(*field)) {
                    return Err("morph_forbidden_field_patch");
                }
            }
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

fn reject_morph_metadata_business_fields(
    metadata: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    for field in [
        "id",
        "schema",
        "realm_id",
        "scope_circle_id",
        "schema_refs",
        "morph_type",
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
    validate_nonempty_unique_string_array(
        operation.payload.get("from_schema_refs"),
        "from_schema_refs",
    )?;
    validate_nonempty_unique_string_array(
        operation.payload.get("to_schema_refs"),
        "to_schema_refs",
    )?;
    match operation
        .payload
        .get("compatibility_class")
        .and_then(serde_json::Value::as_str)
    {
        Some("additive") => Ok(()),
        Some("breaking" | "transformation") => Err("morph_schema_refs_transformation_unsupported"),
        _ => Err("morph schema_migrate compatibility_class is invalid"),
    }
}

fn validate_nonempty_unique_string_array(
    value: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<(), &'static str> {
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
    }
    Ok(())
}

pub(crate) fn validate_cross_signing_reset_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let reset: cokret_sdk::crypto_protocol::CrossSigningResetContent =
        serde_json::from_value(operation.payload.clone())
            .map_err(|_| "cross_signing reset payload violates reset profile")?;
    reset
        .validate_structure()
        .map_err(|_| "cross_signing reset payload violates reset profile")?;
    let now = chrono::Utc::now();
    let skew = (now - reset.issued_at).num_seconds().abs();
    if skew > CROSS_SIGNING_RESET_MAX_CLOCK_SKEW_SECONDS {
        return Err("cross_signing_reset_clock_skew_exceeded");
    }
    Ok(())
}

pub(crate) fn validate_cross_signing_reset_replay_batch(
    operations: &[Operation],
) -> Result<(), &'static str> {
    let mut seen = std::collections::BTreeSet::new();
    for operation in operations {
        if kinds::canonical_kind_for_operation(operation) != Some(kinds::CK_CROSS_SIGNING_RESET) {
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
    let Some(envelope) = content.as_object() else {
        return Err("encrypted content must be a JSON object");
    };

    for field in [
        "cleartext_commitment",
        "authentication_tag",
        "digests",
        "ciphertext_digest",
    ] {
        if envelope.contains_key(field) {
            return Err("encrypted content envelope contains forbidden field");
        }
    }

    for field in [
        "scheme",
        "version",
        "group_id",
        "content_type",
        "ciphertext",
        "aad_visibility_event_id",
        "payload_digest",
        "aad_digest",
    ] {
        if envelope
            .get(field)
            .and_then(|value| value.as_str())
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err("encrypted content envelope is missing required string fields");
        }
    }

    if envelope.get("scheme").and_then(Value::as_str) != Some("mls-rfc9420") {
        return Err("encrypted content envelope scheme must be mls-rfc9420");
    }
    let Some(version) = envelope.get("version").and_then(Value::as_str) else {
        return Err("encrypted content envelope requires version");
    };
    if !version.split_once('.').is_some_and(|(major, minor)| {
        !major.is_empty()
            && !minor.is_empty()
            && major.bytes().all(|byte| byte.is_ascii_digit())
            && minor.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Err("encrypted content envelope version must be major.minor");
    }
    if envelope
        .get("epoch")
        .is_none_or(|value| value.as_u64().is_none())
    {
        return Err("encrypted content envelope requires numeric epoch");
    }

    let Some(aad) = envelope.get("aad").and_then(Value::as_object) else {
        return Err("encrypted content envelope requires aad");
    };
    if aad
        .get("realm_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
        || aad
            .get("event_kind")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err("encrypted content envelope aad requires realm_id and event_kind");
    }

    let Some(key_ref) = envelope.get("key_ref").and_then(Value::as_object) else {
        return Err("encrypted content envelope requires key_ref");
    };
    if key_ref.get("algorithm").and_then(Value::as_str) != Some("MLS")
        || key_ref
            .get("group_state_ref")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err("encrypted content envelope key_ref is invalid");
    }

    for field in ["payload_digest", "aad_digest"] {
        if !envelope
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(is_valid_encrypted_envelope_digest)
        {
            return Err(
                "encrypted content envelope digest must be sha256/blake3:<64 lowercase hex>",
            );
        }
    }

    match envelope
        .get("aad_visibility_event_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "hidden" => {
            if aad.contains_key("event_id") || aad.contains_key("event_ref_digest") {
                return Err("encrypted content envelope hidden aad exposes event id");
            }
        }
        "routing_digest" => {
            if aad.contains_key("event_id") {
                return Err("encrypted content envelope routing_digest aad forbids event_id");
            }
            if !aad
                .get("event_ref_digest")
                .and_then(Value::as_str)
                .is_some_and(is_valid_encrypted_envelope_digest)
            {
                return Err(
                    "encrypted content envelope routing_digest aad requires event_ref_digest",
                );
            }
        }
        "opaque_id" => {
            if aad.contains_key("event_ref_digest") {
                return Err("encrypted content envelope opaque_id aad forbids event_ref_digest");
            }
            if aad
                .get("event_id")
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err("encrypted content envelope opaque_id aad requires event_id");
            }
        }
        _ => return Err("encrypted content envelope aad_visibility_event_id is invalid"),
    }

    Ok(())
}

fn is_valid_encrypted_envelope_digest(value: &str) -> bool {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return false;
    };
    matches!(algorithm, "sha256" | "blake3")
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
