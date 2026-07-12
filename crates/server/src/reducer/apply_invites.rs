use serde_json::{Value, json};

use super::*;

const INVITE_STATE_PENDING: &str = "pending";
const INVITE_STATE_CLAIMED: &str = "claimed";
const INVITE_STATE_EXPIRED: &str = "expired";

impl ProjectionState {
    pub(crate) fn apply_invite_third_party(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_sdk::events::kinds::INVITE_THIRD_PARTY)
        {
            return ProjectionEffect::Ignored;
        }
        self.cleanup_expired_invites(now);

        let Some(payload) = operation.payload.as_object() else {
            return rejected("invite_payload_not_object");
        };
        let invite = payload.get("invite").and_then(Value::as_object);
        let Some(invite_id) = invite_string_field(payload, invite, "invite_id", "id") else {
            return rejected("invite_id_required");
        };
        if arkret_sdk::InviteId::new(invite_id.clone()).is_err() {
            return rejected("invite_id_invalid");
        }
        let realm_id = invite_string_field(payload, invite, "realm_id", "realm_id")
            .unwrap_or_else(|| operation.realm_id.to_string());
        if realm_id != operation.realm_id.as_str() {
            return rejected("invite_realm_mismatch");
        }
        let Some(inviter) = invite_string_field(payload, invite, "inviter", "inviter") else {
            return rejected("inviter_required");
        };
        if arkret_sdk::Did::new(inviter.clone()).is_err() {
            return rejected("inviter_invalid");
        }
        let Some(third_party_id) = invite_value_field(payload, invite, "third_party_id") else {
            return rejected("third_party_id_required");
        };
        if let Err(reason) = validate_third_party_id(third_party_id) {
            return rejected(reason);
        }
        let Some(expires_at) = invite_string_field(payload, invite, "expires_at", "expires_at")
            .and_then(|value| parse_timestamp(&value))
        else {
            return rejected("expires_at_required");
        };
        let created_at = invite_string_field(payload, invite, "created_at", "created_at")
            .and_then(|value| parse_timestamp(&value))
            .unwrap_or(operation.created_at);
        let join_rule_snapshot = invite_value_field(payload, invite, "join_rule_snapshot")
            .cloned()
            .unwrap_or_else(|| json!({"join_rule": "invite"}));
        let state = invite_string_field(payload, invite, "state", "state")
            .unwrap_or_else(|| INVITE_STATE_PENDING.to_owned());
        if state != INVITE_STATE_PENDING {
            return rejected("invite_state_invalid");
        }

        if let Some(existing) = self.invites.get(&invite_id) {
            return ProjectionEffect::InviteStateChanged {
                invite_id: existing.invite_id.clone(),
                realm_id: existing.realm_id.clone(),
                state: existing.state.clone(),
                invitee: existing.invitee.clone(),
            };
        }
        if let Some(token_commitment) = token_commitment_for_third_party(third_party_id)
            && self.invites.values().any(|existing| {
                existing.invite_id != invite_id
                    && matches!(
                        existing.state.as_str(),
                        INVITE_STATE_PENDING | INVITE_STATE_CLAIMED
                    )
                    && existing.expires_at > now
                    && existing
                        .third_party_id
                        .as_ref()
                        .and_then(token_commitment_for_third_party)
                        == Some(token_commitment)
            })
        {
            return rejected("duplicate_token_commitment");
        }

        let mut projection = InviteProjection {
            invite_id: invite_id.clone(),
            realm_id: realm_id.clone(),
            inviter,
            invitee: None,
            third_party_id: Some(third_party_id.clone()),
            join_rule_snapshot,
            state: INVITE_STATE_PENDING.to_owned(),
            expires_at,
            created_at,
            updated_at: created_at,
            claim_nonces: BTreeMap::new(),
        };
        if expires_at <= now {
            expire_invite_projection(&mut projection, now);
        }
        let state = projection.state.clone();
        let invitee = projection.invitee.clone();
        self.invites.insert(invite_id.clone(), projection);
        ProjectionEffect::InviteStateChanged {
            invite_id,
            realm_id,
            state,
            invitee,
        }
    }

    pub(crate) fn apply_invite_claim(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_sdk::events::kinds::INVITE_CLAIM)
        {
            return ProjectionEffect::Ignored;
        }
        self.cleanup_expired_invites(now);

        let Some(payload) = operation.payload.as_object() else {
            return rejected("invite_claim_payload_not_object");
        };
        let Some(invite_id) = string_field(payload, "invite_id") else {
            return rejected("invite_id_required");
        };
        if arkret_sdk::InviteId::new(invite_id.clone()).is_err() {
            return rejected("invite_id_invalid");
        }
        let Some(subject_id) = string_field(payload, "subject_id") else {
            return rejected("subject_id_required");
        };
        if arkret_sdk::Did::new(subject_id.clone()).is_err() {
            return rejected("subject_id_invalid");
        }
        let Some(token_commitment) = string_field(payload, "token_commitment") else {
            return rejected("token_commitment_required");
        };
        if !valid_hash(&token_commitment) {
            return rejected("token_commitment_invalid");
        }
        let Some(claim_nonce) = string_field(payload, "claim_nonce") else {
            return rejected("claim_nonce_required");
        };
        let Some(binding_proof) = payload.get("binding_proof") else {
            return rejected("binding_proof_required");
        };
        let Some(subject_proof) = payload.get("subject_proof") else {
            return rejected("subject_proof_required");
        };
        let realm_policy_components = self
            .realm_policy_components_cell_value(operation.realm_id.as_str())
            .cloned();

        let Some(invite) = self.invites.get_mut(&invite_id) else {
            return rejected("not_found");
        };
        match invite.claim_nonces.get(&claim_nonce) {
            Some(existing_operation_id)
                if existing_operation_id != operation.operation_id.as_str() =>
            {
                return rejected("duplicate_conflict");
            }
            Some(_) => {}
            None => {
                invite
                    .claim_nonces
                    .insert(claim_nonce.clone(), operation.operation_id.to_string());
            }
        }
        if invite.expires_at <= now {
            expire_invite_projection(invite, now);
            return rejected("expired_invite_token");
        }
        if invite.realm_id != operation.realm_id.as_str() {
            return rejected("not_found");
        }
        match invite.state.as_str() {
            INVITE_STATE_PENDING => {}
            INVITE_STATE_CLAIMED => return rejected("duplicate_conflict"),
            _ => return rejected("not_found"),
        }
        if let Some(existing_invitee) = invite.invitee.as_deref()
            && existing_invitee != subject_id
        {
            return rejected("not_found");
        }
        let Some(third_party_id) = invite.third_party_id.as_ref() else {
            return rejected("not_found");
        };
        let Some(expected_token_commitment) = token_commitment_for_third_party(third_party_id)
        else {
            return rejected("not_found");
        };
        if expected_token_commitment != token_commitment {
            return rejected("not_found");
        }
        if let Err(reason) = validate_claim_join_rule(&invite.join_rule_snapshot) {
            return rejected(reason);
        }
        if let Err(reason) = validate_binding_proof(
            binding_proof,
            third_party_id,
            &invite.realm_id,
            &subject_id,
            &claim_nonce,
            now,
            invite.expires_at,
            realm_policy_components.as_ref(),
        ) {
            return rejected(reason);
        }
        if let Err(reason) = validate_subject_proof(
            subject_proof,
            binding_proof,
            &invite_id,
            &invite.realm_id,
            &subject_id,
            &token_commitment,
            &claim_nonce,
            third_party_id,
        ) {
            return rejected(reason);
        }

        invite.state = INVITE_STATE_CLAIMED.to_owned();
        invite.invitee = Some(subject_id.clone());
        invite.updated_at = now;
        cleanup_third_party_projection(invite);
        self.members.insert(
            (invite.realm_id.clone(), subject_id.clone()),
            SolandMembershipState {
                member: subject_id.clone(),
                realm_id: invite.realm_id.clone(),
                state: "invite".to_owned(),
                role: role_from_join_rule_snapshot(&invite.join_rule_snapshot),
                delivery_status: None,
                recipient_service_id: None,
                membership_event_ref: None,
                delivery_binding_frontier: None,
                invited_at: Some(now),
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );

        ProjectionEffect::InviteStateChanged {
            invite_id,
            realm_id: invite.realm_id.clone(),
            state: INVITE_STATE_CLAIMED.to_owned(),
            invitee: Some(subject_id),
        }
    }

    pub(crate) fn cleanup_expired_invites(&mut self, now: chrono::DateTime<chrono::Utc>) {
        for invite in self.invites.values_mut() {
            if matches!(
                invite.state.as_str(),
                INVITE_STATE_PENDING | INVITE_STATE_CLAIMED
            ) && invite.expires_at <= now
            {
                expire_invite_projection(invite, now);
            }
        }
    }
}

fn rejected(reason: &str) -> ProjectionEffect {
    ProjectionEffect::Rejected {
        reason: reason.to_owned(),
    }
}

fn invite_string_field(
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

fn invite_value_field<'a>(
    payload: &'a serde_json::Map<String, Value>,
    invite: Option<&'a serde_json::Map<String, Value>>,
    field: &str,
) -> Option<&'a Value> {
    invite
        .and_then(|object| object.get(field))
        .or_else(|| payload.get(field))
}

fn string_field(payload: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
}

fn valid_hash(value: &str) -> bool {
    value.starts_with("sha256:") && arkret_sdk::Hash::new(value.to_owned()).is_ok()
}

fn validate_third_party_id(third_party_id: &Value) -> Result<(), &'static str> {
    let Some(object) = third_party_id.as_object() else {
        return Err("third_party_id_not_object");
    };
    for forbidden in ["token", "plaintext_token", "email", "phone", "address"] {
        if object.contains_key(forbidden) {
            return Err("third_party_id_contains_plaintext_secret");
        }
    }
    let Some(service_id) = object
        .get("verification_service_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err("verification_service_id_required");
    };
    if arkret_sdk::Did::new(service_id.to_owned()).is_err() {
        return Err("verification_service_id_invalid");
    }
    if object
        .get("verification_public_key")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err("verification_public_key_required");
    }
    if let Some(max_claims) = object.get("max_claims").and_then(Value::as_u64)
        && max_claims > 1
    {
        return Err("unsupported_max_claims");
    }
    if let Some(token_commitment) = token_commitment_for_third_party(third_party_id)
        && !valid_hash(token_commitment)
    {
        return Err("token_commitment_invalid");
    }
    if object.get("lookup_table_ref").is_none()
        && token_commitment_for_third_party(third_party_id).is_none()
    {
        return Err("token_commitment_required");
    }
    Ok(())
}

fn token_commitment_for_third_party(third_party_id: &Value) -> Option<&str> {
    third_party_id
        .get("token_commitment")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn validate_claim_join_rule(snapshot: &Value) -> Result<(), &'static str> {
    let rule = snapshot
        .get("join_rule")
        .or_else(|| snapshot.get("default_join_rule"))
        .and_then(Value::as_str)
        .unwrap_or("invite");
    match rule {
        "invite" | "restricted" => Ok(()),
        "knock_restricted" => Err("unsupported_join_rule"),
        _ => Err("unsupported_join_rule"),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_binding_proof(
    binding_proof: &Value,
    third_party_id: &Value,
    invite_realm_id: &str,
    subject_id: &str,
    claim_nonce: &str,
    now: chrono::DateTime<chrono::Utc>,
    invite_expires_at: chrono::DateTime<chrono::Utc>,
    realm_policy_components: Option<&Value>,
) -> Result<(), &'static str> {
    let Some(object) = binding_proof.as_object() else {
        return Err("binding_proof_not_object");
    };
    let Some(service_id) = proof_string(object, "verification_service_id") else {
        return Err("binding_proof_service_id_required");
    };
    if arkret_sdk::Did::new(service_id.clone()).is_err() {
        return Err("binding_proof_service_id_invalid");
    }
    let expected_service_id = third_party_id
        .get("verification_service_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if service_id != expected_service_id {
        return Err("verification_service_not_authorized");
    }
    if !realm_policy_components.is_some_and(|value| value_allowlists_service(value, &service_id)) {
        return Err("verification_service_not_authorized");
    }
    let Some(proof_subject) = proof_string(object, "subject_id") else {
        return Err("binding_proof_subject_required");
    };
    if proof_subject != subject_id {
        return Err("binding_proof_subject_mismatch");
    }
    let Some(proof_realm) = proof_string(object, "realm_id") else {
        return Err("binding_proof_realm_required");
    };
    if proof_realm != invite_realm_id {
        return Err("binding_proof_realm_mismatch");
    }
    let Some(audience) = proof_string(object, "audience") else {
        return Err("binding_proof_audience_required");
    };
    if audience != arkret_sdk::INVITE_CLAIM_AUDIENCE {
        return Err("binding_proof_audience_mismatch");
    }
    let Some(proof_nonce) = proof_string(object, "claim_nonce") else {
        return Err("binding_proof_nonce_required");
    };
    if proof_nonce != claim_nonce {
        return Err("binding_proof_nonce_mismatch");
    }
    let Some(expires_at) =
        proof_string(object, "expires_at").and_then(|value| parse_timestamp(&value))
    else {
        return Err("binding_proof_expires_at_invalid");
    };
    if expires_at <= now || expires_at > invite_expires_at {
        return Err("binding_proof_expired");
    }
    let Some(method) = proof_string(object, "verification_method") else {
        return Err("binding_proof_method_required");
    };
    if let Some(expected_method) = third_party_id
        .get("verification_public_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && method != expected_method
    {
        return Err("binding_proof_method_mismatch");
    }
    if proof_string(object, "signature").is_none() && proof_string(object, "sig").is_none() {
        return Err("binding_proof_signature_required");
    }
    Ok(())
}

fn validate_subject_proof(
    subject_proof: &Value,
    binding_proof: &Value,
    invite_id: &str,
    realm_id: &str,
    subject_id: &str,
    token_commitment: &str,
    claim_nonce: &str,
    third_party_id: &Value,
) -> Result<(), &'static str> {
    if !subject_proof.is_object() {
        return Err("subject_proof_not_object");
    };
    let subject_proof: arkret_sdk::InviteSubjectProof =
        serde_json::from_value(subject_proof.clone()).map_err(|_| "subject_proof_invalid")?;
    if subject_proof.verification_method.trim().is_empty() {
        return Err("subject_proof_method_required");
    }
    if subject_proof.alg != arkret_sdk::INVITE_SUBJECT_PROOF_ALG {
        return Err("subject_proof_alg_unsupported");
    }
    if subject_proof.signature.trim().is_empty() {
        return Err("subject_proof_signature_required");
    }
    subject_proof
        .validate()
        .map_err(|_| "subject_proof_invalid")?;
    let Some(binding_digest) = arkret_sdk::canonical::canonical_sha256(binding_proof).ok() else {
        return Err("binding_proof_digest_invalid");
    };
    let expected_digest = arkret_sdk::invite_subject_proof_transcript_digest(
        subject_id,
        invite_id,
        realm_id,
        token_commitment,
        claim_nonce,
        third_party_id
            .get("verification_service_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        binding_digest.as_str(),
    )
    .map_err(|_| "subject_proof_transcript_invalid")?;
    if subject_proof.transcript_digest != expected_digest {
        return Err("subject_proof_transcript_mismatch");
    }
    Ok(())
}

fn proof_string(object: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn value_allowlists_service(value: &Value, service_id: &str) -> bool {
    match value {
        Value::Array(items) => items
            .iter()
            .any(|item| item.is_object() && value_allowlists_service(item, service_id)),
        Value::Object(object) => object.iter().any(|(key, item)| {
            let key_matches = matches!(
                key.as_str(),
                "allowed_verification_service_ids"
                    | "verification_service_ids"
                    | "third_party_verification_service_ids"
                    | "third_party_invite_verification_services"
            );
            if key_matches {
                item.as_array()
                    .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(service_id)))
                    || item.as_str() == Some(service_id)
            } else {
                value_allowlists_service(item, service_id)
            }
        }),
        _ => false,
    }
}

fn expire_invite_projection(invite: &mut InviteProjection, now: chrono::DateTime<chrono::Utc>) {
    invite.state = INVITE_STATE_EXPIRED.to_owned();
    invite.updated_at = now;
    cleanup_third_party_projection(invite);
    if let Some(third_party_id) = invite.third_party_id.as_mut()
        && let Some(object) = third_party_id.as_object_mut()
    {
        object.remove("token_commitment");
    }
}

fn cleanup_third_party_projection(invite: &mut InviteProjection) {
    if let Some(third_party_id) = invite.third_party_id.as_mut()
        && let Some(object) = third_party_id.as_object_mut()
    {
        for key in [
            "token_salt",
            "token_salt_id",
            "lookup_table_ref",
            "pepper",
            "pepper_id",
        ] {
            object.remove(key);
        }
    }
}

fn role_from_join_rule_snapshot(snapshot: &Value) -> String {
    snapshot
        .get("role")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("member")
        .to_owned()
}
