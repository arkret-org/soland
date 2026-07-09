use super::*;

pub(super) async fn preview_token_matches_policy(
    state: &AppState,
    parsed: &cokret_sdk::ParsedAddress,
    realm_id: &str,
    token: &str,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(meta) = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
    else {
        return false;
    };
    let Some(policy) = meta.preview_policy.as_ref() else {
        return false;
    };
    if policy.get("mode").and_then(Value::as_str) == Some("none") {
        return false;
    }
    if !policy_array_contains(policy, "audiences", "link_token_holder") {
        return false;
    }

    let Some(claim) = decode_preview_token(token) else {
        return false;
    };
    if claim.get("link_type").and_then(Value::as_str) != Some("preview") {
        return false;
    }
    if claim
        .get("nonce")
        .and_then(Value::as_str)
        .is_none_or(|nonce| nonce.trim().is_empty())
    {
        return false;
    }
    if token_expired(&claim) {
        return false;
    }
    if !token_audience_matches(&claim, session) {
        return false;
    }
    if !preview_token_signature_valid(state, &claim) {
        return false;
    }
    let expected_policy_digest = meta
        .preview_policy_digest
        .as_deref()
        .map(str::to_owned)
        .or_else(|| canonical_value_digest(policy));
    if claim
        .get("preview_policy_digest")
        .and_then(Value::as_str)
        .map(str::to_owned)
        != expected_policy_digest
    {
        return false;
    }
    token_target_matches_claim(&claim, parsed, realm_id, LinkType::Preview)
}

pub(super) fn optional_structured_token_target_matches(
    token: &str,
    parsed: &cokret_sdk::ParsedAddress,
    realm_id: &str,
    effective_link_type: LinkType,
) -> bool {
    match decode_preview_token(token) {
        Some(claim) if claim.get("target_digest").is_some() => {
            token_target_matches_claim(&claim, parsed, realm_id, effective_link_type)
        }
        Some(_) => false,
        None => parsed.strand.is_none() && parsed.message.is_none(),
    }
}

pub(super) fn token_target_matches_claim(
    claim: &Value,
    parsed: &cokret_sdk::ParsedAddress,
    realm_id: &str,
    effective_link_type: LinkType,
) -> bool {
    let Some(token_digest) = claim.get("target_digest").and_then(Value::as_str) else {
        return false;
    };
    let mut descriptor = TargetDescriptor::from_parsed(parsed);
    descriptor.set_realm_id(realm_id);
    descriptor.link_type = effective_link_type;
    target_digest(&descriptor)
        .ok()
        .as_deref()
        .is_some_and(|expected| expected == token_digest)
}

pub(super) fn decode_preview_token(token: &str) -> Option<Value> {
    let encoded = token
        .trim()
        .strip_prefix("ak:preview-token:")
        .unwrap_or_else(|| token.trim());
    if encoded.starts_with('{') {
        return serde_json::from_str(encoded).ok();
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub(super) fn token_expired(claim: &Value) -> bool {
    let Some(expires_at) = parse_token_expiry(claim.get("exp")) else {
        return true;
    };
    expires_at <= Utc::now()
}

pub(super) fn parse_token_expiry(value: Option<&Value>) -> Option<DateTime<Utc>> {
    match value? {
        Value::String(value) => DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|datetime| datetime.with_timezone(&Utc)),
        Value::Number(value) => {
            let raw = value.as_i64()?;
            if raw > 10_000_000_000 {
                Utc.timestamp_millis_opt(raw).single()
            } else {
                Utc.timestamp_opt(raw, 0).single()
            }
        }
        _ => None,
    }
}

pub(super) fn token_audience_matches(claim: &Value, session: Option<&SessionRecord>) -> bool {
    let matches_audience = |aud: &str| {
        aud == "anonymous"
            || session.is_some_and(|session| {
                aud == session.actor || aud == "authenticated" || aud == "link_token_holder"
            })
    };
    match claim.get("aud") {
        Some(Value::String(aud)) => matches_audience(aud),
        Some(Value::Array(audiences)) => audiences
            .iter()
            .filter_map(Value::as_str)
            .any(matches_audience),
        _ => false,
    }
}

pub(super) fn preview_token_signature_valid(state: &AppState, claim: &Value) -> bool {
    if claim.get("iss").and_then(Value::as_str) != Some(state.config.service_did.as_str()) {
        return false;
    }
    let Some(proof) = claim.get("proof").and_then(Value::as_object) else {
        return false;
    };
    if proof.get("kind").and_then(Value::as_str) != Some("detached_jws")
        || proof.get("alg").and_then(Value::as_str) != Some("EdDSA")
    {
        return false;
    }
    let Some(verification_method) = proof.get("verification_method").and_then(Value::as_str) else {
        return false;
    };
    if verification_method != state.config.service_did
        && !verification_method.starts_with(&format!("{}#", state.config.service_did))
    {
        return false;
    }
    let mut unsigned = claim.clone();
    if let Value::Object(object) = &mut unsigned {
        object.remove("proof");
    } else {
        return false;
    }
    let Ok(canonical_bytes) = canonical::canonical_json_bytes(&unsigned) else {
        return false;
    };
    let expected_digest = canonical::sha256_digest(&canonical_bytes);
    if proof.get("payload_digest").and_then(Value::as_str) != Some(expected_digest.as_str()) {
        return false;
    }
    let Some(jws) = proof.get("jws").and_then(Value::as_str) else {
        return false;
    };
    verify_detached_jws_with_service_key(&canonical_bytes, jws, state)
}

pub(super) fn verify_detached_jws_with_service_key(
    canonical_bytes: &[u8],
    jws: &str,
    state: &AppState,
) -> bool {
    let mut parts = jws.split('.');
    let (Some(protected_b64), Some(detached_payload), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if !detached_payload.is_empty() {
        return false;
    }
    let Ok(protected) = URL_SAFE_NO_PAD.decode(protected_b64) else {
        return false;
    };
    let Ok(protected) = serde_json::from_slice::<Value>(&protected) else {
        return false;
    };
    if protected.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return false;
    }
    let Ok(signature_bytes) = URL_SAFE_NO_PAD.decode(signature_b64) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };
    let signing_input = format!(
        "{protected_b64}.{}",
        URL_SAFE_NO_PAD.encode(canonical_bytes)
    );
    state
        .notary_signing_key()
        .verifying_key()
        .verify(signing_input.as_bytes(), &signature)
        .is_ok()
}

pub(super) fn policy_array_contains(policy: &Value, field: &str, expected: &str) -> bool {
    policy
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
}

// Converged to the single crate-root canonical-digest helper (delegates
// to SDK `canonical_sha256`); re-exported so directory call sites keep
// referencing `canonical_value_digest`.
pub(super) use crate::canonical_value_digest;
