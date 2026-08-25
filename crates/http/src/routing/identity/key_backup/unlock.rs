use super::*;

fn key_backup_untrusted_signature() -> AppError {
    AppError::new(
        ErrorCode::SignatureInvalid,
        "key backup auth_data.signature is not anchored to the actor device trust root",
    )
    .with_status(StatusCode::UNAUTHORIZED)
    .with_wire_code("untrusted_backup_signature")
}

/// key-management.md §7.4.1 (normative): a device signature alone cannot defend
/// against a malicious/compromised server injecting or substituting a backup
/// envelope signed by a revoked old device key. Before a receiver trusts an
/// envelope, it anchors `auth_data.signature` to the accepted
/// `ak.device.authorize` event for the device.
pub(super) async fn anchor_key_backup_auth_data_trust_root(
    state: &AppState,
    actor_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let auth = backup
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(key_backup_untrusted_signature)?;
    let device_id = auth
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or_else(key_backup_untrusted_signature)?;
    let signature_b64 = auth
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(key_backup_untrusted_signature)?;
    let verification_method = auth
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(key_backup_untrusted_signature)?;
    let claimed_device_authorize_event_id = auth
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .filter(|event_id| !event_id.trim().is_empty())
        .ok_or_else(key_backup_untrusted_signature)?;
    EventId::new(claimed_device_authorize_event_id.to_owned())
        .map_err(|_| key_backup_untrusted_signature())?;
    let record = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: actor_id.to_owned(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|error| AppError::internal(format!("device lookup failed: {error}")))?
        .ok_or_else(key_backup_untrusted_signature)?;
    if record.revoked_at.is_some() || record.verification_state != "verified" {
        return Err(key_backup_untrusted_signature());
    }
    let projected_event_id = record
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .ok_or_else(key_backup_untrusted_signature)?;
    if projected_event_id != claimed_device_authorize_event_id {
        return Err(key_backup_untrusted_signature());
    }
    let device_public_key = record
        .payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .ok_or_else(key_backup_untrusted_signature)?;
    if !key_backup_verification_method_matches_device_key(
        actor_id,
        device_id,
        device_public_key,
        verification_method,
    ) {
        return Err(AppError::new(
            ErrorCode::SignatureInvalid,
            "key backup verification method does not match the authorized device key",
        )
        .with_status(StatusCode::UNAUTHORIZED)
        .with_wire_code("untrusted_backup_signature"));
    }
    verify_key_backup_auth_data_signature(backup, device_public_key, signature_b64)
}

fn verify_key_backup_auth_data_signature(
    backup: &Value,
    device_public_key: &str,
    signature_b64: &str,
) -> Result<(), AppError> {
    let verifying_key = crate::routing::identity::device_signing::decode_ed25519_key(
        device_public_key,
        "multibase",
    )
    .map_err(|_| key_backup_untrusted_signature())?;
    let canonical = KeyBackup::signing_payload_bytes_from_wire(backup).map_err(|error| {
        AppError::internal(format!(
            "key backup signature transcript is invalid: {error}"
        ))
    })?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| key_backup_untrusted_signature())?;
    let signature = Signature::from_slice(&raw).map_err(|_| key_backup_untrusted_signature())?;
    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| key_backup_untrusted_signature())
}

fn key_backup_verification_method_matches_device_key(
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    verification_method: &str,
) -> bool {
    // `did-usage-and-verification.md` §2.2: a proof `verification_method` MUST
    // be a DID URL with a `#fragment`; a bare DID never names a concrete
    // verification method.
    let did_key = device_public_key
        .strip_prefix("did:key:")
        .map_or_else(|| format!("did:key:{device_public_key}"), str::to_owned);
    let fragment = did_key
        .strip_prefix("did:key:")
        .unwrap_or(device_public_key);
    verification_method == format!("{principal_id}#{device_id}")
        || verification_method == format!("{did_key}#{fragment}")
        || verification_method == format!("{did_key}#device")
}

pub(super) fn key_backup_canonical_digest_without_signature(
    backup: &Value,
) -> Result<String, AppError> {
    KeyBackup::signature_independent_digest_from_wire(backup)
        .map_err(|error| AppError::internal(format!("key backup canonical digest failed: {error}")))
}

pub(super) fn required_proof_string<'a>(
    proof: &'a Value,
    field: &str,
) -> Result<&'a str, AppError> {
    proof
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::SchemaViolation,
                format!("key backup unlock proof `{field}` is required"),
            )
        })
}

pub(super) fn validate_key_backup_unlock_proof_shape(
    proof: &Value,
    actor_id: &str,
    session_device_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let proof = serde_json::from_value::<KeyBackupUnlockProof>(proof.clone())
        .map_err(|error| schema_error(format!("invalid key backup unlock proof: {error}")))?;
    proof
        .validate()
        .map_err(|error| schema_error(format!("invalid key backup unlock proof: {error}")))?;
    let backup = serde_json::from_value::<KeyBackup>(backup.clone())
        .map_err(|error| schema_error(format!("invalid key backup envelope: {error}")))?;
    backup
        .validate()
        .map_err(|error| schema_error(format!("invalid key backup envelope: {error}")))?;
    if proof.principal_id.as_str() != actor_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof principal_id must match authenticated actor",
        ));
    }
    if proof.requesting_device_id.as_str() != session_device_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof requesting_device_id must match authenticated session device",
        ));
    }
    if proof.backup_id != backup.backup_id
        || proof.backup_kind != backup.backup_kind
        || proof.series_id != backup.series_id
        || proof.ciphertext_digest.as_str() != backup.ciphertext_digest
    {
        return Err(AppError::capability_denied(
            "key backup unlock proof does not match backup metadata",
        ));
    }
    Ok(())
}

pub(super) async fn verify_key_backup_unlock_proof_signature(
    state: &AppState,
    proof: &Value,
) -> Result<(), AppError> {
    let proof = serde_json::from_value::<KeyBackupUnlockProof>(proof.clone())
        .map_err(|error| schema_error(format!("invalid key backup unlock proof: {error}")))?;
    let canonical = proof
        .signing_payload_bytes()
        .map_err(|error| schema_error(format!("invalid key backup unlock proof: {error}")))?;
    let verification_method = proof.auth_data.verification_method.as_str();
    let signature_b64 = proof.auth_data.signature.as_str();
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .map_err(|_| {
            AppError::capability_denied("key backup unlock proof signature is not base64url")
        })?;
    let signature = Signature::from_slice(&raw).map_err(|_| {
        AppError::capability_denied("key backup unlock proof signature must be 64 Ed25519 bytes")
    })?;
    let public_key = if proof.proof_kind == arkret_models_crypto::ProofKind::RecoveryUnlock {
        let record = state
            .recovery_sessions()
            .session(proof.recovery_session_id.as_str())
            .await
            .map_err(|error| {
                AppError::internal(format!("recovery session lookup failed: {error}"))
            })?
            .ok_or_else(|| {
                AppError::capability_denied(
                    "key backup unlock proof recovery session record is missing",
                )
            })?;
        super::super::recovery::recovery_session_unlock_verifying_key(&record, verification_method)?
    } else {
        crate::jws_verify::resolve_ed25519_pubkey_async(state, verification_method)
            .await
            .map_err(|error| {
                AppError::capability_denied(format!(
                    "key backup unlock proof verification method invalid: {error}"
                ))
            })?
    };
    public_key.verify(&canonical, &signature).map_err(|_| {
        AppError::capability_denied("key backup unlock proof signature verification failed")
    })
}

/// Recovery-ceremony proof kinds whose transcript MUST be anchored to a
/// verified/completed recovery session (key-management.md §7.7.1 / §7.8:
/// an unbound proof MUST be rejected with `recovery_evidence_unbound`).
/// `principal_signing` is outside that closed set: it is a device-signed
/// decrypt proof, not a ceremony, and is therefore not anchored to a recovery
/// session. It moves inside the set once the policy-layer recovery-session
/// driver exists.
fn proof_kind_requires_recovery_session(proof_kind: &str) -> bool {
    matches!(
        proof_kind,
        "recovery_unlock" | "threshold_recovery" | "device_quorum" | "trusted_recovery_service"
    )
}

pub(super) async fn enforce_recovery_session_binding_when_present(
    state: &AppState,
    proof: &Value,
    session: &soland_services::identity::SessionIdentityState,
) -> Result<(), AppError> {
    let recovery_session_id = required_proof_string(proof, "recovery_session_id")?;
    let Some(record) = state
        .recovery_sessions()
        .session(recovery_session_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery session lookup failed: {error}")))?
    else {
        // Fail closed for recovery-ceremony proof kinds: a proof that claims
        // a recovery session which does not exist locally cannot be anchored
        // to a verified/completed ceremony (key-management.md §7.8).
        let proof_kind = required_proof_string(proof, "proof_kind")?;
        if proof_kind_requires_recovery_session(proof_kind) {
            return Err(AppError::conflict(
                "key backup unlock proof recovery session record is missing for a recovery-ceremony proof_kind",
            )
            .with_wire_code("recovery_evidence_unbound"));
        }
        return Ok(());
    };
    if record.principal_id != session.actor || record.requesting_device_id != session.device_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof recovery session binding does not match caller",
        ));
    }
    if let Some(grant) = session.session_grant.as_ref()
        && grant.credential_class
            == arkret_models_identity::SessionGrantCredentialClass::RecoverySession
        && (record.session_grant_id != grant.grant_id.as_str()
            || record.session_grant_cnf_jkt != grant.cnf_jkt)
    {
        return Err(AppError::capability_denied(
            "key backup unlock proof recovery session does not match the presented recovery grant",
        ));
    }
    if !matches!(
        record.state,
        arkret_models_crypto::SessionState::Verified | arkret_models_crypto::SessionState::Completed
    ) {
        // Registry reason `recovery_evidence_unbound`: the unlock proof is
        // not backed by a verified/completed recovery session, so the
        // recovery evidence is not bound to the session it claims.
        return Err(AppError::conflict(
            "key backup unlock proof recovery session must be verified or completed",
        )
        .with_wire_code("recovery_evidence_unbound"));
    }
    if let Some((kind, digest)) =
        super::super::recovery::recovery_session_proof_kind_and_digest(&record)
        && (required_proof_string(proof, "proof_kind")? != kind
            || required_proof_string(proof, "proof_digest")? != digest)
    {
        return Err(AppError::capability_denied(
            "key backup unlock proof proof_digest does not match recovery session",
        ));
    }
    Ok(())
}

/// Spec `keys_backups_unlock_request_body` (additionalProperties: false) —
/// the unlock proof travels as the `proof` field of the JSON request body of
/// `POST /_arkret/self/keys/backups/{backup_id}/unlock`; header / query
/// carriers are forbidden. The proof MUST validate as
/// `ak.schema.key_backup_unlock_proof.v1` and is verified against the
/// recovery session, caller, requesting device key, and target envelope
/// before the full ciphertext is returned (key-management.md §7.7.1 / §7.8).
pub(super) async fn verify_key_backup_unlock_proof(
    state: &AppState,
    proof: &Value,
    session: &soland_services::identity::SessionIdentityState,
    backup: &Value,
) -> Result<(), AppError> {
    validate_key_backup_unlock_proof_shape(proof, &session.actor, &session.device_id, backup)?;
    enforce_recovery_session_binding_when_present(state, proof, session).await?;
    verify_key_backup_unlock_proof_signature(state, proof).await
}

#[cfg(test)]
mod tests {
    use super::{
        key_backup_verification_method_matches_device_key, proof_kind_requires_recovery_session,
    };

    // did-usage-and-verification.md §2.2 — a proof `verification_method` MUST
    // be a DID URL with a `#fragment`. A bare `did:key:<mb>` names no concrete
    // verification method and must not satisfy the key-backup device binding.
    #[test]
    fn key_backup_verification_method_rejects_bare_did_key() {
        let principal = "did:webvh:z6mkfixture:alice.example";
        let device = "ak:device:primary";
        let key = "z6MkBackup";

        for accepted in [
            format!("{principal}#{device}"),
            format!("did:key:{key}#{key}"),
            format!("did:key:{key}#device"),
        ] {
            assert!(key_backup_verification_method_matches_device_key(
                principal, device, key, &accepted
            ));
        }
        assert!(!key_backup_verification_method_matches_device_key(
            principal,
            device,
            key,
            &format!("did:key:{key}"),
        ));
        assert!(!key_backup_verification_method_matches_device_key(
            principal, device, key, principal
        ));
    }

    // key-management.md §7.7.1 / §7.8 — recovery-ceremony proof kinds fail
    // closed when the claimed recovery session record is absent; the
    // `principal_signing` device proof is outside that closed set and proceeds
    // without a durable session record.
    #[test]
    fn recovery_ceremony_proof_kinds_require_a_recovery_session() {
        for kind in [
            "recovery_unlock",
            "threshold_recovery",
            "device_quorum",
            "trusted_recovery_service",
        ] {
            assert!(
                proof_kind_requires_recovery_session(kind),
                "{kind} must require a durable recovery session"
            );
        }
        assert!(!proof_kind_requires_recovery_session("principal_signing"));
        // Unknown kinds never reach this check (the shape validator rejects
        // them first), but classify them as session-requiring anyway so a
        // future closed-set widening cannot silently fail open here.
    }
}
