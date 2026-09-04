use super::*;

pub(super) fn authorization_event_actor_matches_account(
    actor_key: &str,
    account_id: &AccountId,
) -> bool {
    arkret_wire::ActorId::account(account_id.clone())
        .canonical_key()
        .is_ok_and(|expected| expected == actor_key)
}

pub(super) async fn verify_recovery_policy_auth_signature(
    state: &AppState,
    payload: &Value,
    record: &ValidatedRecoveryPolicy,
    session: &SessionRecord,
    existing: Option<&RecoveryPolicyState>,
) -> Result<(), AppError> {
    let primary =
        verify_recovery_auth_signature(state, payload, record.account_id.principal_id.as_str())
            .await;
    if primary.is_ok() {
        return primary;
    }

    if existing.is_some() || !recovery_policy_uses_session_device(payload, record, session) {
        return primary;
    }

    verify_recovery_policy_session_device_signature(state, payload, record, session).await
}

pub(super) fn recovery_policy_uses_session_device(
    payload: &Value,
    record: &ValidatedRecoveryPolicy,
    session: &SessionRecord,
) -> bool {
    payload
        .get("auth_data")
        .and_then(Value::as_object)
        .and_then(|auth_data| auth_data.get("verification_method"))
        .and_then(Value::as_str)
        .is_some_and(|verification_method| {
            recovery_policy_verification_method_matches_session(
                verification_method,
                record.account_id.principal_id.as_str(),
                &session.device_id,
            )
        })
}

fn recovery_policy_verification_method_matches_session(
    verification_method: &str,
    principal_core_id: &str,
    device_id: &str,
) -> bool {
    let Some((principal_did, fragment)) = verification_method.trim().rsplit_once('#') else {
        return false;
    };
    if fragment != device_id {
        return false;
    }
    arkret_wire::Did::new(principal_did.to_owned())
        .ok()
        .and_then(|did| arkret_wire::project_did_to_core_id(&did).ok())
        .is_some_and(|core_id| core_id.as_str() == principal_core_id)
}

pub(super) async fn verify_recovery_policy_session_device_signature(
    state: &AppState,
    payload: &Value,
    record: &ValidatedRecoveryPolicy,
    session: &SessionRecord,
) -> Result<(), AppError> {
    if session.actor != record.account_id.principal_id.as_str() {
        return Err(crate::app_error!(
            CapabilityDenied,
            "session actor does not match recovery policy principal",
        )
        .with_wire_code("recovery_principal_isolation"));
    }
    let auth_data = payload
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::param_invalid("auth_data is required"))?;
    let verification_method = auth_data
        .get("verification_method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::param_invalid("auth_data.verification_method is required"))?;
    if !recovery_policy_verification_method_matches_session(
        verification_method,
        record.account_id.principal_id.as_str(),
        &session.device_id,
    ) {
        return Err(recovery_signature_error(format!(
            "genesis recovery policy device signature must use the session principal's DID and device fragment `{}`",
            session.device_id
        )));
    }

    let device_key = resolve_session_device_key_for_genesis_policy(
        state,
        record.account_id.principal_id.as_str(),
        session,
    )
    .await?;
    let typed: RecoveryPolicy = serde_json::from_value(payload.clone()).map_err(|error| {
        AppError::param_invalid(format!("recovery policy violates SDK shape: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let transcript_bytes = typed
        .signature_transcript_bytes()
        .map_err(|error| AppError::internal(format!("recovery transcript failed: {error}")))?;

    let signature_b64 = auth_data
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("auth_data.signature is required"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("auth_data.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("auth_data.signature must be 64 Ed25519 bytes"))?;
    device_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_policy_device_digest");
            recovery_signature_error("genesis recovery policy device signature verification failed")
        })
}

pub(super) async fn resolve_session_device_key_for_genesis_policy(
    state: &AppState,
    principal_id: &str,
    session: &SessionRecord,
) -> Result<VerifyingKey, AppError> {
    let not_bound = || {
        AppError::conflict(format!(
            "session device `{}` is not bound to principal `{principal_id}` with a public key",
            session.device_id
        ))
        .with_wire_code("recovery_policy_device_unauthorized")
    };
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: principal_id.to_owned(),
            device_id: session.device_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(format!("device lookup failed: {error}")))?
        .ok_or_else(not_bound)?;
    if device.revoked_at.is_some() {
        return Err(not_bound());
    }
    let material = device
        .payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(not_bound)?;
    crate::routing::identity::device_signing::decode_ed25519_key(material, "multibase")
        .map_err(|error| AppError::internal(format!("session device key invalid: {error}")))
}

pub(super) async fn verify_recovery_auth_signature(
    state: &AppState,
    payload: &Value,
    principal_id: &str,
) -> Result<(), AppError> {
    let auth_data = payload
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::param_invalid("auth_data is required"))?;
    let verification_method = auth_data
        .get("verification_method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::param_invalid("auth_data.verification_method is required"))?;
    let (method_did, device_fragment) = verification_method.rsplit_once('#').ok_or_else(|| {
        recovery_signature_error("recovery authority method has no device fragment")
    })?;
    let method_did = arkret_identifiers::Did::new(method_did.to_owned()).map_err(|error| {
        recovery_signature_error(format!("recovery authority method DID is invalid: {error}"))
    })?;
    let method_principal = arkret_wire::project_did_to_core_id(&method_did).map_err(|error| {
        recovery_signature_error(format!(
            "recovery authority method DID cannot be projected: {error}"
        ))
    })?;
    if method_principal.as_str() != principal_id {
        return Err(recovery_signature_error(
            "recovery authority method does not belong to the policy principal",
        ));
    }
    let device_id =
        arkret_identifiers::DeviceId::new(device_fragment.to_owned()).map_err(|error| {
            recovery_signature_error(format!(
                "recovery authority device fragment is invalid: {error}"
            ))
        })?;
    let authority_key = arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(principal_id.to_owned()).map_err(|error| {
            AppError::internal(format!("recovery policy principal id is invalid: {error}"))
        })?,
        arkret_identifiers::DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("local Station id is invalid: {error}")))?,
    );
    let authority = state
        .persistence()
        .principal_resolution_by_account_id(&authority_key)
        .await
        .map_err(|error| AppError::internal(format!("recovery authority lookup failed: {error}")))?
        .ok_or_else(|| {
            recovery_signature_error("recovery account authority pair is not durably accepted")
        })?;
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: principal_id.to_owned(),
            device_id: device_id.to_string(),
        })
        .await
        .map_err(|error| {
            AppError::internal(format!("recovery authority device lookup failed: {error}"))
        })?
        .ok_or_else(|| recovery_signature_error("recovery authority device is unavailable"))?;
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return Err(recovery_signature_error(
            "recovery authority device is not active",
        ));
    }
    let projected = serde_json::from_value::<
        crate::routing::identity::device_signing::ProjectedDevicePayload,
    >(device.payload)
    .map_err(|error| {
        AppError::internal(format!(
            "recovery authority device evidence is invalid: {error}"
        ))
    })?;
    let authorize_event_id = projected.device_authorize_event_id.ok_or_else(|| {
        recovery_signature_error("recovery authority device has no accepted authorization Event")
    })?;
    let authorize_event = state
        .event_queries()
        .canonical_event(authorize_event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "recovery authority authorization lookup failed: {error}"
            ))
        })?
        .ok_or_else(|| {
            recovery_signature_error("recovery authority authorization Event is unavailable")
        })?;
    if !authorization_event_actor_matches_account(&authorize_event.actor_id, &authority_key)
        || authorize_event.kind != arkret_wire::event_kind_str::DEVICE_AUTHORIZE
        || authorize_event.realm_id.as_deref() != Some(authority.pcr_realm_id.as_str())
    {
        return Err(recovery_signature_error(
            "recovery authority device authorization is outside the selected account lineage",
        ));
    }
    let material = projected
        .device_public_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| recovery_signature_error("recovery authority device key is unavailable"))?;
    let device_key =
        crate::routing::identity::device_signing::decode_ed25519_key(material, "multibase")
            .map_err(|error| {
                recovery_signature_error(format!(
                    "recovery authority device key is invalid: {error}"
                ))
            })?;
    let typed: RecoveryPolicy = serde_json::from_value(payload.clone()).map_err(|error| {
        AppError::param_invalid(format!("recovery policy violates SDK shape: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let transcript_bytes = typed
        .signature_transcript_bytes()
        .map_err(|error| AppError::internal(format!("recovery transcript failed: {error}")))?;
    let signature_b64 = auth_data
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("auth_data.signature is required"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("auth_data.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("auth_data.signature must be 64 Ed25519 bytes"))?;
    device_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_policy_device_digest");
            recovery_signature_error("recovery policy authority signature verification failed")
        })
}

#[cfg(test)]
mod account_lineage_tests {
    use super::*;

    #[test]
    fn device_authorization_requires_the_complete_account_actor() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let account = AccountId::new(principal.clone(), station);
        let expected = arkret_wire::ActorId::account(account.clone());
        assert!(authorization_event_actor_matches_account(
            &expected.canonical_key().unwrap(),
            &account,
        ));
        let foreign = arkret_wire::ActorId::account(AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        for key in [
            foreign.canonical_key().unwrap(),
            arkret_wire::ActorId::service(principal.clone())
                .canonical_key()
                .unwrap(),
            principal.to_string(),
        ] {
            assert!(!authorization_event_actor_matches_account(&key, &account));
        }
    }
}
