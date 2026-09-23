//! Authenticated signer-key self query over committed authority state.

use arkret_canonical::base64url::base64url_decode;
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload;
use arkret_models_identity::{
    CurrentSignerKeyQuerySender, ResolvedSignerKey, SignerKeyQueryResult, SignerKeyQuerySelector,
    SignerKeysQueryOutcome, SignerKeysQueryRequestBody,
};
use arkret_wire::{
    CommittedEventRef, CurrentSelector, EventId, RealmId, StationSigningKey, TypedCurrentResult,
};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::AuthArgs;
use crate::state::AppState;

pub(crate) fn self_router() -> Router {
    Router::with_path("signer-keys/query").post(self_query)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.signer_keys.read.resolve", tags("identity"))]
async fn self_query(
    aa: AuthArgs,
    body: JsonBody<SignerKeysQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SignerKeysQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate().map_err(self_request_error)?;
    let actor = super::session_actor::validated_session_actor(state, &session).await?;
    if actor.as_account_id() != Some(&body.recipient_account_id)
        || body.recipient_account_id.station_id != state.service_core_id()
    {
        return Err(AppError::not_found("signer key unavailable"));
    }
    json_ok(resolve_self_signer_keys(state, &session, &body).await?)
}

pub(crate) fn self_request_error(error: arkret_wire::WireError) -> AppError {
    AppError::from_rejection(
        match error.error_code() {
            Some(arkret_wire::ErrorCode::PayloadTooLarge) => {
                arkret_wire::ErrorCode::PayloadTooLarge
            }
            _ => arkret_wire::ErrorCode::SchemaViolation,
        },
        error.to_string(),
    )
}

pub(crate) fn self_result_error(error: arkret_wire::WireError) -> AppError {
    AppError::from_rejection(
        match error.error_code() {
            Some(arkret_wire::ErrorCode::LimitExceeded) => arkret_wire::ErrorCode::LimitExceeded,
            _ => arkret_wire::ErrorCode::SchemaViolation,
        },
        error.to_string(),
    )
}

pub(crate) async fn resolve_self_signer_keys(
    state: &AppState,
    session: &soland_services::identity::SessionIdentityState,
    body: &SignerKeysQueryRequestBody,
) -> Result<SignerKeysQueryOutcome, AppError> {
    body.validate().map_err(self_request_error)?;
    let requester = arkret_wire::ActorId::account(body.recipient_account_id.clone());
    let requester_is_member =
        crate::routing::realm_has_member(state, body.realm_id.as_str(), &requester.to_string())
            .await;
    let ordinary = state
        .realms()
        .realm_metadata(body.realm_id.as_str())
        .await
        .ok()
        .flatten()
        .is_some_and(|realm| !realm.minimal_metadata_realm);
    let mut results = Vec::with_capacity(body.queries.len());
    for selector in &body.queries {
        let visible = ordinary
            && if let Some(reference) = selector.committed_event_ref() {
                exact_visible_committed_event(state, session, &body.realm_id, reference).await
            } else {
                requester_is_member
                    && crate::routing::realm_has_member(
                        state,
                        body.realm_id.as_str(),
                        &selector.actor().to_string(),
                    )
                    .await
            };
        let resolved = if visible {
            match selector {
                SignerKeyQuerySelector::CurrentAdmission {
                    sender: CurrentSignerKeyQuerySender::Agent { .. },
                } => current_agent_key(state, &body.realm_id, selector).await,
                // A historical answer needs the authorization state as of the
                // exact accepted Event, rather than a current-key substitution.
                _ => None,
            }
        } else {
            None
        };
        results.push(
            resolved.unwrap_or_else(|| SignerKeyQueryResult::Unavailable {
                selector: selector.clone(),
            }),
        );
    }
    let outcome = SignerKeysQueryOutcome {
        request_id: body.request_id.clone(),
        realm_id: body.realm_id.clone(),
        recipient_account_id: body.recipient_account_id.clone(),
        results,
    };
    outcome
        .validate_for_request(body)
        .map_err(self_result_error)?;
    Ok(outcome)
}

async fn exact_visible_committed_event(
    state: &AppState,
    session: &soland_services::identity::SessionIdentityState,
    realm_id: &RealmId,
    reference: &CommittedEventRef,
) -> bool {
    let Ok(Some(record)) = state
        .authority_commits()
        .committed_event(&reference.event_id)
        .await
    else {
        return false;
    };
    if record.event.event_id != reference.event_id
        || record.event.realm_id != *realm_id
        || record.commit.event_ref != reference.event_id
        || record.commit.commit_id != reference.commit_id
        || record.commit.stream_ref != reference.stream_ref
        || record.commit.stream_position != reference.stream_position
    {
        return false;
    }
    let Ok(Some(event_record)) = state
        .event_queries()
        .canonical_event(reference.event_id.as_str())
        .await
    else {
        return false;
    };
    event_record.realm_id.as_deref() == Some(realm_id.as_str())
        && crate::routing::events::event_log::event_visible_to_session(
            state,
            &event_record,
            session,
        )
        .await
}

async fn current_agent_key(
    state: &AppState,
    realm_id: &RealmId,
    selector: &SignerKeyQuerySelector,
) -> Option<SignerKeyQueryResult> {
    let agent_id = &selector.actor().as_account_id()?.principal_id;
    let agent = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .ok()??;
    if agent.id != agent_id.as_str() {
        return None;
    }
    let pcr_realm_id = RealmId::new(agent.principal_control_realm_id).ok()?;
    let material = state
        .authority_commits()
        .realm_state_snapshot_material(&pcr_realm_id)
        .await
        .ok()??;
    let mut status = None;
    let mut active = Vec::new();
    for entry in &material.current_state_entries {
        let TypedCurrentResult::Value {
            selector: current,
            value,
            revision,
        } = entry
        else {
            continue;
        };
        match current {
            CurrentSelector::AgentStatus { agent_id: subject } if subject == agent_id => {
                if status
                    .replace(serde_json::from_value::<AgentLifecycleState>(value.clone()).ok()?)
                    .is_some()
                {
                    return None;
                }
            }
            CurrentSelector::AgentKey {
                agent_id: subject,
                agent_key_id,
            } if subject == agent_id => {
                for authorization in value.get("authorizations")?.as_array()? {
                    let entry_value = authorization.get("value")?;
                    // Keyed-set revoke markers share this family but have no
                    // verification_method; they are not active authorizations.
                    if entry_value.get("verification_method").is_none() {
                        continue;
                    }
                    let payload: AgentKeyAuthorizePayload =
                        serde_json::from_value(entry_value.clone()).ok()?;
                    if payload.agent_id != *agent_id
                        || payload.key_id.as_str() != agent_key_id.as_str()
                    {
                        return None;
                    }
                    if payload
                        .expires_at
                        .is_some_and(|expiry| expiry <= chrono::Utc::now())
                    {
                        continue;
                    }
                    let event_id =
                        EventId::new(authorization.get("tag_id")?.as_str()?.strip_suffix(":1")?)
                            .ok()?;
                    active.push((payload, event_id, revision.clone()));
                }
            }
            _ => {}
        }
    }
    if status != Some(AgentLifecycleState::Active) || active.len() != 1 {
        return None;
    }
    let (payload, event_id, revision) = active.pop()?;
    if payload.verification_method != *selector.verification_method() {
        return None;
    }
    let raw_key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &payload.public_key,
        &payload.verification_method,
    )
    .ok()?
    .raw_public_key;
    let record = state
        .authority_commits()
        .committed_event(&event_id)
        .await
        .ok()??;
    let revision_record = state
        .authority_commits()
        .committed_event_by_commit_id(&revision.commit_id)
        .await
        .ok()??;
    let accepted_payload = AgentKeyAuthorizePayload::try_from(&record.event).ok()?;
    let accepted_key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &accepted_payload.public_key,
        &accepted_payload.verification_method,
    )
    .ok()?;
    if record.event.event_id != event_id
        || record.event.realm_id != pcr_realm_id
        || record.commit.event_ref != event_id
        || accepted_payload.agent_id != *agent_id
        || accepted_payload.key_id != payload.key_id
        || accepted_payload.verification_method != payload.verification_method
        || accepted_key.raw_public_key != raw_key
        || serde_json::to_value(&accepted_payload).ok()? != serde_json::to_value(&payload).ok()?
        || revision_record.commit.commit_id != revision.commit_id
        || revision_record.commit.stream_ref != record.commit.stream_ref
        || revision_record.commit.stream_position != revision.stream_position
        || record.commit.stream_position > revision.stream_position
        || !material.visible_stream_heads.iter().any(|head| {
            head.stream_ref == record.commit.stream_ref
                && head.stream_position >= revision.stream_position
        })
    {
        return None;
    }
    let authorization_ref = CommittedEventRef {
        event_id,
        commit_id: record.commit.commit_id,
        stream_ref: record.commit.stream_ref,
        stream_position: record.commit.stream_position,
    };
    let key = StationSigningKey {
        actor: selector.actor().clone(),
        verification_method: selector.verification_method().clone(),
        public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            raw_key,
        ))
        .ok()?,
        authorization_ref: authorization_ref.event_id.clone(),
    };
    let key = ResolvedSignerKey::from_station_key(
        key,
        authorization_ref,
        revision,
        material.governance_generation,
        selector,
        realm_id,
    )
    .ok()?;
    Some(SignerKeyQueryResult::CurrentResolved {
        selector: selector.clone(),
        key,
    })
}

/// Resolve the active Agent producer key for an Event being admitted now.
///
/// This checks the durable Agent status/key projection and the exact accepted
/// authorization Commit at one PCR snapshot cut. Callers still verify the
/// Event producer proof and enforce the Agent's action scope separately. This
/// must never be used for a historical Event whose key may since have rotated.
pub(crate) async fn current_agent_producer_binding(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<([u8; 32], CommittedEventRef), String> {
    let producer = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| "Agent Event has no producer proof".to_owned())?;
    let actor = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    let agent_id = &actor
        .as_account_id()
        .ok_or_else(|| "Agent producer is not an account ActorId".to_owned())?
        .principal_id;
    let agent = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Agent producer record unavailable".to_owned())?;
    let realm_id =
        RealmId::new(agent.principal_control_realm_id).map_err(|error| error.to_string())?;
    let selector = SignerKeyQuerySelector::CurrentAdmission {
        sender: CurrentSignerKeyQuerySender::Agent {
            actor: actor.clone(),
            verification_method: producer.verification_method.clone(),
        },
    };
    let Some(SignerKeyQueryResult::CurrentResolved { key, .. }) =
        current_agent_key(state, &realm_id, &selector).await
    else {
        return Err("Agent producer has no current accepted signing key".to_owned());
    };
    let raw_key = base64url_decode(key.public_key_b64u.as_str())
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "Agent producer key must be 32 bytes".to_owned())?;
    Ok((raw_key, key.authorization_ref))
}

pub(super) async fn current_device_projection_document(
    state: &AppState,
    attestation: &arkret_models_crypto::DeviceProjectionAttestation,
) -> Result<arkret_identity::DidDocument, AppError> {
    let unavailable = || AppError::not_found("current signer evidence is unavailable");
    let did =
        arkret_identity::verification_method_did(attestation.proof.verification_method.as_str())
            .map_err(|_| unavailable())?;
    if arkret_wire::project_did_to_core_id(&did).map_err(|_| unavailable())?
        != attestation.attestation.account_id.station_id
    {
        return Err(unavailable());
    }
    let current = state
        .dids()
        .resolve_current_service_did(&did)
        .await
        .map_err(|_| unavailable())?;
    Ok(current.document)
}

pub(super) fn verify_current_device_projection(
    attestation: &arkret_models_crypto::DeviceProjectionAttestation,
    document: &arkret_identity::DidDocument,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    let method = &attestation.proof.verification_method;
    let did = arkret_identity::verification_method_did(method.as_str())
        .map_err(|error| error.to_string())?;
    if document.id != did
        || arkret_wire::project_did_to_core_id(&did).map_err(|error| error.to_string())?
            != attestation.attestation.account_id.station_id
    {
        return Err("device projection issuer mismatch".to_owned());
    }
    arkret_identity::validate_verification_method_relationship(
        document,
        method,
        &did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| error.to_string())?;
    let key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(document, method.as_str())
        .map_err(|error| error.to_string())?;
    arkret_signatures::device_projection::verify_device_projection_attestation(
        attestation,
        &key,
        now,
    )
    .map_err(|error| error.to_string())
}
