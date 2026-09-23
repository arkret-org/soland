//! Producer proof preflight for the current self authority endpoint.
//!
//! This resolves live local signer material from accepted PCR/Agent state.
//! The authority transaction still has to freeze and recheck the same
//! authorization cut before the Event becomes committed.

use arkret_models_identity::session_credential::{
    SessionGrantCredentialClass, SessionGrantHolderBinding,
};
use arkret_wire::{AccountId, ActorId, DeviceId, Did, Event};
use soland_services::identity::SessionIdentityState;
use soland_services::{ServiceError, ServiceResult};
use soland_storage::SelfProducerCommitGuard;

use super::AppState;

fn rejected(message: impl Into<String>) -> ServiceError {
    ServiceError::Conflict(message.into())
}

fn method_device_id(
    method: &arkret_wire::DidUrl,
    principal: &arkret_wire::DidCoreId,
) -> Option<DeviceId> {
    let (controller, fragment) = method.as_str().rsplit_once('#')?;
    let did = Did::new(controller.to_owned()).ok()?;
    if &arkret_wire::project_did_to_core_id(&did).ok()? != principal {
        return None;
    }
    DeviceId::new(fragment.to_owned()).ok()
}

pub(crate) async fn verify_self_event_producer(
    state: &AppState,
    session: &SessionIdentityState,
    event: &Event,
) -> ServiceResult<SelfProducerCommitGuard> {
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let actor = crate::routing::identity::session_actor::validated_session_actor(state, session)
        .await
        .map_err(|error| rejected(format!("authenticated Account unavailable: {error}")))?;
    if event.actor_id != actor || event.executed_by.is_some() {
        return Err(rejected(
            "self Event requires the exact authenticated actor without delegated execution",
        ));
    }
    let account = actor
        .as_account_id()
        .ok_or_else(|| rejected("self Event actor must be an AccountId"))?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| ServiceError::SchemaViolation("self Event has no producer proof".into()))?;
    let grant = session
        .session_grant
        .as_ref()
        .ok_or_else(|| rejected("self Event needs an authenticated standard grant"))?;
    if grant.credential_class != SessionGrantCredentialClass::Standard
        || grant.account_id != *account
    {
        return Err(rejected("self Event grant does not bind the exact Account"));
    }
    let (key, guard) = match &grant.holder_binding {
        SessionGrantHolderBinding::HumanDevice { .. } => {
            human_producer_key(state, session, account, proof).await?
        }
        SessionGrantHolderBinding::AgentRuntime {
            agent_id,
            agent_key_authorization_ref,
            verification_method,
        } => {
            if agent_id != &account.principal_id
                || verification_method != &proof.verification_method
                || session.agent_session.is_none()
                || grant.device_binding.is_some()
            {
                return Err(rejected("Agent grant triple differs from Event producer"));
            }
            let committed = state
                .authority_commits()
                .committed_event(agent_key_authorization_ref)
                .await?
                .ok_or_else(|| rejected("Agent grant authorization Event is not committed"))?;
            if committed.event.event_id != *agent_key_authorization_ref
                || committed.commit.event_ref != *agent_key_authorization_ref
                || committed.event.kind != arkret_wire::EventKind::AgentKeyAuthorize
            {
                return Err(rejected("Agent grant authorization Commit is invalid"));
            }
            let authorized: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload =
                serde_json::from_value(
                    serde_json::to_value(&committed.event.payload)
                        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
                )
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
            if authorized.agent_id != *agent_id
                || authorized.verification_method != *verification_method
            {
                return Err(rejected(
                    "Agent grant authorization differs from accepted Event",
                ));
            }
            let (current, current_authorization) =
                crate::routing::identity::current_signer_evidence::current_agent_producer_binding(
                    state, event,
                )
                .await
                .map_err(rejected)?;
            if current_authorization.event_id != *agent_key_authorization_ref
                || current_authorization.commit_id != committed.commit.commit_id
                || current_authorization.stream_ref != committed.commit.stream_ref
                || current_authorization.stream_position != committed.commit.stream_position
            {
                return Err(rejected("Agent grant authorization is no longer current"));
            }
            let accepted = arkret_signatures::agent::validate_agent_runtime_public_key(
                &authorized.public_key,
                &authorized.verification_method,
            )
            .map_err(|error| rejected(error.to_string()))?;
            if current != accepted.raw_public_key {
                return Err(rejected(
                    "Agent grant key differs from current accepted key",
                ));
            }
            (
                arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: current.to_vec(),
                },
                SelfProducerCommitGuard::Agent {
                    pcr_realm_id: current_authorization.stream_ref.realm_id().clone(),
                    agent_id: agent_id.clone(),
                    authorization_ref: current_authorization,
                    verification_method: verification_method.clone(),
                },
            )
        }
        _ => return Err(rejected("self Event grant holder cannot sign this Event")),
    };
    let digest_suite = state
        .projections()
        .realm_digest_suite(event.realm_id.as_str());
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        digest_suite,
    )
    .map_err(|error| rejected(format!("Event producer proof invalid: {error}")))?;
    Ok(guard)
}

async fn human_producer_key(
    state: &AppState,
    session: &SessionIdentityState,
    account: &AccountId,
    proof: &arkret_wire::ProducerEventProof,
) -> ServiceResult<(
    arkret_signatures::PublicKeyMaterial,
    SelfProducerCommitGuard,
)> {
    let device_id = DeviceId::new(session.device_id.clone())
        .map_err(|_| rejected("human session has no canonical device id"))?;
    if method_device_id(&proof.verification_method, &account.principal_id)
        != Some(device_id.clone())
    {
        return Err(rejected(
            "Event proof DID controller or fragment differs from authenticated device",
        ));
    }
    let expected = session
        .session_grant
        .as_ref()
        .and_then(|grant| grant.device_binding.as_ref())
        .ok_or_else(|| rejected("human grant has no accepted device binding"))?;
    if expected.device_id != device_id {
        return Err(rejected(
            "human grant device differs from authenticated session",
        ));
    }
    let selector =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            account.principal_id.as_str(),
            device_id.as_str(),
        )
        .await?;
    if selector.authorization_ref.event_id != *expected.committed_authorization()
        || selector.authorization_ref.event_id != expected.authorization_event_id
        || expected.model_generation_ref == 0
    {
        return Err(rejected(
            "human grant is stale against current device authorization",
        ));
    }
    if state
        .persistence()
        .device_revocation_gate_status(&selector)
        .await?
        != soland_storage::DeviceRevocationGateStatus::Active
    {
        return Err(rejected(
            "Event producer device revocation gate is not active",
        ));
    }
    let facet =
        crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
            state,
            account.principal_id.as_str(),
            device_id.as_str(),
        )
        .await?;
    let authorization = crate::routing::identity::device_signing::current_device_authorization(
        state,
        &ActorId::account(account.clone()),
        &device_id,
        &facet,
    )
    .await?
    .ok_or_else(|| rejected("Event producer device authorization is unavailable"))?;
    if authorization.authorized_generation_ref != expected.model_generation_ref {
        return Err(rejected(
            "human grant generation differs from current device authorization",
        ));
    }
    let multibase = authorization
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| rejected("accepted device key is not did:key"))?;
    Ok((
        arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        },
        SelfProducerCommitGuard::HumanDevice(selector),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_method_must_name_the_exact_account_did_and_device_fragment() {
        let controller = Did::new("did:webvh:z6Mkfull:alice.example".to_owned()).unwrap();
        let principal = arkret_wire::project_did_to_core_id(&controller).unwrap();
        let device =
            DeviceId::new("ak:device:01904100-0000-7000-8000-a11ce0000001".to_owned()).unwrap();
        let method = arkret_wire::DidUrl::new(format!("{}#{}", controller, device)).unwrap();
        assert_eq!(method_device_id(&method, &principal), Some(device.clone()));
        let other = arkret_wire::DidUrl::new(format!("did:webvh:z6Mkother:bob.example#{}", device))
            .unwrap();
        assert_eq!(method_device_id(&other, &principal), None);
    }
}
