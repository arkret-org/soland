use arkret_models_collaboration::direct_conversation_ops::{
    AcceptedAtServiceBinding, AcceptedAtServiceBindingCore, MultikeyMethodType,
    PrincipalServiceBindingCommitOutcome, PrincipalServiceBindingCommitRequestBody,
    PrincipalServiceBindingPrepareOutcome, PrincipalServiceBindingPrepareRequestBody,
    PrincipalServiceBindingProofPurpose, PrincipalServiceKind, ServiceVerificationMethod,
};
use arkret_wire::{Base64UrlString, Hash, PrincipalAuthorityInstance, ProtocolSignature};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer as _;
use salvo::Writer as _;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::{Depot, Request};
use serde::{Deserialize, Serialize};
use soland_http::error::{AppError, ErrorCode};
use soland_services::identity::{AccountDataCasOutcome, AccountDataState};

use super::super::AuthArgs;
use crate::JsonResult;
use crate::state::AppState;

const BINDING_STATE_KEY: &str = "ak.internal.principal_service_binding.v1";
const MAX_CAS_ATTEMPTS: usize = 8;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalServiceBindingState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_binding: Option<AcceptedAtServiceBinding>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pending: std::collections::BTreeMap<String, PendingPrincipalServiceBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingPrincipalServiceBinding {
    prepare: PrincipalServiceBindingPrepareOutcome,
    principal_authorization_evidence: arkret_wire::FederatedDeviceSigningKeyEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_current_binding_digest: Option<Hash>,
}

fn canonical_now() -> Result<DateTime<Utc>, AppError> {
    DateTime::<Utc>::from_timestamp_millis(Utc::now().timestamp_millis())
        .ok_or_else(|| AppError::internal("current timestamp is out of range"))
}

fn decode_state(
    entry: Option<&AccountDataState>,
) -> Result<PrincipalServiceBindingState, AppError> {
    entry
        .map(|entry| {
            serde_json::from_value(entry.payload.clone()).map_err(|error| {
                AppError::internal(format!(
                    "stored principal service binding state is invalid: {error}"
                ))
            })
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

async fn load_state(
    state: &AppState,
    principal_id: &str,
) -> Result<(Option<AccountDataState>, PrincipalServiceBindingState), AppError> {
    let entry = state
        .account_data()
        .entry(principal_id, BINDING_STATE_KEY)
        .await
        .map_err(|error| {
            AppError::internal(format!("principal service binding lookup failed: {error}"))
        })?;
    let decoded = decode_state(entry.as_ref())?;
    Ok((entry, decoded))
}

async fn compare_and_set_state(
    state: &AppState,
    principal_id: &str,
    previous: Option<&AccountDataState>,
    payload: &PrincipalServiceBindingState,
    updated_at: DateTime<Utc>,
) -> Result<bool, AppError> {
    let expected_revision = previous.map_or(0, |entry| entry.revision);
    let record = AccountDataState {
        actor_id: principal_id.to_owned(),
        account_data_key: BINDING_STATE_KEY.to_owned(),
        revision: expected_revision + 1,
        payload: serde_json::to_value(payload).map_err(|error| {
            AppError::internal(format!(
                "principal service binding state encoding failed: {error}"
            ))
        })?,
        tombstone: false,
        updated_at,
    };
    let result = state
        .account_data()
        .compare_and_set(record, expected_revision)
        .await
        .map_err(|error| {
            AppError::internal(format!("principal service binding persist failed: {error}"))
        })?;
    Ok(matches!(result, AccountDataCasOutcome::Applied(_)))
}

/// Development-only fixture seam. The supplied accepted binding already
/// carries the exact authority instance and is validated before persistence.
pub(crate) async fn install_conformance_binding(
    state: &AppState,
    binding: AcceptedAtServiceBinding,
) -> Result<(), AppError> {
    if !state.config().development_mode {
        return Err(AppError::new(
            ErrorCode::NotFound,
            "conformance principal binding installation requires development mode",
        ));
    }
    binding
        .validate_shape()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    for _ in 0..MAX_CAS_ATTEMPTS {
        let (previous, mut stored) = load_state(state, binding.principal_id.as_str()).await?;
        stored.current_binding = Some(binding.clone());
        if compare_and_set_state(
            state,
            binding.principal_id.as_str(),
            previous.as_ref(),
            &stored,
            canonical_now()?,
        )
        .await?
        {
            return Ok(());
        }
    }
    Err(AppError::conflict(
        "principal service binding fixture changed concurrently",
    ))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.principal_service_binding.command.prepare",
    tags("identity")
)]
pub(super) async fn prepare(
    aa: AuthArgs,
    body: JsonBody<PrincipalServiceBindingPrepareRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PrincipalServiceBindingPrepareOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let (previous, mut stored) = load_state(state, &session.actor).await?;
    if stored
        .current_binding
        .as_ref()
        .map(|binding| &binding.binding_digest)
        != body.expected_current_binding_digest.as_ref()
    {
        return Err(AppError::conflict(
            "principal service binding predecessor changed",
        ));
    }
    if let Some(pending) = stored.pending.get(body.request_id.as_str()) {
        return crate::json_ok(pending.prepare.clone());
    }
    let device_id = arkret_wire::DeviceId::new(session.device_id.clone()).map_err(|error| {
        AppError::invalid_param(format!("session device id is invalid: {error}"))
    })?;
    let actor_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::invalid_param(format!("session actor is invalid: {error}")))?;
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: session.actor.clone(),
            device_id: session.device_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(format!("binding device lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "binding device is unavailable",
            )
        })?;
    let payload = serde_json::from_value::<
        crate::routing::identity::device_signing::ProjectedDevicePayload,
    >(device.payload)
    .map_err(|error| AppError::internal(format!("binding device evidence is invalid: {error}")))?;
    let authorize_event_id = payload.device_authorize_event_id.ok_or_else(|| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "binding device has no accepted authorization Event",
        )
    })?;
    let authorize = state
        .event_queries()
        .canonical_event(authorize_event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("binding authorization lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "binding authorization Event is unavailable",
            )
        })?;
    let realm_id = arkret_wire::RealmId::new(authorize.realm_id.ok_or_else(|| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "binding authorization has no PCR Realm",
        )
    })?)
    .map_err(|error| AppError::internal(format!("binding PCR Realm is invalid: {error}")))?;
    let resolution = state
        .persistence()
        .principal_resolution_for_realm(&realm_id)
        .await
        .map_err(|error| AppError::internal(format!("binding authority lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "binding authority is unavailable",
            )
        })?;
    if resolution.authority_instance.principal_id != actor_id
        || resolution.authority_instance.principal_server_id.as_str() != state.service_id()
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "binding authority does not match the authenticated principal",
        ));
    }
    let principal_method =
        arkret_wire::DidUrl::new(format!("{}#{}", resolution.projection.full_id, device_id))
            .map_err(|error| {
                AppError::internal(format!("binding principal method is invalid: {error}"))
            })?;
    let principal_authorization_evidence =
        crate::jws_verify::federated_device_signing_key_evidence(
            state,
            &actor_id,
            &device_id,
            principal_method.as_str(),
        )
        .await
        .map_err(|error| AppError::new(ErrorCode::FailedPrecondition, error))?;
    let service_resolution = state
        .current_signed_service_resolution()
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "service resolution is unavailable",
            )
        })?;
    let accepted_at = canonical_now()?;
    let expires_at = accepted_at + chrono::Duration::minutes(5);
    let challenge_id = Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()),
    )
    .map_err(|error| AppError::internal(format!("binding challenge is invalid: {error}")))?;
    let (_, service_method_id) =
        state
            .current_service_receipt_binding()
            .await
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FailedPrecondition,
                    format!("current service assertion method is unavailable: {error}"),
                )
            })?;
    let authority_evidence = principal_authorization_evidence
        .registration_did_evidence
        .method_evidence
        .clone();
    let mut binding_draft = AcceptedAtServiceBindingCore {
        principal_id: actor_id,
        authority_instance: resolution.authority_instance,
        service_id: arkret_wire::DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service id is invalid: {error}")))?,
        trust_domain: state.config().trust_domain.clone(),
        service_kind: PrincipalServiceKind::PrincipalServer,
        service_verification_method: ServiceVerificationMethod {
            id: service_method_id,
            controller: state.service_full_id(),
            method_type: MultikeyMethodType::Multikey,
            public_key_multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                state.notary_verifying_key().as_bytes(),
            ),
        },
        endpoint_origins: vec![service_resolution.record.base_url.clone()],
        document_digest: authority_evidence.document_digest.clone(),
        authority_evidence,
        service_resolution: arkret_models_identity::ServiceResolutionCarrier::Inline {
            inline: service_resolution,
        },
        authorization_challenge: challenge_id.clone(),
        history_head: Some(
            principal_authorization_evidence
                .registration_did_evidence
                .method_history_head
                .clone(),
        ),
        version_id: Some(
            principal_authorization_evidence
                .registration_did_evidence
                .version_id
                .clone(),
        ),
        not_before: accepted_at,
        expires_at: Some(expires_at),
        accepted_at,
        predecessor_binding_digest: body.expected_current_binding_digest.clone(),
        binding_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
            .map_err(|error| AppError::internal(error.to_string()))?,
    };
    binding_draft.binding_digest = binding_draft
        .computed_binding_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let outcome = PrincipalServiceBindingPrepareOutcome {
        request_id: body.request_id.clone(),
        challenge_id,
        binding_draft,
        issued_at: accepted_at,
        expires_at,
    };
    outcome
        .validate_shape()
        .map_err(|error| AppError::internal(error.to_string()))?;
    stored.pending.insert(
        body.request_id.to_string(),
        PendingPrincipalServiceBinding {
            prepare: outcome.clone(),
            principal_authorization_evidence,
            expected_current_binding_digest: body.expected_current_binding_digest,
        },
    );
    if !compare_and_set_state(
        state,
        &session.actor,
        previous.as_ref(),
        &stored,
        accepted_at,
    )
    .await?
    {
        return Err(AppError::conflict(
            "principal service binding changed concurrently",
        ));
    }
    crate::json_ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.principal_service_binding.command.commit",
    tags("identity")
)]
pub(super) async fn commit(
    aa: AuthArgs,
    body: JsonBody<PrincipalServiceBindingCommitRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PrincipalServiceBindingCommitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    for _ in 0..MAX_CAS_ATTEMPTS {
        let (previous, mut stored) = load_state(state, &session.actor).await?;
        if let Some(binding) = stored.current_binding.as_ref()
            && binding.binding_digest == body.binding_digest
        {
            return crate::json_ok(PrincipalServiceBindingCommitOutcome {
                binding: binding.clone(),
            });
        }
        let pending = stored
            .pending
            .get(body.request_id.as_str())
            .cloned()
            .ok_or_else(|| {
                AppError::conflict("principal service binding challenge is unavailable")
            })?;
        if pending.prepare.challenge_id != body.challenge_id
            || pending.prepare.binding_draft.binding_digest != body.binding_digest
            || pending.prepare.expires_at <= canonical_now()?
            || stored
                .current_binding
                .as_ref()
                .map(|binding| &binding.binding_digest)
                != pending.expected_current_binding_digest.as_ref()
            || body.principal_authorization_proof.verification_method
                != pending.principal_authorization_evidence.verification_method
            || body.principal_authorization_proof.created_at
                != pending.prepare.binding_draft.accepted_at
        {
            return Err(AppError::conflict(
                "principal service binding challenge does not match the prepared draft",
            ));
        }
        let principal_input = pending
            .prepare
            .binding_draft
            .proof_signing_input_bytes(
                PrincipalServiceBindingProofPurpose::PrincipalAuthorization,
                &body.principal_authorization_proof.verification_method,
            )
            .map_err(|error| AppError::invalid_param(error.to_string()))?;
        let signing_multibase = pending
            .principal_authorization_evidence
            .device_signing_key
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| AppError::internal("binding device key is not did:key"))?;
        let public_key = arkret_signatures::proof::PublicKeyMaterial::Ed25519Multibase {
            value: signing_multibase.to_owned(),
        };
        if !arkret_signatures::proof::verify_detached_ed25519_signature(
            &public_key,
            &principal_input,
            body.principal_authorization_proof.jws.as_str(),
        ) {
            return Err(AppError::new(
                ErrorCode::SignatureInvalid,
                "principal service binding authorization proof is invalid",
            ));
        }
        let service_input = pending
            .prepare
            .binding_draft
            .proof_signing_input_bytes(
                PrincipalServiceBindingProofPurpose::ServiceAcceptance,
                &pending.prepare.binding_draft.service_verification_method.id,
            )
            .map_err(|error| AppError::internal(error.to_string()))?;
        let service_signature = state.notary_signing_key().sign(&service_input);
        let service_acceptance_proof = ProtocolSignature {
            verification_method: pending
                .prepare
                .binding_draft
                .service_verification_method
                .id
                .clone(),
            created_at: pending.prepare.binding_draft.accepted_at,
            jws: Base64UrlString::new(URL_SAFE_NO_PAD.encode(service_signature.to_bytes()))
                .map_err(|error| AppError::internal(error.to_string()))?,
        };
        let draft = pending.prepare.binding_draft;
        let binding = AcceptedAtServiceBinding {
            principal_id: draft.principal_id,
            authority_instance: draft.authority_instance,
            service_id: draft.service_id,
            trust_domain: draft.trust_domain,
            service_kind: draft.service_kind,
            service_verification_method: draft.service_verification_method,
            endpoint_origins: draft.endpoint_origins,
            document_digest: draft.document_digest,
            authority_evidence: draft.authority_evidence,
            service_resolution: draft.service_resolution,
            authorization_challenge: draft.authorization_challenge,
            history_head: draft.history_head,
            version_id: draft.version_id,
            not_before: draft.not_before,
            expires_at: draft.expires_at,
            accepted_at: draft.accepted_at,
            predecessor_binding_digest: draft.predecessor_binding_digest,
            binding_digest: draft.binding_digest,
            service_acceptance_proof,
            principal_authorization_proof: body.principal_authorization_proof.clone(),
            principal_authorization_evidence: pending.principal_authorization_evidence,
        };
        binding
            .validate_shape()
            .map_err(|error| AppError::invalid_param(error.to_string()))?;
        stored.current_binding = Some(binding.clone());
        stored.pending.remove(body.request_id.as_str());
        if compare_and_set_state(
            state,
            &session.actor,
            previous.as_ref(),
            &stored,
            canonical_now()?,
        )
        .await?
        {
            return crate::json_ok(PrincipalServiceBindingCommitOutcome { binding });
        }
    }
    Err(AppError::conflict(
        "principal service binding changed concurrently",
    ))
}

/// The stored accepted-at binding for exactly this authority instance.
///
/// Deliberately unused today, and deliberately not deleted: it is the only
/// selector shape `contact-and-direct-conversation.md` §9.1.2 permits, and the
/// alternative — selecting a binding by principal core — is the same-core PCR
/// substitution AUTH-RELAY-003 forbids. The resolver cannot call it until the
/// `creation_required` branch carries the founder's exact authority instance,
/// and `prepare`/`commit` above cannot produce a binding until the same carrier
/// lands, so the only writer today is the conformance fixture. Tracked in
/// `arkret-work/work/active/2026-08-08-1108-soland-unwired-spec-capabilities.md`:
/// wire it or delete it together with the fixture field, never widen it.
#[allow(dead_code)]
pub(crate) async fn binding_for_authority(
    state: &AppState,
    authority: &PrincipalAuthorityInstance,
) -> Result<Option<AcceptedAtServiceBinding>, AppError> {
    authority
        .validate()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let (_, binding_state) = load_state(state, authority.principal_id.as_str()).await?;
    Ok(binding_state
        .current_binding
        .filter(|binding| binding.authority_instance == *authority))
}
