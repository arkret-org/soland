use std::collections::BTreeMap;

use arkret_models_collaboration::direct_conversation_ops::{
    AcceptedAtServiceBinding, AcceptedAtServiceBindingCore, DidBindingEvidenceKind,
    DidBindingEvidenceReceipt, DidBindingMethodProof, DidBindingMethodProofKind, DidBindingWitness,
    MultikeyMethodType, PrincipalServiceBindingCommitOutcome,
    PrincipalServiceBindingCommitRequestBody, PrincipalServiceBindingPrepareOutcome,
    PrincipalServiceBindingPrepareRequestBody, PrincipalServiceBindingProofPurpose,
    PrincipalServiceKind, ServiceVerificationMethod,
};
use arkret_wire::{
    Base64UrlString, CoreId, DeviceId, DidUrl, FullId, Hash, PrincipalId, ProtocolSignature,
    ServiceId, project_full_id_to_core_id,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signer as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::{Depot, Request};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soland_http::error::{AppError, ErrorCode};
use soland_services::identity::{AccountDataCasOutcome, AccountDataState};

use super::super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

const BINDING_STATE_KEY: &str = "ak.internal.principal_service_binding.v1";
const CHALLENGE_TTL_MINUTES: i64 = 5;
const MAX_CAS_ATTEMPTS: usize = 8;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalServiceBindingState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_binding: Option<AcceptedAtServiceBinding>,
    #[serde(default)]
    prepares: BTreeMap<String, PrincipalServiceBindingPrepareRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalServiceBindingPrepareRecord {
    request_digest: String,
    outcome: PrincipalServiceBindingPrepareOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_request_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_outcome: Option<PrincipalServiceBindingCommitOutcome>,
}

fn canonical_now() -> Result<DateTime<Utc>, AppError> {
    DateTime::<Utc>::from_timestamp_millis(Utc::now().timestamp_millis())
        .ok_or_else(|| AppError::internal("current timestamp is out of range"))
}

fn request_digest(value: &impl Serialize) -> Result<String, AppError> {
    arkret_canonical::canonical_sha256(value)
        .map_err(|error| AppError::invalid_param(format!("request is not canonical: {error}")))
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

async fn binding_authority_evidence(
    state: &AppState,
    principal_id: &FullId,
    accepted_at: DateTime<Utc>,
) -> Result<BindingAuthoritySnapshot, AppError> {
    if principal_id.method() != "webvh" {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "principal service binding requires complete did:webvh authority history",
        )
        .with_status(StatusCode::PRECONDITION_FAILED));
    }
    let mut records = state
        .dids()
        .log_events(principal_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("principal DID history lookup failed: {error}"))
        })?;
    records.sort_by_key(|entry| entry.seq);
    for (index, entry) in records.iter().enumerate() {
        if entry.did != principal_id.as_str() || entry.seq != index as u64 + 1 {
            return Err(AppError::new(
                ErrorCode::FailedPrecondition,
                "principal DID history identity or sequence is inconsistent",
            )
            .with_status(StatusCode::PRECONDITION_FAILED));
        }
        let digest = arkret_canonical::canonical_sha256(&entry.operation).map_err(|error| {
            AppError::internal(format!("principal DID history digest failed: {error}"))
        })?;
        if digest != entry.event_digest {
            return Err(AppError::new(
                ErrorCode::FailedPrecondition,
                "principal DID history digest is inconsistent",
            )
            .with_status(StatusCode::PRECONDITION_FAILED));
        }
    }
    let entries = records
        .iter()
        .map(|entry| entry.operation.clone())
        .collect::<Vec<_>>();
    let point =
        arkret_signatures::webvh::validate_webvh_history_at(principal_id, &entries, accepted_at)
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FailedPrecondition,
                    format!("principal DID history is not acceptable: {error}"),
                )
                .with_status(StatusCode::PRECONDITION_FAILED)
            })?;
    let document: arkret_identity::DidDocument = serde_json::from_value(point.document.clone())
        .map_err(|error| {
            AppError::internal(format!("validated DID document is invalid: {error}"))
        })?;
    let document_digest = arkret_identity::document_canonical_digest(&document)
        .map_err(|error| AppError::internal(format!("DID document digest failed: {error}")))?;

    let accepted_entry_count = entries
        .iter()
        .position(|entry| {
            entry.get("versionId").and_then(Value::as_str) == Some(point.version_id.as_str())
        })
        .map(|index| index + 1)
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "accepted-at DID version is absent from verified history",
            )
            .with_status(StatusCode::PRECONDITION_FAILED)
        })?;
    let accepted_entries = &entries[..accepted_entry_count];

    let mut declared_witnesses = Vec::new();
    for entry in accepted_entries {
        if let Some(policy) = entry
            .get("parameters")
            .map(arkret_identity::parse_did_webvh_witness_policy)
            .transpose()
            .map_err(|error| AppError::invalid_param(error.to_string()))?
            .flatten()
        {
            declared_witnesses = policy.witnesses;
        }
    }
    declared_witnesses.sort();
    declared_witnesses.dedup();
    let witnesses = declared_witnesses
        .iter()
        .map(|value| {
            let witness_full_id = FullId::new(value.clone()).map_err(|error| {
                AppError::internal(format!("validated witness DID is invalid: {error}"))
            })?;
            Ok(DidBindingWitness {
                controlling_organization: witness_full_id.clone(),
                witness_did: witness_full_id,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let witness_proofs = accepted_entries
        .iter()
        .filter_map(|entry| entry.get("witness").cloned())
        .collect::<Vec<Value>>();
    if !witnesses.is_empty() && witness_proofs.is_empty() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "principal DID witness proof set is unavailable",
        )
        .with_status(StatusCode::PRECONDITION_FAILED));
    }
    let witness_proofs_digest = Hash::new(
        arkret_canonical::canonical_sha256(&witness_proofs)
            .map_err(|error| AppError::internal(format!("witness proof digest failed: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("witness proof digest invalid: {error}")))?;
    let history_head = point.version_id.clone();
    let receipt = DidBindingEvidenceReceipt {
        kind: DidBindingEvidenceKind::AkDidBindingEvidenceV1,
        method: principal_id.method().to_owned(),
        document_digest: document_digest.clone(),
        method_proofs: vec![DidBindingMethodProof {
            kind: DidBindingMethodProofKind::WebvhLog,
            history_head: history_head.clone(),
            witnesses,
            witness_proofs_digest,
        }],
    };
    Ok(BindingAuthoritySnapshot {
        document,
        document_digest,
        receipt,
        history_head,
        version_id: point.version_id,
    })
}

struct BindingAuthoritySnapshot {
    document: arkret_identity::DidDocument,
    document_digest: Hash,
    receipt: DidBindingEvidenceReceipt,
    history_head: String,
    version_id: String,
}

async fn session_principal_ids(
    state: &AppState,
    actor_id: &str,
) -> Result<(CoreId, FullId), AppError> {
    if let Ok(full_id) = FullId::new(actor_id.to_owned()) {
        let core_id = project_full_id_to_core_id(&full_id).map_err(|error| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                format!("session principal has no active core-id adapter: {error}"),
            )
            .with_status(StatusCode::PRECONDITION_FAILED)
        })?;
        return Ok((core_id, full_id));
    }
    let core_id = CoreId::new(actor_id.to_owned()).map_err(|error| {
        AppError::invalid_param(format!("session principal core id is invalid: {error}"))
    })?;
    let current = state
        .persistence()
        .current_principal_resolution(&core_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("principal resolution lookup failed: {error}"))
        })?;
    match current {
        Some(record) => Ok((core_id, record.projection.full_id)),
        None => Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "accepted principal full-id resolution is unavailable",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)),
    }
}

async fn prepare_binding_core(
    state: &AppState,
    principal_id: &CoreId,
    principal_full_id: &FullId,
    challenge_id: Base64UrlString,
    predecessor_binding_digest: Option<Hash>,
    accepted_at: DateTime<Utc>,
) -> Result<AcceptedAtServiceBindingCore, AppError> {
    let authority = binding_authority_evidence(state, principal_full_id, accepted_at).await?;
    let service_full_id = state.service_resolution_commitment().full_id.clone();
    let service_id = project_full_id_to_core_id(&service_full_id).map_err(|error| {
        AppError::internal(format!(
            "service DID has no active core-id adapter: {error}"
        ))
    })?;
    let verification_method =
        DidUrl::new(format!("{service_full_id}#notary-key")).map_err(|error| {
            AppError::internal(format!("service verification method is invalid: {error}"))
        })?;
    let public_base = reqwest::Url::parse(&state.config().public_base_url)
        .map_err(|error| AppError::internal(format!("public base URL is invalid: {error}")))?;
    if public_base.scheme() != "https" {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "principal service binding requires a canonical HTTPS public origin",
        )
        .with_status(StatusCode::PRECONDITION_FAILED));
    }
    let endpoint_origin = public_base.origin().ascii_serialization();
    let placeholder = Hash::new(format!("sha256:{}", "0".repeat(64)))
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut core = AcceptedAtServiceBindingCore {
        principal_id: PrincipalId::from(principal_id.clone()),
        service_id: ServiceId::from(service_id),
        trust_domain: state.config().trust_domain.clone(),
        service_kind: PrincipalServiceKind::PrincipalServer,
        service_verification_method: ServiceVerificationMethod {
            id: verification_method,
            controller: service_full_id,
            method_type: MultikeyMethodType::Multikey,
            public_key_multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                state.notary_verifying_key().as_bytes(),
            ),
        },
        endpoint_origins: vec![endpoint_origin],
        document_digest: authority.document_digest,
        authority_evidence: authority.receipt,
        authorization_challenge: challenge_id,
        history_head: Some(authority.history_head),
        version_id: Some(authority.version_id),
        not_before: accepted_at,
        expires_at: None,
        accepted_at,
        predecessor_binding_digest,
        binding_digest: placeholder,
    };
    core.binding_digest = core
        .computed_binding_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    core.validate_shape()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(core)
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
    let (principal_id, principal_full_id) = session_principal_ids(state, &session.actor).await?;
    let body = body.into_inner();
    if !(22..=128).contains(&body.request_id.as_str().len()) {
        return Err(AppError::invalid_param(
            "request_id must carry 128 bits of entropy",
        ));
    }
    let intent_digest = request_digest(&body)?;

    for _ in 0..MAX_CAS_ATTEMPTS {
        let (entry, mut binding_state) = load_state(state, principal_id.as_str()).await?;
        if let Some(existing) = binding_state.prepares.get(body.request_id.as_str()) {
            if existing.request_digest != intent_digest {
                return Err(AppError::conflict(
                    "principal service binding request_id was reused with different intent",
                ));
            }
            // Prepare is a frozen authoring-material read.  Even after commit,
            // exact replay must return the same challenge so a client that lost
            // the commit response can reconstruct the deterministic signature
            // and replay the exact commit request.
            return json_ok(existing.outcome.clone());
        }
        let current_digest = binding_state
            .current_binding
            .as_ref()
            .map(|binding| binding.binding_digest.clone());
        if current_digest != body.expected_current_binding_digest {
            return Err(AppError::new(
                ErrorCode::CasConflict,
                "principal service binding predecessor changed",
            )
            .with_status(StatusCode::CONFLICT));
        }
        let issued_at = canonical_now()?;
        let challenge_id = Base64UrlString::new(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>()))
            .map_err(|error| {
                AppError::internal(format!("generated challenge is invalid: {error}"))
            })?;
        let binding_draft = prepare_binding_core(
            state,
            &principal_id,
            &principal_full_id,
            challenge_id.clone(),
            current_digest,
            issued_at,
        )
        .await?;
        let outcome = PrincipalServiceBindingPrepareOutcome {
            request_id: body.request_id.clone(),
            challenge_id,
            binding_draft,
            issued_at,
            expires_at: issued_at + Duration::minutes(CHALLENGE_TTL_MINUTES),
        };
        outcome
            .validate_shape()
            .map_err(|error| AppError::internal(error.to_string()))?;
        binding_state.prepares.insert(
            body.request_id.as_str().to_owned(),
            PrincipalServiceBindingPrepareRecord {
                request_digest: intent_digest.clone(),
                outcome: outcome.clone(),
                commit_request_digest: None,
                commit_outcome: None,
            },
        );
        if compare_and_set_state(
            state,
            principal_id.as_str(),
            entry.as_ref(),
            &binding_state,
            issued_at,
        )
        .await?
        {
            return json_ok(outcome);
        }
    }
    Err(AppError::new(
        ErrorCode::CasConflict,
        "principal service binding changed concurrently",
    )
    .with_status(StatusCode::CONFLICT))
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
    let (principal_id, _) = session_principal_ids(state, &session.actor).await?;
    let body = body.into_inner();
    let commit_digest = request_digest(&body)?;

    for _ in 0..MAX_CAS_ATTEMPTS {
        let (entry, mut binding_state) = load_state(state, principal_id.as_str()).await?;
        let prepared = binding_state
            .prepares
            .get(body.request_id.as_str())
            .cloned()
            .ok_or_else(|| AppError::not_found("principal service binding prepare not found"))?;
        if let Some(outcome) = prepared.commit_outcome {
            if prepared.commit_request_digest.as_deref() == Some(commit_digest.as_str()) {
                return json_ok(outcome);
            }
            return Err(AppError::conflict(
                "consumed principal service binding challenge was reused",
            ));
        }
        let now = canonical_now()?;
        let draft = &prepared.outcome.binding_draft;
        if prepared.outcome.challenge_id != body.challenge_id
            || draft.authorization_challenge != body.challenge_id
            || draft.binding_digest != body.binding_digest
            || prepared.outcome.expires_at <= now
            || body.principal_authorization_proof.created_at != draft.accepted_at
        {
            return Err(AppError::new(
                ErrorCode::FailedPrecondition,
                "principal service binding challenge or frozen draft does not match",
            )
            .with_status(StatusCode::PRECONDITION_FAILED));
        }
        let current_digest = binding_state
            .current_binding
            .as_ref()
            .map(|binding| binding.binding_digest.clone());
        if current_digest != draft.predecessor_binding_digest {
            return Err(AppError::new(
                ErrorCode::CasConflict,
                "principal service binding predecessor changed before commit",
            )
            .with_status(StatusCode::CONFLICT));
        }
        let principal_input = draft
            .proof_signing_input_bytes(
                PrincipalServiceBindingProofPurpose::PrincipalAuthorization,
                &body.principal_authorization_proof.verification_method,
            )
            .map_err(|error| AppError::invalid_param(error.to_string()))?;
        verify_principal_authorization_at(
            state,
            draft,
            &principal_input,
            body.principal_authorization_proof.jws.as_str(),
            body.principal_authorization_proof
                .verification_method
                .as_str(),
        )
        .await
        .map_err(|error| {
            AppError::new(ErrorCode::InvalidSignature, error.to_string())
                .with_status(StatusCode::UNAUTHORIZED)
        })?;

        let service_method = draft.service_verification_method.id.clone();
        let service_input = draft
            .proof_signing_input_bytes(
                PrincipalServiceBindingProofPurpose::ServiceAcceptance,
                &service_method,
            )
            .map_err(|error| AppError::internal(error.to_string()))?;
        let service_signature =
            URL_SAFE_NO_PAD.encode(state.notary_signing_key().sign(&service_input).to_bytes());
        let binding = AcceptedAtServiceBinding {
            principal_id: draft.principal_id.clone(),
            service_id: draft.service_id.clone(),
            trust_domain: draft.trust_domain.clone(),
            service_kind: draft.service_kind,
            service_verification_method: draft.service_verification_method.clone(),
            endpoint_origins: draft.endpoint_origins.clone(),
            document_digest: draft.document_digest.clone(),
            authority_evidence: draft.authority_evidence.clone(),
            authorization_challenge: draft.authorization_challenge.clone(),
            history_head: draft.history_head.clone(),
            version_id: draft.version_id.clone(),
            not_before: draft.not_before,
            expires_at: draft.expires_at,
            accepted_at: draft.accepted_at,
            predecessor_binding_digest: draft.predecessor_binding_digest.clone(),
            binding_digest: draft.binding_digest.clone(),
            service_acceptance_proof: ProtocolSignature {
                verification_method: service_method,
                created_at: draft.accepted_at,
                jws: Base64UrlString::new(service_signature)
                    .map_err(|error| AppError::internal(error.to_string()))?,
            },
            principal_authorization_proof: body.principal_authorization_proof.clone(),
        };
        binding
            .validate_shape()
            .map_err(|error| AppError::internal(error.to_string()))?;
        let outcome = PrincipalServiceBindingCommitOutcome {
            binding: binding.clone(),
        };
        let record = binding_state
            .prepares
            .get_mut(body.request_id.as_str())
            .expect("prepare record was loaded above");
        record.commit_request_digest = Some(commit_digest.clone());
        record.commit_outcome = Some(outcome.clone());
        binding_state.current_binding = Some(binding);
        if compare_and_set_state(
            state,
            principal_id.as_str(),
            entry.as_ref(),
            &binding_state,
            now,
        )
        .await?
        {
            return json_ok(outcome);
        }
    }
    Err(AppError::new(
        ErrorCode::CasConflict,
        "principal service binding changed concurrently",
    )
    .with_status(StatusCode::CONFLICT))
}

async fn verify_principal_authorization_at(
    state: &AppState,
    draft: &AcceptedAtServiceBindingCore,
    payload: &[u8],
    signature_b64url: &str,
    verification_method: &str,
) -> Result<(), crate::jws_verify::PrincipalAuthorizedJwsError> {
    use crate::jws_verify::PrincipalAuthorizedJwsError;

    let method_full_id = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()))?;
    let method_core_id = project_full_id_to_core_id(&method_full_id)
        .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()))?;
    let frozen_principal_core_id = CoreId::from(draft.principal_id.clone());
    if method_core_id != frozen_principal_core_id || method_full_id.method() != "webvh" {
        return Err(PrincipalAuthorizedJwsError::Verification(
            "principal authorization method does not map to the frozen principal core id"
                .to_owned(),
        ));
    }

    // Re-evaluate the complete method-native history at the frozen timestamp;
    // a current DID document or current device projection cannot prove that a
    // method was authorized when this draft was accepted.
    let authority = binding_authority_evidence(state, &method_full_id, draft.accepted_at)
        .await
        .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()))?;
    if authority.document_digest != draft.document_digest
        || authority.receipt != draft.authority_evidence
        || Some(authority.history_head.as_str()) != draft.history_head.as_deref()
        || Some(authority.version_id.as_str()) != draft.version_id.as_deref()
    {
        return Err(PrincipalAuthorizedJwsError::Verification(
            "principal authority at accepted_at does not match the frozen draft".to_owned(),
        ));
    }

    let device_prefix = format!("{method_full_id}#");
    if let Some(device_id) = verification_method.strip_prefix(&device_prefix)
        && DeviceId::new(device_id.to_owned()).is_ok()
    {
        return verify_historical_device_signature(
            state,
            &frozen_principal_core_id,
            &method_full_id,
            device_id,
            draft.accepted_at,
            payload,
            signature_b64url,
        )
        .await
        .map_err(PrincipalAuthorizedJwsError::Verification);
    }

    let fragment = verification_method.split_once('#').map(|(_, value)| value);
    let key_material = authority
        .document
        .verification_methods
        .get(verification_method)
        .or_else(|| fragment.and_then(|value| authority.document.verification_methods.get(value)))
        .or_else(|| {
            fragment.and_then(|value| {
                authority
                    .document
                    .verification_methods
                    .get(&format!("#{value}"))
            })
        })
        .ok_or_else(|| {
            PrincipalAuthorizedJwsError::Verification(
                "verification method was absent from the accepted-at DID document".to_owned(),
            )
        })?;
    let key =
        crate::routing::identity::device_signing::decode_ed25519_key(key_material, "multibase")
            .map_err(PrincipalAuthorizedJwsError::Verification)?;
    crate::jws_verify::verify_ed25519_signature_with_public_key(
        payload,
        signature_b64url,
        key.as_bytes(),
    )
    .map_err(PrincipalAuthorizedJwsError::Verification)
}

async fn verify_historical_device_signature(
    state: &AppState,
    principal_core_id: &CoreId,
    principal_full_id: &FullId,
    device_id: &str,
    accepted_at: DateTime<Utc>,
    payload: &[u8],
    signature_b64url: &str,
) -> Result<(), String> {
    let mut events = BTreeMap::new();
    for actor_id in [principal_core_id.as_str(), principal_full_id.as_str()] {
        for event in state
            .event_queries()
            .accepted_events_for_actor(actor_id)
            .await
            .map_err(|error| format!("accepted device history lookup failed: {error}"))?
        {
            events.entry(event.event_id.clone()).or_insert(event);
        }
    }
    let mut events = events.into_values().collect::<Vec<_>>();
    events.sort_by_key(|event| (event.received_at, event.actor_seq));

    let latest_reanchor = events
        .iter()
        .filter(|event| {
            event.kind == arkret_wire::EventKind::DeviceReanchor.as_str()
                && event.received_at <= accepted_at
        })
        .map(|event| (event.received_at, event.actor_seq))
        .max();
    let authorization = events
        .iter()
        .filter(|event| {
            if event.kind != arkret_wire::EventKind::DeviceAuthorize.as_str()
                || event.received_at > accepted_at
                || event
                    .envelope
                    .pointer("/payload/device_id")
                    .and_then(Value::as_str)
                    != Some(device_id)
                || !event
                    .envelope
                    .pointer("/payload/principal_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| {
                        value == principal_core_id.as_str() || value == principal_full_id.as_str()
                    })
            {
                return false;
            }
            let not_before = event
                .envelope
                .pointer("/payload/not_before")
                .and_then(Value::as_str)
                .and_then(parse_timestamp);
            let expires_at = event
                .envelope
                .pointer("/payload/expires_at")
                .and_then(Value::as_str)
                .and_then(parse_timestamp);
            not_before.is_some_and(|value| value <= accepted_at)
                && expires_at.is_none_or(|value| accepted_at <= value)
                && latest_reanchor
                    .is_none_or(|generation| (event.received_at, event.actor_seq) >= generation)
        })
        .max_by_key(|event| (event.received_at, event.actor_seq))
        .ok_or_else(|| "device verification method was not authorized at accepted_at".to_owned())?;

    if events.iter().any(|event| {
        event.kind == arkret_wire::EventKind::DeviceRevoke.as_str()
            && event.received_at <= accepted_at
            && event
                .envelope
                .pointer("/payload/device_id")
                .and_then(Value::as_str)
                == Some(device_id)
            && event
                .envelope
                .pointer("/payload/revoked_at")
                .and_then(Value::as_str)
                .and_then(parse_timestamp)
                .is_some_and(|revoked_at| revoked_at <= accepted_at)
            && (event.received_at, event.actor_seq)
                >= (authorization.received_at, authorization.actor_seq)
    }) {
        return Err("device verification method was revoked at accepted_at".to_owned());
    }
    let key_material = authorization
        .envelope
        .pointer("/payload/device_public_key")
        .and_then(Value::as_str)
        .ok_or_else(|| "accepted device authorization has no signing key".to_owned())?;
    let key =
        crate::routing::identity::device_signing::decode_ed25519_key(key_material, "multibase")?;
    crate::jws_verify::verify_ed25519_signature_with_public_key(
        payload,
        signature_b64url,
        key.as_bytes(),
    )
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

pub(crate) async fn current_binding(
    state: &AppState,
    principal_id: &str,
) -> Result<Option<AcceptedAtServiceBinding>, AppError> {
    let core_id = if let Ok(core_id) = CoreId::new(principal_id.to_owned()) {
        core_id
    } else {
        let full_id = FullId::new(principal_id.to_owned()).map_err(|error| {
            AppError::invalid_param(format!("principal identifier is invalid: {error}"))
        })?;
        project_full_id_to_core_id(&full_id).map_err(|error| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                format!("principal has no active core-id adapter: {error}"),
            )
            .with_status(StatusCode::PRECONDITION_FAILED)
        })?
    };
    let (_, binding_state) = load_state(state, core_id.as_str()).await?;
    Ok(binding_state.current_binding)
}
