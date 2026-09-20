//! Moderation user-facing endpoints.
//!
//! - `POST /_arkret/self/moderation/report` (`ak.self.moderation.command.report.v1`) — submit the
//!   caller-authored signed report Event through ordinary Event admission.

use std::collections::BTreeSet;

use arkret_identifiers::{EventId, RealmId};
use arkret_models_collaboration::events_payloads::moderation::{
    FrankingProof, FrankingSealObservationOutcome, FrankingSealObservationRequest,
};
use arkret_wire::{ActorId, EventKind, ScopeRef};
use ed25519_dalek::Signer as _;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
#[cfg(test)]
use soland_http::error::ErrorCode;
use soland_http::result::{JsonResult, json_ok};
use soland_services::runtime_guards::MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES;

use super::{now, realm_has_member, sha256_hex};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{ModerationReportOutcome, ModerationReportRequestBody};

pub(super) fn protocol_router() -> Router {
    Router::new().push(Router::with_path("moderation/report").post(moderation_report))
}

fn authored_event_wire_value(
    event: &arkret_wire::AuthoredEvent,
) -> Result<Value, serde_json::Error> {
    serde_json::to_value(event.event())
}

fn author_franking_proof_event(
    proof: FrankingProof,
    service_actor_id: arkret_wire::DidCoreId,
    prev_refs: Vec<EventId>,
    basis: arkret_wire::SealId,
    actor_seq: u64,
    hlc: arkret_identifiers::Hlc,
    created_at: chrono::DateTime<chrono::Utc>,
    digest_suite: arkret_canonical::DigestSuite,
) -> arkret_event_draft::Result<arkret_wire::AuthoredEvent> {
    let auth_context = arkret_wire::AuthContext {
        authority_refs: vec![basis.clone()],
    };
    arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::ModerationFrankingProof>::new(
        ScopeRef::Realm {
            realm_id: proof.realm_id.clone(),
        },
        arkret_wire::ActorId::service(service_actor_id),
        proof,
    )
    .and_then(|draft| {
        draft
            .with_prev_refs(prev_refs)
            .with_auth_context(auth_context)
            .with_data_basis(basis)
            .author_with_digest_suite(actor_seq, hlc, created_at, digest_suite)
    })
}

/// Persist the receiving service's canonical delivery receipt for one accepted
/// encrypted Event. The canonical Event store is the only durable identity and
/// restart source; the old private audit digest is deliberately not written.
pub(crate) async fn prepare_franking_proof_event(
    state: &AppState,
    target: &soland_services::events::AcceptedEvent,
) -> Result<soland_services::events::CommitAcceptedEventCommand, AppError> {
    let realm_id = target
        .realm_id
        .as_deref()
        .ok_or_else(|| AppError::internal("franking target Event has no Realm"))?;
    let target_event_id = target.event_id.as_str();

    let service_actor = state.service_id().as_str();
    let records = state
        .event_queries()
        .canonical_events_for_realm_actor(realm_id, service_actor)
        .await
        .map_err(|error| {
            AppError::internal(format!("franking Event frontier lookup failed: {error}"))
        })?;
    let max_actor_seq = records.iter().map(|record| record.actor_seq).max();
    let actor_seq = max_actor_seq
        .map(|value| {
            value.checked_add(1).ok_or_else(|| {
                crate::app_error!(
                    FrontierSequenceExhausted,
                    "franking Event actor sequence is exhausted",
                )
            })
        })
        .transpose()?
        .unwrap_or(0);
    let mut prev_refs = Vec::new();
    if let Some(max_actor_seq) = max_actor_seq {
        prev_refs = records
            .iter()
            .filter(|record| record.actor_seq == max_actor_seq)
            .map(|record| {
                EventId::new(record.event_id.clone()).map_err(|error| {
                    AppError::internal(format!("franking predecessor invalid: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        prev_refs.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        prev_refs.dedup();
    }

    let service_did = state.service_resolution_commitment().did.clone();
    let service_actor_id = arkret_wire::project_did_to_core_id(&service_did)
        .map_err(|error| AppError::internal(format!("service DID cannot be projected: {error}")))?;
    let verification_method = arkret_wire::DidUrl::new(format!("{service_did}#notary-key"))
        .map_err(|error| AppError::internal(format!("service notary method invalid: {error}")))?;
    let signing_key = state.notary_signing_key();
    let proof = FrankingProof::signed(
        RealmId::new(realm_id.to_owned())
            .map_err(|error| AppError::internal(format!("franking Realm id invalid: {error}")))?,
        EventId::new(target_event_id.to_owned())
            .map_err(|error| AppError::internal(format!("franking target id invalid: {error}")))?,
        service_actor_id.clone(),
        verification_method.clone(),
        target.received_at,
        uuid::Uuid::now_v7().simple().to_string(),
        |bytes| {
            Ok(arkret_canonical::base64url_encode(
                signing_key.sign(bytes).to_bytes(),
            ))
        },
    )
    .map_err(|error| AppError::internal(format!("franking proof signing failed: {error}")))?;

    let created_at = now();
    let hlc = arkret_identifiers::Hlc::new(state.hlc().now())
        .map_err(|error| AppError::internal(format!("franking HLC invalid: {error}")))?;
    let seal = crate::notary::ensure_realm_seal_head(
        state,
        &RealmId::new(realm_id.to_owned())
            .map_err(|error| AppError::internal(format!("franking Realm id invalid: {error}")))?,
    )
    .await
    .map_err(|error| AppError::internal(format!("franking Realm Seal lookup failed: {error}")))?
    .ok_or_else(|| {
        crate::app_error!(
            FrontierUnavailable,
            "franking target Realm has no accepted Seal",
        )
    })?;
    let digest_suite = state.projections().realm_digest_suite(realm_id);
    let mut event = author_franking_proof_event(
        proof,
        service_actor_id,
        prev_refs,
        seal.id,
        actor_seq,
        hlc,
        created_at,
        digest_suite,
    )
    .map_err(|error| AppError::internal(format!("franking Event build failed: {error}")))?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        signing_key.as_ref().clone(),
        service_did,
        verification_method.clone(),
    );
    let signer_evidence_ref =
        crate::routing::identity::agents::evidence::retain_current_service_signer_evidence_ref(
            state, created_at,
        )
        .await?;
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new(signer_evidence_ref).with_created_at(created_at),
    )
    .map_err(|error| AppError::internal(format!("franking Event signing failed: {error}")))?;
    let session = soland_services::identity::SessionIdentityState {
        token_hash: "franking-proof-service".to_owned(),
        account_pk: None,
        actor: state.service_id().clone(),
        device_id: String::new(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: created_at + chrono::Duration::minutes(5),
        created_at,
        revoked_at: None,
    };
    let envelope = authored_event_wire_value(&event)
        .map_err(|error| AppError::internal(format!("franking Event serialize failed: {error}")))?;
    crate::routing::events::event_log::prepare_service_franking_proof_event_value(
        state,
        &session,
        envelope,
        realm_id,
        target_event_id,
    )
    .await
    .map_err(|error| {
        crate::app_error!(
            ParamInvalid,
            format!("franking Event admission failed: {}", error.message()),
        )
        .with_rejection_code(error.code())
    })
}

#[derive(Clone, Debug)]
pub(super) struct ModerationReportSafety {
    pub effective_scope: Value,
    pub evidence_package: Option<Value>,
    pub franking_proof: Option<Value>,
}

pub(super) fn moderation_request_source_ip_hash(req: &Request) -> String {
    // Shared with the rate limiter. The local copy this replaced differed on
    // both halves: it required the trust flag to be exactly `"1"` (so `=true`
    // silently disabled it here while the limiter honoured it), and it took
    // the *leftmost* `X-Forwarded-For` token without checking it parses as an
    // IP — a caller-supplied value, which made the recorded report provenance
    // forgeable whenever the flag was on.
    let source = crate::ratelimit::trusted_forwarded_client(req)
        .unwrap_or_else(|| req.remote_addr().to_string());
    sha256_hex(source.as_bytes())
}

pub(super) fn moderation_request_source_service(req: &Request) -> Option<String> {
    req.headers()
        .get("source-service-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) async fn validate_moderation_report_safety(
    state: &AppState,
    realm_id: &str,
    reporter_id: &str,
    reporter_actor: Option<&ActorId>,
    target_ref: &str,
    effective_scope: Option<&ScopeRef>,
    evidence_package: &Value,
    franking_proof: &Value,
    source_service: Option<&str>,
    source_ip_hash: &str,
) -> Result<ModerationReportSafety, AppError> {
    let rate_reporter = reporter_actor
        .map(ToString::to_string)
        .unwrap_or_else(|| reporter_id.to_owned());
    let rate = state.record_moderation_report_attempt(
        &rate_reporter,
        source_service,
        realm_id,
        source_ip_hash,
        target_ref,
    );
    if rate.rate_limited {
        return Err(
            crate::app_error!(RateLimited, "moderation report rate limit exceeded",)
                .with_reason_detail(format!(
                    "bucket={} count={} limit={} retry_after_ms={}",
                    rate.bucket.as_deref().unwrap_or("unknown"),
                    rate.count,
                    rate.limit,
                    rate.retry_after_ms
                )),
        );
    }

    validate_moderation_report_content_safety(
        state,
        realm_id,
        reporter_actor,
        target_ref,
        effective_scope,
        evidence_package,
        franking_proof,
    )
    .await
}

async fn validate_signed_moderation_report_safety(
    state: &AppState,
    realm_id: &str,
    reporter_actor: &ActorId,
    target_ref: &str,
    effective_scope: Option<&ScopeRef>,
    evidence_package: &Value,
    franking_proof: &Value,
) -> Result<ModerationReportSafety, AppError> {
    validate_moderation_report_content_safety(
        state,
        realm_id,
        Some(reporter_actor),
        target_ref,
        effective_scope,
        evidence_package,
        franking_proof,
    )
    .await
}

async fn validate_moderation_report_content_safety(
    state: &AppState,
    realm_id: &str,
    reporter_actor: Option<&ActorId>,
    target_ref: &str,
    effective_scope: Option<&ScopeRef>,
    evidence_package: &Value,
    franking_proof: &Value,
) -> Result<ModerationReportSafety, AppError> {
    let effective_scope = moderation_effective_scope_value(realm_id, effective_scope)?;
    let target_scope =
        moderation_target_effective_scope_value(state, realm_id, reporter_actor, target_ref)?;
    if target_scope != effective_scope {
        return Err(moderation_target_not_found());
    }
    let evidence_package =
        validate_moderation_evidence_package(evidence_package, &effective_scope)?;
    let franking_proof =
        validate_moderation_franking_proof(state, realm_id, franking_proof).await?;
    Ok(ModerationReportSafety {
        effective_scope,
        evidence_package,
        franking_proof,
    })
}

fn moderation_effective_scope_value(
    realm_id: &str,
    effective_scope: Option<&ScopeRef>,
) -> Result<Value, AppError> {
    match effective_scope {
        None => Ok(json!({"kind": "realm", "realm_id": realm_id})),
        Some(ScopeRef::Realm {
            realm_id: scope_realm,
        }) => {
            if scope_realm.as_str() != realm_id {
                return Err(AppError::param_invalid(
                    "effective_scope.realm_id must match report realm_id",
                ));
            }
            Ok(json!({"kind": "realm", "realm_id": scope_realm.as_str()}))
        }
        Some(ScopeRef::Circle {
            realm_id: scope_realm,
            circle_id,
        }) => {
            if scope_realm.as_str() != realm_id {
                return Err(AppError::param_invalid(
                    "effective_scope.realm_id must match report realm_id",
                ));
            }
            Ok(json!({
                "kind": "circle",
                "realm_id": scope_realm.as_str(),
                "circle_id": circle_id.as_str(),
            }))
        }
        // `ScopeRef` is #[non_exhaustive]; fail closed on any scope
        // kind this build does not understand rather than guessing a shape.
        Some(_) => Err(AppError::param_invalid(
            "effective_scope kind is not supported",
        )),
    }
}

fn moderation_target_not_found() -> AppError {
    AppError::not_found("moderation target not found")
}

fn moderation_target_effective_scope_value(
    state: &AppState,
    realm_id: &str,
    reporter_actor: Option<&ActorId>,
    target_ref: &str,
) -> Result<Value, AppError> {
    if target_ref == realm_id {
        return Ok(json!({"kind": "realm", "realm_id": realm_id}));
    }
    let projection = state.projections().snapshot();
    let scope_circle_id = if let Some(message) = moderation_target_message(&projection, target_ref)
        .filter(|message| message.realm_id == realm_id)
    {
        message
            .content
            .get("scope_circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| projection.strand_scope_circle_id(&message.thread_id))
    } else if let Some(strand) = projection
        .strands
        .get(target_ref)
        .filter(|strand| strand.realm_id == realm_id)
    {
        strand.scope_circle_id.clone()
    } else if let Some(morph) = projection
        .morphs
        .get(target_ref)
        .filter(|morph| morph.realm_id == realm_id)
    {
        morph.scope_circle_id.clone()
    } else if let Some(space) = projection
        .space_containers
        .get(target_ref)
        .filter(|space| space.realm_id == realm_id)
    {
        space.scope_circle_id.clone()
    } else if let Some(relation) = projection
        .relations
        .get(target_ref)
        .filter(|relation| relation.realm_id == realm_id)
    {
        relation.scope_circle_id.clone()
    } else {
        return Err(moderation_target_not_found());
    };
    if let Some(circle_id) = scope_circle_id {
        let reporter_actor = reporter_actor.ok_or_else(moderation_target_not_found)?;
        if !projection.circle_scope_visible_to_actor(&circle_id, &reporter_actor.to_string()) {
            return Err(moderation_target_not_found());
        }
        return Ok(json!({
            "kind": "circle",
            "realm_id": realm_id,
            "circle_id": circle_id,
        }));
    }
    Ok(json!({"kind": "realm", "realm_id": realm_id}))
}

fn moderation_target_message<'a>(
    projection: &'a soland_domain::reducer::ProjectionState,
    target_ref: &str,
) -> Option<&'a soland_domain::reducer::MessageState> {
    projection.messages.get(target_ref).or_else(|| {
        target_ref
            .strip_prefix("ak:message:")
            .and_then(|suffix| projection.messages.get(&format!("ak:event:{suffix}")))
    })
}

fn validate_moderation_evidence_package(
    evidence_package: &Value,
    effective_scope: &Value,
) -> Result<Option<Value>, AppError> {
    if evidence_package.is_null() {
        return Ok(None);
    }
    let object = evidence_package
        .as_object()
        .ok_or_else(|| AppError::param_invalid("evidence_package must be an object"))?;
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(evidence_package).map_err(|error| {
            AppError::json_invalid(format!(
                "evidence_package is not canonical-json encodable: {error}"
            ))
        })?;
    if canonical_bytes.len() > MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES {
        return Err(crate::app_error!(
            PayloadTooLarge,
            "evidence_package exceeds max_total_blob_bytes",
        )
        .with_reason_detail(format!(
            "max_total_blob_bytes={}",
            MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES
        )));
    }
    let Some(encryption) = object
        .get("encryption")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::param_invalid(
            "evidence_package.encryption is required",
        ));
    };
    let encryption = encryption.to_ascii_lowercase();
    if matches!(encryption.as_str(), "none" | "plaintext" | "cleartext") {
        return Err(AppError::param_invalid(
            "evidence_package must be encrypted",
        ));
    }
    if !object
        .get("ciphertext_digest")
        .and_then(Value::as_str)
        .is_some_and(is_valid_report_hash)
    {
        return Err(AppError::param_invalid(
            "evidence_package.ciphertext_digest must be a hash digest",
        ));
    }
    if object
        .get("plaintext_digest")
        .and_then(Value::as_str)
        .is_some_and(|digest| !is_valid_report_hash(digest))
    {
        return Err(AppError::param_invalid(
            "evidence_package.plaintext_digest must be a hash digest",
        ));
    }
    if object
        .get("recipients")
        .and_then(Value::as_array)
        .is_none_or(|recipients| recipients.is_empty())
    {
        return Err(AppError::param_invalid(
            "evidence_package.recipients must name at least one moderator audience",
        ));
    }
    let scope_matches = object.get("effective_scope") == Some(effective_scope)
        || object
            .get("audience")
            .and_then(|audience| audience.get("effective_scope"))
            == Some(effective_scope);
    if !scope_matches {
        return Err(AppError::param_invalid(
            "evidence_package audience must bind the report effective_scope",
        ));
    }
    if let Some(key) = contains_forbidden_key(evidence_package, EVIDENCE_PACKAGE_FORBIDDEN_KEYS) {
        return Err(AppError::param_invalid(format!(
            "evidence_package contains forbidden key `{key}`"
        )));
    }
    Ok(Some(evidence_package.clone()))
}

async fn validate_moderation_franking_proof(
    state: &AppState,
    realm_id: &str,
    franking_proof: &Value,
) -> Result<Option<Value>, AppError> {
    if franking_proof.is_null() {
        return Ok(None);
    }
    let object = franking_proof
        .as_object()
        .ok_or_else(|| AppError::param_invalid("franking_proof must be an object"))?;
    if object.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return Err(AppError::param_invalid(
            "franking_proof.realm_id must match report realm_id",
        ));
    }
    if arkret_identifiers::EventId::new(required_string_field(
        object,
        "event_id",
        "franking_proof",
    )?)
    .is_err()
    {
        return Err(AppError::param_invalid(
            "franking_proof.event_id must be an event id",
        ));
    }
    let received_by = required_string_field(object, "received_by", "franking_proof")?;
    arkret_wire::DidCoreId::new(received_by.to_owned())
        .map_err(|_| AppError::param_invalid("franking_proof.received_by must be a DID Core ID"))?;
    let replay_nonce = required_string_field(object, "replay_nonce", "franking_proof")?;
    if !is_valid_replay_nonce(replay_nonce) {
        return Err(AppError::param_invalid(
            "franking_proof.replay_nonce must be base64url 16..256 chars",
        ));
    }
    if required_string_field(object, "signature", "franking_proof")?.is_empty() {
        return Err(AppError::param_invalid(
            "franking_proof.signature must be non-empty",
        ));
    }
    let received_at = required_string_field(object, "received_at", "franking_proof")?;
    if arkret_canonical::validate_timestamp_canonical(received_at).is_err() {
        return Err(AppError::param_invalid(
            "franking_proof.received_at must be a canonical Arkret timestamp",
        ));
    }
    if let Some(key) = contains_forbidden_key(franking_proof, FRANKING_PROOF_FORBIDDEN_KEYS) {
        return Err(AppError::param_invalid(format!(
            "franking_proof contains forbidden key `{key}`"
        )));
    }
    let typed_proof: FrankingProof =
        serde_json::from_value(franking_proof.clone()).map_err(|error| {
            franking_proof_invalid(format!("franking_proof typed validation failed: {error}"))
        })?;
    let verification_key = crate::jws_verify::resolve_ed25519_pubkey_at(
        state,
        typed_proof.verification_method.as_str(),
        typed_proof.received_at,
    )
    .await
    .map_err(|error| {
        franking_proof_invalid(format!(
            "franking_proof verification method has no authenticated historical state: {error}"
        ))
    })?;
    typed_proof
        .verify_signature(|_, bytes, signature| {
            crate::jws_verify::verify_ed25519_signature_with_public_key(
                bytes,
                signature,
                verification_key.as_bytes(),
            )
            .map_err(arkret_wire::WireError::Protocol)
        })
        .map_err(|error| franking_proof_invalid(error.to_string()))?;
    validate_franking_event_time_anchor(state, realm_id, &typed_proof).await?;
    Ok(Some(franking_proof.clone()))
}

async fn validate_franking_event_time_anchor(
    state: &AppState,
    realm_id: &str,
    proof: &FrankingProof,
) -> Result<(), AppError> {
    let target = state
        .event_queries()
        .canonical_event(proof.event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "franking_proof event anchor lookup failed: {error}"
            ))
        })?
        .ok_or_else(|| {
            franking_proof_invalid(
                "franking_proof.event_id does not reference an accepted local event anchor",
            )
        })?;
    let target_realm_id = target
        .realm_id
        .as_deref()
        .ok_or_else(|| franking_proof_invalid("franking_proof event anchor is missing realm_id"))?;
    if target_realm_id != realm_id {
        return Err(franking_proof_invalid(
            "franking_proof event anchor realm_id does not match report realm_id",
        ));
    }
    let proof_payload = serde_json::to_value(proof).map_err(|error| {
        franking_proof_invalid(format!("franking_proof serialization failed: {error}"))
    })?;
    let mut matching = state
        .event_queries()
        .franking_proofs_for_target(realm_id, &proof.received_by, proof.event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("franking proof Event lookup failed: {error}"))
        })?
        .into_iter()
        .filter(|candidate| candidate.envelope.get("payload") == Some(&proof_payload));
    let proof_event = matching.next().ok_or_else(|| {
        franking_proof_invalid("franking_proof has no byte-identical accepted durable proof Event")
    })?;
    if matching.next().is_some() {
        return Err(franking_proof_invalid(
            "franking_proof has multiple byte-identical durable proof Events",
        ));
    }
    materialize_franking_seal_observation(state, &proof_event, &target)
        .await
        .map(|_| ())
        .map_err(|error| franking_proof_invalid(error.message))
}

// Wire code for an invalid franking proof. `proof_invalid` is a registered
// `reason_code`, so it is sourced from the SDK as `arkret_wire::ReasonCode::PROOF_INVALID`
// rather than a local literal.
fn franking_proof_invalid(message: impl Into<String>) -> AppError {
    AppError::param_invalid(message).with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
}

fn required_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<&'a str, AppError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid(format!("{context}.{field} is required")))
}

fn is_valid_report_hash(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .or_else(|| value.strip_prefix("blake3:"))
        .is_some_and(|hex| {
            hex.len() == 64 && hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        })
}

fn is_valid_replay_nonce(value: &str) -> bool {
    (16..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn contains_forbidden_key(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(object) => object.iter().find_map(|(key, nested)| {
            if keys.contains(&key.as_str()) {
                Some(key.clone())
            } else {
                contains_forbidden_key(nested, keys)
            }
        }),
        Value::Array(values) => values
            .iter()
            .find_map(|nested| contains_forbidden_key(nested, keys)),
        _ => None,
    }
}

const EVIDENCE_PACKAGE_FORBIDDEN_KEYS: &[&str] = &[
    "plaintext",
    "plaintext_body",
    "body_plaintext",
    "message_plaintext",
    "history_key",
    "history_secret",
    "mls_epoch_secret",
    "epoch_secret",
    "epoch_key",
    "exporter_secret",
];

const FRANKING_PROOF_FORBIDDEN_KEYS: &[&str] = &[
    "plaintext",
    "plaintext_body",
    "attachment_filename",
    "reply_excerpt",
    "mentions",
    "private_handle",
    "plaintext_digest",
    "plaintext_hash",
    "mls_group_id",
    "epoch",
];

#[allow(dead_code)]
async fn moderation_franking_seal_observation(
    aa: AuthArgs,
    body: JsonBody<FrankingSealObservationRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<FrankingSealObservationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    if crate::routing::events::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_MODERATION_READ_FRANKING_SEAL_OBSERVATION_V1,
    )
    .is_err()
    {
        return Err(franking_observation_not_found());
    }
    let request = body.into_inner();
    let proof_event = state
        .event_queries()
        .canonical_event(request.proof_event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("franking proof Event lookup failed: {error}"))
        })?
        .ok_or_else(franking_observation_not_found)?;
    let target_event = state
        .event_queries()
        .canonical_event(request.target_event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("franking target Event lookup failed: {error}"))
        })?
        .ok_or_else(franking_observation_not_found)?;
    let target_envelope =
        parse_accepted_event(&target_event).map_err(|_| franking_observation_not_found())?;
    if proof_event.realm_id.as_deref() != Some(request.realm_id.as_str())
        || target_event.realm_id.as_deref() != Some(request.realm_id.as_str())
        || proof_event.kind != EventKind::ModerationFrankingProof.as_str()
        || target_envelope.kind != EventKind::MessageCreate
        || !target_envelope
            .payload
            .get("encrypted_content")
            .is_some_and(Value::is_object)
        || !actor_has_exact_scope_moderation_capability(
            state,
            &target_envelope.scope_ref,
            &session.actor,
        )
        .await
    {
        return Err(franking_observation_not_found());
    }
    let outcome = materialize_franking_seal_observation(state, &proof_event, &target_event)
        .await
        .map_err(|error| {
            if error.http_status() == StatusCode::NOT_FOUND {
                franking_observation_not_found()
            } else {
                error
            }
        })?;
    outcome
        .validate_binding(&request)
        .map_err(|_| franking_observation_not_found())?;
    json_ok(outcome)
}

fn franking_observation_not_found() -> AppError {
    AppError::not_found("franking Seal observation not found")
}

fn parse_accepted_event(
    record: &soland_services::events::AcceptedEvent,
) -> Result<arkret_wire::Event, AppError> {
    serde_json::from_value(record.envelope.clone())
        .map_err(|error| AppError::internal(format!("accepted Event is malformed: {error}")))
}

async fn actor_has_exact_scope_moderation_capability(
    state: &AppState,
    scope: &ScopeRef,
    actor: &str,
) -> bool {
    if state.is_admin_principal(actor) {
        return true;
    }
    let Ok(principal_id) = arkret_wire::DidCoreId::new(actor.to_owned()) else {
        return false;
    };
    let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal_id,
        state.service_core_id().clone(),
    ));
    let (realm_id, resource) = match scope {
        ScopeRef::Realm { realm_id } => (realm_id.as_str(), realm_id.as_str()),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => (realm_id.as_str(), circle_id.as_str()),
        _ => return false,
    };
    let projection = state.projections().snapshot();
    let owner = projection
        .realm_authority_root(realm_id)
        .map(|root| root.controller_actor_id.to_string());
    let members = RealmId::new(realm_id.to_owned())
        .ok()
        .and_then(|id| state.realm_directory().snapshot().get(&id).cloned())
        .map(|realm| {
            realm
                .members
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    [
        arkret_wire::CapabilityActionId::MODERATION_DECISION,
        arkret_wire::CapabilityActionId::REALM_ADMIN,
    ]
    .into_iter()
    .any(|action| {
        state
            .authorization()
            .check(soland_services::authorization::AuthorizationCheck {
                actor: &actor_id,
                action,
                resource,
                realm_id,
                owner: owner.as_deref(),
                members: &members,
                resource_facets: &[],
            })
            .allowed
    })
}

async fn materialize_franking_seal_observation(
    state: &AppState,
    proof_record: &soland_services::events::AcceptedEvent,
    target_record: &soland_services::events::AcceptedEvent,
) -> Result<FrankingSealObservationOutcome, AppError> {
    let proof_event = parse_accepted_event(proof_record)?;
    let target_event = parse_accepted_event(target_record)?;
    let proof: FrankingProof = serde_json::from_value(
        serde_json::to_value(&proof_event.payload).map_err(|_| franking_observation_not_found())?,
    )
    .map_err(|_| franking_observation_not_found())?;
    if proof_record.kind != EventKind::ModerationFrankingProof.as_str()
        || proof_record.realm_id != target_record.realm_id
        || proof.realm_id.as_str() != proof_record.realm_id.as_deref().unwrap_or_default()
        || proof.event_id.as_str() != target_record.event_id
        || proof.received_by.as_str() != proof_record.actor_id
    {
        return Err(franking_observation_not_found());
    }
    let realm_id = proof.realm_id.clone();
    let leaves = state
        .projections()
        .realm_seal_basis_leaves(&realm_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("franking Seal frontier lookup failed: {error}"))
        })?;
    let closure = state
        .projections()
        .seal_basis_closure(&leaves)
        .await
        .map_err(|error| {
            AppError::internal(format!("franking Seal ancestry lookup failed: {error}"))
        })?;
    let mut seals = Vec::with_capacity(closure.len());
    for seal_id in closure {
        seals.push(
            state
                .projections()
                .seal_by_id(&seal_id)
                .await
                .map_err(|error| {
                    AppError::internal(format!("franking Seal lookup failed: {error}"))
                })?
                .ok_or_else(|| AppError::internal(format!("accepted Seal {seal_id} is missing")))?,
        );
    }
    seals.sort_by(|left, right| {
        (left.sealed_at, left.notary_seq, left.id.as_str()).cmp(&(
            right.sealed_at,
            right.notary_seq,
            right.id.as_str(),
        ))
    });
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| {
            AppError::internal(format!("franking Event closure lookup failed: {error}"))
        })?;
    let mut events = std::collections::BTreeMap::new();
    for record in records {
        if record.realm_id.as_deref() != Some(realm_id.as_str()) {
            continue;
        }
        let event = parse_accepted_event(&record)?;
        events.insert(event.event_id.clone(), event);
    }
    let mut observation = None;
    for seal in seals {
        for anchor in &seal.existence_anchors {
            let Some(ancestry_events) =
                existence_anchor_closure(anchor, &proof_event.event_id, &events)?
            else {
                continue;
            };
            let anchor = anchor.clone();
            observation = Some((seal, anchor, ancestry_events));
            break;
        }
        if observation.is_some() {
            break;
        }
    }
    let (covering_seal, existence_anchor, ancestry_events) =
        observation.ok_or_else(franking_observation_not_found)?;
    let authenticated =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await?;
    let service_signer_evidence =
        arkret_identity::service_signer_evidence_for_method_from_authenticated_resolution(
            authenticated,
            &proof.received_by,
            proof.verification_method.clone(),
            proof.received_at,
        )
        .map_err(|error| {
            AppError::internal(format!(
                "build historical franking signer evidence: {error}"
            ))
        })?;
    Ok(FrankingSealObservationOutcome {
        proof_event,
        target_event,
        covering_seal,
        service_signer_evidence,
        existence_anchor,
        ancestry_events,
    })
}

fn existence_anchor_closure(
    anchor: &arkret_wire::ExistenceAnchor,
    proof_event_id: &EventId,
    events: &std::collections::BTreeMap<EventId, arkret_wire::Event>,
) -> Result<Option<Vec<arkret_wire::Event>>, AppError> {
    anchor.validate_structural().map_err(|error| {
        AppError::internal(format!("invalid retained existence anchor: {error}"))
    })?;
    let mut pending = anchor.frontier.clone();
    let mut visited = BTreeSet::new();
    let mut contains_proof = false;
    while let Some(event_id) = pending.pop() {
        if !visited.insert(event_id.clone()) {
            continue;
        }
        if visited.len() > 4096 {
            return Ok(None);
        }
        let Some(event) = events.get(&event_id) else {
            return Ok(None);
        };
        contains_proof |= &event_id == proof_event_id;
        pending.extend(event.prev_refs.iter().cloned());
    }
    if !contains_proof {
        return Ok(None);
    }
    let mut ancestry_events = visited
        .into_iter()
        .filter(|event_id| event_id != proof_event_id)
        .filter_map(|event_id| events.get(&event_id).cloned())
        .collect::<Vec<_>>();
    ancestry_events.sort_by(|left, right| left.event_id.cmp(&right.event_id));
    Ok(Some(ancestry_events))
}

#[endpoint(
    operation_id = "ak.self.moderation.command.report",
    summary = "File a content moderation report",
    tags("moderation")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.moderation.command.report.v1"))]
async fn moderation_report(
    aa: AuthArgs,
    body: JsonBody<ModerationReportRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ModerationReportOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let digest_suite = state
        .projections()
        .realm_digest_suite(body.report_event.event.realm_id.as_str());
    body.validate(digest_suite)
        .map_err(|error| AppError::param_invalid(format!("report_event: {error}")))?;
    let event = &body.report_event.event;
    let payload: arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload =
        serde_json::from_value(Value::Object(event.payload.clone().into_iter().collect()))
            .map_err(|error| AppError::param_invalid(format!("report_event payload: {error}")))?;
    let reporter_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let reporter_account = reporter_actor.as_account_id().ok_or_else(|| {
        AppError::capability_denied("self moderation reports require an authenticated account")
    })?;
    let event_value = serde_json::to_value(event)
        .map_err(|error| AppError::param_invalid(format!("report_event encode: {error}")))?;
    let canonical_bytes = crate::routing::events::event_log::event_canonical_bytes(&event_value)
        .map_err(|error| {
            AppError::param_invalid(format!("report_event canonical form: {}", error.message))
        })?;
    let exact_replay = state
        .event_queries()
        .canonical_event(event.event_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("moderation replay lookup failed: {error}")))?
        .is_some_and(|record| record.canonical_bytes == canonical_bytes);
    if !exact_replay {
        if !realm_has_member(state, event.realm_id.as_str(), &reporter_actor.to_string()).await {
            return Err(AppError::capability_denied(
                "reporter_id cannot see the target realm",
            ));
        }
        let evidence_package = payload
            .evidence_package
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("evidence package encode failed: {error}"))
            })?
            .unwrap_or(Value::Null);
        let franking_proof = payload
            .franking_proof
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| AppError::internal(format!("franking proof encode failed: {error}")))?
            .unwrap_or(Value::Null);
        validate_signed_moderation_report_safety(
            state,
            event.realm_id.as_str(),
            &reporter_actor,
            payload.target_ref.as_str(),
            payload.effective_scope.as_ref(),
            &evidence_package,
            &franking_proof,
        )
        .await?;
    }
    let accepted_target =
        arkret_models_collaboration::governance::moderation::ModerationReportAcceptedTargetBasis {
            target_ref: payload.target_ref.to_string(),
            effective_scope: event.scope_ref.clone(),
        };
    body.validate_authoring_context(reporter_account, &accepted_target, digest_suite)
        .map_err(|error| AppError::param_invalid(format!("report_event: {error}")))?;
    let report_id = body
        .report_id(digest_suite)
        .map_err(|error| AppError::param_invalid(format!("report_event: {error}")))?;
    let report_event_id = event.event_id.clone();
    let report_payload = Value::Object(event.payload.clone().into_iter().collect());
    let report_scope = event.scope_ref.clone();
    let report_created_at = event.created_at;
    crate::routing::events::event_log::submit_initial_event_submission(
        state,
        &session,
        body.report_event,
    )
    .await
    .map_err(|error| {
        crate::routing::events::event_log::submit_one_error_to_app_error(
            "moderation report Event submit failed",
            error.status(),
            error.code(),
            &error.message(),
        )
    })?;
    crate::routing::events::projection::materialize_moderation_report_record(
        state,
        &report_event_id,
        &report_payload,
        &report_scope,
        report_created_at,
    )
    .await
    .map_err(AppError::internal)?;
    json_ok(ModerationReportOutcome {
        report_id,
        status:
            arkret_models_collaboration::governance::moderation::ModerationReportStatus::Submitted,
        routed_to_ids: Vec::new(),
    })
}

pub(crate) async fn visible_reports_for_actor(
    state: &AppState,
    actor: &str,
    realm_filter: Option<&str>,
) -> Vec<Value> {
    let all = state
        .governance()
        .moderation_reports()
        .await
        .unwrap_or_default();
    let mut visible = Vec::new();
    for report in all {
        let realm_id = report_realm_id(&report);
        if realm_filter.is_some_and(|filter| realm_id != Some(filter)) {
            continue;
        }
        if moderation_report_visible_to_actor(state, &report, actor).await {
            visible.push(report);
        }
    }
    visible
}

pub(crate) async fn moderation_report_visible_to_actor(
    state: &AppState,
    report: &Value,
    actor: &str,
) -> bool {
    if state.is_admin_principal(actor) {
        return true;
    }
    match report_realm_id(report) {
        Some(realm_id) => moderation_routing_visible_to_actor(state, realm_id, actor).await,
        None => false,
    }
}

fn report_realm_id(report: &Value) -> Option<&str> {
    report.get("realm_id").and_then(Value::as_str)
}

async fn moderation_routing_visible_to_actor(
    state: &AppState,
    realm_id: &str,
    actor: &str,
) -> bool {
    if state.is_admin_principal(actor) {
        return true;
    }
    let owner = state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.owner);
    // Realm metadata stores the normative complete ActorId, while authenticated
    // sessions identify the signing principal. Resolve the same identity facet
    // used by authorization before comparing or passing the owner onward.
    let owner_principal = owner.as_deref().and_then(|owner| {
        serde_json::from_str::<arkret_wire::ActorId>(owner)
            .ok()
            .map(|actor_id| actor_id.signing_principal_id().as_str().to_owned())
    });
    if owner_principal.as_deref() == Some(actor) {
        return true;
    }
    let Ok(principal_id) = arkret_wire::DidCoreId::new(actor.to_owned()) else {
        return false;
    };
    let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal_id,
        state.service_core_id().clone(),
    ));
    let members = {
        let realms = state.realm_directory().snapshot();
        RealmId::new(realm_id.to_owned())
            .ok()
            .and_then(|id| realms.get(&id))
            .map(|realm| {
                realm
                    .members
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default()
    };
    [
        arkret_wire::CapabilityActionId::MODERATION_DECISION,
        arkret_wire::CapabilityActionId::REALM_ADMIN,
    ]
    .into_iter()
    .any(|action| {
        state
            .authorization()
            .check(soland_services::authorization::AuthorizationCheck {
                actor: &actor_id,
                action,
                resource: realm_id,
                realm_id,
                owner: owner_principal.as_deref(),
                members: &members,
                resource_facets: &[],
            })
            .allowed
    })
}

#[cfg(test)]
mod report_safety_tests {
    use serde_json::{Value, json};
    use soland_storage_postgres::Db;

    use super::*;
    use crate::config::{AppConfig, ObjectStorageConfig};

    const REALM: &str = "ak:realm:AUFiO2if_pcrsCPNPTKGbSLg0Q25_sBaNHxyQyo5pn7z";
    const TARGET: &str = "ak:message:AUDcGyskAu9_TgDdHy4-tLmIbJp1s_rpjKSw3apHadK8";
    const FRANKING_RECEIVED_AT: &str = "2026-04-30T00:00:00.000Z";
    const REPORTER: &str = "ak:did_core:web:alice.example";

    fn test_state() -> AppState {
        let state = AppState::new(
            AppConfig {
                object_storage: ObjectStorageConfig::local(
                    std::env::temp_dir().join("soland-moderation-tests"),
                ),
                development_mode: true,
                jws_replay_window_seconds: 0,
                jws_replay_window_per_family: std::collections::BTreeMap::new(),
                ..AppConfig::test_default()
            },
            Db { pool: None },
        );
        state.test_projection().lock().messages.insert(
            TARGET.replacen("ak:message:", "ak:event:", 1),
            soland_domain::reducer::MessageState {
                event_id: TARGET.replacen("ak:message:", "ak:event:", 1),
                message_id: TARGET.to_owned(),
                realm_id: REALM.to_owned(),
                sender: REPORTER.to_owned(),
                thread_id: REALM.to_owned(),
                content: json!({ "kind": "ak.content.text", "body": "reported" }),
                encrypted: false,
                operation_id: "ak:operation:01904100-0000-7000-8000-000000000777".to_owned(),
                created_at: chrono::Utc::now(),
                revision_of: None,
                redacted_at: None,
            },
        );
        state
    }

    fn realm_scope() -> Value {
        json!({"kind": "realm", "realm_id": REALM})
    }

    fn restricted_circle_state() -> (AppState, ActorId, String) {
        let state = test_state();
        let reporter = ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(REPORTER).unwrap(),
            state.service_core_id().clone(),
        ));
        let circle_id = "ak:circle:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M".to_owned();
        {
            let mut projection = state.test_projection().lock();
            projection
                .messages
                .get_mut(&TARGET.replacen("ak:message:", "ak:event:", 1))
                .unwrap()
                .content["scope_circle_id"] = json!(circle_id);
            projection.circles.insert(
                circle_id.clone(),
                soland_domain::reducer::CircleProjection {
                    circle_id: circle_id.clone(),
                    realm_id: REALM.into(),
                    profile_ref: None,
                    title: "Restricted reports".into(),
                    summary: None,
                    display: json!({}),
                    directory_visibility: "members".into(),
                    join_rule: "invite".into(),
                    history_access: "since_join".into(),
                    content_encryption_floor: None,
                    metadata_encryption_floor: None,
                    encryption_profile: "none".into(),
                    content_scheme: None,
                    durability_policy: None,
                    mls_group_ref: None,
                    state: soland_domain::reducer::CircleLifecycleState::Active,
                    state_changed_at: None,
                    created_by: reporter.to_string(),
                    created_at: now(),
                    updated_by: None,
                    updated_at: None,
                    members: BTreeSet::from([reporter.to_string()]),
                },
            );
        }
        (state, reporter, circle_id)
    }

    #[test]
    fn report_circle_visibility_requires_exact_reporter_actor() {
        let (state, reporter, circle_id) = restricted_circle_state();
        assert_eq!(
            moderation_target_effective_scope_value(&state, REALM, Some(&reporter), TARGET)
                .unwrap(),
            json!({"kind": "circle", "realm_id": REALM, "circle_id": circle_id}),
        );
        let foreign = ActorId::account(arkret_wire::AccountId::new(
            reporter.signing_principal_id().clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        let service = ActorId::service(reporter.signing_principal_id().clone());
        for other in [&foreign, &service] {
            assert!(
                moderation_target_effective_scope_value(&state, REALM, Some(other), TARGET)
                    .is_err()
            );
        }
    }

    #[test]
    fn unmapped_mimi_reporter_cannot_use_principal_as_circle_membership() {
        let (state, ..) = restricted_circle_state();
        assert!(moderation_target_effective_scope_value(&state, REALM, None, TARGET).is_err());
        // The provider-authenticated facade keeps its existing Realm reporting
        // behavior, but no principal-only hint confers private Circle access.
        assert_eq!(
            moderation_target_effective_scope_value(&state, REALM, None, REALM).unwrap(),
            realm_scope(),
        );
    }

    fn hash(ch: char) -> String {
        format!("sha256:{}", ch.to_string().repeat(64))
    }

    fn franking_event_fixture() -> (String, String, Vec<u8>) {
        let canonical_bytes = b"{}".to_vec();
        let canonical_digest = arkret_canonical::sha256_digest(&canonical_bytes);
        let digest = arkret_identifiers::Hash::new(canonical_digest.clone()).unwrap();
        let event_id = arkret_identifiers::EventId::from_event_digest(&digest)
            .unwrap()
            .to_string();
        (event_id, canonical_digest, canonical_bytes)
    }

    async fn seed_franking_event_anchor(state: &AppState, received_at: &str) {
        let received_at = chrono::DateTime::parse_from_rfc3339(received_at)
            .unwrap()
            .with_timezone(&chrono::Utc);
        let (event_id, canonical_digest, canonical_bytes) = franking_event_fixture();
        state
            .event_queries()
            .store_canonical_event(soland_services::events::AcceptedEvent {
                event_id,
                actor_id: REPORTER.to_owned(),
                actor_seq: 1,
                realm_id: Some(REALM.to_owned()),
                kind: "ak.message.create".to_owned(),
                schema_id: "ak.schema.event.v1".to_owned(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                canonical_digest,
                canonical_bytes,
                envelope: json!({
                    "payload": {
                        "encrypted_content": {
                            "payload_digest": hash('d')
                        }
                    }
                }),
                received_at,
            })
            .await
            .unwrap();
    }

    fn valid_evidence(scope: Value) -> Value {
        json!({
            "encryption": "xchacha20poly1305",
            "recipients": ["did:web:moderator.example#key-1"],
            "ciphertext_digest": hash('a'),
            "plaintext_digest": hash('b'),
            "effective_scope": scope,
        })
    }

    fn valid_franking(state: &AppState) -> Value {
        let (event_id, ..) = franking_event_fixture();
        let proof = FrankingProof::signed(
            RealmId::new(REALM.to_owned()).unwrap(),
            EventId::new(event_id).unwrap(),
            arkret_wire::DidCoreId::new(state.service_id().clone()).unwrap(),
            state.service_verification_method("notary-key").unwrap(),
            chrono::DateTime::parse_from_rfc3339(FRANKING_RECEIVED_AT)
                .unwrap()
                .with_timezone(&chrono::Utc),
            "nonce_0123456789".to_owned(),
            |bytes| {
                Ok(arkret_canonical::base64url_encode(
                    state.notary_signing_key().sign(bytes).to_bytes(),
                ))
            },
        )
        .unwrap();
        serde_json::to_value(proof).unwrap()
    }

    #[test]
    fn authored_event_wire_value_is_the_bare_event_envelope() {
        let realm_id = RealmId::new(REALM.to_owned()).unwrap();
        let event = crate::test_event::raw_event(
            arkret_wire::EventKind::MessageCreate.as_str(),
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            crate::test_actor_id_str("did:web:alice.example"),
            0,
            arkret_wire::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
            json!({
                "strand_id": arkret_wire::StrandId::from_event_id(
                    &EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x31; 32]),
                ),
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"},
            }),
        )
        .unwrap();
        let authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();

        let wire = authored_event_wire_value(&authored).unwrap();

        assert_eq!(wire["event_id"], json!(authored.event_id()));
        assert!(wire.get("digest_suite").is_none());
        assert!(wire.get("event").is_none());
    }

    #[test]
    fn service_franking_event_binds_authority_and_data_to_the_same_seal() {
        let state = test_state();
        let proof: FrankingProof = serde_json::from_value(valid_franking(&state)).unwrap();
        let basis = arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "1".repeat(64))).unwrap();
        let created_at = chrono::DateTime::parse_from_rfc3339(FRANKING_RECEIVED_AT)
            .unwrap()
            .with_timezone(&chrono::Utc);

        let event = author_franking_proof_event(
            proof,
            state.service_core_id().clone(),
            Vec::new(),
            basis.clone(),
            0,
            arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
            created_at,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();

        assert_eq!(event.event().data_basis.as_ref(), Some(&basis));
        assert_eq!(
            event
                .event()
                .auth_context
                .as_ref()
                .map(|context| context.authority_refs.as_slice()),
            Some(std::slice::from_ref(&basis)),
        );
    }

    #[test]
    fn evidence_package_must_bind_effective_scope() {
        let scope = realm_scope();
        let good = valid_evidence(scope.clone());
        assert!(validate_moderation_evidence_package(&good, &scope).is_ok());

        let bad_scope = json!({
            "kind": "realm",
            "realm_id": "ak:realm:AY0gS_Ca_ad26DoNgNiV6G3woRWfh98gR3yAOYzEkyz5",
        });
        let bad = valid_evidence(bad_scope);
        let error = validate_moderation_evidence_package(&bad, &scope).unwrap_err();
        assert_eq!(error.code, ErrorCode::ParamInvalid);
    }

    #[test]
    fn evidence_package_over_max_total_blob_bytes_is_rejected() {
        let scope = realm_scope();
        let mut evidence = valid_evidence(scope.clone());
        evidence
            .as_object_mut()
            .unwrap()
            .insert("padding".to_owned(), json!("x".repeat(70 * 1024)));
        let error = validate_moderation_evidence_package(&evidence, &scope).unwrap_err();
        assert_eq!(error.code, ErrorCode::PayloadTooLarge);
    }

    #[tokio::test]
    async fn duplicate_target_report_hits_layered_rate_limit() {
        let state = test_state();
        let first = validate_moderation_report_safety(
            &state,
            REALM,
            REPORTER,
            None,
            TARGET,
            None,
            &Value::Null,
            &Value::Null,
            None,
            "source-ip-hash",
        )
        .await;
        assert!(first.is_ok());

        let second = validate_moderation_report_safety(
            &state,
            REALM,
            REPORTER,
            None,
            TARGET,
            None,
            &Value::Null,
            &Value::Null,
            None,
            "source-ip-hash",
        )
        .await
        .unwrap_err();
        assert_eq!(second.code, ErrorCode::RateLimited);
    }

    #[tokio::test]
    async fn franking_without_event_time_anchor_is_rejected() {
        let state = test_state();
        let proof = valid_franking(&state);
        let error = validate_moderation_franking_proof(&state, REALM, &proof)
            .await
            .unwrap_err();
        assert_eq!(error.wire_code(), "param_invalid");
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );
    }

    #[tokio::test]
    async fn franking_backdated_outside_event_anchor_is_rejected() {
        let state = test_state();
        seed_franking_event_anchor(&state, "2026-04-30T00:10:01.000Z").await;
        let proof = valid_franking(&state);
        let error = validate_moderation_franking_proof(&state, REALM, &proof)
            .await
            .unwrap_err();
        assert_eq!(error.wire_code(), "param_invalid");
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );
    }

    #[test]
    fn franking_existence_anchor_requires_retained_event_ancestry() {
        let proof = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32]);
        let anchor = arkret_wire::ExistenceAnchor {
            authorization_event_id: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [2; 32],
            ),
            generation_event_id: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [3; 32],
            ),
            frontier: vec![proof.clone()],
        };
        assert!(
            existence_anchor_closure(&anchor, &proof, &std::collections::BTreeMap::new())
                .unwrap()
                .is_none()
        );
        let invalid = arkret_wire::ExistenceAnchor {
            frontier: vec![],
            ..anchor
        };
        assert!(
            existence_anchor_closure(&invalid, &proof, &std::collections::BTreeMap::new()).is_err()
        );
    }
}
