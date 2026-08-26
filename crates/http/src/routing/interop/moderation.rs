//! Moderation user-facing endpoints.
//!
//! - `POST /_arkret/self/moderation/report` (`ak.self.moderation.command.report`) — submit the
//!   caller-authored signed report DataEvent through ordinary Event admission.
//! - moderation appeals are durable `ak.moderation.appeal.*` events submitted through `POST
//!   /_arkret/self/events`. The four-state appeal FSM and separation-of-duties enforcement are
//!   authoritative in the reducer (`soland_domain::reducer::apply_moderation`), surfaced at ingest
//!   by the moderation projection preflight.

use arkret_identifiers::{EventId, Hash, RealmId};
use arkret_models_collaboration::events_payloads::moderation::{
    FrankingProof, FrankingProofEventTimeAnchor, ModerationReportPayload,
};
use arkret_wire::{EventKind, ScopeRef};
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::runtime_guards::MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES;

use super::{now, realm_has_member, sha256_hex};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{ModerationReportOutcome, ModerationReportRequestBody};

pub(super) fn protocol_router() -> Router {
    Router::new().push(Router::with_path("moderation/report").post(moderation_report))
}

pub(crate) async fn persist_mimi_facade_moderation_report_event(
    state: &AppState,
    payload: ModerationReportPayload,
) -> Result<String, AppError> {
    let service_event_lock = crate::routing::events::event_log::service_event_authoring_lock();
    let _service_event_guard = service_event_lock.lock().await;
    let service_actor = state.service_id().as_str();
    let records = state
        .event_queries()
        .canonical_events_for_realm_actor(payload.realm_id.as_str(), service_actor)
        .await
        .map_err(|error| {
            AppError::internal(format!("moderation Event frontier lookup failed: {error}"))
        })?;
    let max_actor_seq = records.iter().map(|record| record.actor_seq).max();
    let actor_seq = max_actor_seq
        .map(|value| {
            value.checked_add(1).ok_or_else(|| {
                AppError::new(
                    ErrorCode::FrontierSequenceExhausted,
                    "moderation Event actor sequence is exhausted",
                )
                .with_status(StatusCode::CONFLICT)
            })
        })
        .transpose()?
        .unwrap_or(0);
    let realm_id = payload.realm_id.clone();
    let service_did = state.service_resolution_commitment().full_id.clone();
    let service_actor_id = arkret_wire::project_full_id_to_core_id(&service_did)
        .map_err(|error| AppError::internal(format!("service DID cannot be projected: {error}")))?;
    let created_at = now();
    let hlc = arkret_identifiers::Hlc::new(state.hlc().now())
        .map_err(|error| AppError::internal(format!("moderation HLC invalid: {error}")))?;
    let typed_payload = payload;
    typed_payload
        .validate_provenance(&service_actor_id)
        .map_err(AppError::param_invalid)?;
    if typed_payload.provenance
        != Some(
            arkret_models_collaboration::events_payloads::moderation::ModerationReportProvenance::MimiFacade,
        )
        || typed_payload.source_provider.is_none()
    {
        return Err(AppError::param_invalid(
            "service-authored moderation report requires MIMI facade provenance",
        ));
    }
    let event_scope =
        typed_payload
            .effective_scope
            .clone()
            .unwrap_or_else(|| arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            });
    let reporter = typed_payload.reporter.as_str().to_owned();
    let target_ref = typed_payload.target_ref.clone();
    // Actor frontier and CBA basis are producer-signed envelope members, so
    // they are resolved before authoring rather than written onto an Event that
    // already carries an id.
    let mut prev_refs = Vec::new();
    if let Some(max_actor_seq) = max_actor_seq {
        prev_refs = records
            .iter()
            .filter(|record| record.actor_seq == max_actor_seq)
            .map(|record| {
                EventId::new(record.event_id.clone()).map_err(|error| {
                    AppError::internal(format!("moderation predecessor invalid: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        prev_refs.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        prev_refs.dedup();
    }
    let seal = crate::notary::ensure_realm_seal_head(state, &realm_id)
        .map_err(|error| {
            AppError::internal(format!("moderation Realm Seal lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                "moderation target Realm has no accepted Seal",
            )
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?;
    let auth_context = arkret_wire::AuthContext {
        key_id: arkret_wire::OpaqueLocalId::new("notary-key").expect("notary key id is opaque"),
        key_epoch: 0,
        credential_epoch: None,
    };
    let digest_suite = state.projections().realm_digest_suite(realm_id.as_str());
    let mut event =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::SelfModerationReport>::new(
            event_scope,
            service_actor_id.clone(),
            service_actor_id,
            typed_payload,
        )
        .and_then(|draft| {
            draft
                .with_prev_refs(prev_refs)
                .with_seal_ref(seal.id)
                .with_auth_context(auth_context)
                .author_with_digest_suite(actor_seq, hlc, created_at, digest_suite)
        })
        .map_err(|error| AppError::internal(format!("moderation Event build failed: {error}")))?;
    let verification_method = arkret_wire::DidUrl::new(format!("{service_did}#notary-key"))
        .map_err(|error| {
            AppError::internal(format!(
                "service notary verification method is invalid: {error}"
            ))
        })?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        service_did,
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .map_err(|error| AppError::internal(format!("moderation Event signing failed: {error}")))?;
    let event_id = event.event_id().to_string();
    let session = soland_services::identity::SessionIdentityState {
        token_hash: "moderation-report-service".to_owned(),
        actor: state.service_id().clone(),
        // Service session: this internal admission authenticates a service
        // identity, which owns no device (see `envelope_core`).
        device_id: String::new(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: created_at + chrono::Duration::minutes(5),
        created_at,
        revoked_at: None,
    };
    let envelope = serde_json::to_value(event).map_err(|error| {
        AppError::internal(format!("moderation Event serialize failed: {error}"))
    })?;
    crate::routing::events::event_log::submit_mimi_moderation_report_event_value(
        state,
        &session,
        envelope,
        realm_id.as_str(),
        &reporter,
        &target_ref,
    )
    .await
    .map_err(|error| {
        AppError::new(
            ErrorCode::ParamInvalid,
            format!("moderation Event admission failed: {}", error.message),
        )
        .with_status(error.status)
        .with_wire_code(error.code)
    })?;
    Ok(event_id)
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
    reporter: &str,
    target_ref: &str,
    effective_scope: Option<&ScopeRef>,
    evidence_package: &Value,
    franking_proof: &Value,
    source_service: Option<&str>,
    source_ip_hash: &str,
) -> Result<ModerationReportSafety, AppError> {
    let rate = state.record_moderation_report_attempt(
        reporter,
        source_service,
        realm_id,
        source_ip_hash,
        target_ref,
    );
    if rate.rate_limited {
        return Err(AppError::new(
            ErrorCode::RateLimited,
            "moderation report rate limit exceeded",
        )
        .with_status(StatusCode::TOO_MANY_REQUESTS)
        .with_reason_detail(format!(
            "bucket={} count={} limit={} retry_after_ms={}",
            rate.bucket.as_deref().unwrap_or("unknown"),
            rate.count,
            rate.limit,
            rate.retry_after_ms
        )));
    }

    validate_moderation_report_content_safety(
        state,
        realm_id,
        reporter,
        target_ref,
        effective_scope,
        evidence_package,
        franking_proof,
        true,
    )
    .await
}

async fn validate_signed_moderation_report_safety(
    state: &AppState,
    realm_id: &str,
    reporter: &str,
    target_ref: &str,
    effective_scope: Option<&ScopeRef>,
    evidence_package: &Value,
    franking_proof: &Value,
) -> Result<ModerationReportSafety, AppError> {
    validate_moderation_report_content_safety(
        state,
        realm_id,
        reporter,
        target_ref,
        effective_scope,
        evidence_package,
        franking_proof,
        false,
    )
    .await
}

async fn validate_moderation_report_content_safety(
    state: &AppState,
    realm_id: &str,
    reporter: &str,
    target_ref: &str,
    effective_scope: Option<&ScopeRef>,
    evidence_package: &Value,
    franking_proof: &Value,
    consume_franking_nonce: bool,
) -> Result<ModerationReportSafety, AppError> {
    let effective_scope = moderation_effective_scope_value(realm_id, effective_scope)?;
    let target_scope =
        moderation_target_effective_scope_value(state, realm_id, reporter, target_ref)?;
    if target_scope != effective_scope {
        return Err(moderation_target_not_found());
    }
    let evidence_package =
        validate_moderation_evidence_package(evidence_package, &effective_scope)?;
    let franking_proof =
        validate_moderation_franking_proof(state, realm_id, franking_proof, consume_franking_nonce)
            .await?;
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
    reporter: &str,
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
        if !projection.circle_scope_visible_to_actor(&circle_id, reporter) {
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
        return Err(AppError::new(
            ErrorCode::PayloadTooLarge,
            "evidence_package exceeds max_total_blob_bytes",
        )
        .with_status(StatusCode::PAYLOAD_TOO_LARGE)
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
    consume_nonce: bool,
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
    validate_franking_event_time_anchor(state, realm_id, &typed_proof).await?;
    if consume_nonce
        && !state.remember_moderation_franking_nonce(realm_id, received_by, replay_nonce)
    {
        return Err(AppError::new(
            ErrorCode::DuplicateConflict,
            "franking_proof replay_nonce was already used",
        )
        .with_status(StatusCode::CONFLICT));
    }
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
    let proof_event = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| {
            AppError::internal(format!("franking proof Event lookup failed: {error}"))
        })?
        .into_iter()
        .find(|candidate| {
            candidate.kind == EventKind::ModerationFrankingProof.as_str()
                && candidate.realm_id.as_deref() == Some(realm_id)
                && candidate.actor_id == proof.received_by.as_str()
                && candidate.envelope.get("payload") == Some(&proof_payload)
        })
        .ok_or_else(|| {
            franking_proof_invalid(
                "franking_proof has no byte-identical accepted durable proof Event",
            )
        })?;
    let proof_event_digest = Hash::new(proof_event.canonical_digest.clone()).map_err(|error| {
        franking_proof_invalid(format!("invalid franking proof Event digest: {error}"))
    })?;
    let covering_seal = state
        .projections()
        .seal_covering_event(&proof_event_digest)
        .map_err(|error| {
            AppError::internal(format!(
                "franking proof covering Seal lookup failed: {error}"
            ))
        })?
        .ok_or_else(|| {
            franking_proof_invalid("franking_proof durable Event has no accepted covering Seal")
        })?;
    let proof_event_created_at = proof_event
        .envelope
        .get("created_at")
        .and_then(Value::as_str)
        .ok_or_else(|| franking_proof_invalid("franking proof Event has no created_at"))?
        .parse()
        .map_err(|error| {
            franking_proof_invalid(format!("invalid franking proof Event created_at: {error}"))
        })?;
    let anchor = FrankingProofEventTimeAnchor::new(
        EventId::new(target.event_id.clone())
            .map_err(|error| franking_proof_invalid(format!("invalid event anchor id: {error}")))?,
        RealmId::new(target_realm_id.to_owned()).map_err(|error| {
            franking_proof_invalid(format!("invalid event anchor realm_id: {error}"))
        })?,
        arkret_identifiers::DidCoreId::new(state.service_id().clone()).map_err(|error| {
            franking_proof_invalid(format!("invalid local franking service DID: {error}"))
        })?,
        proof_event_created_at,
        covering_seal.sealed_at,
    );
    proof
        .validate_event_time_anchor(&anchor)
        .map_err(|error| franking_proof_invalid(error.to_string()))
}

// Wire code for an invalid franking proof. `proof_invalid` is a registered
// `reason_code`, so it is sourced from the SDK as `arkret_wire::ReasonCode::PROOF_INVALID`
// rather than a local literal.
fn franking_proof_invalid(message: impl Into<String>) -> AppError {
    AppError::param_invalid(message).with_wire_code(arkret_wire::ReasonCode::PROOF_INVALID)
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

#[endpoint(
    operation_id = "ak.self.moderation.command.report",
    summary = "File a content moderation report",
    tags("moderation")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.moderation.command.report"))]
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
    let principal_id = arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
        AppError::internal(format!(
            "authenticated session principal id is invalid: {error}"
        ))
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
        if !realm_has_member(state, event.realm_id.as_str(), &session.actor).await {
            return Err(AppError::capability_denied(
                "reporter cannot see the target realm",
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
            payload.reporter.as_str(),
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
    body.validate_authoring_context(&principal_id, &accepted_target, digest_suite)
        .map_err(|error| AppError::param_invalid(format!("report_event: {error}")))?;
    let report_id = body
        .report_id(digest_suite)
        .map_err(|error| AppError::param_invalid(format!("report_event: {error}")))?;
    crate::routing::events::event_log::submit_initial_event_submission(
        state,
        &session,
        body.report_event,
    )
    .await
    .map_err(|error| {
        crate::routing::events::event_log::submit_one_error_to_app_error(
            "moderation report Event submit failed",
            error.status,
            error.code,
            &error.message,
        )
    })?;
    json_ok(ModerationReportOutcome {
        report_id,
        status:
            arkret_models_collaboration::governance::moderation::ModerationReportStatus::Submitted,
        routed_to: Vec::new(),
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
    if owner.as_deref() == Some(actor) {
        return true;
    }
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
        arkret_wire::CapabilityActionId::REALM_MODERATION_POLICY,
        arkret_wire::CapabilityActionId::REALM_ADMIN,
    ]
    .into_iter()
    .any(|action| {
        state
            .authorization()
            .check(soland_services::authorization::AuthorizationCheck {
                actor,
                actor_principal_server_id: Some(state.service_id()),
                action,
                resource: realm_id,
                realm_id,
                owner: owner.as_deref(),
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
                history_basis_seals: Vec::new(),
                revision_of: None,
                redacted_at: None,
            },
        );
        state
    }

    fn realm_scope() -> Value {
        json!({"kind": "realm", "realm_id": REALM})
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

    fn valid_franking() -> Value {
        let (event_id, ..) = franking_event_fixture();
        let received_by = crate::test_event::principal_server_id();
        json!({
            "realm_id": REALM,
            "event_id": event_id,
            "received_by": received_by,
            "verification_method": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service#notary-key",
            "received_at": FRANKING_RECEIVED_AT,
            "replay_nonce": "nonce_0123456789",
            "signature": "sig",
        })
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
    async fn franking_replay_nonce_is_rejected_within_window() {
        let state = test_state();
        seed_franking_event_anchor(&state, FRANKING_RECEIVED_AT).await;
        let proof = valid_franking();
        assert!(
            validate_moderation_franking_proof(&state, REALM, &proof, true)
                .await
                .is_ok()
        );
        let replay = validate_moderation_franking_proof(&state, REALM, &proof, true)
            .await
            .unwrap_err();
        assert_eq!(replay.code, ErrorCode::DuplicateConflict);
    }

    #[tokio::test]
    async fn franking_without_event_time_anchor_is_rejected() {
        let state = test_state();
        let proof = valid_franking();
        let error = validate_moderation_franking_proof(&state, REALM, &proof, true)
            .await
            .unwrap_err();
        assert_eq!(error.wire_code(), arkret_wire::ReasonCode::PROOF_INVALID);
    }

    #[tokio::test]
    async fn franking_backdated_outside_event_anchor_is_rejected() {
        let state = test_state();
        seed_franking_event_anchor(&state, "2026-04-30T00:10:01.000Z").await;
        let proof = valid_franking();
        let error = validate_moderation_franking_proof(&state, REALM, &proof, true)
            .await
            .unwrap_err();
        assert_eq!(error.wire_code(), arkret_wire::ReasonCode::PROOF_INVALID);
    }
}
