//! Moderation user-facing endpoints.
//!
//! - `POST /_arkret/self/moderation/report` (`ak.self.moderation.command.report`) — file a report.
//!   Persists both the report record and a derived queue item (`ModerationQueueItem`) per the
//!   spec's triage architecture.
//! - moderation appeals are durable `ak.moderation.appeal.*` events submitted through `POST
//!   /_arkret/self/events`. The four-state appeal FSM and separation-of-duties enforcement are
//!   authoritative in the reducer (`soland_domain::reducer::apply_moderation`), surfaced at ingest
//!   by the moderation projection preflight.

use arkret_identifiers::{Did, EventId, Hash, RealmId};
use arkret_models_collaboration::events_payloads::moderation::{
    FrankingProof, FrankingProofEventTimeAnchor, MODERATION_FRANKING_PROOF_KIND,
};
use arkret_wire::EffectiveScope;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::runtime_guards::MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES;

use super::{append_audit_log, now, realm_has_member, sha256_hex, validate_did};
use crate::ids;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{ModerationReportOutcome, ModerationReportRequestBody};

pub(super) fn protocol_router() -> Router {
    Router::new().push(Router::with_path("moderation/report").post(moderation_report))
}

#[derive(Clone, Debug)]
pub(super) struct ModerationReportSafety {
    pub effective_scope: Value,
    pub evidence_package: Option<Value>,
    pub franking_proof: Option<Value>,
}

pub(super) fn moderation_request_source_ip_hash(req: &Request) -> String {
    let source = trusted_forwarded_client(req).unwrap_or_else(|| req.remote_addr().to_string());
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
    effective_scope: Option<&EffectiveScope>,
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

    let effective_scope = moderation_effective_scope_value(realm_id, effective_scope)?;
    let target_scope =
        moderation_target_effective_scope_value(state, realm_id, reporter, target_ref)?;
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

fn trusted_forwarded_client(req: &Request) -> Option<String> {
    if std::env::var("SOLAND_RATE_LIMIT_TRUST_X_FORWARDED_FOR")
        .ok()
        .as_deref()
        != Some("1")
    {
        return None;
    }
    let header = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())?;
    header
        .split(',')
        .map(str::trim)
        .find(|part| !part.is_empty())
        .map(ToOwned::to_owned)
}

fn moderation_effective_scope_value(
    realm_id: &str,
    effective_scope: Option<&EffectiveScope>,
) -> Result<Value, AppError> {
    match effective_scope {
        None => Ok(json!({"kind": "realm", "realm_id": realm_id})),
        Some(EffectiveScope::Realm {
            realm_id: scope_realm,
        }) => {
            if scope_realm.as_str() != realm_id {
                return Err(AppError::invalid_param(
                    "effective_scope.realm_id must match report realm_id",
                ));
            }
            Ok(json!({"kind": "realm", "realm_id": scope_realm.as_str()}))
        }
        Some(EffectiveScope::Circle {
            realm_id: scope_realm,
            circle_id,
        }) => {
            if scope_realm.as_str() != realm_id {
                return Err(AppError::invalid_param(
                    "effective_scope.realm_id must match report realm_id",
                ));
            }
            Ok(json!({
                "kind": "circle",
                "realm_id": scope_realm.as_str(),
                "circle_id": circle_id.as_str(),
            }))
        }
        // `EffectiveScope` is #[non_exhaustive]; fail closed on any scope
        // kind this build does not understand rather than guessing a shape.
        Some(_) => Err(AppError::invalid_param(
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
    projection: &'a soland_services::projection::ProjectionSnapshot,
    target_ref: &str,
) -> Option<&'a soland_services::projection::MessageReadModel> {
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
        .ok_or_else(|| AppError::invalid_param("evidence_package must be an object"))?;
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(evidence_package).map_err(|error| {
            AppError::bad_json(format!(
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
        return Err(AppError::invalid_param(
            "evidence_package.encryption is required",
        ));
    };
    let encryption = encryption.to_ascii_lowercase();
    if matches!(encryption.as_str(), "none" | "plaintext" | "cleartext") {
        return Err(AppError::invalid_param(
            "evidence_package must be encrypted",
        ));
    }
    if !object
        .get("ciphertext_digest")
        .and_then(Value::as_str)
        .is_some_and(is_valid_report_hash)
    {
        return Err(AppError::invalid_param(
            "evidence_package.ciphertext_digest must be a hash digest",
        ));
    }
    if object
        .get("plaintext_digest")
        .and_then(Value::as_str)
        .is_some_and(|digest| !is_valid_report_hash(digest))
    {
        return Err(AppError::invalid_param(
            "evidence_package.plaintext_digest must be a hash digest",
        ));
    }
    if object
        .get("recipients")
        .and_then(Value::as_array)
        .is_none_or(|recipients| recipients.is_empty())
    {
        return Err(AppError::invalid_param(
            "evidence_package.recipients must name at least one moderator audience",
        ));
    }
    let scope_matches = object.get("effective_scope") == Some(effective_scope)
        || object
            .get("audience")
            .and_then(|audience| audience.get("effective_scope"))
            == Some(effective_scope);
    if !scope_matches {
        return Err(AppError::invalid_param(
            "evidence_package audience must bind the report effective_scope",
        ));
    }
    if let Some(key) = contains_forbidden_key(evidence_package, EVIDENCE_PACKAGE_FORBIDDEN_KEYS) {
        return Err(AppError::invalid_param(format!(
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
        .ok_or_else(|| AppError::invalid_param("franking_proof must be an object"))?;
    if object.get("kind").and_then(Value::as_str) != Some(MODERATION_FRANKING_PROOF_KIND) {
        return Err(AppError::invalid_param(
            "franking_proof.kind must be ak.moderation.franking_proof",
        ));
    }
    if object.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return Err(AppError::invalid_param(
            "franking_proof.realm_id must match report realm_id",
        ));
    }
    if !required_string_field(object, "franking_proof_id", "franking_proof")?
        .starts_with("ak:franking_proof:")
    {
        return Err(AppError::invalid_param(
            "franking_proof.franking_proof_id must be a franking proof id",
        ));
    }
    if !required_string_field(object, "event_id", "franking_proof")?.starts_with("ak:event:") {
        return Err(AppError::invalid_param(
            "franking_proof.event_id must be an event id",
        ));
    }
    for field in ["routing_metadata_digest", "ciphertext_digest", "aad_digest"] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(is_valid_report_hash)
        {
            return Err(AppError::invalid_param(format!(
                "franking_proof.{field} must be a hash digest"
            )));
        }
    }
    let received_by = required_string_field(object, "received_by", "franking_proof")?;
    validate_did(received_by)
        .map_err(|_| AppError::invalid_param("franking_proof.received_by must be a DID"))?;
    let replay_nonce = required_string_field(object, "replay_nonce", "franking_proof")?;
    if !is_valid_replay_nonce(replay_nonce) {
        return Err(AppError::invalid_param(
            "franking_proof.replay_nonce must be base64url 16..256 chars",
        ));
    }
    if required_string_field(object, "signature", "franking_proof")?.is_empty() {
        return Err(AppError::invalid_param(
            "franking_proof.signature must be non-empty",
        ));
    }
    let received_at = required_string_field(object, "received_at", "franking_proof")?;
    if arkret_canonical::validate_timestamp_canonical(received_at).is_err() {
        return Err(AppError::invalid_param(
            "franking_proof.received_at must be a canonical Arkret timestamp",
        ));
    }
    validate_franking_sender_claim(object)?;
    if let Some(key) = contains_forbidden_key(franking_proof, FRANKING_PROOF_FORBIDDEN_KEYS) {
        return Err(AppError::invalid_param(format!(
            "franking_proof contains forbidden key `{key}`"
        )));
    }
    let typed_proof: FrankingProof =
        serde_json::from_value(franking_proof.clone()).map_err(|error| {
            franking_proof_invalid(format!("franking_proof typed validation failed: {error}"))
        })?;
    validate_franking_event_time_anchor(state, realm_id, &typed_proof).await?;
    if !state.remember_moderation_franking_nonce(realm_id, received_by, replay_nonce) {
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
    let record = state
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
    let record_realm_id = record
        .realm_id
        .as_deref()
        .ok_or_else(|| franking_proof_invalid("franking_proof event anchor is missing realm_id"))?;
    if record_realm_id != realm_id {
        return Err(franking_proof_invalid(
            "franking_proof event anchor realm_id does not match report realm_id",
        ));
    }
    let ciphertext_digest = encrypted_event_payload_digest(&record).ok_or_else(|| {
        franking_proof_invalid(
            "franking_proof event anchor is not an accepted encrypted v1 message event",
        )
    })?;
    let anchor = FrankingProofEventTimeAnchor::new(
        EventId::new(record.event_id.clone())
            .map_err(|error| franking_proof_invalid(format!("invalid event anchor id: {error}")))?,
        RealmId::new(record_realm_id.to_owned()).map_err(|error| {
            franking_proof_invalid(format!("invalid event anchor realm_id: {error}"))
        })?,
        Did::new(state.service_id().clone()).map_err(|error| {
            franking_proof_invalid(format!("invalid local franking service DID: {error}"))
        })?,
        record.received_at,
        Hash::new(ciphertext_digest.to_owned()).map_err(|error| {
            franking_proof_invalid(format!("invalid event anchor ciphertext digest: {error}"))
        })?,
    );
    proof
        .validate_event_time_anchor(&anchor)
        .map_err(|error| franking_proof_invalid(error.to_string()))
}

fn encrypted_event_payload_digest(
    record: &soland_services::events::CanonicalEventRecord,
) -> Option<&str> {
    record
        .envelope
        .pointer("/payload/encrypted_content/payload_digest")
        .and_then(Value::as_str)
        .filter(|value| is_valid_report_hash(value))
}

// Wire code for an invalid franking proof. `proof_invalid` is a registered
// `reason_code`, so it is sourced from the SDK as `arkret_wire::ReasonCode::PROOF_INVALID`
// rather than a local literal.
fn franking_proof_invalid(message: impl Into<String>) -> AppError {
    AppError::invalid_param(message).with_wire_code(arkret_wire::ReasonCode::PROOF_INVALID)
}

fn validate_franking_sender_claim(object: &serde_json::Map<String, Value>) -> Result<(), AppError> {
    let sender_claim = object
        .get("sender_claim")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("franking_proof.sender_claim must be an object"))?;
    let actor_id = required_string_field(sender_claim, "actor_id", "franking_proof.sender_claim")?;
    validate_did(actor_id).map_err(|_| {
        AppError::invalid_param("franking_proof.sender_claim.actor_id must be a DID")
    })?;
    let device_id =
        required_string_field(sender_claim, "device_id", "franking_proof.sender_claim")?;
    if !device_id.starts_with("ak:device:") {
        return Err(AppError::invalid_param(
            "franking_proof.sender_claim.device_id must be a device id",
        ));
    }
    if !sender_claim
        .get("mls_group_id_digest")
        .and_then(Value::as_str)
        .is_some_and(is_valid_report_hash)
    {
        return Err(AppError::invalid_param(
            "franking_proof.sender_claim.mls_group_id_digest must be a hash digest",
        ));
    }
    Ok(())
}

fn required_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<&'a str, AppError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param(format!("{context}.{field} is required")))
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
    if body.reporter.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "reporter must match authenticated actor",
        ));
    }
    if !realm_has_member(state, body.realm_id.as_str(), &session.actor).await {
        return Err(AppError::capability_denied(
            "reporter cannot see the target realm",
        ));
    }
    let realm_id = body.realm_id.as_str().to_owned();
    let target_ref = body.target_ref.clone();
    let report_reason_code = body.report_reason_code.clone();
    let reporter = body.reporter.as_str().to_owned();
    let source_service = moderation_request_source_service(req);
    let source_ip_hash = moderation_request_source_ip_hash(req);
    let evidence_package = body
        .evidence_package
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| AppError::internal(format!("evidence package encode failed: {error}")))?
        .unwrap_or(Value::Null);
    let franking_proof = body
        .franking_proof
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| AppError::internal(format!("franking proof encode failed: {error}")))?
        .unwrap_or(Value::Null);
    let safety = validate_moderation_report_safety(
        state,
        &realm_id,
        &reporter,
        &target_ref,
        body.effective_scope.as_ref(),
        &evidence_package,
        &franking_proof,
        source_service.as_deref(),
        &source_ip_hash,
    )
    .await?;
    let report_id = ids::generate_report_id();
    // Internal assignment keeps the `<did>#moderation` role form; the wire
    // `routed_to` carries bare DIDs only (spec pattern forbids fragments).
    let moderation_role = format!("{}#moderation", state.service_id());
    let mut report_fields = serde_json::Map::new();
    report_fields.insert("report_id".to_owned(), json!(report_id));
    report_fields.insert("realm_id".to_owned(), json!(realm_id));
    report_fields.insert("effective_scope".to_owned(), safety.effective_scope);
    report_fields.insert("target_ref".to_owned(), json!(target_ref));
    report_fields.insert("report_reason_code".to_owned(), json!(report_reason_code));
    if let Some(description) = body.description {
        report_fields.insert("description".to_owned(), json!(description));
    }
    report_fields.insert("reporter".to_owned(), json!(reporter));
    if !body.evidence_refs.is_empty() {
        report_fields.insert("evidence_refs".to_owned(), json!(body.evidence_refs));
    }
    if let Some(evidence_package) = safety.evidence_package {
        report_fields.insert("evidence_package".to_owned(), evidence_package);
    }
    if let Some(franking_proof) = safety.franking_proof {
        report_fields.insert("franking_proof".to_owned(), franking_proof);
    }
    report_fields.insert("created_at".to_owned(), json!(now()));
    let report_payload = Value::Object(report_fields);
    if let Err(error) = state
        .governance()
        .append_moderation_report(report_payload.clone())
        .await
    {
        tracing::error!(%error, "failed to append moderation report");
    }
    if let Err(error) = state
        .governance()
        .append_moderation_action(json!({
            "action_id": ids::generate("moderation_action"),
            "report_id": report_id,
            "realm_id": realm_id,
            "target_ref": target_ref,
            "status": "open",
            "assigned_to": moderation_role.clone(),
            "created_at": now(),
        }))
        .await
    {
        tracing::error!(%error, "failed to append moderation action");
    }
    // Spec triage: each accepted report is wrapped in a
    // `ModerationQueueItem` cell so admins can prioritise / route /
    // assign reviewers. We default to `status=submitted`,
    // `visibility=metadata_only`, `priority=normal` — sodmin can update
    // via `POST /_soland/admin/moderation/queue/{id}/{assign,prioritise}`.
    let queue_item_ref = ids::generate("modq");
    let queue_item = json!({
        "id": queue_item_ref,
        "report": report_payload,
        "status": "submitted",
        "priority": "normal",
        "visibility": "metadata_only",
        "assigned_to": [moderation_role],
        "audit_refs": [],
        "created_at": now(),
    });
    if let Err(error) = state
        .governance()
        .upsert_moderation_queue_item(queue_item)
        .await
    {
        tracing::warn!(%error, "queue item upsert failed (likely Pg backend stub)");
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "moderation.report",
        json!({"report_id": report_id.clone(), "id": queue_item_ref}),
        "submitted",
    )
    .await;
    let mut routed_to = Vec::new();
    if moderation_routing_visible_to_actor(state, &realm_id, &session.actor).await {
        match validate_did(state.service_id()) {
            Ok(did) => routed_to.push(did),
            Err(_) => tracing::warn!(
                service_id = %state.service_id(),
                "service_id is not a valid bare DID; omitted from routed_to"
            ),
        }
    }
    json_ok(ModerationReportOutcome {
        report_id,
        status: "submitted".to_owned(),
        routed_to,
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
        "ak.moderation.decision",
        "ak.realm.moderation_policy",
        "ak.realm.admin",
    ]
    .into_iter()
    .any(|action| {
        state
            .authorization()
            .check(soland_services::authorization::AuthorizationCheck {
                actor,
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

    const REALM: &str = "ak:realm:01904100-0000-7000-8000-d0d0d0d0d0d0";
    const TARGET: &str = "ak:message:01904100-0000-7000-8000-000000000777";
    const FRANKING_EVENT: &str = "ak:event:01904100-0000-7000-8000-000000000222";
    const FRANKING_RECEIVED_AT: &str = "2026-04-30T00:00:00.000Z";
    const REPORTER: &str = "did:web:alice.example";

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
                expiry: None,
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

    async fn seed_franking_event_anchor(state: &AppState, received_at: &str) {
        let received_at = chrono::DateTime::parse_from_rfc3339(received_at)
            .unwrap()
            .with_timezone(&chrono::Utc);
        state
            .event_queries()
            .store_canonical_event(soland_services::events::CanonicalEventRecord {
                event_id: FRANKING_EVENT.to_owned(),
                actor_id: REPORTER.to_owned(),
                actor_seq: 1,
                realm_id: Some(REALM.to_owned()),
                kind: "ak.message.create".to_owned(),
                schema_id: "ak.schema.event.v1".to_owned(),
                canonical_digest: hash('9'),
                canonical_bytes: b"{}".to_vec(),
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
        json!({
            "kind": "ak.moderation.franking_proof",
            "franking_proof_id": "ak:franking_proof:01904100-0000-7000-8000-000000000111",
            "realm_id": REALM,
            "event_id": FRANKING_EVENT,
            "routing_metadata_digest": hash('c'),
            "ciphertext_digest": hash('d'),
            "aad_digest": hash('e'),
            "sender_claim": {
                "actor_id": REPORTER,
                "device_id": "ak:device:01904100-0000-7000-8000-000000000333",
                "mls_group_id_digest": hash('f'),
            },
            "received_by": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
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
            "realm_id": "ak:realm:01904100-0000-7000-8000-badbadbadbad",
        });
        let bad = valid_evidence(bad_scope);
        let error = validate_moderation_evidence_package(&bad, &scope).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParam);
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
            validate_moderation_franking_proof(&state, REALM, &proof)
                .await
                .is_ok()
        );
        let replay = validate_moderation_franking_proof(&state, REALM, &proof)
            .await
            .unwrap_err();
        assert_eq!(replay.code, ErrorCode::DuplicateConflict);
    }

    #[tokio::test]
    async fn franking_without_event_time_anchor_is_rejected() {
        let state = test_state();
        let proof = valid_franking();
        let error = validate_moderation_franking_proof(&state, REALM, &proof)
            .await
            .unwrap_err();
        assert_eq!(error.wire_code(), arkret_wire::ReasonCode::PROOF_INVALID);
    }

    #[tokio::test]
    async fn franking_backdated_outside_event_anchor_is_rejected() {
        let state = test_state();
        seed_franking_event_anchor(&state, "2026-04-30T00:10:01.000Z").await;
        let proof = valid_franking();
        let error = validate_moderation_franking_proof(&state, REALM, &proof)
            .await
            .unwrap_err();
        assert_eq!(error.wire_code(), arkret_wire::ReasonCode::PROOF_INVALID);
    }
}
