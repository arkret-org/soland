//! Read-only preparation of one caller-signed ordinary message.
use arkret_models_collaboration::message_authoring::{
    MessageAuthoringContent, MessagePrepareOutcome, MessagePrepareRequestBody,
};
use arkret_models_collaboration::prepared_event_draft::PreparedEventDraft;
use arkret_wire::{ActorId, Base64UrlString, EncryptedPayloadScheme, Event, Hash, ScopeRef};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::with_path("messages/prepare").post(prepare)
}
fn invalid(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(SchemaViolation, error.to_string())
}

fn prepared_event_draft(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<PreparedEventDraft, AppError> {
    let digest_payload = event
        .digest_payload()
        .map_err(|error| AppError::internal(format!("message Event draft: {error}")))?;
    let unsigned_bytes = arkret_canonical::canonical_json_bytes(&digest_payload)
        .map_err(|error| AppError::internal(format!("message Event draft bytes: {error}")))?;
    Ok(PreparedEventDraft {
        unsigned_event_bytes: Base64UrlString::new(arkret_canonical::base64url_encode(
            &unsigned_bytes,
        ))
        .map_err(|error| AppError::internal(format!("message draft encode: {error}")))?,
        event_digest: Hash::new(
            event
                .event_digest_with_digest_suite(digest_suite)
                .map_err(|error| AppError::internal(format!("message Event digest: {error}")))?,
        )
        .map_err(|error| AppError::internal(format!("message Event digest invalid: {error}")))?,
    })
}

async fn device_active(
    state: &AppState,
    selector: &soland_storage::DeviceRevocationGateSelector,
) -> Result<(), AppError> {
    state
        .persistence()
        .device_revocation_gate_status(selector)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ensure_allowed()
        .map_err(|e| AppError::capability_denied(e.to_string()))
}

async fn validate_encryption_context(
    state: &AppState,
    request: &MessagePrepareRequestBody,
    scope: &ScopeRef,
    device: &str,
) -> Result<(), AppError> {
    let group = scope.canonical_mls_group_id().map_err(invalid)?;
    let current = state
        .mls_commits()
        .commit(scope, &group)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let MessageAuthoringContent::Mls {
        encrypted_content,
        encrypted_metadata,
        encryption_context: frozen,
    } = &request.intent.content
    else {
        if current.is_some() {
            return Err(crate::app_error!(
                FailedPrecondition,
                "plaintext is not allowed after MLS activation",
            )
            .with_reason_code(arkret_wire::ReasonCode::MLS_ACTIVATION_REQUIRED));
        }
        return Ok(());
    };
    encrypted_content.validate().map_err(invalid)?;
    if let Some(metadata) = encrypted_metadata {
        metadata.validate().map_err(invalid)?;
        if metadata.encryption_context != encrypted_content.encryption_context {
            return Err(crate::app_error!(
                FailedPrecondition,
                "message content and metadata use different encryption contexts",
            ));
        }
    }
    if &frozen.effective_scope != scope
        || frozen.sender_domain != device
        || frozen.scheme != EncryptedPayloadScheme::MlsRfc9420
        || encrypted_content.encryption_context.counter().is_some()
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "message encryption scope, scheme, or sender does not match the authenticated target",
        ));
    }
    let current = current.ok_or_else(|| {
        crate::app_error!(
            RevisionUnavailable,
            "accepted MLS group state is unavailable",
        )
    })?;
    let current_ref = current
        .accepted_commit_ref
        .as_deref()
        .unwrap_or(&current.genesis_event_ref);
    if current.effective_scope != *scope
        || current.epoch != encrypted_content.encryption_context.epoch()
        || current_ref
            != encrypted_content
                .encryption_context
                .group_state_ref()
                .as_str()
        || current.governance_binding.effective_scope() != scope
        || state
            .projections()
            .snapshot()
            .pending_mls_removals
            .iter()
            .any(|removal| {
                removal.realm_id == request.realm_id.as_str()
                    && removal.circle_id.as_deref() == scope.circle_id().map(|id| id.as_str())
            })
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "frozen message encryption context is no longer applicable",
        )
        .with_reason_code(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE));
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.self.messages.command.prepare", tags("messages"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.messages.command.prepare.v1"))]
async fn prepare(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<MessagePrepareRequestBody>,
) -> JsonResult<MessagePrepareOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    let body = body.into_inner();
    body.validate().map_err(invalid)?;
    if body.account_id != account || body.account_id.station_id.as_str() != state.service_id() {
        return Err(AppError::not_found("message preparation not found"));
    }
    let observed_at = crate::wire::now();
    let expires_at = body
        .created_at
        .checked_add_signed(chrono::Duration::seconds(300))
        .ok_or_else(|| {
            crate::app_error!(
                AuthoringRequestExpired,
                "message preparation timestamp overflows expiry",
            )
        })?;
    if body.created_at > observed_at || expires_at <= observed_at {
        return Err(crate::app_error!(
            AuthoringRequestExpired,
            "message preparation has expired or has a future creation time",
        ));
    }
    let request_digest = body.canonical_request_digest().map_err(invalid)?;
    let request_hash = request_digest.as_str().to_owned();
    let generation =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            account.principal_id.as_str(),
            &session.device_id,
        )
        .await
        .map_err(|e| AppError::capability_denied(e.to_string()))?;
    device_active(state, &generation).await?;
    let actor = ActorId::account(account);
    let operation_id = "ak.self.messages.command.prepare.v1";
    let key = format!(
        "{}:{}:{}",
        session.device_id, generation.authorization_ref.event_id, body.request_id
    );
    if let Some(record) = state
        .jobs()
        .scoped_idempotency_record(&actor, operation_id, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    {
        if record.request_hash != request_hash {
            return Err(crate::app_error!(
                DuplicateConflict,
                "message request_id already has another intent",
            ));
        }
        if record.expires_at <= observed_at {
            return Err(crate::app_error!(
                AuthoringRequestExpired,
                "message preparation expired",
            ));
        }
        let result: MessagePrepareOutcome =
            serde_json::from_value(record.response_body).map_err(invalid)?;
        result.validate_against_request(&body).map_err(invalid)?;
        return json_ok(result);
    }
    let scope = {
        let projection = state.projections().snapshot();
        let strand = projection
            .strands
            .get(body.intent.strand_id.as_str())
            .filter(|strand| strand.realm_id == body.realm_id.as_str())
            .ok_or_else(|| AppError::not_found("message target not found"))?;
        let _ = strand;
        match projection.strand_scope_circle_id(body.intent.strand_id.as_str()) {
            Some(circle) => ScopeRef::Circle {
                realm_id: body.realm_id.clone(),
                circle_id: arkret_wire::CircleId::new(circle).map_err(invalid)?,
            },
            None => ScopeRef::Realm {
                realm_id: body.realm_id.clone(),
            },
        }
    };
    validate_encryption_context(state, &body, &scope, &session.device_id).await?;
    let digest_suite = state
        .projections()
        .realm_digest_suite(body.realm_id.as_str());
    let authored =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
            scope,
            actor.clone(),
            body.intent.payload(),
        )
        .and_then(|draft| draft.author_with_digest_suite(body.created_at, digest_suite))
        .map_err(invalid)?;
    let outcome = MessagePrepareOutcome {
        request_digest,
        draft: prepared_event_draft(authored.event(), digest_suite)?,
        observed_at,
        expires_at,
    };
    outcome.validate_against_request(&body).map_err(invalid)?;
    device_active(state, &generation).await?;
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            authenticated_actor: actor.clone(),
            operation_id: operation_id.to_owned(),
            idempotency_key: key.clone(),
            request_hash: request_hash.clone(),
            response_status: 200,
            response_body: serde_json::to_value(&outcome).map_err(invalid)?,
            created_at: observed_at,
            expires_at: outcome.expires_at,
        })
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let landed = state
        .jobs()
        .scoped_idempotency_record(&actor, operation_id, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(AuthoringRequestExpired, "preparation record is unavailable",)
        })?;
    if landed.request_hash != request_hash {
        return Err(crate::app_error!(
            DuplicateConflict,
            "message request identity conflicts with concurrent request",
        ));
    }
    let result: MessagePrepareOutcome =
        serde_json::from_value(landed.response_body).map_err(invalid)?;
    result.validate_against_request(&body).map_err(invalid)?;
    device_active(state, &generation).await?;
    json_ok(result)
}
