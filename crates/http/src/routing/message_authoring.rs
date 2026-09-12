//! Read-only preparation of one caller-signed ordinary message.
use arkret_models_collaboration::message_authoring::{
    MessageAuthoringContent, MessagePrepareOutcome, MessagePrepareRequestBody,
};
use arkret_wire::{ActorId, AuthContext, AuthorizationRef, ErrorCode, ScopeRef};
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
    AppError::new(ErrorCode::SchemaViolation, error.to_string())
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
    let MessageAuthoringContent::Mls {
        encrypted_content,
        encryption_context: frozen,
        ..
    } = &request.intent.content
    else {
        return Ok(());
    };
    if &frozen.effective_scope != scope || frozen.sender_domain != device {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "message encryption scope or sender does not match target and authenticated device",
        ));
    }
    let group = scope.canonical_mls_group_id().map_err(invalid)?;
    let current = state
        .mls_commits()
        .commit(scope, &group)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                "accepted MLS group state is unavailable",
            )
        })?;
    let current_ref = current
        .accepted_commit_ref
        .as_deref()
        .unwrap_or(&current.genesis_event_ref);
    if current.frontier_contested
        || current.effective_scope != *scope
        || current.epoch != encrypted_content.encryption_context.epoch()
        || current_ref
            != encrypted_content
                .encryption_context
                .group_state_ref()
                .as_str()
        || current.governance_binding.content_scheme().as_str() != frozen.scheme.as_str()
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
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "frozen message encryption context is no longer applicable",
        ));
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
    let canonical_request = req.payload().await.map_err(invalid)?.to_vec();
    let body = body.into_inner();
    body.validate().map_err(invalid)?;
    if body.account_id != account || body.account_id.station_id.as_str() != state.service_id() {
        return Err(AppError::not_found("message preparation not found"));
    }
    let observed_at = crate::wire::now();
    body.validate_time(observed_at).map_err(|_| {
        AppError::new(
            ErrorCode::AuthoringRequestExpired,
            "message preparation has expired or has a future creation time",
        )
    })?;
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
        session.device_id, generation.target_device_generation_ref, body.request_id
    );
    let request_hash = arkret_canonical::sha256_digest(&canonical_request);
    if let Some(record) = state
        .jobs()
        .scoped_idempotency_record(&actor, operation_id, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    {
        if record.request_hash != request_hash {
            return Err(AppError::new(
                ErrorCode::DuplicateConflict,
                "message request_id already has another intent",
            ));
        }
        if record.expires_at <= observed_at {
            return Err(AppError::new(
                ErrorCode::AuthoringRequestExpired,
                "message preparation expired",
            ));
        }
        let result: MessagePrepareOutcome =
            serde_json::from_value(record.response_body).map_err(invalid)?;
        result
            .validate_for_canonical_request(&canonical_request)
            .map_err(invalid)?;
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
    let frontier = crate::routing::events::event_log::load_realm_actor_frontier(
        state,
        body.realm_id.clone(),
        actor.clone(),
        crate::routing::events::event_log::VerifiedActorPredecessors::from_verified(&[]),
    )
    .await?;
    let mut leaves = state
        .projections()
        .realm_seal_leaves(&body.realm_id)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    leaves.sort();
    leaves.dedup();
    arkret_wire::SealBasis {
        leaves: leaves.clone(),
    }
    .validate_protocol_bounds()
    .map_err(|_| {
        AppError::new(
            ErrorCode::FrontierUnavailable,
            "accepted authorization Seal is unavailable",
        )
    })?;
    let auth = AuthContext {
        key_id: arkret_wire::OpaqueLocalId::new(
            session
                .device_id
                .strip_prefix("ak:")
                .unwrap_or(&session.device_id),
        )
        .map_err(invalid)?,
        key_epoch: 0,
        credential_epoch: None,
    };
    let direct = state
        .projections()
        .snapshot()
        .realm_is_direct_conversation(body.realm_id.as_str());
    let direct_binding = if direct {
        Some(
            arkret_wire::EventId::new(
                state
                    .contacts()
                    .settled_direct_binding_for_realm(body.realm_id.as_str())
                    .ok_or_else(|| {
                        AppError::new(
                            ErrorCode::FrontierUnavailable,
                            "settled Direct Conversation binding unavailable",
                        )
                    })?
                    .binding_event_ref,
            )
            .map_err(invalid)?,
        )
    } else {
        None
    };
    let authorities = if direct {
        vec![Some(
            arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_PARTICIPANT_V1,
        )]
    } else {
        vec![Some(arkret_wire::REALM_AUTHORITY_ROOT_CELL), None]
    };
    let mut outcome = None;
    let mut failure = None;
    'basis: for seal in leaves {
        let suite = state
            .projections()
            .predecessor_digest_suite(&body.realm_id, std::slice::from_ref(&seal))
            .await
            .map_err(|e| AppError::new(ErrorCode::FrontierUnavailable, e.to_string()))?;
        for authority in &authorities {
            let draft = MessagePrepareOutcome::prepare(
                &body,
                frontier.clone(),
                scope.clone(),
                seal.clone(),
                auth.clone(),
                authority
                    .map(AuthorizationRef::new)
                    .transpose()
                    .map_err(invalid)?,
                direct_binding.clone(),
                suite,
                observed_at,
            )
            .map_err(invalid)?;
            let authored = draft.validate_for_request(&body).map_err(invalid)?;
            match crate::routing::events::event_log::validate_message_authoring_candidate(
                state,
                authored.event(),
                suite,
            )
            .await
            {
                Ok(()) => {
                    outcome = Some(draft);
                    break 'basis;
                }
                Err(error) => {
                    failure = Some(error);
                }
            }
        }
    }
    let mut outcome = outcome.ok_or_else(|| {
        failure.unwrap_or_else(|| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                "accepted message authorization unavailable",
            )
        })
    })?;
    outcome.request_digest = arkret_wire::Hash::new(request_hash.clone()).map_err(invalid)?;
    outcome
        .validate_for_canonical_request(&canonical_request)
        .map_err(invalid)?;
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
            AppError::new(
                ErrorCode::AuthoringRequestExpired,
                "preparation record is unavailable",
            )
        })?;
    if landed.request_hash != request_hash {
        return Err(AppError::new(
            ErrorCode::DuplicateConflict,
            "message request identity conflicts with concurrent request",
        ));
    }
    let result: MessagePrepareOutcome =
        serde_json::from_value(landed.response_body).map_err(invalid)?;
    result
        .validate_for_canonical_request(&canonical_request)
        .map_err(invalid)?;
    device_active(state, &generation).await?;
    json_ok(result)
}
