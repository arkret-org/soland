use arkret_identifiers::EventId;
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
use arkret_models_integration::{
    AppletNamespaceDomain, AppletTransactionOutcome, RejectedItem, namespace_pattern_matches,
};
use arkret_wire::Event;
use salvo::http::StatusCode;
use soland_services::events::{AppletTransactionReplayResult, AppletTransactionReplayState};
use soland_services::identity::SessionIdentityState as SessionRecord;
use soland_http::error::AppError;

use super::signature::VerifiedInboundTransactionSignature;
use super::types::AppletRecord;
use crate::routing::events::event_log::submit_event_value;
use crate::state::AppState;

pub(super) async fn process_verified_transaction(
    state: &AppState,
    transaction: AppletTransactionRequestBody,
    idempotency_key: &str,
    verified: VerifiedInboundTransactionSignature,
) -> Result<AppletTransactionOutcome, AppError> {
    let source_service_id = transaction.source_service_id.to_string();
    let begin = state
        .event_queries()
        .begin_applet_transaction(AppletTransactionReplayState {
            source_service_id: source_service_id.clone(),
            idempotency_key: idempotency_key.to_owned(),
            source_signature_anchor: verified.source_signature_anchor.clone(),
            request_digest: verified.request_digest.clone(),
            outcome: None,
            received_at: chrono::Utc::now(),
            completed_at: None,
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to begin applet transaction replay record");
            AppError::internal("applet transaction replay store unavailable")
        })?;
    match begin {
        AppletTransactionReplayResult::Fresh => {}
        AppletTransactionReplayResult::Existing(existing) => {
            return replayed_transaction_outcome(existing, &verified);
        }
    }

    let mut rejected = Vec::new();
    for event in transaction.events {
        let event_id = event.event_id.to_string();
        if let Err(reason_code) =
            validate_transaction_event_binding(&verified.install, &source_service_id, &event)
        {
            rejected.push(rejected_event(&event_id, reason_code));
            continue;
        }
        let envelope = match serde_json::to_value(&event) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, %event_id, "applet transaction event serialization failed");
                rejected.push(rejected_event(&event_id, "bad_json"));
                continue;
            }
        };
        let session = applet_event_session(state, &event);
        match submit_event_value(state, &session, envelope).await {
            Ok(outcome) => {
                tracing::debug!(
                    event_id = %outcome.event_id,
                    duplicate = outcome.duplicate,
                    "applet transaction event accepted"
                );
            }
            Err(error) => {
                tracing::warn!(
                    event_id = %event_id,
                    code = %error.code,
                    message = %error.message,
                    "applet transaction event rejected"
                );
                rejected.push(rejected_event_with_detail(
                    &event_id,
                    error.code,
                    error.message,
                ));
            }
        }
    }

    let outcome = AppletTransactionOutcome {
        ok: rejected.is_empty(),
        rejected,
        retry_after_ms: None,
    };
    let outcome_value = serde_json::to_value(&outcome).map_err(|error| {
        AppError::internal(format!("applet transaction outcome serialize: {error}"))
    })?;
    state
        .event_queries()
        .complete_applet_transaction(&source_service_id, idempotency_key, outcome_value)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to complete applet transaction replay record");
            AppError::internal("applet transaction replay store unavailable")
        })?;
    Ok(outcome)
}

fn replayed_transaction_outcome(
    existing: AppletTransactionReplayState,
    verified: &VerifiedInboundTransactionSignature,
) -> Result<AppletTransactionOutcome, AppError> {
    if existing.request_digest != verified.request_digest
        || existing.source_signature_anchor != verified.source_signature_anchor
    {
        return Err(AppError::conflict(
            "Idempotency-Key was already used for a different applet transaction",
        )
        .with_wire_code("duplicate_conflict"));
    }
    let Some(outcome) = existing.outcome else {
        return Err(
            AppError::conflict("applet transaction is already in progress")
                .with_status(StatusCode::CONFLICT)
                .with_wire_code("applet_transaction_in_progress"),
        );
    };
    serde_json::from_value(outcome).map_err(|error| {
        AppError::internal(format!(
            "stored applet transaction outcome invalid: {error}"
        ))
    })
}

fn applet_event_session(state: &AppState, event: &Event) -> SessionRecord {
    let now = chrono::Utc::now();
    SessionRecord {
        token_hash: "applet-transaction-source-signature".to_owned(),
        actor: event.actor_id.to_string(),
        device_id: "applet-transaction".to_owned(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        expires_at: now + chrono::Duration::minutes(5),
        created_at: now,
        revoked_at: None,
    }
}

fn validate_transaction_event_binding(
    install: &AppletRecord,
    source_service_id: &str,
    event: &Event,
) -> Result<(), &'static str> {
    let package = install.package.as_ref().ok_or("applet_install_required")?;
    if package.service_id.as_str() != source_service_id {
        return Err("applet_registration_unauthorized");
    }
    if install.revoked_at.is_some()
        || !matches!(install.status.as_str(), "installed" | "partially_installed")
    {
        return Err("applet_revoked");
    }
    if event.realm_id.as_str() != install.portal_realm_id {
        return Err("applet_effective_scope_mismatch");
    }
    if event.applet_id.as_ref().map(|id| id.as_str()) != Some(install.applet_id.as_str()) {
        return Err("applet_id_mismatch");
    }
    if event
        .authorization_ref
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err("authorization_ref_missing");
    }
    let actor_id = event.actor_id.as_str();
    if actor_id == install.bot_actor_id {
        return Ok(());
    }
    if install
        .ghosts
        .iter()
        .any(|ghost| ghost.ghost_actor_id == actor_id && ghost.revoked_at.is_none())
    {
        return Ok(());
    }
    let Some(namespaces) = install.namespaces.as_ref() else {
        return Err("applet_namespace_mismatch");
    };
    let matched = namespaces.actors.iter().any(|entry| {
        !namespace_pattern_is_wildcard(&entry.pattern)
            && namespace_pattern_matches(AppletNamespaceDomain::Actors, &entry.pattern, actor_id)
    });
    if matched {
        Ok(())
    } else {
        Err("applet_namespace_mismatch")
    }
}

fn namespace_pattern_is_wildcard(pattern: &str) -> bool {
    pattern.contains('*') || pattern.ends_with(':') || pattern.ends_with('/')
}

fn rejected_event(event_id: &str, reason_code: impl Into<String>) -> RejectedItem {
    RejectedItem {
        event_id: EventId::new(event_id.to_owned()).ok(),
        reason_code: reason_code.into(),
        retry_after_ms: None,
    }
}

fn rejected_event_with_detail(
    event_id: &str,
    reason_code: impl Into<String>,
    detail: impl Into<String>,
) -> RejectedItem {
    let _detail = detail.into();
    rejected_event(event_id, reason_code)
}

