//! Durable physical-erasure execution derived from accepted account-status
//! Events. The Event is the command; this worker owns no parallel peer API.

use std::sync::Arc;

use arkret_models_collaboration::events_payloads::account::AccountStatusPayload;
use arkret_models_collaboration::governance::erasure::{
    ErasureReceiptPackage, ErasureStorageBoundary,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_wire::EventId;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::AppState;

const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExecutionState {
    Pending,
    Completed,
    FanoutEnqueued,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountErasureExecution {
    receiver_service_id: arkret_wire::DidCoreId,
    account_authority_service_id: arkret_wire::DidCoreId,
    account_id: String,
    principal_id: arkret_wire::DidCoreId,
    triggering_status_event_id: EventId,
    storage_boundary: ErasureStorageBoundary,
    state: ExecutionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package: Option<ErasureReceiptPackage>,
}

fn execution_scope(state: &AppState) -> String {
    format!("erasure-execution:{}", state.service_id())
}

fn execution_key(event_id: &EventId, state: ExecutionState) -> String {
    let phase = match state {
        ExecutionState::Pending => "intent",
        ExecutionState::Completed => "completed",
        ExecutionState::FanoutEnqueued => "fanout_enqueued",
    };
    format!("{}:account_private_store:{phase}", event_id.as_str())
}

fn execution_hash(execution: &AccountErasureExecution) -> Result<String, AppError> {
    #[derive(Serialize)]
    struct Coordinates<'a> {
        receiver_service_id: &'a arkret_wire::DidCoreId,
        account_authority_service_id: &'a arkret_wire::DidCoreId,
        account_id: &'a str,
        principal_id: &'a arkret_wire::DidCoreId,
        triggering_status_event_id: &'a EventId,
        storage_boundary: ErasureStorageBoundary,
    }
    arkret_canonical::canonical_sha256(&Coordinates {
        receiver_service_id: &execution.receiver_service_id,
        account_authority_service_id: &execution.account_authority_service_id,
        account_id: &execution.account_id,
        principal_id: &execution.principal_id,
        triggering_status_event_id: &execution.triggering_status_event_id,
        storage_boundary: execution.storage_boundary,
    })
    .map_err(|error| AppError::internal(format!("erasure execution digest: {error}")))
}

/// Persist the execution intent before the account-status receiver acknowledges
/// an erasure_pending Event. Exact replay is a no-op; any coordinate change is
/// a permanent duplicate conflict.
pub async fn ensure_intent(
    state: &AppState,
    account_authority_service_id: &str,
    account_id: &str,
    principal_id: &arkret_wire::DidCoreId,
    event_id: &EventId,
) -> Result<(), AppError> {
    let scope = execution_scope(state);
    let key = execution_key(event_id, ExecutionState::Pending);
    let execution = AccountErasureExecution {
        receiver_service_id: arkret_wire::DidCoreId::new(state.service_id().to_owned())
            .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?,
        account_authority_service_id: arkret_wire::DidCoreId::new(
            account_authority_service_id.to_owned(),
        )
        .map_err(|error| AppError::internal(format!("Account Authority DID invalid: {error}")))?,
        account_id: account_id.to_owned(),
        principal_id: principal_id.clone(),
        triggering_status_event_id: event_id.clone(),
        storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
        state: ExecutionState::Pending,
        package: None,
    };
    let request_hash = execution_hash(&execution)?;
    if let Some(existing) = state
        .jobs()
        .idempotency_record(&scope, &key)
        .await
        .map_err(|error| AppError::internal(format!("erasure intent lookup: {error}")))?
    {
        if existing.request_hash != request_hash {
            return Err(AppError::conflict(
                "erasure execution key is bound to different coordinates",
            ));
        }
        return Ok(());
    }
    let created_at = Utc::now();
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            principal_id: scope,
            idempotency_key: key,
            service_id: state.service_id().clone(),
            request_hash,
            response_status: 202,
            response_body: serde_json::to_value(&execution)
                .map_err(|error| AppError::internal(format!("erasure intent encode: {error}")))?,
            created_at,
            expires_at: created_at + Duration::days(36_500),
        })
        .await
        .map_err(|error| AppError::internal(format!("erasure intent store: {error}")))
}

async fn store_execution(
    state: &AppState,
    execution: &AccountErasureExecution,
    created_at: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            principal_id: execution_scope(state),
            idempotency_key: execution_key(&execution.triggering_status_event_id, execution.state),
            service_id: state.service_id().clone(),
            request_hash: execution_hash(execution)?,
            response_status: if execution.state == ExecutionState::Pending {
                202
            } else {
                200
            },
            response_body: serde_json::to_value(execution).map_err(|error| {
                AppError::internal(format!("erasure execution encode: {error}"))
            })?,
            created_at,
            expires_at: created_at + Duration::days(36_500),
        })
        .await
        .map_err(|error| AppError::internal(format!("erasure execution store: {error}")))
}

async fn run_execution(
    state: &AppState,
    account_id: &str,
    principal_id: &arkret_wire::DidCoreId,
    event_id: &EventId,
) -> Result<(), AppError> {
    let account_authority_service_id =
        crate::routing::events::peer::trusted_account_authority_service_id(state).await?;
    ensure_intent(
        state,
        account_authority_service_id.as_str(),
        account_id,
        principal_id,
        event_id,
    )
    .await?;
    let scope = execution_scope(state);
    let mut stored = None;
    for phase in [
        ExecutionState::FanoutEnqueued,
        ExecutionState::Completed,
        ExecutionState::Pending,
    ] {
        if let Some(record) = state
            .jobs()
            .idempotency_record(&scope, &execution_key(event_id, phase))
            .await
            .map_err(|error| AppError::internal(format!("erasure execution lookup: {error}")))?
        {
            stored = Some(record);
            break;
        }
    }
    let stored = stored
        .ok_or_else(|| AppError::internal("erasure execution disappeared after intent store"))?;
    let mut execution: AccountErasureExecution = serde_json::from_value(stored.response_body)
        .map_err(|error| AppError::internal(format!("erasure execution decode: {error}")))?;
    if execution_hash(&execution)? != stored.request_hash {
        return Err(AppError::conflict(
            "stored erasure execution coordinates do not match their digest",
        ));
    }
    if execution.state == ExecutionState::Pending {
        let package = crate::routing::identity::account::lifecycle::execute_account_status_erasure(
            state,
            &execution.account_id,
            execution.principal_id.as_str(),
            &execution.triggering_status_event_id,
        )
        .await?;
        execution.package = Some(package);
        execution.state = ExecutionState::Completed;
        store_execution(state, &execution, stored.created_at).await?;
        let completed = state
            .jobs()
            .idempotency_record(&scope, &execution_key(event_id, ExecutionState::Completed))
            .await
            .map_err(|error| AppError::internal(format!("erasure completion lookup: {error}")))?
            .ok_or_else(|| AppError::internal("erasure completion was not persisted"))?;
        execution = serde_json::from_value(completed.response_body)
            .map_err(|error| AppError::internal(format!("erasure completion decode: {error}")))?;
    }
    if execution.state == ExecutionState::Completed {
        let package = execution
            .package
            .as_ref()
            .ok_or_else(|| AppError::internal("completed erasure execution has no receipt"))?;
        crate::routing::federation::federation::erasure_receipts::persist_issued_package(
            state,
            package,
            &execution.account_authority_service_id,
        )
        .await?;
        crate::routing::identity::account::lifecycle::fanout_account_status_erasure_receipt(
            state,
            execution.principal_id.as_str(),
            package,
        )
        .await?;
        execution.state = ExecutionState::FanoutEnqueued;
        store_execution(state, &execution, stored.created_at).await?;
    }
    Ok(())
}

/// Reconcile every accepted erasure_pending Event. This makes a crash between
/// Event commit and intent persistence recoverable without introducing a
/// second command carrier.
pub async fn run_once(state: &AppState) -> Result<usize, AppError> {
    let mut processed = 0_usize;
    for record in state
        .event_queries()
        .accepted_events()
        .await
        .map_err(|error| AppError::internal(format!("erasure Event scan: {error}")))?
    {
        if record.kind != arkret_wire::EventKind::AccountStatus.as_str() {
            continue;
        }
        let event: arkret_wire::Event = serde_json::from_value(record.envelope)
            .map_err(|error| AppError::internal(format!("erasure Event decode: {error}")))?;
        let payload: AccountStatusPayload = serde_json::from_value(
            serde_json::to_value(&event.payload)
                .map_err(|error| AppError::internal(format!("erasure payload encode: {error}")))?,
        )
        .map_err(|error| AppError::internal(format!("erasure payload decode: {error}")))?;
        if payload.status != AccountStatus::ErasurePending {
            continue;
        }
        run_execution(
            state,
            &payload.account_id,
            &payload.principal_id,
            &event.event_id,
        )
        .await?;
        processed += 1;
    }
    Ok(processed)
}

pub fn spawn(state: AppState) -> Arc<tokio::task::JoinHandle<()>> {
    Arc::new(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        loop {
            ticker.tick().await;
            if let Err(error) = run_once(&state).await {
                tracing::error!(%error, worker = "account_erasure", "erasure reconciliation failed");
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution(state: ExecutionState) -> AccountErasureExecution {
        AccountErasureExecution {
            receiver_service_id: arkret_wire::DidCoreId::new(
                "ak:did_core:web:principal.example".to_owned(),
            )
            .unwrap(),
            account_authority_service_id: arkret_wire::DidCoreId::new(
                "ak:did_core:web:authority.example".to_owned(),
            )
            .unwrap(),
            account_id: "account-1".to_owned(),
            principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned())
                .unwrap(),
            triggering_status_event_id: EventId::new(
                "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned(),
            )
            .unwrap(),
            storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
            state,
            package: None,
        }
    }

    #[test]
    fn append_only_phases_keep_one_coordinate_digest() {
        let pending = execution(ExecutionState::Pending);
        let completed = execution(ExecutionState::Completed);

        assert_eq!(
            execution_hash(&pending).unwrap(),
            execution_hash(&completed).unwrap()
        );
        assert_ne!(
            execution_key(&pending.triggering_status_event_id, ExecutionState::Pending),
            execution_key(
                &pending.triggering_status_event_id,
                ExecutionState::Completed
            )
        );
        assert_ne!(
            execution_key(
                &pending.triggering_status_event_id,
                ExecutionState::Completed
            ),
            execution_key(
                &pending.triggering_status_event_id,
                ExecutionState::FanoutEnqueued
            )
        );
    }

    #[test]
    fn authority_source_is_part_of_execution_coordinates() {
        let original = execution(ExecutionState::Pending);
        let mut different_authority = original.clone();
        different_authority.account_authority_service_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:other-authority.example".to_owned())
                .unwrap();

        assert_ne!(
            execution_hash(&original).unwrap(),
            execution_hash(&different_authority).unwrap()
        );
    }
}
