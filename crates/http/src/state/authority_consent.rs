//! Exact caller-signed Consent submission into the PCR current unit.

use arkret_wire::EventAdmissionSubmission;
use chrono::Utc;
use soland_services::identity::SessionIdentityState;
use soland_services::{ServiceError, ServiceResult};
use soland_storage::{ConsentAdmissionOutcome, ConsentAdmissionWrite};

use super::AppState;

pub(crate) async fn submit(
    state: &AppState,
    session: &SessionIdentityState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<ConsentAdmissionOutcome> {
    request
        .validate()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    if request.approval_signatures.is_some()
        || !matches!(
            request.event.kind,
            arkret_wire::EventKind::ConsentGrant | arkret_wire::EventKind::ConsentRevoke
        )
    {
        return Err(ServiceError::SchemaViolation(
            "invalid Consent submission".into(),
        ));
    }
    super::authority_producer_validation::verify_self_event_producer_key(
        state,
        session,
        &request.event,
    )
    .await?;
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|e| ServiceError::Internal(e.to_string()))?;
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            &request.event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            Utc::now(),
        )
        .await?;
    let outcome = state
        .persistence()
        .admit_consent(ConsentAdmissionWrite { transaction })
        .await?;
    if let ConsentAdmissionOutcome::Committed(record) = &outcome {
        if let Some(update) = &record.quarantine_update {
            use crate::routing::identity::device_messages::{
                ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate,
                ActorPrivateDeviceUpdate, fanout_actor_private_update,
                station_device_message_sender,
            };
            let holder = request.event.actor_id.as_account_id().ok_or_else(|| {
                ServiceError::Internal("committed Consent holder is not an Account".into())
            })?;
            fanout_actor_private_update(
                state,
                holder.principal_id.as_str(),
                ActorPrivateDeviceUpdate::AccountData {
                    sender: station_device_message_sender(state),
                    content: ActorPrivateAccountDataUpdate {
                        operation: ActorPrivateAccountDataOperation::Put,
                        account_data_key: update.account_data_key.clone(),
                        revision: update.revision,
                        content: Some(update.payload.clone()),
                        updated_at: update.updated_at,
                    },
                    created_at: update.updated_at,
                },
            )
            .await;
        }
    }
    Ok(outcome)
}
