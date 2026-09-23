//! Preflight for the current MLS governance binding carried by an Event.
//!
//! RealmCommit admission and the durable MLS group-state compare-and-swap are
//! performed by the authority commit transaction. This module checks the
//! producer's closed payload before that transaction is prepared.

use arkret_models_collaboration::events_payloads::mls::MlsGenesisPayload;
use arkret_models_crypto::MlsCommitPayload;
use arkret_wire::{Event, EventKind};
use soland_http::error::AppError;

pub(super) fn validate_transition_binding_input(event: &Event) -> Result<(), AppError> {
    match event.kind {
        EventKind::MlsGenesis => {
            let payload: MlsGenesisPayload = serde_json::from_value(
                serde_json::to_value(&event.payload)
                    .map_err(|error| AppError::param_invalid(error.to_string()))?,
            )
            .map_err(|error| AppError::param_invalid(format!("invalid MLS Genesis: {error}")))?;
            payload
                .validate()
                .map_err(|error| AppError::param_invalid(error.to_string()))?;
            if payload.effective_scope() != &event.scope_ref {
                return Err(AppError::param_invalid(
                    "MLS Genesis governance binding differs from Event scope",
                ));
            }
        }
        EventKind::MlsCommit => {
            let payload: MlsCommitPayload = serde_json::from_value(
                serde_json::to_value(&event.payload)
                    .map_err(|error| AppError::param_invalid(error.to_string()))?,
            )
            .map_err(|error| AppError::param_invalid(format!("invalid MLS Commit: {error}")))?;
            payload
                .validate()
                .map_err(|error| AppError::param_invalid(error.to_string()))?;
            if payload.governance_binding().effective_scope() != &event.scope_ref {
                return Err(AppError::param_invalid(
                    "MLS Commit governance binding differs from Event scope",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}
