//! Sidecar ensure admission boundary.
//!
//! The current request carries producer-signed Events. An accepted result
//! requires their RealmCommits, Sidecar current state and any delivery intents
//! to commit in one authority transaction.

use arkret_wire::{Event, EventKind};
use salvo::http::StatusCode;

use super::{AppState, SessionRecord, SubmitOneError};

pub(crate) async fn submit_sidecar_ensure_batch(
    _state: &AppState,
    _session: &SessionRecord,
    create_event: Option<Event>,
    context_attach_event: Event,
) -> Result<(), SubmitOneError> {
    if context_attach_event.kind != EventKind::SidecarContextAttach {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Sidecar ensure requires a context attach Event",
        ));
    }
    arkret_schema::validate_event_for_submit(&context_attach_event).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("invalid Sidecar attach Event: {error}"),
        )
    })?;
    if let Some(create_event) = create_event {
        if create_event.kind != EventKind::SidecarCreate
            || create_event.realm_id != context_attach_event.realm_id
            || create_event.actor_id != context_attach_event.actor_id
        {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "Sidecar create and attach Events must share Realm and controller",
            ));
        }
        arkret_schema::validate_event_for_submit(&create_event).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid Sidecar create Event: {error}"),
            )
        })?;
    }
    Err(SubmitOneError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        "Sidecar ensure awaits atomic Event/RealmCommit/current admission",
    ))
}
