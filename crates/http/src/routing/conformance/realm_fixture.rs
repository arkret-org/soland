//! Development-only accepted Realm Event installation for live conformance.
//!
//! The installer persists canonical Events and drives the production SDK cell
//! projector plus Soland reducer. It does not create federation outcomes or
//! mutate the outbox, so live scenarios still exercise the production submit,
//! fanout, retry, authority recheck, and delivery-status paths.

use arkret_wire::{Event, EventKind, OperationId, OperationKind};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use soland_http::error::AppError;
use soland_services::events::{AcceptedEvent, ProjectedEvent};
use soland_services::projection::ProjectionEffectView;

use crate::state::AppState;
use crate::{JsonResult, json_ok};

const MAX_FIXTURE_EVENTS: usize = 64;

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RealmFixtureInstallRequest {
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    events: Vec<Event>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RealmFixtureInstallOutcome {
    accepted_event_count: usize,
    projected_event_count: usize,
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.conformance.realm_fixture.install",
    tags("conformance")
)]
pub async fn install(
    depot: &mut Depot,
    body: JsonBody<RealmFixtureInstallRequest>,
) -> JsonResult<RealmFixtureInstallOutcome> {
    super::ensure_enabled()?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.events.is_empty() || body.events.len() > MAX_FIXTURE_EVENTS {
        return Err(AppError::param_invalid(
            "Realm fixture requires between one and 64 Events",
        ));
    }
    let realm_id = body.events[0].realm_id.clone();
    if body.events.iter().any(|event| event.realm_id != realm_id) {
        return Err(AppError::param_invalid(
            "Realm fixture Events must share one Realm",
        ));
    }
    let already_has_realm = state
        .projections()
        .snapshot()
        .realm_null_subject_cells
        .keys()
        .any(|(candidate, _)| candidate == realm_id.as_str());
    if !already_has_realm && body.events[0].kind != EventKind::RealmCreate {
        return Err(AppError::param_invalid(
            "a new Realm fixture must begin with ak.realm.create",
        ));
    }

    let received_at = chrono::Utc::now();
    let mut projected = 0;
    let mut staged_bootstrap = Vec::new();
    let genesis_live_digest_suite = (!already_has_realm)
        .then(|| arkret::declared_genesis_live_digest_suite(&body.events[0]))
        .transpose()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    for (index, event) in body.events.iter().enumerate() {
        let digest_suite = if already_has_realm {
            state
                .projections()
                .realm_digest_suite(event.realm_id.as_str())
        } else if index == 0 {
            arkret_canonical::DigestSuite::Sha256
        } else {
            genesis_live_digest_suite.expect("new Realm fixture derived its genesis digest suite")
        };
        let event_digest = event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        let envelope = serde_json::to_value(event)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        let digest_payload = event
            .digest_payload()
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        let canonical_bytes = arkret_canonical::canonical_json_bytes(&digest_payload)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        state
            .event_queries()
            .store_canonical_event(AcceptedEvent {
                event_id: event.event_id.to_string(),
                actor_id: event.actor_id.to_string(),
                actor_seq: event.actor_seq,
                realm_id: Some(event.realm_id.to_string()),
                kind: event.kind.as_str().to_owned(),
                schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
                digest_suite,
                canonical_digest: event_digest,
                canonical_bytes,
                envelope,
                received_at,
            })
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;

        let operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            OperationId::new(arkret_identifiers::new_prefixed_uuid7("ak:operation:"))
                .map_err(|error| AppError::internal(error.to_string()))?,
            OperationKind::Create,
            None,
            event,
            digest_suite,
        )
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
        let writes = state
            .projections()
            .project_accepted_cell_writes_with_digest_suite(event, digest_suite)
            .map_err(AppError::param_invalid)?;
        if already_has_realm {
            if let ProjectionEffectView::Rejected { reason } =
                state
                    .projections()
                    .apply_projected(&operation, &writes, state.hlc())
            {
                return Err(AppError::param_invalid(format!(
                    "Realm fixture projection rejected: {reason}"
                )));
            }
        } else {
            staged_bootstrap.push(soland_services::projection::ProjectedOperation {
                operation: operation.clone(),
                cell_writes: writes,
            });
        }
        state
            .event_queries()
            .append_projected_event(ProjectedEvent {
                event_id: event.event_id.to_string(),
                realm_id: event.realm_id.to_string(),
                event_kind: event.kind.clone(),
                operation_kind: "create".to_owned(),
                operation_id: Some(operation.operation_id.to_string()),
                sender: Some(event.actor_id.to_string()),
                payload: serde_json::Value::Object(event.payload.clone().into_iter().collect()),
                created_at: event.created_at,
                received_at,
            })
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        projected += 1;
    }
    if !already_has_realm {
        let staged = state
            .projections()
            .stage_realm_bootstrap(&staged_bootstrap, false)
            .map_err(|error| {
                AppError::param_invalid(format!(
                    "Realm fixture bootstrap projection rejected: {}",
                    error.reason
                ))
            })?;
        state
            .projections()
            .install_staged_realm_bootstrap(staged)
            .map_err(|error| {
                AppError::internal(format!(
                    "Realm fixture bootstrap projection merge failed: {}",
                    error.reason
                ))
            })?;
    }

    json_ok(RealmFixtureInstallOutcome {
        accepted_event_count: body.events.len(),
        projected_event_count: projected,
    })
}
