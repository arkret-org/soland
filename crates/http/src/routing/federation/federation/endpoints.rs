use arkret_identifiers::{Did, RealmId};
use chrono::Duration;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::actor_signature::{
    federation_verify_actor_digest, federation_verify_actor_unsigned_digest,
    verify_federation_actor_signature,
};
use super::inbound_policy::ensure_private_inbound_read_rail_local;
use super::signature::validate_federation_request_binding;
use super::{now, sync_token};
use crate::state::AppState;

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(in crate::routing::federation::federation) struct FederationActorEventsOutcome {
    actor: String,
    events: Vec<Value>,
    erasure_receipts: Vec<Value>,
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.federation.actor_events",
    tags("federation")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.federation.actor_events"))]
pub(crate) async fn federation_actor_events(
    actor_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<FederationActorEventsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_read_rail_local(state)?;
    let actor = actor_id.into_inner();
    if Did::new(actor.clone()).is_err() {
        return Err(AppError::invalid_param("invalid actor_id"));
    }
    const FEDERATION_ACTOR_EVENTS_SCAN_CAP: usize = 10_000;
    let mut events = state
        .event_queries()
        .projected_events_capped(FEDERATION_ACTOR_EVENTS_SCAN_CAP)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|event| projection_event_matches_actor(event, &actor))
        .collect::<Vec<_>>();
    events.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    let erasure_receipts = {
        let projection = state.projections().snapshot();
        for event in &mut events {
            crate::routing::events::projection::tombstone_projection_event_for_erased_actor(
                &projection,
                event,
            );
        }
        projection
            .erasure_receipts
            .iter()
            .filter(|receipt| receipt.subject_ref.as_deref() == Some(actor.as_str()))
            .map(|receipt| receipt.payload.clone())
            .collect::<Vec<_>>()
    };
    let events = events
        .iter()
        .map(crate::routing::events::projection::projection_event_json)
        .collect::<Vec<_>>();
    json_ok(FederationActorEventsOutcome {
        actor,
        events,
        erasure_receipts,
    })
}

fn projection_event_matches_actor(
    event: &soland_services::events::ProjectedEvent,
    actor: &str,
) -> bool {
    crate::routing::events::projection::projection_event_actor(event) == Some(actor)
        || event
            .payload
            .get("subject")
            .and_then(Value::as_object)
            .and_then(|subject| subject.get("subject_ref"))
            .and_then(Value::as_str)
            == Some(actor)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.federation.realm_members",
    tags("federation")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.federation.realm_members"))]
pub(crate) async fn federation_realm_members(
    realm_id: QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<arkret_models_collaboration::federation::wire_dtos::FederationRealmMemberList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_read_rail_local(state)?;
    let realm_id_value = RealmId::new(realm_id.into_inner())
        .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let members = state
        .realm_directory()
        .snapshot()
        .get(&realm_id_value)
        .map(|realm| {
            realm
                .members
                .iter()
                .map(
                    |principal_id| {
                        arkret_models_collaboration::federation::wire_dtos::MemberRef {
                            principal_id: principal_id.clone(),
                            membership: arkret_models_collaboration::sync_frames::account_sync::MembershipState::Join,
                        }
                    },
                )
                .collect()
        })
        .unwrap_or_default();
    json_ok(
        arkret_models_collaboration::federation::wire_dtos::FederationRealmMemberList {
            members,
            membership_frontier: sync_token(state).await,
            next_cursor: None,
        },
    )
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.federation.verify_actor",
    tags("federation")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.federation.verify_actor"))]
pub(crate) async fn federation_verify_actor(
    body: JsonBody<
        arkret_models_collaboration::federation::wire_dtos::FederationVerifyActorRequestBody,
    >,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_collaboration::federation::wire_dtos::FederationVerifyActorOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let request_hash = federation_verify_actor_digest(&body).map_err(|message| {
        AppError::new(soland_http::error::ErrorCode::SchemaViolation, message)
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    validate_federation_request_binding(&state.config().trust_domain, req, &request_hash)?;

    if state.config().development_mode {
        return json_ok(
            arkret_models_collaboration::federation::wire_dtos::FederationVerifyActorOutcome {
                valid: false,
                actor_id: body.actor_id.clone(),
                verified_key_id: None,
                key_log_head: None,
                did_document_ref: Some(format!("{}#document", body.actor_id)),
                expires_at: Some(now() + Duration::minutes(5)),
                warnings: vec![
                    "development_mode skipped actor signature verification; valid=false because no \
                     signature was checked"
                        .to_owned(),
                ],
            },
        );
    }

    let unsigned_request_digest =
        federation_verify_actor_unsigned_digest(&body).map_err(|message| {
            AppError::new(soland_http::error::ErrorCode::SchemaViolation, message)
                .with_status(StatusCode::BAD_REQUEST)
        })?;
    let verification =
        verify_federation_actor_signature(state, &body, &unsigned_request_digest).await?;

    json_ok(
        arkret_models_collaboration::federation::wire_dtos::FederationVerifyActorOutcome {
            valid: true,
            actor_id: body.actor_id.clone(),
            verified_key_id: Some(verification.verified_key_id),
            key_log_head: Some(verification.key_log_head),
            did_document_ref: Some(verification.did_document_ref),
            expires_at: Some(now() + Duration::minutes(5)),
            warnings: Vec::new(),
        },
    )
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationSealsOutcome {
    pub seals: Vec<arkret_wire::Seal>,
    pub fanout_topology: String,
    pub next_cursor: Option<String>,
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.federation.seals.pull",
    tags("federation")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.federation.seals.pull"))]
pub(crate) async fn federation_seals_pull(
    depot: &mut Depot,
    realm_id: QueryParam<String, true>,
) -> JsonResult<FederationSealsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_read_rail_local(state)?;
    let realm_id = realm_id.into_inner();
    if RealmId::new(realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    let realm = RealmId::new(realm_id).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let leaves = state
        .projections()
        .realm_seal_leaves(&realm)
        .unwrap_or_default();
    let mut seals = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        if let Ok(Some(seal)) = state.projections().seal_by_id(leaf) {
            seals.push(seal);
        }
    }
    json_ok(FederationSealsOutcome {
        seals,
        fanout_topology: state
            .settings()
            .federation_fanout_topology
            .as_str()
            .to_owned(),
        next_cursor: None,
    })
}
