//! Development-only state installation and observation for Direct Repair E2E.
//!
//! The installer accepts complete typed Events and runs the ordinary SDK cell
//! projector plus Soland reducer before persisting the accepted/projected rows.
//! It never manufactures a repair outcome and the E2E still enters through the
//! production self-dispatch and peer-relay handlers.

use arkret_models_identity::ServiceResolutionCarrier;
use arkret_wire::{Event, EventKind, Hash, OperationId, OperationKind};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soland_http::error::AppError;
use soland_services::events::{CanonicalEventRecord, ProjectedEvent};
use soland_services::identity::{
    ContactRecord, DirectConversationCoordinatesRecord, DirectConversationEndorsement,
};
use soland_services::projection::ProjectionEffectView;

use crate::state::AppState;
use crate::{JsonResult, json_ok};

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct DirectRepairFixtureContact {
    requester: String,
    target: String,
    request_event_ref: String,
    response_event_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer_service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer_service_resolution: Option<ServiceResolutionCarrier>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct DirectRepairFixtureBinding {
    pair_key: Hash,
    binding_digest: Hash,
    participants_unordered: Vec<String>,
    realm_id: String,
    main_strand_id: String,
    binding_event_ref: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct DirectRepairFixtureInstallRequest {
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    events: Vec<Event>,
    binding: DirectRepairFixtureBinding,
    contacts: Vec<DirectRepairFixtureContact>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DirectRepairFixtureInstallOutcome {
    accepted_event_count: usize,
    projected_event_count: usize,
    accepted_contact_count: usize,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct DirectRepairMessagesRequest {
    recipient: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DirectRepairMessageView {
    device_id: String,
    position: i64,
    #[salvo(schema(value_type = serde_json::Value))]
    content: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DirectRepairMessagesOutcome {
    messages: Vec<DirectRepairMessageView>,
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.conformance.direct_repair.install",
    tags("conformance")
)]
pub async fn install(
    depot: &mut Depot,
    body: JsonBody<DirectRepairFixtureInstallRequest>,
) -> JsonResult<DirectRepairFixtureInstallOutcome> {
    super::ensure_enabled()?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.events.len() < 5 || body.events.len() > 16 {
        return Err(AppError::param_invalid(
            "direct repair fixture requires founding, activation, and rejoin Events",
        ));
    }
    if body.binding.participants_unordered.len() != 2 || body.contacts.len() != 2 {
        return Err(AppError::param_invalid(
            "direct repair fixture requires one exact pair and two directional Contacts",
        ));
    }
    let required = [
        EventKind::RealmCreate,
        EventKind::MemberState,
        EventKind::StrandCreate,
        EventKind::DirectConversationMlsGenerationActivate,
    ];
    if required
        .iter()
        .any(|kind| !body.events.iter().any(|event| &event.kind == kind))
    {
        return Err(AppError::param_invalid(
            "direct repair fixture is missing a canonical projected Event",
        ));
    }
    if body
        .events
        .iter()
        .any(|event| event.realm_id.as_str() != body.binding.realm_id)
    {
        return Err(AppError::param_invalid(
            "direct repair fixture Events must share the bound Realm",
        ));
    }

    let received_at = chrono::Utc::now();
    let mut projected = 0;
    for event in &body.events {
        let event_digest = event
            .event_digest()
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        let envelope = serde_json::to_value(event)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        let canonical_bytes = arkret_canonical::canonical_json_bytes(&envelope)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        state
            .event_queries()
            .store_canonical_event(CanonicalEventRecord {
                event_id: event.event_id.to_string(),
                actor_id: event.actor_id.to_string(),
                actor_seq: event.actor_seq,
                realm_id: Some(event.realm_id.to_string()),
                kind: event.kind.as_str().to_owned(),
                schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
                canonical_digest: event_digest,
                canonical_bytes,
                envelope,
                received_at,
            })
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;

        let is_repair_rejoin = event.kind == EventKind::MemberState
            && event.authorization_ref.as_ref().map(|value| value.as_str())
                == Some(arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_REPAIR_V1);
        if required.contains(&event.kind) && !is_repair_rejoin {
            let operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
                OperationId::new(arkret_identifiers::new_prefixed_uuid7("ak:operation:"))
                    .map_err(|error| AppError::internal(error.to_string()))?,
                OperationKind::Create,
                None,
                event,
            )
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
            let writes = state
                .projections()
                .project_accepted_cell_writes(event)
                .map_err(AppError::param_invalid)?;
            if let ProjectionEffectView::Rejected { reason } =
                state
                    .projections()
                    .apply_projected(&operation, &writes, state.hlc())
            {
                return Err(AppError::param_invalid(format!(
                    "direct repair fixture projection rejected: {reason}"
                )));
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
                    payload: Value::Object(event.payload.clone().into_iter().collect()),
                    created_at: event.created_at,
                    received_at,
                })
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            projected += 1;
        }
    }

    state.contacts().install_direct_binding(
        body.binding.pair_key.to_string(),
        body.binding.binding_digest.to_string(),
        DirectConversationCoordinatesRecord {
            participants_unordered: body.binding.participants_unordered,
            realm_id: body.binding.realm_id,
            main_strand_id: body.binding.main_strand_id,
            created_at: received_at,
        },
        DirectConversationEndorsement {
            actor_id: body.events[0].actor_id.to_string(),
            binding_event_ref: body.binding.binding_event_ref,
        },
    );

    for contact in body.contacts {
        state
            .contacts()
            .save_contact(ContactRecord {
                requester: contact.requester,
                target: contact.target,
                contact_round_id: Some(arkret_canonical::sha256_digest(
                    arkret_identifiers::new_prefixed_uuid7(""),
                )),
                version: Some(1),
                granted_to_target_scopes: vec!["direct_message".to_owned()],
                granted_to_requester_scopes: vec!["direct_message".to_owned()],
                status: "accepted".to_owned(),
                request_event_ref: Some(contact.request_event_ref),
                request_receipts: Vec::new(),
                request_mirror_receipts: Vec::new(),
                contact_round_evidence: None,
                contact_round_evidence_history: Vec::new(),
                control_outcomes: Vec::new(),
                response_event_ref: Some(contact.response_event_ref),
                tombstone_event_ref: None,
                message: None,
                peer_service_id: contact.peer_service_id,
                peer_service_resolution: contact
                    .peer_service_resolution
                    .map(|carrier| serde_json::to_value(carrier).expect("typed carrier encodes")),
                created_at: received_at,
                updated_at: received_at,
            })
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    json_ok(DirectRepairFixtureInstallOutcome {
        accepted_event_count: body.events.len(),
        projected_event_count: projected,
        accepted_contact_count: 2,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.conformance.direct_repair.messages",
    tags("conformance")
)]
pub async fn messages(
    depot: &mut Depot,
    body: JsonBody<DirectRepairMessagesRequest>,
) -> JsonResult<DirectRepairMessagesOutcome> {
    super::ensure_enabled()?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let mut observed_messages = Vec::new();
    for device in state
        .identities()
        .devices_for_actor(&body.recipient)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        for message in state
            .deliveries()
            .device_messages_after(&body.recipient, &device.device_id, 0)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            observed_messages.push(DirectRepairMessageView {
                device_id: device.device_id.clone(),
                position: message.position,
                content: message.content,
            });
        }
    }
    observed_messages.sort_by(|left, right| {
        left.device_id
            .cmp(&right.device_id)
            .then_with(|| left.position.cmp(&right.position))
    });
    json_ok(DirectRepairMessagesOutcome {
        messages: observed_messages,
    })
}
