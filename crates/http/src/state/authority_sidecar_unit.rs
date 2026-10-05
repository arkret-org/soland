//! Producer-guarded Sidecar create/attach commits as one accepted batch.

use arkret_wire::{Event, EventAdmissionSubmission};
use soland_services::identity::SessionIdentityState;
use soland_services::{ServiceError, ServiceResult};

use super::AppState;

pub(crate) async fn commit_sidecar_ensure_unit(
    state: &AppState,
    session: &SessionIdentityState,
    create: Option<Event>,
    attach: Event,
) -> ServiceResult<()> {
    let mut source_events = Vec::new();
    if let Some(create) = create {
        source_events.push(create);
    }
    source_events.push(attach);
    let committed_at = chrono::Utc::now();
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let mut commands = Vec::new();
    for event in source_events {
        let producer = super::authority_producer_validation::verify_self_event_producer(
            state, session, &event,
        )
        .await?;
        let transaction = state
            .authority_commits()
            .prepare_self_event_transaction(
                &event,
                &state.service_core_id(),
                method.clone(),
                state.notary_signing_key().as_ref(),
                committed_at,
            )
            .await?;
        let envelope = serde_json::to_value(&event)
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let canonical_bytes = arkret_canonical::canonical_json_bytes(
            &event
                .digest_payload()
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let canonical_digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let record = soland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            realm_id: Some(event.realm_id.to_string()),
            kind: event.kind.as_str().to_owned(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest,
            canonical_bytes,
            envelope,
            received_at: committed_at,
        };
        commands.push(soland_services::events::CommitAcceptedEventCommand {
            authority_commit: transaction,
            self_producer_guard: Some(producer),
            applet_producer_guard: None,
            widget_token_gate: None,
            forwarded_producer_evidence: None,
            forwarded_agent_producer: None,
            agent_deployment_ceiling: arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
            event: record,
            parent_membership_admission: None,
            contact_projection: None,
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: vec![soland_services::events::ProjectedEvent {
                event_id: event.event_id.to_string(),
                realm_id: event.realm_id.to_string(),
                event_kind: event.kind.clone(),
                operation_kind: "create".into(),
                operation_id: None,
                sender: Some(event.actor_id.to_string()),
                payload: serde_json::to_value(&event.payload)
                    .map_err(|error| ServiceError::Internal(error.to_string()))?,
                created_at: event.created_at,
                received_at: committed_at,
            }],
            idempotency: None,
            deliveries: Vec::new(),
            realm_fanout_source: Some(EventAdmissionSubmission::new(event)),
        });
    }
    state
        .events()
        .commit_accepted_event_batch(soland_services::events::CommitAcceptedEventBatchCommand {
            events: commands,
            franking_replay_nonce: None,
            realm_organization_proof: None,
            invite_claim_proof: None,
            event_approvals: None,
            applet_record: None,
            applet_authoring_preview: None,
            agent_membership_cascade: None,
        })
        .await?;
    Ok(())
}
