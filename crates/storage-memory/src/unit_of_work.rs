use async_trait::async_trait;
use soland_storage::{
    EventBatchCommitRequest, EventCommitOutcome, EventCommitRequest, EventCommitUnitOfWork,
    PersistenceError, PersistenceResult, ids,
};

use crate::events::quarantine_memory_event;
#[cfg(feature = "fault-injection")]
use crate::{FaultPoint, FaultTiming};
use crate::{MemoryDeviceRevocationState, SolandMemoryPersistenceStore};

fn stage_agent_membership_cascade(
    records: &mut std::collections::BTreeMap<
        String,
        arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupPendingRecord,
    >,
    transition: Option<&soland_storage::AgentMembershipCascadeCommit>,
    events: &[EventCommitRequest],
) -> PersistenceResult<()> {
    use arkret_models_collaboration::governance::agent_membership_cascade::{
        AgentCleanupStatus, MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS,
    };
    use soland_storage::AgentMembershipCascadeCommit;

    let Some(transition) = transition else {
        return Ok(());
    };
    let event_ids = events
        .iter()
        .map(|request| request.event.event_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    match transition {
        AgentMembershipCascadeCommit::AtomicSelfLeave {
            controller_transition_event_id,
            agent_transition_event_ids,
            expected_agent_ids,
        } => {
            if agent_transition_event_ids.is_empty()
                || agent_transition_event_ids.len() > MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: invalid atomic Agent cleanup cardinality".to_owned(),
                ));
            }
            let mut expected = agent_transition_event_ids
                .iter()
                .map(arkret_wire::EventId::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            if expected.len() != agent_transition_event_ids.len()
                || !expected.insert(controller_transition_event_id.as_str())
                || expected != event_ids
                || expected_agent_ids.len() != agent_transition_event_ids.len()
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: atomic Agent cascade Event set mismatch".to_owned(),
                ));
            }
            let submitted_agent_ids = events
                .iter()
                .filter(|request| request.event.event_id != controller_transition_event_id.as_str())
                .map(|request| request.event.actor_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let expected_agent_ids = expected_agent_ids
                .iter()
                .map(arkret_wire::DidCoreId::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            if submitted_agent_ids != expected_agent_ids {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: atomic Agent cascade actor set mismatch".to_owned(),
                ));
            }
        }
        AgentMembershipCascadeCommit::EmergencyTerminal { record } => {
            record.validate().map_err(|error| {
                PersistenceError::Conflict(format!(
                    "schema_violation: invalid Agent cleanup intent: {error}"
                ))
            })?;
            if event_ids
                != std::collections::BTreeSet::from([record.controller_terminal_event_id.as_str()])
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: emergency terminal Event set mismatch".to_owned(),
                ));
            }
            let terminal = events
                .first()
                .expect("validated singleton terminal Event set");
            let typed =
                serde_json::from_value::<arkret_wire::Event>(terminal.event.envelope.clone())
                    .map_err(|error| {
                        PersistenceError::Conflict(format!(
                            "schema_violation: emergency terminal Event is invalid: {error}"
                        ))
                    })?;
            let initiator = typed.executed_by.as_ref().unwrap_or(&typed.actor_id);
            if terminal.event.actor_id != record.controller_authority.principal_id.as_str()
                || terminal.event.realm_id.as_deref() != Some(record.realm_id.as_str())
                || terminal.event.canonical_digest
                    != record.controller_terminal_event_digest.as_str()
                || typed.principal_server_id != record.controller_authority.principal_server_id
                || initiator != &record.initiator_authority.principal_id
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: emergency terminal Event does not bind cleanup intent"
                        .to_owned(),
                ));
            }
            match records.get(record.cleanup_intent_digest.as_str()) {
                Some(existing) if existing == record => {}
                Some(_) => {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: cleanup intent digest names different content"
                            .to_owned(),
                    ));
                }
                None => {
                    if records.values().any(|existing| {
                        existing.controller_terminal_event_id == record.controller_terminal_event_id
                    }) {
                        return Err(PersistenceError::Conflict(
                            "duplicate_conflict: terminal Event names a different cleanup intent"
                                .to_owned(),
                        ));
                    }
                    records.insert(record.cleanup_intent_digest.to_string(), record.clone());
                }
            }
        }
        AgentMembershipCascadeCommit::EmergencyCleanup {
            cleanup_intent_digest,
            controller_terminal_event_id,
            agent_transition_event_ids,
            completed_at,
        } => {
            let record = records
                .get_mut(cleanup_intent_digest.as_str())
                .ok_or_else(|| {
                    PersistenceError::Conflict(
                        "failed_precondition: Agent cleanup intent is unavailable".to_owned(),
                    )
                })?;
            if record.controller_terminal_event_id != *controller_terminal_event_id
                || event_ids
                    != agent_transition_event_ids
                        .iter()
                        .map(arkret_wire::EventId::as_str)
                        .collect()
                || agent_transition_event_ids.len() != record.expected_agent_ids.len()
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: emergency Agent cleanup does not match frozen intent"
                        .to_owned(),
                ));
            }
            let actor_ids = events
                .iter()
                .map(|request| request.event.actor_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let expected_actor_ids = record
                .expected_agent_ids
                .iter()
                .map(arkret_wire::DidCoreId::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            if actor_ids != expected_actor_ids {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: emergency Agent cleanup actor set mismatch".to_owned(),
                ));
            }
            if record.status == AgentCleanupStatus::AgentCleanupCompleted {
                if record.agent_transition_event_ids.as_ref() != Some(agent_transition_event_ids) {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: completed Agent cleanup replay differs".to_owned(),
                    ));
                }
                return Ok(());
            }
            record.status = AgentCleanupStatus::AgentCleanupCompleted;
            record.completed_at = Some(*completed_at);
            record.agent_transition_event_ids = Some(agent_transition_event_ids.clone());
            record.validate().map_err(|error| {
                PersistenceError::Conflict(format!(
                    "schema_violation: completed Agent cleanup is invalid: {error}"
                ))
            })?;
        }
    }
    Ok(())
}

fn stage_control_proposal_ack(
    staged: &mut std::collections::BTreeMap<String, arkret_wire::ControlProposalAck>,
    request: &EventCommitRequest,
) -> PersistenceResult<()> {
    let event: arkret_wire::Event = serde_json::from_value(request.event.envelope.clone())
        .map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: accepted Event envelope is not canonical wire: {error}"
            ))
        })?;
    // Control/Data routing is defined by the typed Event plane. In particular,
    // a closed genesis anchor is a basis-free Control Move, while a DataEvent
    // carries the data-plane seal/auth context. Do not infer the plane from
    // `seal_basis` or from the presence of a Control Proposal Ack.
    let is_control_move =
        event.kind.is_reducer_input() && event.seal_ref.is_none() && event.auth_context.is_none();
    if !is_control_move {
        if request.control_proposal_ingress.is_some() {
            return Err(PersistenceError::Conflict(
                "schema_violation: non-Control Event cannot carry Control Proposal authority"
                    .to_owned(),
            ));
        }
        return Ok(());
    }
    let event_digest = event
        .event_digest_with_digest_suite(request.event.digest_suite)
        .map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: accepted Control Move digest failed: {error}"
            ))
        })?;
    if event_digest != request.event.canonical_digest {
        return Err(PersistenceError::Conflict(
            "schema_violation: canonical digest differs from Control Move digest".to_owned(),
        ));
    }
    let Some(ingress) = request.control_proposal_ingress.as_ref() else {
        return Err(PersistenceError::Conflict(
            "schema_violation: accepted Control Move is missing its durable ingress classification"
                .to_owned(),
        ));
    };
    let ack = match ingress {
        arkret_state::state::store::ControlProposalIngress::AcklessSelfPrincipal(_) => {
            if event.kind == arkret_wire::EventKind::DeviceRevoke
                || !soland_storage::has_self_principal_pcr_device_authorized_shape(
                    &event,
                    request.event.digest_suite,
                )
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: invalid self-principal PCR device-authorized Control Move"
                        .to_owned(),
                ));
            }
            return Ok(());
        }
        arkret_state::state::store::ControlProposalIngress::AckRequired(ack) => ack,
    };
    ack.validate_protocol_bounds().map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: invalid Control Proposal Ack: {error}"
        ))
    })?;
    if ack.proposal_digest.as_str() != event_digest || ack.realm_id != event.realm_id {
        return Err(PersistenceError::Conflict(
            "schema_violation: Control Proposal Ack does not bind Control Move".to_owned(),
        ));
    }
    if let Some(existing) = staged.get(&request.event.event_id)
        && existing != ack
    {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: Control Move has a different Control Proposal Ack".to_owned(),
        ));
    }
    staged.insert(request.event.event_id.clone(), ack.clone());
    Ok(())
}

fn stage_device_revocation(
    state: &mut MemoryDeviceRevocationState,
    request: &EventCommitRequest,
) -> PersistenceResult<bool> {
    if let Some(selector) = request.device_revocation_gate.as_ref() {
        state.status(selector).ensure_allowed()?;
    }
    let is_revoke = arkret_wire::EventKind::DeviceRevoke == request.event.kind;
    let Some(transition) = request.device_revocation_transition.as_ref() else {
        return if is_revoke {
            Err(PersistenceError::Conflict(
                "schema_violation: accepted device revoke is missing derived transition".to_owned(),
            ))
        } else {
            Ok(false)
        };
    };
    if !is_revoke
        || transition.proposal_event_id != request.event.event_id
        || transition.proposal_digest != request.event.canonical_digest
        || request
            .control_proposal_ingress
            .as_ref()
            .and_then(arkret_state::state::store::ControlProposalIngress::ack)
            != Some(&transition.control_proposal_ack)
    {
        return Err(PersistenceError::Conflict(
            "schema_violation: device revocation transition does not bind Event and Ack".to_owned(),
        ));
    }
    state.stage_transition(transition, chrono::Utc::now())
}

fn stage_canonical_event(
    staged: &mut std::collections::BTreeMap<String, soland_storage::CanonicalEventRecord>,
    event: soland_storage::CanonicalEventRecord,
) -> PersistenceResult<()> {
    ids::validated_event_identity_parts_for_suite(
        &event.event_id,
        &event.canonical_digest,
        &event.canonical_bytes,
        event.digest_suite,
    )?;
    if let Some(existing) = staged.get(&event.event_id) {
        let reason = if existing.canonical_bytes == event.canonical_bytes {
            "duplicate_conflict"
        } else {
            "event_hash_collision"
        };
        return Err(PersistenceError::Conflict(reason.to_owned()));
    }
    staged.insert(event.event_id.clone(), event);
    Ok(())
}

fn stage_projection_event(
    staged: &mut Vec<soland_storage::ProjectionEventRecord>,
    projection: soland_storage::ProjectionEventRecord,
) -> PersistenceResult<bool> {
    if let Some(existing) = staged
        .iter()
        .find(|existing| existing.event_id == projection.event_id)
    {
        if existing.realm_id == projection.realm_id
            && existing.event_kind == projection.event_kind
            && existing.operation_kind == projection.operation_kind
            && existing.operation_id == projection.operation_id
            && existing.sender == projection.sender
            && existing.payload == projection.payload
            && existing.created_at == projection.created_at
            && existing.received_at == projection.received_at
        {
            return Ok(false);
        }
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: projection differs for Event identity".to_owned(),
        ));
    }
    staged.push(projection);
    Ok(true)
}

fn stage_device_pairing_authorization(
    staged: &mut std::collections::BTreeMap<String, soland_storage::DevicePairingRecord>,
    event_id: &str,
    commit: Option<&soland_storage::DevicePairingAuthorizationCommit>,
) -> PersistenceResult<()> {
    let Some(commit) = commit else {
        return Ok(());
    };
    if commit.authorized_event_ref != event_id {
        return Err(PersistenceError::Conflict(
            "schema_violation: device pairing authorization does not bind committed Event"
                .to_owned(),
        ));
    }
    let commit_new_device_pubkey =
        serde_json::to_value(&commit.new_device_pubkey).map_err(|error| {
            PersistenceError::Internal(format!(
                "cannot encode device pairing authorization public key: {error}"
            ))
        })?;
    let pairing = staged
        .get_mut(&commit.device_pairing_request_id)
        .ok_or_else(|| PersistenceError::Conflict("device_pairing_not_found".to_owned()))?;
    if pairing.state != "pending_authorization"
        || pairing.expires_at <= commit.changed_at
        || pairing.pairing_code != commit.pairing_code
        || pairing.new_device_pubkey != commit_new_device_pubkey
    {
        return Err(PersistenceError::Conflict(
            "device_pairing_not_found".to_owned(),
        ));
    }
    pairing.state = "authorized".to_owned();
    pairing.device_id = Some(commit.device_id.clone());
    pairing.authorized_by_actor_id = Some(commit.authorized_by_actor_id.clone());
    pairing.authorized_event_ref = Some(commit.authorized_event_ref.clone());
    Ok(())
}

fn stage_contact_projection(
    staged: &mut std::collections::BTreeMap<
        soland_storage::ContactKey,
        soland_storage::ContactRecord,
    >,
    commit: Option<&soland_storage::ContactProjectionCommit>,
) -> PersistenceResult<()> {
    let Some(commit) = commit else {
        return Ok(());
    };
    let key = (
        commit.record.requester.clone(),
        commit.record.target.clone(),
    );
    let reverse_key = (key.1.clone(), key.0.clone());
    let current_key = if staged.contains_key(&key) {
        key.clone()
    } else {
        reverse_key
    };
    match (staged.get(&current_key), commit.expected_updated_at) {
        (None, None) => {}
        (Some(current), Some(expected))
            if current.updated_at == expected && commit.record.updated_at > expected => {}
        _ => {
            return Err(PersistenceError::Conflict(commit.conflict_code.clone()));
        }
    }
    if current_key != key {
        staged.remove(&current_key);
    }
    staged.insert(key, commit.record.clone());
    Ok(())
}

#[async_trait]
impl EventCommitUnitOfWork for SolandMemoryPersistenceStore {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::EventCommit, FaultTiming::Before)?;
        // Settle seal-derived revocation state first so the staged gate
        // check below observes `Revoked` exactly like the Postgres JOIN does.
        self.device_revocations.settle_from_control_events();
        let mut events = self.events.data.lock();
        let mut quarantined = self.events.quarantined.lock();
        let mut collision_variants = self.events.collision_variants.lock();
        let mut control_proposal_acks = self.events.control_proposal_acks.lock();
        let mut projections = self.projection_events.data.lock();
        let mut idempotency = self.idempotency_keys.data.lock();
        let mut event_outbox_ids = self.events.event_outbox_ids.lock();
        let mut outbox = self.federation_outbox.data.lock();
        let mut pairings = self.device_pairings.data.lock();
        let mut contacts = self.contacts.data.lock();
        let mut invite_policies = self.invite_receive_policies.data.lock();
        let mut device_revocations = self.device_revocations.state.lock();

        let mut staged_events = events.clone();
        let mut staged_control_proposal_acks = control_proposal_acks.clone();
        let mut staged_projections = projections.clone();
        let mut staged_idempotency = idempotency.clone();
        let mut staged_outbox = outbox.clone();
        let mut staged_event_outbox_ids = event_outbox_ids.clone();
        let mut staged_pairings = pairings.clone();
        let mut staged_contacts = contacts.clone();
        let mut staged_invite_policies = invite_policies.clone();
        let mut staged_device_revocations = device_revocations.clone();

        stage_device_pairing_authorization(
            &mut staged_pairings,
            &request.event.event_id,
            request.device_pairing_authorization.as_ref(),
        )?;

        ids::validated_event_identity_parts_for_suite(
            &request.event.event_id,
            &request.event.canonical_digest,
            &request.event.canonical_bytes,
            request.event.digest_suite,
        )?;
        if quarantined.contains_key(&request.event.event_id) {
            if collision_variants
                .get(&request.event.event_id)
                .is_some_and(|variants| {
                    variants
                        .iter()
                        .any(|variant| variant.canonical_bytes == request.event.canonical_bytes)
                })
            {
                return Err(PersistenceError::Conflict(
                    "event_hash_collision".to_owned(),
                ));
            }
            quarantine_memory_event(
                &mut events,
                &mut quarantined,
                &mut collision_variants,
                &mut projections,
                &event_outbox_ids,
                &mut outbox,
                request.event,
            );
            return Err(PersistenceError::Conflict(
                "event_hash_collision".to_owned(),
            ));
        }
        let revocation_inserted =
            stage_device_revocation(&mut staged_device_revocations, &request)?;
        if let Some(existing) = staged_events.get(&request.event.event_id) {
            if existing.canonical_bytes != request.event.canonical_bytes {
                quarantine_memory_event(
                    &mut events,
                    &mut quarantined,
                    &mut collision_variants,
                    &mut projections,
                    &event_outbox_ids,
                    &mut outbox,
                    request.event,
                );
                return Err(PersistenceError::Conflict(
                    "event_hash_collision".to_owned(),
                ));
            }
            if revocation_inserted {
                return Err(PersistenceError::Conflict(
                    "schema_violation: replayed revoke Event lacks its atomic target".to_owned(),
                ));
            }
            *pairings = staged_pairings;
            return Ok(EventCommitOutcome {
                event_inserted: false,
                projections_inserted: 0,
                outbox_inserted: 0,
            });
        }
        if arkret_wire::EventKind::RealmCreate == request.event.kind
            && request.event.realm_id.is_some()
            && staged_events.values().any(|existing| {
                arkret_wire::EventKind::RealmCreate == existing.kind
                    && existing.realm_id == request.event.realm_id
            })
        {
            return Err(PersistenceError::Conflict(
                "realm_already_exists".to_owned(),
            ));
        }
        soland_storage::validate_actor_scope_commit(staged_events.values(), &request.event)?;
        stage_control_proposal_ack(&mut staged_control_proposal_acks, &request)?;
        stage_contact_projection(&mut staged_contacts, request.contact_projection.as_ref())?;
        if let Some(policy) = request
            .contact_projection
            .as_ref()
            .and_then(|commit| commit.invite_policy.as_ref())
        {
            staged_invite_policies.insert(policy.subject_id.to_string(), policy.clone());
        }
        let event_id = request.event.event_id.clone();
        stage_canonical_event(&mut staged_events, request.event)?;

        let mut projections_inserted = 0;
        for projection in request.projections {
            ids::parse_event_id(&projection.event_id).ok_or_else(|| {
                PersistenceError::SchemaViolation(format!(
                    "malformed canonical Event id: {:?}",
                    projection.event_id
                ))
            })?;
            arkret_wire::RealmId::new(projection.realm_id.clone()).map_err(|_| {
                PersistenceError::SchemaViolation(format!(
                    "malformed Realm id: {:?}",
                    projection.realm_id
                ))
            })?;
            if let Some(operation_id) = projection.operation_id.as_deref() {
                ids::typed_uuid_part_or_schema_violation(operation_id)?;
            }
            if stage_projection_event(&mut staged_projections, projection)? {
                projections_inserted += 1;
            }
        }

        if let Some(record) = request.idempotency {
            let key = (record.principal_id.clone(), record.idempotency_key.clone());
            if staged_idempotency.contains_key(&key) {
                return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
            }
            staged_idempotency.insert(key, record);
        }

        let mut outbox_inserted = 0;

        for record in request.outbox {
            record.validate_shape().map_err(|error| {
                PersistenceError::Conflict(format!("schema_violation: {error}"))
            })?;
            let existing_id = staged_outbox.values().find_map(|existing| {
                (existing.peer_did == record.peer_did
                    && existing.idempotency_key == record.idempotency_key)
                    .then(|| existing.id.clone())
            });
            let outbox_id = if let Some(existing_id) = existing_id {
                existing_id
            } else {
                if staged_outbox.contains_key(&record.id) {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
                }
                let outbox_id = record.id.clone();
                staged_outbox.insert(outbox_id.clone(), record);
                outbox_inserted += 1;
                outbox_id
            };
            staged_event_outbox_ids
                .entry(event_id.clone())
                .or_default()
                .insert(outbox_id);
        }

        *events = staged_events;
        *control_proposal_acks = staged_control_proposal_acks;
        *projections = staged_projections;
        *idempotency = staged_idempotency;
        *outbox = staged_outbox;
        *event_outbox_ids = staged_event_outbox_ids;
        *pairings = staged_pairings;
        *contacts = staged_contacts;
        *invite_policies = staged_invite_policies;
        *device_revocations = staged_device_revocations;

        let outcome = EventCommitOutcome {
            event_inserted: true,
            projections_inserted,
            outbox_inserted,
        };
        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::EventCommit, FaultTiming::After)?;
        Ok(outcome)
    }

    async fn commit_event_batch(
        &self,
        request: EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::EventCommit, FaultTiming::Before)?;
        if request.events.is_empty() {
            return Err(PersistenceError::Conflict(
                "schema_violation: empty event batch".to_owned(),
            ));
        }
        // Same seal-derived settlement as `commit_event` above.
        self.device_revocations.settle_from_control_events();
        let mut events = self.events.data.lock();
        let mut quarantined = self.events.quarantined.lock();
        let mut collision_variants = self.events.collision_variants.lock();
        let mut control_proposal_acks = self.events.control_proposal_acks.lock();
        let mut projections = self.projection_events.data.lock();
        let mut idempotency = self.idempotency_keys.data.lock();
        let mut event_outbox_ids = self.events.event_outbox_ids.lock();
        let mut outbox = self.federation_outbox.data.lock();
        let mut applets = self.applets.records.lock();
        let mut pairings = self.device_pairings.data.lock();
        let mut contacts = self.contacts.data.lock();
        let mut invite_policies = self.invite_receive_policies.data.lock();
        let mut device_revocations = self.device_revocations.state.lock();
        let mut agent_membership_cascades = self.agent_membership_cascades.data.lock();

        let mut staged_events = events.clone();
        let mut staged_control_proposal_acks = control_proposal_acks.clone();
        let mut staged_projections = projections.clone();
        let mut staged_idempotency = idempotency.clone();
        let mut staged_outbox = outbox.clone();
        let mut staged_event_outbox_ids = event_outbox_ids.clone();
        let mut staged_applets = applets.clone();
        let mut staged_pairings = pairings.clone();
        let mut staged_contacts = contacts.clone();
        let mut staged_invite_policies = invite_policies.clone();
        let mut staged_device_revocations = device_revocations.clone();
        let mut staged_agent_membership_cascades = agent_membership_cascades.clone();
        let mut event_inserted = false;
        let mut projections_inserted = 0;
        let mut outbox_inserted = 0;

        stage_agent_membership_cascade(
            &mut staged_agent_membership_cascades,
            request.agent_membership_cascade.as_ref(),
            &request.events,
        )?;

        for event_request in request.events {
            stage_device_pairing_authorization(
                &mut staged_pairings,
                &event_request.event.event_id,
                event_request.device_pairing_authorization.as_ref(),
            )?;
            ids::validated_event_identity_parts_for_suite(
                &event_request.event.event_id,
                &event_request.event.canonical_digest,
                &event_request.event.canonical_bytes,
                event_request.event.digest_suite,
            )?;
            if quarantined.contains_key(&event_request.event.event_id) {
                if collision_variants
                    .get(&event_request.event.event_id)
                    .is_some_and(|variants| {
                        variants.iter().any(|variant| {
                            variant.canonical_bytes == event_request.event.canonical_bytes
                        })
                    })
                {
                    return Err(PersistenceError::Conflict(
                        "event_hash_collision".to_owned(),
                    ));
                }
                quarantine_memory_event(
                    &mut events,
                    &mut quarantined,
                    &mut collision_variants,
                    &mut projections,
                    &event_outbox_ids,
                    &mut outbox,
                    event_request.event,
                );
                return Err(PersistenceError::Conflict(
                    "event_hash_collision".to_owned(),
                ));
            }
            let revocation_inserted =
                stage_device_revocation(&mut staged_device_revocations, &event_request)?;
            if let Some(existing) = staged_events.get(&event_request.event.event_id) {
                if existing.canonical_bytes != event_request.event.canonical_bytes {
                    if !events.contains_key(&event_request.event.event_id) {
                        events.insert(event_request.event.event_id.clone(), existing.clone());
                    }
                    quarantine_memory_event(
                        &mut events,
                        &mut quarantined,
                        &mut collision_variants,
                        &mut projections,
                        &event_outbox_ids,
                        &mut outbox,
                        event_request.event,
                    );
                    return Err(PersistenceError::Conflict(
                        "event_hash_collision".to_owned(),
                    ));
                }
                if revocation_inserted {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: replayed revoke Event lacks its atomic target"
                            .to_owned(),
                    ));
                }
                continue;
            }
            if arkret_wire::EventKind::RealmCreate == event_request.event.kind
                && event_request.event.realm_id.is_some()
                && staged_events.values().any(|existing| {
                    arkret_wire::EventKind::RealmCreate == existing.kind
                        && existing.realm_id == event_request.event.realm_id
                })
            {
                return Err(PersistenceError::Conflict(
                    "realm_already_exists".to_owned(),
                ));
            }
            soland_storage::validate_actor_scope_commit(
                staged_events.values(),
                &event_request.event,
            )?;
            stage_control_proposal_ack(&mut staged_control_proposal_acks, &event_request)?;
            let event_id = event_request.event.event_id.clone();
            stage_contact_projection(
                &mut staged_contacts,
                event_request.contact_projection.as_ref(),
            )?;
            if let Some(policy) = event_request
                .contact_projection
                .as_ref()
                .and_then(|commit| commit.invite_policy.as_ref())
            {
                staged_invite_policies.insert(policy.subject_id.to_string(), policy.clone());
            }
            stage_canonical_event(&mut staged_events, event_request.event)?;
            event_inserted = true;

            for projection in event_request.projections {
                ids::parse_event_id(&projection.event_id).ok_or_else(|| {
                    PersistenceError::SchemaViolation(format!(
                        "malformed canonical Event id: {:?}",
                        projection.event_id
                    ))
                })?;
                arkret_wire::RealmId::new(projection.realm_id.clone()).map_err(|_| {
                    PersistenceError::SchemaViolation(format!(
                        "malformed Realm id: {:?}",
                        projection.realm_id
                    ))
                })?;
                if let Some(operation_id) = projection.operation_id.as_deref() {
                    ids::typed_uuid_part_or_schema_violation(operation_id)?;
                }
                if stage_projection_event(&mut staged_projections, projection)? {
                    projections_inserted += 1;
                }
            }
            if let Some(record) = event_request.idempotency {
                let key = (record.principal_id.clone(), record.idempotency_key.clone());
                if staged_idempotency.contains_key(&key) {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
                }
                staged_idempotency.insert(key, record);
            }
            for record in event_request.outbox {
                record.validate_shape().map_err(|error| {
                    PersistenceError::Conflict(format!("schema_violation: {error}"))
                })?;
                let existing_id = staged_outbox.values().find_map(|existing| {
                    (existing.peer_did == record.peer_did
                        && existing.idempotency_key == record.idempotency_key)
                        .then(|| existing.id.clone())
                });
                let already_present = existing_id.is_some();
                let outbox_id = existing_id.unwrap_or_else(|| record.id.clone());
                staged_event_outbox_ids
                    .entry(event_id.clone())
                    .or_default()
                    .insert(outbox_id.clone());
                if !already_present {
                    if staged_outbox.contains_key(&record.id) {
                        return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
                    }
                    staged_outbox.insert(record.id.clone(), record);
                    outbox_inserted += 1;
                }
            }
        }

        if let Some(mutation) = request.applet_ghosts {
            let record = staged_applets
                .get_mut(&mutation.applet_id)
                .ok_or_else(|| PersistenceError::NotFound("applet registration".to_owned()))?;
            let active = record
                .get("revoked_at")
                .is_none_or(serde_json::Value::is_null)
                && matches!(
                    record.get("status").and_then(serde_json::Value::as_str),
                    Some("installed" | "partially_installed")
                );
            if !active {
                return Err(PersistenceError::Conflict("applet_revoked".to_owned()));
            }
            let record = record.as_object_mut().ok_or_else(|| {
                PersistenceError::Internal("applet record is not an object".to_owned())
            })?;
            let ghosts = record
                .entry("ghosts")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| {
                    PersistenceError::Internal("applet ghosts is not an array".to_owned())
                })?;
            let duplicate = ghosts.iter().any(|existing| {
                existing.get("external_id") == mutation.ghost.get("external_id")
                    || existing.get("ghost_actor_id") == mutation.ghost.get("ghost_actor_id")
            });
            if duplicate {
                return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
            }
            ghosts.push(mutation.ghost);
        }

        *events = staged_events;
        *control_proposal_acks = staged_control_proposal_acks;
        *projections = staged_projections;
        *idempotency = staged_idempotency;
        *outbox = staged_outbox;
        *event_outbox_ids = staged_event_outbox_ids;
        *applets = staged_applets;
        *pairings = staged_pairings;
        *contacts = staged_contacts;
        *invite_policies = staged_invite_policies;
        *device_revocations = staged_device_revocations;
        *agent_membership_cascades = staged_agent_membership_cascades;

        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::EventCommit, FaultTiming::After)?;
        Ok(EventCommitOutcome {
            event_inserted,
            projections_inserted,
            outbox_inserted,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use soland_storage::{
        AgentMembershipCascadeCommit, AgentMembershipCascadeStore, AppletGhostCommit,
        CanonicalEventRecord, DeviceMessageRecord, DeviceRevocationGateAction,
        DeviceRevocationGateLinearizationRequest, DeviceRevocationGateSelector,
        DeviceRevocationGateStatus, DeviceRevocationStore, DeviceRevocationTransition,
        EventBatchCommitRequest, EventCommitRequest, EventCommitUnitOfWork,
        EventProjectionStoreRegistry, IdempotencyRecord, PersistenceError, ProjectionEventRecord,
    };

    use super::stage_control_proposal_ack;
    use crate::SolandMemoryPersistenceStore;

    fn typed_id(prefix: &str) -> String {
        format!("{prefix}{}", uuid::Uuid::now_v7())
    }

    fn realm_id() -> String {
        let digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            uuid::Uuid::now_v7().as_bytes(),
        ))
        .unwrap();
        arkret_wire::RealmId::from_event_id(
            &arkret_wire::EventId::from_event_digest(&digest).unwrap(),
        )
        .to_string()
    }

    fn event_request(
        event_seed: String,
        realm_id: String,
        actor_id: &str,
        idempotency: Option<IdempotencyRecord>,
    ) -> EventCommitRequest {
        let event = arkret_wire::test_support::raw_event_at(
            "ak.test.data",
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(realm_id.clone()).unwrap(),
            },
            arkret_wire::project_full_id_to_core_id(
                &arkret_wire::DidFullId::new(actor_id.to_owned()).unwrap(),
            )
            .unwrap(),
            arkret_wire::project_full_id_to_core_id(
                &arkret_wire::DidFullId::new(actor_id.to_owned()).unwrap(),
            )
            .unwrap(),
            0,
            arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
            serde_json::json!({"seed": event_seed}),
            Utc::now(),
        )
        .unwrap();
        let event_id = event.event_id.as_str().to_owned();
        let canonical_digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let envelope = serde_json::to_value(&event).unwrap();
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        EventCommitRequest {
            device_pairing_authorization: None,
            contact_projection: None,
            event: CanonicalEventRecord {
                event_id: event_id.clone(),
                actor_id: actor_id.to_owned(),
                actor_seq: 0,
                realm_id: Some(realm_id),
                kind: "ak.test.data".to_owned(),
                schema_id: "arkret://events/profile/create/v1".to_owned(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                canonical_digest,
                canonical_bytes,
                envelope,
                received_at: Utc::now(),
            },
            control_proposal_ingress: None,
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: Vec::new(),
            idempotency,
            outbox: Vec::new(),
        }
    }

    fn cascade_event_request(
        seed: &str,
        realm_id: &str,
        actor_full_id: &str,
    ) -> EventCommitRequest {
        let mut request = event_request(seed.to_owned(), realm_id.to_owned(), actor_full_id, None);
        let event: arkret_wire::Event =
            serde_json::from_value(request.event.envelope.clone()).unwrap();
        request.event.actor_id = event.actor_id.to_string();
        request
    }

    fn emergency_terminal_request(realm_id: &str) -> EventCommitRequest {
        let mut request = cascade_event_request(
            "emergency-terminal",
            realm_id,
            "did:web:emergency-controller.example",
        );
        let mut event: arkret_wire::Event =
            serde_json::from_value(request.event.envelope.clone()).unwrap();
        event.principal_server_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap();
        event.executed_by =
            Some(arkret_wire::DidCoreId::new("ak:did_core:web:moderator.example").unwrap());
        event
            .refresh_content_bound_identity_with_digest_suite(request.event.digest_suite)
            .unwrap();
        request.event.event_id = event.event_id.to_string();
        request.event.canonical_digest = event
            .event_digest_with_digest_suite(request.event.digest_suite)
            .unwrap();
        request.event.canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        request.event.envelope = serde_json::to_value(event).unwrap();
        request
    }

    fn cleanup_record(
        controller: &EventCommitRequest,
        realm_id: &str,
        agent_ids: Vec<arkret_wire::DidCoreId>,
    ) -> arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupPendingRecord
    {
        use arkret_models_collaboration::governance::agent_membership_cascade::{
            AgentCleanupPendingRecord, AgentCleanupStatus, AgentMembershipCascadeSchema,
        };

        let accepted_at = controller.event.received_at;
        let mut record = AgentCleanupPendingRecord {
            schema: AgentMembershipCascadeSchema::V1,
            realm_id: arkret_wire::RealmId::new(realm_id.to_owned()).unwrap(),
            controller_authority: arkret_wire::PrincipalAuthorityKey {
                principal_id: arkret_wire::DidCoreId::new(controller.event.actor_id.clone())
                    .unwrap(),
                principal_server_id: arkret_wire::DidCoreId::new(
                    "ak:did_core:web:principal.example",
                )
                .unwrap(),
            },
            controller_membership_generation_ref: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x42; 32],
            ),
            initiator_authority: arkret_wire::PrincipalAuthorityKey {
                principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:moderator.example")
                    .unwrap(),
                principal_server_id: arkret_wire::DidCoreId::new(
                    "ak:did_core:web:principal.example",
                )
                .unwrap(),
            },
            controller_terminal_event_id: arkret_wire::EventId::new(
                controller.event.event_id.clone(),
            )
            .unwrap(),
            controller_terminal_event_digest: arkret_wire::Hash::new(
                controller.event.canonical_digest.clone(),
            )
            .unwrap(),
            expected_agent_ids: agent_ids,
            cleanup_intent_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            status: AgentCleanupStatus::AgentCleanupPending,
            accepted_at,
            cleanup_due_at: accepted_at + Duration::hours(1),
            completed_at: None,
            agent_transition_event_ids: None,
        };
        record.cleanup_intent_digest = record.expected_cleanup_intent_digest().unwrap();
        record.validate().unwrap();
        record
    }

    fn self_principal_pcr_control_request() -> EventCommitRequest {
        let actor_id = "did:web:alice.example";
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x31; 32],
        ))
        .into_string();
        let created_at = Utc::now();
        let mut event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::ContactRequested.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(realm_id.clone()).unwrap(),
            },
            arkret_wire::project_full_id_to_core_id(
                &arkret_wire::DidFullId::new(actor_id.to_owned()).unwrap(),
            )
            .unwrap(),
            arkret_wire::project_full_id_to_core_id(
                &arkret_wire::DidFullId::new(actor_id.to_owned()).unwrap(),
            )
            .unwrap(),
            0,
            arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
            serde_json::json!({"contact_id": "ak:contact:test"}),
            created_at,
        )
        .unwrap();
        event.seal_basis = Some(arkret_wire::SealBasis {
            leaves: vec![
                arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ],
        });
        event.event_id = event
            .derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let event_digest = arkret_wire::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        let producer = arkret_wire::Proof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            proof_purpose: None,
            verification_method: arkret_wire::DidUrl::new(format!(
                "{actor_id}#ak:device:01904100-0000-7000-8000-000000000001"
            ))
            .unwrap(),
            event_digest: event_digest.clone(),
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at,
            domain: None,
            audience: None,
            jws: "fixture.signature".to_owned(),
        };
        let admission = arkret_wire::PrincipalServerAdmissionProof {
            kind: arkret_wire::PrincipalServerAdmissionProofKind::PrincipalServerAdmission,
            verification_method: arkret_wire::DidUrl::new(format!(
                "{actor_id}#principal-server-admission-key"
            ))
            .unwrap(),
            event_digest: event_digest.clone(),
            producer_proof_digest:
                arkret_wire::PrincipalServerAdmissionProof::producer_proof_digest(&producer)
                    .unwrap(),
            producer_verification_method: producer.verification_method.clone(),
            producer_signing_key: arkret_wire::DidKey::new("did:key:z6Mkhfixture").unwrap(),
            signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
            signer_resolution_evidence_digest: arkret_wire::Hash::new(format!(
                "sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
            accepted_at: created_at,
            jws: "fixture.admission.signature".to_owned(),
        };
        event.proofs = vec![producer.into(), admission.into()];
        event
            .validate_principal_server_admission_binding(arkret_canonical::DigestSuite::Sha256)
            .expect("fixture accepted Event proof set");
        let event_id = event.event_id.to_string();
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        EventCommitRequest {
            device_pairing_authorization: None,
            contact_projection: None,
            event: CanonicalEventRecord {
                event_id,
                actor_id: actor_id.to_owned(),
                actor_seq: event.actor_seq,
                realm_id: Some(realm_id),
                kind: event.kind.to_string(),
                schema_id: "arkret://events/contact/requested/v1".to_owned(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                canonical_digest: event_digest.to_string(),
                canonical_bytes,
                envelope: serde_json::to_value(event).unwrap(),
                received_at: created_at,
            },
            control_proposal_ingress: Some(
                arkret_state::state::store::ControlProposalIngress::AcklessSelfPrincipal(
                    arkret_state::state::store::AcklessSelfPrincipalIngress {
                        device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
                        device_authorize_event_id: format!("ak:event:{}", "b".repeat(43)),
                        device_generation_ref: 1,
                        seal_basis_digest: format!("sha256:{}", "a".repeat(64)),
                    },
                ),
            ),
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: Vec::new(),
            idempotency: None,
            outbox: Vec::new(),
        }
    }

    fn device_revoke_request() -> (EventCommitRequest, DeviceRevocationGateSelector) {
        let realm_id = realm_id();
        let actor_id = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let principal_server_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:soland.example").unwrap();
        let created_at = Utc::now();
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::DeviceRevoke.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(realm_id.clone()).unwrap(),
            },
            actor_id.clone(),
            principal_server_id.clone(),
            0,
            arkret_wire::Hlc::new("019f00000000-0000-00000002").unwrap(),
            serde_json::json!({
                "principal_id": actor_id,
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "revoked_by": "ak:did_core:web:alice.example",
                "revoked_at": created_at,
                "reason": "fixture"
            }),
            created_at,
        )
        .unwrap();
        let event_digest = arkret_wire::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        let policy = arkret_wire::ControlProposalDecisionPolicy::default();
        let mut authority_ack = arkret_wire::ControlProposalAuthorityAck {
            realm_id: event.realm_id.clone(),
            proposal_digest: event_digest.clone(),
            received_at: created_at,
            decision_due_at: created_at + policy.decision_window,
            absolute_due_at: created_at + policy.absolute_horizon,
            authority_set_ref: arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64)))
                .unwrap(),
            signature: arkret_wire::PayloadSignature {
                verification_method: arkret_wire::DidUrl::new("did:web:soland.example#authority-1")
                    .unwrap(),
                payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at,
                jws: "e30..c2ln".to_owned(),
                extra: Default::default(),
            },
        };
        authority_ack.signature.payload_digest = authority_ack.authority_ack_digest().unwrap();
        let control_proposal_ack =
            arkret_wire::ControlProposalAck::from_authority_acks(vec![authority_ack], policy)
                .unwrap();
        let event_id = event.event_id.to_string();
        let canonical_digest = event_digest.to_string();
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        let selector = DeviceRevocationGateSelector {
            principal_id: actor_id.to_string(),
            principal_server_id: principal_server_id.to_string(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            target_device_authorize_event_id:
                "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD".to_owned(),
            target_device_generation_ref: 7,
        };
        let transition = DeviceRevocationTransition {
            selector: selector.clone(),
            proposal_event_id: event_id.clone(),
            proposal_digest: canonical_digest.clone(),
            control_proposal_ack: control_proposal_ack.clone(),
        };
        (
            EventCommitRequest {
                device_pairing_authorization: None,
                contact_projection: None,
                event: CanonicalEventRecord {
                    event_id,
                    actor_id: actor_id.to_string(),
                    actor_seq: event.actor_seq,
                    realm_id: Some(realm_id),
                    kind: event.kind.to_string(),
                    schema_id: "arkret://events/device/revoke/v1".to_owned(),
                    digest_suite: arkret_canonical::DigestSuite::Sha256,
                    canonical_digest,
                    canonical_bytes,
                    envelope: serde_json::to_value(event).unwrap(),
                    received_at: created_at,
                },
                control_proposal_ingress: Some(
                    arkret_state::state::store::ControlProposalIngress::AckRequired(
                        control_proposal_ack,
                    ),
                ),
                device_revocation_transition: Some(transition),
                device_revocation_gate: None,
                projections: Vec::new(),
                idempotency: None,
                outbox: Vec::new(),
            },
            selector,
        )
    }

    #[test]
    fn self_principal_pcr_device_authority_is_the_only_ackless_control_shape() {
        let request = self_principal_pcr_control_request();
        let mut staged = std::collections::BTreeMap::new();
        stage_control_proposal_ack(&mut staged, &request)
            .expect("current Human PCR device proof is sufficient proposal authority");
        assert!(
            staged.is_empty(),
            "Ack-less PCR move must not synthesize an Ack"
        );

        let mut missing_classification = request.clone();
        missing_classification.control_proposal_ingress = None;
        assert!(matches!(
            stage_control_proposal_ack(&mut staged, &missing_classification),
            Err(PersistenceError::Conflict(reason))
                if reason.contains("missing its durable ingress classification")
        ));

        let mut delegated = request;
        let mut event: arkret_wire::Event =
            serde_json::from_value(delegated.event.envelope.clone()).unwrap();
        event.executed_by = Some(arkret_wire::DidCoreId::from(
            arkret_wire::project_full_id_to_core_id(
                &arkret_wire::DidFullId::new("did:web:controller.example").unwrap(),
            )
            .unwrap(),
        ));
        delegated.event.canonical_digest = event
            .event_digest_with_digest_suite(delegated.event.digest_suite)
            .unwrap();
        delegated.event.envelope = serde_json::to_value(event).unwrap();
        assert!(matches!(
            stage_control_proposal_ack(&mut staged, &delegated),
            Err(PersistenceError::Conflict(reason))
                if reason.contains("invalid self-principal PCR device-authorized")
        ));
    }

    #[tokio::test]
    async fn exact_replay_is_noop_but_forged_preimage_is_rejected_before_lookup() {
        let store = SolandMemoryPersistenceStore::new();
        let request = event_request(
            "exact-replay".to_owned(),
            realm_id(),
            "did:web:replay.example",
            None,
        );
        store
            .events
            .data
            .lock()
            .insert(request.event.event_id.clone(), request.event.clone());

        let replay = store.commit_event(request.clone()).await.unwrap();
        assert_eq!(replay, soland_storage::EventCommitOutcome::default());

        let event_id = request.event.event_id.clone();
        let mut collision = request;
        collision.event.canonical_bytes.push(0);
        let error = store.commit_event(collision).await.unwrap_err();
        assert!(matches!(
            error,
            PersistenceError::Conflict(reason) if reason == "event_id_digest_mismatch"
        ));
        assert!(store.events.data.lock().contains_key(&event_id));
        assert!(store.events.quarantined.lock().is_empty());
    }

    #[tokio::test]
    async fn agent_membership_cascade_commits_exact_sets_and_durable_cleanup_atomically() {
        let store = SolandMemoryPersistenceStore::new();
        let realm_id = realm_id();
        let controller = cascade_event_request(
            "controller-terminal",
            &realm_id,
            "did:web:controller.example",
        );
        let agent_a = cascade_event_request("agent-a-leave", &realm_id, "did:web:agent-a.example");
        let agent_b = cascade_event_request("agent-b-leave", &realm_id, "did:web:agent-b.example");
        let controller_event_id =
            arkret_wire::EventId::new(controller.event.event_id.clone()).unwrap();
        let agent_event_ids = vec![
            arkret_wire::EventId::new(agent_a.event.event_id.clone()).unwrap(),
            arkret_wire::EventId::new(agent_b.event.event_id.clone()).unwrap(),
        ];

        let mut incomplete = EventBatchCommitRequest {
            events: vec![controller.clone(), agent_a.clone()],
            applet_ghosts: None,
            agent_membership_cascade: Some(AgentMembershipCascadeCommit::AtomicSelfLeave {
                controller_transition_event_id: controller_event_id.clone(),
                agent_transition_event_ids: agent_event_ids.clone(),
                expected_agent_ids: vec![
                    arkret_wire::DidCoreId::new(agent_a.event.actor_id.clone()).unwrap(),
                    arkret_wire::DidCoreId::new(agent_b.event.actor_id.clone()).unwrap(),
                ],
            }),
        };
        assert!(matches!(
            store.commit_event_batch(incomplete.clone()).await,
            Err(PersistenceError::Conflict(reason))
                if reason.contains("atomic Agent cascade Event set mismatch")
        ));
        assert!(
            incomplete.events.iter().all(|request| !store
                .events
                .data
                .lock()
                .contains_key(&request.event.event_id)),
            "an invalid cascade must not commit a prefix"
        );

        incomplete.events.push(agent_b.clone());
        let committed = store.commit_event_batch(incomplete).await.unwrap();
        assert!(committed.event_inserted);
        assert!(
            [&controller, &agent_a, &agent_b]
                .into_iter()
                .all(|request| store
                    .events
                    .data
                    .lock()
                    .contains_key(&request.event.event_id))
        );

        let terminal = emergency_terminal_request(&realm_id);
        let expected_agent_ids = vec![
            arkret_wire::DidCoreId::new("ak:did_core:web:emergency-agent-a.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:emergency-agent-b.example").unwrap(),
        ];
        let record = cleanup_record(&terminal, &realm_id, expected_agent_ids.clone());
        let cleanup_digest = record.cleanup_intent_digest.clone();
        let terminal_event_id = record.controller_terminal_event_id.clone();
        store
            .commit_event_batch(EventBatchCommitRequest {
                events: vec![terminal.clone()],
                applet_ghosts: None,
                agent_membership_cascade: Some(AgentMembershipCascadeCommit::EmergencyTerminal {
                    record: record.clone(),
                }),
            })
            .await
            .unwrap();
        assert_eq!(
            store
                .agent_membership_cascades
                .agent_cleanup_intent(&cleanup_digest)
                .await
                .unwrap(),
            Some(record)
        );

        let cleanup_a = cascade_event_request(
            "emergency-agent-a-leave",
            &realm_id,
            "did:web:emergency-agent-a.example",
        );
        let cleanup_b = cascade_event_request(
            "emergency-agent-b-leave",
            &realm_id,
            "did:web:emergency-agent-b.example",
        );
        let cleanup_event_ids = vec![
            arkret_wire::EventId::new(cleanup_a.event.event_id.clone()).unwrap(),
            arkret_wire::EventId::new(cleanup_b.event.event_id.clone()).unwrap(),
        ];
        store
            .commit_event_batch(EventBatchCommitRequest {
                events: vec![cleanup_a, cleanup_b],
                applet_ghosts: None,
                agent_membership_cascade: Some(AgentMembershipCascadeCommit::EmergencyCleanup {
                    cleanup_intent_digest: cleanup_digest.clone(),
                    controller_terminal_event_id: terminal_event_id,
                    agent_transition_event_ids: cleanup_event_ids.clone(),
                    completed_at: Utc::now(),
                }),
            })
            .await
            .unwrap();
        let completed = store
            .agent_membership_cascades
            .agent_cleanup_intent(&cleanup_digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            completed.status,
            arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupStatus::AgentCleanupCompleted
        );
        assert_eq!(
            completed.agent_transition_event_ids,
            Some(cleanup_event_ids)
        );
    }

    #[tokio::test]
    async fn device_revoke_acceptance_replay_gate_seal_and_cleanup_are_one_state_machine() {
        let store = SolandMemoryPersistenceStore::new();
        let (request, selector) = device_revoke_request();
        let proposal_digest = request.event.canonical_digest.clone();
        let proposal_event_id = request.event.event_id.clone();

        let accepted = store.commit_event(request.clone()).await.unwrap();
        assert!(accepted.event_inserted);
        assert!(matches!(
            store.device_revocations.gate_status(&selector).await.unwrap(),
            DeviceRevocationGateStatus::Pending { ref blocking_proposal_digest }
                if blocking_proposal_digest == &proposal_digest
        ));
        let first_targets = store
            .device_revocations
            .list_targets(&selector)
            .await
            .unwrap();
        assert_eq!(first_targets.len(), 1);
        assert_eq!(first_targets[0].acceptance_seq, 1);

        let gated_event_id = typed_id("ak:event:");
        let mut gated_event = event_request(
            gated_event_id.clone(),
            realm_id(),
            "did:web:alice.example",
            None,
        );
        gated_event.device_revocation_gate = Some(selector.clone());
        assert!(matches!(
            store.commit_event(gated_event).await,
            Err(PersistenceError::Conflict(reason)) if reason == "device_revocation_pending"
        ));
        assert!(!store.events.data.lock().contains_key(&gated_event_id));

        assert!(matches!(
            store
                .device_messages()
                .append(
                    Some(&selector),
                    DeviceMessageRecord {
                        idempotency_key: "revocation-pending-message".to_owned(),
                        sender: selector.principal_id.clone(),
                        recipient: selector.principal_id.clone(),
                        device_id: selector.device_id.clone(),
                        position: 1,
                        content: serde_json::json!({"kind": "fixture"}),
                        created_at: Utc::now(),
                    },
                )
                .await,
            Err(PersistenceError::Conflict(reason)) if reason == "device_revocation_pending"
        ));

        let replay = store.commit_event(request).await.unwrap();
        assert_eq!(replay, soland_storage::EventCommitOutcome::default());
        assert_eq!(
            store
                .device_revocations
                .list_targets(&selector)
                .await
                .unwrap(),
            first_targets
        );

        let linearization_request = DeviceRevocationGateLinearizationRequest {
            principal_id: selector.principal_id.clone(),
            principal_server_id: selector.principal_server_id.clone(),
            device_id: selector.device_id.clone(),
            expected_device_authorize_event_id: Some(
                selector.target_device_authorize_event_id.clone(),
            ),
            expected_device_generation_ref: Some(selector.target_device_generation_ref),
            origin_current_selector: Some(selector.clone()),
            action_class: DeviceRevocationGateAction::SessionGrantIssue,
            intent_digest: format!("sha256:{}", "b".repeat(64)),
            requested_at: Utc::now(),
        };
        let first = store
            .device_revocations
            .linearize_gate(linearization_request.clone())
            .await
            .unwrap();
        let replay = store
            .device_revocations
            .linearize_gate(linearization_request)
            .await
            .unwrap();
        assert_eq!(first, replay);
        assert!(matches!(
            first.status,
            DeviceRevocationGateStatus::Pending { .. }
        ));

        let sealed_at = Utc::now();
        assert!(
            store
                .device_revocations
                .mark_sealed(
                    &proposal_digest,
                    &format!("ak:seal:sha256:{}", "c".repeat(64)),
                    sealed_at
                )
                .await
                .unwrap()
        );
        assert!(matches!(
            store
                .device_revocations
                .gate_status(&selector)
                .await
                .unwrap(),
            DeviceRevocationGateStatus::Revoked { .. }
        ));
        assert_eq!(
            store
                .device_revocations
                .pending_cleanup_intents(10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .device_revocations
                .complete_material_cleanup(&proposal_digest, Utc::now())
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .device_revocations
                .pending_cleanup_intents(10)
                .await
                .unwrap()
                .len(),
            1,
            "the durable task remains until the MLS step is acknowledged"
        );
        assert!(
            store
                .device_revocations
                .complete_mls_obligation_by_event_id(&proposal_event_id, Utc::now())
                .await
                .unwrap()
        );
        assert!(
            store
                .device_revocations
                .pending_cleanup_intents(10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn failed_event_commit_leaves_no_revocation_event_ack_or_pending_target() {
        let store = SolandMemoryPersistenceStore::new();
        let (mut request, selector) = device_revoke_request();
        let event_id = request.event.event_id.clone();
        request.projections.push(ProjectionEventRecord {
            event_id: event_id.clone(),
            realm_id: "not-a-typed-realm".to_owned(),
            event_kind: arkret_wire::EventKind::DeviceRevoke.to_string(),
            operation_kind: "revoke".to_owned(),
            operation_id: None,
            sender: Some(selector.principal_id.clone()),
            payload: serde_json::json!({}),
            created_at: Utc::now(),
            received_at: Utc::now(),
        });

        assert!(store.commit_event(request).await.is_err());
        assert!(!store.events.data.lock().contains_key(&event_id));
        assert!(
            !store
                .events
                .control_proposal_acks
                .lock()
                .contains_key(&event_id)
        );
        assert!(
            store
                .device_revocations
                .list_targets(&selector)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .device_revocations
                .gate_status(&selector)
                .await
                .unwrap(),
            DeviceRevocationGateStatus::Active
        );
    }

    #[tokio::test]
    async fn ghost_batch_rolls_back_events_and_projection_on_idempotency_conflict() {
        let store = SolandMemoryPersistenceStore::new();
        let applet_id = typed_id("ak:applet:");
        store.applets.records.lock().insert(
            applet_id.clone(),
            serde_json::json!({
                "status": "installed",
                "revoked_at": null,
                "ghosts": [],
            }),
        );
        let principal_id = "did:web:bridge.example";
        let idempotency_key = "ghost-batch-conflict";
        let now = Utc::now();
        store.idempotency_keys.data.lock().insert(
            (principal_id.to_owned(), idempotency_key.to_owned()),
            IdempotencyRecord {
                principal_id: principal_id.to_owned(),
                idempotency_key: idempotency_key.to_owned(),
                service_id: "did:web:soland.example".to_owned(),
                request_hash: "sha256:first".to_owned(),
                response_status: 201,
                response_body: serde_json::json!({"first": true}),
                created_at: now,
                expires_at: now + Duration::hours(1),
            },
        );
        let event_id = typed_id("ak:event:");
        let request = EventBatchCommitRequest {
            events: vec![event_request(
                event_id.clone(),
                realm_id(),
                principal_id,
                Some(IdempotencyRecord {
                    principal_id: principal_id.to_owned(),
                    idempotency_key: idempotency_key.to_owned(),
                    service_id: "did:web:soland.example".to_owned(),
                    request_hash: "sha256:competing".to_owned(),
                    response_status: 201,
                    response_body: serde_json::json!({"first": false}),
                    created_at: now,
                    expires_at: now + Duration::hours(1),
                }),
            )],
            applet_ghosts: Some(AppletGhostCommit {
                applet_id: applet_id.clone(),
                ghost: serde_json::json!({
                    "ghost_actor_id": "did:web:bridge.example:ghost:one",
                    "external_id": "one",
                }),
            }),
            agent_membership_cascade: None,
        };

        assert!(store.commit_event_batch(request).await.is_err());
        assert!(!store.events.data.lock().contains_key(&event_id));
        assert_eq!(
            store.applets.records.lock()[&applet_id]["ghosts"],
            serde_json::json!([])
        );
    }

    #[tokio::test]
    async fn ghost_batch_appends_without_replacing_existing_ghosts() {
        let store = SolandMemoryPersistenceStore::new();
        let applet_id = typed_id("ak:applet:");
        store.applets.records.lock().insert(
            applet_id.clone(),
            serde_json::json!({
                "status": "installed",
                "revoked_at": null,
                "ghosts": [{
                    "ghost_actor_id": "did:web:bridge.example:ghost:first",
                    "external_id": "first",
                }],
            }),
        );
        let request = EventBatchCommitRequest {
            events: vec![event_request(
                typed_id("ak:event:"),
                realm_id(),
                "did:web:bridge.example:ghost:second",
                None,
            )],
            applet_ghosts: Some(AppletGhostCommit {
                applet_id: applet_id.clone(),
                ghost: serde_json::json!({
                    "ghost_actor_id": "did:web:bridge.example:ghost:second",
                    "external_id": "second",
                }),
            }),
            agent_membership_cascade: None,
        };

        store.commit_event_batch(request).await.unwrap();
        assert_eq!(
            store.applets.records.lock()[&applet_id]["ghosts"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}
