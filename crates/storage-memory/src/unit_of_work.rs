use arkret_models_collaboration::http_bodies::DevicePairingState;
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
        arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupRecord,
    >,
    transition: Option<&soland_storage::AgentMembershipCascadeCommit>,
    events: &[EventCommitRequest],
) -> PersistenceResult<()> {
    use arkret_models_collaboration::governance::agent_membership_cascade::MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS;
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
                .map(|request| soland_storage::admitted_cascade_agent_id(&request.event))
                .collect::<PersistenceResult<std::collections::BTreeSet<_>>>()?;
            let expected_agent_count = expected_agent_ids.len();
            let expected_agent_ids = expected_agent_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            if submitted_agent_ids != expected_agent_ids
                || expected_agent_ids.len() != expected_agent_count
            {
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
            let controller = arkret_wire::ActorId::account(record.controller_account_id.clone());
            let expected_initiator = &record.initiator_actor_id;
            if terminal.event.actor_id != controller.to_string()
                || terminal.event.realm_id.as_deref() != Some(record.realm_id.as_str())
                || typed.actor_id != controller
                || initiator != expected_initiator
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: emergency terminal Event does not bind cleanup intent"
                        .to_owned(),
                ));
            }
            match records.get(record.cleanup_intent_digest.as_str()) {
                Some(existing) if existing == record.as_ref() => {}
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
                    records.insert(
                        record.cleanup_intent_digest.to_string(),
                        record.as_ref().clone(),
                    );
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
                .map(|request| soland_storage::admitted_cascade_agent_id(&request.event))
                .collect::<PersistenceResult<std::collections::BTreeSet<_>>>()?;
            let expected_actor_ids = record
                .expected_agent_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            if actor_ids != expected_actor_ids {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: emergency Agent cleanup actor set mismatch".to_owned(),
                ));
            }
            if record.completed_at.is_some() {
                if record.agent_transition_event_ids.as_ref() != Some(agent_transition_event_ids) {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: completed Agent cleanup replay differs".to_owned(),
                    ));
                }
                return Ok(());
            }
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
    let is_control_move = event.kind.is_control_plane();
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
    if let Some(existing) = staged.get(&event_digest)
        && existing != ack
    {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: Control Move has a different Control Proposal Ack".to_owned(),
        ));
    }
    staged.insert(event_digest, ack.clone());
    Ok(())
}

fn stage_event_governance_dependencies(
    data: &mut crate::governance_history::GovernanceDependencyData,
    request: &EventCommitRequest,
) -> PersistenceResult<()> {
    let event = serde_json::from_value::<arkret_wire::Event>(request.event.envelope.clone())
        .map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: accepted Event envelope is not canonical wire: {error}"
            ))
        })?;
    let is_control_move = event.kind.is_control_plane();
    if !is_control_move {
        return if request.governance_dependencies.is_empty() {
            Ok(())
        } else {
            Err(PersistenceError::Conflict(
                "schema_violation: non-Control Event cannot carry governance dependencies"
                    .to_owned(),
            ))
        };
    }
    let event_digest = event
        .event_digest_with_digest_suite(request.event.digest_suite)
        .map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: accepted Control Move digest failed: {error}"
            ))
        })?;
    for dependency in &request.governance_dependencies {
        let source_matches = matches!(
            &dependency.source,
            soland_storage::GovernanceDependencySource::ControlEvent(digest)
                if digest.as_str() == event_digest
        );
        if dependency.realm_id != event.realm_id || !source_matches {
            return Err(PersistenceError::Conflict(
                "schema_violation: governance dependency does not bind committed Control Move"
                    .to_owned(),
            ));
        }
        crate::governance_history::stage_governance_dependency_exact(data, dependency)?;
    }
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
    if pairing.state != DevicePairingState::PendingAuthorization
        || pairing.expires_at <= commit.changed_at
        || pairing.pairing_code != commit.pairing_code
        || pairing.new_device_pubkey != commit_new_device_pubkey
    {
        return Err(PersistenceError::Conflict(
            "device_pairing_not_found".to_owned(),
        ));
    }
    pairing.state = DevicePairingState::Authorized;
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
        commit.record.requester_id.clone(),
        commit.record.target_id.clone(),
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

fn stage_contact_verified_mirror(
    staged: &mut std::collections::BTreeMap<
        (String, String),
        soland_storage::ContactVerifiedMirrorRecord,
    >,
    commit: Option<&soland_storage::ContactProjectionCommit>,
) -> PersistenceResult<()> {
    let Some(mirror) = commit.and_then(|commit| commit.verified_mirror.as_ref()) else {
        return Ok(());
    };
    let key = (
        mirror.target_holder_id.clone(),
        mirror.request_event_id.clone(),
    );
    if let Some(existing) = staged.get(&key) {
        if existing == mirror {
            return Ok(());
        }
        return Err(PersistenceError::Conflict(
            "contact_verified_mirror_conflict".to_owned(),
        ));
    }
    if staged.values().any(|existing| {
        existing.target_holder_id == mirror.target_holder_id
            && existing.request_digest == mirror.request_digest
    }) {
        return Err(PersistenceError::Conflict(
            "contact_verified_mirror_conflict".to_owned(),
        ));
    }
    staged.insert(key, mirror.clone());
    Ok(())
}

fn stage_consent_projection(
    staged_cells: &mut std::collections::BTreeMap<
        soland_storage::ConsentCellKey,
        soland_storage::ConsentCellRecord,
    >,
    staged_account_data: &mut std::collections::BTreeMap<
        (String, String),
        soland_storage::AccountDataRecord,
    >,
    commit: Option<&soland_storage::ConsentProjectionCommit>,
) -> PersistenceResult<()> {
    let Some(commit) = commit else {
        return Ok(());
    };
    let key = soland_storage::ConsentCellKey {
        holder_principal_id: commit.cell.holder_principal_id.clone(),
        cell_id: commit.cell.cell_id.clone(),
    };
    if let Some(current) = staged_cells.get(&key)
        && (current.peer_principal_id != commit.cell.peer_principal_id
            || current.consent_scope != commit.cell.consent_scope)
    {
        return Err(PersistenceError::Conflict(
            "consent_intent_rebind".to_owned(),
        ));
    }
    staged_cells.insert(key, commit.cell.clone());
    if let Some(cas) = commit.invite_quarantine.as_ref() {
        let account_key = (
            cas.record.actor.clone(),
            cas.record.account_data_key.clone(),
        );
        let current_revision = staged_account_data
            .get(&account_key)
            .map_or(0, |record| record.revision);
        if current_revision != cas.expected_revision
            || cas.record.revision != cas.expected_revision.saturating_add(1)
        {
            return Err(PersistenceError::Conflict(cas.conflict_code.clone()));
        }
        staged_account_data.insert(account_key, cas.record.clone());
    }
    Ok(())
}

fn stage_membership_compensation_evidence(
    staged: &mut std::collections::BTreeMap<
        String,
        soland_storage::MembershipCompensationEvidenceRecord,
    >,
    request: &EventCommitRequest,
) -> PersistenceResult<()> {
    let event = serde_json::from_value::<arkret_wire::Event>(request.event.envelope.clone())
        .map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: accepted Event envelope is not canonical wire: {error}"
            ))
        })?;
    let selects_compensation = event.authorization_ref.as_ref().is_some_and(|value| {
        arkret_wire::MembershipCompensationDelegationRef::new(value.as_str()).is_ok()
    });
    let record = match (
        selects_compensation,
        request.membership_compensation_evidence.as_ref(),
    ) {
        (false, None) => return Ok(()),
        (true, None) | (false, Some(_)) => {
            return Err(PersistenceError::Conflict(
                "schema_violation: membership compensation carrier presence mismatch".to_owned(),
            ));
        }
        (true, Some(record)) => record,
    };
    let expected_bytes =
        arkret_canonical::canonical_json_bytes(&record.evidence).map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: membership compensation evidence is not canonicalizable: {error}"
            ))
        })?;
    if record.event_id != request.event.event_id
        || record.event_digest != request.event.canonical_digest
        || record.admission_id != record.evidence.delegation.core.admission_id.as_str()
        || record.delegation_digest != record.evidence.delegation.delegation_digest.as_str()
        || record.canonical_bytes != expected_bytes
    {
        return Err(PersistenceError::Conflict(
            "schema_violation: membership compensation evidence record is not self-consistent"
                .to_owned(),
        ));
    }
    record.evidence.validate_for_event(&event).map_err(|error| {
        PersistenceError::Conflict(format!(
            "membership_compensation_conflict: compensation evidence does not bind Event: {error}"
        ))
    })?;
    if let Some(existing) = staged.get(&record.event_id) {
        return if existing == record {
            Ok(())
        } else {
            Err(PersistenceError::Conflict(
                "membership_compensation_conflict: Event replay changed its compensation evidence"
                    .to_owned(),
            ))
        };
    }
    if staged.values().any(|existing| {
        existing.admission_id == record.admission_id
            && existing.delegation_digest == record.delegation_digest
    }) {
        return Err(PersistenceError::Conflict(
            "membership_compensation_conflict: compensation delegation was already consumed"
                .to_owned(),
        ));
    }
    staged.insert(record.event_id.clone(), record.clone());
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
        let mut contact_verified_mirrors = self.contact_verified_mirrors.data.lock();
        let mut invite_policies = self.invite_receive_policies.data.lock();
        let mut device_revocations = self.device_revocations.state.lock();
        let mut consent_cells = self.consent_cells.data.lock();
        let mut account_data = self.account_data.data.lock();
        let mut governance_dependencies = self.governance_dependencies.data.lock();
        let mut membership_compensation_evidence =
            self.events.membership_compensation_evidence.lock();

        let mut staged_events = events.clone();
        let mut staged_control_proposal_acks = control_proposal_acks.clone();
        let mut staged_projections = projections.clone();
        let mut staged_idempotency = idempotency.clone();
        let mut staged_outbox = outbox.clone();
        let mut staged_event_outbox_ids = event_outbox_ids.clone();
        let mut staged_pairings = pairings.clone();
        let mut staged_contacts = contacts.clone();
        let mut staged_contact_verified_mirrors = contact_verified_mirrors.clone();
        let mut staged_invite_policies = invite_policies.clone();
        let mut staged_device_revocations = device_revocations.clone();
        let mut staged_consent_cells = consent_cells.clone();
        let mut staged_account_data = account_data.clone();
        let mut staged_governance_dependencies = governance_dependencies.clone();
        let mut staged_membership_compensation_evidence = membership_compensation_evidence.clone();

        stage_membership_compensation_evidence(
            &mut staged_membership_compensation_evidence,
            &request,
        )?;

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
            *membership_compensation_evidence = staged_membership_compensation_evidence;
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
        stage_event_governance_dependencies(&mut staged_governance_dependencies, &request)?;
        stage_contact_projection(&mut staged_contacts, request.contact_projection.as_ref())?;
        stage_contact_verified_mirror(
            &mut staged_contact_verified_mirrors,
            request.contact_projection.as_ref(),
        )?;
        stage_consent_projection(
            &mut staged_consent_cells,
            &mut staged_account_data,
            request.consent_projection.as_ref(),
        )?;
        if let Some((account_id, policy)) = request
            .contact_projection
            .as_ref()
            .and_then(|commit| commit.invite_policy.as_ref())
        {
            soland_storage::validate_invite_policy_account(account_id, policy)?;
            staged_invite_policies.insert(account_id.clone(), policy.clone());
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
                (existing.peer_id == record.peer_id
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
        *contact_verified_mirrors = staged_contact_verified_mirrors;
        *invite_policies = staged_invite_policies;
        *device_revocations = staged_device_revocations;
        *consent_cells = staged_consent_cells;
        *account_data = staged_account_data;
        *governance_dependencies = staged_governance_dependencies;
        *membership_compensation_evidence = staged_membership_compensation_evidence;

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
        soland_storage::validate_franking_replay_nonce_commit(
            &request.events,
            request.franking_replay_nonce.as_ref(),
        )?;
        soland_storage::validate_agent_approval_nonce_commit(
            &request.events,
            request.agent_approval_nonce.as_ref(),
        )?;
        // Same seal-derived settlement as `commit_event` above.
        self.device_revocations.settle_from_control_events();
        let mut events = self.events.data.lock();
        let mut quarantined = self.events.quarantined.lock();
        let mut collision_variants = self.events.collision_variants.lock();
        let mut control_proposal_acks = self.events.control_proposal_acks.lock();
        let mut projections = self.projection_events.data.lock();
        let mut idempotency = self.idempotency_keys.data.lock();
        let mut franking_replay_nonces = self.franking_replay_nonces.lock();
        let mut agent_approval_nonces = self.agent_approval_nonces.lock();
        let mut event_outbox_ids = self.events.event_outbox_ids.lock();
        let mut outbox = self.federation_outbox.data.lock();
        let mut applet_identities = self.applets.identities.lock();
        let mut applets = self.applets.records.lock();
        let mut authoring_previews = self.applets.authoring_previews.lock();
        let mut pairings = self.device_pairings.data.lock();
        let mut contacts = self.contacts.data.lock();
        let mut contact_verified_mirrors = self.contact_verified_mirrors.data.lock();
        let mut invite_policies = self.invite_receive_policies.data.lock();
        let mut device_revocations = self.device_revocations.state.lock();
        let mut agent_membership_cascades = self.agent_membership_cascades.data.lock();
        let mut governance_dependencies = self.governance_dependencies.data.lock();
        let mut membership_compensation_evidence =
            self.events.membership_compensation_evidence.lock();

        let mut staged_events = events.clone();
        let mut staged_control_proposal_acks = control_proposal_acks.clone();
        let mut staged_projections = projections.clone();
        let mut staged_idempotency = idempotency.clone();
        let mut staged_franking_replay_nonces = franking_replay_nonces.clone();
        let mut staged_agent_approval_nonces = agent_approval_nonces.clone();
        let mut staged_outbox = outbox.clone();
        let mut staged_event_outbox_ids = event_outbox_ids.clone();
        let mut staged_applet_identities = applet_identities.clone();
        let mut staged_applets = applets.clone();
        let mut staged_authoring_previews = authoring_previews.clone();
        let mut staged_pairings = pairings.clone();
        let mut staged_contacts = contacts.clone();
        let mut staged_contact_verified_mirrors = contact_verified_mirrors.clone();
        let mut staged_invite_policies = invite_policies.clone();
        let mut staged_device_revocations = device_revocations.clone();
        let mut staged_agent_membership_cascades = agent_membership_cascades.clone();
        let mut staged_governance_dependencies = governance_dependencies.clone();
        let mut staged_membership_compensation_evidence = membership_compensation_evidence.clone();
        let mut event_inserted = false;
        let mut projections_inserted = 0;
        let mut outbox_inserted = 0;

        stage_agent_membership_cascade(
            &mut staged_agent_membership_cascades,
            request.agent_membership_cascade.as_ref(),
            &request.events,
        )?;

        for event_request in request.events {
            stage_membership_compensation_evidence(
                &mut staged_membership_compensation_evidence,
                &event_request,
            )?;
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
            stage_event_governance_dependencies(
                &mut staged_governance_dependencies,
                &event_request,
            )?;
            let event_id = event_request.event.event_id.clone();
            stage_contact_projection(
                &mut staged_contacts,
                event_request.contact_projection.as_ref(),
            )?;
            stage_contact_verified_mirror(
                &mut staged_contact_verified_mirrors,
                event_request.contact_projection.as_ref(),
            )?;
            if let Some((account_id, policy)) = event_request
                .contact_projection
                .as_ref()
                .and_then(|commit| commit.invite_policy.as_ref())
            {
                soland_storage::validate_invite_policy_account(account_id, policy)?;
                staged_invite_policies.insert(account_id.clone(), policy.clone());
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
                    (existing.peer_id == record.peer_id
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

        if let Some(nonce) = request.franking_replay_nonce {
            let expired = staged_franking_replay_nonces
                .iter()
                .map(|(key, existing)| {
                    soland_storage::franking_replay_nonce_expires_at(existing.consumed_at)
                        .map(|expires_at| (key.clone(), expires_at <= nonce.consumed_at))
                })
                .collect::<PersistenceResult<Vec<_>>>()?;
            for (key, expired) in expired {
                if expired {
                    staged_franking_replay_nonces.remove(&key);
                }
            }
            let key = (
                nonce.realm_id.clone(),
                nonce.received_by.clone(),
                nonce.replay_nonce.clone(),
            );
            if staged_franking_replay_nonces.contains_key(&key) {
                return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
            }
            let active_in_scope = staged_franking_replay_nonces
                .keys()
                .filter(|(realm_id, received_by, _)| {
                    realm_id == &nonce.realm_id && received_by == &nonce.received_by
                })
                .count();
            if active_in_scope >= soland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE {
                return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
            }
            staged_franking_replay_nonces.insert(key, nonce);
        }

        if let Some(nonce) = request.agent_approval_nonce {
            let key = (
                nonce.agent_id.clone(),
                nonce.authorization_ref.clone(),
                nonce.request_id.clone(),
                nonce.approval_nonce.clone(),
            );
            if staged_agent_approval_nonces.insert(key, nonce).is_some() {
                return Err(PersistenceError::Conflict(
                    arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED.to_owned(),
                ));
            }
        }

        if let Some(preview) = request.applet_authoring_preview {
            let matches_current = staged_authoring_previews
                .get(&preview.subject_key)
                .is_some_and(|current| current.request_digest == preview.request_digest);
            if !matches_current {
                return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
            }
            staged_authoring_previews.remove(&preview.subject_key);
        }

        if let Some(mutation) = request.applet_record {
            soland_storage::validate_applet_installation_record(&mutation.record)?;
            if let Some(expected) = mutation.expected_record.as_ref() {
                soland_storage::validate_applet_installation_record(expected)?;
            }
            let identity_key = (
                mutation.applet_id.to_string(),
                mutation.identity.target_station_id.to_string(),
            );
            if soland_storage::applet_id_from_record(&mutation.identity.record)?
                != mutation.applet_id.as_str()
                || mutation
                    .identity
                    .record
                    .get("bot_actor_station_id")
                    .and_then(serde_json::Value::as_str)
                    != Some(mutation.identity.target_station_id.as_str())
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: Applet identity winner key does not match its record"
                        .to_owned(),
                ));
            }
            if let Some(expected_identity) = mutation.identity.expected_record.as_ref() {
                if &mutation.identity.record != expected_identity
                    || staged_applet_identities.get(&identity_key) != Some(expected_identity)
                {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: Applet identity winner changed".to_owned(),
                    ));
                }
            } else {
                match staged_applet_identities.entry(identity_key) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(mutation.identity.record.clone());
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(PersistenceError::Conflict(
                            "duplicate_conflict: Applet identity winner already exists".to_owned(),
                        ));
                    }
                }
            }
            let effective_scope_key =
                soland_storage::applet_effective_scope_key_from_record(&mutation.record)?;
            let installation_key = (mutation.applet_id.to_string(), effective_scope_key);
            if soland_storage::applet_id_from_record(&mutation.record)?
                != mutation.applet_id.as_str()
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: Applet installation key does not match its record"
                        .to_owned(),
                ));
            }
            let namespace_claims = soland_storage::applet_namespaces_from_record(&mutation.record)?;
            if let Some(expected_record) = mutation.expected_record.as_ref() {
                let expected_namespaces =
                    soland_storage::applet_namespaces_from_record(expected_record)?;
                if namespace_claims != expected_namespaces {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: Applet package.namespaces are immutable".to_owned(),
                    ));
                }
            } else {
                for ((existing_applet_id, _), existing_record) in &staged_applets {
                    if existing_applet_id == mutation.applet_id.as_str() {
                        continue;
                    }
                    let active = existing_record
                        .get("revoked_at")
                        .is_none_or(serde_json::Value::is_null)
                        && matches!(
                            existing_record
                                .get("status")
                                .and_then(serde_json::Value::as_str),
                            Some("installed" | "partially_installed")
                        );
                    if !active {
                        continue;
                    }
                    let namespaces =
                        soland_storage::applet_namespaces_from_record(existing_record)?;
                    if !namespace_claims.conflicts_with(&namespaces).is_empty() {
                        return Err(PersistenceError::Conflict(
                            "applet_namespace_conflict".to_owned(),
                        ));
                    }
                }
            }
            let managed_authorities = soland_storage::applet_managed_authorities_from_record(
                &mutation.identity.record,
                &mutation.record,
            )?;
            let previous_managed_authorities = mutation
                .expected_record
                .as_ref()
                .map(|record| {
                    soland_storage::applet_managed_authorities_from_record(
                        &mutation.identity.record,
                        record,
                    )
                })
                .transpose()?
                .unwrap_or_default();
            if !previous_managed_authorities.is_subset(&managed_authorities) {
                return Err(PersistenceError::Conflict(
                    "schema_violation: Applet managed authority anchors are immutable".to_owned(),
                ));
            }
            for claim in managed_authorities.difference(&previous_managed_authorities) {
                for ((existing_applet_id, _), existing_record) in &staged_applets {
                    if existing_applet_id == mutation.applet_id.as_str() {
                        continue;
                    }
                    let Some(existing_identity) =
                        staged_applet_identities
                            .iter()
                            .find_map(|((applet_id, _), identity)| {
                                (applet_id == existing_applet_id).then_some(identity)
                            })
                    else {
                        return Err(PersistenceError::Conflict(
                            "schema_violation: Applet installation has no identity winner"
                                .to_owned(),
                        ));
                    };
                    if soland_storage::applet_managed_authorities_from_record(
                        existing_identity,
                        existing_record,
                    )?
                    .contains(claim)
                    {
                        return Err(PersistenceError::Conflict(
                            "applet_managed_authority_conflict".to_owned(),
                        ));
                    }
                }
            }
            if let Some(expected) = mutation.expected_record {
                let existing = staged_applets
                    .get(&installation_key)
                    .ok_or_else(|| PersistenceError::NotFound("applet installation".to_owned()))?;
                if existing != &expected {
                    return Err(PersistenceError::Conflict("cas_conflict".to_owned()));
                }
                let active = existing
                    .get("revoked_at")
                    .is_none_or(serde_json::Value::is_null)
                    && matches!(
                        existing.get("status").and_then(serde_json::Value::as_str),
                        Some("installed" | "partially_installed")
                    );
                if !active {
                    return Err(PersistenceError::Conflict("applet_revoked".to_owned()));
                }
            } else if staged_applets.contains_key(&installation_key) {
                return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
            }
            staged_applets.insert(installation_key, mutation.record);
        }

        *events = staged_events;
        *control_proposal_acks = staged_control_proposal_acks;
        *projections = staged_projections;
        *idempotency = staged_idempotency;
        *franking_replay_nonces = staged_franking_replay_nonces;
        *agent_approval_nonces = staged_agent_approval_nonces;
        *outbox = staged_outbox;
        *event_outbox_ids = staged_event_outbox_ids;
        *applet_identities = staged_applet_identities;
        *applets = staged_applets;
        *authoring_previews = staged_authoring_previews;
        *pairings = staged_pairings;
        *contacts = staged_contacts;
        *contact_verified_mirrors = staged_contact_verified_mirrors;
        *invite_policies = staged_invite_policies;
        *device_revocations = staged_device_revocations;
        *agent_membership_cascades = staged_agent_membership_cascades;
        *governance_dependencies = staged_governance_dependencies;
        *membership_compensation_evidence = staged_membership_compensation_evidence;

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
        AgentMembershipCascadeCommit, AgentMembershipCascadeStore, AppletAuthoringPreviewCommit,
        AppletAuthoringPreviewRecord, AppletIdentityCommit, AppletRecordCommit,
        CanonicalEventRecord, DeviceMessageRecord, DeviceRevocationGateAction,
        DeviceRevocationGateLinearizationRequest, DeviceRevocationGateSelector,
        DeviceRevocationGateStatus, DeviceRevocationStore, DeviceRevocationTransition,
        EventBatchCommitRequest, EventCommitRequest, EventCommitUnitOfWork,
        EventProjectionStoreRegistry, EventStore, FrankingReplayNonceCommit, IdempotencyRecord,
        MembershipCompensationEvidenceRecord, PersistenceError, ProjectionEventRecord,
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

    fn test_applet_scope() -> arkret_wire::ScopeRef {
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(realm_id()).unwrap(),
        }
    }

    fn test_applet_record(
        mut record: serde_json::Value,
        scope: &arkret_wire::ScopeRef,
        applet_id: &str,
    ) -> serde_json::Value {
        let object = record.as_object_mut().unwrap();
        object.remove("bot_actor_id");
        object.remove("bot_actor_station_id");
        object.insert("applet_id".to_owned(), serde_json::json!(applet_id));
        object.insert(
            "effective_scope".to_owned(),
            serde_json::to_value(scope).unwrap(),
        );
        record
    }

    fn test_applet_identity(applet_id: &str, bot_actor_id: &str) -> serde_json::Value {
        serde_json::json!({
            "applet_id": applet_id,
            "bot_actor_id": bot_actor_id,
            "bot_actor_station_id": "ak:did_core:web:soland.example",
        })
    }

    fn existing_identity_commit(identity: &serde_json::Value) -> AppletIdentityCommit {
        AppletIdentityCommit {
            target_station_id: arkret_wire::DidCoreId::new(
                "ak:did_core:web:soland.example".to_owned(),
            )
            .unwrap(),
            expected_record: Some(identity.clone()),
            record: identity.clone(),
        }
    }

    fn test_applet_key(applet_id: &str, scope: &arkret_wire::ScopeRef) -> (String, String) {
        (
            applet_id.to_owned(),
            soland_storage::applet_effective_scope_key(scope).unwrap(),
        )
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
            arkret_wire::DidCoreId::new(actor_id.to_owned()).unwrap(),
            arkret_wire::DidCoreId::new(actor_id.to_owned()).unwrap(),
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
            governance_dependencies: Vec::new(),
            membership_compensation_evidence: None,
            device_pairing_authorization: None,
            contact_projection: None,
            consent_projection: None,
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

    fn compensation_control_ack(
        realm_id: &str,
        event_digest: &str,
        received_at: chrono::DateTime<Utc>,
    ) -> arkret_wire::ControlProposalAck {
        let policy = arkret_wire::ControlProposalDecisionPolicy::default();
        let mut authority_ack = arkret_wire::ControlProposalAuthorityAck {
            realm_id: arkret_wire::RealmId::new(realm_id.to_owned()).unwrap(),
            proposal_digest: arkret_wire::Hash::new(event_digest.to_owned()).unwrap(),
            received_at,
            decision_due_at: received_at + policy.decision_window,
            absolute_due_at: received_at + policy.absolute_horizon,
            authority_set_ref: arkret_wire::Hash::new(format!("sha256:{}", "44".repeat(32)))
                .unwrap(),
            signature: arkret_wire::PayloadSignature {
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:principal.example#authority-1",
                )
                .unwrap(),
                payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "00".repeat(32)))
                    .unwrap(),
                created_at: received_at,
                jws: "e30..c2ln".to_owned(),
            },
        };
        authority_ack.signature.payload_digest = authority_ack.authority_ack_digest().unwrap();
        arkret_wire::ControlProposalAck::from_authority_acks(vec![authority_ack], policy).unwrap()
    }

    fn membership_compensation_request() -> EventCommitRequest {
        let realm_id = realm_id();
        let station_id = arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap();
        let join_actor_id = arkret_wire::ActorId::hosted_principal(
            arkret_wire::DidCoreId::new("ak:did_core:web:join-actor.example").unwrap(),
            station_id.clone(),
        );
        let member_id = arkret_wire::ActorId::hosted_principal(
            arkret_wire::DidCoreId::new("ak:did_core:web:join-subject.example").unwrap(),
            station_id.clone(),
        );
        let executor_id = arkret_wire::ActorId::hosted_principal(
            arkret_wire::DidCoreId::new("ak:did_core:web:executor.example").unwrap(),
            station_id,
        );
        let join_event_id =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x41; 32]);
        let admission_id = arkret_wire::ProtocolOpaqueId::new("membership-admission-1").unwrap();
        let now = Utc::now();
        let verification_method =
            arkret_wire::DidUrl::new("did:web:join-actor.example#key-1").unwrap();
        let core = arkret_wire::MembershipCompensationDelegationCore {
            authority: arkret_wire::MembershipCompensationAuthority::V1,
            admission_id: admission_id.clone(),
            join_event_id: join_event_id.clone(),
            membership_cell_id: arkret_wire::ProtocolOpaqueId::new("membership-cell-1").unwrap(),
            member_id: member_id.clone(),
            join_actor_id: join_actor_id.clone(),
            executed_by: None,
            authorization_ref: None,
            verification_method: verification_method.clone(),
            executor_id: executor_id.clone(),
            executor_proof_key_kid: arkret_wire::DidUrl::new("did:web:executor.example#key-1")
                .unwrap(),
            resource_id: arkret_wire::RealmId::new(realm_id.clone()).unwrap(),
            action: arkret_wire::MembershipCompensationAction::Remove,
            deadline: now + Duration::hours(1),
        };
        let delegation_digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&core).unwrap(),
        ))
        .unwrap();
        let delegation_id = arkret_wire::MembershipCompensationDelegationRef::new(format!(
            "ak:membership_compensation_delegation:sha256:{}",
            delegation_digest.as_str().strip_prefix("sha256:").unwrap()
        ))
        .unwrap();
        let signature = || arkret_wire::ProtocolSignature {
            verification_method: verification_method.clone(),
            created_at: now,
            jws: arkret_wire::Base64UrlString::new("AA").unwrap(),
        };
        let evidence = arkret_wire::MembershipCompensationSubmissionEvidence {
            delegation: arkret_wire::MembershipCompensationExecutorDelegation {
                delegation_id: delegation_id.clone(),
                core,
                delegation_digest: delegation_digest.clone(),
                signature: signature(),
            },
            join_accepted_proof: arkret_wire::MembershipJoinAcceptedProof {
                admission_id: admission_id.clone(),
                join_event_id,
                accepted_at: now,
                issuer_id: join_actor_id.signing_principal_id().clone(),
                signature: signature(),
            },
            terminal_certificate: arkret_wire::MembershipCompensationTerminalCertificate {
                domain: arkret_wire::MembershipCompensationTerminalDomain::V1,
                admission_id: admission_id.clone(),
                delegation_digest: delegation_digest.clone(),
                operation_id: arkret_wire::ProtocolOperationId::new(
                    "ak:operation:019a6aa0-1000-7000-8000-000000000000",
                )
                .unwrap(),
                terminal_state:
                    arkret_wire::MembershipCompensationTerminalState::FailedAfterMembershipAcceptance,
                certified_at: now,
                issuer_id: join_actor_id.signing_principal_id().clone(),
                signature: signature(),
            },
            single_use_cas_token: arkret_wire::MembershipCompensationCasToken {
                domain: arkret_wire::MembershipCompensationCasDomain::V1,
                admission_id,
                delegation_digest,
                expected_state: arkret_wire::MembershipCompensationExpectedState::Unused,
                destination_id: executor_id.route_service_id().clone(),
                issued_at: now,
                expires_at: now + Duration::hours(1),
                issuer_id: join_actor_id.signing_principal_id().clone(),
                signature: signature(),
            },
        };
        let mut request = event_request(
            "membership-compensation".to_owned(),
            realm_id.clone(),
            "ak:did_core:web:join-actor.example",
            None,
        );
        let mut event: arkret_wire::Event =
            serde_json::from_value(request.event.envelope.clone()).unwrap();
        event.kind = arkret_wire::EventKind::MemberState;
        event.actor_id = join_actor_id;
        event.payload = serde_json::from_value(serde_json::json!({
            "member_id": member_id,
            "membership": "leave",
            "reason": "compensate failed admission"
        }))
        .unwrap();
        event.executed_by = Some(executor_id);
        event.authorization_ref =
            Some(arkret_wire::AuthorizationRef::new(delegation_id.as_str()).unwrap());
        event
            .refresh_content_bound_identity_with_digest_suite(request.event.digest_suite)
            .unwrap();
        request.event.event_id = event.event_id.to_string();
        request.event.kind = event.kind.to_string();
        request.event.actor_id = event.actor_id.to_string();
        request.event.schema_id = "arkret://events/member/state/v1".to_owned();
        request.event.canonical_digest = event
            .event_digest_with_digest_suite(request.event.digest_suite)
            .unwrap();
        request.event.canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        request.event.envelope = serde_json::to_value(event).unwrap();
        request.control_proposal_ingress = Some(
            arkret_state::state::store::ControlProposalIngress::AckRequired(
                compensation_control_ack(
                    &realm_id,
                    &request.event.canonical_digest,
                    request.event.received_at,
                ),
            ),
        );
        let canonical_bytes = arkret_canonical::canonical_json_bytes(&evidence).unwrap();
        request.membership_compensation_evidence = Some(MembershipCompensationEvidenceRecord {
            event_id: request.event.event_id.clone(),
            event_digest: request.event.canonical_digest.clone(),
            admission_id: evidence.delegation.core.admission_id.to_string(),
            delegation_digest: evidence.delegation.delegation_digest.to_string(),
            canonical_bytes,
            evidence,
        });
        request
    }

    fn retarget_compensation_event(mut request: EventCommitRequest) -> EventCommitRequest {
        let mut event: arkret_wire::Event =
            serde_json::from_value(request.event.envelope.clone()).unwrap();
        event.actor_seq += 1;
        event
            .refresh_content_bound_identity_with_digest_suite(request.event.digest_suite)
            .unwrap();
        request.event.event_id = event.event_id.to_string();
        request.event.actor_seq = event.actor_seq;
        request.event.canonical_digest = event
            .event_digest_with_digest_suite(request.event.digest_suite)
            .unwrap();
        request.event.canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        request.event.envelope = serde_json::to_value(event).unwrap();
        request.control_proposal_ingress = Some(
            arkret_state::state::store::ControlProposalIngress::AckRequired(
                compensation_control_ack(
                    request.event.realm_id.as_deref().unwrap(),
                    &request.event.canonical_digest,
                    request.event.received_at,
                ),
            ),
        );
        let record = request.membership_compensation_evidence.as_mut().unwrap();
        record.event_id = request.event.event_id.clone();
        record.event_digest = request.event.canonical_digest.clone();
        request
    }

    #[cfg(feature = "fault-injection")]
    fn typed_event_request(
        kind: &str,
        realm_id: &str,
        actor_id: &str,
        payload: serde_json::Value,
    ) -> EventCommitRequest {
        let mut request = event_request(
            uuid::Uuid::now_v7().to_string(),
            realm_id.to_owned(),
            actor_id,
            None,
        );
        let mut event: arkret_wire::Event =
            serde_json::from_value(request.event.envelope.clone()).unwrap();
        event.kind = kind.into();
        event.payload = serde_json::from_value(payload).unwrap();
        event
            .refresh_content_bound_identity_with_digest_suite(request.event.digest_suite)
            .unwrap();
        request.event.event_id = event.event_id.to_string();
        request.event.kind = kind.to_owned();
        request.event.schema_id = format!("ak.schema.{}.v1", kind.replace('.', "_"));
        request.event.canonical_digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        request.event.canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        request.event.envelope = serde_json::to_value(event).unwrap();
        request
    }

    fn cascade_event_request(seed: &str, realm_id: &str, actor_id: &str) -> EventCommitRequest {
        let mut request = event_request(seed.to_owned(), realm_id.to_owned(), actor_id, None);
        let event: arkret_wire::Event =
            serde_json::from_value(request.event.envelope.clone()).unwrap();
        request.event.actor_id = event.actor_id.to_string();
        request
    }

    fn cascade_agent_event_request(
        seed: &str,
        realm_id: &str,
        principal: &str,
    ) -> EventCommitRequest {
        let mut request = cascade_event_request(seed, realm_id, principal);
        let mut event: arkret_wire::Event =
            serde_json::from_value(request.event.envelope.clone()).unwrap();
        event.actor_id = arkret_wire::ActorId::hosted_principal(
            arkret_wire::DidCoreId::new(principal).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:agent-station.example").unwrap(),
        );
        event.kind = arkret_wire::EventKind::MemberState;
        event.payload = serde_json::from_value(serde_json::json!({
            "member_id": event.actor_id,
            "membership": "leave",
            "reason": seed
        }))
        .unwrap();
        event
            .refresh_content_bound_identity_with_digest_suite(request.event.digest_suite)
            .unwrap();
        request.event.event_id = event.event_id.to_string();
        request.event.actor_id = event.actor_id.to_string();
        request.event.kind = event.kind.to_string();
        request.event.schema_id = "arkret://events/member/state/v1".to_owned();
        request.event.canonical_digest = event
            .event_digest_with_digest_suite(request.event.digest_suite)
            .unwrap();
        request.event.canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        request.event.envelope = serde_json::to_value(event).unwrap();
        request.control_proposal_ingress = Some(
            arkret_state::state::store::ControlProposalIngress::AckRequired(
                compensation_control_ack(
                    realm_id,
                    &request.event.canonical_digest,
                    request.event.received_at,
                ),
            ),
        );
        request
    }

    fn emergency_terminal_request(realm_id: &str) -> EventCommitRequest {
        let mut request = cascade_event_request(
            "emergency-terminal",
            realm_id,
            "ak:did_core:web:emergency-controller.example",
        );
        let mut event: arkret_wire::Event =
            serde_json::from_value(request.event.envelope.clone()).unwrap();
        event.executed_by = Some(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:moderator.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        )));
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
        agent_ids: Vec<arkret_wire::ActorId>,
    ) -> arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupRecord {
        use arkret_models_collaboration::governance::agent_membership_cascade::{
            AgentCleanupRecord, AgentMembershipCascadeSchema,
        };

        let accepted_at = controller.event.received_at;
        let mut record = AgentCleanupRecord {
            schema: AgentMembershipCascadeSchema::V1,
            realm_id: arkret_wire::RealmId::new(realm_id.to_owned()).unwrap(),
            controller_account_id: serde_json::from_str::<arkret_wire::ActorId>(
                &controller.event.actor_id,
            )
            .unwrap()
            .as_account_id()
            .cloned()
            .unwrap(),
            controller_membership_generation_ref: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x42; 32],
            ),
            initiator_actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:moderator.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            )),
            controller_terminal_event_id: arkret_wire::EventId::new(
                controller.event.event_id.clone(),
            )
            .unwrap(),
            expected_agent_ids: agent_ids,
            cleanup_intent_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
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
        let actor_did = "did:web:alice.example";
        let actor_id = "ak:did_core:web:alice.example";
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
            arkret_wire::DidCoreId::new(actor_id.to_owned()).unwrap(),
            arkret_wire::DidCoreId::new(actor_id.to_owned()).unwrap(),
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
        let producer = arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            proof_purpose: None,
            verification_method: arkret_wire::DidUrl::new(format!(
                "{actor_did}#ak:device:01904100-0000-7000-8000-000000000001"
            ))
            .unwrap(),
            event_digest: event_digest.clone(),
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at,
            domain: None,
            audience: None,
            jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
        };
        let admission = arkret_wire::StationAdmissionProof {
            kind: arkret_wire::StationAdmissionProofKind::StationAdmission,
            verification_method: arkret_wire::DidUrl::new(format!(
                "{actor_did}#station-admission-key"
            ))
            .unwrap(),
            event_digest: event_digest.clone(),
            producer_proof_digest: arkret_wire::StationAdmissionProof::producer_proof_digest(
                &producer,
            )
            .unwrap(),
            producer_verification_method: producer.verification_method.clone(),
            producer_signing_key_did: arkret_wire::DidKey::new("did:key:z6Mkhfixture").unwrap(),
            producer_signer_resolution_evidence_ref: None,
            producer_signer_resolution_evidence_digest: None,
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
            jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
        };
        event.proofs = vec![producer.into(), admission.into()];
        event
            .validate_station_admission_binding(arkret_canonical::DigestSuite::Sha256)
            .expect("fixture accepted Event proof set");
        let event_id = event.event_id.to_string();
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        EventCommitRequest {
            governance_dependencies: Vec::new(),
            membership_compensation_evidence: None,
            device_pairing_authorization: None,
            contact_projection: None,
            consent_projection: None,
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
        let station_id = arkret_wire::DidCoreId::new("ak:did_core:web:soland.example").unwrap();
        let created_at = Utc::now();
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::DeviceRevoke.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(realm_id.clone()).unwrap(),
            },
            actor_id.clone(),
            station_id.clone(),
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
            principal_id: actor_id.clone(),
            station_id,
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
                governance_dependencies: Vec::new(),
                membership_compensation_evidence: None,
                device_pairing_authorization: None,
                contact_projection: None,
                consent_projection: None,
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
        event.executed_by = Some(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::project_did_to_core_id(
                &arkret_wire::Did::new("did:web:controller.example").unwrap(),
            )
            .unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        )));
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

    #[test]
    fn non_reducer_event_rejects_ingress_and_stores_no_control_proposal_ack() {
        let mut request = event_request(
            typed_id("ak:event:"),
            realm_id(),
            "ak:did_core:web:alice.example",
            None,
        );
        let (control_request, _) = device_revoke_request();
        request.control_proposal_ingress = control_request.control_proposal_ingress;
        let mut staged = std::collections::BTreeMap::new();
        assert!(matches!(
            stage_control_proposal_ack(&mut staged, &request),
            Err(PersistenceError::Conflict(reason))
                if reason.contains("non-Control Event cannot carry Control Proposal authority")
        ));

        request.control_proposal_ingress = None;
        stage_control_proposal_ack(&mut staged, &request)
            .expect("a non-reducer Event requires no Control Proposal ingress classification");
        assert!(
            staged.is_empty(),
            "a non-reducer Event must not gain a durable Control Proposal Ack"
        );
    }

    #[tokio::test]
    async fn exact_replay_is_noop_but_forged_preimage_is_rejected_before_lookup() {
        let store = SolandMemoryPersistenceStore::new();
        let request = event_request(
            "exact-replay".to_owned(),
            realm_id(),
            "ak:did_core:web:replay.example",
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
    async fn membership_compensation_evidence_is_atomic_replay_safe_and_single_use() {
        let store = SolandMemoryPersistenceStore::new();
        let request = membership_compensation_request();
        let event_id = request.event.event_id.clone();

        let accepted = store.commit_event(request.clone()).await.unwrap();
        assert!(accepted.event_inserted);
        let stored = store
            .events
            .membership_compensation_evidence(&event_id)
            .await
            .unwrap()
            .expect("accepted compensation evidence is durable");
        assert_eq!(
            stored.canonical_bytes,
            request
                .membership_compensation_evidence
                .as_ref()
                .unwrap()
                .canonical_bytes
        );

        let replay = store.commit_event(request.clone()).await.unwrap();
        assert_eq!(replay, soland_storage::EventCommitOutcome::default());

        let mut changed_carrier = request.clone();
        let changed = changed_carrier
            .membership_compensation_evidence
            .as_mut()
            .unwrap();
        changed.evidence.single_use_cas_token.signature.created_at += Duration::seconds(1);
        changed.canonical_bytes =
            arkret_canonical::canonical_json_bytes(&changed.evidence).unwrap();
        assert!(matches!(
            store.commit_event(changed_carrier).await,
            Err(PersistenceError::Conflict(reason))
                if reason.contains("Event replay changed its compensation evidence")
        ));

        let second_event = retarget_compensation_event(request);
        assert!(matches!(
            store.commit_event(second_event).await,
            Err(PersistenceError::Conflict(reason))
                if reason.contains("compensation delegation was already consumed")
        ));
    }

    #[cfg(feature = "fault-injection")]
    #[tokio::test]
    async fn franking_target_proof_faults_distinguish_rollback_from_response_loss() {
        let realm_id = realm_id();
        let target = typed_event_request(
            arkret_wire::EventKind::MessageCreate.as_str(),
            &realm_id,
            "ak:did_core:web:message-sender.example",
            serde_json::json!({"encrypted_content": {"ciphertext": "fixture"}}),
        );
        let target_event_id = target.event.event_id.clone();
        let received_by =
            arkret_wire::DidCoreId::new("ak:did_core:web:soland.example".to_owned()).unwrap();
        let proof = typed_event_request(
            arkret_wire::EventKind::ModerationFrankingProof.as_str(),
            &realm_id,
            received_by.as_str(),
            serde_json::json!({"event_id": target_event_id}),
        );
        let proof_event_id = proof.event.event_id.clone();
        let batch = EventBatchCommitRequest {
            events: vec![target, proof],
            agent_approval_nonce: None,
            franking_replay_nonce: None,
            applet_record: None,
            applet_authoring_preview: None,
            agent_membership_cascade: None,
        };

        let before_store = SolandMemoryPersistenceStore::new();
        before_store.fault_injector().arm(crate::FaultPlan::new(
            crate::FaultPoint::EventCommit,
            crate::FaultTiming::Before,
            1,
        ));
        let before_error = before_store
            .commit_event_batch(batch.clone())
            .await
            .unwrap_err();
        assert!(matches!(before_error, PersistenceError::Database(_)));
        assert!(
            !before_store
                .events
                .data
                .lock()
                .contains_key(&target_event_id)
        );
        assert!(
            !before_store
                .events
                .data
                .lock()
                .contains_key(&proof_event_id)
        );
        assert!(
            before_store
                .events
                .franking_proofs_for_target(&realm_id, &received_by, &target_event_id)
                .await
                .unwrap()
                .is_empty()
        );

        let response_loss_store = SolandMemoryPersistenceStore::new();
        response_loss_store
            .fault_injector()
            .arm(crate::FaultPlan::new(
                crate::FaultPoint::EventCommit,
                crate::FaultTiming::After,
                1,
            ));
        let response_loss = response_loss_store
            .commit_event_batch(batch.clone())
            .await
            .unwrap_err();
        assert!(matches!(response_loss, PersistenceError::Database(_)));
        assert!(
            response_loss_store
                .events
                .data
                .lock()
                .contains_key(&target_event_id)
        );
        assert!(
            response_loss_store
                .events
                .data
                .lock()
                .contains_key(&proof_event_id)
        );
        assert_eq!(
            response_loss_store
                .events
                .franking_proofs_for_target(&realm_id, &received_by, &target_event_id)
                .await
                .unwrap()
                .len(),
            1
        );

        let retry = response_loss_store
            .commit_event_batch(batch)
            .await
            .expect("an exact retry after response loss is a no-op");
        assert_eq!(retry, soland_storage::EventCommitOutcome::default());
        assert_eq!(
            response_loss_store
                .events
                .franking_proofs_for_target(&realm_id, &received_by, &target_event_id)
                .await
                .unwrap()
                .len(),
            1,
            "the retry must not materialize a second proof Event"
        );
    }

    #[tokio::test]
    async fn franking_nonce_replay_rolls_back_the_competing_report_event() {
        let store = SolandMemoryPersistenceStore::new();
        let realm_id = realm_id();
        let received_by = "ak:did_core:web:receiver.example";
        let replay_nonce = "nonce_0123456789";
        let mut first = event_request(
            typed_id("ak:event:"),
            realm_id.clone(),
            "ak:did_core:web:reporter_id-one.example",
            None,
        );
        first.event.kind = arkret_wire::EventKind::SelfModerationReport.to_string();
        first.event.envelope["payload"] = serde_json::json!({
            "franking_proof": {
                "received_by": received_by,
                "replay_nonce": replay_nonce,
            }
        });
        let first_id = first.event.event_id.clone();
        store
            .commit_event_batch(EventBatchCommitRequest {
                events: vec![first],
                agent_approval_nonce: None,
                franking_replay_nonce: Some(FrankingReplayNonceCommit {
                    realm_id: realm_id.clone(),
                    received_by: arkret_wire::DidCoreId::new(received_by.to_owned()).unwrap(),
                    replay_nonce: replay_nonce.to_owned(),
                    report_event_id: first_id.clone(),
                    consumed_at: Utc::now(),
                }),
                applet_record: None,
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            })
            .await
            .unwrap();

        let mut competing = event_request(
            typed_id("ak:event:"),
            realm_id.clone(),
            "ak:did_core:web:reporter_id-two.example",
            None,
        );
        competing.event.kind = arkret_wire::EventKind::SelfModerationReport.to_string();
        competing.event.envelope["payload"] = serde_json::json!({
            "franking_proof": {
                "received_by": received_by,
                "replay_nonce": replay_nonce,
            }
        });
        let competing_id = competing.event.event_id.clone();
        let error = store
            .commit_event_batch(EventBatchCommitRequest {
                events: vec![competing],
                agent_approval_nonce: None,
                franking_replay_nonce: Some(FrankingReplayNonceCommit {
                    realm_id,
                    received_by: arkret_wire::DidCoreId::new(received_by.to_owned()).unwrap(),
                    replay_nonce: replay_nonce.to_owned(),
                    report_event_id: competing_id.clone(),
                    consumed_at: Utc::now(),
                }),
                applet_record: None,
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(error, PersistenceError::Conflict(reason) if reason == "duplicate_conflict")
        );
        assert!(store.events.data.lock().contains_key(&first_id));
        assert!(!store.events.data.lock().contains_key(&competing_id));
        assert_eq!(store.franking_replay_nonces.lock().len(), 1);
    }

    #[tokio::test]
    async fn franking_nonce_ledger_evicts_only_expired_rows() {
        let store = SolandMemoryPersistenceStore::new();
        let realm_id = realm_id();
        let received_by =
            arkret_wire::DidCoreId::new("ak:did_core:web:receiver-expiry.example".to_owned())
                .unwrap();
        let first_consumed_at = Utc::now();
        let old_key = (
            realm_id.clone(),
            received_by.clone(),
            "nonce_old_0123456789".to_owned(),
        );
        store.franking_replay_nonces.lock().insert(
            old_key.clone(),
            FrankingReplayNonceCommit {
                realm_id: realm_id.clone(),
                received_by: received_by.clone(),
                replay_nonce: old_key.2.clone(),
                report_event_id: typed_id("ak:event:"),
                consumed_at: first_consumed_at,
            },
        );
        let consumed_at = soland_storage::franking_replay_nonce_expires_at(first_consumed_at)
            .expect("fixture expiry");
        let mut just_before_report = event_request(
            typed_id("ak:event:"),
            realm_id.clone(),
            "ak:did_core:web:reporter-before-expiry.example",
            None,
        );
        just_before_report.event.kind = arkret_wire::EventKind::SelfModerationReport.to_string();
        just_before_report.event.envelope["payload"] = serde_json::json!({
            "franking_proof": {
                "received_by": received_by.as_str(),
                "replay_nonce": old_key.2.as_str(),
            }
        });
        let just_before_event_id = just_before_report.event.event_id.clone();
        let just_before_error = store
            .commit_event_batch(EventBatchCommitRequest {
                events: vec![just_before_report],
                agent_approval_nonce: None,
                franking_replay_nonce: Some(FrankingReplayNonceCommit {
                    realm_id: realm_id.clone(),
                    received_by: received_by.clone(),
                    replay_nonce: old_key.2.clone(),
                    report_event_id: just_before_event_id.clone(),
                    consumed_at: consumed_at - chrono::TimeDelta::microseconds(1),
                }),
                applet_record: None,
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            just_before_error,
            PersistenceError::Conflict(reason) if reason == "duplicate_conflict"
        ));
        assert!(!store.events.data.lock().contains_key(&just_before_event_id));
        assert!(store.franking_replay_nonces.lock().contains_key(&old_key));

        let replay_nonce = "nonce_new_0123456789";
        let mut report = event_request(
            typed_id("ak:event:"),
            realm_id.clone(),
            "ak:did_core:web:reporter-expiry.example",
            None,
        );
        report.event.kind = arkret_wire::EventKind::SelfModerationReport.to_string();
        report.event.envelope["payload"] = serde_json::json!({
            "franking_proof": {
                "received_by": received_by.as_str(),
                "replay_nonce": replay_nonce,
            }
        });
        let report_event_id = report.event.event_id.clone();
        store
            .commit_event_batch(EventBatchCommitRequest {
                events: vec![report],
                agent_approval_nonce: None,
                franking_replay_nonce: Some(FrankingReplayNonceCommit {
                    realm_id: realm_id.clone(),
                    received_by: received_by.clone(),
                    replay_nonce: replay_nonce.to_owned(),
                    report_event_id,
                    consumed_at,
                }),
                applet_record: None,
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            })
            .await
            .unwrap();
        let ledger = store.franking_replay_nonces.lock();
        assert!(!ledger.contains_key(&old_key));
        assert_eq!(ledger.len(), 1);
    }

    #[tokio::test]
    async fn franking_nonce_ledger_capacity_fails_closed_without_evicting_active_rows() {
        let store = SolandMemoryPersistenceStore::new();
        let realm_id = realm_id();
        let received_by =
            arkret_wire::DidCoreId::new("ak:did_core:web:receiver-cap.example".to_owned()).unwrap();
        let consumed_at = Utc::now();
        {
            let mut ledger = store.franking_replay_nonces.lock();
            for index in 0..soland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE {
                let replay_nonce = format!("active_nonce_{index:08}");
                ledger.insert(
                    (realm_id.clone(), received_by.clone(), replay_nonce.clone()),
                    FrankingReplayNonceCommit {
                        realm_id: realm_id.clone(),
                        received_by: received_by.clone(),
                        replay_nonce,
                        report_event_id: format!("ak:event:capacity-{index}"),
                        consumed_at,
                    },
                );
            }
        }
        let replay_nonce = "nonce_over_capacity_0123456789";
        let mut report = event_request(
            typed_id("ak:event:"),
            realm_id.clone(),
            "ak:did_core:web:reporter-cap.example",
            None,
        );
        report.event.kind = arkret_wire::EventKind::SelfModerationReport.to_string();
        report.event.envelope["payload"] = serde_json::json!({
            "franking_proof": {
                "received_by": received_by.as_str(),
                "replay_nonce": replay_nonce,
            }
        });
        let report_event_id = report.event.event_id.clone();
        let error = store
            .commit_event_batch(EventBatchCommitRequest {
                events: vec![report],
                agent_approval_nonce: None,
                franking_replay_nonce: Some(FrankingReplayNonceCommit {
                    realm_id,
                    received_by,
                    replay_nonce: replay_nonce.to_owned(),
                    report_event_id: report_event_id.clone(),
                    consumed_at: consumed_at + chrono::TimeDelta::seconds(1),
                }),
                applet_record: None,
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            PersistenceError::Conflict(reason) if reason == "duplicate_conflict"
        ));
        assert!(!store.events.data.lock().contains_key(&report_event_id));
        assert_eq!(
            store.franking_replay_nonces.lock().len(),
            soland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE
        );
    }

    #[tokio::test]
    async fn agent_membership_cascade_commits_exact_sets_and_durable_cleanup_atomically() {
        let store = SolandMemoryPersistenceStore::new();
        let realm_id = realm_id();
        let controller = cascade_event_request(
            "controller-terminal",
            &realm_id,
            "ak:did_core:web:controller.example",
        );
        let agent_a = cascade_agent_event_request(
            "agent-a-leave",
            &realm_id,
            "ak:did_core:web:agent-a.example",
        );
        let agent_b = cascade_agent_event_request(
            "agent-b-leave",
            &realm_id,
            "ak:did_core:web:agent-b.example",
        );
        let controller_event_id =
            arkret_wire::EventId::new(controller.event.event_id.clone()).unwrap();
        let agent_event_ids = vec![
            arkret_wire::EventId::new(agent_a.event.event_id.clone()).unwrap(),
            arkret_wire::EventId::new(agent_b.event.event_id.clone()).unwrap(),
        ];

        let mut incomplete = EventBatchCommitRequest {
            events: vec![controller.clone(), agent_a.clone()],
            agent_approval_nonce: None,
            franking_replay_nonce: None,
            applet_record: None,
            applet_authoring_preview: None,
            agent_membership_cascade: Some(AgentMembershipCascadeCommit::AtomicSelfLeave {
                controller_transition_event_id: controller_event_id.clone(),
                agent_transition_event_ids: agent_event_ids.clone(),
                expected_agent_ids: vec![
                    soland_storage::admitted_cascade_agent_id(&agent_a.event).unwrap(),
                    soland_storage::admitted_cascade_agent_id(&agent_b.event).unwrap(),
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
        let mut duplicate_agent = incomplete.clone();
        if let Some(AgentMembershipCascadeCommit::AtomicSelfLeave {
            expected_agent_ids, ..
        }) = duplicate_agent.agent_membership_cascade.as_mut()
        {
            expected_agent_ids[1] = expected_agent_ids[0].clone();
        }
        assert!(matches!(store.commit_event_batch(duplicate_agent).await,
            Err(PersistenceError::Conflict(reason)) if reason.contains("actor set mismatch")));
        let mut wrong_station = incomplete.clone();
        if let Some(AgentMembershipCascadeCommit::AtomicSelfLeave {
            expected_agent_ids, ..
        }) = wrong_station.agent_membership_cascade.as_mut()
        {
            expected_agent_ids[0] = arkret_wire::ActorId::hosted_principal(
                expected_agent_ids[0].signing_principal_id().clone(),
                arkret_wire::DidCoreId::new("ak:did_core:web:wrong-station.example").unwrap(),
            );
        }
        assert!(matches!(store.commit_event_batch(wrong_station).await,
            Err(PersistenceError::Conflict(reason)) if reason.contains("actor set mismatch")));
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
            arkret_wire::ActorId::hosted_principal(
                arkret_wire::DidCoreId::new("ak:did_core:web:emergency-agent-a.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:agent-station.example").unwrap(),
            ),
            arkret_wire::ActorId::hosted_principal(
                arkret_wire::DidCoreId::new("ak:did_core:web:emergency-agent-b.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:agent-station.example").unwrap(),
            ),
        ];
        let record = cleanup_record(&terminal, &realm_id, expected_agent_ids.clone());
        let cleanup_digest = record.cleanup_intent_digest.clone();
        let terminal_event_id = record.controller_terminal_event_id.clone();
        store
            .commit_event_batch(EventBatchCommitRequest {
                events: vec![terminal.clone()],
                agent_approval_nonce: None,
                franking_replay_nonce: None,
                applet_record: None,
                applet_authoring_preview: None,
                agent_membership_cascade: Some(AgentMembershipCascadeCommit::EmergencyTerminal {
                    record: Box::new(record.clone()),
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

        let cleanup_a = cascade_agent_event_request(
            "emergency-agent-a-leave",
            &realm_id,
            "ak:did_core:web:emergency-agent-a.example",
        );
        let cleanup_b = cascade_agent_event_request(
            "emergency-agent-b-leave",
            &realm_id,
            "ak:did_core:web:emergency-agent-b.example",
        );
        let cleanup_event_ids = vec![
            arkret_wire::EventId::new(cleanup_a.event.event_id.clone()).unwrap(),
            arkret_wire::EventId::new(cleanup_b.event.event_id.clone()).unwrap(),
        ];
        store
            .commit_event_batch(EventBatchCommitRequest {
                events: vec![cleanup_a, cleanup_b],
                agent_approval_nonce: None,
                franking_replay_nonce: None,
                applet_record: None,
                applet_authoring_preview: None,
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
        assert!(completed.completed_at.is_some());
        assert_eq!(
            completed.agent_transition_event_ids,
            Some(cleanup_event_ids)
        );
    }

    #[test]
    fn cascade_agent_projection_rejects_same_principal_wrong_station_or_member() {
        let mut request = cascade_agent_event_request(
            "agent-identity-binding",
            &realm_id(),
            "ak:did_core:web:agent-a.example",
        );
        let expected = arkret_wire::DidCoreId::new("ak:did_core:web:agent-a.example").unwrap();
        assert_eq!(
            soland_storage::admitted_cascade_agent_id(&request.event).unwrap(),
            arkret_wire::ActorId::hosted_principal(
                expected.clone(),
                arkret_wire::DidCoreId::new("ak:did_core:web:agent-station.example").unwrap(),
            )
        );
        let original_actor = request.event.actor_id.clone();
        request.event.actor_id = arkret_wire::ActorId::hosted_principal(
            expected.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:wrong-station.example").unwrap(),
        )
        .to_string();
        assert!(soland_storage::admitted_cascade_agent_id(&request.event).is_err());
        request.event.actor_id = original_actor;
        request.event.envelope["payload"]["member_id"] =
            serde_json::to_value(arkret_wire::ActorId::hosted_principal(
                expected,
                arkret_wire::DidCoreId::new("ak:did_core:web:wrong-station.example").unwrap(),
            ))
            .unwrap();
        assert!(soland_storage::admitted_cascade_agent_id(&request.event).is_err());
    }

    #[tokio::test]
    async fn device_revoke_acceptance_replay_gate_seal_and_cleanup_are_one_state_machine() {
        let store = SolandMemoryPersistenceStore::new();
        let (request, selector) = device_revoke_request();
        let proposal_digest = request.event.canonical_digest.clone();
        let proposal_event_id = request.event.event_id.clone();

        let accepted = store.commit_event(request.clone()).await.unwrap();
        assert!(accepted.event_inserted);
        {
            let stored_acks = store.events.control_proposal_acks.lock();
            assert_eq!(
                stored_acks
                    .get(&proposal_digest)
                    .map(|ack| ack.proposal_digest.as_str()),
                Some(proposal_digest.as_str()),
                "durable Ack must be indexed by the canonical proposal digest"
            );
            assert!(
                !stored_acks.contains_key(&proposal_event_id),
                "the EventId must never become the internal proposal-Ack key"
            );
        }
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
            "ak:did_core:web:alice.example",
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
                        sender: selector.principal_id.to_string(),
                        recipient: selector.principal_id.to_string(),
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
            station_id: selector.station_id.clone(),
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
        let proposal_digest = request.event.canonical_digest.clone();
        request.projections.push(ProjectionEventRecord {
            event_id: event_id.clone(),
            realm_id: "not-a-typed-realm".to_owned(),
            event_kind: arkret_wire::EventKind::DeviceRevoke.to_string(),
            operation_kind: "revoke".to_owned(),
            operation_id: None,
            sender: Some(selector.principal_id.to_string()),
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
                .contains_key(&proposal_digest)
        );
        assert!(
            !store
                .events
                .control_proposal_acks
                .lock()
                .contains_key(&event_id),
            "the EventId must not be retained as a compatibility Ack key"
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
        let applet_scope = test_applet_scope();
        let original_record = test_applet_record(
            serde_json::json!({
                "status": "installed",
                "revoked_at": null,
                "bot_actor_id": "ak:did_core:web:fixture-bot.example",
                "bot_actor_station_id": "ak:did_core:web:soland.example",
                "package": {"namespaces": {}},
                "ghosts": [],
            }),
            &applet_scope,
            &applet_id,
        );
        let applet_identity =
            test_applet_identity(&applet_id, "ak:did_core:web:fixture-bot.example");
        store.applets.identities.lock().insert(
            (
                applet_id.clone(),
                "ak:did_core:web:soland.example".to_owned(),
            ),
            applet_identity.clone(),
        );
        store.applets.records.lock().insert(
            test_applet_key(&applet_id, &applet_scope),
            original_record.clone(),
        );
        let principal_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:bridge.example".to_owned()).unwrap();
        let idempotency_key = "ghost-batch-conflict";
        let now = Utc::now();
        store.idempotency_keys.data.lock().insert(
            (principal_id.clone(), idempotency_key.to_owned()),
            IdempotencyRecord {
                principal_id: principal_id.clone(),
                idempotency_key: idempotency_key.to_owned(),
                service_id: arkret_wire::DidCoreId::new(
                    "ak:did_core:web:soland.example".to_owned(),
                )
                .unwrap(),
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
                principal_id.as_str(),
                Some(IdempotencyRecord {
                    principal_id: principal_id.clone(),
                    idempotency_key: idempotency_key.to_owned(),
                    service_id: arkret_wire::DidCoreId::new(
                        "ak:did_core:web:soland.example".to_owned(),
                    )
                    .unwrap(),
                    request_hash: "sha256:competing".to_owned(),
                    response_status: 201,
                    response_body: serde_json::json!({"first": false}),
                    created_at: now,
                    expires_at: now + Duration::hours(1),
                }),
            )],
            agent_approval_nonce: None,
            franking_replay_nonce: None,
            applet_record: Some(AppletRecordCommit {
                applet_id: arkret_wire::AppletId::new(applet_id.clone()).unwrap(),
                identity: existing_identity_commit(&applet_identity),
                expected_record: Some(original_record),
                record: test_applet_record(
                    serde_json::json!({
                        "status": "installed",
                        "revoked_at": null,
                        "bot_actor_id": "ak:did_core:web:fixture-bot.example",
                        "bot_actor_station_id": "ak:did_core:web:soland.example",
                        "package": {"namespaces": {}},
                        "ghosts": [{
                            "ghost_actor_id": "ak:did_core:web:bridge.example:ghost:one",
                            "actor_station_id": "ak:did_core:web:soland.example",
                            "external_id": "one",
                        }],
                    }),
                    &applet_scope,
                    &applet_id,
                ),
            }),
            applet_authoring_preview: None,
            agent_membership_cascade: None,
        };

        assert!(store.commit_event_batch(request).await.is_err());
        assert!(!store.events.data.lock().contains_key(&event_id));
        assert_eq!(
            store.applets.records.lock()[&test_applet_key(&applet_id, &applet_scope)]["ghosts"],
            serde_json::json!([])
        );
    }

    #[tokio::test]
    async fn ghost_batch_appends_without_replacing_existing_ghosts() {
        let store = SolandMemoryPersistenceStore::new();
        let applet_id = typed_id("ak:applet:");
        let applet_scope = test_applet_scope();
        let preview_subject = "ghost-preview-subject".to_owned();
        let preview_request = "sha256:ghost-preview-request".to_owned();
        let now = Utc::now();
        store.applets.authoring_previews.lock().insert(
            preview_subject.clone(),
            AppletAuthoringPreviewRecord {
                subject_key: preview_subject.clone(),
                basis_digest: "sha256:ghost-preview-basis".to_owned(),
                request_digest: preview_request.clone(),
                signed_request: serde_json::json!({"signed": true}),
                issued_at: now,
                expires_at: now + Duration::minutes(5),
            },
        );
        store.applets.records.lock().insert(
            test_applet_key(&applet_id, &applet_scope),
            test_applet_record(
                serde_json::json!({
                    "status": "installed",
                    "revoked_at": null,
                    "bot_actor_id": "ak:did_core:web:fixture-bot.example",
                    "bot_actor_station_id": "ak:did_core:web:soland.example",
                    "package": {"namespaces": {}},
                    "ghosts": [{
                        "ghost_actor_id": "ak:did_core:web:bridge.example:ghost:first",
                        "actor_station_id": "ak:did_core:web:soland.example",
                        "external_id": "first",
                    }],
                }),
                &applet_scope,
                &applet_id,
            ),
        );
        let applet_identity =
            test_applet_identity(&applet_id, "ak:did_core:web:fixture-bot.example");
        store.applets.identities.lock().insert(
            (
                applet_id.clone(),
                "ak:did_core:web:soland.example".to_owned(),
            ),
            applet_identity.clone(),
        );
        let request = EventBatchCommitRequest {
            events: vec![event_request(
                typed_id("ak:event:"),
                realm_id(),
                "ak:did_core:web:bridge.example:ghost:second",
                None,
            )],
            agent_approval_nonce: None,
            franking_replay_nonce: None,
            applet_record: Some(AppletRecordCommit {
                applet_id: arkret_wire::AppletId::new(applet_id.clone()).unwrap(),
                identity: existing_identity_commit(&applet_identity),
                expected_record: Some(test_applet_record(
                    serde_json::json!({
                        "status": "installed",
                        "revoked_at": null,
                        "bot_actor_id": "ak:did_core:web:fixture-bot.example",
                        "bot_actor_station_id": "ak:did_core:web:soland.example",
                        "package": {"namespaces": {}},
                        "ghosts": [{
                            "ghost_actor_id": "ak:did_core:web:bridge.example:ghost:first",
                            "actor_station_id": "ak:did_core:web:soland.example",
                            "external_id": "first",
                        }],
                    }),
                    &applet_scope,
                    &applet_id,
                )),
                record: test_applet_record(
                    serde_json::json!({
                        "status": "installed",
                        "revoked_at": null,
                        "bot_actor_id": "ak:did_core:web:fixture-bot.example",
                        "bot_actor_station_id": "ak:did_core:web:soland.example",
                        "package": {"namespaces": {}},
                        "ghosts": [{
                            "ghost_actor_id": "ak:did_core:web:bridge.example:ghost:first",
                            "actor_station_id": "ak:did_core:web:soland.example",
                            "external_id": "first",
                        }, {
                            "ghost_actor_id": "ak:did_core:web:bridge.example:ghost:second",
                            "actor_station_id": "ak:did_core:web:soland.example",
                            "external_id": "second",
                        }],
                    }),
                    &applet_scope,
                    &applet_id,
                ),
            }),
            applet_authoring_preview: Some(AppletAuthoringPreviewCommit {
                subject_key: preview_subject.clone(),
                request_digest: preview_request,
            }),
            agent_membership_cascade: None,
        };

        store.commit_event_batch(request).await.unwrap();
        assert_eq!(
            store.applets.records.lock()[&test_applet_key(&applet_id, &applet_scope)]["ghosts"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(
            !store
                .applets
                .authoring_previews
                .lock()
                .contains_key(&preview_subject),
            "Applet Event batch must atomically consume the current preview generation"
        );

        let stale_preview_subject = "stale-ghost-preview-subject".to_owned();
        let stale_preview_request = "sha256:stale-ghost-preview-request".to_owned();
        store.applets.authoring_previews.lock().insert(
            stale_preview_subject.clone(),
            AppletAuthoringPreviewRecord {
                subject_key: stale_preview_subject.clone(),
                basis_digest: "sha256:stale-ghost-preview-basis".to_owned(),
                request_digest: stale_preview_request.clone(),
                signed_request: serde_json::json!({"signed": "stale"}),
                issued_at: now,
                expires_at: now + Duration::minutes(5),
            },
        );
        let stale_event_id = typed_id("ak:event:");
        let stale = EventBatchCommitRequest {
            events: vec![event_request(
                stale_event_id.clone(),
                realm_id(),
                "ak:did_core:web:bridge.example:ghost:third",
                None,
            )],
            agent_approval_nonce: None,
            franking_replay_nonce: None,
            applet_record: Some(AppletRecordCommit {
                applet_id: arkret_wire::AppletId::new(applet_id.clone()).unwrap(),
                identity: existing_identity_commit(&applet_identity),
                expected_record: Some(test_applet_record(
                    serde_json::json!({
                        "status": "installed",
                        "revoked_at": null,
                        "bot_actor_id": "ak:did_core:web:fixture-bot.example",
                        "bot_actor_station_id": "ak:did_core:web:soland.example",
                        "package": {"namespaces": {}},
                        "ghosts": [{
                            "ghost_actor_id": "ak:did_core:web:bridge.example:ghost:first",
                            "actor_station_id": "ak:did_core:web:soland.example",
                            "external_id": "first",
                        }],
                    }),
                    &applet_scope,
                    &applet_id,
                )),
                record: test_applet_record(
                    serde_json::json!({
                        "status": "installed",
                        "revoked_at": null,
                        "bot_actor_id": "ak:did_core:web:fixture-bot.example",
                        "bot_actor_station_id": "ak:did_core:web:soland.example",
                        "package": {"namespaces": {}},
                        "ghosts": [{
                            "ghost_actor_id": "ak:did_core:web:bridge.example:ghost:first",
                            "actor_station_id": "ak:did_core:web:soland.example",
                            "external_id": "first",
                        }, {
                            "ghost_actor_id": "ak:did_core:web:bridge.example:ghost:third",
                            "actor_station_id": "ak:did_core:web:soland.example",
                            "external_id": "third",
                        }],
                    }),
                    &applet_scope,
                    &applet_id,
                ),
            }),
            applet_authoring_preview: Some(AppletAuthoringPreviewCommit {
                subject_key: stale_preview_subject.clone(),
                request_digest: stale_preview_request,
            }),
            agent_membership_cascade: None,
        };

        let error = store.commit_event_batch(stale).await.unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::CasConflict)
        );
        assert!(!store.events.data.lock().contains_key(&stale_event_id));
        assert!(
            store
                .applets
                .authoring_previews
                .lock()
                .contains_key(&stale_preview_subject),
            "failed Applet Event batch must roll preview consumption back"
        );
        let applets = store.applets.records.lock();
        let ghosts = applets[&test_applet_key(&applet_id, &applet_scope)]["ghosts"]
            .as_array()
            .unwrap();
        assert_eq!(ghosts.len(), 2);
        assert!(ghosts.iter().any(|ghost| {
            ghost["ghost_actor_id"] == "ak:did_core:web:bridge.example:ghost:second"
        }));
        assert!(!ghosts.iter().any(|ghost| {
            ghost["ghost_actor_id"] == "ak:did_core:web:bridge.example:ghost:third"
        }));
    }

    #[tokio::test]
    async fn concurrent_applet_claims_commit_one_complete_batch_only() {
        let store = SolandMemoryPersistenceStore::new();
        let authority = soland_storage::ManagedAuthorityClaim {
            actor_id: "ak:did_core:web:managed.example".to_owned(),
            station_id: "ak:did_core:web:soland.example".to_owned(),
        };
        let namespaces = arkret_models_integration::AppletWireNamespaces {
            realms: vec![arkret_models_integration::AppletNamespaceEntry::exclusive(
                "bridge:workspace:*",
            )],
            ..Default::default()
        };
        let build = |suffix: &str| {
            let applet_id = typed_id("ak:applet:");
            let event_id = typed_id("ak:event:");
            let applet_scope = test_applet_scope();
            EventBatchCommitRequest {
                events: vec![event_request(
                    event_id,
                    realm_id(),
                    &format!("ak:did_core:web:{suffix}.example"),
                    None,
                )],
                agent_approval_nonce: None,
                franking_replay_nonce: None,
                applet_record: Some(AppletRecordCommit {
                    applet_id: arkret_wire::AppletId::new(applet_id.clone()).unwrap(),
                    identity: AppletIdentityCommit {
                        target_station_id: arkret_wire::DidCoreId::new(
                            authority.station_id.clone(),
                        )
                        .unwrap(),
                        expected_record: None,
                        record: test_applet_identity(&applet_id, &authority.actor_id),
                    },
                    expected_record: None,
                    record: test_applet_record(
                        serde_json::json!({
                            "status": "installed",
                            "revoked_at": null,
                            "bot_actor_id": authority.actor_id.clone(),
                            "bot_actor_station_id": authority.station_id.clone(),
                            "package": {"namespaces": namespaces.clone()},
                            "ghosts": [],
                        }),
                        &applet_scope,
                        &applet_id,
                    ),
                }),
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            }
        };
        let left = build("claim-left");
        let right = build("claim-right");
        let (left, right) = tokio::join!(
            store.commit_event_batch(left),
            store.commit_event_batch(right)
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        assert_eq!(store.applets.records.lock().len(), 1);
        assert_eq!(store.events.data.lock().len(), 1);
    }

    #[tokio::test]
    async fn applet_installations_are_unique_per_scope_and_share_one_identity() {
        let store = SolandMemoryPersistenceStore::new();
        let applet_id = typed_id("ak:applet:");
        let identity = serde_json::json!({
            "applet_id": applet_id,
            "bot_actor_id": "ak:did_core:web:shared-bot.example",
            "bot_actor_station_id": "ak:did_core:web:soland.example",
        });
        let install = |scope: arkret_wire::ScopeRef, identity: serde_json::Value, reuse: bool| {
            let event_realm_id = scope.realm_id().to_string();
            let record = serde_json::json!({
                "applet_id": applet_id,
                "effective_scope": scope.clone(),
                "status": "installed",
                "revoked_at": null,
                "package": {"namespaces": {}},
                "ghosts": [],
            });
            EventBatchCommitRequest {
                events: vec![event_request(
                    typed_id("ak:event:"),
                    event_realm_id,
                    "ak:did_core:web:applet-admin.example",
                    None,
                )],
                agent_approval_nonce: None,
                franking_replay_nonce: None,
                applet_record: Some(AppletRecordCommit {
                    applet_id: arkret_wire::AppletId::new(applet_id.clone()).unwrap(),
                    identity: AppletIdentityCommit {
                        target_station_id: arkret_wire::DidCoreId::new(
                            "ak:did_core:web:soland.example".to_owned(),
                        )
                        .unwrap(),
                        expected_record: reuse.then(|| identity.clone()),
                        record: identity,
                    },
                    expected_record: None,
                    record,
                }),
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            }
        };
        let first_scope = test_applet_scope();
        let second_scope = test_applet_scope();
        store
            .commit_event_batch(install(first_scope, identity.clone(), false))
            .await
            .unwrap();
        store
            .commit_event_batch(install(second_scope.clone(), identity.clone(), true))
            .await
            .unwrap();
        assert_eq!(store.applets.records.lock().len(), 2);

        let conflicting_identity = serde_json::json!({
            "applet_id": applet_id,
            "bot_actor_id": "ak:did_core:web:different-bot.example",
            "bot_actor_station_id": "ak:did_core:web:soland.example",
        });
        let error = store
            .commit_event_batch(install(test_applet_scope(), conflicting_identity, true))
            .await
            .unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::DuplicateConflict)
        );
        assert_eq!(store.applets.records.lock().len(), 2);
    }
}
