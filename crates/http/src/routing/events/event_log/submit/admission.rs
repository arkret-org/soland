use super::*;

pub(super) struct EventSequenceAdmissionContext<'a> {
    pub(super) state: &'a AppState,
    pub(super) session: &'a SessionRecord,
    pub(super) parsed: &'a ValidatedEventEnvelope,
    pub(super) submitted_event: &'a Event,
    pub(super) actor_key: &'a str,
    pub(super) membership_compensation_evidence:
        Option<&'a arkret_wire::MembershipCompensationSubmissionEvidence>,
    pub(super) internal_admission: Option<&'a InternalEventAdmission>,
}

/// Admit the Event against the durable actor chain while the caller keeps all
/// submit-lane guards alive. This stage performs no writes and must run after
/// exact-duplicate resolution but before projection preflight.
pub(super) async fn admit_event_sequence(
    context: EventSequenceAdmissionContext<'_>,
) -> Result<Vec<soland_services::events::AcceptedEvent>, SubmitOneError> {
    let EventSequenceAdmissionContext {
        state,
        session,
        parsed,
        submitted_event,
        actor_key,
        membership_compensation_evidence,
        internal_admission,
    } = context;
    let service = state.event_queries();
    if let Some(evidence) = membership_compensation_evidence {
        validate_membership_compensation_live_state(state, submitted_event, evidence).await?;
    }
    if parsed.kind == arkret_wire::EventKind::RealmCreate.as_str()
        && service
            .realm_event_stats(parsed.realm_id.as_str())
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("events store unavailable: {error}"),
                )
            })?
            .count
            > 0
    {
        return Err(realm_already_exists_error());
    }
    let mut scoped_actor_records = service
        .canonical_events_for_realm_actor(parsed.realm_id.as_str(), actor_key)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("events store unavailable: {error}"),
            )
        })?;
    if let Some(max_seq) = scoped_actor_records
        .iter()
        .map(|record| record.actor_seq)
        .max()
        && parsed.actor_seq < max_seq
        && !internal_admission.is_some_and(InternalEventAdmission::is_peer_replication)
    {
        let next_actor_seq = max_seq.checked_add(1).ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::CONFLICT,
                "frontier_sequence_exhausted",
                "actor sequence is exhausted",
            )
        })?;
        let mut frontier_event_ids = scoped_actor_records
            .iter()
            .filter(|record| record.actor_seq == max_seq)
            .map(|record| {
                EventId::new(record.event_id.clone()).map_err(|_| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "stored event_id is invalid",
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        frontier_event_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        frontier_event_ids.dedup();
        let current_frontier = super::super::endpoints::build_realm_actor_frontier(
            state,
            parsed.realm_id.clone(),
            parsed.actor.clone(),
            next_actor_seq,
            frontier_event_ids,
        )
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("actor frontier unavailable: {error}"),
            )
        })?;
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "cas_conflict",
            "actor_seq is older than the accepted actor frontier",
        )
        .with_details(
            arkret_models_collaboration::event_sync::EventsActorCasConflictProblem {
                accepted: false,
                current_frontier,
            },
        ));
    }
    let mut max_actor_predecessor_seq = None;
    for prev_ref in &parsed.prev_refs {
        let predecessor = service
            .canonical_event(prev_ref.as_str())
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("events store unavailable: {error}"),
                )
            })?;
        if predecessor.is_none() {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "prev_refs must reference accepted events",
            ));
        }
        let predecessor = predecessor.expect("presence checked above");
        if predecessor.realm_id.as_deref() != Some(parsed.realm_id.as_str()) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "prev_refs must not reference an Event in another Realm",
            ));
        }
        if predecessor.actor_id == actor_key {
            max_actor_predecessor_seq = Some(
                max_actor_predecessor_seq.map_or(predecessor.actor_seq, |current: u64| {
                    current.max(predecessor.actor_seq)
                }),
            );
        }
    }
    if max_actor_predecessor_seq
        .is_some_and(|predecessor_seq| predecessor_seq.checked_add(1) != Some(parsed.actor_seq))
        || (max_actor_predecessor_seq.is_none() && parsed.actor_seq != 0)
    {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "prev_refs must include the preceding actor sequence in the same Realm",
        ));
    }
    enforce_sibling_fork_limit(state, session, parsed, &scoped_actor_records).await?;
    Ok(scoped_actor_records)
}
