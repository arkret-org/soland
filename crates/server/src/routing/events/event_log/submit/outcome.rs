use super::*;

pub(in crate::routing::events::event_log) fn events_submit_outcome(
    status: EventsSubmitStatus,
    accepted: Vec<String>,
    duplicate: Vec<String>,
    rejected: Vec<EventsSubmitRejectedItem>,
    quarantine: Vec<String>,
    cursor: Option<String>,
) -> EventsSubmitOutcome {
    EventsSubmitOutcome {
        status,
        accepted: accepted
            .into_iter()
            .filter_map(|event_id| EventId::new(event_id).ok())
            .collect(),
        duplicate: duplicate
            .into_iter()
            .filter_map(|event_id| EventId::new(event_id).ok())
            .collect(),
        rejected,
        quarantine: quarantine
            .into_iter()
            .filter_map(|event_id| EventId::new(event_id).ok())
            .collect(),
        actor_frontier: None,
        realm_frontier: None,
        cursor,
        original_outcome: None,
    }
}

pub(super) async fn enforce_sibling_fork_limit(
    state: &AppState,
    session: &SessionRecord,
    parsed: &ValidatedEventEnvelope,
    existing_records: &[CanonicalEventRecord],
) -> Result<(), SubmitOneError> {
    let prev_frontier_digest = prev_frontier_digest(&parsed.prev_refs)?;
    let sibling_count = existing_records
        .iter()
        .filter(|record| record.actor_id == parsed.actor_id && record.actor_seq == parsed.actor_seq)
        .filter_map(|record| stored_prev_frontier_digest(record).ok())
        .filter(|digest| digest == &prev_frontier_digest)
        .count();
    if sibling_count < arkret_sdk::MAX_ACTOR_SEQ_SIBLINGS {
        return Ok(());
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "events.submit",
        json!({
            "event_id": parsed.event_id.clone(),
            "realm_id": parsed.realm_id.clone(),
            "actor_id": parsed.actor_id.clone(),
            "actor_seq": parsed.actor_seq,
            "prev_frontier_digest": prev_frontier_digest,
            "accepted_sibling_count": sibling_count,
            "max_actor_seq_siblings": arkret_sdk::MAX_ACTOR_SEQ_SIBLINGS,
        }),
        "fork_quarantine",
    )
    .await;
    Err(SubmitOneError::quarantine(
        parsed.event_id.clone(),
        "fork_quarantine",
        "actor_seq sibling fork limit exceeded; event is quarantined pending actor-chain repair",
    ))
}
