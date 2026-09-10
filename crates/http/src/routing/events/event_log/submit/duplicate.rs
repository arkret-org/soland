use super::super::endpoints::VerifiedActorPredecessors;
use super::*;

/// Inputs needed to classify an event-id collision before any new canonical
/// write is attempted.
pub(super) struct ExistingEventStage<'a> {
    pub(super) mls_frontier_leaves:
        Option<&'a [arkret_wire::mls_transition::MlsSecurityFrontierLeaf]>,
    pub(super) session: &'a SessionRecord,
    pub(super) envelope: &'a Value,
    pub(super) parsed: &'a ValidatedEventEnvelope,
    pub(super) submitted_event: &'a Event,
    pub(super) membership_compensation_evidence:
        Option<&'a arkret_wire::MembershipCompensationSubmissionEvidence>,
    pub(super) has_control_event: bool,
    pub(super) ackless_self_principal_ingress:
        Option<&'a arkret_state::state::store::AcklessSelfPrincipalIngress>,
    pub(super) ingress_receipt: Option<&'a arkret_wire::IngressReceipt>,
    pub(super) agent_pcr_genesis: bool,
    pub(super) self_principal_pcr_device_authorized: bool,
    pub(super) received_at: chrono::DateTime<chrono::Utc>,
}

/// Resolve an exact retry, a witness disagreement, or the absence of an
/// existing canonical Event. This runs before Realm/frontier admission so a
/// retry of a managed genesis is classified by its globally stable event id.
pub(super) async fn resolve_existing_event_stage(
    state: &AppState,
    stage: ExistingEventStage<'_>,
) -> Result<Option<SubmittedEventOutcome>, SubmitOneError> {
    let ExistingEventStage {
        session,
        envelope,
        parsed,
        submitted_event,
        mls_frontier_leaves,
        membership_compensation_evidence,
        has_control_event,
        ackless_self_principal_ingress,
        ingress_receipt,
        agent_pcr_genesis,
        self_principal_pcr_device_authorized,
        received_at,
    } = stage;
    let service = state.event_queries();
    let existing = service
        .canonical_event(parsed.event_id.as_str())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("canonical Event duplicate lookup failed: {error}"),
            )
        })?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    let stored_envelope_bytes = serde_json::to_vec(&existing.envelope).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            error.to_string(),
        )
    })?;
    if existing.envelope == *envelope
        || exact_producer_retry(&stored_envelope_bytes, submitted_event)
    {
        let retained_leaves = service
            .mls_frontier_leaves(parsed.event_id.as_str())
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    error.to_string(),
                )
            })?;
        if retained_leaves.as_deref() != mls_frontier_leaves {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "schema_violation",
                "the same MLS Event was replayed with different public leaf input",
            ));
        }
        let stored_compensation_evidence = service
            .membership_compensation_evidence(parsed.event_id.as_str())
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("stored membership compensation evidence lookup failed: {error}"),
                )
            })?;
        match (
            stored_compensation_evidence.as_ref(),
            membership_compensation_evidence,
        ) {
            (None, None) => {}
            (Some(stored), Some(incoming)) => {
                let incoming_bytes =
                    arkret_canonical::canonical_json_bytes(incoming).map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::BAD_REQUEST,
                            "schema_violation",
                            format!(
                                "membership compensation evidence is not canonicalizable: {error}"
                            ),
                        )
                    })?;
                if stored.canonical_bytes != incoming_bytes {
                    return Err(SubmitOneError::new(
                        StatusCode::CONFLICT,
                        "membership_compensation_conflict",
                        "the same Event was replayed with different membership compensation evidence",
                    ));
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "membership_compensation_conflict",
                    "the Event replay does not match its accepted membership compensation carrier",
                ));
            }
        }
        if has_control_event {
            restore_exact_duplicate_control_event(
                state,
                &existing,
                ackless_self_principal_ingress,
                parsed.digest_suite,
            )
            .await?;
        }
        let frontier = super::super::endpoints::load_realm_actor_frontier(
            state,
            parsed.realm_id.clone(),
            parsed.actor.clone(),
            VerifiedActorPredecessors::none(),
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("post-submit frontier unavailable: {error}"),
            )
        })?;
        let mut response = with_ingress_receipt(
            event_submit_response(
                state,
                session,
                EventsSubmitStatus::Duplicate,
                existing.event_id.clone(),
                frontier,
            )
            .await,
            ingress_receipt,
        );
        if (envelope.get("seal_basis").is_some() || agent_pcr_genesis)
            && !self_principal_pcr_device_authorized
        {
            let digest = Hash::new(parsed.canonical_digest.clone()).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("stored Control Move digest is invalid: {error}"),
                )
            })?;
            let ack = stored_control_proposal_ack(state, &digest).await?;
            response.outcome.control_proposal_acks.push(ack);
        }
        apply_durable_delivery_summary(state, &mut response).await?;
        return Ok(Some(response));
    }

    if existing.canonical_bytes == parsed.canonical_bytes {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "Event retry must preserve the original producer proof and any admission proof",
        ));
    }

    append_audit_log(
        state,
        Some(&session.actor),
        "events.submit",
        json!({
            "event_id": parsed.event_id,
            "reason": "witness_disagreement",
            "canonical_digest": parsed.canonical_digest
        }),
        "witness_disagreement",
    )
    .await;
    let record = super::identity_anchor::canonical_record(parsed, envelope.clone(), received_at);
    Err(quarantine_verified_event_collision(state, record).await)
}
