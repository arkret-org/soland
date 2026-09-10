use super::*;

pub(super) struct AcceptedEventCommit<'a> {
    pub(super) session: &'a SessionRecord,
    pub(super) parsed: &'a ValidatedEventEnvelope,
    pub(super) envelope_for_bootstrap: &'a Value,
    pub(super) accepted_canonical_bytes: &'a [u8],
    pub(super) command: soland_services::events::CommitAcceptedEventCommand,
    pub(super) agent_approval_nonce: Option<soland_storage::AgentApprovalNonceCommit>,
    pub(super) ingress_receipt: Option<&'a arkret_wire::offline_publication::IngressReceipt>,
    pub(super) control_event_for_proposal: bool,
    pub(super) self_principal_pcr_device_authorized: bool,
    pub(super) received_at: chrono::DateTime<chrono::Utc>,
}

/// Persist the canonical Event and translate the storage conflict registry
/// back to the submit wire contract. An exact duplicate discovered by the
/// commit race returns its complete response; a newly committed Event returns
/// `None` so the caller can run post-commit effects.
pub(super) async fn commit_accepted_event_stage(
    state: &AppState,
    context: AcceptedEventCommit<'_>,
) -> Result<Option<SubmittedEventOutcome>, SubmitOneError> {
    let AcceptedEventCommit {
        session,
        parsed,
        envelope_for_bootstrap,
        accepted_canonical_bytes,
        command,
        agent_approval_nonce,
        ingress_receipt,
        control_event_for_proposal,
        self_principal_pcr_device_authorized,
        received_at,
    } = context;
    let franking_replay_nonce =
        moderation_franking_replay_nonce(parsed, envelope_for_bootstrap, received_at)?;
    let encrypted_message = is_encrypted_message(parsed, envelope_for_bootstrap);
    let commit_result = if encrypted_message {
        // Service actor sequence allocation and the final transaction stay
        // under one process-wide authoring lock. PostgreSQL's Realm/actor
        // advisory lock supplies the cross-process CAS; this lock prevents
        // avoidable sibling construction inside one instance.
        let service_event_lock = service_event_authoring_lock();
        let _service_event_guard = service_event_lock.lock().await;
        let proof_command = Box::pin(
            crate::routing::interop::moderation::prepare_franking_proof_event(
                state,
                &command.event,
            ),
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                error.http_status(),
                error.wire_code(),
                format!("franking proof preparation failed: {error}"),
            )
        })?;
        state
            .events()
            .commit_accepted_event_batch(soland_services::events::CommitAcceptedEventBatchCommand {
                events: vec![command, proof_command],
                agent_approval_nonce,
                franking_replay_nonce,
                applet_record: None,
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            })
            .await
    } else if franking_replay_nonce.is_some() || agent_approval_nonce.is_some() {
        state
            .events()
            .commit_accepted_event_batch(soland_services::events::CommitAcceptedEventBatchCommand {
                events: vec![command],
                agent_approval_nonce,
                franking_replay_nonce,
                applet_record: None,
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            })
            .await
    } else {
        state.events().commit_accepted_event(command).await
    };
    let Err(error) = commit_result else {
        return Ok(None);
    };
    if parsed.kind == arkret_wire::EventKind::RealmCreate.as_str()
        && error.is_realm_already_exists()
    {
        return Err(realm_already_exists_error());
    }
    if error.is_conflict_kind() {
        let message = error.detail();
        // The commit lane's conflict code decides the status and the wire
        // reason. Reading it as a value (rather than substring-matching the
        // diagnostic) is what keeps a reworded message from silently moving
        // an admission decision, and what makes an unregistered conflict
        // visible instead of falling through to a 500 labelled "events store
        // unavailable".
        let conflict = error.conflict_code();
        if conflict == Some(ConflictCode::CasConflict)
            && parsed.kind == arkret_wire::EventKind::AccountDataSet.as_str()
        {
            let payload = &envelope_for_bootstrap["payload"];
            if let (Some(key), Some(expected)) = (
                payload["key"].as_str(),
                payload["expected_revision"].as_u64(),
            ) {
                let current = state
                    .account_data()
                    .entry(&parsed.actor.to_string(), key)
                    .await
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            error.to_string(),
                        )
                    })?;
                let revision = current.as_ref().map_or(0, |row| row.revision);
                if revision != expected {
                    let mut details = json!({"account_data_key":key,"current_revision":revision});
                    if let Some(row) = current.filter(|row| !row.tombstone) {
                        details["current_entry"] = json!({"account_data_key":row.account_data_key,"revision":row.revision,"content":row.payload,"updated_at":arkret_canonical::format_timestamp_canonical(row.updated_at)});
                    }
                    return Err(SubmitOneError::new(
                        StatusCode::CONFLICT,
                        "cas_conflict",
                        "account data revision changed before accepted commit",
                    )
                    .with_details(details));
                }
            }
        }
        if conflict == Some(ConflictCode::CasConflict) {
            let current_frontier = super::super::endpoints::load_realm_actor_frontier(
                state,
                parsed.realm_id.clone(),
                parsed.actor.clone(),
            )
            .await
            .map_err(|frontier_error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("actor frontier unavailable: {frontier_error}"),
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
        if conflict == Some(ConflictCode::ForkQuarantine) {
            return Err(SubmitOneError::quarantine(
                parsed.event_id.to_string(),
                "fork_quarantine",
                "actor_seq sibling fork limit exceeded; event is quarantined pending actor-chain repair",
            ));
        }
        if conflict == Some(ConflictCode::SchemaViolation) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                message,
            ));
        }
        if conflict == Some(ConflictCode::ReducerProjectionFailed) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "reducer_projection_failed",
                message,
            ));
        }
        if conflict == Some(ConflictCode::FailedPrecondition) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "failed_precondition",
                message,
            ));
        }
        if conflict == Some(ConflictCode::DependencyMissing) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                message,
            ));
        }
        if conflict == Some(ConflictCode::MembershipCompensationConflict) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "membership_compensation_conflict",
                message,
            ));
        }
        if conflict == Some(ConflictCode::DevicePairingNotFound) {
            return Err(SubmitOneError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "device pairing request not found",
            ));
        }
        if conflict == Some(ConflictCode::DeviceRevocationPending) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "device_revocation_pending",
                "device revocation is pending",
            ));
        }
        if conflict == Some(ConflictCode::DeviceRevoked) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "device_revoked",
                "device generation is revoked",
            ));
        }
        if conflict == Some(ConflictCode::AppletRevoked) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "applet_revoked",
                "Applet authority was revoked before the Event commit",
            ));
        }
        if conflict == Some(ConflictCode::ApprovalNonceReused) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED,
                "agent approval nonce was already consumed",
            ));
        }
        if conflict == Some(ConflictCode::DuplicateConflict) {
            let service = state.event_queries();
            if let Ok(Some(existing)) = service.canonical_event(parsed.event_id.as_str()).await
                && (existing.canonical_bytes == parsed.canonical_bytes
                    || existing.canonical_bytes.as_slice() == accepted_canonical_bytes)
            {
                let frontier = super::super::endpoints::load_realm_actor_frontier(
                    state,
                    parsed.realm_id.clone(),
                    parsed.actor.clone(),
                )
                .await
                .map_err(|frontier_error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("actor frontier unavailable: {frontier_error}"),
                    )
                })?;
                let mut response = with_ingress_receipt(
                    event_submit_response(
                        state,
                        session,
                        EventsSubmitStatus::Duplicate,
                        parsed.event_id.to_string(),
                        frontier,
                    )
                    .await,
                    ingress_receipt,
                );
                if control_event_for_proposal && !self_principal_pcr_device_authorized {
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
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "duplicate_conflict",
                "event_id already exists with different canonical bytes",
            ));
        }
    }
    if let Some(collision) = map_event_hash_collision(parsed.event_id.to_string(), &error) {
        return Err(collision);
    }
    if error.is_conflict_kind() {
        // The commit lane rejected the write for a reason this routing layer
        // has no registered code for. Fail closed, but do not claim the store
        // is unavailable: that message sent operators looking at the database
        // for what is a classification gap in this file.
        tracing::error!(
            %error,
            "commit rejected a canonical event with an unregistered conflict code"
        );
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "unclassified persistence conflict",
        ));
    }
    tracing::error!(%error, "failed to persist canonical event");
    Err(SubmitOneError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "events store unavailable",
    ))
}
