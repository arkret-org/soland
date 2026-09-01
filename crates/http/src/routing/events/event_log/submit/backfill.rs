use super::*;

pub(in crate::routing) async fn verify_frontier_backfill_event(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<(), String> {
    let suite = trusted_federated_event_digest_suites(state, &[event])?[0];
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(|error| format!("event_id_digest_mismatch:{error}"))?;
    verify_federated_event_admission(state, event, suite)
        .await
        .map_err(|error| format!("invalid_proof:{error}"))?;
    Ok(())
}

/// Admission for a full Event obtained over the authenticated peer read rail.
/// Reuse the submit validators and commit path; reads never confer authority.
pub(in crate::routing) async fn admit_frontier_backfill_event(
    state: &AppState,
    source_id: &str,
    source_trust_domain: &str,
    submission: &arkret_wire::EventFederationSubmission,
    seals: &[arkret_wire::Seal],
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let event = &submission.event;
    let digest_suite = trusted_federated_event_digest_suites(state, &[event])
        .map_err(|error| SubmitOneError::new(StatusCode::BAD_REQUEST, "schema_violation", error))?
        [0];
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "event_id_digest_mismatch",
                error.to_string(),
            )
        })?;
    let (method, key) = verify_federated_event_admission(state, event, digest_suite)
        .await
        .map_err(|error| SubmitOneError::new(StatusCode::BAD_REQUEST, "invalid_proof", error))?;
    submission
        .validate_structural(digest_suite)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                error.to_string(),
            )
        })?;
    validate_membership_compensation_semantics(
        event,
        submission.membership_compensation_evidence.as_ref(),
    )?;
    if let Some(lease) = &submission.authorization_lease {
        validate_authorization_lease_for_event(state, None, event, lease).await?;
        validate_ingress_receipt_proofs(state, &submission.ingress_receipts, lease).await?;
        store_inbound_publication_evidence(
            state,
            &InboundPublicationEvidence {
                event_digest: event.event_digest_with_digest_suite(digest_suite).map_err(
                    |error| {
                        SubmitOneError::new(
                            StatusCode::BAD_REQUEST,
                            "event_id_digest_mismatch",
                            error.to_string(),
                        )
                    },
                )?,
                realm_id: event.realm_id.to_string(),
                authorization_lease: lease.clone(),
                ingress_receipts: submission.ingress_receipts.clone(),
            },
        )
        .await?;
    }
    let envelope = typed_event_to_canonical_value(event.clone())?;
    let profile = crate::routing::federation::federation::federation_profile_intersection_for_peer(
        state,
        source_id,
        Some(source_trust_domain),
    )
    .await
    .map_err(|error| SubmitOneError::new(StatusCode::BAD_REQUEST, error.code, error.message))?;
    profile
        .enforce_event(&envelope)
        .map_err(|error| SubmitOneError::new(StatusCode::BAD_REQUEST, error.code, error.message))?;
    let realm_id = event.realm_id.as_str();
    if !crate::routing::federation::federation::federation_actor_origin_acceptable(
        state,
        &event.actor_id,
        source_id,
        Some(event.actor_id.route_service_id().as_str()),
        realm_id,
        Some(event.kind.as_str()),
    )
    .await
    {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "backfill actor is outside authenticated peer authority",
        ));
    }
    if event.kind == arkret_wire::EventKind::MlsWelcome {
        crate::routing::mls::validate_federated_welcome_peer_claim(
            state,
            source_id,
            realm_id,
            &event.actor_id,
            &envelope["payload"],
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                error,
            )
        })?;
    }
    accept_federated_seal_prerequisite(state, &event.realm_id, &envelope, seals, digest_suite)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                error.status.unwrap_or(StatusCode::BAD_REQUEST),
                error.wire_code(),
                error.message.to_string(),
            )
        })?;
    let created_at = now();
    let device_id = event_string_field_from_value(&envelope, "device_id").unwrap_or_default();
    let session = SessionRecord {
        token_hash: format!("federation:{source_trust_domain}:{}", event.event_id),
        account_pk: None,
        actor: event.actor_id.signing_principal_id().to_string(),
        device_id: device_id.clone(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: created_at + Duration::minutes(5),
        created_at,
        revoked_at: None,
    };
    let admission = InternalEventAdmission::peer_federated_event(
        realm_id,
        event.actor_id.clone(),
        device_id,
        event.event_id.to_string(),
        method,
        key,
    );
    let prepared = prepare_agent_event_admission_receipt(state, event, created_at)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                error,
            )
        })?;
    let idempotency = prepared
        .as_ref()
        .and_then(|receipt| receipt.idempotency.clone())
        .map(SubmitCommitIdempotency::Prepared);
    submit_event_value_with_context(
        state,
        &session,
        envelope,
        SubmitEventContext {
            internal_admission: Some(&admission),
            control_proposal_ack: submission.control_proposal_ack.as_ref(),
            ackless_self_principal_admission_evidence: submission
                .ackless_self_principal_admission_evidence
                .as_ref(),
            federation_source_id: Some(source_id),
            membership_compensation_evidence: submission.membership_compensation_evidence.as_ref(),
            ..SubmitEventContext::empty()
        },
        SubmitMode::Commit(SubmitCommitOptions {
            idempotency,
            ..SubmitCommitOptions::none()
        }),
    )
    .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn frontier_backfill_detects_controls_and_compensation_that_need_evidence() {
        let mut event = arkret_wire::test_support::raw_event_at(
            "ak.message.create",
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(
                    "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                )
                .unwrap(),
            },
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            0,
            arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
            serde_json::json!({}),
            chrono::Utc::now(),
        )
        .unwrap();
        assert!(!event.kind.is_control_plane());
        for kind in [
            arkret_wire::EventKind::MemberState,
            arkret_wire::EventKind::DeviceRevoke,
            arkret_wire::EventKind::RealmCreate,
        ] {
            event.kind = kind;
            assert!(event.kind.is_control_plane());
        }
        event.kind = arkret_wire::EventKind::MessageCreate;
        event.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new(format!(
                "ak:membership_compensation_delegation:sha256:{}",
                "a".repeat(64)
            ))
            .unwrap(),
        );
        assert!(event.authorization_ref.as_ref().is_some_and(|reference| {
            arkret_wire::MembershipCompensationDelegationRef::new(reference.as_str()).is_ok()
        }));
    }
}
