use arkret_state::state::store::{AcklessSelfPrincipalIngress, ControlProposalIngress};

use super::*;

pub(super) struct AcceptedEventCommandPreparation<'a, 'options> {
    pub(super) state: &'a AppState,
    pub(super) parsed: &'a ValidatedEventEnvelope,
    pub(super) actor_key: &'a str,
    pub(super) envelope: Value,
    pub(super) accepted_canonical_bytes: &'a [u8],
    pub(super) governance_dependency: Option<soland_storage::GovernanceDependencyWrite>,
    pub(super) projected_event: Option<&'a soland_services::events::ProjectedEvent>,
    pub(super) accepted_response: &'a SubmittedEventOutcome,
    pub(super) deliveries: Vec<soland_services::federation::FederationDeliveryRecord>,
    pub(super) device_revoke_target_device_id: Option<&'a str>,
    pub(super) control_proposal_ack: Option<&'a arkret_wire::ControlProposalAck>,
    pub(super) local_device_revocation_gate: Option<soland_storage::DeviceRevocationGateSelector>,
    pub(super) validated_agent_approval: Option<ValidatedAgentApproval>,
    pub(super) membership_compensation_evidence:
        Option<&'a arkret_wire::MembershipCompensationSubmissionEvidence>,
    pub(super) internal_admission: Option<&'a InternalEventAdmission>,
    pub(super) consent_admission: Option<&'a crate::routing::identity::consent::ConsentAdmission>,
    pub(super) ackless_self_principal_ingress: Option<&'a AcklessSelfPrincipalIngress>,
    pub(super) commit_options: Option<&'a SubmitCommitOptions<'options>>,
    pub(super) received_at: chrono::DateTime<chrono::Utc>,
}

pub(super) struct PreparedAcceptedEventCommand {
    pub(super) command: soland_services::events::CommitAcceptedEventCommand,
    pub(super) agent_approval_nonce: Option<soland_storage::AgentApprovalNonceCommit>,
}

/// Freeze every atomic sidecar into the canonical Event commit command.
///
/// The caller must first finish federation fanout construction and add the
/// ingress receipt, canonical Ack and delivery summary to `accepted_response`.
/// This stage then binds that final response to idempotency and performs no
/// persistence write; the caller keeps all submit-lane guards alive through
/// the later commit and post-commit stages.
pub(super) async fn prepare_accepted_event_command(
    preparation: AcceptedEventCommandPreparation<'_, '_>,
) -> Result<PreparedAcceptedEventCommand, SubmitOneError> {
    let AcceptedEventCommandPreparation {
        state,
        parsed,
        actor_key,
        envelope,
        accepted_canonical_bytes,
        governance_dependency,
        projected_event,
        accepted_response,
        deliveries,
        device_revoke_target_device_id,
        control_proposal_ack,
        local_device_revocation_gate,
        validated_agent_approval,
        membership_compensation_evidence,
        internal_admission,
        consent_admission,
        ackless_self_principal_ingress,
        commit_options,
        received_at,
    } = preparation;
    let device_revocation_transition =
        if let Some(target_device_id) = device_revoke_target_device_id {
            let control_proposal_ack = control_proposal_ack.cloned().ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_precondition",
                    "ak.device.revoke requires a canonical Control Proposal Ack",
                )
            })?;
            let selector =
                crate::routing::identity::device_generation::active_device_revocation_gate_selector(
                    state,
                    parsed.actor_id.as_str(),
                    target_device_id,
                )
                .await
                .map_err(|error| {
                    SubmitOneError::new(
                        if error.is_not_found() {
                            StatusCode::FORBIDDEN
                        } else {
                            StatusCode::INTERNAL_SERVER_ERROR
                        },
                        if error.is_not_found() {
                            "device_unauthorized"
                        } else {
                            "internal_error"
                        },
                        format!("revoke target device authorization unavailable: {error}"),
                    )
                })?;
            Some(soland_storage::DeviceRevocationTransition {
                selector,
                proposal_event_id: parsed.event_id.to_string(),
                proposal_digest: parsed.canonical_digest.clone(),
                control_proposal_ack,
            })
        } else {
            None
        };
    let agent_approval_nonce =
        validated_agent_approval.map(|approval| soland_storage::AgentApprovalNonceCommit {
            agent_id: approval.agent_id,
            authorization_ref: approval.authorization_ref,
            request_id: approval.request_id,
            approval_nonce: approval.approval_nonce,
            event_id: parsed.event_id.to_string(),
            expires_at: approval.expires_at,
            consumed_at: received_at,
        });
    let membership_compensation_evidence = membership_compensation_evidence
        .map(|evidence| -> Result<_, SubmitOneError> {
            let canonical_bytes =
                arkret_canonical::canonical_json_bytes(evidence).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        format!("membership compensation evidence is not canonicalizable: {error}"),
                    )
                })?;
            Ok(soland_storage::MembershipCompensationEvidenceRecord {
                event_id: parsed.event_id.to_string(),
                event_digest: parsed.canonical_digest.clone(),
                admission_id: evidence.delegation.core.admission_id.to_string(),
                delegation_id: evidence.delegation.delegation_id.as_str().to_owned(),
                canonical_bytes,
                evidence: evidence.clone(),
            })
        })
        .transpose()?;
    let command = soland_services::events::CommitAcceptedEventCommand {
        replicated: internal_admission.is_some_and(InternalEventAdmission::is_peer_replication),
        membership_compensation_evidence,
        governance_dependencies: governance_dependency.into_iter().collect(),
        device_pairing_authorization: commit_options
            .and_then(|options| options.device_pairing)
            .and_then(|admission| admission.commit_authorization.clone()),
        contact_projection: commit_options.and_then(|options| options.contact_projection.cloned()),
        consent_projection: consent_admission
            .map(crate::routing::identity::consent::ConsentAdmission::commit),
        event: soland_services::events::AcceptedEvent {
            event_id: parsed.event_id.to_string(),
            actor_id: actor_key.to_owned(),
            actor_seq: parsed.actor_seq,
            realm_id: Some(parsed.realm_id.to_string()),
            kind: parsed.kind.clone(),
            schema_id: parsed.schema_id.clone(),
            digest_suite: parsed.digest_suite,
            canonical_digest: parsed.canonical_digest.clone(),
            canonical_bytes: accepted_canonical_bytes.to_vec(),
            envelope,
            received_at,
        },
        control_proposal_ingress: match (
            ackless_self_principal_ingress.cloned(),
            control_proposal_ack.cloned(),
        ) {
            (Some(class), None) => Some(ControlProposalIngress::AcklessSelfPrincipal(class)),
            (None, Some(ack)) => Some(ControlProposalIngress::AckRequired(ack)),
            _ => None,
        },
        device_revocation_transition,
        device_revocation_gate: local_device_revocation_gate,
        projections: projected_event
            .iter()
            .map(|event| soland_services::events::ProjectedEvent {
                event_id: event.event_id.clone(),
                realm_id: event.realm_id.clone(),
                event_kind: event.event_kind.clone(),
                operation_kind: event.operation_kind.clone(),
                operation_id: event.operation_id.clone(),
                sender: event.sender.clone(),
                payload: event.payload.clone(),
                created_at: event.created_at,
                received_at: event.received_at,
            })
            .collect(),
        idempotency: commit_options
            .and_then(|options| options.idempotency.as_ref())
            .map(|source| match source {
                SubmitCommitIdempotency::Prepared(record) => record.clone(),
                SubmitCommitIdempotency::CommitKey(record) => {
                    let created_at = now();
                    soland_services::events::IdempotentResponse {
                        authenticated_actor: record.authenticated_actor.clone(),
                        operation_id: record.operation_id.clone(),
                        key: record.key.clone(),
                        request_hash: record.request_hash.clone(),
                        status: StatusCode::OK.as_u16() as i32,
                        body: serde_json::to_value(&accepted_response.outcome)
                            .unwrap_or_else(|_| json!({"status": "accepted"})),
                        created_at,
                        expires_at: created_at + Duration::seconds(IDEMPOTENCY_KEY_TTL_SECONDS),
                    }
                }
            }),
        deliveries,
    };
    Ok(PreparedAcceptedEventCommand {
        command,
        agent_approval_nonce,
    })
}
