use arkret_state::state::store::{AcklessSelfPrincipalIngress, ControlProposalIngress};

use super::*;

pub(super) struct AcceptedEventCommandPreparation<'a, 'options> {
    pub(super) publication_event: Option<&'a Event>,
    pub(super) mls_frontier_leaves:
        Option<&'a [arkret_wire::mls_transition::MlsSecurityFrontierLeaf]>,
    pub(super) state: &'a AppState,
    pub(super) parsed: &'a ValidatedEventEnvelope,
    pub(super) actor_key: &'a str,
    pub(super) envelope: Value,
    pub(super) accepted_canonical_bytes: &'a [u8],
    pub(super) governance_dependency: Vec<soland_storage::GovernanceDependencyWrite>,
    pub(super) projected_event: Option<&'a soland_services::events::ProjectedEvent>,
    pub(super) deliveries: Vec<soland_services::federation::FederationDeliveryRecord>,
    pub(super) device_revoke_target_device_id: Option<&'a str>,
    pub(super) control_proposal_ack: Option<&'a arkret_wire::ControlProposalAck>,
    pub(super) local_device_revocation_gate: Option<soland_storage::DeviceRevocationGateSelector>,
    pub(super) historical_producer: Option<arkret::historical_producer::VerifiedHistoricalEventProducer>,
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
}

/// Freeze every atomic sidecar into the canonical Event commit command.
///
/// This stage performs no persistence write. The caller keeps all submit-lane
/// guards alive through the later commit and post-commit stages.
pub(super) async fn prepare_accepted_event_command(
    preparation: AcceptedEventCommandPreparation<'_, '_>,
) -> Result<PreparedAcceptedEventCommand, SubmitOneError> {
    let AcceptedEventCommandPreparation {
        publication_event,
        state,
        parsed,
        actor_key,
        envelope,
        accepted_canonical_bytes,
        governance_dependency,
        projected_event,
        deliveries,
        device_revoke_target_device_id,
        control_proposal_ack,
        local_device_revocation_gate,
        historical_producer,
        mls_frontier_leaves,
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
    let is_public_group =
        envelope.pointer("/scope_ref/kind").and_then(Value::as_str) != Some("sidecar");
    let mls_public_genesis = if is_public_group && parsed.kind == "ak.mls.genesis" {
        let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
            serde_json::from_value(envelope.get("payload").cloned().unwrap_or(Value::Null))
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "schema_violation",
                        error.to_string(),
                    )
                })?;
        let limit = arkret_models_collaboration::mls_group_state_material::MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES as usize;
        let group_info_bytes = crate::routing::governance_history::load_mls_public_blob(
            state,
            payload.group_info_ref.as_str(),
            limit,
        )
        .await
        .map_err(|error| SubmitOneError::Rejected {
            error: Box::new(error),
            details: None,
        })?;
        let ratchet_tree_bytes = crate::routing::governance_history::load_mls_public_blob(
            state,
            payload.ratchet_tree_ref.as_str(),
            limit - group_info_bytes.len(),
        )
        .await
        .map_err(|error| SubmitOneError::Rejected {
            error: Box::new(error),
            details: None,
        })?;
        Some(soland_storage::MlsPublicGenesisInput {
            group_info_bytes,
            ratchet_tree_bytes,
            producer_signing_key: parsed.producer_signing_key.clone().ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_precondition",
                    "MLS Genesis requires an exact verified producer key",
                )
            })?,
            producer_device_id: parsed.device_id.clone(),
        })
    } else {
        None
    };
    let mls_public_producer =
        if is_public_group && matches!(parsed.kind.as_str(), "ak.mls.proposal" | "ak.mls.commit") {
            Some(soland_storage::MlsPublicHandshakeProducer {
                signing_key: parsed.producer_signing_key.clone().ok_or_else(|| {
                    SubmitOneError::new(
                        StatusCode::PRECONDITION_FAILED,
                        "failed_precondition",
                        "MLS public handshake requires a verified producer key",
                    )
                })?,
                device_id: parsed.device_id.clone(),
            })
        } else {
            None
        };
    let mut contact_projection =
        commit_options.and_then(|options| options.contact_projection.cloned());
    if let Some(draft) = commit_options.and_then(|options| options.contact_completion_draft) {
        let invalid = |message: String| {
            SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                message,
            )
        };
        if draft.event.event_id != parsed.event_id
            || arkret_canonical::canonical_json_bytes(&draft.event)
                .map_err(|error| invalid(error.to_string()))?
                != accepted_canonical_bytes
        {
            return Err(invalid(
                "Contact plan does not bind the authenticated Event bytes".into(),
            ));
        }
        let [proof] = draft.event.proofs.as_slice() else {
            return Err(invalid("Contact requires one producer".into()));
        };
        let did_key = parsed
            .producer_signing_key
            .as_ref()
            .ok_or_else(|| invalid("Contact verified producer key is unavailable".into()))?;
        let multibase = did_key
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| invalid("Contact producer key is not did:key".into()))?;
        let public = arkret_canonical::decode_ed25519_multibase(multibase)
            .map_err(|error| invalid(error.to_string()))?;
        let encoded_key =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(public))
                .map_err(|error| invalid(error.to_string()))?;
        let producer = if draft.event.executed_by.is_some() {
            let record = state
                .agent_pairings()
                .agent(draft.event.actor_id.signing_principal_id().as_str())
                .await
                .map_err(|error| invalid(error.to_string()))?
                .ok_or_else(|| invalid("Contact Agent native identity is unavailable".into()))?;
            // The stored immutable delegation supplies a locator, never a new
            // authorization. Authenticate its complete native chain before the
            // exact producer projection is frozen with the pending command.
            let (locator, _) = record
                .controller_authorization_ref
                .as_str()
                .split_once('#')
                .ok_or_else(|| {
                    invalid("Contact Agent delegation has no full DID locator".into())
                })?;
            let did = arkret_wire::Did::new(locator).map_err(|error| invalid(error.to_string()))?;
            let mut entries = state
                .dids()
                .log_events(did.as_str())
                .await
                .map_err(|error| invalid(error.to_string()))?;
            entries.sort_by_key(|entry| entry.seq);
            let history = ContactAgentHistory(arkret_models_identity::IdentityLogListOutcome {
                did: did.clone(),
                method: arkret_models_identity::DidMethodUri::Webvh,
                native_history: Some(true),
                entries: entries.into_iter().map(|entry| entry.operation).collect(),
                next_cursor: None,
                has_more: false,
            });
            let identity = arkret::contact_authorization::verify_contact_agent_identity(
                &draft.event,
                &draft.holder,
                &did,
                &history,
            )
            .map_err(|error| invalid(error.to_string()))?;
            arkret_models_collaboration::contact_operations::ContactProducerSigner::delegated(
                proof.verification_method.clone(),
                encoded_key,
                identity.did().clone(),
            )
        } else {
            arkret_models_collaboration::contact_operations::ContactProducerSigner::direct(
                proof.verification_method.clone(),
                encoded_key,
            )
        }
        .map_err(|error| invalid(error.to_string()))?;
        contact_projection
            .as_mut()
            .ok_or_else(|| invalid("Contact business projection is absent".into()))?
            .completion_intent = Some(
            draft
                .clone()
                .bind_producer(producer)
                .map_err(|error| invalid(error.to_string()))?,
        );
    }
    let command = soland_services::events::CommitAcceptedEventCommand {
        publication_event: publication_event.cloned(),
        mls_public_producer,
        mls_public_genesis,
        mls_frontier_leaves: mls_frontier_leaves.map(<[_]>::to_vec),
        replicated: internal_admission.is_some_and(InternalEventAdmission::is_peer_replication),
        membership_compensation_evidence,
        governance_dependencies: governance_dependency.into_iter().collect(),
        device_pairing_authorization: commit_options
            .and_then(|options| options.device_pairing)
            .and_then(|admission| admission.commit_authorization.clone()),
        contact_projection,
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
        historical_producer,
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
            }),
        deliveries,
    };
    Ok(PreparedAcceptedEventCommand { command })
}

/// Only supplies retained native bytes; the SDK authenticates the whole chain.
struct ContactAgentHistory(arkret_models_identity::IdentityLogListOutcome);
impl arkret_identity::AuthorityDidHistoryResolver for ContactAgentHistory {
    fn resolve_complete_history(
        &self,
        did: &arkret_wire::Did,
    ) -> Result<
        arkret_models_identity::IdentityLogListOutcome,
        arkret_identity::AuthorityHistoryUnavailable,
    > {
        if &self.0.did != did {
            return Err(arkret_identity::AuthorityHistoryUnavailable {
                message: "unrelated Contact Agent DID".into(),
            });
        }
        Ok(self.0.clone())
    }
}
