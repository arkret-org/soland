use super::*;

/// Inputs whose effects are intentionally deferred until the canonical Event
/// and its atomic commit command have succeeded.
///
/// Keeping this boundary explicit prevents rebuildable projections,
/// notifications, and audit writes from drifting back into the persistence
/// transaction or being observed for a rejected Event.
pub(super) struct AcceptedEventPostCommit<'a> {
    pub(super) session: &'a SessionRecord,
    pub(super) parsed: &'a ValidatedEventEnvelope,
    pub(super) accepted_event: &'a Event,
    pub(super) accepted_control_event: Option<&'a Event>,
    pub(super) ackless_self_principal_ingress:
        Option<&'a arkret_state::state::store::AcklessSelfPrincipalIngress>,
    pub(super) control_proposal_ack: Option<&'a arkret_wire::ControlProposalAck>,
    pub(super) consent_admission: Option<&'a crate::routing::identity::consent::ConsentAdmission>,
    pub(super) projection_operation: Option<arkret_event_draft::ProjectedEventOperation>,
    pub(super) projected_cell_writes: &'a [arkret_wire::cbs::ProjectedCellWrite],
    pub(super) projected_event: Option<soland_services::events::ProjectedEvent>,
    pub(super) envelope: &'a Value,
}

/// Apply only rebuildable or externally observable effects after the durable
/// canonical commit has completed.
pub(super) async fn apply_accepted_event_post_commit(
    state: &AppState,
    stage: AcceptedEventPostCommit<'_>,
) -> Result<(), SubmitOneError> {
    let AcceptedEventPostCommit {
        session,
        parsed,
        accepted_event,
        accepted_control_event,
        ackless_self_principal_ingress,
        control_proposal_ack,
        consent_admission,
        projection_operation,
        projected_cell_writes,
        projected_event,
        envelope,
    } = stage;

    if let Some(control_event) = accepted_control_event {
        // The durable pending row carries the ingress classification:
        // device-authorized self-principal PCR moves stay ack-less until the
        // same authority signs a successor Seal; every other Control Move
        // binds its canonical Ack.
        let ingress = match (ackless_self_principal_ingress, control_proposal_ack) {
            (Some(class), None) => {
                arkret_state::state::store::ControlProposalIngress::AcklessSelfPrincipal(
                    class.clone(),
                )
            }
            (None, Some(ack)) => {
                arkret_state::state::store::ControlProposalIngress::AckRequired(ack.clone())
            }
            (Some(_), Some(_)) | (None, None) => {
                return Err(SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "accepted Control Move violates its durable ingress classification",
                ));
            }
        };
        state
            .projections()
            .put_pending_control_event(control_event, &ingress, parsed.digest_suite)
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("accepted Control Move pending index unavailable: {error}"),
                )
            })?;
        state.wake_control_seal_coordinator();
    }
    if let Some(admission) = consent_admission {
        // The cell row and its invalidation are already durable; publish the
        // runtime projection and the holder's notifications.
        crate::routing::identity::consent::apply_committed_consent_admission(state, admission)
            .await;
    }
    if let Some(operation) = projection_operation {
        crate::routing::events::projection::project_accepted_canonical_event_from_device(
            state,
            parsed.actor_id.as_str(),
            parsed.device_id_str(),
            &operation,
            projected_cell_writes,
        )
        .await;
        resolve_moderation_dismiss_queue_item(state, &operation, parsed.event_id.as_str()).await;
    }
    if (parsed.kind == arkret_wire::EventKind::RealmCreate.as_str()
        || parsed.kind == arkret_wire::EventKind::IdentityResolutionUpdate.as_str())
        && let Err(error) = persist_principal_resolution_projection(state, accepted_event).await
    {
        // This index is rebuildable from canonical Events. The Event is
        // already committed, so never misreport it as rejected; surface the
        // drift for repair and let public reads fail closed meanwhile.
        tracing::error!(%error, event_id = %parsed.event_id, "principal resolution read-index update failed");
    }
    if let Some(event) = projected_event {
        let _ = state.publish_event_notification(crate::state::EventNotification::event(
            event.realm_id.clone(),
            event.event_id.clone(),
            crate::routing::events::projection::projection_event_json(&event),
        ));
    } else {
        // Actor-scoped streams consume durable control history even when the
        // Event has no timeline projection. Its canonical envelope supplies
        // only a wake-up hint; subscribers reload the accepted record.
        let _ = state.publish_event_notification(crate::state::EventNotification::event(
            parsed.realm_id.to_string(),
            parsed.event_id.to_string(),
            envelope.clone(),
        ));
    }
    if parsed.kind == arkret_wire::event_kind_str::REALM_CREATE
        && let Some(envelope_object) = envelope.as_object()
    {
        bootstrap_realm_member_index(
            state,
            parsed.realm_id.as_str(),
            parsed.actor_id.as_str(),
            envelope_object,
        )
        .await;
        organizations::record_realm_organizations_from_event(
            state,
            parsed.realm_id.as_str(),
            envelope,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Realm organization projection persistence failed: {error}"),
            )
        })?;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "events.submit",
        json!({
            "event_id": parsed.event_id.clone(),
            "realm_id": parsed.realm_id.clone(),
            "kind": parsed.kind.clone(),
            "canonical_digest": parsed.canonical_digest.clone()
        }),
        "accepted",
    )
    .await;
    Ok(())
}

pub(super) async fn persist_principal_resolution_projection(
    state: &AppState,
    event: &Event,
) -> Result<(), String> {
    let kind = event.kind.as_str();
    if kind != arkret_wire::EventKind::RealmCreate.as_str()
        && kind != arkret_wire::EventKind::IdentityResolutionUpdate.as_str()
    {
        return Ok(());
    }
    let Some(projection_value) = state
        .projections()
        .snapshot()
        .principal_resolution_for_realm(event.realm_id.as_str())
        .cloned()
    else {
        // Ordinary Realm creation has no principal-resolution cell.
        if kind == arkret_wire::EventKind::RealmCreate.as_str() {
            return Ok(());
        }
        return Err("accepted principal resolution Event did not materialize its cell".to_owned());
    };
    let projection = serde_json::from_value(projection_value)
        .map_err(|error| format!("materialized principal resolution is invalid: {error}"))?;
    let existing = state
        .persistence()
        .principal_resolution_for_realm(&event.realm_id)
        .await
        .map_err(|error| format!("load principal resolution index: {error}"))?;
    let expected = if kind == arkret_wire::EventKind::IdentityResolutionUpdate.as_str() {
        event
            .preconditions
            .iter()
            .find(|precondition| precondition.predicate.op == arkret_wire::PredicateOp::HeadEq)
            .and_then(|precondition| precondition.predicate.value.as_ref())
            .and_then(|value| value.get("resolution_event_ref"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "accepted principal resolution update precondition omits its predecessor".to_owned()
            })?
            .into()
    } else {
        None
    };
    let (account_id, pcr_realm_id, genesis_event) = if let Some(existing) = existing.as_ref() {
        (
            existing.account_id.clone(),
            existing.pcr_realm_id.clone(),
            existing.genesis_event.clone(),
        )
    } else {
        if kind != arkret_wire::EventKind::RealmCreate.as_str() {
            return Err("principal resolution update has no account-local PCR lineage".to_owned());
        }
        let account_id =
            event.actor_id.as_account_id().cloned().ok_or_else(|| {
                "principal resolution genesis actor is not an AccountId".to_owned()
            })?;
        (account_id, event.realm_id.clone(), event.clone())
    };
    let record = soland_storage::PrincipalResolutionRecord {
        account_id,
        pcr_realm_id,
        genesis_event,
        current_event: event.clone(),
        projection,
    };
    match state
        .persistence()
        .compare_and_set_principal_resolution(expected, record)
        .await
        .map_err(|error| format!("store principal resolution index: {error}"))?
    {
        soland_storage::PrincipalResolutionCasResult::Applied(_) => Ok(()),
        soland_storage::PrincipalResolutionCasResult::Conflict(Some(current))
            if current.current_event.event_id == event.event_id =>
        {
            Ok(())
        }
        soland_storage::PrincipalResolutionCasResult::Conflict(_) => {
            Err("principal resolution read-index CAS conflict".to_owned())
        }
    }
}

pub(super) fn operation_with_unsigned_agent_context(
    operation: &Operation,
    envelope: &Value,
) -> Operation {
    let mut operation = operation.clone();
    if let Some(object) = operation.payload.as_object_mut()
        && !object.contains_key("agent_context")
        && let Some(agent_context) = envelope
            .get("unsigned")
            .and_then(|unsigned| unsigned.get("agent_context"))
            .filter(|value| value.is_object())
    {
        object.insert("agent_context".to_owned(), agent_context.clone());
    }
    operation
}

pub(super) async fn record_rejected_invite_claim_effect(
    state: &AppState,
    operation: &Operation,
) -> Result<(), String> {
    if !kinds::operation_is_invite_claim(operation) {
        return Ok(());
    }
    let Some(payload) = operation.payload.as_object() else {
        return Ok(());
    };
    let Some(invite_id) = rejected_invite_claim_string_field(payload, "invite_id") else {
        return Ok(());
    };
    let Some(claim_nonce) = rejected_invite_claim_string_field(payload, "claim_nonce") else {
        return Ok(());
    };

    let invites = state.realm_invites();
    let Some(mut record) = invites
        .get(&invite_id)
        .await
        .map_err(|error| format!("load invite {invite_id}: {error}"))?
    else {
        return Ok(());
    };

    let mut changed = false;
    match record.claim_nonces.get(&claim_nonce) {
        Some(existing_operation_id) if existing_operation_id != operation.operation_id.as_str() => {
            return Ok(());
        }
        Some(_) => {}
        None => {
            record
                .claim_nonces
                .insert(claim_nonce.clone(), operation.operation_id.to_string());
            changed = true;
        }
    }

    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= operation.created_at)
    {
        record.status = "expired".to_owned();
        record.invite_token.clear();
        remove_rejected_claim_active_material(&mut record.third_party_invite, true);
        changed = true;
    }

    if !changed {
        return Ok(());
    }
    record.updated_at = Some(operation.created_at);
    invites
        .put(record)
        .await
        .map_err(|error| format!("store invite rejected claim effect: {error}"))
}

pub(super) fn rejected_invite_claim_string_field(
    payload: &serde_json::Map<String, Value>,
    field: &str,
) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn remove_rejected_claim_active_material(
    third_party_invite: &mut Option<
        arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvite,
    >,
    remove_commitment: bool,
) {
    let Some(value) = third_party_invite.as_mut() else {
        return;
    };
    // The closed `ThirdPartyInvite` schema never admits `token_salt` /
    // `pepper` members; only the registered handles can be present.
    value.token_salt_id = None;
    value.lookup_table_ref = None;
    value.pepper_id = None;
    if remove_commitment {
        value.token_commitment = None;
    }
}

/// Every Seal a receiver needs to close the transported Events' CBS basis,
/// packaged as the request's `cbs_proof_bundles[]`.
///
/// Each target gets its own single-target bundle. Bundles may overlap because
/// the wire contract is receiver-relative and permits bounded verifiable
/// supersets.
async fn federation_cbs_proof_bundles(
    state: &AppState,
    events: &[Event],
) -> Result<Vec<arkret_wire::CbsProofBundle>, String> {
    let mut targets = BTreeSet::new();
    for event in events {
        if let Some(seal_ref) = &event.seal_ref {
            targets.insert(seal_ref.clone());
        }
        if let Some(seal_basis) = &event.seal_basis {
            targets.extend(seal_basis.leaves.iter().cloned());
        }
    }
    if targets.len() > arkret_wire::event_submission::MAX_SUBMISSION_CBS_BUNDLES {
        return Err("federation CBS target count exceeds the v1 limit".to_owned());
    }
    cbs_proof_bundles_for_targets(state, &targets).await
}

/// One receiver-relative bundle per target Seal.
///
/// Shared by the federation fanout above and by `ak.self.invites.command.dispatch.v1`:
/// both need the same predecessor closure over the same accepted Seal store, and
/// `cbs-profiles.md` §5 gives them one shape, so there is one builder.
pub(in crate::routing) async fn cbs_proof_bundles_for_targets(
    state: &AppState,
    targets: &BTreeSet<arkret_identifiers::SealId>,
) -> Result<Vec<arkret_wire::CbsProofBundle>, String> {
    let mut bundles = Vec::with_capacity(targets.len());
    for target_seal_ref in targets {
        let mut pending = vec![target_seal_ref.clone()];
        let mut by_id = BTreeMap::new();
        while let Some(seal_id) = pending.pop() {
            if by_id.contains_key(&seal_id) {
                continue;
            }
            let seal = state
                .projections()
                .seal_by_id(&seal_id)
                .await
                .map_err(|error| format!("read federation Seal prerequisite {seal_id}: {error}"))?
                .ok_or_else(|| format!("federation Seal prerequisite {seal_id} is unavailable"))?;
            pending.extend(seal.predecessor_refs.iter().cloned());
            by_id.insert(seal_id, seal);
        }
        if by_id.len() > arkret_wire::cbs_proof_bundle::MAX_BUNDLE_SEALS {
            return Err("federation Seal prerequisite closure exceeds the v1 limit".to_owned());
        }
        bundles.push(arkret_wire::CbsProofBundle {
            target_seal_ref: target_seal_ref.clone(),
            seals: by_id.into_values().collect(),
            control_moves: Vec::new(),
            inclusion_proofs: Vec::new(),
            availability_proofs: Vec::new(),
        });
    }
    Ok(bundles)
}

/// Pair delayed Events with the publication evidence they were admitted under
/// and transport online Events without offline publication evidence
/// (`offline-publication.md` §2.1).
///
/// Stored evidence exists only for an explicitly delayed publication. This
/// service must never mint replacement evidence: that would re-stamp
/// `received_at` and silently widen a fixed revocation window.
async fn federation_submissions(
    state: &AppState,
    events: &[Event],
    current_control_proposal_ack: Option<&arkret_wire::ControlProposalAck>,
    pending_control_proposal_acks: &[arkret_wire::ControlProposalAck],
    pending_evidence: &[soland_services::events::PublicationEvidenceRecord],
    membership_compensation_evidence: Option<
        &arkret_wire::MembershipCompensationSubmissionEvidence,
    >,
    pending_mls_input: Option<(
        &arkret_wire::EventId,
        &[arkret_wire::mls_transition::MlsSecurityFrontierLeaf],
    )>,
) -> Result<Vec<arkret_wire::EventFederationSubmission>, String> {
    let digest_suites = accepted_event_digest_suites(events)?;
    let mut digests = Vec::with_capacity(events.len());
    for (event, digest_suite) in events.iter().zip(digest_suites.iter().copied()) {
        let digest = event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| {
                format!(
                    "failed to digest Event {} for federation: {error}",
                    event.event_id
                )
            })?;
        digests.push(digest);
    }
    let evidence = state
        .event_queries()
        .publication_evidence_for_digests(&digests)
        .await
        .map_err(|error| format!("failed to read federation publication evidence: {error}"))?;
    // `pending_evidence` is this unit's own evidence, minted but not yet
    // durable: the identity-anchor batch commits its receipts in the same
    // transaction as the Events, and the outbox rows are built before that
    // transaction runs. Prefer it over the store so a first-time anchor can
    // still assemble its fanout.
    let by_digest = evidence
        .into_iter()
        .chain(pending_evidence.iter().cloned())
        .map(|record| (record.event_digest.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let mut submissions = Vec::with_capacity(events.len());
    for (event, digest) in events.iter().zip(digests) {
        let record = by_digest.get(&digest);
        let is_control_move = event.kind.is_control_plane();
        let proposal_digest = is_control_move
            .then(|| arkret_identifiers::Hash::new(digest.clone()))
            .transpose()
            .map_err(|error| {
                format!(
                    "Control Move {} digest is not a typed Hash: {error}",
                    event.event_id
                )
            })?;
        let durable_snapshot = if let Some(digest) = proposal_digest.as_ref() {
            state
                .projections()
                .control_proposal_snapshot(digest)
                .await
                .map_err(|error| {
                    format!(
                        "failed to read Control Move {} ingress evidence for federation: {error}",
                        event.event_id
                    )
                })?
        } else {
            None
        };
        let ackless_self_principal_admission_evidence = durable_snapshot
            .as_ref()
            .and_then(|snapshot| match &snapshot.ingress_class {
                arkret_state::state::store::ControlProposalIngressClass::AcklessSelfPrincipal(
                    evidence,
                ) => Some(evidence),
                arkret_state::state::store::ControlProposalIngressClass::AckRequired => None,
            })
            .map(|evidence| {
                Ok::<_, String>(arkret_wire::AcklessSelfPrincipalAdmissionEvidence {
                    device_id: arkret_wire::DeviceId::new(evidence.device_id.clone())
                        .map_err(|error| error.to_string())?,
                    device_authorize_event_id: arkret_wire::EventId::new(
                        evidence.device_authorize_event_id.clone(),
                    )
                    .map_err(|error| error.to_string())?,
                    device_generation_ref: evidence.device_generation_ref,
                    seal_basis_digest: arkret_wire::Hash::new(evidence.seal_basis_digest.clone())
                        .map_err(|error| error.to_string())?,
                })
            })
            .transpose()?;
        let control_proposal_ack = if let Some(proposal_digest) = proposal_digest {
            if ackless_self_principal_admission_evidence.is_some() {
                None
            } else {
                if let Some(ack) = current_control_proposal_ack
                    .filter(|ack| ack.proposal_digest == proposal_digest)
                    .or_else(|| {
                        pending_control_proposal_acks
                            .iter()
                            .find(|ack| ack.proposal_digest == proposal_digest)
                    })
                {
                    Some(ack.clone())
                } else {
                    match state
                        .projections()
                        .control_proposal_ack(&proposal_digest)
                        .await
                    {
                        Ok(Some(ack)) => Some(ack),
                        Ok(None) => {
                            return Err(format!(
                                "Control Move {} has no stored Control Proposal Ack and cannot be federated",
                                event.event_id
                            ));
                        }
                        Err(error) => {
                            return Err(format!(
                                "failed to read Control Move {} Control Proposal Ack for federation: {error}",
                                event.event_id
                            ));
                        }
                    }
                }
            }
        } else {
            None
        };
        submissions.push(arkret_wire::EventFederationSubmission {
            mls_frontier_leaves: match pending_mls_input {
                Some((event_id, leaves)) if *event_id == event.event_id => Some(leaves.to_vec()),
                _ => state
                    .event_queries()
                    .mls_frontier_leaves(event.event_id.as_str())
                    .await
                    .map_err(|error| error.to_string())?,
            },
            event: event.clone(),
            authorization_lease: record.map(|record| record.authorization_lease.clone()),
            ingress_receipts: record
                .map(|record| vec![record.ingress_receipt.clone()])
                .unwrap_or_default(),
            control_proposal_ack,
            ackless_self_principal_admission_evidence,
            membership_compensation_evidence: membership_compensation_evidence
                .filter(|evidence| {
                    authorization_selects_compensation(
                        event.authorization_ref.as_ref(),
                        &evidence.delegation.delegation_id,
                    )
                })
                .cloned(),
        });
    }
    Ok(submissions)
}

fn authorization_selects_compensation(
    authorization_ref: Option<&arkret_wire::AuthorizationRef>,
    delegation_id: &arkret_wire::MembershipCompensationDelegationRef,
) -> bool {
    authorization_ref.map(arkret_wire::AuthorizationRef::as_str) == Some(delegation_id.as_str())
}

/// Preserve a protocol-atomic local Event batch as one federation request.
/// Realm genesis units cannot be split into independent outbox rows because
/// receivers must validate and commit create + closed facets as one
/// transaction.
///
/// Built **before** the Event transaction so the rows can be committed with
/// it. Any construction failure is returned, never logged and swallowed: an
/// Event that needs fanout must not be accepted locally without a durable
/// delivery intent to go with it.
pub(super) async fn peer_event_batch_fanout_records(
    state: &AppState,
    parsed_events: &[ValidatedEventEnvelope],
    envelopes: &[Value],
) -> Result<Vec<soland_services::federation::FederationDeliveryRecord>, String> {
    let Some(first) = parsed_events.first() else {
        return Ok(Vec::new());
    };
    if parsed_events.len() != envelopes.len() {
        return Err("peer Event batch fanout cardinality mismatch".to_owned());
    }
    let mut peers = dynamic_peer_event_targets(state, first).await?;
    // The atomic genesis unit is routed after acceptance, but its canonical
    // destination is already explicit in a routable peer member join inside
    // the batch. Read that binding directly so bootstrap delivery never
    // depends on projection-install visibility or on the first Realm-create
    // envelope carrying a destination of its own.
    for (parsed, envelope) in parsed_events.iter().zip(envelopes) {
        let Some((member_id, service_id)) = joined_member_route_target(&parsed.kind, envelope)
        else {
            continue;
        };
        if service_id.as_str() == state.service_id()
            || peers
                .iter()
                .any(|peer| peer.service_id == service_id.as_str())
        {
            continue;
        }
        let url = crate::routing::federation::resolved_peer_base_url(
            state,
            service_id.as_str(),
            "station",
            false,
        )
        .await
        .ok();
        peers.push(DynamicPeerEventTarget {
            url,
            service_id: service_id.to_string(),
            membership_frontier: vec![parsed.event_id.to_string()],
            authority_witnesses: vec![soland_services::federation::RealmFanoutAuthorityWitness {
                member_id,
                membership_event_ref: parsed.event_id.to_string(),
            }],
        });
    }
    if peers.is_empty() {
        return Ok(Vec::new());
    }
    let events = envelopes
        .iter()
        .cloned()
        .map(serde_json::from_value::<Event>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to type check peer Event batch: {error}"))?;
    let cbs_proof_bundles =
        federation_cbs_proof_bundles(state, &events)
            .await
            .map_err(|error| {
                format!("failed to resolve peer Event batch CBS proof bundles: {error}")
            })?;
    // The Realm genesis path stores its ingress receipts before it gets here
    // (`mint_and_store_ingress_receipt`), so the store is the only source.
    let submissions = federation_submissions(state, &events, None, &[], &[], None, None).await?;
    let digest_suites = accepted_event_digest_suites(&events)?;
    let binding_payload = json!({
        "domain": arkret_wire::DomainSeparationId::PEER_EVENTS_COMMAND_SUBMIT_V1_SERVICE_BINDING_V1,
        "realm_id": first.realm_id,
        "event_ids": parsed_events.iter().map(|event| event.event_id.as_str()).collect::<Vec<_>>(),
        "canonical_digests": parsed_events.iter().map(|event| event.canonical_digest.as_str()).collect::<Vec<_>>(),
    });
    let now = chrono::Utc::now().timestamp();
    let mut records = Vec::new();
    for peer in peers {
        if peer.service_id == *state.service_id() {
            continue;
        }
        let service_binding_ref = service_binding_ref_for_target(first, &binding_payload, &peer)
            .ok_or_else(|| {
                format!(
                    "failed to build peer Event batch service binding for {}",
                    peer.service_id
                )
            })?;
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(state.service_id().as_bytes());
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(peer.service_id.as_bytes());
        for parsed in parsed_events {
            hasher_input.extend_from_slice(b"|");
            hasher_input.extend_from_slice(parsed.event_id.as_str().as_bytes());
            hasher_input.extend_from_slice(b"|");
            hasher_input.extend_from_slice(parsed.canonical_digest.as_bytes());
        }
        let idempotency_key = format!("ak:outbox:event-batch:{}", sha256_hex(&hasher_input));
        let body = EventsSubmitFederationBatchRequestBody {
            service_binding_ref,
            events: submissions.clone(),
            cbs_proof_bundles: cbs_proof_bundles.clone(),
        };
        body.validate_federation_transport(&digest_suites)
            .map_err(|error| {
                format!(
                    "peer Event batch for {} violates the federation transport contract: {error}",
                    peer.service_id
                )
            })?;
        let payload_json = canonical::canonical_json_bytes(&body)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| format!("failed to encode peer Event batch for {}", peer.service_id))?;
        records.push(soland_services::federation::FederationDeliveryRecord {
            id: uuid::Uuid::new_v4().to_string(),
            peer_id: arkret_wire::DidCoreId::new(peer.service_id)
                .map_err(|error| format!("peer Event target service_id is invalid: {error}"))?,
            peer_url: peer
                .url
                .as_deref()
                .map(|url| url.trim_end_matches('/').to_owned()),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key,
            payload_json,
            coalescing_key: None,
            coalescing_position: None,
            realm_fanout: Some(soland_services::federation::RealmFanoutBinding {
                realm_id: first.realm_id.to_string(),
                source_event_ids: parsed_events
                    .iter()
                    .map(|event| event.event_id.to_string())
                    .collect(),
                authority_witnesses: peer.authority_witnesses,
            }),
            created_at: now,
        });
    }
    Ok(records)
}

pub(super) async fn direct_conversation_founding_fanout_records(
    state: &AppState,
    parsed_events: &[ValidatedEventEnvelope],
    envelopes: &[Value],
    receipt: &DirectConversationFoundingAcceptanceReceipt,
    founding_authority_evidence: &arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingAuthorityEvidence,
    pending_control_proposal_acks: &[arkret_wire::ControlProposalAck],
) -> Result<Vec<soland_services::federation::FederationDeliveryRecord>, String> {
    if parsed_events.len() != 4 || envelopes.len() != 4 {
        return Err("Direct Conversation founding fanout requires exactly four Events".to_owned());
    }
    let mut peers = Vec::new();
    for (parsed, envelope) in parsed_events.iter().zip(envelopes) {
        let Some((member_id, service_id)) = joined_member_route_target(&parsed.kind, envelope)
        else {
            continue;
        };
        if service_id.as_str() == state.service_id()
            || peers
                .iter()
                .any(|peer: &DynamicPeerEventTarget| peer.service_id == service_id.as_str())
        {
            continue;
        }
        let url = crate::routing::federation::resolved_peer_base_url(
            state,
            service_id.as_str(),
            "station",
            false,
        )
        .await
        .ok();
        peers.push(DynamicPeerEventTarget {
            url,
            service_id: service_id.to_string(),
            membership_frontier: Vec::new(),
            authority_witnesses: vec![soland_services::federation::RealmFanoutAuthorityWitness {
                member_id,
                membership_event_ref: parsed.event_id.to_string(),
            }],
        });
    }
    let events = envelopes
        .iter()
        .cloned()
        .map(serde_json::from_value::<Event>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to type Direct Conversation founding Events: {error}"))?;
    let cbs_proof_bundles = federation_cbs_proof_bundles(state, &events)
        .await
        .map_err(|error| format!("failed to resolve founding CBS proof bundles: {error}"))?;
    let submissions = federation_submissions(
        state,
        &events,
        None,
        pending_control_proposal_acks,
        &[],
        None,
        None,
    )
    .await?;
    let submissions: [arkret_wire::EventFederationSubmission; 4] = submissions
        .try_into()
        .map_err(|_| "founding federation submission cardinality changed".to_owned())?;
    let now = chrono::Utc::now().timestamp();
    let mut records = Vec::new();
    for peer in peers {
        let body = arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingFederationSubmission {
            unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
            events: submissions.clone(),
            source_acceptance_receipt: receipt.clone(),
            founding_authority_evidence: founding_authority_evidence.clone(),
            cbs_proof_bundles: cbs_proof_bundles.clone(),
        };
        let payload_json = canonical::canonical_json_bytes(&body)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| format!("failed to encode founding delivery for {}", peer.service_id))?;
        records.push(soland_services::federation::FederationDeliveryRecord {
            id: uuid::Uuid::new_v4().to_string(),
            peer_id: arkret_wire::DidCoreId::new(peer.service_id.clone())
                .map_err(|error| format!("founding target service_id is invalid: {error}"))?,
            peer_url: peer
                .url
                .as_deref()
                .map(|url| url.trim_end_matches('/').to_owned()),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key: format!(
                "ak:outbox:direct-conversation-founding:{}:{}",
                receipt.pair_key, receipt.founding_unit_digest
            ),
            payload_json,
            coalescing_key: None,
            coalescing_position: None,
            realm_fanout: Some(soland_services::federation::RealmFanoutBinding {
                realm_id: parsed_events[0].realm_id.to_string(),
                source_event_ids: parsed_events
                    .iter()
                    .map(|event| event.event_id.to_string())
                    .collect(),
                authority_witnesses: peer.authority_witnesses,
            }),
            created_at: now,
        });
    }
    Ok(records)
}

fn joined_member_route_target(
    kind: &str,
    envelope: &Value,
) -> Option<(arkret_wire::ActorId, arkret_wire::DidCoreId)> {
    if kind != arkret_wire::EventKind::MemberState.as_str() {
        return None;
    }
    let payload = serde_json::from_value::<
        arkret_models_collaboration::governance::membership_invite::MembershipPayload,
    >(envelope.get("payload")?.clone())
    .ok()?;
    if payload.membership
        != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
    {
        return None;
    }
    let service_id = payload.member_id.route_service_id().clone();
    Some((payload.member_id, service_id))
}

/// Federation delivery intents for one accepted Event, built **before** its
/// commit so they can travel inside the same transaction.
///
/// `pending_evidence` carries publication evidence this unit minted but has not
/// yet persisted — the identity-anchor batch writes its ingress receipts in the
/// very transaction these rows join, so the store cannot see them yet. Paths
/// that store their receipts up front pass an empty slice.
pub(super) async fn peer_event_fanout_records(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
    current_control_proposal_ack: Option<&arkret_wire::ControlProposalAck>,
    pending_evidence: &[soland_services::events::PublicationEvidenceRecord],
    membership_compensation_evidence: Option<
        &arkret_wire::MembershipCompensationSubmissionEvidence,
    >,
    mls_frontier_leaves: Option<&[arkret_wire::mls_transition::MlsSecurityFrontierLeaf]>,
) -> Result<Vec<soland_services::federation::FederationDeliveryRecord>, String> {
    let mut peers = dynamic_peer_event_targets(state, parsed).await?;
    // A standalone member join is evaluated before its projection becomes
    // visible, so the joining member's Station route cannot appear in
    // `dynamic_peer_event_targets` yet. Treat the accepted Event as the
    // authority witness for that exact target, matching the atomic Realm
    // bootstrap path above.
    if let Some((member_id, service_id)) = joined_member_route_target(&parsed.kind, envelope)
        && service_id.as_str() != state.service_id()
        && !peers
            .iter()
            .any(|peer| peer.service_id == service_id.as_str())
    {
        let url = crate::routing::federation::resolved_peer_base_url(
            state,
            service_id.as_str(),
            "station",
            false,
        )
        .await
        .ok();
        peers.push(DynamicPeerEventTarget {
            url,
            service_id: service_id.to_string(),
            membership_frontier: vec![parsed.event_id.to_string()],
            authority_witnesses: vec![soland_services::federation::RealmFanoutAuthorityWitness {
                member_id,
                membership_event_ref: parsed.event_id.to_string(),
            }],
        });
    }
    if peers.is_empty() {
        return Ok(Vec::new());
    }
    let event_id = parsed.event_id.as_str();
    let binding_payload = json!({
        "domain": arkret_wire::DomainSeparationId::PEER_EVENTS_COMMAND_SUBMIT_V1_SERVICE_BINDING_V1,
        "realm_id": parsed.realm_id,
        "event_id": event_id,
        "canonical_digest": parsed.canonical_digest,
    });
    let event = serde_json::from_value::<Event>(envelope.clone())
        .map_err(|error| format!("failed to type check peer fanout Event {event_id}: {error}"))?;
    let now = chrono::Utc::now().timestamp();
    let mut records = Vec::new();
    for peer in peers {
        if peer.service_id == *state.service_id() {
            continue;
        }
        let dependencies = realm_event_dependency_records(state, parsed, envelope, &peer).await?;
        // A directed Event can be the first reason this Realm is routed to a
        // remote Station. Preserve the receiver's fail-closed
        // dependency admission by delivering the original atomic Realm
        // genesis unit immediately before that Event. The deterministic
        // idempotency key collapses this prerequisite for later fanout.
        if let Some(bootstrap) =
            realm_bootstrap_fanout_record(state, parsed, &peer, now.saturating_sub(1)).await?
        {
            records.push(bootstrap);
        }
        let service_binding_ref = service_binding_ref_for_target(parsed, &binding_payload, &peer)
            .ok_or_else(|| {
            format!(
                "failed to build typed dynamic ak.peer.events.command.submit.v1 service binding \
                     for {}",
                peer.service_id
            )
        })?;
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(state.service_id().as_bytes());
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(peer.service_id.as_bytes());
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(event_id.as_bytes());
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(parsed.canonical_digest.as_bytes());
        for dependency in &dependencies {
            hasher_input.extend_from_slice(b"|");
            hasher_input.extend_from_slice(dependency.event_id.as_bytes());
            hasher_input.extend_from_slice(b"|");
            hasher_input.extend_from_slice(dependency.canonical_digest.as_bytes());
        }
        let idempotency_key = format!("ak:outbox:event:{}", sha256_hex(&hasher_input));
        let mut peer_events = dependencies
            .iter()
            .map(|record| serde_json::from_value::<Event>(record.envelope.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                format!(
                    "failed to type check a causal prerequisite of {event_id} for {}: {error}",
                    peer.service_id
                )
            })?;
        peer_events.push(event.clone());
        peer_events.sort_by_key(|event| u8::from(!event.kind.is_control_plane()));
        let cbs_proof_bundles = federation_cbs_proof_bundles(state, &peer_events)
            .await
            .map_err(|error| {
                format!(
                    "failed to resolve dynamic peer Event {event_id} CBS proof bundles: {error}"
                )
            })?;
        let submissions = federation_submissions(
            state,
            &peer_events,
            current_control_proposal_ack,
            &[],
            pending_evidence,
            membership_compensation_evidence,
            mls_frontier_leaves.map(|leaves| (&event.event_id, leaves)),
        )
        .await?;
        let digest_suites = accepted_event_digest_suites(&peer_events)?;
        let body = EventsSubmitFederationBatchRequestBody {
            service_binding_ref,
            events: submissions,
            cbs_proof_bundles,
        };
        body.validate_federation_transport(&digest_suites).map_err(|error| {
            format!(
                "dynamic peer Event {event_id} violates the federation transport contract: {error}"
            )
        })?;
        let payload = canonical::canonical_json_bytes(&body)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| {
                format!(
                    "failed to encode dynamic ak.peer.events.command.submit.v1 body for {event_id}"
                )
            })?;
        records.push(soland_services::federation::FederationDeliveryRecord {
            id: uuid::Uuid::new_v4().to_string(),
            peer_id: arkret_wire::DidCoreId::new(peer.service_id).map_err(|error| {
                format!("dynamic peer Event target service_id is invalid: {error}")
            })?,
            peer_url: peer
                .url
                .as_deref()
                .map(|url| url.trim_end_matches('/').to_owned()),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key,
            payload_json: payload,
            coalescing_key: None,
            coalescing_position: None,
            realm_fanout: Some(soland_services::federation::RealmFanoutBinding {
                realm_id: parsed.realm_id.to_string(),
                source_event_ids: vec![parsed.event_id.to_string()],
                authority_witnesses: peer.authority_witnesses.clone(),
            }),
            created_at: now,
        });
    }
    Ok(records)
}

async fn realm_event_dependency_records(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
    peer: &DynamicPeerEventTarget,
) -> Result<Vec<AcceptedEvent>, String> {
    let records = state
        .event_queries()
        .realm_events_newest_first(parsed.realm_id.as_str())
        .await
        .map_err(|error| {
            format!(
                "failed to load causal prerequisites of Realm {} for {}: {error}",
                parsed.realm_id, peer.service_id
            )
        })?;
    let Some(create) = records
        .iter()
        .find(|record| record.kind == arkret_wire::EventKind::RealmCreate.as_str())
    else {
        return Ok(Vec::new());
    };
    let bootstrap_ids = records
        .iter()
        .filter(|record| {
            record.actor_id == create.actor_id && record.received_at == create.received_at
        })
        .map(|record| record.event_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let by_digest = records
        .iter()
        .map(|record| (record.canonical_digest.clone(), record.event_id.clone()))
        .collect::<BTreeMap<_, _>>();
    let by_id = records
        .into_iter()
        .map(|record| (record.event_id.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let mut visited = bootstrap_ids;
    let mut ordered = Vec::new();
    for dependency in &parsed.prev_refs {
        append_stored_event_dependencies(dependency.as_str(), &by_id, &mut visited, &mut ordered);
    }
    if let Some(seal_ref) = envelope.get("seal_ref").and_then(Value::as_str)
        && let Ok(seal_id) = arkret_identifiers::SealId::new(seal_ref.to_owned())
    {
        let mut pending = vec![seal_id];
        let mut seals_by_id = BTreeMap::new();
        while let Some(seal_id) = pending.pop() {
            if seals_by_id.contains_key(&seal_id) {
                continue;
            }
            if let Ok(Some(seal)) = state.projections().seal_by_id(&seal_id).await {
                pending.extend(seal.predecessor_refs.iter().cloned());
                seals_by_id.insert(seal_id, seal);
            }
        }
        let mut seals = seals_by_id.into_values().collect::<Vec<_>>();
        seals.sort_by(|left, right| {
            (left.notary_seq, left.id.as_str()).cmp(&(right.notary_seq, right.id.as_str()))
        });
        for seal in seals {
            for digest in seal.delta {
                if let Some(event_id) = by_digest.get(digest.as_str()) {
                    append_stored_event_dependencies(event_id, &by_id, &mut visited, &mut ordered);
                }
            }
        }
    }

    Ok(ordered)
}

fn append_stored_event_dependencies(
    event_id: &str,
    by_id: &BTreeMap<String, AcceptedEvent>,
    visited: &mut std::collections::BTreeSet<String>,
    ordered: &mut Vec<AcceptedEvent>,
) {
    if !visited.insert(event_id.to_owned()) {
        return;
    }
    let Some(record) = by_id.get(event_id) else {
        return;
    };
    if let Some(prev_refs) = record.envelope.get("prev_refs").and_then(Value::as_array) {
        for predecessor in prev_refs.iter().filter_map(Value::as_str) {
            append_stored_event_dependencies(predecessor, by_id, visited, ordered);
        }
    }
    ordered.push(record.clone());
}

/// The Realm genesis unit this peer needs before the Event itself, when one
/// applies.
///
/// `Ok(None)` means "not applicable" (no stored Realm-create, or a
/// agent PCR genesis, which is a different protocol unit). `Err` means
/// the prerequisite exists but could not be assembled — the caller must reject
/// the admission rather than accept an Event whose prerequisite would never
/// arrive.
async fn realm_bootstrap_fanout_record(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    peer: &DynamicPeerEventTarget,
    created_at: i64,
) -> Result<Option<soland_services::federation::FederationDeliveryRecord>, String> {
    let records = state
        .event_queries()
        .realm_events_newest_first(parsed.realm_id.as_str())
        .await
        .map_err(|error| {
            format!(
                "failed to load Realm {} bootstrap prerequisite for {}: {error}",
                parsed.realm_id, peer.service_id
            )
        })?;
    let Some(create) = records.iter().find(|record| {
        record.kind == arkret_wire::EventKind::RealmCreate.as_str()
            && record.realm_id.as_deref() == Some(parsed.realm_id.as_str())
    }) else {
        return Ok(None);
    };
    let bootstrap_received_at = create.received_at;
    let bootstrap_actor_id = create.actor_id.clone();
    let mut bootstrap_records = records
        .into_iter()
        .filter(|record| {
            record.realm_id.as_deref() == Some(parsed.realm_id.as_str())
                && record.actor_id == bootstrap_actor_id
                && record.received_at == bootstrap_received_at
        })
        .collect::<Vec<_>>();
    bootstrap_records.sort_by(|left, right| {
        left.actor_seq
            .cmp(&right.actor_seq)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let events = bootstrap_records
        .iter()
        .map(|record| serde_json::from_value::<Event>(record.envelope.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "failed to type check stored Realm {} bootstrap prerequisite: {error}",
                parsed.realm_id
            )
        })?;
    if arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events).is_err() {
        // Agent PCR genesis is a different protocol unit and does not
        // use ordinary Realm bootstrap fanout.
        return Ok(None);
    }

    let event_ids = bootstrap_records
        .iter()
        .map(|record| record.event_id.as_str())
        .collect::<Vec<_>>();
    let canonical_digests = bootstrap_records
        .iter()
        .map(|record| record.canonical_digest.as_str())
        .collect::<Vec<_>>();
    let binding_payload = json!({
        "domain": arkret_wire::DomainSeparationId::PEER_EVENTS_COMMAND_SUBMIT_V1_SERVICE_BINDING_V1,
        "realm_id": parsed.realm_id,
        "event_ids": event_ids,
        "canonical_digests": canonical_digests,
    });
    let Some(first_record) = bootstrap_records.first() else {
        return Ok(None);
    };
    let service_binding_ref = service_binding_ref_for_realm_target(
        parsed.realm_id.as_str(),
        first_record.event_id.as_str(),
        &binding_payload,
        peer,
    )
    .ok_or_else(|| {
        format!(
            "failed to build Realm {} bootstrap service binding for {}",
            parsed.realm_id, peer.service_id
        )
    })?;
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(state.service_id().as_bytes());
    hasher_input.extend_from_slice(b"|");
    hasher_input.extend_from_slice(peer.service_id.as_bytes());
    hasher_input.extend_from_slice(b"|");
    hasher_input.extend_from_slice(parsed.realm_id.as_str().as_bytes());
    for record in &bootstrap_records {
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(record.event_id.as_bytes());
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(record.canonical_digest.as_bytes());
    }
    let idempotency_key = format!("ak:outbox:realm-bootstrap:{}", sha256_hex(&hasher_input));
    // This prerequisite is a *stored* Realm genesis unit, so its evidence is
    // already durable — nothing pending to fold in.
    let submissions = federation_submissions(state, &events, None, &[], &[], None, None).await?;
    let digest_suites = accepted_event_digest_suites(&events)?;
    let body = EventsSubmitFederationBatchRequestBody {
        service_binding_ref,
        events: submissions,
        // Realm bootstrap prerequisites precede any Seal, so the batch closes
        // no CBS basis of its own.
        cbs_proof_bundles: Vec::new(),
    };
    body.validate_federation_transport(&digest_suites).map_err(|error| {
        format!(
            "Realm {} bootstrap prerequisite violates the federation transport contract: {error}",
            parsed.realm_id
        )
    })?;
    let payload_json = canonical::canonical_json_bytes(&body)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| {
            format!(
                "failed to encode Realm {} bootstrap prerequisite",
                parsed.realm_id
            )
        })?;
    Ok(Some(
        soland_services::federation::FederationDeliveryRecord {
            id: uuid::Uuid::new_v4().to_string(),
            peer_id: arkret_wire::DidCoreId::new(peer.service_id.clone()).map_err(|error| {
                format!("Realm bootstrap target service_id is invalid: {error}")
            })?,
            peer_url: peer
                .url
                .as_deref()
                .map(|url| url.trim_end_matches('/').to_owned()),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key,
            payload_json,
            coalescing_key: None,
            coalescing_position: None,
            realm_fanout: Some(soland_services::federation::RealmFanoutBinding {
                realm_id: parsed.realm_id.to_string(),
                source_event_ids: bootstrap_records
                    .iter()
                    .map(|record| record.event_id.clone())
                    .collect(),
                authority_witnesses: peer.authority_witnesses.clone(),
            }),
            created_at,
        },
    ))
}

struct DynamicPeerEventTarget {
    url: Option<String>,
    service_id: String,
    membership_frontier: Vec<String>,
    authority_witnesses: Vec<soland_services::federation::RealmFanoutAuthorityWitness>,
}

async fn dynamic_peer_event_targets(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
) -> Result<Vec<DynamicPeerEventTarget>, String> {
    let service_frontiers = {
        let projection = state.projections().snapshot();
        // sync/federation.md §4.4 — peers whose federation service delegation
        // for this Realm has been revoked MUST NOT receive future outbound
        // pushes. Compute the revoked-peer set once under the projection lock.
        // The revoke / grant capability control events themselves still fan out
        // so the peer can invalidate its allow cache (federation.md §4.4:
        // the pushed payload MUST carry the original Event Envelope so the
        // receiver can invalidate its capability cache immediately); only
        // non-capability events are gated.
        let is_capability_control_event = matches!(
            parsed.kind.as_str(),
            arkret_wire::event_kind_str::CAPABILITY_REVOKE
                | arkret_wire::event_kind_str::CAPABILITY_GRANT
        );
        let revoked_peers = if is_capability_control_event {
            std::collections::BTreeSet::new()
        } else {
            projection.federation_delivery_revoked_peers(parsed.realm_id.as_str())
        };
        let mut service_frontiers: BTreeMap<
            String,
            (
                BTreeSet<String>,
                Vec<soland_services::federation::RealmFanoutAuthorityWitness>,
            ),
        > = BTreeMap::new();
        for member in projection.members_of_realm(parsed.realm_id.as_str()) {
            if member.state != "join" {
                continue;
            }
            let member_id = serde_json::from_str::<arkret_wire::ActorId>(&member.member)
                .map_err(|error| format!("invalid projected member ActorId: {error}"))?;
            let service_id = member_id.route_service_id().as_str();
            if service_id == state.service_id() {
                continue;
            }
            if revoked_peers.contains(service_id) {
                tracing::info!(
                    event_id = %parsed.event_id,
                    realm_id = %parsed.realm_id,
                    revoked_peer_id = %service_id,
                    "skipping outbound federation push to peer with revoked service delegation (federation.md §4.4)"
                );
                continue;
            }
            let membership_event_ref = member.membership_event_ref.as_deref().ok_or_else(|| {
                format!(
                    "routable member {} lacks a membership Event reference",
                    member.member
                )
            })?;
            let entry = service_frontiers.entry(service_id.to_owned()).or_default();
            entry.0.insert(membership_event_ref.to_owned());
            entry
                .1
                .push(soland_services::federation::RealmFanoutAuthorityWitness {
                    member_id,
                    membership_event_ref: membership_event_ref.to_owned(),
                });
        }

        service_frontiers
    };

    let mut targets = Vec::new();
    for (service_id, (membership_frontier, authority_witnesses)) in service_frontiers {
        let url = crate::routing::federation::resolved_peer_base_url(
            state,
            &service_id,
            "station",
            false,
        )
        .await
        .ok();
        targets.push(DynamicPeerEventTarget {
            url,
            service_id,
            membership_frontier: membership_frontier.into_iter().collect(),
            authority_witnesses,
        });
    }
    Ok(targets)
}

fn service_binding_ref_for_target(
    parsed: &ValidatedEventEnvelope,
    binding_payload: &Value,
    target: &DynamicPeerEventTarget,
) -> Option<arkret_models_collaboration::event_sync::FederationServiceBindingRef> {
    service_binding_ref_for_realm_target(
        parsed.realm_id.as_str(),
        parsed.event_id.as_str(),
        binding_payload,
        target,
    )
}

fn service_binding_ref_for_realm_target(
    realm_id: &str,
    fallback_event_id: &str,
    binding_payload: &Value,
    target: &DynamicPeerEventTarget,
) -> Option<arkret_models_collaboration::event_sync::FederationServiceBindingRef> {
    let membership_frontier =
        typed_frontier_or_fallback(&target.membership_frontier, fallback_event_id)?;
    Some(
        arkret_models_collaboration::event_sync::FederationServiceBindingRef {
            realm_id: RealmId::new(realm_id.to_owned()).ok()?,
            realm_policy_digest: Hash::new(canonical_json_hash(binding_payload)?).ok()?,
            membership_frontier,
            destination_kind: "station".to_owned(),
        },
    )
}

pub(super) fn typed_frontier_or_fallback(
    frontier: &[String],
    fallback_event_id: &str,
) -> Option<Vec<EventId>> {
    let mut typed = frontier
        .iter()
        .filter_map(|event_id| EventId::new(event_id.to_owned()).ok())
        .collect::<Vec<_>>();
    if typed.is_empty() {
        typed.push(EventId::new(fallback_event_id.to_owned()).ok()?);
    }
    Some(typed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{authorization_selects_compensation, joined_member_route_target};

    #[test]
    fn compensation_carrier_follows_only_its_exact_event() {
        let delegation_id = arkret_wire::MembershipCompensationDelegationRef::new(format!(
            "ak:membership_compensation_delegation:sha256:{}",
            "11".repeat(32)
        ))
        .unwrap();
        let selected = arkret_wire::AuthorizationRef::new(delegation_id.as_str()).unwrap();
        let ordinary = arkret_wire::AuthorizationRef::new(
            "ak:grant:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM",
        )
        .unwrap();

        assert!(authorization_selects_compensation(
            Some(&selected),
            &delegation_id
        ));
        assert!(!authorization_selects_compensation(
            Some(&ordinary),
            &delegation_id
        ));
        assert!(!authorization_selects_compensation(None, &delegation_id));
    }

    #[test]
    fn bootstrap_fanout_derives_peer_service_from_joined_account_id() {
        let envelope = json!({
            "payload": {
                "member_id": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:web:bob.example",
                        "station_id": "ak:did_core:web:soland-beta.example"
                    }
                },
                "membership": "join"
            }
        });
        let (member_id, service_id) =
            joined_member_route_target(arkret_wire::EventKind::MemberState.as_str(), &envelope)
                .expect("joined account has a route service");
        assert_eq!(
            member_id.signing_principal_id().as_str(),
            "ak:did_core:web:bob.example"
        );
        assert_eq!(service_id.as_str(), "ak:did_core:web:soland-beta.example");
        assert_eq!(
            joined_member_route_target(arkret_wire::EventKind::RealmCreate.as_str(), &envelope,),
            None
        );
        assert_eq!(
            joined_member_route_target(
                arkret_wire::EventKind::MemberState.as_str(),
                &json!({
                    "payload": {
                        "member_id": {
                            "kind": "account",
                            "account_id": {
                                "principal_id": "ak:did_core:web:bob.example",
                                "station_id": "ak:did_core:web:soland-beta.example"
                            }
                        },
                        "membership": "leave"
                    }
                }),
            ),
            None
        );
    }
}
