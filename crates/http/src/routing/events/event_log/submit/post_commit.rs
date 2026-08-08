use super::*;

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
        remove_rejected_claim_active_material(&mut record.third_party_id, true);
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
    third_party_id: &mut Option<Value>,
    remove_commitment: bool,
) {
    let Some(value) = third_party_id.as_mut() else {
        return;
    };
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for key in [
        "token_salt",
        "token_salt_id",
        "lookup_table_ref",
        "pepper",
        "pepper_id",
    ] {
        object.remove(key);
    }
    if remove_commitment {
        object.remove("token_commitment");
    }
}

/// Every Seal a receiver needs to close the transported Events' CBA basis,
/// packaged as the request's `cba_proof_bundles[]`.
///
/// Each target gets its own single-target bundle. Bundles may overlap because
/// the wire contract is receiver-relative and permits bounded verifiable
/// supersets.
fn federation_cba_proof_bundles(
    state: &AppState,
    events: &[Event],
) -> Result<Vec<arkret_wire::CbaProofBundle>, String> {
    let mut targets = BTreeSet::new();
    for event in events {
        if let Some(seal_ref) = &event.seal_ref {
            targets.insert(seal_ref.clone());
        }
        if let Some(seal_basis) = &event.seal_basis {
            targets.extend(seal_basis.leaves.iter().cloned());
        }
    }
    if targets.len() > arkret_wire::event_submission::MAX_SUBMISSION_CBA_BUNDLES {
        return Err("federation CBA target count exceeds the v1 limit".to_owned());
    }
    targets
        .into_iter()
        .map(|target_seal_ref| {
            let mut pending = vec![target_seal_ref.clone()];
            let mut by_id = BTreeMap::new();
            while let Some(seal_id) = pending.pop() {
                if by_id.contains_key(&seal_id) {
                    continue;
                }
                let seal = state
                    .projections()
                    .seal_by_id(&seal_id)
                    .map_err(|error| {
                        format!("read federation Seal prerequisite {seal_id}: {error}")
                    })?
                    .ok_or_else(|| {
                        format!("federation Seal prerequisite {seal_id} is unavailable")
                    })?;
                pending.extend(seal.predecessor_refs.iter().cloned());
                by_id.insert(seal_id, seal);
            }
            if by_id.len() > arkret_wire::cba_proof_bundle::MAX_BUNDLE_SEALS {
                return Err("federation Seal prerequisite closure exceeds the v1 limit".to_owned());
            }
            Ok(arkret_wire::CbaProofBundle {
                target_seal_ref,
                seals: by_id.into_values().collect(),
                control_moves: Vec::new(),
                inclusion_proofs: Vec::new(),
                availability_proofs: Vec::new(),
            })
        })
        .collect()
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
) -> Result<Vec<arkret_wire::EventFederationSubmission>, String> {
    let mut digests = Vec::with_capacity(events.len());
    for event in events {
        let digest = event.event_digest().map_err(|error| {
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
        let is_control_move = event.kind.is_reducer_input()
            && event.seal_ref.is_none()
            && event.auth_context.is_none();
        let control_proposal_ack = if is_control_move {
            let proposal_digest =
                arkret_identifiers::Hash::new(digest.clone()).map_err(|error| {
                    format!(
                        "Control Move {} digest is not a typed Hash: {error}",
                        event.event_id
                    )
                })?;
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
                match state.projections().control_proposal_ack(&proposal_digest) {
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
        } else {
            None
        };
        submissions.push(arkret_wire::EventFederationSubmission {
            event: event.clone(),
            authorization_lease: record.map(|record| record.authorization_lease.clone()),
            ingress_receipts: record
                .map(|record| vec![record.ingress_receipt.clone()])
                .unwrap_or_default(),
            control_proposal_ack,
            membership_compensation_evidence: membership_compensation_evidence.cloned(),
        });
    }
    Ok(submissions)
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
    let mut peers = dynamic_peer_event_targets(state, first).await;
    // The atomic genesis unit is routed after acceptance, but its canonical
    // destination is already explicit in a routable peer member join inside
    // the batch. Read that binding directly so bootstrap delivery never
    // depends on projection-install visibility or on the first Realm-create
    // envelope carrying a destination of its own.
    for (parsed, envelope) in parsed_events.iter().zip(envelopes) {
        let Some(service_id) = routable_member_delivery_service(&parsed.kind, envelope) else {
            continue;
        };
        if service_id == state.service_id()
            || peers.iter().any(|peer| peer.service_id == service_id)
        {
            continue;
        }
        let Some(url) =
            crate::routing::federation::federation::peer_url_for_service_id(state, service_id)
        else {
            tracing::warn!(
                event_id = %parsed.event_id,
                realm_id = %parsed.realm_id,
                destination_service_id = service_id,
                "bootstrap peer member has no configured federation service URL"
            );
            continue;
        };
        peers.push(DynamicPeerEventTarget {
            url,
            service_id: service_id.to_owned(),
            membership_frontier: vec![parsed.event_id.clone()],
            delivery_binding_frontier: vec![parsed.event_id.clone()],
            realm_sync_endpoint: false,
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
    let mut signer_key_evidence = Vec::new();
    let mut evidence_methods = std::collections::BTreeSet::new();
    for event in &events {
        let evidence = crate::jws_verify::federated_event_signer_evidence(state, event)
            .await
            .map_err(|error| {
                format!(
                    "failed to resolve peer Event batch signer evidence for {}: {error}",
                    event.event_id
                )
            })?;
        for entry in evidence {
            if evidence_methods.insert(entry.verification_method.clone()) {
                signer_key_evidence.push(entry);
            }
        }
    }
    let agent_signer_evidence_bundle =
        crate::routing::identity::agents::evidence::signer_evidence_bundle_for_events(
            state, &events,
        )
        .await;
    let cba_proof_bundles = federation_cba_proof_bundles(state, &events).map_err(|error| {
        format!("failed to resolve peer Event batch CBA proof bundles: {error}")
    })?;
    // The Realm genesis path stores its ingress receipts before it gets here
    // (`mint_and_store_ingress_receipt`), so the store is the only source.
    let submissions = federation_submissions(state, &events, None, &[], &[], None).await?;
    let binding_payload = json!({
        "domain": "ak.peer.events.command.submit.service_binding.v1",
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
            hasher_input.extend_from_slice(parsed.event_id.as_bytes());
            hasher_input.extend_from_slice(b"|");
            hasher_input.extend_from_slice(parsed.canonical_digest.as_bytes());
        }
        let idempotency_key = format!("ak:outbox:event-batch:{}", sha256_hex(&hasher_input));
        let body = EventsSubmitFederationBatchRequestBody {
            service_binding_ref,
            events: submissions.clone(),
            cba_proof_bundles: cba_proof_bundles.clone(),
            signer_key_evidence: signer_key_evidence.clone(),
            agent_signer_evidence_bundle: agent_signer_evidence_bundle.clone(),
        };
        body.validate_federation_transport().map_err(|error| {
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
            peer_did: peer.service_id,
            peer_url: peer.url.trim_end_matches('/').to_owned(),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key,
            payload_json,
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
    founder_basis_evidence: &arkret_models_collaboration::direct_conversation_ops::DirectConversationFounderBasisEvidence,
    source_service_binding: &arkret_models_collaboration::direct_conversation_ops::AcceptedAtServiceBinding,
    pending_control_proposal_acks: &[arkret_wire::ControlProposalAck],
) -> Result<Vec<soland_services::federation::FederationDeliveryRecord>, String> {
    if parsed_events.len() != 3 || envelopes.len() != 3 {
        return Err("Direct Conversation founding fanout requires exactly three Events".to_owned());
    }
    let mut peers = Vec::new();
    for (parsed, envelope) in parsed_events.iter().zip(envelopes) {
        let Some(service_id) = routable_member_delivery_service(&parsed.kind, envelope) else {
            continue;
        };
        if service_id == state.service_id()
            || peers
                .iter()
                .any(|peer: &DynamicPeerEventTarget| peer.service_id == service_id)
        {
            continue;
        }
        let Some(url) =
            crate::routing::federation::federation::peer_url_for_service_id(state, service_id)
        else {
            return Err(format!(
                "Direct Conversation founding destination {service_id} has no configured federation URL"
            ));
        };
        peers.push(DynamicPeerEventTarget {
            url,
            service_id: service_id.to_owned(),
            membership_frontier: Vec::new(),
            delivery_binding_frontier: Vec::new(),
            realm_sync_endpoint: false,
        });
    }
    let events = envelopes
        .iter()
        .cloned()
        .map(serde_json::from_value::<Event>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to type Direct Conversation founding Events: {error}"))?;
    let mut signer_key_evidence = Vec::new();
    let mut methods = std::collections::BTreeSet::new();
    for event in &events {
        for evidence in crate::jws_verify::federated_event_signer_evidence(state, event)
            .await
            .map_err(|error| format!("failed to resolve founding signer evidence: {error}"))?
        {
            if methods.insert(evidence.verification_method.clone()) {
                signer_key_evidence.push(evidence);
            }
        }
    }
    let cba_proof_bundles = federation_cba_proof_bundles(state, &events)
        .map_err(|error| format!("failed to resolve founding CBA proof bundles: {error}"))?;
    let submissions = federation_submissions(
        state,
        &events,
        None,
        pending_control_proposal_acks,
        &[],
        None,
    )
    .await?;
    let submissions: [arkret_wire::EventFederationSubmission; 3] = submissions
        .try_into()
        .map_err(|_| "founding federation submission cardinality changed".to_owned())?;
    let now = chrono::Utc::now().timestamp();
    let mut records = Vec::new();
    for peer in peers {
        let body = arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingFederationSubmission {
            unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
            events: submissions.clone(),
            source_acceptance_receipt: receipt.clone(),
            source_service_continuity: arkret_models_collaboration::direct_conversation_ops::PrincipalServiceBindingContinuity {
                accepted_binding: source_service_binding.clone(),
                cutovers: Vec::new(),
            },
            founder_basis_evidence: founder_basis_evidence.clone(),
            cba_proof_bundles: cba_proof_bundles.clone(),
            signer_key_evidence: signer_key_evidence.clone(),
        };
        let payload_json = canonical::canonical_json_bytes(&body)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| format!("failed to encode founding delivery for {}", peer.service_id))?;
        records.push(soland_services::federation::FederationDeliveryRecord {
            id: uuid::Uuid::new_v4().to_string(),
            peer_did: peer.service_id.clone(),
            peer_url: peer.url.trim_end_matches('/').to_owned(),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key: format!(
                "ak:outbox:direct-conversation-founding:{}:{}",
                receipt.pair_key, receipt.founding_unit_digest
            ),
            payload_json,
            created_at: now,
        });
    }
    Ok(records)
}

fn routable_member_delivery_service<'a>(kind: &str, envelope: &'a Value) -> Option<&'a str> {
    if kind != arkret_wire::EventKind::MEMBER_STATE {
        return None;
    }
    let payload = envelope.get("payload")?;
    if payload.get("membership").and_then(Value::as_str) != Some("join")
        || payload.get("delivery_status").and_then(Value::as_str) != Some("routable")
    {
        return None;
    }
    payload
        .get("delivery_binding")
        .and_then(Value::as_object)
        .and_then(|binding| binding.get("recipient_service_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|service_id| !service_id.is_empty())
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
) -> Result<Vec<soland_services::federation::FederationDeliveryRecord>, String> {
    let peers = dynamic_peer_event_targets(state, parsed).await;
    if peers.is_empty() {
        return Ok(Vec::new());
    }
    let event_id = parsed.event_id.as_str();
    let binding_payload = json!({
        "domain": "ak.peer.events.command.submit.service_binding.v1",
        "realm_id": parsed.realm_id,
        "event_id": event_id,
        "canonical_digest": parsed.canonical_digest,
    });
    let event = serde_json::from_value::<Event>(envelope.clone())
        .map_err(|error| format!("failed to type check peer fanout Event {event_id}: {error}"))?;
    let signer_key_evidence = crate::jws_verify::federated_event_signer_evidence(state, &event)
        .await
        .map_err(|error| {
            format!("failed to resolve peer Event {event_id} signer evidence: {error}")
        })?;
    let agent_signer_evidence_bundle =
        crate::routing::identity::agents::evidence::signer_evidence_bundle_for_events(
            state,
            std::slice::from_ref(&event),
        )
        .await;
    let now = chrono::Utc::now().timestamp();
    let mut records = Vec::new();
    for peer in peers {
        if peer.service_id == *state.service_id() {
            continue;
        }
        let dependencies = realm_event_dependency_records(state, parsed, envelope, &peer).await?;
        // A directed Event can be the first reason this Realm is routed to a
        // remote principal server. Preserve the receiver's fail-closed
        // dependency admission by delivering the original atomic Realm
        // genesis unit immediately before that Event. The deterministic
        // idempotency key collapses this prerequisite for later fanout.
        if !peer.realm_sync_endpoint
            && let Some(bootstrap) =
                realm_bootstrap_fanout_record(state, parsed, &peer, now.saturating_sub(1)).await?
        {
            records.push(bootstrap);
        }
        let service_binding_ref = service_binding_ref_for_target(parsed, &binding_payload, &peer)
            .ok_or_else(|| {
            format!(
                "failed to build typed dynamic ak.peer.events.command.submit service binding \
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
        for frontier in &peer.delivery_binding_frontier {
            hasher_input.extend_from_slice(b"|");
            hasher_input.extend_from_slice(frontier.as_bytes());
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
        peer_events.sort_by_key(|event| {
            match event
                .kind
                .descriptor()
                .and_then(|descriptor| descriptor.plane)
            {
                Some("control") => 0_u8,
                _ => 1_u8,
            }
        });
        let mut peer_signer_key_evidence = signer_key_evidence.clone();
        let mut evidence_methods = peer_signer_key_evidence
            .iter()
            .map(|evidence| evidence.verification_method.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for dependency in &peer_events {
            let evidence = crate::jws_verify::federated_event_signer_evidence(state, dependency)
                .await
                .map_err(|error| {
                    format!(
                        "failed to resolve causal prerequisite {} signer evidence: {error}",
                        dependency.event_id
                    )
                })?;
            for entry in evidence {
                if evidence_methods.insert(entry.verification_method.clone()) {
                    peer_signer_key_evidence.push(entry);
                }
            }
        }
        let peer_agent_signer_evidence_bundle =
            crate::routing::identity::agents::evidence::signer_evidence_bundle_for_events(
                state,
                &peer_events,
            )
            .await
            .or_else(|| agent_signer_evidence_bundle.clone());
        let cba_proof_bundles =
            federation_cba_proof_bundles(state, &peer_events).map_err(|error| {
                format!(
                    "failed to resolve dynamic peer Event {event_id} CBA proof bundles: {error}"
                )
            })?;
        let submissions = federation_submissions(
            state,
            &peer_events,
            current_control_proposal_ack,
            &[],
            pending_evidence,
            membership_compensation_evidence,
        )
        .await?;
        let body = EventsSubmitFederationBatchRequestBody {
            service_binding_ref,
            events: submissions,
            cba_proof_bundles,
            signer_key_evidence: peer_signer_key_evidence,
            agent_signer_evidence_bundle: peer_agent_signer_evidence_bundle,
        };
        body.validate_federation_transport().map_err(|error| {
            format!(
                "dynamic peer Event {event_id} violates the federation transport contract: {error}"
            )
        })?;
        let payload = canonical::canonical_json_bytes(&body)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| {
                format!(
                    "failed to encode dynamic ak.peer.events.command.submit body for {event_id}"
                )
            })?;
        records.push(soland_services::federation::FederationDeliveryRecord {
            id: uuid::Uuid::new_v4().to_string(),
            peer_did: peer.service_id,
            peer_url: peer.url.trim_end_matches('/').to_owned(),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key,
            payload_json: payload,
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
) -> Result<Vec<CanonicalEventRecord>, String> {
    let records = state
        .event_queries()
        .realm_events_newest_first(&parsed.realm_id)
        .await
        .map_err(|error| {
            format!(
                "failed to load causal prerequisites of Realm {} for {}: {error}",
                parsed.realm_id, peer.service_id
            )
        })?;
    let Some(create) = records
        .iter()
        .find(|record| record.kind == arkret_wire::EventKind::REALM_CREATE)
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
        append_stored_event_dependencies(dependency, &by_id, &mut visited, &mut ordered);
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
            if let Ok(Some(seal)) = state.projections().seal_by_id(&seal_id) {
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
    by_id: &BTreeMap<String, CanonicalEventRecord>,
    visited: &mut std::collections::BTreeSet<String>,
    ordered: &mut Vec<CanonicalEventRecord>,
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
/// managed-agent PCR genesis, which is a different protocol unit). `Err` means
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
        .realm_events_newest_first(&parsed.realm_id)
        .await
        .map_err(|error| {
            format!(
                "failed to load Realm {} bootstrap prerequisite for {}: {error}",
                parsed.realm_id, peer.service_id
            )
        })?;
    let Some(create) = records.iter().find(|record| {
        record.kind == arkret_wire::EventKind::REALM_CREATE
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
        // Managed-agent PCR genesis is a different protocol unit and does not
        // use ordinary Realm bootstrap fanout.
        return Ok(None);
    }

    let mut signer_key_evidence = Vec::new();
    let mut evidence_methods = std::collections::BTreeSet::new();
    for event in &events {
        let evidence = crate::jws_verify::federated_event_signer_evidence(state, event)
            .await
            .map_err(|error| {
                format!(
                    "failed to resolve Realm bootstrap prerequisite {} signer evidence: {error}",
                    event.event_id
                )
            })?;
        for entry in evidence {
            if evidence_methods.insert(entry.verification_method.clone()) {
                signer_key_evidence.push(entry);
            }
        }
    }
    let agent_signer_evidence_bundle =
        crate::routing::identity::agents::evidence::signer_evidence_bundle_for_events(
            state, &events,
        )
        .await;
    let event_ids = bootstrap_records
        .iter()
        .map(|record| record.event_id.as_str())
        .collect::<Vec<_>>();
    let canonical_digests = bootstrap_records
        .iter()
        .map(|record| record.canonical_digest.as_str())
        .collect::<Vec<_>>();
    let binding_payload = json!({
        "domain": "ak.peer.events.command.submit.service_binding.v1",
        "realm_id": parsed.realm_id,
        "event_ids": event_ids,
        "canonical_digests": canonical_digests,
    });
    let Some(first_record) = bootstrap_records.first() else {
        return Ok(None);
    };
    let service_binding_ref = service_binding_ref_for_realm_target(
        &parsed.realm_id,
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
    hasher_input.extend_from_slice(parsed.realm_id.as_bytes());
    for record in &bootstrap_records {
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(record.event_id.as_bytes());
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(record.canonical_digest.as_bytes());
    }
    let idempotency_key = format!("ak:outbox:realm-bootstrap:{}", sha256_hex(&hasher_input));
    // This prerequisite is a *stored* Realm genesis unit, so its evidence is
    // already durable — nothing pending to fold in.
    let submissions = federation_submissions(state, &events, None, &[], &[], None).await?;
    let body = EventsSubmitFederationBatchRequestBody {
        service_binding_ref,
        events: submissions,
        // Realm bootstrap prerequisites precede any Seal, so the batch closes
        // no CBA basis of its own.
        cba_proof_bundles: Vec::new(),
        signer_key_evidence,
        agent_signer_evidence_bundle,
    };
    body.validate_federation_transport().map_err(|error| {
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
            peer_did: peer.service_id.clone(),
            peer_url: peer.url.trim_end_matches('/').to_owned(),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key,
            payload_json,
            created_at,
        },
    ))
}

struct DynamicPeerEventTarget {
    url: String,
    service_id: String,
    membership_frontier: Vec<String>,
    delivery_binding_frontier: Vec<String>,
    realm_sync_endpoint: bool,
}

async fn dynamic_peer_event_targets(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
) -> Vec<DynamicPeerEventTarget> {
    let mut service_frontiers = {
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
            "ak.capability.revoke" | "ak.capability.grant"
        );
        let revoked_peers = if is_capability_control_event {
            std::collections::BTreeSet::new()
        } else {
            projection.federation_delivery_revoked_peers(&parsed.realm_id)
        };
        let mut service_frontiers: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> =
            BTreeMap::new();
        for member in projection.members_of_realm(&parsed.realm_id) {
            if member.delivery_status.as_deref() != Some("routable") {
                continue;
            }
            let Some(service_id) = member.recipient_service_id.as_deref() else {
                continue;
            };
            if service_id == state.service_id() {
                continue;
            }
            if revoked_peers.contains(service_id) {
                tracing::info!(
                    event_id = %parsed.event_id,
                    realm_id = %parsed.realm_id,
                    revoked_peer_service_id = %service_id,
                    "skipping outbound federation push to peer with revoked service delegation (federation.md §4.4)"
                );
                continue;
            }
            let entry = service_frontiers.entry(service_id.to_owned()).or_default();
            if let Some(frontier) = member.membership_event_ref.as_deref() {
                entry.0.insert(frontier.to_owned());
            }
            if let Some(frontier) = member
                .delivery_binding_frontier
                .as_deref()
                .or(member.membership_event_ref.as_deref())
            {
                entry.1.insert(frontier.to_owned());
            }
        }

        service_frontiers
    };

    // Realm-level `sync_endpoints` are the canonical replication binding for
    // mirrors and shared sync services. They are independent of member-level
    // delivery bindings and are carried by the current accepted policy bundle.
    let mut endpoint_urls = BTreeMap::new();
    let mut realm_sync_endpoint_service_ids = BTreeSet::new();
    if let Ok(records) = state
        .event_queries()
        .realm_events_newest_first(&parsed.realm_id)
        .await
        && let Some(policy_bundle) = records
            .iter()
            .find(|record| record.kind == arkret_wire::EventKind::REALM_POLICY_BUNDLE)
        && let Some(endpoints) = policy_bundle
            .envelope
            .pointer("/payload/sync_endpoints")
            .and_then(Value::as_array)
    {
        for endpoint in endpoints {
            let Some(service_id) = endpoint
                .get("did")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            if service_id == state.service_id() {
                continue;
            }
            let Some(url) = endpoint
                .get("endpoint")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let entry = service_frontiers.entry(service_id.to_owned()).or_default();
            entry.0.insert(policy_bundle.event_id.clone());
            entry.1.insert(policy_bundle.event_id.clone());
            endpoint_urls.insert(service_id.to_owned(), url.to_owned());
            realm_sync_endpoint_service_ids.insert(service_id.to_owned());
        }
    }

    service_frontiers
        .into_iter()
        .filter_map(
            |(service_id, (membership_frontier, delivery_binding_frontier))| {
                let url = match endpoint_urls.remove(&service_id).or_else(|| {
                    crate::routing::federation::federation::peer_url_for_service_id(
                        state,
                        &service_id,
                    )
                }) {
                    Some(url) => url,
                    None => {
                        tracing::warn!(
                            event_id = %parsed.event_id,
                            realm_id = %parsed.realm_id,
                            destination_service_id = %service_id,
                            "dynamic peer event fanout target has no configured service URL"
                        );
                        return None;
                    }
                };
                let realm_sync_endpoint = realm_sync_endpoint_service_ids.contains(&service_id);
                Some(DynamicPeerEventTarget {
                    url,
                    service_id,
                    membership_frontier: membership_frontier.into_iter().collect(),
                    delivery_binding_frontier: delivery_binding_frontier.into_iter().collect(),
                    realm_sync_endpoint,
                })
            },
        )
        .collect()
}

fn service_binding_ref_for_target(
    parsed: &ValidatedEventEnvelope,
    binding_payload: &Value,
    target: &DynamicPeerEventTarget,
) -> Option<arkret_models_collaboration::event_sync::FederationServiceBindingRef> {
    service_binding_ref_for_realm_target(
        &parsed.realm_id,
        &parsed.event_id,
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
    let delivery_binding_frontier =
        typed_frontier_or_fallback(&target.delivery_binding_frontier, fallback_event_id)?;
    Some(
        arkret_models_collaboration::event_sync::FederationServiceBindingRef {
            realm_id: RealmId::new(realm_id.to_owned()).ok()?,
            realm_policy_digest: Hash::new(canonical_json_hash(binding_payload)?).ok()?,
            membership_frontier,
            delivery_binding_frontier,
            destination_service_kind: "principal_server".to_owned(),
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

    use super::routable_member_delivery_service;

    #[test]
    fn bootstrap_fanout_reads_routable_peer_service_from_member_join() {
        let envelope = json!({
            "payload": {
                "actor_id": "did:web:bob.example",
                "membership": "join",
                "delivery_status": "routable",
                "delivery_binding": {
                    "binding_source": "explicit",
                    "recipient_service_id": "did:web:soland-beta.example"
                }
            }
        });
        assert_eq!(
            routable_member_delivery_service(arkret_wire::EventKind::MEMBER_STATE, &envelope,),
            Some("did:web:soland-beta.example")
        );
        assert_eq!(
            routable_member_delivery_service(arkret_wire::EventKind::REALM_CREATE, &envelope,),
            None
        );
        assert_eq!(
            routable_member_delivery_service(
                arkret_wire::EventKind::MEMBER_STATE,
                &json!({
                    "payload": {
                        "membership": "join",
                        "delivery_status": "unroutable"
                    }
                }),
            ),
            None
        );
    }
}
