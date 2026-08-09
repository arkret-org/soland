use arkret_models_collaboration::agent_operations::AgentLifecycleState;

use super::*;

pub(crate) fn direct_pair_key(
    state: &AppState,
    left: &str,
    right: &str,
) -> Result<String, AppError> {
    let trust_domain = arkret_identifiers::TypedTrustDomainId::new(
        state.config().trust_domain.clone(),
    )
    .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    let left = direct_pair_key_participant(left, "actor")?;
    let right = direct_pair_key_participant(right, "peer")?;
    arkret_models_collaboration::objects::direct_conversation::direct_conversation_pair_key(
        trust_domain,
        left,
        right,
    )
    .map(|pair_key| pair_key.into_string())
    .map_err(|error| AppError::internal(format!("direct pair key construction failed: {error}")))
}

pub(super) fn direct_pair_key_participant(
    did: &str,
    role: &str,
) -> Result<
    arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant,
    AppError,
> {
    let did = Did::new(did.to_owned()).map_err(|error| {
        AppError::internal(format!(
            "stored direct conversation {role} DID invalid: {error}"
        ))
    })?;
    let did_str = did.as_str();
    if DIRECT_CONVERSATION_PAIRWISE_DID_METHOD_PREFIXES
        .iter()
        .any(|prefix| did_str.starts_with(prefix))
    {
        return Err(direct_resolve_precondition(
            arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
            "direct conversation pairwise DID requires a verified stable-subject identity link",
        ));
    }
    Ok(arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
        did,
    ))
}

/// The settled coordinates for a pair.
///
/// `contact-and-direct-conversation.md` §8.3: the binding cell is an or_set and
/// the binding is written once and never retired, so "settled" means every
/// endorsement agrees on one digest. Two distinct digests are a materialization
/// conflict, not a race to resolve — see [`direct_binding_conflict`].
pub(crate) fn active_direct_binding(
    state: &AppState,
    pair_key: &str,
) -> Option<DirectConversationBindingRecord> {
    let binding = state.contacts().direct_binding(pair_key)?;
    direct_binding_matches_projection(state, &binding).then_some(binding)
}

/// `true` when the pair carries two distinct endorsement digests
/// (`direct_conversation_pair_materialization_conflict`, §5.7).
pub(crate) fn direct_binding_conflict(state: &AppState, pair_key: &str) -> bool {
    state.contacts().direct_binding_is_conflicted(pair_key)
}

pub(crate) fn direct_binding_matches_projection(
    state: &AppState,
    binding: &DirectConversationBindingRecord,
) -> bool {
    if binding.participants_unordered.len() != 2 {
        return false;
    }
    let projection = state.projections().snapshot();
    if !projection.realm_is_direct_conversation(&binding.realm_id)
        || projection.realm_is_destroyed(&binding.realm_id)
        || projection.realm_is_tombstoned(&binding.realm_id)
    {
        return false;
    }
    let active_members: BTreeSet<_> = projection
        .members_of_realm(&binding.realm_id)
        .into_iter()
        .map(|membership| membership.member.as_str())
        .collect();
    let participants: BTreeSet<_> = binding
        .participants_unordered
        .iter()
        .map(String::as_str)
        .collect();
    if active_members != participants {
        return false;
    }
    projection
        .strands
        .get(&binding.main_strand_id)
        .is_some_and(|strand| {
            strand.realm_id == binding.realm_id
                && strand.scope_circle_id.is_none()
                && strand.state.as_str() == "active"
                && strand
                    .tracks
                    .get(arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION)
                    .is_some_and(|discussion| {
                        discussion.enabled != Some(false) && discussion.is_primary == Some(true)
                    })
        })
}

fn direct_binding_payload_from_operation(
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<
    arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
    &'static str,
> {
    // The Event-to-Operation adapter deliberately exposes receiver-owned
    // envelope context (Seal/CAS fields as well as identity/HLC fields) to
    // reducers.  The canonical DirectConversationBoundPayload is closed, so
    // parse the same stripped wire payload used by the schema validator.  A
    // hand-maintained subset here regressed as soon as direct authoring began
    // attaching `seal_ref`, `seal_basis` and `preconditions`.
    let payload = operation.payload.clone();
    serde_json::from_value(payload).map_err(|_| "direct_conversation_binding_invalid")
}

pub(crate) async fn validate_direct_binding_operation(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<(), &'static str> {
    if soland_services::operation_semantics::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::DirectConversationBound)
    {
        return Ok(());
    }
    let payload = direct_binding_payload_from_operation(operation).map_err(|reason| {
        tracing::warn!(
            target: "soland_http::error",
            stage = "payload",
            reason,
            "direct conversation binding validation failed"
        );
        "direct_conversation_binding_invalid"
    })?;
    let issuer = operation.context.sender.as_str();
    if !payload
        .participants_unordered
        .iter()
        .any(|participant| participant.as_str() == issuer)
    {
        tracing::warn!(
            target: "soland_http::error",
            stage = "issuer_participant",
            issuer,
            participants = ?payload.participants_unordered,
            "direct conversation binding validation failed"
        );
        return Err("direct_conversation_binding_invalid");
    }
    let trust_domain = arkret_identifiers::TypedTrustDomainId::new(
        state.config().trust_domain.clone(),
    )
    .map_err(|_| {
        tracing::warn!(
            target: "soland_http::error",
            stage = "trust_domain",
            "direct conversation binding validation failed"
        );
        "direct_conversation_binding_invalid"
    })?;
    payload.validate_pair_key(trust_domain).map_err(|_| {
        tracing::warn!(
            target: "soland_http::error",
            stage = "pair_key",
            pair_key = %payload.pair_key,
            participants = ?payload.participants_unordered,
            "direct conversation binding validation failed"
        );
        "direct_conversation_binding_invalid"
    })?;

    // The canonical precursor Events are the admission authority. The MLS
    // activation is also a security-barrier singleton, so its accepted cell
    // projection must be visible before a binding can endorse it. A binding
    // that races projection catches up by exact retry; it must not treat a
    // merely stored activation proposal as final.
    if let Err(stage) = validate_direct_binding_event_refs(state, &payload).await {
        tracing::warn!(
            target: "soland_http::error",
            stage,
            realm_id = %payload.realm_id,
            "direct conversation binding validation failed"
        );
        return Err("direct_conversation_binding_invalid");
    }
    if payload.authorization_basis.kind
        == arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AcceptedContact
    {
        let left = payload.participants_unordered[0].as_str();
        let right = payload.participants_unordered[1].as_str();
        // `participants_unordered` is canonical pair-key order, not contact
        // request direction. Resolve both directions or a random DID ordering
        // can make the same accepted contact intermittently disappear.
        let contact = accepted_contact_for_pair(state, left, right, "direct_message")
            .await
            .map_err(|error| {
                tracing::warn!(
                    target: "soland_http::error",
                    %error,
                    left,
                    right,
                    "direct conversation accepted-contact lookup failed"
                );
                "direct_conversation_binding_invalid"
            })?
            .ok_or("direct_conversation_binding_invalid")?;
        if contact.status != "accepted" {
            tracing::warn!(
                target: "soland_http::error",
                stage = "contact_status",
                status = %contact.status,
                "direct conversation binding validation failed"
            );
            return Err("direct_conversation_binding_invalid");
        }
        let verified_contact_refs = contact_fact_refs(&contact);
        if !accepted_contact_authorization_refs_match(
            &verified_contact_refs,
            &payload.authorization_basis.event_refs,
        ) {
            tracing::warn!(
                target: "soland_http::error",
                stage = "contact_refs",
                verified = ?verified_contact_refs,
                provided = ?payload.authorization_basis.event_refs,
                "direct conversation binding validation failed"
            );
            return Err("direct_conversation_binding_invalid");
        }
    }

    // §8.3 — the or_set element key is `(binding_digest, actor_id)`. A second
    // *distinct* digest for the same pair is a materialization conflict and
    // MUST be refused before projection; §9.3 forbids resolving it by picking a
    // winner. Re-endorsing the same coordinates (either participant, any number
    // of times) stays a compatible add and is admitted here.
    let digest = direct_binding_endorsement_digest(&payload)?;
    if let Some(bindings) = state
        .contacts()
        .direct_bindings_for_pair(payload.pair_key.as_ref())
        && !bindings.is_empty()
        && !bindings.digests().any(|known| known == digest)
    {
        tracing::warn!(
            target: "soland_http::error",
            stage = "pair_materialization_conflict",
            pair_key = %payload.pair_key,
            incoming = %digest,
            known = ?bindings.digests().collect::<Vec<_>>(),
            "direct conversation binding validation failed"
        );
        return Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_PAIR_MATERIALIZATION_CONFLICT);
    }
    Ok(())
}

/// Enforce the Direct Conversation active-generation sequence against the one
/// accepted CAS-register value. Pending proposals never become authority, but
/// they do count toward the bounded fan-out for the same predecessor.
pub(crate) async fn validate_direct_mls_generation_operation(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<(), &'static str> {
    if soland_services::operation_semantics::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::DirectConversationMlsGenerationActivate)
    {
        return Ok(());
    }
    let proposed = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::DirectConversationMlsGenerationActivatePayload,
    >(operation.payload.clone())
    .map_err(|_| "direct_conversation_mls_generation_invalid")?;
    let snapshot = state.projections().snapshot();
    if !snapshot.realm_is_direct_conversation(operation.realm_id.as_str()) {
        return Err("direct_conversation_mls_generation_invalid");
    }
    let current_value = snapshot
        .realm_null_subject_cell_value(
            operation.realm_id.as_str(),
            arkret_wire::CellFamilyId::DIRECT_CONVERSATION_ACTIVE_MLS_GENERATION_V1,
        )
        .cloned();
    let realm_events = state
        .event_queries()
        .projected_events_for_realm(operation.realm_id.as_str())
        .await
        .map_err(|_| "direct_conversation_activation_authority_unavailable")?;
    let mut founders = realm_events
        .iter()
        .filter(|event| event.event_kind == arkret_wire::EventKind::RealmCreate)
        .filter_map(|event| event.sender.clone())
        .collect::<Vec<_>>();
    founders.sort_unstable();
    founders.dedup();
    let [founder] = founders.as_slice() else {
        return Err("direct_conversation_activation_authority_unavailable");
    };
    let binding = state.contacts().direct_binding(proposed.pair_key.as_str());
    let selected_state = state
        .event_queries()
        .accepted_event(proposed.selected_group_state_ref.as_str())
        .await
        .map_err(|_| "direct_conversation_activation_authority_unavailable")?
        .ok_or("direct_conversation_activation_authority_unavailable")?;
    if selected_state.realm_id.as_deref() != Some(operation.realm_id.as_str())
        || !matches!(
            arkret_wire::EventKind::from_wire(&selected_state.kind),
            arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit
        )
    {
        return Err("direct_conversation_activation_authority_unavailable");
    }
    let selected_payload = selected_state
        .envelope
        .get("payload")
        .cloned()
        .ok_or("direct_conversation_activation_authority_unavailable")?;
    if selected_payload
        .get("group_id")
        .or_else(|| selected_payload.get("mls_group_id"))
        .and_then(Value::as_str)
        != Some(proposed.mls_group_id.as_str())
    {
        return Err("direct_conversation_activation_authority_unavailable");
    }
    let genesis = state
        .event_queries()
        .accepted_event(proposed.genesis_event_ref.as_str())
        .await
        .map_err(|_| "direct_conversation_activation_authority_unavailable")?
        .ok_or("direct_conversation_activation_authority_unavailable")?;
    if genesis.kind != arkret_wire::EventKind::MlsGenesis.as_str()
        || genesis.realm_id.as_deref() != Some(operation.realm_id.as_str())
        || genesis
            .envelope
            .get("payload")
            .and_then(|payload| {
                payload
                    .get("group_id")
                    .or_else(|| payload.get("mls_group_id"))
            })
            .and_then(Value::as_str)
            != Some(proposed.mls_group_id.as_str())
    {
        return Err("direct_conversation_activation_authority_unavailable");
    }
    let effective_scope = selected_payload
        .get("effective_scope")
        .cloned()
        .or_else(|| {
            selected_payload
                .get("governance_binding")
                .or_else(|| selected_payload.get("mls_governance_binding"))
                .and_then(|binding| binding.get("effective_scope"))
                .cloned()
        })
        .ok_or("direct_conversation_activation_authority_unavailable")?;
    let selected_frontier = state
        .mls_commits()
        .commit(&effective_scope, proposed.mls_group_id.as_str())
        .await
        .map_err(|_| "direct_conversation_activation_authority_unavailable")?
        .ok_or("direct_conversation_activation_authority_unavailable")?;
    let selected_ref_is_current =
        if selected_state.kind == arkret_wire::EventKind::MlsGenesis.as_str() {
            selected_frontier.accepted_commit_ref.is_none()
                && selected_frontier.genesis_event_ref == proposed.selected_group_state_ref.as_str()
        } else {
            selected_frontier.accepted_commit_ref.as_deref()
                == Some(proposed.selected_group_state_ref.as_str())
        };
    if selected_frontier.frontier_contested
        || selected_frontier.genesis_event_ref != proposed.genesis_event_ref.as_str()
        || !selected_ref_is_current
    {
        return Err("direct_conversation_activation_authority_unavailable");
    }
    let (selected_actors, locally_consumed_welcome_actors) =
        crate::routing::mls::current_authorized_claimed_group_actors(
            state,
            proposed.mls_group_id.as_str(),
        )
        .await
        .map_err(|_| "direct_conversation_activation_authority_unavailable")?;
    let expected_actors = if proposed.mls_generation == 0 {
        BTreeSet::from([founder.clone()])
    } else if let Some(binding) = binding.as_ref() {
        binding.participants_unordered.iter().cloned().collect()
    } else {
        snapshot
            .members_of_realm(operation.realm_id.as_str())
            .into_iter()
            .filter(|member| member.state == "join")
            .map(|member| member.member.clone())
            .collect()
    };
    if expected_actors.len() != if proposed.mls_generation == 0 { 1 } else { 2 }
        || selected_actors != expected_actors
    {
        return Err("direct_conversation_activation_authority_unavailable");
    }
    validate_direct_generation_predecessor(&proposed, current_value.as_ref())?;
    match proposed.mls_generation {
        0 => {
            if operation.context.sender.as_str() != founder.as_str() || binding.is_some() {
                return Err("direct_conversation_activation_authority_unavailable");
            }
        }
        1 => {
            if operation.context.sender.as_str() == founder.as_str()
                || binding.is_some()
                || !locally_consumed_welcome_actors.contains(operation.context.sender.as_str())
            {
                return Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_ACTIVATION_AUTHOR_INVALID);
            }
        }
        _ => {
            let binding = binding.ok_or("direct_conversation_activation_authority_unavailable")?;
            if binding.realm_id != operation.realm_id.as_str()
                || binding.main_strand_id != proposed.main_strand_id.as_str()
                || !binding
                    .participants_unordered
                    .iter()
                    .any(|participant| participant.as_str() == operation.context.sender.as_str())
            {
                return Err("direct_conversation_activation_authority_unavailable");
            }
        }
    }
    let pending = state
        .projections()
        .pending_control_events_for_notary(&operation.realm_id, None, 4096)
        .map_err(|_| "direct_conversation_activation_authority_unavailable")?;
    let same_predecessor_candidates = pending
        .iter()
        .filter(|event| {
            event.kind == arkret_wire::EventKind::DirectConversationMlsGenerationActivate
                && event.event_id != operation.context.event_id
                && event.payload.get("pair_key") == operation.payload.get("pair_key")
                && event.payload.get("main_strand_id") == operation.payload.get("main_strand_id")
                && event.payload.get("predecessor_active_value_digest")
                    == operation.payload.get("predecessor_active_value_digest")
        })
        .count();
    validate_direct_generation_candidate_cap(same_predecessor_candidates)?;
    Ok(())
}

fn validate_direct_generation_predecessor(
    proposed: &arkret_models_collaboration::events_payloads::DirectConversationMlsGenerationActivatePayload,
    current_value: Option<&Value>,
) -> Result<(), &'static str> {
    match (proposed.mls_generation, current_value) {
        (0, None) => Ok(()),
        (0, Some(_)) | (_, None) => Err("direct_conversation_mls_generation_predecessor_invalid"),
        (generation, Some(current_value)) => {
            let current = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::DirectConversationMlsGenerationActivatePayload,
            >(current_value.clone())
            .map_err(|_| "direct_conversation_mls_generation_predecessor_invalid")?;
            if current.mls_generation.checked_add(1) != Some(generation)
                || current.pair_key != proposed.pair_key
                || current.main_strand_id != proposed.main_strand_id
            {
                return Err("direct_conversation_mls_generation_predecessor_invalid");
            }
            let current_digest = arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(current_value)
                    .map_err(|_| "direct_conversation_mls_generation_predecessor_invalid")?,
            )
            .map_err(|_| "direct_conversation_mls_generation_predecessor_invalid")?;
            if proposed.predecessor_active_value_digest.as_ref() != Some(&current_digest) {
                return Err("direct_conversation_mls_generation_predecessor_invalid");
            }
            Ok(())
        }
    }
}

fn validate_direct_generation_candidate_cap(
    existing_same_predecessor_candidates: usize,
) -> Result<(), &'static str> {
    if existing_same_predecessor_candidates >= 16 {
        Err(arkret_wire::ErrorCode::MLS_GENERATION_PROPOSAL_FANOUT_EXCEEDED)
    } else {
        Ok(())
    }
}

async fn accepted_direct_event(
    state: &AppState,
    event_id: &arkret_identifiers::EventId,
    realm_id: &arkret_identifiers::RealmId,
    kind: &str,
) -> Result<arkret_wire::Event, &'static str> {
    let accepted = state
        .event_queries()
        .accepted_event(event_id.as_str())
        .await
        .map_err(|_| "referenced_event_query")?
        .ok_or("referenced_event_missing")?;
    if accepted.realm_id.as_deref() != Some(realm_id.as_str()) || accepted.kind != kind {
        return Err("referenced_event_mismatch");
    }
    serde_json::from_value(accepted.envelope).map_err(|_| "referenced_event_decode")
}

/// Validate a Direct Conversation binding against the accepted founding facts.
///
/// The binding no longer carries member/Strand/MLS refs: uniqueness comes from founder-only
/// admission, so this checks that the endorsed coordinates really are an accepted DM founding unit,
/// that the Realm creator is the founder derived from the pair's root Contact basis, and that the
/// referenced generation-1 activation exists in the same Realm.
async fn validate_direct_binding_event_refs(
    state: &AppState,
    payload: &arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
) -> Result<(), &'static str> {
    let realm_create = accepted_direct_realm_create(state, &payload.realm_id).await?;
    let genesis = realm_create
        .payload
        .get("object")
        .cloned()
        .and_then(|object| {
            serde_json::from_value::<arkret_models_collaboration::events_payloads::RealmGenesis>(
                object,
            )
            .ok()
        })
        .ok_or("direct_conversation_realm_role_invalid")?;
    arkret_models_collaboration::objects::direct_conversation::DirectConversationRealmRole::validate(
        &genesis,
    )
    .map_err(|_| "direct_conversation_realm_role_invalid")?;

    let creator = realm_create.actor_id.as_str();
    let participants: Vec<&str> = payload
        .participants_unordered
        .iter()
        .map(arkret_identifiers::Did::as_str)
        .collect();
    if participants.len() != 2 || !participants.contains(&creator) {
        return Err("creator_participant");
    }

    // founder-only creation: the Realm creator MUST be the participant derived from the pair's root
    // basis. Anything else is not a competing candidate, it is invalid.
    let peer = participants
        .iter()
        .copied()
        .find(|participant| *participant != creator)
        .ok_or("direct_conversation_binding_invalid")?;
    validate_direct_founder(state, payload, creator, peer).await?;

    // main Strand must be an accepted ak.strand.create inside the same Realm.
    let realm_events = state
        .event_queries()
        .projected_events_for_realm(payload.realm_id.as_str())
        .await
        .map_err(|_| "direct_conversation_binding_invalid")?;
    let has_main_strand = realm_events.iter().any(|event| {
        event.event_kind == arkret_wire::EventKind::StrandCreate
            && event
                .payload
                .get("object")
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str)
                == Some(payload.main_strand_id.as_str())
    });
    if !has_main_strand {
        return Err("main_strand");
    }

    // the endorsed first exact-pair generation must be an accepted activation in this Realm.
    let activation = accepted_direct_event(
        state,
        &payload.initial_exact_pair_generation_ref,
        &payload.realm_id,
        arkret_wire::EventKind::DirectConversationMlsGenerationActivate.as_str(),
    )
    .await?;
    if activation.payload.get("phase").and_then(Value::as_str) != Some("exact_pair")
        || activation
            .payload
            .get("main_strand_id")
            .and_then(Value::as_str)
            != Some(payload.main_strand_id.as_str())
        || activation.payload.get("pair_key").and_then(Value::as_str)
            != Some(payload.pair_key.as_str())
    {
        return Err("initial_exact_pair_generation");
    }
    let active_generation = state
        .projections()
        .snapshot()
        .realm_null_subject_cell_value(
            payload.realm_id.as_str(),
            arkret_wire::CellFamilyId::DIRECT_CONVERSATION_ACTIVE_MLS_GENERATION_V1,
        )
        .cloned()
        .ok_or("initial_exact_pair_generation_not_final")?;
    if serde_json::to_value(&activation.payload)
        .map_err(|_| "initial_exact_pair_generation_not_final")?
        != active_generation
    {
        return Err("initial_exact_pair_generation_not_final");
    }

    match payload.authorization_basis.kind {
        arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AcceptedContact => {
            // Contact facts are principal-scoped projection facts, including facts delivered across
            // federation; the caller validates them against the accepted ContactRecord.
            if payload.authorization_basis.event_refs.len() != 2 {
                return Err("contact_ref_count");
            }
        }
        arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::ManagedAgentController => {
            let mut authorization_kinds = BTreeSet::new();
            for event_ref in &payload.authorization_basis.event_refs {
                let accepted = state
                    .event_queries()
                    .accepted_event(event_ref.as_str())
                    .await
                    .map_err(|_| "direct_conversation_binding_invalid")?
                    .ok_or("direct_conversation_binding_invalid")?;
                authorization_kinds.insert(accepted.kind);
            }
            let expected = BTreeSet::from([
                arkret_wire::EventKind::AgentProvision.as_str().to_owned(),
                arkret_wire::EventKind::AgentKeyAuthorize.as_str().to_owned(),
            ]);
            if payload.authorization_basis.event_refs.len() != 2 || authorization_kinds != expected
            {
                return Err("managed_agent_authorization_refs");
            }
            let record = state
                .agent_pairings()
                .agent(peer)
                .await
                .map_err(|_| "direct_conversation_binding_invalid")?
                .ok_or("direct_conversation_binding_invalid")?;
            // controller-to-own-Agent fixes the founder to the controller, so the Realm creator is
            // the controller and the Agent is the peer.
            if record.controller_id != creator || record.state != AgentLifecycleState::Active {
                return Err("managed_agent_record");
            }
            let provision_refs = record
                .provision_event_refs
                .as_ref()
                .ok_or("direct_conversation_binding_invalid")?;
            let expected_refs = [
                provision_refs
                    .get("provision_event_id")
                    .and_then(Value::as_str),
                record.authorized_event_ref.as_deref(),
            ]
            .into_iter()
            .collect::<Option<BTreeSet<_>>>()
            .ok_or("direct_conversation_binding_invalid")?;
            let provided_refs = payload
                .authorization_basis
                .event_refs
                .iter()
                .map(arkret_identifiers::EventId::as_str)
                .collect::<BTreeSet<_>>();
            if provided_refs != expected_refs {
                return Err("managed_agent_refs");
            }
            crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
                state,
                &record,
                payload.created_at.to_owned(),
            )
            .await
            .map_err(|_| "direct_conversation_binding_invalid")?;
        }
    }

    Ok(())
}

/// Locate the accepted `ak.realm.create` for a Direct Conversation Realm.
async fn accepted_direct_realm_create(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
) -> Result<arkret_wire::Event, &'static str> {
    let create_ref = state
        .event_queries()
        .projected_events_for_realm(realm_id.as_str())
        .await
        .map_err(|_| "direct_conversation_binding_invalid")?
        .into_iter()
        .find(|event| event.event_kind == arkret_wire::EventKind::RealmCreate)
        .map(|event| event.event_id)
        .ok_or("direct_conversation_binding_invalid")?;
    let event_id = arkret_identifiers::EventId::new(create_ref)
        .map_err(|_| "direct_conversation_binding_invalid")?;
    accepted_direct_event(
        state,
        &event_id,
        realm_id,
        arkret_wire::EventKind::RealmCreate.as_str(),
    )
    .await
}

/// Enforce founder-only creation.
///
/// The founder is derived from the pair's Contact basis and is the sole principal allowed to author
/// the founding unit, which is what removes the cross-server creation race. A Realm created by the
/// other participant is not a competing candidate: it is invalid and MUST NOT be projected.
async fn validate_direct_founder(
    state: &AppState,
    payload: &arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
    creator: &str,
    peer: &str,
) -> Result<(), &'static str> {
    use arkret_models_collaboration::objects::direct_conversation::{
        DirectConversationAuthorizationKind, DirectConversationFounderBasis,
        direct_conversation_founder,
    };

    let basis = match payload.authorization_basis.kind {
        // controller-to-own-Agent has no Contact basis: the founder is fixed to the controller so
        // an Agent runtime key never needs Direct Conversation founding scope.
        DirectConversationAuthorizationKind::ManagedAgentController => {
            DirectConversationFounderBasis::ControllerOwnedAgent {
                controller_id: arkret_identifiers::Did::new(creator.to_owned())
                    .map_err(|_| "direct_conversation_binding_invalid")?,
            }
        }
        DirectConversationAuthorizationKind::AcceptedContact => {
            let record = accepted_contact_for_pair(state, creator, peer, "direct_message")
                .await
                .map_err(|_| "direct_conversation_binding_invalid")?
                .ok_or("direct_conversation_founder_basis_unavailable")?;
            direct_founder_basis_from_contact(&record)?
        }
    };

    let [left, right]: [arkret_identifiers::Did; 2] = payload
        .participants_unordered
        .clone()
        .try_into()
        .map_err(|_| "direct_conversation_binding_invalid")?;
    let founder = direct_conversation_founder([left, right], &basis)
        .map_err(|_| "direct_conversation_founder_basis_unavailable")?;
    if founder.as_str() != creator {
        tracing::warn!(
            target: "soland_http::error",
            stage = "founder",
            %creator,
            founder = %founder,
            "direct conversation Realm was not created by the derived founder"
        );
        return Err("direct_conversation_founder_mismatch");
    }
    Ok(())
}

fn accepted_contact_authorization_refs_match(
    verified_contact_refs: &[String],
    provided_refs: &[arkret_identifiers::EventId],
) -> bool {
    let verified = verified_contact_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let provided = provided_refs
        .iter()
        .map(arkret_identifiers::EventId::as_str)
        .collect::<BTreeSet<_>>();
    verified.len() == 2 && provided.len() == 2 && provided == verified
}

/// or_set add for one accepted `ak.direct_conversation.bound` Event.
///
/// `contact-and-direct-conversation.md` §8.3 fixes the element key at
/// `(binding_digest, envelope.actor_id)`: the same participant re-signing the
/// same coordinates counts once, and both participants signing the same
/// coordinates are compatible adds that MUST NOT join to bottom. Nothing here
/// picks a winner between two different endorsements — §9.3 forbids any such
/// selector, and a second distinct digest is refused at admission by
/// [`validate_direct_binding_operation`] and surfaces as `suspended`.
pub(crate) async fn project_canonical_direct_binding(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) {
    if soland_services::operation_semantics::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::DirectConversationBound)
    {
        return;
    }
    let Ok(payload) = direct_binding_payload_from_operation(operation) else {
        return;
    };
    let event_ref = operation.context.event_id.to_string();
    let actor_id = operation.context.sender.to_string();
    let Ok(digest) = direct_binding_endorsement_digest(&payload) else {
        return;
    };
    state.contacts().endorse_direct_binding(
        payload.pair_key.as_ref(),
        digest,
        soland_services::identity::DirectConversationCoordinatesRecord {
            participants_unordered: payload
                .participants_unordered
                .iter()
                .map(ToString::to_string)
                .collect(),
            realm_id: payload.realm_id.to_string(),
            main_strand_id: payload.main_strand_id.to_string(),
            created_at: payload.created_at,
        },
        soland_services::identity::DirectConversationEndorsement {
            actor_id,
            binding_event_ref: event_ref,
        },
    );
}

/// Identity of one endorsement inside the or_set.
///
/// §8.3 derives the element key from the registered
/// `ak.direct-conversation.binding-digest.v1` domain and the closed normalized
/// binding object. `created_at` and Event author/proof are excluded, so two
/// participants endorsing the same coordinates at different wall-clock times
/// collapse to the same semantic digest. The digest remains receiver-derived
/// and MUST NOT appear in the payload.
fn direct_binding_endorsement_digest(
    payload: &arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
) -> Result<String, &'static str> {
    payload
        .binding_digest()
        .map(|digest| digest.into_string())
        .map_err(|_| "direct_conversation_binding_invalid")
}

#[cfg(test)]
mod binding_digest_tests {
    use super::*;

    fn generation_payload(
        generation: u64,
        predecessor: Option<arkret_wire::Hash>,
    ) -> arkret_models_collaboration::events_payloads::DirectConversationMlsGenerationActivatePayload
    {
        arkret_models_collaboration::events_payloads::DirectConversationMlsGenerationActivatePayload {
            pair_key: arkret_wire::Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            mls_generation: generation,
            phase: if generation == 0 {
                arkret_models_collaboration::events_payloads::DirectConversationMlsGenerationPhase::ProvisionalHistorySend
            } else {
                arkret_models_collaboration::events_payloads::DirectConversationMlsGenerationPhase::ExactPair
            },
            mls_group_id: arkret_wire::MlsGroupId::new("direct-generation-test-group").unwrap(),
            genesis_event_ref: arkret_wire::EventId::new(
                "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            )
            .unwrap(),
            selected_group_state_ref: arkret_wire::NonEmptyString::new(format!(
                "selected-generation-{generation}"
            ))
            .unwrap(),
            main_strand_id: arkret_wire::StrandId::new(
                "ak:strand:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo",
            )
            .unwrap(),
            predecessor_active_value_digest: predecessor,
        }
    }

    fn value_digest(value: &Value) -> arkret_wire::Hash {
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(value).unwrap()).unwrap()
    }

    #[test]
    fn registered_binding_digest_kat_is_used_for_projection_identity() {
        let payload = serde_json::json!({
            "pair_key": "sha256:e8c24c1badc48eefa472a1700e87a6597a95aedfab8cbe3173f1622b9ad427b5",
            "participants_unordered": [
                "did:webvh:z6mkfixture:bob.example",
                "did:webvh:z6mkfixture:alice.example"
            ],
            "realm_id": "ak:realm:AVYxXzYx_KzaGx7X62doksaQR0ISkneyOwwF1k6ExHKy",
            "main_strand_id": "ak:strand:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo",
            "founding_unit_digest": format!("sha256:{}", "b".repeat(64)),
            "authorization_basis": {
                "kind": "accepted_contact",
                "event_refs": [
                    "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
                    "ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N"
                ]
            },
            "initial_exact_pair_generation_ref": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "created_at": "2026-08-07T12:34:56.000Z"
        });
        let payload = serde_json::from_value(payload).unwrap();
        assert_eq!(
            direct_binding_endorsement_digest(&payload).unwrap(),
            "sha256:bb50b66aa3a8e808ea61743efb278f1d55d0849f534ce2ee6ab01e893ce15a58"
        );
    }

    #[test]
    fn generation_candidate_cap_accepts_sixteenth_and_rejects_seventeenth() {
        assert!(validate_direct_generation_candidate_cap(15).is_ok());
        assert_eq!(
            validate_direct_generation_candidate_cap(16),
            Err(arkret_wire::ErrorCode::MLS_GENERATION_PROPOSAL_FANOUT_EXCEEDED)
        );
    }

    #[test]
    fn generation_cas_has_one_winner_and_rejects_same_predecessor_loser() {
        let generation_zero = generation_payload(0, None);
        let generation_zero_value = serde_json::to_value(&generation_zero).unwrap();
        let generation_one = generation_payload(1, Some(value_digest(&generation_zero_value)));
        assert!(
            validate_direct_generation_predecessor(&generation_one, Some(&generation_zero_value))
                .is_ok()
        );

        let accepted_winner = serde_json::to_value(&generation_one).unwrap();
        assert_eq!(
            validate_direct_generation_predecessor(&generation_one, Some(&accepted_winner)),
            Err("direct_conversation_mls_generation_predecessor_invalid"),
            "a same-generation loser cannot replace the accepted singleton"
        );
        let generation_two = generation_payload(2, Some(value_digest(&accepted_winner)));
        assert!(
            validate_direct_generation_predecessor(&generation_two, Some(&accepted_winner)).is_ok()
        );
    }

    #[test]
    fn generation_predecessor_binds_the_whole_accepted_value() {
        let generation_zero = generation_payload(0, None);
        let original = serde_json::to_value(&generation_zero).unwrap();
        let proposed = generation_payload(1, Some(value_digest(&original)));

        let mut changed = original;
        changed["selected_group_state_ref"] = serde_json::json!("different-selected-state");
        assert_eq!(
            validate_direct_generation_predecessor(&proposed, Some(&changed)),
            Err("direct_conversation_mls_generation_predecessor_invalid")
        );

        let skipped = generation_payload(3, Some(value_digest(&changed)));
        assert_eq!(
            validate_direct_generation_predecessor(&skipped, Some(&changed)),
            Err("direct_conversation_mls_generation_predecessor_invalid")
        );
    }
}

/// Derive the founder basis from an accepted Contact record.
///
/// Normal branch: the founder is the **responder**, i.e. the participant that is not the request
/// issuer. This is normative, not a coin flip. The basis is lit up by the responder's
/// `normal_response_acceptance_receipt`, which proves the responder was online at the moment the
/// basis came into existence; the requester may have gone offline days earlier. Base v1 defines no
/// fallback, so naming the possibly-absent party would leave the pair unable to ever create the
/// conversation.
pub(crate) fn direct_founder_basis_from_contact(
    record: &ContactRecord,
) -> Result<
    arkret_models_collaboration::objects::direct_conversation::DirectConversationFounderBasis,
    &'static str,
> {
    if let Some(bundle) = record.basis_evidence.as_ref() {
        if record.basis_id.as_deref() != Some(bundle.basis_id.as_str()) {
            return Err("direct_conversation_founder_basis_unavailable");
        }
        if let arkret_models_collaboration::contact_operations::ContactBasis::Glare {
            requests,
            ..
        } = &bundle.basis
        {
            let attestations = bundle
                .glare_concurrency_attestations
                .as_ref()
                .ok_or("direct_conversation_founder_basis_unavailable")?;
            if bundle.request_receipts.len() != 2
                || attestations.iter().any(|attestation| {
                    attestation.complete_through == 0
                        || requests.iter().any(|request| {
                            !attestation
                                .observed_frontier
                                .contains(&request.request_event_ref)
                        })
                })
            {
                return Err("direct_conversation_founder_basis_unavailable");
            }
            let first = &requests[0];
            let receipt = bundle
                .request_receipts
                .iter()
                .find(|receipt| receipt.core.request_event_ref == first.request_event_ref)
                .ok_or("direct_conversation_founder_basis_unavailable")?;
            let digest = arkret_identifiers::Hash::new(
                arkret_canonical::canonical_sha256(receipt)
                    .map_err(|_| "direct_conversation_founder_basis_unavailable")?,
            )
            .map_err(|_| "direct_conversation_founder_basis_unavailable")?;
            if digest != first.request_acceptance_receipt_digest {
                return Err("direct_conversation_founder_basis_unavailable");
            }
            return Ok(
                arkret_models_collaboration::objects::direct_conversation::DirectConversationFounderBasis::Glare {
                    first_request_issuer: receipt.core.holder.subject_id().clone(),
                },
            );
        }
    }
    let request_issuer = arkret_identifiers::Did::new(record.requester.clone())
        .map_err(|_| "direct_conversation_founder_basis_unavailable")?;
    Ok(
        arkret_models_collaboration::objects::direct_conversation::DirectConversationFounderBasis::Normal {
            request_issuer,
        },
    )
}

/// Which participant may author the founding unit for this pair, if it can be determined now.
///
/// Returns `None` when the basis cannot be verified, so the caller reports
/// `temporarily_unavailable` rather than inventing an answer.
pub(crate) async fn direct_founder_for_pair(
    state: &AppState,
    actor: &str,
    peer: &str,
    contact: Option<&ContactRecord>,
    managed_agent: bool,
) -> Result<Option<String>, AppError> {
    use arkret_models_collaboration::objects::direct_conversation::{
        DirectConversationFounderBasis, direct_conversation_founder,
    };

    let basis = if managed_agent {
        // controller-to-own-Agent has no Contact basis; the founder is fixed to the controller so
        // an Agent runtime key never needs Direct Conversation founding scope.
        let controller = if state
            .agent_pairings()
            .agent(peer)
            .await
            .map_err(|error| AppError::internal(format!("managed Agent lookup failed: {error}")))?
            .is_some()
        {
            actor
        } else {
            peer
        };
        DirectConversationFounderBasis::ControllerOwnedAgent {
            controller_id: arkret_identifiers::Did::new(controller.to_owned())
                .map_err(|error| AppError::internal(format!("controller DID invalid: {error}")))?,
        }
    } else {
        let Some(record) = contact else {
            return Ok(None);
        };
        match direct_founder_basis_from_contact(record) {
            Ok(basis) => basis,
            Err(_) => return Ok(None),
        }
    };

    let left = arkret_identifiers::Did::new(actor.to_owned())
        .map_err(|error| AppError::internal(format!("actor DID invalid: {error}")))?;
    let right = arkret_identifiers::Did::new(peer.to_owned())
        .map_err(|error| AppError::internal(format!("peer DID invalid: {error}")))?;
    Ok(direct_conversation_founder([left, right], &basis)
        .ok()
        .map(|founder| founder.to_string()))
}

/// Current active exact-pair MLS generation activation for a bound conversation.
pub(crate) async fn direct_active_generation_ref(
    state: &AppState,
    pair_key: &str,
    binding: &DirectConversationBindingRecord,
) -> Result<Option<EventId>, AppError> {
    let active_value = state
        .projections()
        .snapshot()
        .realm_null_subject_cell_value(
            &binding.realm_id,
            arkret_wire::CellFamilyId::DIRECT_CONVERSATION_ACTIVE_MLS_GENERATION_V1,
        )
        .cloned();
    let Some(active_value) = active_value else {
        // Missing and Bottom both require reconciliation. Neither may be
        // replaced by selecting the numerically greatest observed Event.
        return Ok(None);
    };
    let mut matching_refs = state
        .event_queries()
        .projected_events_for_realm(&binding.realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .into_iter()
        .filter(|event| {
            event.event_kind == arkret_wire::EventKind::DirectConversationMlsGenerationActivate
                && event.payload == active_value
                && event.payload.get("pair_key").and_then(Value::as_str) == Some(pair_key)
                && event.payload.get("main_strand_id").and_then(Value::as_str)
                    == Some(binding.main_strand_id.as_str())
        })
        .map(|event| event.event_id)
        .collect::<Vec<_>>();
    matching_refs.sort_unstable();
    matching_refs.dedup();
    if matching_refs.len() != 1 {
        return Ok(None);
    }
    EventId::new(matching_refs.pop().expect("cardinality checked"))
        .map(Some)
        .map_err(|error| AppError::internal(format!("stored activation ref invalid: {error}")))
}
