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

pub(crate) fn active_direct_binding(
    state: &AppState,
    pair_key: &str,
) -> Option<DirectConversationBindingRecord> {
    let binding = state
        .contacts()
        .direct_binding(pair_key)
        .filter(|binding| {
            binding.state == "active" && valid_contact_event_ref(&binding.binding_event_ref)
        })?;
    direct_binding_matches_projection(state, &binding).then_some(binding)
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

pub(crate) async fn retire_direct_bindings_for_operation(
    state: &AppState,
    operation: &arkret_event_draft::Operation,
) {
    let kind = soland_services::operation_semantics::canonical_kind_for_operation(operation);
    let member_ended = kind == Some(arkret_wire::EventKind::MEMBER_STATE)
        && matches!(
            operation.payload.get("membership").and_then(Value::as_str),
            Some("leave" | "ban")
        );
    let realm_ended = matches!(
        kind,
        Some(arkret_wire::EventKind::REALM_TOMBSTONE | arkret_wire::EventKind::REALM_DESTROY)
    );
    let archived_strand = (kind == Some(arkret_wire::EventKind::STRAND_ARCHIVE))
        .then(|| operation.payload.get("target_ref").and_then(Value::as_str))
        .flatten();
    if !member_ended && !realm_ended && archived_strand.is_none() {
        return;
    }
    let member = member_ended
        .then(|| crate::routing::events::operations::membership_target(operation))
        .flatten();
    let retired = state.contacts().retire_affected_direct_bindings(
        operation.realm_id.as_str(),
        member,
        archived_strand,
        realm_ended,
        now(),
    );
    for (pair_key, binding) in retired {
        if let Err(error) = state
            .contacts()
            .save_direct_binding(&pair_key, binding)
            .await
        {
            tracing::error!(%error, %pair_key, "failed to persist retired direct binding");
        }
    }
}

fn direct_binding_payload_from_operation(
    operation: &arkret_event_draft::Operation,
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
    let payload =
        crate::routing::events::operations::projection_context_stripped_payload(&operation.payload);
    serde_json::from_value(payload).map_err(|_| "direct_conversation_binding_invalid")
}

pub(crate) async fn validate_direct_binding_operation(
    state: &AppState,
    operation: &arkret_event_draft::Operation,
) -> Result<(), &'static str> {
    if soland_services::operation_semantics::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::DIRECT_CONVERSATION_BOUND)
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
    let issuer = operation
        .payload
        .get("sender")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            tracing::warn!(
                target: "soland_http::error",
                stage = "issuer_missing",
                "direct conversation binding validation failed"
            );
            "direct_conversation_binding_invalid"
        })?;
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

    // The canonical precursor Events are the admission authority. Projection
    // application is asynchronous, so consulting the derived Realm view here
    // creates a race when a binding immediately follows its accepted
    // Realm/member/Strand/MLS Events. Active-binding reads still require the
    // projection to agree; admission validates every exact precursor below.
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
    Ok(())
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
    let realm = realm_create
        .payload
        .get("object")
        .cloned()
        .and_then(|object| {
            serde_json::from_value::<arkret_models_collaboration::objects::realm::Realm>(object)
                .ok()
        })
        .ok_or("direct_conversation_realm_role_invalid")?;
    arkret_models_collaboration::objects::direct_conversation::DirectConversationRealmRole::validate(
        &realm,
    )
    .map_err(|_| "direct_conversation_realm_role_invalid")?;

    let creator = realm_create
        .payload
        .get("object")
        .and_then(|object| object.get("created_by"))
        .and_then(Value::as_str)
        .ok_or("direct_conversation_binding_invalid")?;
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
        event.event_kind == arkret_wire::EventKind::STRAND_CREATE
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
        arkret_wire::EventKind::DIRECT_CONVERSATION_MLS_GENERATION_ACTIVATE,
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
                arkret_wire::EventKind::AGENT_PROVISION.to_owned(),
                arkret_wire::EventKind::AGENT_KEY_AUTHORIZE.to_owned(),
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
        .find(|event| event.event_kind == arkret_wire::EventKind::REALM_CREATE)
        .map(|event| event.event_id)
        .ok_or("direct_conversation_binding_invalid")?;
    let event_id = arkret_identifiers::EventId::new(create_ref)
        .map_err(|_| "direct_conversation_binding_invalid")?;
    accepted_direct_event(
        state,
        &event_id,
        realm_id,
        arkret_wire::EventKind::REALM_CREATE,
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

pub(crate) async fn project_canonical_direct_binding(
    state: &AppState,
    operation: &arkret_event_draft::Operation,
) {
    if soland_services::operation_semantics::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::DIRECT_CONVERSATION_BOUND)
    {
        return;
    }
    let Ok(payload) = direct_binding_payload_from_operation(operation) else {
        return;
    };
    let Some(event_ref) = operation
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return;
    };
    let pair_key = payload.pair_key.to_string();

    let incoming_digest = operation
        .canonical_event_digest
        .as_deref()
        .unwrap_or_default();
    if incoming_digest.is_empty() {
        return;
    }
    let current = state.contacts().direct_binding(&pair_key);
    if let Some(current) = current.as_ref()
        && current.binding_event_ref != event_ref
        && direct_binding_matches_projection(state, current)
    {
        let current_digest = state
            .event_queries()
            .accepted_event(&current.binding_event_ref)
            .await
            .ok()
            .flatten()
            .map(|event| event.canonical_digest);
        if current_digest
            .as_deref()
            .is_some_and(|digest| digest >= incoming_digest)
        {
            return;
        }
    }
    let binding = DirectConversationBindingRecord {
        participants_unordered: payload
            .participants_unordered
            .iter()
            .map(ToString::to_string)
            .collect(),
        realm_id: payload.realm_id.to_string(),
        main_strand_id: payload.main_strand_id.to_string(),
        binding_event_ref: event_ref.clone(),
        state: "active".to_owned(),
        authoring_context: None,
        created_at: payload.created_at,
        updated_at: now(),
    };
    if let Err(error) = state
        .contacts()
        .save_direct_binding(&pair_key, binding.clone())
        .await
    {
        tracing::error!(%error, %pair_key, "failed to persist canonical direct binding projection");
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
    // NOTE: glare bases (both sides requested concurrently) derive the founder from the
    // canonically-ordered pair of request refs. The stored ContactRecord keeps a single
    // requester/target orientation and does not persist both request refs, so a glare pair cannot
    // be derived here yet. We deliberately do NOT guess: guessing would let the two sides
    // disagree about who may create, which is exactly the race founder derivation exists to
    // remove.
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
    binding: &DirectConversationBindingRecord,
) -> Result<EventId, AppError> {
    let mut best: Option<(u64, String)> = None;
    for event in state
        .event_queries()
        .projected_events_for_realm(&binding.realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        if event.event_kind != arkret_wire::EventKind::DIRECT_CONVERSATION_MLS_GENERATION_ACTIVATE {
            continue;
        }
        let generation = event
            .payload
            .get("mls_generation")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if best
            .as_ref()
            .is_none_or(|(current, _)| generation > *current)
        {
            best = Some((generation, event.event_id));
        }
    }
    let (_, event_id) = best.ok_or_else(|| {
        direct_resolve_precondition(
            arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
            "direct conversation has no active MLS generation",
        )
    })?;
    EventId::new(event_id)
        .map_err(|error| AppError::internal(format!("stored activation ref invalid: {error}")))
}
