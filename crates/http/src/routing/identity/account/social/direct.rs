use arkret_models_collaboration::agent_operations::AgentLifecycleState;

use super::*;

pub(crate) fn direct_pair_key(
    state: &AppState,
    left: &str,
    right: &str,
) -> Result<String, AppError> {
    let trust_domain = state.config().trust_domain.clone();
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
    identity: &str,
    role: &str,
) -> Result<
    arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant,
    AppError,
> {
    let core_id = DidCoreId::new(identity.to_owned()).map_err(|error| {
        AppError::internal(format!(
            "stored direct conversation {role} core identity invalid: {error}"
        ))
    })?;
    Ok(arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
        core_id,
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

pub(crate) async fn direct_group_state_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<Option<(arkret_wire::EventId, arkret_wire::Hash)>, AppError> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned()).map_err(|error| {
        AppError::internal(format!("direct conversation Realm id is invalid: {error}"))
    })?;
    let mut matching = state
        .mls_commits()
        .commits()
        .await
        .map_err(|error| AppError::internal(format!("MLS group-state lookup failed: {error}")))?
        .into_iter()
        .filter(|commit| {
            matches!(
                &commit.effective_scope,
                arkret_wire::ScopeRef::Realm { realm_id: commit_realm_id }
                    if commit_realm_id == &realm_id
            )
        });
    let Some(commit) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() || commit.frontier_contested {
        return Ok(None);
    }
    let state_ref = commit
        .accepted_commit_ref
        .as_deref()
        .unwrap_or(commit.genesis_event_ref.as_str());
    let event_ref = arkret_wire::EventId::new(state_ref.to_owned()).map_err(|error| {
        AppError::internal(format!(
            "stored MLS group-state Event ref is invalid: {error}"
        ))
    })?;
    let record = state
        .event_queries()
        .canonical_event(event_ref.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("MLS group-state Event lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                "current MLS group-state Event is unavailable",
            )
        })?;
    if record.event_id != event_ref.as_str()
        || record.realm_id.as_deref() != Some(realm_id.as_str())
        || (record.kind != arkret_wire::EventKind::MlsGenesis.as_str()
            && record.kind != arkret_wire::EventKind::MlsCommit.as_str())
    {
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "current MLS group-state Event binding is invalid",
        ));
    }
    let digest = arkret_wire::Hash::new(record.canonical_digest).map_err(|error| {
        AppError::internal(format!("stored MLS group-state digest is invalid: {error}"))
    })?;
    Ok(Some((event_ref, digest)))
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
        .unordered_participant_ids
        .iter()
        .any(|participant| participant.as_str() == issuer)
    {
        tracing::warn!(
            target: "soland_http::error",
            stage = "issuer_participant",
            issuer,
            participants = ?payload.unordered_participant_ids,
            "direct conversation binding validation failed"
        );
        return Err("direct_conversation_binding_invalid");
    }
    let trust_domain = state.config().trust_domain.clone();
    payload.validate_pair_key(trust_domain).map_err(|_| {
        tracing::warn!(
            target: "soland_http::error",
            stage = "pair_key",
            pair_key = %payload.pair_key,
            participants = ?payload.unordered_participant_ids,
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
        let left = payload.unordered_participant_ids[0].as_str();
        let right = payload.unordered_participant_ids[1].as_str();
        // `unordered_participant_ids` is canonical pair-key order, not contact
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
/// that the Realm creator is the founder derived from the pair's root Contact round, and that the
/// main Strand is accepted in the same Realm.
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
        .unordered_participant_ids
        .iter()
        .map(arkret_identifiers::DidCoreId::as_str)
        .collect();
    if participants.len() != 2 || !participants.contains(&creator) {
        return Err("creator_participant");
    }

    // founder-only creation: the Realm creator MUST be the participant derived from the pair's root
    // authority. Anything else is not a competing candidate, it is invalid.
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
/// The founder is derived from the pair's Contact round and is the sole principal allowed to author
/// the founding unit, which is what removes the cross-server creation race. A Realm created by the
/// other participant is not a competing candidate: it is invalid and MUST NOT be projected.
async fn validate_direct_founder(
    state: &AppState,
    payload: &arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
    creator: &str,
    peer: &str,
) -> Result<(), &'static str> {
    use arkret_models_collaboration::objects::direct_conversation::{
        DirectConversationAuthorizationKind, DirectConversationFoundingAuthority,
        direct_conversation_founder,
    };

    let authority = match payload.authorization_basis.kind {
        // controller-to-own-Agent has no Contact round: the founder is fixed to the controller so
        // an Agent runtime key never needs Direct Conversation founding scope.
        DirectConversationAuthorizationKind::ManagedAgentController => {
            DirectConversationFoundingAuthority::ControllerOwnedAgent {
                controller_id: arkret_identifiers::DidCoreId::new(creator.to_owned())
                    .map_err(|_| "direct_conversation_binding_invalid")?,
            }
        }
        DirectConversationAuthorizationKind::AcceptedContact => {
            let record = accepted_contact_for_pair(state, creator, peer, "direct_message")
                .await
                .map_err(|_| "direct_conversation_binding_invalid")?
                .ok_or("direct_conversation_founding_authority_unavailable")?;
            direct_founding_authority_from_contact(&record)?
        }
    };

    let [left, right]: [arkret_identifiers::DidCoreId; 2] = payload
        .unordered_participant_ids
        .clone()
        .try_into()
        .map_err(|_| "direct_conversation_binding_invalid")?;
    let founder = direct_conversation_founder([left, right], &authority)
        .map_err(|_| "direct_conversation_founding_authority_unavailable")?;
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
                .unordered_participant_ids
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

/// Derive the founding authority from an accepted Contact record.
///
/// Normal branch: the founder is the **responder**, i.e. the participant that is not the request
/// issuer. This is normative, not a coin flip. The authority is lit up by the responder's
/// `normal_response_acceptance_receipt`, which proves the responder was online at the moment the
/// authority came into existence; the requester may have gone offline days earlier. Base v1 defines
/// no fallback, so naming the possibly-absent party would leave the pair unable to ever create the
/// conversation.
pub(crate) fn direct_founding_authority_from_contact(
    record: &ContactRecord,
) -> Result<
    arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthority,
    &'static str,
> {
    if let Some(bundle) = record.contact_round_evidence.as_ref() {
        if record.contact_round_id.as_deref() != Some(bundle.contact_round_id.as_str()) {
            return Err("direct_conversation_founding_authority_unavailable");
        }
        arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingAuthorityEvidence::Human {
            contact_round_evidence: bundle.clone(),
            contact_round_continuity_chain: record.contact_round_evidence_history.clone(),
        }
        .participants_and_founder()
        .map_err(|_| "direct_conversation_founding_authority_unavailable")?;
        arkret_models_collaboration::contact_operations::validate_recontact_continuity(
            bundle,
            &record.contact_round_evidence_history,
        )
        .map_err(|_| "direct_conversation_founding_authority_unavailable")?;
        let root = record
            .contact_round_evidence_history
            .last()
            .unwrap_or(bundle);
        if let arkret_models_collaboration::contact_operations::ContactRound::Glare {
            requests,
            ..
        } = &root.contact_round
        {
            let attestations = root
                .glare_concurrency_attestations
                .as_ref()
                .ok_or("direct_conversation_founding_authority_unavailable")?;
            if root.request_receipts.len() != 2
                || attestations.iter().any(|attestation| {
                    attestation.complete_through == 0
                        || requests.iter().any(|request| {
                            !attestation
                                .observed_frontier
                                .contains(&request.request_event_ref)
                        })
                })
            {
                return Err("direct_conversation_founding_authority_unavailable");
            }
            let first = &requests[0];
            let receipt = root
                .request_receipts
                .iter()
                .find(|receipt| receipt.core.request_event_ref == first.request_event_ref)
                .ok_or("direct_conversation_founding_authority_unavailable")?;
            let digest = arkret_identifiers::Hash::new(
                arkret_canonical::canonical_sha256(receipt)
                    .map_err(|_| "direct_conversation_founding_authority_unavailable")?,
            )
            .map_err(|_| "direct_conversation_founding_authority_unavailable")?;
            if digest != first.request_acceptance_receipt_digest {
                return Err("direct_conversation_founding_authority_unavailable");
            }
            return Ok(
                arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthority::Glare {
                    first_request_issuer: receipt.core.holder.contact_actor_id().clone(),
                },
            );
        }
        let arkret_models_collaboration::contact_operations::ContactRound::Normal {
            request_event_ref,
            ..
        } = &root.contact_round
        else {
            unreachable!("glare returned above")
        };
        let request_issuer = root
            .request_receipts
            .iter()
            .find(|receipt| receipt.core.request_event_ref == *request_event_ref)
            .map(|receipt| receipt.core.holder.contact_actor_id().clone())
            .ok_or("direct_conversation_founding_authority_unavailable")?;
        return Ok(
            arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthority::Normal {
                request_issuer,
            },
        );
    }
    Err("direct_conversation_founding_authority_unavailable")
}

/// Which participant may author the founding unit for this pair, if it can be determined now.
///
/// Returns `None` when the authority cannot be verified, so the caller reports
/// `temporarily_unavailable` rather than inventing an answer.
pub(crate) async fn direct_founder_for_pair(
    state: &AppState,
    actor: &str,
    peer: &str,
    contact: Option<&ContactRecord>,
    managed_agent: bool,
) -> Result<Option<String>, AppError> {
    use arkret_models_collaboration::objects::direct_conversation::{
        DirectConversationFoundingAuthority, direct_conversation_founder,
    };

    let authority = if managed_agent {
        // controller-to-own-Agent has no Contact round; the founder is fixed to the controller so
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
        DirectConversationFoundingAuthority::ControllerOwnedAgent {
            controller_id: arkret_identifiers::DidCoreId::new(controller.to_owned())
                .map_err(|error| AppError::internal(format!("controller DID invalid: {error}")))?,
        }
    } else {
        let Some(record) = contact else {
            return Ok(None);
        };
        match direct_founding_authority_from_contact(record) {
            Ok(authority) => authority,
            Err(_) => return Ok(None),
        }
    };

    let left = arkret_identifiers::DidCoreId::new(actor.to_owned())
        .map_err(|error| AppError::internal(format!("actor DID invalid: {error}")))?;
    let right = arkret_identifiers::DidCoreId::new(peer.to_owned())
        .map_err(|error| AppError::internal(format!("peer DID invalid: {error}")))?;
    Ok(direct_conversation_founder([left, right], &authority)
        .ok()
        .map(|founder| founder.to_string()))
}
