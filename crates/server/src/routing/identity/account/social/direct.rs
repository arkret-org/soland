use super::*;

pub(crate) async fn ensure_direct_peer_resolvable(
    state: &AppState,
    peer: &str,
) -> Result<(), AppError> {
    let account = state
        .identity_application()
        .find_account_by_actor(soland_application::identity::FindAccountByActorQuery {
            actor_id: peer.to_owned(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if account.is_none() {
        return Err(direct_resolve_precondition(
            arkret_core::ErrorCode::PEER_UNRESOLVABLE,
            "direct conversation peer is not resolvable on this Principal Server",
        ));
    }
    let peer_did = Did::new(peer.to_owned()).map_err(|_| {
        direct_resolve_precondition(
            arkret_core::ErrorCode::PEER_UNRESOLVABLE,
            "direct conversation peer DID is invalid",
        )
    })?;
    let has_cross_signing_control = state
        .cross_signing
        .lock()
        .current_cross_signing(&peer_did)
        .is_some();
    if !has_cross_signing_control {
        return Err(direct_resolve_precondition(
            arkret_core::ErrorCode::PEER_UNRESOLVABLE,
            "direct conversation peer has no accepted cross-signing control state",
        ));
    }
    Ok(())
}

pub(crate) fn direct_pair_key(
    state: &AppState,
    left: &str,
    right: &str,
) -> Result<String, AppError> {
    let trust_domain = arkret_core::TypedTrustDomainId::new(state.config.trust_domain.clone())
        .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    let left = direct_pair_key_participant(left, "actor")?;
    let right = direct_pair_key_participant(right, "peer")?;
    arkret_core::direct_conversation_pair_key(trust_domain, left, right)
        .map(|pair_key| pair_key.into_string())
        .map_err(|error| {
            AppError::internal(format!("direct pair key construction failed: {error}"))
        })
}

pub(super) fn direct_pair_key_participant(
    did: &str,
    role: &str,
) -> Result<arkret_core::DirectConversationPairKeyParticipant, AppError> {
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
            arkret_core::ErrorCode::PEER_UNRESOLVABLE,
            "direct conversation pairwise DID requires a verified stable-subject identity link",
        ));
    }
    Ok(arkret_core::DirectConversationPairKeyParticipant::unmapped(
        did,
    ))
}

pub(crate) fn active_direct_binding(
    state: &AppState,
    pair_key: &str,
) -> Option<DirectConversationBindingRecord> {
    let binding = state
        .direct_conversation_bindings
        .lock()
        .get(pair_key)
        .filter(|binding| {
            binding.state == "active" && valid_contact_event_ref(&binding.binding_event_ref)
        })
        .cloned()?;
    direct_binding_matches_projection(state, &binding).then_some(binding)
}

pub(crate) fn direct_binding_matches_projection(
    state: &AppState,
    binding: &DirectConversationBindingRecord,
) -> bool {
    if binding.participants_unordered.len() != 2 {
        return false;
    }
    let projection = state.projection.lock();
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
                && strand.state == soland_domain::reducer::ObjectLifecycleState::Active
                && strand
                    .tracks
                    .get(arkret_core::STRAND_TRACK_NAME_DISCUSSION)
                    .is_some_and(|discussion| {
                        discussion.enabled != Some(false) && discussion.is_primary == Some(true)
                    })
        })
}

pub(crate) async fn retire_direct_bindings_for_operation(
    state: &AppState,
    operation: &arkret_core::Operation,
) {
    let kind = soland_domain::kinds::canonical_kind_for_operation(operation);
    let member_ended = kind == Some(arkret_core::events::EventKind::MEMBER_STATE)
        && matches!(
            operation.payload.get("membership").and_then(Value::as_str),
            Some("leave" | "ban")
        );
    let realm_ended = matches!(
        kind,
        Some(
            arkret_core::events::EventKind::REALM_TOMBSTONE
                | arkret_core::events::EventKind::REALM_DESTROY
        )
    );
    let archived_strand = (kind == Some(arkret_core::events::EventKind::STRAND_ARCHIVE))
        .then(|| operation.payload.get("target_ref").and_then(Value::as_str))
        .flatten();
    if !member_ended && !realm_ended && archived_strand.is_none() {
        return;
    }
    let member = member_ended
        .then(|| crate::routing::events::operations::membership_target(operation))
        .flatten();
    let retired = {
        let mut bindings = state.direct_conversation_bindings.lock();
        bindings
            .iter_mut()
            .filter_map(|(pair_key, binding)| {
                let affected = binding.state == "active"
                    && binding.realm_id == operation.realm_id.as_str()
                    && (realm_ended
                        || member.is_some_and(|member| {
                            binding
                                .participants_unordered
                                .iter()
                                .any(|participant| participant == member)
                        })
                        || archived_strand.is_some_and(|strand| strand == binding.main_strand_id));
                affected.then(|| {
                    binding.state = "retired".to_owned();
                    binding.updated_at = now();
                    (pair_key.clone(), binding.clone())
                })
            })
            .collect::<Vec<_>>()
    };
    for (pair_key, binding) in retired {
        if let Err(error) = state
            .contact_application()
            .save_direct_binding(&pair_key, binding)
            .await
        {
            tracing::error!(%error, %pair_key, "failed to persist retired direct binding");
        }
    }
}

fn direct_binding_payload_from_operation(
    operation: &arkret_core::Operation,
) -> Result<arkret_core::DirectConversationBoundPayload, &'static str> {
    let mut payload = operation.payload.clone();
    let object = payload
        .as_object_mut()
        .ok_or("direct_conversation_binding_invalid")?;
    for projection_field in ["event_id", "sender", "hlc"] {
        object.remove(projection_field);
    }
    serde_json::from_value(payload).map_err(|_| "direct_conversation_binding_invalid")
}

pub(crate) async fn validate_direct_binding_operation(
    state: &AppState,
    operation: &arkret_core::Operation,
) -> Result<(), &'static str> {
    if soland_domain::kinds::canonical_kind_for_operation(operation)
        != Some(arkret_core::events::EventKind::DIRECT_CONVERSATION_BOUND)
    {
        return Ok(());
    }
    let payload = direct_binding_payload_from_operation(operation)?;
    let issuer = operation
        .payload
        .get("sender")
        .and_then(Value::as_str)
        .ok_or("direct_conversation_binding_invalid")?;
    if !payload
        .participants_unordered
        .iter()
        .any(|participant| participant.as_str() == issuer)
    {
        return Err("direct_conversation_binding_invalid");
    }
    let trust_domain = arkret_core::TypedTrustDomainId::new(state.config.trust_domain.clone())
        .map_err(|_| "direct_conversation_binding_invalid")?;
    payload
        .validate_pair_key(trust_domain)
        .map_err(|_| "direct_conversation_binding_invalid")?;

    if payload.binding_state == arkret_core::DirectConversationAuthoredBindingState::Retired {
        let supersedes = payload
            .supersedes_binding_ref
            .as_ref()
            .ok_or("direct_conversation_binding_invalid")?;
        let current = state
            .direct_conversation_bindings
            .lock()
            .get(payload.pair_key.as_str())
            .cloned()
            .ok_or("direct_conversation_binding_invalid")?;
        return (current.binding_event_ref == supersedes.as_str())
            .then_some(())
            .ok_or("direct_conversation_binding_invalid");
    }

    let candidate = DirectConversationBindingRecord {
        participants_unordered: payload
            .participants_unordered
            .iter()
            .map(ToString::to_string)
            .collect(),
        realm_id: payload.realm_id.to_string(),
        main_strand_id: payload.main_strand_id.to_string(),
        binding_event_ref: operation
            .payload
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        state: "active".to_owned(),
        created_at: payload.created_at,
        updated_at: now(),
    };
    if !direct_binding_matches_projection(state, &candidate) {
        return Err("direct_conversation_binding_invalid");
    }
    let left = payload.participants_unordered[0].as_str();
    let right = payload.participants_unordered[1].as_str();
    let contact = state
        .contact_application()
        .contact_any(left, right)
        .await
        .map_err(|_| "direct_conversation_binding_invalid")?
        .ok_or("direct_conversation_binding_invalid")?;
    if contact.status != "accepted" {
        return Err("direct_conversation_binding_invalid");
    }
    let verified_contact_refs: BTreeSet<_> = contact_fact_refs(&contact).into_iter().collect();
    if payload.contact_refs.is_empty()
        || payload
            .contact_refs
            .iter()
            .any(|reference| !verified_contact_refs.contains(reference.as_str()))
    {
        return Err("direct_conversation_binding_invalid");
    }
    Ok(())
}

pub(crate) async fn project_canonical_direct_binding(
    state: &AppState,
    operation: &arkret_core::Operation,
) {
    if soland_domain::kinds::canonical_kind_for_operation(operation)
        != Some(arkret_core::events::EventKind::DIRECT_CONVERSATION_BOUND)
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
    if payload.binding_state == arkret_core::DirectConversationAuthoredBindingState::Retired {
        let retired = {
            let mut bindings = state.direct_conversation_bindings.lock();
            bindings.get_mut(&pair_key).and_then(|binding| {
                (payload
                    .supersedes_binding_ref
                    .as_ref()
                    .map(ToString::to_string)
                    == Some(binding.binding_event_ref.clone()))
                .then(|| {
                    binding.state = "retired".to_owned();
                    binding.updated_at = now();
                    binding.clone()
                })
            })
        };
        if let Some(binding) = retired
            && let Err(error) = state
                .contact_application()
                .save_direct_binding(&pair_key, binding)
                .await
        {
            tracing::error!(%error, %pair_key, "failed to persist canonical direct binding retirement");
        }
        return;
    }

    let incoming_digest = operation
        .canonical_event_digest
        .as_deref()
        .unwrap_or_default();
    if incoming_digest.is_empty() {
        return;
    }
    let current = state
        .direct_conversation_bindings
        .lock()
        .get(&pair_key)
        .cloned();
    if let Some(current) = current.as_ref()
        && current.binding_event_ref != event_ref
        && direct_binding_matches_projection(state, current)
    {
        let current_digest = state
            .event_query_application()
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
        binding_event_ref: event_ref,
        state: "active".to_owned(),
        created_at: payload.created_at,
        updated_at: now(),
    };
    if let Err(error) = state
        .contact_application()
        .save_direct_binding(&pair_key, binding.clone())
        .await
    {
        tracing::error!(%error, %pair_key, "failed to persist canonical direct binding projection");
        return;
    }
    state
        .direct_conversation_bindings
        .lock()
        .insert(pair_key, binding);
}

/// Spec contact-and-direct-conversation.md §6 step5 / §7 / §8 — resolve(create=true)
/// stands up a *real event-log* DM Realm: it submits `ak.realm.create`
/// (DM well-known shape), both participants' `ak.member.state{join}`, and
/// the main `ak.strand.create`, then writes the direct conversation binding
/// fact. The realm becomes a true event Realm both sides can submit
/// `ak.message.create` into (accepted, peer-readable) — not just a
/// directory entry. Reuses soland's existing local operation acceptance +
/// projection path (`accept_local_operations`); it does NOT build a parallel
/// realm-materialization path.
enum DirectBindingReservation {
    Existing(DirectConversationBindingRecord),
    Pending(String),
    Reserved {
        realm_id: String,
        main_strand_id: String,
        actor_member_event_ref: String,
        peer_member_event_ref: String,
        main_strand_create_ref: String,
        mls_group_id: String,
        reserved: DirectConversationBindingRecord,
    },
}

pub(crate) async fn create_direct_binding_with_realm(
    state: &AppState,
    pair_key: &str,
    actor: &str,
    actor_device_id: &str,
    peer: &str,
    contact: &ContactRecord,
) -> Result<
    (
        DirectConversationBindingRecord,
        bool,
        Option<arkret_core::Event>,
    ),
    AppError,
> {
    // Reserve the canonical binding under lock so concurrent resolves for the
    // same pair collapse onto a single realm. The reservation holds the
    // generated realm/strand ids; we release the lock before the (async) event
    // submission so projection writes don't deadlock against the guard.
    let reservation = {
        let mut guard = state.direct_conversation_bindings.lock();
        if let Some(existing) = guard.get(pair_key) {
            if existing.state == "active"
                && valid_contact_event_ref(&existing.binding_event_ref)
                && direct_binding_matches_projection(state, existing)
            {
                DirectBindingReservation::Existing(existing.clone())
            } else if matches!(existing.state.as_str(), "pending" | "authoring_required") {
                DirectBindingReservation::Pending(existing.binding_event_ref.clone())
            } else {
                reserve_direct_binding(pair_key, actor, peer, &mut guard)
            }
        } else {
            reserve_direct_binding(pair_key, actor, peer, &mut guard)
        }
    };
    let (
        realm_id,
        main_strand_id,
        actor_member_event_ref,
        peer_member_event_ref,
        main_strand_create_ref,
        mls_group_id,
        reserved,
    ) = match reservation {
        DirectBindingReservation::Existing(binding) => return Ok((binding, false, None)),
        DirectBindingReservation::Pending(binding_event_ref) => {
            return wait_for_pending_direct_binding(state, pair_key, &binding_event_ref).await;
        }
        DirectBindingReservation::Reserved {
            realm_id,
            main_strand_id,
            actor_member_event_ref,
            peer_member_event_ref,
            main_strand_create_ref,
            mls_group_id,
            reserved,
        } => (
            realm_id,
            main_strand_id,
            actor_member_event_ref,
            peer_member_event_ref,
            main_strand_create_ref,
            mls_group_id,
            reserved,
        ),
    };

    let claim = match claim_direct_keypackage(
        state,
        actor,
        peer,
        &realm_id,
        &main_strand_id,
        &mls_group_id,
    )
    .await
    {
        Ok(claim) => claim,
        Err(error) => {
            rollback_reserved_direct_binding(state, pair_key, &reserved).await;
            return Err(error);
        }
    };

    // Submit the genesis events that turn the reserved ids into a real
    // event-log Realm. The realm creator (`actor`) bootstraps the Realm +
    // its own membership in one event; the peer is added with an explicit
    // join; the main Strand is created last. If any step is rejected we must
    // not leave a dangling "active" binding pointing at an orphan realm, so
    // we roll back the reservation and surface the failure.
    if let Err(error) =
        submit_direct_realm_genesis(state, &realm_id, &main_strand_id, actor, peer).await
    {
        rollback_reserved_direct_binding(state, pair_key, &reserved).await;
        return Err(AppError::internal(format!(
            "direct conversation realm genesis failed: {error}"
        )));
    }

    let member_event_refs = vec![
        actor_member_event_ref.clone(),
        peer_member_event_ref.clone(),
    ];
    let governance_binding =
        direct_mls_governance_binding(&realm_id, &mls_group_id, &member_event_refs);
    if let Err(error) = submit_direct_mls_genesis(
        state,
        actor,
        actor_device_id,
        &realm_id,
        &mls_group_id,
        &member_event_refs,
        &governance_binding,
    )
    .await
    {
        rollback_reserved_direct_binding(state, pair_key, &reserved).await;
        return Err(error);
    }
    if let Err(error) = submit_direct_mls_welcome(
        state,
        actor,
        actor_device_id,
        peer,
        &realm_id,
        &mls_group_id,
        &claim,
        &governance_binding,
    )
    .await
    {
        rollback_reserved_direct_binding(state, pair_key, &reserved).await;
        return Err(error);
    }

    // Genesis succeeded, but the participant has not signed the canonical
    // binding Event yet. Persist only an authoring reservation; canonical
    // Event projection is the sole transition to `active`.
    let staged_binding = stage_reserved_direct_binding(state, pair_key, &reserved)?;

    if let Err(error) = state
        .contact_application()
        .save_direct_binding(pair_key, staged_binding.clone())
        .await
    {
        let removed = {
            let mut guard = state.direct_conversation_bindings.lock();
            let removed = guard
                .get(pair_key)
                .is_some_and(|binding| binding.binding_event_ref == reserved.binding_event_ref);
            if removed {
                guard.remove(pair_key);
            }
            removed
        };
        tracing::error!(
            %error,
            pair_key,
            removed,
            "failed to persist direct binding to durable storage"
        );
        return Err(AppError::internal(format!(
            "failed to persist direct binding: {error}"
        )));
    }
    if let Err(error) = publish_reserved_direct_binding(state, pair_key, &staged_binding) {
        if let Err(delete_error) = state
            .contact_application()
            .delete_direct_binding(pair_key)
            .await
        {
            tracing::warn!(
                %delete_error,
                pair_key,
                "failed to delete direct binding after publish failure"
            );
        }
        return Err(error);
    }

    let binding_fact = arkret_core::DirectConversationBoundPayload {
        pair_key: arkret_core::Hash::new(pair_key.to_owned())
            .map_err(|error| AppError::internal(format!("stored pair key is invalid: {error}")))?,
        participants_unordered: staged_binding
            .participants_unordered
            .iter()
            .map(|participant| arkret_core::Did::new(participant.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                AppError::internal(format!("stored direct participant is invalid: {error}"))
            })?,
        realm_id: arkret_core::RealmId::new(realm_id.clone())
            .map_err(|error| AppError::internal(format!("stored realm id is invalid: {error}")))?,
        main_strand_id: arkret_core::StrandId::new(main_strand_id.clone()).map_err(|error| {
            AppError::internal(format!("stored main strand id is invalid: {error}"))
        })?,
        contact_refs: contact_fact_refs(contact)
            .into_iter()
            .map(arkret_core::EventId::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                AppError::internal(format!("stored contact event ref is invalid: {error}"))
            })?,
        member_event_refs: member_event_refs
            .into_iter()
            .map(arkret_core::EventId::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                AppError::internal(format!("stored member event ref is invalid: {error}"))
            })?,
        main_strand_create_ref: arkret_core::EventId::new(main_strand_create_ref).map_err(
            |error| AppError::internal(format!("stored strand event ref is invalid: {error}")),
        )?,
        created_at: staged_binding.created_at,
        binding_state: arkret_core::DirectConversationAuthoredBindingState::Active,
        supersedes_binding_ref: None,
    };
    let trust_domain = arkret_core::TypedTrustDomainId::new(state.config.trust_domain.clone())
        .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    binding_fact
        .validate_pair_key(trust_domain)
        .map_err(|error| {
            AppError::internal(format!(
                "direct binding pair key validation failed: {error}"
            ))
        })?;
    let binding_fact_payload = serde_json::to_value(binding_fact)
        .map_err(|error| AppError::internal(format!("direct binding encoding failed: {error}")))?;
    // The participant device signs and submits the returned draft through the
    // canonical Event endpoint. Issuing the draft is auditable, but MUST NOT
    // append a projection record that could be mistaken for a signed fact.
    append_audit_log(
        state,
        Some(actor),
        "ak.direct_conversation.binding_draft_issued",
        binding_fact_payload.clone(),
        "accepted",
    )
    .await;

    let binding_event = unsigned_direct_binding_event(
        state,
        actor,
        &reserved.binding_event_ref,
        binding_fact_payload,
    )?;

    Ok((staged_binding, false, Some(binding_event)))
}

fn unsigned_direct_binding_event(
    state: &AppState,
    actor: &str,
    event_id: &str,
    payload: Value,
) -> Result<arkret_core::Event, AppError> {
    let realm_id = arkret_core::RealmId::new(
        soland_domain::identity::principal_control_realm_for_did(actor),
    )
    .map_err(|error| AppError::internal(format!("direct binding PCR id invalid: {error}")))?;
    let actor_id = arkret_core::Did::new(actor.to_owned())
        .map_err(|error| AppError::internal(format!("direct binding actor invalid: {error}")))?;
    let hlc = arkret_core::Hlc::new(state.hlc.now())
        .map_err(|error| AppError::internal(format!("direct binding HLC invalid: {error}")))?;
    let mut event = arkret_core::Event::new(
        arkret_core::events::EventKind::DIRECT_CONVERSATION_BOUND,
        realm_id,
        actor_id,
        0,
        hlc,
        payload,
    )
    .map_err(|error| AppError::internal(format!("direct binding Event invalid: {error}")))?;
    event.event_id = arkret_core::EventId::new(event_id.to_owned())
        .map_err(|error| AppError::internal(format!("direct binding event id invalid: {error}")))?;
    Ok(event)
}

fn reserve_direct_binding(
    pair_key: &str,
    actor: &str,
    peer: &str,
    guard: &mut BTreeMap<String, DirectConversationBindingRecord>,
) -> DirectBindingReservation {
    let realm_id = crate::ids::generate_realm_id();
    let main_strand_id = crate::ids::generate("strand");
    let binding_event_ref = crate::ids::generate_event_id();
    let actor_member_event_ref = crate::ids::generate_event_id();
    let peer_member_event_ref = crate::ids::generate_event_id();
    let main_strand_create_ref = crate::ids::generate_event_id();
    let mls_group_id = crate::ids::generate("mls_group");
    let created_at = direct_now_seconds();
    let binding = DirectConversationBindingRecord {
        participants_unordered: sorted_participants(actor, peer),
        realm_id: realm_id.clone(),
        main_strand_id: main_strand_id.clone(),
        binding_event_ref,
        state: "pending".to_owned(),
        created_at,
        updated_at: created_at,
    };
    guard.insert(pair_key.to_owned(), binding.clone());
    DirectBindingReservation::Reserved {
        realm_id,
        main_strand_id,
        actor_member_event_ref,
        peer_member_event_ref,
        main_strand_create_ref,
        mls_group_id,
        reserved: binding,
    }
}

pub(super) fn stage_reserved_direct_binding(
    state: &AppState,
    pair_key: &str,
    reserved: &DirectConversationBindingRecord,
) -> Result<DirectConversationBindingRecord, AppError> {
    let mut staged = reserved.clone();
    staged.state = "authoring_required".to_owned();
    staged.updated_at = now();
    let guard = state.direct_conversation_bindings.lock();
    let still_reserved = guard
        .get(pair_key)
        .is_some_and(|binding| binding.binding_event_ref == reserved.binding_event_ref);
    if !still_reserved {
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "direct conversation binding reservation was superseded",
        ));
    }
    Ok(staged)
}

pub(super) fn publish_reserved_direct_binding(
    state: &AppState,
    pair_key: &str,
    active: &DirectConversationBindingRecord,
) -> Result<(), AppError> {
    let mut guard = state.direct_conversation_bindings.lock();
    let still_reserved = guard
        .get(pair_key)
        .is_some_and(|binding| binding.binding_event_ref == active.binding_event_ref);
    if !still_reserved {
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "direct conversation binding reservation was superseded before publish",
        ));
    }
    guard.insert(pair_key.to_owned(), active.clone());
    Ok(())
}

pub(super) async fn wait_for_pending_direct_binding(
    state: &AppState,
    pair_key: &str,
    binding_event_ref: &str,
) -> Result<
    (
        DirectConversationBindingRecord,
        bool,
        Option<arkret_core::Event>,
    ),
    AppError,
> {
    for _ in 0..DIRECT_BINDING_PENDING_POLL_ATTEMPTS {
        tokio::time::sleep(std::time::Duration::from_millis(
            DIRECT_BINDING_PENDING_POLL_DELAY_MS,
        ))
        .await;
        let observed = state
            .direct_conversation_bindings
            .lock()
            .get(pair_key)
            .cloned();
        match observed {
            Some(binding)
                if binding.binding_event_ref == binding_event_ref && binding.state == "active" =>
            {
                return Ok((binding, false, None));
            }
            Some(binding) if binding.binding_event_ref == binding_event_ref => {}
            _ => {
                return Err(AppError::new(
                    ErrorCode::TemporarilyUnavailable,
                    "direct conversation binding reservation did not complete",
                ));
            }
        }
    }
    Err(AppError::new(
        ErrorCode::TemporarilyUnavailable,
        "direct conversation binding reservation is still pending",
    ))
}

pub(super) async fn rollback_reserved_direct_binding(
    state: &AppState,
    pair_key: &str,
    reserved: &DirectConversationBindingRecord,
) {
    let removed = {
        let mut guard = state.direct_conversation_bindings.lock();
        let removed = guard
            .get(pair_key)
            .is_some_and(|binding| binding.binding_event_ref == reserved.binding_event_ref);
        if removed {
            guard.remove(pair_key);
        }
        removed
    };
    if removed
        && let Err(error) = state
            .contact_application()
            .delete_direct_binding(pair_key)
            .await
    {
        tracing::warn!(%error, pair_key, "failed to delete rolled-back direct binding");
    }
}

pub(super) async fn claim_direct_keypackage(
    state: &AppState,
    actor: &str,
    peer: &str,
    realm_id: &str,
    main_strand_id: &str,
    mls_group_id: &str,
) -> Result<arkret_core::KeyPackageClaimRecord, AppError> {
    let target_principal_id = Did::new(peer.to_owned()).map_err(|_| {
        direct_resolve_precondition(
            arkret_core::ErrorCode::PEER_UNRESOLVABLE,
            "direct conversation peer DID is invalid",
        )
    })?;
    let requester = Did::new(actor.to_owned()).map_err(|_| {
        direct_resolve_precondition(
            arkret_core::ErrorCode::PEER_UNRESOLVABLE,
            "direct conversation requester DID is invalid",
        )
    })?;
    let body = arkret_core::KeyPackagesClaimRequestBody {
        target_principal_id,
        intended_realm_id: RealmId::new(realm_id.to_owned())
            .map_err(|error| AppError::internal(format!("generated realm_id invalid: {error}")))?,
        requester,
        required_capabilities: vec!["ak.mls.rfc9420".to_owned()],
        claim_nonce: URL_SAFE_NO_PAD.encode(format!("direct:{realm_id}:{mls_group_id}").as_bytes()),
        expires_at: now() + chrono::Duration::minutes(5),
        target_device_ids: Vec::new(),
        minimal_metadata_allowed: Some(true),
        timeout_ms: Some(5_000),
        strand_id: Some(StrandId::new(main_strand_id.to_owned()).map_err(|error| {
            AppError::internal(format!("generated main_strand_id invalid: {error}"))
        })?),
        mls_group_id: Some(mls_group_id.to_owned()),
        proofs: Vec::new(),
    };
    let outcome = crate::routing::mls::claim_keypackages_for_request(state, &body)
        .await
        .map_err(|error| match error.wire_code_override.as_deref() {
            Some("claim_generation_mismatch") => direct_resolve_precondition(
                arkret_core::ErrorCode::PEER_UNRESOLVABLE,
                "direct conversation peer has no accepted cross-signing control state",
            ),
            _ => error,
        })?;
    outcome
        .claims
        .into_iter()
        .next()
        .ok_or_else(direct_keypackage_unknown)
}

pub(super) fn direct_keypackage_unknown() -> AppError {
    direct_resolve_precondition(
        arkret_core::ErrorCode::KEYPACKAGE_UNKNOWN,
        "direct conversation peer has no claimable KeyPackage",
    )
}

pub(super) async fn submit_direct_mls_genesis(
    state: &AppState,
    actor: &str,
    actor_device_id: &str,
    realm_id: &str,
    mls_group_id: &str,
    member_event_refs: &[String],
    governance_binding: &Value,
) -> Result<(), AppError> {
    let effective_scope = json!({"kind": "realm", "realm_id": realm_id});
    let payload = json!({
        "mls_group_id": mls_group_id,
        "effective_scope": effective_scope,
        "epoch": 0,
        "creator_principal_id": actor,
        "creator_device_id": actor_device_id,
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_digest": arkret_core::canonical::sha256_digest(format!("direct-group-info:{realm_id}:{mls_group_id}")),
        "ratchet_tree_digest": arkret_core::canonical::sha256_digest(format!("direct-ratchet-tree:{realm_id}:{mls_group_id}")),
        "covered_seals": member_event_refs,
        "governance_binding": governance_binding,
        "created_at": arkret_core::canonical::format_timestamp_canonical(now()),
    });
    let op = direct_mls_operation(
        realm_id,
        arkret_core::events::EventKind::MLS_GENESIS,
        payload,
    )?;
    let effect =
        soland_domain::reducer::mls::apply_group_genesis(&mut state.projection.lock(), &op);
    match &effect {
        soland_domain::reducer::ProjectionEffect::Mls(
            soland_domain::reducer::MlsEffect::GroupGenesis { .. },
        ) => {
            crate::routing::events::projection::mirror_mls_effect_to_persistence(
                state,
                actor,
                actor_device_id,
                &op,
                &effect,
            )
            .await;
            Ok(())
        }
        soland_domain::reducer::ProjectionEffect::Rejected { reason } => Err(AppError::internal(
            format!("direct conversation MLS genesis rejected: {reason}"),
        )),
        other => Err(AppError::internal(format!(
            "unexpected direct conversation MLS genesis effect: {other:?}"
        ))),
    }
}

pub(super) async fn submit_direct_mls_welcome(
    state: &AppState,
    actor: &str,
    actor_device_id: &str,
    peer: &str,
    realm_id: &str,
    mls_group_id: &str,
    claim: &arkret_core::KeyPackageClaimRecord,
    governance_binding: &Value,
) -> Result<(), AppError> {
    let welcome_bytes = format!(
        "direct-mls-welcome:{realm_id}:{mls_group_id}:{}",
        claim.claim_id
    )
    .into_bytes();
    let welcome_digest = arkret_core::canonical::sha256_digest(&welcome_bytes);
    let created_at = now();
    let signature_seed = arkret_core::canonical::sha256_digest(format!(
        "direct-welcome-signature:{realm_id}:{mls_group_id}:{}",
        claim.claim_id
    ));
    let mut claim_ref = json!({
        "claim_id": claim.claim_id.as_str(),
        "keypackage_ref": claim.keypackage_ref.as_str(),
        "keypackage_digest": claim.keypackage_digest.as_str(),
        "capabilities_digest": claim.capabilities_digest.as_str(),
    });
    if let Some(generation) = claim.ssk_generation {
        claim_ref["ssk_generation"] = json!(generation);
    } else if let Some(event_id) = claim.device_authorize_event_id.as_deref() {
        claim_ref["device_authorize_event_id"] = json!(event_id);
    } else {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "direct MLS claim is missing a valid trust binding",
        )
        .with_wire_code("claim_generation_mismatch"));
    }
    let mut claim_envelope = json!({
        "keypackage_ref": claim.keypackage_ref.as_str(),
        "keypackage_digest": claim.keypackage_digest.as_str(),
        "intended_realm_id": realm_id,
        "claim_id": claim.claim_id.as_str(),
        "requester_did": actor,
        "nonce": URL_SAFE_NO_PAD.encode(format!("direct-welcome:{realm_id}:{mls_group_id}:{}", claim.claim_id).as_bytes()),
        "welcome_digest": welcome_digest,
        "created_at": arkret_core::canonical::format_timestamp_canonical(created_at),
        "signature": {
            "kid": format!("{actor}#self-signing"),
            "alg": "EdDSA",
            "sig": URL_SAFE_NO_PAD.encode(signature_seed.as_bytes()),
        }
    });
    let requester_ssk_generation = arkret_core::Did::new(actor.to_owned())
        .ok()
        .and_then(|did| {
            let manager = state.cross_signing.lock();
            {
                manager
                    .current_cross_signing(&did)
                    .map(|publish| publish.generation.get())
            }
        });
    if let Some(generation) = requester_ssk_generation {
        claim_envelope["ssk_generation"] = json!(generation);
    } else {
        claim_envelope["requester_device_id"] = json!(actor_device_id);
    }
    let payload = json!({
        "mls_group_id": mls_group_id,
        "epoch": 1,
        "recipient_principal_id": peer,
        "recipient_device_id": claim.device_id.as_str(),
        "sender_device_id": actor_device_id,
        "keypackage_ref": claim.keypackage_ref.as_str(),
        "keypackage_digest": claim.keypackage_digest.as_str(),
        "claim_id": claim.claim_id.as_str(),
        "claim_ref": claim_ref,
        "claim_envelope": claim_envelope,
        "welcome_ref": format!("ak:blob:{}", arkret_core::canonical::sha256_digest(&welcome_bytes)),
        "welcome_bytes_b64": URL_SAFE_NO_PAD.encode(&welcome_bytes),
        "expires_at": arkret_core::canonical::format_timestamp_canonical(
            created_at + chrono::Duration::days(1)
        ),
        "governance_binding": governance_binding,
    });
    let op = direct_mls_operation(
        realm_id,
        arkret_core::events::EventKind::MLS_WELCOME,
        payload,
    )?;
    let effect =
        soland_domain::reducer::mls::apply_welcome_enqueue(&mut state.projection.lock(), &op);
    match &effect {
        soland_domain::reducer::ProjectionEffect::Mls(
            soland_domain::reducer::MlsEffect::WelcomeEnqueued { .. },
        ) => {
            crate::routing::events::projection::mirror_mls_effect_to_persistence(
                state,
                actor,
                actor_device_id,
                &op,
                &effect,
            )
            .await;
            Ok(())
        }
        soland_domain::reducer::ProjectionEffect::Rejected { reason } => Err(AppError::internal(
            format!("direct conversation MLS welcome rejected: {reason}"),
        )),
        other => Err(AppError::internal(format!(
            "unexpected direct conversation MLS welcome effect: {other:?}"
        ))),
    }
}

pub(super) fn direct_mls_governance_binding(
    realm_id: &str,
    mls_group_id: &str,
    member_event_refs: &[String],
) -> Value {
    let effective_scope = json!({"kind": "realm", "realm_id": realm_id});
    json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "effective_scope": effective_scope,
        "mls_group_id": mls_group_id,
        "previous_epoch": 0,
        "next_epoch": 0,
        "membership_frontier": member_event_refs,
        "policy_root": arkret_core::canonical::sha256_digest(format!("direct-policy:{realm_id}:{mls_group_id}")),
        "binding_profile": soland_domain::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        "reducer_profile": soland_domain::kinds::MLS_REDUCER_PROFILE_V1,
    })
}

pub(super) fn direct_mls_operation(
    realm_id: &str,
    object_type: &str,
    payload: Value,
) -> Result<arkret_core::Operation, AppError> {
    let operation_id = direct_operation_id()
        .map_err(|error| AppError::internal(format!("direct MLS operation id failed: {error}")))?;
    let realm_id = RealmId::new(realm_id.to_owned())
        .map_err(|error| AppError::internal(format!("direct MLS realm id failed: {error}")))?;
    Ok(arkret_core::Operation::create(
        operation_id,
        realm_id,
        object_type,
        payload,
    ))
}

pub(super) fn sorted_participants(actor: &str, peer: &str) -> Vec<String> {
    let mut participants = vec![actor.to_owned(), peer.to_owned()];
    participants.sort();
    participants
}

/// Build + accept the DM Realm genesis operations through the canonical
/// local-operation path. Order matters: realm.create (creator becomes the
/// first member), peer member.state{join}, then the main strand.create.
pub(super) async fn submit_direct_realm_genesis(
    state: &AppState,
    realm_id: &str,
    main_strand_id: &str,
    actor: &str,
    peer: &str,
) -> Result<(), &'static str> {
    let realm_scope = arkret_core::RealmId::new(realm_id.to_owned())
        .map_err(|_| "generated invalid direct conversation realm id")?;

    // ak.realm.create — DM Realm well-known shape (spec §7): mls_rfc9420
    // encryption profile, fail-closed join rule, direct-conversation
    // discriminator in `fields`. The creator is treated as a member by the
    // genesis bootstrap.
    let realm_op = direct_realm_create_operation(state, realm_scope.clone(), actor)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&realm_op)).await?;

    // ak.member.state{join} — add the peer so both participants are active
    // members (active member count == 2, spec §7).
    let member_op = direct_member_join_operation(realm_scope.clone(), peer)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&member_op)).await?;

    // ak.strand.create — main discussion Strand (spec §8): discussion track is
    // primary; no Circle scope.
    let strand_op = direct_strand_create_operation(realm_scope, main_strand_id, actor)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&strand_op)).await?;

    Ok(())
}

pub(super) fn direct_operation_id() -> Result<arkret_core::OperationId, &'static str> {
    arkret_core::OperationId::new(crate::ids::generate_operation_id())
        .map_err(|_| "generated invalid operation id")
}

pub(super) fn direct_now_seconds() -> chrono::DateTime<chrono::Utc> {
    let now = now();
    chrono::DateTime::from_timestamp(now.timestamp(), 0).unwrap_or(now)
}

pub(super) fn direct_realm_create_payload(
    state: &AppState,
    realm_scope: arkret_core::RealmId,
    creator: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, &'static str> {
    let creator_did = arkret_core::Did::new(creator.to_owned())
        .map_err(|_| "invalid direct realm creator DID")?;
    let trust_domain = arkret_core::TypedTrustDomainId::new(state.config.trust_domain.clone())
        .map_err(|_| "invalid direct realm trust domain")?;
    let payload = arkret_core::direct_conversation_realm_create_payload(
        realm_scope,
        creator_did.clone(),
        trust_domain,
        arkret_core::NotaryProfile::SingleDid,
        arkret_core::NotaryValue::single_did(creator_did),
        created_at,
    );
    serde_json::to_value(payload).map_err(|_| "direct realm create payload serialization failed")
}

pub(super) fn direct_realm_create_operation(
    state: &AppState,
    realm_scope: arkret_core::RealmId,
    creator: &str,
) -> Result<arkret_core::Operation, &'static str> {
    let created_at = direct_now_seconds();
    let payload = direct_realm_create_payload(state, realm_scope.clone(), creator, created_at)?;
    let mut operation = arkret_core::Operation::create(
        direct_operation_id()?,
        realm_scope,
        arkret_core::events::EventKind::REALM_CREATE,
        payload,
    );
    operation.created_at = created_at;
    Ok(operation)
}

pub(super) fn direct_member_join_operation(
    realm_scope: arkret_core::RealmId,
    member: &str,
) -> Result<arkret_core::Operation, &'static str> {
    let created_at = direct_now_seconds();
    let payload = direct_member_join_payload(realm_scope.clone(), member)?;
    let mut operation = arkret_core::Operation::create(
        direct_operation_id()?,
        realm_scope,
        arkret_core::events::EventKind::MEMBER_STATE,
        payload,
    );
    operation.created_at = created_at;
    Ok(operation)
}

pub(super) fn direct_member_join_payload(
    realm_scope: arkret_core::RealmId,
    member: &str,
) -> Result<Value, &'static str> {
    let member_did =
        arkret_core::Did::new(member.to_owned()).map_err(|_| "invalid direct peer member DID")?;
    arkret_core::direct_conversation_member_join_payload(
        realm_scope,
        member_did,
        arkret_core::models::DeliveryStatus::Unroutable,
    )
    .to_value()
    .map_err(|_| "direct peer member join payload serialization failed")
}

pub(super) fn direct_strand_create_payload(
    realm_scope: arkret_core::RealmId,
    main_strand_id: &str,
    creator: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, &'static str> {
    let strand_id = arkret_core::StrandId::new(main_strand_id.to_owned())
        .map_err(|_| "generated invalid direct conversation strand id")?;
    let creator_did = arkret_core::Did::new(creator.to_owned())
        .map_err(|_| "invalid direct strand creator DID")?;
    let payload = arkret_core::direct_conversation_main_strand_create_payload(
        strand_id,
        realm_scope,
        creator_did,
        created_at,
    );
    serde_json::to_value(payload).map_err(|_| "direct strand create payload serialization failed")
}

pub(super) fn direct_strand_create_operation(
    realm_scope: arkret_core::RealmId,
    main_strand_id: &str,
    creator: &str,
) -> Result<arkret_core::Operation, &'static str> {
    let created_at = direct_now_seconds();
    let payload =
        direct_strand_create_payload(realm_scope.clone(), main_strand_id, creator, created_at)?;
    let mut operation = arkret_core::Operation::create(
        direct_operation_id()?,
        realm_scope,
        arkret_core::events::EventKind::STRAND_CREATE,
        payload,
    );
    operation.created_at = created_at;
    Ok(operation)
}
