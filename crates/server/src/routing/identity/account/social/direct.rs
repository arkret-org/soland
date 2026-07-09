use super::*;

pub(crate) async fn ensure_direct_peer_resolvable(
    state: &AppState,
    peer: &str,
) -> Result<(), AppError> {
    let account = state
        .persistence
        .accounts()
        .get(peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if account.is_none() {
        return Err(direct_resolve_precondition(
            crate::error::reasons::PEER_UNRESOLVABLE,
            "direct conversation peer is not resolvable on this Principal Server",
        ));
    }
    let peer_did = Did::new(peer.to_owned()).map_err(|_| {
        direct_resolve_precondition(
            crate::error::reasons::PEER_UNRESOLVABLE,
            "direct conversation peer DID is invalid",
        )
    })?;
    let has_cross_signing_control = state
        .cross_signing
        .lock()
        .current_cross_signing(&peer_did)
        .is_some_and(|publish| publish.generation >= 1);
    if !has_cross_signing_control {
        return Err(direct_resolve_precondition(
            crate::error::reasons::PEER_UNRESOLVABLE,
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
    let trust_domain = cokret_sdk::TypedTrustDomainId::new(state.config.trust_domain.clone())
        .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    let left = direct_pair_key_participant(left, "actor")?;
    let right = direct_pair_key_participant(right, "peer")?;
    cokret_sdk::direct_conversation_pair_key(trust_domain, left, right).map_err(|error| {
        AppError::internal(format!("direct pair key construction failed: {error}"))
    })
}

pub(super) fn direct_pair_key_participant(
    did: &str,
    role: &str,
) -> Result<cokret_sdk::DirectConversationPairKeyParticipant, AppError> {
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
            crate::error::reasons::PEER_UNRESOLVABLE,
            "direct conversation pairwise DID requires a verified stable-subject identity link",
        ));
    }
    Ok(cokret_sdk::DirectConversationPairKeyParticipant::unmapped(
        did,
    ))
}

pub(crate) fn active_direct_binding(
    state: &AppState,
    pair_key: &str,
) -> Option<DirectConversationBindingRecord> {
    state
        .direct_conversation_bindings
        .lock()
        .get(pair_key)
        .filter(|binding| {
            binding.state == "active" && valid_contact_event_ref(&binding.binding_event_ref)
        })
        .cloned()
}

/// Spec contact-and-direct-conversation.md §6 step5 / §7 / §8 — resolve(create=true)
/// stands up a *real event-log* DM Realm: it submits `ck.realm.create`
/// (DM well-known shape), both participants' `ck.member.state{join}`, and
/// the main `ck.strand.create`, then writes the direct conversation binding
/// fact. The realm becomes a true event Realm both sides can submit
/// `ck.message.create` into (accepted, peer-readable) — not just a
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
) -> Result<(DirectConversationBindingRecord, bool), AppError> {
    // Reserve the canonical binding under lock so concurrent resolves for the
    // same pair collapse onto a single realm. The reservation holds the
    // generated realm/strand ids; we release the lock before the (async) event
    // submission so projection writes don't deadlock against the guard.
    let reservation = {
        let mut guard = state.direct_conversation_bindings.lock();
        if let Some(existing) = guard.get(pair_key) {
            if existing.state == "active" && valid_contact_event_ref(&existing.binding_event_ref) {
                DirectBindingReservation::Existing(existing.clone())
            } else if existing.state == "pending" {
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
        DirectBindingReservation::Existing(binding) => return Ok((binding, false)),
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

    // Genesis succeeded — write the binding through to durable storage so the
    // canonical pair → (realm_id, main_strand_id) projection survives restart.
    let active_binding = activate_reserved_direct_binding(state, pair_key, &reserved)?;

    if let Err(error) = state
        .persistence
        .direct_conversation_bindings()
        .put(pair_key, &active_binding)
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
    if let Err(error) = publish_reserved_direct_binding(state, pair_key, &active_binding) {
        if let Err(delete_error) = state
            .persistence
            .direct_conversation_bindings()
            .delete(pair_key)
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

    let binding_fact_payload = json!({
        "pair_key": pair_key,
        "participants_unordered": active_binding.participants_unordered.clone(),
        "realm_id": realm_id,
        "main_strand_id": main_strand_id,
        "contact_refs": contact_fact_refs(contact),
        "member_event_refs": member_event_refs,
        "main_strand_create_ref": main_strand_create_ref,
        "created_at": active_binding.created_at.to_rfc3339(),
    });
    crate::routing::events::projection::append_projection_event(
        state,
        ProjectionEventRecord {
            event_id: reserved.binding_event_ref.clone(),
            realm_id: crate::routing::identity::recovery::principal_control_realm_for_did(actor),
            event_kind: "ck.direct_conversation.bound".to_owned(),
            operation_type: "direct_conversation_binding_fact".to_owned(),
            operation_id: None,
            sender: Some(actor.to_owned()),
            payload: binding_fact_payload.clone(),
            created_at: active_binding.created_at,
            received_at: chrono::Utc::now(),
        },
    )
    .await;
    // Binding fact (spec §6) — the canonical pair → (realm_id, main_strand_id)
    // signed fact / projection. Recorded after the realm + membership + main
    // Strand are all live so it only ever references a verifiable realm.
    append_audit_log(
        state,
        Some(actor),
        "ck.direct_conversation.bound",
        binding_fact_payload,
        "accepted",
    )
    .await;

    Ok((active_binding, true))
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
    let binding = DirectConversationBindingRecord {
        participants_unordered: sorted_participants(actor, peer),
        realm_id: realm_id.clone(),
        main_strand_id: main_strand_id.clone(),
        binding_event_ref,
        state: "pending".to_owned(),
        created_at: now(),
        updated_at: now(),
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

pub(super) fn activate_reserved_direct_binding(
    state: &AppState,
    pair_key: &str,
    reserved: &DirectConversationBindingRecord,
) -> Result<DirectConversationBindingRecord, AppError> {
    let mut active = reserved.clone();
    active.state = "active".to_owned();
    active.updated_at = now();
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
    Ok(active)
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
) -> Result<(DirectConversationBindingRecord, bool), AppError> {
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
                return Ok((binding, false));
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
            .persistence
            .direct_conversation_bindings()
            .delete(pair_key)
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
) -> Result<cokret_sdk::KeyPackageClaimRecord, AppError> {
    let target_principal_id = Did::new(peer.to_owned()).map_err(|_| {
        direct_resolve_precondition(
            crate::error::reasons::PEER_UNRESOLVABLE,
            "direct conversation peer DID is invalid",
        )
    })?;
    let requester = Did::new(actor.to_owned()).map_err(|_| {
        direct_resolve_precondition(
            crate::error::reasons::PEER_UNRESOLVABLE,
            "direct conversation requester DID is invalid",
        )
    })?;
    let body = cokret_sdk::KeyPackagesClaimRequestBody {
        target_principal_id,
        intended_realm_id: RealmId::new(realm_id.to_owned())
            .map_err(|error| AppError::internal(format!("generated realm_id invalid: {error}")))?,
        requester,
        required_capabilities: vec!["ck.mls.rfc9420".to_owned()],
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
                crate::error::reasons::PEER_UNRESOLVABLE,
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
        crate::error::reasons::KEYPACKAGE_UNKNOWN,
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
        "group_info_digest": cokret_sdk::canonical::sha256_digest(format!("direct-group-info:{realm_id}:{mls_group_id}")),
        "ratchet_tree_digest": cokret_sdk::canonical::sha256_digest(format!("direct-ratchet-tree:{realm_id}:{mls_group_id}")),
        "covered_seals": member_event_refs,
        "governance_binding": governance_binding,
        "created_at": now().to_rfc3339_opts(SecondsFormat::Secs, true),
    });
    let op = direct_mls_operation(realm_id, cokret_sdk::events::kinds::MLS_GENESIS, payload)?;
    let effect = crate::reducer::mls::apply_group_genesis(&mut state.projection.lock(), &op);
    match &effect {
        crate::reducer::ProjectionEffect::Mls(crate::reducer::MlsEffect::GroupGenesis {
            ..
        }) => {
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
        crate::reducer::ProjectionEffect::Rejected { reason } => Err(AppError::internal(format!(
            "direct conversation MLS genesis rejected: {reason}"
        ))),
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
    claim: &cokret_sdk::KeyPackageClaimRecord,
    governance_binding: &Value,
) -> Result<(), AppError> {
    let welcome_bytes = format!(
        "direct-mls-welcome:{realm_id}:{mls_group_id}:{}",
        claim.claim_id
    )
    .into_bytes();
    let welcome_digest = cokret_sdk::canonical::sha256_digest(&welcome_bytes);
    let created_at = now();
    let signature_seed = cokret_sdk::canonical::sha256_digest(format!(
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
        "created_at": created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        "signature": {
            "kid": format!("{actor}#self-signing"),
            "alg": "EdDSA",
            "sig": URL_SAFE_NO_PAD.encode(signature_seed.as_bytes()),
        }
    });
    let requester_ssk_generation = cokret_sdk::Did::new(actor.to_owned())
        .ok()
        .and_then(|did| {
            let manager = state.cross_signing.lock();
            {
                manager
                    .current_cross_signing(&did)
                    .map(|publish| publish.generation)
            }
        })
        .filter(|generation| *generation >= 1);
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
        "welcome_ref": format!("ck:blob:{}", cokret_sdk::canonical::sha256_digest(&welcome_bytes)),
        "welcome_bytes_b64": URL_SAFE_NO_PAD.encode(&welcome_bytes),
        "expires_at": (created_at + chrono::Duration::days(1)).to_rfc3339_opts(SecondsFormat::Secs, true),
        "governance_binding": governance_binding,
    });
    let op = direct_mls_operation(realm_id, cokret_sdk::events::kinds::MLS_WELCOME, payload)?;
    let effect = crate::reducer::mls::apply_welcome_enqueue(&mut state.projection.lock(), &op);
    match &effect {
        crate::reducer::ProjectionEffect::Mls(crate::reducer::MlsEffect::WelcomeEnqueued {
            ..
        }) => {
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
        crate::reducer::ProjectionEffect::Rejected { reason } => Err(AppError::internal(format!(
            "direct conversation MLS welcome rejected: {reason}"
        ))),
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
        "policy_root": cokret_sdk::canonical::sha256_digest(format!("direct-policy:{realm_id}:{mls_group_id}")),
        "binding_profile": crate::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        "reducer_profile": crate::kinds::MLS_REDUCER_PROFILE_V1,
    })
}

pub(super) fn direct_mls_operation(
    realm_id: &str,
    object_type: &str,
    payload: Value,
) -> Result<cokret_sdk::Operation, AppError> {
    let operation_id = direct_operation_id()
        .map_err(|error| AppError::internal(format!("direct MLS operation id failed: {error}")))?;
    let realm_id = RealmId::new(realm_id.to_owned())
        .map_err(|error| AppError::internal(format!("direct MLS realm id failed: {error}")))?;
    Ok(cokret_sdk::Operation::create(
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
    let realm_scope = cokret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|_| "generated invalid direct conversation realm id")?;

    // ck.realm.create — DM Realm well-known shape (spec §7): mls_rfc9420
    // encryption profile, fail-closed join rule, direct-conversation
    // discriminator in `fields`. The creator is treated as a member by the
    // genesis bootstrap.
    let realm_op = direct_realm_create_operation(state, realm_scope.clone(), actor)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&realm_op)).await?;

    // ck.member.state{join} — add the peer so both participants are active
    // members (active member count == 2, spec §7).
    let member_op = direct_member_join_operation(realm_scope.clone(), peer)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&member_op)).await?;

    // ck.strand.create — main discussion Strand (spec §8): discussion track is
    // primary; no Circle scope.
    let strand_op = direct_strand_create_operation(realm_scope, main_strand_id, actor)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&strand_op)).await?;

    Ok(())
}

pub(super) fn direct_operation_id() -> Result<cokret_sdk::OperationId, &'static str> {
    cokret_sdk::OperationId::new(crate::ids::generate_operation_id())
        .map_err(|_| "generated invalid operation id")
}

pub(super) fn direct_now_seconds() -> chrono::DateTime<chrono::Utc> {
    let now = now();
    chrono::DateTime::from_timestamp(now.timestamp(), 0).unwrap_or(now)
}

pub(super) fn direct_realm_create_payload(
    state: &AppState,
    realm_scope: cokret_sdk::RealmId,
    creator: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, &'static str> {
    let creator_did =
        cokret_sdk::Did::new(creator.to_owned()).map_err(|_| "invalid direct realm creator DID")?;
    let trust_domain = cokret_sdk::TypedTrustDomainId::new(state.config.trust_domain.clone())
        .map_err(|_| "invalid direct realm trust domain")?;
    let mut realm = cokret_sdk::models::Realm::new(
        realm_scope,
        "Direct conversation",
        creator_did.clone(),
        trust_domain,
        cokret_sdk::NotaryProfile::SingleDid,
        cokret_sdk::NotaryValue::single_did(creator_did),
    );
    realm.security_class = Some(cokret_sdk::SecurityClass::Standard);
    realm.default_discoverability = cokret_sdk::Discoverability::InviteOnly;
    realm.default_join_rule = cokret_sdk::JoinRule::Closed;
    realm.history_visibility = cokret_sdk::HistoryVisibility::Joined;
    realm.encryption_profile = cokret_sdk::EncryptionProfile::MlsRfc9420;
    realm.federation_policy = Some(cokret_sdk::FederationPolicy::Restricted);
    realm.created_at = created_at;
    realm.extra.insert(
        "fields".to_owned(),
        json!({
            "conversation_kind": "direct_message",
        }),
    );
    serde_json::to_value(cokret_sdk::models::RealmCreatePayload {
        object: realm,
        initial_relations: None,
    })
    .map_err(|_| "direct realm create payload serialization failed")
}

pub(super) fn direct_realm_create_operation(
    state: &AppState,
    realm_scope: cokret_sdk::RealmId,
    creator: &str,
) -> Result<cokret_sdk::Operation, &'static str> {
    let created_at = direct_now_seconds();
    let payload = direct_realm_create_payload(state, realm_scope.clone(), creator, created_at)?;
    let mut operation = cokret_sdk::Operation::create(
        direct_operation_id()?,
        realm_scope,
        cokret_sdk::events::kinds::REALM_CREATE,
        payload,
    );
    operation.created_at = created_at;
    Ok(operation)
}

pub(super) fn direct_member_join_operation(
    realm_scope: cokret_sdk::RealmId,
    member: &str,
) -> Result<cokret_sdk::Operation, &'static str> {
    let created_at = direct_now_seconds();
    let payload = direct_member_join_payload(realm_scope.clone(), member)?;
    let mut operation = cokret_sdk::Operation::create(
        direct_operation_id()?,
        realm_scope,
        cokret_sdk::events::kinds::MEMBER_STATE,
        payload,
    );
    operation.created_at = created_at;
    Ok(operation)
}

pub(super) fn direct_member_join_payload(
    realm_scope: cokret_sdk::RealmId,
    member: &str,
) -> Result<Value, &'static str> {
    let member_did =
        cokret_sdk::Did::new(member.to_owned()).map_err(|_| "invalid direct peer member DID")?;
    cokret_sdk::models::MembershipPayload::join(
        realm_scope,
        member_did,
        cokret_sdk::models::DeliveryStatus::Unroutable,
        "direct_conversation_peer_bootstrap",
    )
    .to_value()
    .map_err(|_| "direct peer member join payload serialization failed")
}

pub(super) fn direct_strand_create_payload(
    realm_scope: cokret_sdk::RealmId,
    main_strand_id: &str,
    creator: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, &'static str> {
    let strand_id = cokret_sdk::StrandId::new(main_strand_id.to_owned())
        .map_err(|_| "generated invalid direct conversation strand id")?;
    let creator_did = cokret_sdk::Did::new(creator.to_owned())
        .map_err(|_| "invalid direct strand creator DID")?;
    let mut strand = cokret_sdk::models::Strand::discussion(
        strand_id,
        realm_scope,
        "Direct conversation",
        creator_did,
    );
    strand.created_at = created_at;
    serde_json::to_value(cokret_sdk::models::StrandCreatePayload {
        object: strand,
        initial_relations: None,
    })
    .map_err(|_| "direct strand create payload serialization failed")
}

pub(super) fn direct_strand_create_operation(
    realm_scope: cokret_sdk::RealmId,
    main_strand_id: &str,
    creator: &str,
) -> Result<cokret_sdk::Operation, &'static str> {
    let created_at = direct_now_seconds();
    let payload =
        direct_strand_create_payload(realm_scope.clone(), main_strand_id, creator, created_at)?;
    let mut operation = cokret_sdk::Operation::create(
        direct_operation_id()?,
        realm_scope,
        cokret_sdk::events::kinds::STRAND_CREATE,
        payload,
    );
    operation.created_at = created_at;
    Ok(operation)
}
