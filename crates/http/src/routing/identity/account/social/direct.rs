use super::*;

pub(crate) fn direct_authorization_basis_from_contact(
    contact: &ContactRecord,
) -> Result<arkret_core::DirectConversationAuthorizationBasis, AppError> {
    let event_refs = contact_fact_refs(contact)
        .into_iter()
        .map(arkret_core::EventId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AppError::internal(format!("stored contact event ref is invalid: {error}"))
        })?;
    let basis = arkret_core::DirectConversationAuthorizationBasis::accepted_contact(event_refs);
    basis.validate_shape().map_err(|error| {
        AppError::internal(format!(
            "stored direct conversation contact authorization basis is invalid: {error}"
        ))
    })?;
    Ok(basis)
}

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
        let managed_agent = state
            .agent_pairing_application()
            .agent(peer)
            .await
            .map_err(|error| AppError::internal(format!("managed Agent lookup failed: {error}")))?;
        if let Some(record) = managed_agent
            && record.state == "active"
            && record.authorized_event_ref.is_some()
            && crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
                state,
                &record,
                now(),
            )
            .await
            .is_ok()
        {
            return Ok(());
        }
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
        .identity_application()
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
    let trust_domain = arkret_core::TypedTrustDomainId::new(state.config().trust_domain.clone())
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
        .contact_application()
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
    let projection = state.projection_application().snapshot();
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
    let kind = soland_application::operation_semantics::canonical_kind_for_operation(operation);
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
    let retired = state.contact_application().retire_affected_direct_bindings(
        operation.realm_id.as_str(),
        member,
        archived_strand,
        realm_ended,
        now(),
    );
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
    if soland_application::operation_semantics::canonical_kind_for_operation(operation)
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
    let trust_domain = arkret_core::TypedTrustDomainId::new(state.config().trust_domain.clone())
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
            .contact_application()
            .direct_binding(payload.pair_key.as_str())
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
        authoring_context: None,
        created_at: payload.created_at,
        updated_at: now(),
    };
    if !direct_binding_matches_projection(state, &candidate) {
        return Err("direct_conversation_binding_invalid");
    }
    validate_direct_binding_event_refs(state, &payload).await?;
    if payload.authorization_basis.kind
        == arkret_core::DirectConversationAuthorizationKind::AcceptedContact
    {
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
        if payload
            .authorization_basis
            .event_refs
            .iter()
            .any(|reference| !verified_contact_refs.contains(reference.as_str()))
        {
            return Err("direct_conversation_binding_invalid");
        }
    }
    Ok(())
}

async fn accepted_direct_event(
    state: &AppState,
    event_id: &arkret_core::EventId,
    realm_id: &arkret_core::RealmId,
    kind: &str,
) -> Result<arkret_core::Event, &'static str> {
    let accepted = state
        .event_query_application()
        .accepted_event(event_id.as_str())
        .await
        .map_err(|_| "direct_conversation_binding_invalid")?
        .ok_or("direct_conversation_binding_invalid")?;
    if accepted.realm_id.as_deref() != Some(realm_id.as_str()) || accepted.kind != kind {
        return Err("direct_conversation_binding_invalid");
    }
    serde_json::from_value(accepted.envelope).map_err(|_| "direct_conversation_binding_invalid")
}

async fn validate_direct_binding_event_refs(
    state: &AppState,
    payload: &arkret_core::DirectConversationBoundPayload,
) -> Result<(), &'static str> {
    if payload.member_event_refs.len() != 2 {
        return Err("direct_conversation_binding_invalid");
    }
    let mut realm_create_ref = None;
    let mut peer_member_ref = None;
    for event_id in &payload.member_event_refs {
        let accepted = state
            .event_query_application()
            .accepted_event(event_id.as_str())
            .await
            .map_err(|_| "direct_conversation_binding_invalid")?
            .ok_or("direct_conversation_binding_invalid")?;
        match accepted.kind.as_str() {
            arkret_core::events::EventKind::REALM_CREATE if realm_create_ref.is_none() => {
                realm_create_ref = Some(event_id)
            }
            arkret_core::events::EventKind::MEMBER_STATE if peer_member_ref.is_none() => {
                peer_member_ref = Some(event_id)
            }
            _ => return Err("direct_conversation_binding_invalid"),
        }
    }
    let realm_create_ref = realm_create_ref.ok_or("direct_conversation_binding_invalid")?;
    let peer_member_ref = peer_member_ref.ok_or("direct_conversation_binding_invalid")?;
    let realm_create = accepted_direct_event(
        state,
        realm_create_ref,
        &payload.realm_id,
        arkret_core::events::EventKind::REALM_CREATE,
    )
    .await?;
    let creator = realm_create
        .payload
        .get("object")
        .and_then(|object| object.get("created_by"))
        .and_then(Value::as_str)
        .ok_or("direct_conversation_binding_invalid")?;
    if !payload
        .participants_unordered
        .iter()
        .any(|participant| participant.as_str() == creator)
    {
        return Err("direct_conversation_binding_invalid");
    }
    let peer_member = accepted_direct_event(
        state,
        peer_member_ref,
        &payload.realm_id,
        arkret_core::events::EventKind::MEMBER_STATE,
    )
    .await?;
    let peer = peer_member
        .payload
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or("direct_conversation_binding_invalid")?;
    if peer == creator
        || peer_member
            .payload
            .get("membership")
            .and_then(Value::as_str)
            != Some("join")
        || !payload
            .participants_unordered
            .iter()
            .any(|participant| participant.as_str() == peer)
    {
        return Err("direct_conversation_binding_invalid");
    }

    let mut authorization_kinds = BTreeSet::new();
    for event_ref in &payload.authorization_basis.event_refs {
        let accepted = state
            .event_query_application()
            .accepted_event(event_ref.as_str())
            .await
            .map_err(|_| "direct_conversation_binding_invalid")?
            .ok_or("direct_conversation_binding_invalid")?;
        authorization_kinds.insert(accepted.kind);
    }
    match payload.authorization_basis.kind {
        arkret_core::DirectConversationAuthorizationKind::AcceptedContact => {
            let expected = BTreeSet::from([
                arkret_core::events::EventKind::CONTACT_REQUESTED.to_owned(),
                arkret_core::events::EventKind::CONTACT_ACCEPTED.to_owned(),
            ]);
            if payload.authorization_basis.event_refs.len() != 2 || authorization_kinds != expected
            {
                return Err("direct_conversation_binding_invalid");
            }
        }
        arkret_core::DirectConversationAuthorizationKind::ManagedAgentController => {
            let expected = BTreeSet::from([
                arkret_core::events::EventKind::IDENTITY_ACCOUNTABILITY_GRANT.to_owned(),
                arkret_core::events::EventKind::AGENT_SELECTOR_CLAIM.to_owned(),
                arkret_core::events::EventKind::AGENT_KEY_AUTHORIZE.to_owned(),
            ]);
            if payload.authorization_basis.event_refs.len() != 3 || authorization_kinds != expected
            {
                return Err("direct_conversation_binding_invalid");
            }
            let record = state
                .agent_pairing_application()
                .agent(peer)
                .await
                .map_err(|_| "direct_conversation_binding_invalid")?
                .ok_or("direct_conversation_binding_invalid")?;
            if record.controller_id != creator || record.state != "active" {
                return Err("direct_conversation_binding_invalid");
            }
            let provision_refs = record
                .provision_event_refs
                .as_ref()
                .ok_or("direct_conversation_binding_invalid")?;
            let expected_refs = [
                provision_refs
                    .get("accountability_grant_event_id")
                    .and_then(Value::as_str),
                provision_refs
                    .get("selector_claim_event_id")
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
                .map(arkret_core::EventId::as_str)
                .collect::<BTreeSet<_>>();
            if provided_refs != expected_refs {
                return Err("direct_conversation_binding_invalid");
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

    let strand = accepted_direct_event(
        state,
        &payload.main_strand_create_ref,
        &payload.realm_id,
        arkret_core::events::EventKind::STRAND_CREATE,
    )
    .await?;
    if strand
        .payload
        .get("object")
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        != Some(payload.main_strand_id.as_str())
    {
        return Err("direct_conversation_binding_invalid");
    }

    let genesis = accepted_direct_event(
        state,
        &payload.mls_genesis_event_ref,
        &payload.realm_id,
        arkret_core::events::EventKind::MLS_GENESIS,
    )
    .await?;
    let commit = accepted_direct_event(
        state,
        &payload.mls_commit_event_ref,
        &payload.realm_id,
        arkret_core::events::EventKind::MLS_COMMIT,
    )
    .await?;
    let welcome = accepted_direct_event(
        state,
        &payload.mls_welcome_event_ref,
        &payload.realm_id,
        arkret_core::events::EventKind::MLS_WELCOME,
    )
    .await?;
    let group_matches = |event: &arkret_core::Event| {
        event
            .payload
            .get("mls_group_id")
            .or_else(|| event.payload.get("group_id"))
            .and_then(Value::as_str)
            == Some(payload.mls_group_id.as_str())
    };
    if !group_matches(&genesis)
        || genesis.payload.get("epoch").and_then(Value::as_u64) != Some(0)
        || !group_matches(&commit)
        || commit.payload.get("base_epoch").and_then(Value::as_u64) != Some(0)
        || commit.payload.get("next_epoch").and_then(Value::as_u64) != Some(1)
        || !group_matches(&welcome)
        || welcome.payload.get("epoch").and_then(Value::as_u64) != Some(1)
        || welcome.payload.get("commit_ref").and_then(Value::as_str)
            != Some(payload.mls_commit_event_ref.as_str())
    {
        return Err("direct_conversation_binding_invalid");
    }
    let recipient = welcome
        .payload
        .get("recipient_principal_id")
        .and_then(Value::as_str)
        .ok_or("direct_conversation_binding_invalid")?;
    if recipient == creator
        || !payload
            .participants_unordered
            .iter()
            .any(|participant| participant.as_str() == recipient)
    {
        return Err("direct_conversation_binding_invalid");
    }
    let typed_welcome = serde_json::from_value::<arkret_core::MlsWelcomePayload>(
        serde_json::to_value(&welcome.payload)
            .map_err(|_| "direct_conversation_binding_invalid")?,
    )
    .map_err(|_| "direct_conversation_binding_invalid")?;
    if let Some(receipt) = typed_welcome.peer_claim_receipt.as_ref() {
        let request = &receipt.request;
        if request.claim_purpose != arkret_core::PeerKeyPackageClaimPurpose::DirectConversation
            || request.requester.as_str() != creator
            || request.target_principal_id.as_str() != recipient
            || request.intended_realm_id != payload.realm_id
            || request.mls_group_id.as_str() != payload.mls_group_id.as_str()
            || request.strand_id.as_ref() != Some(&payload.main_strand_id)
            || request.pair_key.as_ref() != Some(&payload.pair_key)
            || request.allow_last_resort == Some(true)
        {
            return Err("direct_conversation_binding_invalid");
        }
    }
    Ok(())
}

pub(crate) async fn project_canonical_direct_binding(
    state: &AppState,
    operation: &arkret_core::Operation,
) {
    if soland_application::operation_semantics::canonical_kind_for_operation(operation)
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
        let retired = payload
            .supersedes_binding_ref
            .as_ref()
            .and_then(|supersedes| {
                state
                    .contact_application()
                    .retire_direct_binding_if_current(&pair_key, supersedes.as_str(), now())
            });
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
    let current = state.contact_application().direct_binding(&pair_key);
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
        binding_event_ref: event_ref.clone(),
        state: "active".to_owned(),
        authoring_context: None,
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
    // A binding is principal-scoped, so ordinary Realm federation does not
    // carry it to the other holder. Mirror the exact accepted, participant-
    // signed envelope through the peer-contact rail. Only the actor's home PS
    // sends it; a recipient projecting the mirrored envelope must not echo it
    // back and create a federation loop.
    let Some(issuer) = operation
        .payload
        .get("sender")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return;
    };
    let is_local_issuer = state
        .identity_application()
        .find_account_by_actor(soland_application::identity::FindAccountByActorQuery {
            actor_id: issuer.clone(),
        })
        .await
        .ok()
        .flatten()
        .is_some();
    if !is_local_issuer {
        return;
    }
    let Some(peer) = payload
        .participants_unordered
        .iter()
        .map(ToString::to_string)
        .find(|participant| participant != &issuer)
    else {
        return;
    };
    let Ok(Some(contact)) = state
        .contact_application()
        .contact_any(&issuer, &peer)
        .await
    else {
        return;
    };
    let Some(recipient_service_id) = contact.peer_service_id.as_deref() else {
        return;
    };
    let Ok(Some(record)) = state
        .event_query_application()
        .accepted_event(&event_ref)
        .await
    else {
        return;
    };
    let Ok(event) = serde_json::from_value::<arkret_core::Event>(record.envelope) else {
        return;
    };
    if let Err(error) = crate::routing::identity::contact_federation::federate_signed_contact_fact(
        state,
        &peer,
        recipient_service_id,
        event,
    )
    .await
    {
        tracing::error!(%error, %event_ref, %recipient_service_id, "failed to enqueue direct binding federation");
    }
}

/// Spec contact-and-direct-conversation.md §6 step5 / §7 / §8 — resolve(create=true)
/// reserves the immutable identifiers and participant-authoring drafts needed
/// for a real event-log DM Realm. The participant device signs and submits the
/// atomic Realm bootstrap, main Strand, MLS genesis/Add Commit/Welcome, and
/// finally the principal-scoped binding Event. Soland only projects accepted
/// canonical Events; it never substitutes a server-authored Operation for the
/// participant proof.
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteDirectAuthoringContext {
    actor_member_event_ref: String,
    peer_member_event_ref: String,
    main_strand_create_ref: String,
    mls_group_id: String,
    claim_authorization_draft: arkret_core::PeerKeyPackagesClaimAuthorizationDraft,
    claim_command_dispatched: bool,
    #[serde(default)]
    requester_signing_key_evidence: Option<arkret_core::FederatedDeviceSigningKeyEvidence>,
}

pub(crate) async fn prepare_remote_direct_keypackage_claim(
    state: &AppState,
    pair_key: &str,
    actor: &str,
    peer: &str,
    peer_service_id: &str,
) -> Result<
    (
        DirectConversationBindingRecord,
        arkret_core::PeerKeyPackagesClaimAuthorizationDraft,
    ),
    AppError,
> {
    if peer_service_id == state.service_id() {
        return Err(AppError::internal(
            "remote direct authoring requested for the local service",
        ));
    }
    if crate::routing::federation::federation::peer_url_for_service_id(state, peer_service_id)
        .is_none()
    {
        return Err(direct_resolve_precondition(
            arkret_core::ErrorCode::PEER_UNRESOLVABLE,
            "direct conversation peer service is not configured",
        ));
    }
    if let Some(existing) = state.contact_application().direct_binding(pair_key)
        && existing.state == "authoring_required"
        && let Some(context) = remote_authoring_context(&existing)
    {
        return Ok((existing, context.claim_authorization_draft));
    }

    let reservation = reserve_direct_binding(state, pair_key, actor, peer, None);
    let DirectBindingReservation::Reserved {
        actor_member_event_ref,
        peer_member_event_ref,
        main_strand_create_ref,
        mls_group_id,
        mut reserved,
        ..
    } = reservation
    else {
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "direct conversation reservation is unavailable",
        ));
    };
    let claim_request_id = URL_SAFE_NO_PAD.encode(uuid::Uuid::now_v7().as_bytes());
    let claim_nonce = URL_SAFE_NO_PAD.encode(uuid::Uuid::now_v7().as_bytes());
    let draft: arkret_core::PeerKeyPackagesClaimAuthorizationDraft = serde_json::from_value(json!({
        "request": {
            "claim_request_id": claim_request_id,
            "target_principal_id": peer,
            "requester": actor,
            "intended_realm_id": reserved.realm_id,
            "mls_group_id": mls_group_id,
            "claim_purpose": "direct_conversation",
            "required_capabilities": ["ak.mls.rfc9420"],
            "claim_nonce": claim_nonce,
            "expires_at": arkret_core::canonical::format_timestamp_canonical(now() + chrono::Duration::minutes(5)),
            "target_device_ids": [],
            "minimal_metadata_allowed": true,
            "timeout_ms": 5000,
            "strand_id": reserved.main_strand_id,
            "pair_key": pair_key,
            "allow_last_resort": false
        },
        "transport_binding": {
            "source_service_id": state.service_id(),
            "destination_service_id": peer_service_id,
            "source_trust_domain": state.config().trust_domain,
            "destination_trust_domain": state.config().trust_domain
        }
    }))
    .map_err(|error| AppError::internal(format!("remote claim draft invalid: {error}")))?;
    let context = RemoteDirectAuthoringContext {
        actor_member_event_ref,
        peer_member_event_ref,
        main_strand_create_ref,
        mls_group_id,
        claim_authorization_draft: draft.clone(),
        claim_command_dispatched: false,
        requester_signing_key_evidence: None,
    };
    reserved.state = "authoring_required".to_owned();
    reserved.authoring_context = Some(serde_json::to_value(context).map_err(|error| {
        AppError::internal(format!("remote direct authoring context invalid: {error}"))
    })?);
    reserved.updated_at = now();
    state
        .contact_application()
        .save_direct_binding(pair_key, reserved.clone())
        .await
        .map_err(|error| AppError::internal(format!("save remote direct reservation: {error}")))?;
    Ok((reserved, draft))
}

pub(crate) async fn complete_remote_direct_binding_with_realm(
    state: &AppState,
    pair_key: &str,
    actor: &str,
    actor_device_id: &str,
    peer: &str,
    contact: &ContactRecord,
    signed_claim: &arkret_core::PeerKeyPackagesClaimRequestBody,
) -> Result<
    (
        DirectConversationBindingRecord,
        bool,
        Option<arkret_core::DirectConversationMaterializationDraft>,
    ),
    AppError,
> {
    let reserved = state
        .contact_application()
        .direct_binding(pair_key)
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                "remote direct reservation is missing",
            )
        })?;
    let context = remote_authoring_context(&reserved).ok_or_else(|| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "remote direct reservation authoring context is invalid",
        )
    })?;
    let signed_unsigned = serde_json::to_value(signed_claim.unsigned_request())
        .map_err(|error| AppError::internal(format!("signed peer claim encode: {error}")))?;
    let drafted_unsigned = serde_json::to_value(&context.claim_authorization_draft.request)
        .map_err(|error| AppError::internal(format!("drafted peer claim encode: {error}")))?;
    if arkret_core::canonical::canonical_sha256(&signed_unsigned).ok()
        != arkret_core::canonical::canonical_sha256(&drafted_unsigned).ok()
    {
        return Err(AppError::conflict(
            "peer claim request does not match the reserved authorization draft",
        )
        .with_wire_code("duplicate_conflict"));
    }
    let (claim, claim_receipt) =
        execute_remote_peer_claim(state, pair_key, &reserved, context.clone(), signed_claim)
            .await?;
    let realm_id = reserved.realm_id.clone();
    let main_strand_id = reserved.main_strand_id.clone();
    let authorization_basis = direct_authorization_basis_from_contact(contact)?;
    prepare_reserved_direct_materialization(
        state,
        pair_key,
        actor,
        actor_device_id,
        peer,
        Some(contact),
        authorization_basis,
        &realm_id,
        &main_strand_id,
        &context.actor_member_event_ref,
        &context.peer_member_event_ref,
        &context.main_strand_create_ref,
        &context.mls_group_id,
        reserved,
        claim,
        signed_claim.claim_nonce.as_str(),
        Some(claim_receipt),
    )
    .await
}

fn remote_authoring_context(
    binding: &DirectConversationBindingRecord,
) -> Option<RemoteDirectAuthoringContext> {
    serde_json::from_value(binding.authoring_context.clone()?).ok()
}

pub(crate) fn pending_direct_materialization(
    state: &AppState,
    pair_key: &str,
) -> Option<(
    DirectConversationBindingRecord,
    arkret_core::DirectConversationMaterializationDraft,
)> {
    let binding = state
        .contact_application()
        .direct_binding(pair_key)
        .filter(|binding| binding.state == "authoring_required")?;
    let draft = serde_json::from_value(binding.authoring_context.clone()?).ok()?;
    Some((binding, draft))
}

async fn execute_remote_peer_claim(
    state: &AppState,
    pair_key: &str,
    reserved: &DirectConversationBindingRecord,
    mut context: RemoteDirectAuthoringContext,
    signed_claim: &arkret_core::PeerKeyPackagesClaimRequestBody,
) -> Result<
    (
        arkret_core::KeyPackageClaimRecord,
        arkret_core::PeerKeyPackageClaimReceipt,
    ),
    AppError,
> {
    let destination_service_id = context
        .claim_authorization_draft
        .transport_binding
        .destination_service_id
        .as_str();
    let peer_url = crate::routing::federation::federation::peer_url_for_service_id(
        state,
        destination_service_id,
    )
    .ok_or_else(|| {
        direct_resolve_precondition(
            arkret_core::ErrorCode::PEER_UNRESOLVABLE,
            "direct conversation peer service is not configured",
        )
    })?;
    if context.requester_signing_key_evidence.is_none()
        && let Some(device_id) = signed_claim
            .requester_authorization
            .requester_device_id
            .as_ref()
    {
        context.requester_signing_key_evidence = Some(
            crate::jws_verify::federated_device_signing_key_evidence(
                state,
                &signed_claim.requester,
                device_id,
                signed_claim
                    .requester_authorization
                    .verification_method
                    .as_str(),
            )
            .await
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FailedPrecondition,
                    format!("requester signing key evidence unavailable: {error}"),
                )
            })?,
        );
    }
    let mut federated_claim = signed_claim.clone();
    federated_claim.requester_signing_key_evidence = context.requester_signing_key_evidence.clone();
    federated_claim.validate_shape().map_err(|error| {
        AppError::internal(format!("enriched peer claim shape invalid: {error}"))
    })?;
    let request_value = serde_json::to_value(&federated_claim)
        .map_err(|error| AppError::internal(format!("remote peer claim encode: {error}")))?;
    let request_digest = arkret_core::canonical::canonical_sha256(&request_value)
        .map_err(|error| AppError::internal(format!("remote peer claim digest: {error}")))?;

    let recovery = if context.claim_command_dispatched {
        query_remote_peer_claim(
            state,
            &peer_url,
            destination_service_id,
            &federated_claim,
            &request_digest,
        )
        .await?
    } else {
        context.claim_command_dispatched = true;
        let mut dispatched = reserved.clone();
        dispatched.authoring_context = Some(serde_json::to_value(&context).map_err(|error| {
            AppError::internal(format!("remote claim dispatch context invalid: {error}"))
        })?);
        dispatched.updated_at = now();
        state
            .contact_application()
            .save_direct_binding(pair_key, dispatched.clone())
            .await
            .map_err(|error| {
                AppError::internal(format!("persist remote claim dispatch: {error}"))
            })?;
        match send_signed_peer_json(
            state,
            &peer_url,
            destination_service_id,
            "/_arkret/peer/keys/keypackages/claim",
            &request_value,
            Some(signed_claim.claim_request_id.as_str()),
        )
        .await
        {
            Ok((status, body)) if status.is_success() => RemotePeerClaimRecovery::Claimed(
                Box::new(serde_json::from_slice(&body).map_err(|error| {
                    AppError::internal(format!("remote peer claim outcome invalid: {error}"))
                })?),
            ),
            Ok((status, _)) if status.as_u16() == 412 => {
                rollback_reserved_direct_binding(state, pair_key, reserved).await;
                return Err(direct_conversation_unavailable());
            }
            Ok(_) | Err(_) => {
                query_remote_peer_claim(
                    state,
                    &peer_url,
                    destination_service_id,
                    &federated_claim,
                    &request_digest,
                )
                .await?
            }
        }
    };
    let outcome = match recovery {
        RemotePeerClaimRecovery::Claimed(outcome) => *outcome,
        RemotePeerClaimRecovery::Unknown => {
            // The durable dispatch marker is written before network I/O. A
            // crash in that interval is recovered by querying first and only
            // then replaying the exact idempotent command when the destination
            // proves it has no reservation for this request identity.
            let (status, body) = send_signed_peer_json(
                state,
                &peer_url,
                destination_service_id,
                "/_arkret/peer/keys/keypackages/claim",
                &request_value,
                Some(federated_claim.claim_request_id.as_str()),
            )
            .await
            .map_err(|error| {
                AppError::new(
                    ErrorCode::TemporarilyUnavailable,
                    format!("remote KeyPackage claim replay unavailable: {error}"),
                )
            })?;
            if status.is_success() {
                serde_json::from_slice(&body).map_err(|error| {
                    AppError::internal(format!("remote peer claim replay outcome invalid: {error}"))
                })?
            } else if status.as_u16() == 412 {
                rollback_reserved_direct_binding(state, pair_key, reserved).await;
                return Err(direct_conversation_unavailable());
            } else {
                return Err(AppError::new(
                    ErrorCode::TemporarilyUnavailable,
                    "remote KeyPackage claim replay was not accepted",
                ));
            }
        }
        RemotePeerClaimRecovery::Pending => {
            return Err(AppError::new(
                ErrorCode::TemporarilyUnavailable,
                "remote KeyPackage claim outcome is pending",
            ));
        }
        RemotePeerClaimRecovery::Failed => {
            rollback_reserved_direct_binding(state, pair_key, reserved).await;
            return Err(direct_conversation_unavailable());
        }
    };
    verify_remote_peer_claim_outcome(
        state,
        destination_service_id,
        &federated_claim,
        &request_digest,
        outcome,
    )
    .await
}

enum RemotePeerClaimRecovery {
    Claimed(Box<arkret_core::PeerKeyPackagesClaimOutcome>),
    Unknown,
    Pending,
    Failed,
}

async fn query_remote_peer_claim(
    state: &AppState,
    peer_url: &str,
    destination_service_id: &str,
    signed_claim: &arkret_core::PeerKeyPackagesClaimRequestBody,
    request_digest: &str,
) -> Result<RemotePeerClaimRecovery, AppError> {
    let query = arkret_core::PeerKeyPackagesClaimQueryRequestBody {
        claim_request_id: signed_claim.claim_request_id.clone(),
        request_digest: arkret_core::Hash::new(request_digest.to_owned())
            .map_err(|error| AppError::internal(format!("remote claim query digest: {error}")))?,
    };
    let query_value = serde_json::to_value(query)
        .map_err(|error| AppError::internal(format!("remote claim query encode: {error}")))?;
    let (status, body) = send_signed_peer_json(
        state,
        peer_url,
        destination_service_id,
        "/_arkret/peer/keys/keypackages/claims/query",
        &query_value,
        None,
    )
    .await
    .map_err(|error| {
        AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("remote KeyPackage claim query unavailable: {error}"),
        )
    })?;
    if !status.is_success() {
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "remote KeyPackage claim query was not accepted",
        ));
    }
    let outcome: arkret_core::PeerKeyPackagesClaimQueryOutcome = serde_json::from_slice(&body)
        .map_err(|error| {
            AppError::internal(format!("remote claim query outcome invalid: {error}"))
        })?;
    outcome.validate_shape().map_err(|error| {
        AppError::internal(format!("remote claim query shape invalid: {error}"))
    })?;
    match outcome.state {
        arkret_core::PeerKeyPackagesClaimQueryState::Claimed => outcome
            .claim_outcome
            .map(Box::new)
            .map(RemotePeerClaimRecovery::Claimed)
            .ok_or_else(|| AppError::internal("claimed query outcome is missing claim_outcome")),
        arkret_core::PeerKeyPackagesClaimQueryState::ClaimFailed
        | arkret_core::PeerKeyPackagesClaimQueryState::Expired
        | arkret_core::PeerKeyPackagesClaimQueryState::Revoked => {
            Ok(RemotePeerClaimRecovery::Failed)
        }
        arkret_core::PeerKeyPackagesClaimQueryState::Unknown => {
            Ok(RemotePeerClaimRecovery::Unknown)
        }
        arkret_core::PeerKeyPackagesClaimQueryState::Pending => {
            Ok(RemotePeerClaimRecovery::Pending)
        }
    }
}

async fn verify_remote_peer_claim_outcome(
    state: &AppState,
    destination_service_id: &str,
    request: &arkret_core::PeerKeyPackagesClaimRequestBody,
    request_digest: &str,
    outcome: arkret_core::PeerKeyPackagesClaimOutcome,
) -> Result<
    (
        arkret_core::KeyPackageClaimRecord,
        arkret_core::PeerKeyPackageClaimReceipt,
    ),
    AppError,
> {
    if outcome.claim_request_id != request.claim_request_id
        || outcome.claim_receipt.claim_request_id != request.claim_request_id
        || outcome.claim_receipt.request_digest.as_str() != request_digest
        || outcome.claim_receipt.source_service_id.as_str() != state.service_id()
        || outcome.claim_receipt.destination_service_id.as_str() != destination_service_id
        || outcome.claim_receipt.request != request.unsigned_request()
        || outcome.claim_receipt.expires_at <= now()
        || outcome.claims.len() != 1
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "remote KeyPackage claim receipt binding is invalid",
        ));
    }
    let claims_value = serde_json::to_value(&outcome.claims)
        .map_err(|error| AppError::internal(format!("remote claims encode: {error}")))?;
    let claims_digest = arkret_core::canonical::canonical_sha256(&claims_value)
        .map_err(|error| AppError::internal(format!("remote claims digest: {error}")))?;
    if outcome.claim_receipt.claims_digest.as_str() != claims_digest {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "remote KeyPackage claims digest mismatch",
        ));
    }
    let expected_method = format!("{destination_service_id}#notary-key");
    if outcome.claim_receipt.signature.kid.as_str() != expected_method
        || outcome
            .claim_receipt
            .signature
            .alg
            .as_ref()
            .is_some_and(|algorithm| algorithm.as_str() != "EdDSA")
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "remote KeyPackage claim receipt signer is invalid",
        ));
    }
    let destination_did = arkret_core::Did::new(destination_service_id.to_owned())
        .map_err(|_| AppError::internal("remote service DID is invalid"))?;
    let key = crate::jws_verify::resolve_ed25519_verification_key_for_did(
        state,
        &destination_did,
        &expected_method,
    )
    .await
    .map_err(|error| {
        AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("remote service receipt key unavailable: {error}"),
        )
    })?;
    let signing_bytes =
        arkret_core::peer_keypackage_claim_receipt_signing_bytes(&outcome.claim_receipt)
            .map_err(|error| AppError::internal(format!("remote receipt transcript: {error}")))?;
    if !crate::routing::identity::cross_signing::ed25519_verify(
        &key.public_key,
        &signing_bytes,
        outcome.claim_receipt.signature.sig.as_str(),
    ) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "remote KeyPackage claim receipt signature is invalid",
        ));
    }
    let claim = outcome.claims.into_iter().next().expect("length checked");
    if claim.principal_id != request.target_principal_id
        || claim.last_resort == Some(true)
        || claim.expires_at <= now()
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "remote KeyPackage claim record is invalid",
        ));
    }
    Ok((claim, outcome.claim_receipt))
}

async fn send_signed_peer_json(
    state: &AppState,
    peer_url: &str,
    destination_service_id: &str,
    endpoint: &str,
    body: &Value,
    idempotency_key: Option<&str>,
) -> Result<(reqwest::StatusCode, Vec<u8>), String> {
    let target_url = format!("{}{}", peer_url.trim_end_matches('/'), endpoint);
    let body_bytes = arkret_core::canonical::canonical_json_bytes(body)
        .map_err(|error| format!("canonical request body: {error}"))?;
    let (parsed_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target_url,
        "peer KeyPackage claim",
        state.config().development_mode,
        std::time::Duration::from_secs(5),
    )
    .map_err(|error| error.to_string())?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    if let Some(idempotency_key) = idempotency_key {
        crate::routing::federation::outbox::insert_header_if_valid(
            &mut headers,
            "idempotency-key",
            idempotency_key,
        );
    }
    let content_digest =
        crate::routing::federation::outbox::content_digest_header_value(&body_bytes);
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "content-digest",
        &content_digest,
    );
    for (name, value) in [
        ("source-service-id", state.service_id().as_str()),
        ("destination-service-id", destination_service_id),
        ("source-trust-domain", state.config().trust_domain.as_str()),
        (
            "destination-trust-domain",
            state.config().trust_domain.as_str(),
        ),
    ] {
        crate::routing::federation::outbox::insert_header_if_valid(&mut headers, name, value);
    }
    let headers = crate::routing::federation::outbox::rfc9421_sign(
        state,
        headers,
        "POST",
        &target_url,
        &body_bytes,
    );
    let response = client
        .post(parsed_url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| error.to_string())?
        .to_vec();
    Ok((status, bytes))
}

pub(crate) async fn create_direct_binding_with_realm(
    state: &AppState,
    pair_key: &str,
    actor: &str,
    actor_device_id: &str,
    peer: &str,
    contact: Option<&ContactRecord>,
    authorization_basis: arkret_core::DirectConversationAuthorizationBasis,
) -> Result<
    (
        DirectConversationBindingRecord,
        bool,
        Option<arkret_core::DirectConversationMaterializationDraft>,
    ),
    AppError,
> {
    if let Some((binding, draft)) = pending_direct_materialization(state, pair_key) {
        return Ok((binding, false, Some(draft)));
    }
    // Reserve the canonical binding under lock so concurrent resolves for the
    // same pair collapse onto a single realm. The reservation holds the
    // generated realm/strand ids; we release the lock before the (async) event
    // submission so projection writes don't deadlock against the guard.
    let reservation = reserve_direct_binding(state, pair_key, actor, peer, None);
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

    let claim_nonce =
        URL_SAFE_NO_PAD.encode(format!("direct:{realm_id}:{mls_group_id}").as_bytes());
    prepare_reserved_direct_materialization(
        state,
        pair_key,
        actor,
        actor_device_id,
        peer,
        contact,
        authorization_basis,
        &realm_id,
        &main_strand_id,
        &actor_member_event_ref,
        &peer_member_event_ref,
        &main_strand_create_ref,
        &mls_group_id,
        reserved,
        claim,
        &claim_nonce,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn prepare_reserved_direct_materialization(
    state: &AppState,
    pair_key: &str,
    actor: &str,
    _actor_device_id: &str,
    peer: &str,
    contact: Option<&ContactRecord>,
    authorization_basis: arkret_core::DirectConversationAuthorizationBasis,
    realm_id: &str,
    main_strand_id: &str,
    actor_member_event_ref: &str,
    peer_member_event_ref: &str,
    main_strand_create_ref: &str,
    mls_group_id: &str,
    reserved: DirectConversationBindingRecord,
    claim: arkret_core::KeyPackageClaimRecord,
    claim_nonce: &str,
    claim_receipt: Option<arkret_core::PeerKeyPackageClaimReceipt>,
) -> Result<
    (
        DirectConversationBindingRecord,
        bool,
        Option<arkret_core::DirectConversationMaterializationDraft>,
    ),
    AppError,
> {
    let realm_scope = arkret_core::RealmId::new(realm_id.to_owned())
        .map_err(|error| AppError::internal(format!("direct Realm id invalid: {error}")))?;
    let realm_payload =
        direct_realm_create_payload(state, realm_scope.clone(), actor, reserved.created_at)
            .map_err(AppError::internal)?;
    let mut realm_event = unsigned_direct_materialization_event(
        state,
        actor,
        actor_member_event_ref,
        realm_id,
        arkret_core::events::EventKind::REALM_CREATE,
        realm_payload,
    )?;
    attach_create_cell_contract(&mut realm_event, "ak.component.realm.create.v1", realm_id)?;
    realm_event
        .requirements
        .critical_extensions
        .push(arkret_core::CriticalExtension {
            id: arkret_core::DIRECT_CONVERSATION_REALM_ROLE_FEATURE.to_owned(),
            extension_scope: "payload".to_owned(),
            schema_ref: None,
            profile_ref: Some(arkret_core::DIRECT_CONVERSATION_REALM_PROFILE.to_owned()),
            parameters: None,
            material_digest: None,
            evidence_ref: None,
            fail_closed: true,
        });

    let founding_grant_id = crate::ids::generate("grant");
    let founding_payload = json!({
        "grant_id": founding_grant_id,
        "grant": {
            "id": founding_grant_id,
            "schema": "ak.schema.capability.v1",
            "realm_id": realm_id,
            "issuer": actor,
            "subject": actor,
            "actions": arkret_policy::realm_bootstrap::REALM_FOUNDING_GRANT_ACTIONS,
            "capability_action_registry_digest": arkret_core::current_capability_action_registry_digest()
                .map_err(|error| AppError::internal(format!("capability registry unavailable: {error}")))?,
            "resources": [{
                "kind": "realm",
                "realm_id": realm_id,
                "match_scope": "realm_wide"
            }],
            "issued_at": reserved.created_at,
            "proofs": []
        }
    });
    let founding_grant_event = unsigned_direct_materialization_event(
        state,
        actor,
        &crate::ids::generate_event_id(),
        realm_id,
        arkret_core::events::EventKind::CAPABILITY_GRANT,
        founding_payload,
    )?;

    let member_payload = direct_member_join_operation(state, realm_scope.clone(), peer, contact)
        .map_err(AppError::internal)?
        .payload;
    let mut peer_member_event = unsigned_direct_materialization_event(
        state,
        actor,
        peer_member_event_ref,
        realm_id,
        arkret_core::events::EventKind::MEMBER_STATE,
        member_payload,
    )?;
    attach_member_join_cell_contract(&mut peer_member_event, peer)?;
    let strand_payload =
        direct_strand_create_payload(realm_scope, main_strand_id, actor, reserved.created_at)
            .map_err(AppError::internal)?;
    let mut main_strand_event = unsigned_direct_materialization_event(
        state,
        actor,
        main_strand_create_ref,
        realm_id,
        arkret_core::events::EventKind::STRAND_CREATE,
        strand_payload,
    )?;
    attach_create_cell_contract(
        &mut main_strand_event,
        "ak.component.strand.create.v1",
        main_strand_id,
    )?;

    let member_event_refs = vec![
        actor_member_event_ref.to_owned(),
        peer_member_event_ref.to_owned(),
    ];
    let mls_genesis_event_ref = crate::ids::generate_event_id();
    let mls_commit_event_ref = crate::ids::generate_event_id();
    let mls_welcome_event_ref = crate::ids::generate_event_id();
    let binding_fact = arkret_core::DirectConversationBoundPayload {
        pair_key: arkret_core::Hash::new(pair_key.to_owned())
            .map_err(|error| AppError::internal(format!("stored pair key is invalid: {error}")))?,
        participants_unordered: sorted_participants(actor, peer)
            .into_iter()
            .map(arkret_core::Did::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                AppError::internal(format!("stored direct participant is invalid: {error}"))
            })?,
        realm_id: arkret_core::RealmId::new(realm_id.to_owned())
            .map_err(|error| AppError::internal(format!("stored realm id is invalid: {error}")))?,
        main_strand_id: arkret_core::StrandId::new(main_strand_id.to_owned()).map_err(|error| {
            AppError::internal(format!("stored main strand id is invalid: {error}"))
        })?,
        authorization_basis,
        member_event_refs: member_event_refs
            .into_iter()
            .map(arkret_core::EventId::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                AppError::internal(format!("stored member event ref is invalid: {error}"))
            })?,
        main_strand_create_ref: arkret_core::EventId::new(main_strand_create_ref.to_owned())
            .map_err(|error| {
                AppError::internal(format!("stored strand event ref is invalid: {error}"))
            })?,
        mls_group_id: arkret_core::MlsGroupId::new(mls_group_id.to_owned()).map_err(|error| {
            AppError::internal(format!("stored MLS group id is invalid: {error}"))
        })?,
        mls_genesis_event_ref: arkret_core::EventId::new(mls_genesis_event_ref.clone()).map_err(
            |error| AppError::internal(format!("stored MLS genesis Event id is invalid: {error}")),
        )?,
        mls_commit_event_ref: arkret_core::EventId::new(mls_commit_event_ref.clone()).map_err(
            |error| AppError::internal(format!("stored MLS commit Event id is invalid: {error}")),
        )?,
        mls_welcome_event_ref: arkret_core::EventId::new(mls_welcome_event_ref.clone()).map_err(
            |error| AppError::internal(format!("stored MLS Welcome Event id is invalid: {error}")),
        )?,
        created_at: reserved.created_at,
        binding_state: arkret_core::DirectConversationAuthoredBindingState::Active,
        supersedes_binding_ref: None,
    };
    let trust_domain = arkret_core::TypedTrustDomainId::new(state.config().trust_domain.clone())
        .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    binding_fact
        .validate_pair_key(trust_domain)
        .map_err(|error| {
            AppError::internal(format!(
                "direct binding pair key validation failed: {error}"
            ))
        })?;
    let binding_event = unsigned_direct_binding_event(
        state,
        actor,
        &reserved.binding_event_ref,
        serde_json::to_value(binding_fact).map_err(|error| {
            AppError::internal(format!("direct binding encoding failed: {error}"))
        })?,
    )?;
    let draft = arkret_core::DirectConversationMaterializationDraft {
        materialization_id: arkret_core::NonEmptyString::new(reserved.binding_event_ref.clone())
            .map_err(|error| AppError::internal(format!("materialization id invalid: {error}")))?,
        claim_nonce: arkret_core::Base64UrlString::new(claim_nonce.to_owned())
            .map_err(|error| AppError::internal(format!("claim nonce invalid: {error}")))?,
        mls_group_id: arkret_core::MlsGroupId::new(mls_group_id.to_owned())
            .map_err(|error| AppError::internal(format!("MLS group id invalid: {error}")))?,
        mls_genesis_event_ref: arkret_core::EventId::new(mls_genesis_event_ref).map_err(
            |error| AppError::internal(format!("MLS genesis Event id invalid: {error}")),
        )?,
        mls_commit_event_ref: arkret_core::EventId::new(mls_commit_event_ref)
            .map_err(|error| AppError::internal(format!("MLS commit Event id invalid: {error}")))?,
        mls_welcome_event_ref: arkret_core::EventId::new(mls_welcome_event_ref).map_err(
            |error| AppError::internal(format!("MLS Welcome Event id invalid: {error}")),
        )?,
        expires_at: claim.expires_at,
        claimed_keypackage: claim,
        claim_receipt,
        realm_event,
        founding_grant_event,
        peer_member_event,
        main_strand_event,
        binding_event,
    };
    draft.validate_shape().map_err(|error| {
        AppError::internal(format!("direct materialization draft invalid: {error}"))
    })?;

    let mut staged = stage_reserved_direct_binding(state, pair_key, &reserved)?;
    staged.authoring_context = Some(serde_json::to_value(&draft).map_err(|error| {
        AppError::internal(format!(
            "direct materialization draft encode failed: {error}"
        ))
    })?);
    staged.updated_at = now();
    state
        .contact_application()
        .save_direct_binding(pair_key, staged.clone())
        .await
        .map_err(|error| AppError::internal(format!("save direct materialization: {error}")))?;
    publish_reserved_direct_binding(state, pair_key, &staged)?;
    Ok((staged, false, Some(draft)))
}

fn unsigned_direct_materialization_event(
    state: &AppState,
    actor: &str,
    event_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<arkret_core::Event, AppError> {
    let realm_id = arkret_core::RealmId::new(realm_id.to_owned())
        .map_err(|error| AppError::internal(format!("direct Event realm id invalid: {error}")))?;
    let actor_id = arkret_core::Did::new(actor.to_owned())
        .map_err(|error| AppError::internal(format!("direct Event actor invalid: {error}")))?;
    let hlc = arkret_core::Hlc::new(state.hlc().now())
        .map_err(|error| AppError::internal(format!("direct Event HLC invalid: {error}")))?;
    let mut event = arkret_core::Event::new(kind, realm_id, actor_id, 0, hlc, payload)
        .map_err(|error| AppError::internal(format!("direct Event draft invalid: {error}")))?;
    event.event_id = arkret_core::EventId::new(event_id.to_owned())
        .map_err(|error| AppError::internal(format!("direct Event id invalid: {error}")))?;
    Ok(event)
}

fn unsigned_direct_binding_event(
    state: &AppState,
    actor: &str,
    event_id: &str,
    payload: Value,
) -> Result<arkret_core::Event, AppError> {
    let realm_id = arkret_core::RealmId::new(
        soland_application::identity::principal_control_realm_for_did(actor),
    )
    .map_err(|error| AppError::internal(format!("direct binding PCR id invalid: {error}")))?;
    let actor_id = arkret_core::Did::new(actor.to_owned())
        .map_err(|error| AppError::internal(format!("direct binding actor invalid: {error}")))?;
    let hlc = arkret_core::Hlc::new(state.hlc().now())
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

fn direct_cell_ref(cell_family: &str, subject: &str) -> Result<arkret_core::CellRef, AppError> {
    arkret_core::CellRef::new(format!("ak:cell:{cell_family}:{subject}")).map_err(|error| {
        AppError::internal(format!("direct materialization cell invalid: {error}"))
    })
}

fn attach_create_cell_contract(
    event: &mut arkret_core::Event,
    cell_family: &str,
    subject: &str,
) -> Result<(), AppError> {
    let cell = direct_cell_ref(cell_family, subject)?;
    let value = event
        .payload
        .get("object")
        .cloned()
        .ok_or_else(|| AppError::internal("direct create payload object missing"))?;
    event.preconditions = vec![arkret_core::Precondition {
        cell: cell.clone(),
        predicate: arkret_core::Predicate {
            op: arkret_core::PredicateOp::HeadEq,
            value: Some(Value::Null),
            values: None,
            predicate_id: None,
        },
    }];
    event.effects = vec![arkret_core::Effect {
        cell,
        op: arkret_core::LatticeOp {
            op_type: arkret_core::LatticeOpType::Set,
            tag: None,
            value: Some(value),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        },
    }];
    Ok(())
}

fn attach_member_join_cell_contract(
    event: &mut arkret_core::Event,
    participant: &str,
) -> Result<(), AppError> {
    let cell = direct_cell_ref("ak.component.member.state.v1", participant)?;
    event.preconditions = vec![arkret_core::Precondition {
        cell: cell.clone(),
        predicate: arkret_core::Predicate {
            op: arkret_core::PredicateOp::HeadEq,
            value: Some(Value::Null),
            values: None,
            predicate_id: None,
        },
    }];
    event.effects = vec![arkret_core::Effect {
        cell,
        op: arkret_core::LatticeOp {
            op_type: arkret_core::LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(Value::String("leave".to_owned())),
            to: Some(Value::String("join".to_owned())),
            reason: Some("direct_conversation_bootstrap".to_owned()),
            issuer_seq: None,
        },
    }];
    Ok(())
}

fn reserve_direct_binding(
    state: &AppState,
    pair_key: &str,
    actor: &str,
    peer: &str,
    expected_event_ref: Option<&str>,
) -> DirectBindingReservation {
    if expected_event_ref.is_none()
        && let Some(existing) = state.contact_application().direct_binding(pair_key)
    {
        if existing.state == "active"
            && valid_contact_event_ref(&existing.binding_event_ref)
            && direct_binding_matches_projection(state, &existing)
        {
            return DirectBindingReservation::Existing(existing);
        }
        if matches!(existing.state.as_str(), "pending" | "authoring_required") {
            return DirectBindingReservation::Pending(existing.binding_event_ref);
        }
        return reserve_direct_binding(
            state,
            pair_key,
            actor,
            peer,
            Some(&existing.binding_event_ref),
        );
    }
    let realm_id = crate::ids::generate_realm_id();
    let main_strand_id = crate::ids::generate("strand");
    let binding_event_ref = crate::ids::generate_event_id();
    let actor_member_event_ref = crate::ids::generate_event_id();
    let peer_member_event_ref = crate::ids::generate_event_id();
    let main_strand_create_ref = crate::ids::generate_event_id();
    // Inkson's RFC 9420 group constructor uses the Realm id bytes as the
    // OpenMLS GroupId and exposes its base64url wire form. Reserve that exact
    // value so the resolver plan and the participant-created group cannot
    // diverge.
    let mls_group_id = arkret_core::base64url_encode(realm_id.as_bytes());
    let created_at = direct_now();
    let binding = DirectConversationBindingRecord {
        participants_unordered: sorted_participants(actor, peer),
        realm_id: realm_id.clone(),
        main_strand_id: main_strand_id.clone(),
        binding_event_ref,
        state: "pending".to_owned(),
        authoring_context: None,
        created_at,
        updated_at: created_at,
    };
    if let Err(current) = state
        .contact_application()
        .replace_direct_binding_if_current(pair_key, expected_event_ref, binding.clone())
    {
        return match current {
            Some(current) if current.state == "active" => {
                DirectBindingReservation::Existing(*current)
            }
            Some(current) => DirectBindingReservation::Pending(current.binding_event_ref),
            None => reserve_direct_binding(state, pair_key, actor, peer, None),
        };
    }
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
    staged.authoring_context = None;
    staged.updated_at = now();
    let still_reserved = state
        .contact_application()
        .direct_binding_is_current(pair_key, &reserved.binding_event_ref);
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
    if state
        .contact_application()
        .replace_direct_binding_if_current(
            pair_key,
            Some(&active.binding_event_ref),
            active.clone(),
        )
        .is_err()
    {
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "direct conversation binding reservation was superseded before publish",
        ));
    }
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
        Option<arkret_core::DirectConversationMaterializationDraft>,
    ),
    AppError,
> {
    for _ in 0..DIRECT_BINDING_PENDING_POLL_ATTEMPTS {
        tokio::time::sleep(std::time::Duration::from_millis(
            DIRECT_BINDING_PENDING_POLL_DELAY_MS,
        ))
        .await;
        let observed = state.contact_application().direct_binding(pair_key);
        match observed {
            Some(binding)
                if binding.binding_event_ref == binding_event_ref && binding.state == "active" =>
            {
                return Ok((binding, false, None));
            }
            Some(binding)
                if binding.binding_event_ref == binding_event_ref
                    && binding.state == "authoring_required"
                    && serde_json::from_value::<
                        arkret_core::DirectConversationMaterializationDraft,
                    >(
                        binding.authoring_context.clone().unwrap_or(Value::Null)
                    )
                    .is_ok() =>
            {
                let draft = serde_json::from_value(binding.authoring_context.clone().unwrap())
                    .map_err(|error| {
                        AppError::internal(format!(
                            "stored direct materialization draft invalid: {error}"
                        ))
                    })?;
                return Ok((binding, false, Some(draft)));
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
    let removed = state
        .contact_application()
        .remove_direct_binding_if_current(pair_key, &reserved.binding_event_ref);
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
        .ok_or_else(direct_conversation_unavailable)
}

pub(super) fn direct_conversation_unavailable() -> AppError {
    direct_resolve_precondition(
        arkret_core::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
        "direct conversation is unavailable",
    )
}

pub(super) fn sorted_participants(actor: &str, peer: &str) -> Vec<String> {
    let mut participants = vec![actor.to_owned(), peer.to_owned()];
    participants.sort();
    participants
}

/// Build + accept the DM Realm genesis operations through the canonical
/// local-operation path. Order matters: realm.create (creator becomes the
/// first member), peer member.state{join}, then the main strand.create.
#[cfg(test)]
pub(super) async fn submit_direct_realm_genesis(
    state: &AppState,
    realm_id: &str,
    main_strand_id: &str,
    actor: &str,
    peer: &str,
    contact: Option<&ContactRecord>,
) -> Result<(), &'static str> {
    let realm_scope = arkret_core::RealmId::new(realm_id.to_owned())
        .map_err(|_| "generated invalid direct conversation realm id")?;

    // ak.realm.create — DM Realm well-known shape (spec §7): mls_rfc9420
    // encryption profile, fail-closed join rule, direct-conversation
    // discriminator in `fields`. The creator is treated as a member by the
    // genesis bootstrap.
    let realm_op = direct_realm_create_operation(state, realm_scope.clone(), actor)?;
    // ak.member.state{join} — add the peer so both participants are active
    // members (active member count == 2, spec §7).
    let member_op = direct_member_join_operation(state, realm_scope.clone(), peer, contact)?;

    // ak.strand.create — main discussion Strand (spec §8): discussion track is
    // primary; no Circle scope.
    let strand_op = direct_strand_create_operation(realm_scope, main_strand_id, actor)?;
    // Submit the complete genesis as one ordered batch. Post-commit federation
    // target discovery then observes the peer's routable membership while it
    // prepares fanout for every event in the batch, including realm.create.
    crate::routing::accept_local_operations(state, actor, &[realm_op, member_op, strand_op])
        .await?;

    Ok(())
}

pub(super) fn direct_operation_id() -> Result<arkret_core::OperationId, &'static str> {
    arkret_core::OperationId::new(crate::ids::generate_operation_id())
        .map_err(|_| "generated invalid operation id")
}

pub(super) fn direct_now() -> chrono::DateTime<chrono::Utc> {
    let current = now();
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(current.timestamp_millis())
        .expect("current timestamp milliseconds are representable")
}

pub(super) fn direct_realm_create_payload(
    state: &AppState,
    realm_scope: arkret_core::RealmId,
    creator: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, &'static str> {
    let creator_did = arkret_core::Did::new(creator.to_owned())
        .map_err(|_| "invalid direct realm creator DID")?;
    let trust_domain = arkret_core::TypedTrustDomainId::new(state.config().trust_domain.clone())
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

#[cfg(test)]
pub(super) fn direct_realm_create_operation(
    state: &AppState,
    realm_scope: arkret_core::RealmId,
    creator: &str,
) -> Result<arkret_core::Operation, &'static str> {
    let created_at = direct_now();
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
    state: &AppState,
    realm_scope: arkret_core::RealmId,
    member: &str,
    contact: Option<&ContactRecord>,
) -> Result<arkret_core::Operation, &'static str> {
    let created_at = direct_now();
    let mut payload = direct_member_join_payload(realm_scope.clone(), member)?;
    if let Some(recipient_service_id) = contact
        .and_then(|contact| contact.peer_service_id.as_deref())
        .filter(|service_id| *service_id != state.service_id())
    {
        let service_acceptance_ref = contact
            .expect("remote contact branch requires contact")
            .response_event_ref
            .as_deref()
            .ok_or("remote direct membership requires contact acceptance ref")?;
        let service_endpoint = crate::routing::federation::federation::peer_url_for_service_id(
            state,
            recipient_service_id,
        )
        .ok_or("remote direct membership service endpoint is unavailable")?;
        payload["delivery_status"] = json!("routable");
        payload["delivery_binding"] = json!({
            "recipient_service_id": recipient_service_id,
            "recipient_service_type": "principal_server",
            "binding_scope": "realm",
            "binding_source": "explicit",
            "delivery_modes": ["events", "sync", "to_device", "key_packages"],
            "service_endpoint": service_endpoint,
            "resolved_at": arkret_core::canonical::format_timestamp_canonical(created_at),
            "service_acceptance_ref": service_acceptance_ref,
            "holder_proof_ref": service_acceptance_ref,
            "expires_at": arkret_core::canonical::format_timestamp_canonical(created_at + chrono::Duration::days(30))
        });
    }
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

#[cfg(test)]
pub(super) fn direct_strand_create_operation(
    realm_scope: arkret_core::RealmId,
    main_strand_id: &str,
    creator: &str,
) -> Result<arkret_core::Operation, &'static str> {
    let created_at = direct_now();
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
