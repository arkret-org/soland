use arkret_models_collaboration::agent_operations::AgentLifecycleState;

use super::*;

/// Capability the direct-conversation KeyPackage claim requires. MUST be a
/// value producers actually publish: the canonical SDK KeyPackage capability
/// set is `["mimi.content.v1", "ak.content.v1"]`
/// (`ARKRET_MLS_KEY_PACKAGE_CAPABILITIES`; encryption-and-audit.md §2.6
/// requires `required ⊆ claimed`). Requiring a token outside that set — the
/// previous `ak.mls.rfc9420`, which only ever appeared in local test
/// fixtures — made every real direct-conversation claim fail closed as
/// `mls_keypackage_not_found`.
pub(crate) const DIRECT_CONVERSATION_REQUIRED_CAPABILITY: &str = "ak.content.v1";

pub(crate) fn direct_authorization_basis_from_contact(
    contact: &ContactRecord,
) -> Result<
    arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis,
    AppError,
> {
    let event_refs = contact_fact_refs(contact)
        .into_iter()
        .map(arkret_identifiers::EventId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AppError::internal(format!("stored contact event ref is invalid: {error}"))
        })?;
    let basis = arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis::accepted_contact(event_refs);
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
        .identities()
        .find_account_by_actor(soland_services::identity::FindAccountByActorQuery {
            actor_id: peer.to_owned(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if account.is_none() {
        let managed_agent =
            state.agent_pairings().agent(peer).await.map_err(|error| {
                AppError::internal(format!("managed Agent lookup failed: {error}"))
            })?;
        if let Some(record) = managed_agent
            && record.state == AgentLifecycleState::Active
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
            arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
            "direct conversation peer is not resolvable on this Principal Server",
        ));
    }
    let peer_did = Did::new(peer.to_owned()).map_err(|_| {
        direct_resolve_precondition(
            arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
            "direct conversation peer DID is invalid",
        )
    })?;
    let has_cross_signing_control = state
        .identities()
        .current_cross_signing(&peer_did)
        .is_some();
    if !has_cross_signing_control {
        return Err(direct_resolve_precondition(
            arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
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

    if payload.binding_state == arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthoredBindingState::Retired {
        let supersedes = payload
            .supersedes_binding_ref
            .as_ref()
            .ok_or("direct_conversation_binding_invalid")?;
        let current = state
            .contacts()
            .direct_binding(payload.pair_key.as_str())
            .ok_or("direct_conversation_binding_invalid")?;
        return (current.binding_event_ref == supersedes.as_str())
            .then_some(())
            .ok_or("direct_conversation_binding_invalid");
    }

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

async fn validate_direct_binding_event_refs(
    state: &AppState,
    payload: &arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
) -> Result<(), &'static str> {
    if payload.member_event_refs.len() != 2 {
        return Err("member_ref_count");
    }
    let mut realm_create_ref = None;
    let mut peer_member_ref = None;
    for event_id in &payload.member_event_refs {
        let accepted = state
            .event_queries()
            .accepted_event(event_id.as_str())
            .await
            .map_err(|_| "direct_conversation_binding_invalid")?
            .ok_or("direct_conversation_binding_invalid")?;
        match accepted.kind.as_str() {
            arkret_wire::EventKind::REALM_CREATE if realm_create_ref.is_none() => {
                realm_create_ref = Some(event_id)
            }
            arkret_wire::EventKind::MEMBER_STATE if peer_member_ref.is_none() => {
                peer_member_ref = Some(event_id)
            }
            _ => return Err("member_ref_kind"),
        }
    }
    let realm_create_ref = realm_create_ref.ok_or("direct_conversation_binding_invalid")?;
    let peer_member_ref = peer_member_ref.ok_or("direct_conversation_binding_invalid")?;
    let realm_create = accepted_direct_event(
        state,
        realm_create_ref,
        &payload.realm_id,
        arkret_wire::EventKind::REALM_CREATE,
    )
    .await?;
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
    if !payload
        .participants_unordered
        .iter()
        .any(|participant| participant.as_str() == creator)
    {
        return Err("creator_participant");
    }
    let peer_member = accepted_direct_event(
        state,
        peer_member_ref,
        &payload.realm_id,
        arkret_wire::EventKind::MEMBER_STATE,
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
        return Err("peer_member");
    }

    match payload.authorization_basis.kind {
        arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AcceptedContact => {
            // Contact request/accept facts are principal-scoped projection
            // facts, including facts delivered across federation. Their exact
            // kinds and refs are validated against the accepted ContactRecord
            // by the caller; they are not Realm canonical-event rows.
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
                arkret_wire::EventKind::IDENTITY_ACCOUNTABILITY_GRANT.to_owned(),
                arkret_wire::EventKind::AGENT_SELECTOR_CLAIM.to_owned(),
                arkret_wire::EventKind::AGENT_KEY_AUTHORIZE.to_owned(),
            ]);
            if payload.authorization_basis.event_refs.len() != 3 || authorization_kinds != expected
            {
                return Err("managed_agent_authorization_refs");
            }
            let record = state
                .agent_pairings()
                .agent(peer)
                .await
                .map_err(|_| "direct_conversation_binding_invalid")?
                .ok_or("direct_conversation_binding_invalid")?;
            if record.controller_id != creator || record.state != AgentLifecycleState::Active {
                return Err("managed_agent_record");
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

    let strand = accepted_direct_event(
        state,
        &payload.main_strand_create_ref,
        &payload.realm_id,
        arkret_wire::EventKind::STRAND_CREATE,
    )
    .await?;
    if strand
        .payload
        .get("object")
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        != Some(payload.main_strand_id.as_str())
    {
        return Err("main_strand");
    }

    let genesis = accepted_direct_event(
        state,
        &payload.mls_genesis_event_ref,
        &payload.realm_id,
        arkret_wire::EventKind::MLS_GENESIS,
    )
    .await?;
    let commit = accepted_direct_event(
        state,
        &payload.mls_commit_event_ref,
        &payload.realm_id,
        arkret_wire::EventKind::MLS_COMMIT,
    )
    .await?;
    let welcome = accepted_direct_event(
        state,
        &payload.mls_welcome_event_ref,
        &payload.realm_id,
        arkret_wire::EventKind::MLS_WELCOME,
    )
    .await?;
    let group_matches = |event: &arkret_wire::Event| {
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
        return Err("mls_event_links");
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
        return Err("welcome_recipient");
    }
    let typed_welcome =
        serde_json::from_value::<arkret_models_collaboration::events_payloads::MlsWelcomePayload>(
            serde_json::to_value(&welcome.payload)
                .map_err(|_| "direct_conversation_binding_invalid")?,
        )
        .map_err(|_| "direct_conversation_binding_invalid")?;
    if let Some(receipt) = typed_welcome.peer_claim_receipt.as_ref() {
        let request = &receipt.request;
        if request.claim_purpose
            != arkret_models_crypto::http_bodies::PeerKeyPackageClaimPurpose::DirectConversation
            || request.requester.as_str() != creator
            || request.target_principal_id.as_str() != recipient
            || request.intended_realm_id != payload.realm_id
            || request.mls_group_id.as_str() != payload.mls_group_id.as_str()
            || request.strand_id.as_ref() != Some(&payload.main_strand_id)
            || request.pair_key.as_ref() != Some(&payload.pair_key)
            || request.last_resort_allowed == Some(true)
        {
            return Err("peer_claim_receipt");
        }
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
    if payload.binding_state == arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthoredBindingState::Retired {
        let retired = payload
            .supersedes_binding_ref
            .as_ref()
            .and_then(|supersedes| {
                state
                    .contacts()
                    .retire_direct_binding_if_current(&pair_key, supersedes.as_str(), now())
            });
        if let Some(binding) = retired
            && let Err(error) = state
                .contacts()
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
        return;
    }
}
