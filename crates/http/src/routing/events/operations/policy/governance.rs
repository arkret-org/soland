use arkret_models_collaboration::agent_operations::AgentLifecycleState;

use super::*;

/// Action that authorizes a Realm join / membership review decision.
///
/// Kept in one place so the member-state review branches and the join
/// application surfaces cannot drift into different action sets.
pub(crate) const REALM_MEMBERSHIP_ADMIN_ACTIONS: &[&str] =
    &[arkret_wire::CapabilityActionId::REALM_ADMIN];

/// Apply the closed Direct Conversation admission table in registry order.
///
/// This is deliberately one gate rather than a collection of call-site checks:
/// the first matching reason is wire-visible, so reordering these predicates is
/// a protocol change.  The caller runs this before any reducer/projection work.
pub(super) async fn validate_direct_conversation_admission(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind_for_operation(operation);

    // 1. Binding integrity is evaluated even for the first endorsement, when
    // no settled binding exists yet.  Keep the pair-materialization conflict
    // reason distinct; every malformed/mismatched binding input is collapsed
    // to the registered binding-invalid reason.
    if kind == Some(arkret_wire::EventKind::DirectConversationBound) {
        if let Err(reason) =
            crate::routing::identity::account::validate_direct_binding_operation(state, operation)
                .await
        {
            return Err(
                if reason
                    == arkret_wire::ReasonCode::DIRECT_CONVERSATION_PAIR_MATERIALIZATION_CONFLICT
                {
                    reason
                } else {
                    arkret_wire::ReasonCode::DIRECT_CONVERSATION_BINDING_INVALID
                },
            );
        }
    }

    if !is_direct_conversation_realm(state, operation.realm_id.as_str()) {
        return Ok(());
    }

    // 2. §8.1 — DM coordinates are permanent and successor-free, so an
    // irreversible terminal is refused outright. Reversible `ak.realm.archive`
    // / `ak.realm.freeze` stay available through ordinary Realm authority and
    // only surface as resolver send blockers.
    if matches!(
        kind,
        Some(arkret_wire::EventKind::RealmTombstone | arkret_wire::EventKind::RealmDestroy)
    ) {
        return Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_TERMINAL_FORBIDDEN);
    }

    let authorization_ref = operation
        .context
        .authorization_ref
        .as_ref()
        .map(|reference| reference.as_str());
    let bootstrap_authority = authorization_ref
        == Some(arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_BOOTSTRAP_PARTICIPANT_V1);
    let raw_binding = state
        .contacts()
        .settled_direct_binding_for_realm(operation.realm_id.as_str());

    // 3. The authoritative member projection and immutable binding must name
    // the same two distinct full ActorIds.  The incoming first binding supplies
    // the expected pair; the provisional founder lane is the sole no-binding
    // exception and is independently proved by its registered authority.
    let expected_participants = if let Some(binding) = raw_binding.as_ref() {
        Some(binding.participants_unordered.clone())
    } else if kind == Some(arkret_wire::EventKind::DirectConversationBound) {
        serde_json::from_value::<
            arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
        >(operation.payload.clone())
        .ok()
        .map(|payload| {
            payload
                .unordered_participant_ids
                .into_iter()
                .map(|actor| actor.to_string())
                .collect()
        })
    } else {
        None
    };
    if !bootstrap_authority {
        let participants = expected_participants
            .as_ref()
            .ok_or(arkret_wire::ReasonCode::DIRECT_CONVERSATION_MEMBER_COUNT_INVALID)?;
        let participant_set = participants.iter().cloned().collect::<BTreeSet<_>>();
        let member_set = state
            .projections()
            .snapshot()
            .members_of_realm(operation.realm_id.as_str())
            .into_iter()
            .map(|member| member.member.clone())
            .collect::<BTreeSet<_>>();
        if participants.len() != 2 || participant_set.len() != 2 || member_set != participant_set {
            return Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_MEMBER_COUNT_INVALID);
        }
    }

    // 4. Candidate-pair membership precedes the invite-class guard.  A 3PID
    // invite is necessarily pair-external; a directed invite or join is
    // external when its full candidate ActorId is outside the immutable pair.
    let candidate = direct_conversation_candidate(operation);
    if (kind == Some(arkret_wire::EventKind::InviteThirdParty)
        || candidate.as_ref().is_some_and(|candidate| {
            expected_participants
                .as_ref()
                .is_none_or(|participants| !participants.contains(candidate))
        }))
        && matches!(
            kind,
            Some(
                arkret_wire::EventKind::InviteCreate
                    | arkret_wire::EventKind::InviteThirdParty
                    | arkret_wire::EventKind::MemberState
            )
        )
    {
        return Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_THIRD_PARTY_MEMBER_FORBIDDEN);
    }

    // 5. Founding peer membership is not an invite.  Every invite against an
    // established DM is otherwise closed here.
    if kinds::operation_is_invite(operation) {
        return Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_INVITE_FORBIDDEN);
    }

    // 6. An accepted Direct Conversation has left the founding/materializing
    // root phase.  No general owner aggregation can reopen operational,
    // governance, policy, grant, or terminal writes.
    if authorization_ref == Some(arkret_wire::REALM_AUTHORITY_ROOT_CELL) {
        return Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_ROOT_MASK_VIOLATION);
    }

    // 7. The expensive closed evaluator runs during envelope validation where
    // the accepted-Seal state is available.  This policy-stage assertion keeps
    // an unsupported participant-source action fail-closed under the same
    // non-enumerating reason.
    if authorization_ref == Some(arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_PARTICIPANT_V1)
        && !direct_conversation_participant_event_is_allowlisted(operation)
    {
        return Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_PARTICIPANT_AUTHORITY_DENIED);
    }
    if operation_is_space_container(operation) {
        return Err("direct_conversation_space_forbidden");
    }
    if kinds::canonical_kind_for_operation(operation)
        == Some(arkret_wire::EventKind::RealmHistoryAccess)
    {
        // The effective value is fixed by the Direct Conversation profile;
        // neither the founding unit nor participant/repair authority may
        // publish a mutable policy cell for this Realm role.
        return Err("capability_denied");
    }
    Ok(())
}

fn direct_conversation_candidate(operation: &Operation) -> Option<String> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_wire::EventKind::MemberState) => {
            membership_target(operation).map(|actor| actor.to_string())
        }
        Some(arkret_wire::EventKind::InviteCreate) => operation
            .payload
            .get("invitee_account_id")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_wire::AccountId>(value).ok())
            .map(arkret_wire::ActorId::account)
            .map(|actor| actor.to_string())
            // Keep the old operation fixture spelling readable while all real
            // envelopes remain closed by the typed payload schema.
            .or_else(|| {
                operation
                    .payload
                    .get("invitee_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            }),
        _ => None,
    }
}

fn direct_conversation_participant_event_is_allowlisted(operation: &Operation) -> bool {
    match kinds::canonical_kind_for_operation(operation) {
        Some(
            arkret_wire::EventKind::MessageCreate
            | arkret_wire::EventKind::MessageRedact
            | arkret_wire::EventKind::MessageRevise
            | arkret_wire::EventKind::MlsCommit
            | arkret_wire::EventKind::ReactionAdd
            | arkret_wire::EventKind::ReactionRemove
            | arkret_wire::EventKind::ReadCursorAdvance
            | arkret_wire::EventKind::StrandCreate,
        ) => true,
        Some(arkret_wire::EventKind::MemberState) => {
            operation.payload.get("membership").and_then(Value::as_str) == Some("leave")
                && membership_target(operation).as_ref() == Some(&operation.context.sender)
        }
        _ => false,
    }
}

pub(super) fn operation_is_space_container(operation: &Operation) -> bool {
    matches!(
        kinds::canonical_kind_for_operation(operation),
        Some(
            arkret_wire::EventKind::SpaceCreate
                | arkret_wire::EventKind::SpaceUpdate
                | arkret_wire::EventKind::SpaceParent
                | arkret_wire::EventKind::SpaceArchive
                | arkret_wire::EventKind::SpaceRestore
                | arkret_wire::EventKind::SpaceTombstone
        )
    )
}

pub(super) async fn validate_member_state_policy(
    state: &AppState,
    operation: &Operation,
    agent_membership_cascade: bool,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(arkret_wire::EventKind::MemberState) {
        return Ok(());
    }
    if let Some(reason) = direct_conversation_member_state_guard(state, operation) {
        return Err(reason);
    }
    let carries_cascade_cause = operation.payload.get("membership_cause").is_some()
        || operation
            .payload
            .pointer("/agent_controller_binding/controller_terminal_event_ref")
            .is_some();
    if carries_cascade_cause
        && (!agent_membership_cascade
            || operation.payload.get("membership").and_then(Value::as_str) != Some("leave")
            || operation
                .payload
                .get("membership_cause")
                .and_then(Value::as_str)
                != Some("controller_membership_ended")
            || operation
                .payload
                .pointer("/agent_controller_binding/controller_terminal_event_ref")
                .and_then(Value::as_str)
                .is_none())
    {
        return Err("agent_membership_cascade_required");
    }
    if !agent_membership_cascade
        && matches!(
            operation.payload.get("membership").and_then(Value::as_str),
            Some("leave" | "ban")
        )
        && controller_has_bound_agent_memberships(state, operation)
    {
        return Err("agent_membership_cascade_required");
    }
    if operation.payload.get("membership").and_then(Value::as_str) == Some("join") {
        let target = membership_target(operation);
        if let Some(ref member) = target
            && crate::routing::organizations::organization_policy_blocks_join(
                state,
                operation.realm_id.as_str(),
                member,
            )
            .await
        {
            return Err("organization_policy_denied");
        }
        let actor = &operation.context.sender;
        let Some(target) = target else {
            return Err("invalid_membership_target");
        };
        if actor == &target {
            return Ok(());
        }
        if let Some(agent) = agent_controlled_by_record(state, &target, actor).await {
            match agent.state {
                AgentLifecycleState::Active => {}
                AgentLifecycleState::Paused => return Err("agent_paused"),
                AgentLifecycleState::Deactivated => return Err("agent_deactivated"),
            }
            if !realm_member_is_joined(state, operation.realm_id.as_str(), actor).await {
                return Err("not_member");
            }
            let binding = operation
                .payload
                .get("agent_controller_binding")
                .cloned()
                .and_then(|value| {
                    serde_json::from_value::<
                        arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding,
                    >(value)
                    .ok()
                })
                .ok_or("agent_controller_binding_missing")?;
            let projection = state.projections().snapshot();
            let actor_key = actor.to_string();
            let current_controller = projection
                .member(operation.realm_id.as_str(), &actor_key)
                .ok_or("not_member")?;
            let current_authority = arkret_wire::AccountId::new(
                actor.signing_principal_id().clone(),
                actor.route_service_id().clone(),
            );
            if binding.controller_account_id != current_authority
                || binding.controller_account_id.principal_id != *actor.signing_principal_id()
                || current_controller.membership_event_ref.as_deref()
                    != Some(binding.controller_membership_generation_ref.as_str())
                || binding.controller_terminal_event_ref.is_some()
                || operation.payload.get("membership_cause").is_some()
            {
                return Err("agent_controller_binding_invalid");
            }
            drop(projection);
            if !has_active_accountability_grant(state, &target, actor).await {
                return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
            }
            if realm_requires_content_encryption(state, operation.realm_id.as_str()).await
                && !crate::routing::mls::has_claimable_realm_membership_keypackage(
                    state,
                    target.signing_principal_id().as_str(),
                    operation.realm_id.as_str(),
                )
                .await
            {
                return Err(soland_services::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND);
            }
            return Ok(());
        }
        let realm_id = operation.realm_id.as_str();
        if actor_governs_realm(
            state,
            realm_id,
            actor,
            REALM_MEMBERSHIP_ADMIN_ACTIONS,
            operation.created_at,
        )
        .await
        {
            return Ok(());
        }
        return Err("missing_capability");
    }
    if operation.payload.get("membership").and_then(Value::as_str) == Some("leave") {
        let actor = &operation.context.sender;
        let Some(target) = membership_target(operation) else {
            return Err("invalid_membership_target");
        };
        if actor == &target || agent_controlled_by(state, &target, actor, false).await {
            return Ok(());
        }
        let realm_id = operation.realm_id.as_str();
        if actor_governs_realm(
            state,
            realm_id,
            actor,
            REALM_MEMBERSHIP_ADMIN_ACTIONS,
            operation.created_at,
        )
        .await
        {
            return Ok(());
        }
        return Err("missing_capability");
    }
    if operation.payload.get("membership").and_then(Value::as_str) != Some("ban") {
        return Ok(());
    }
    let actor = &operation.context.sender;
    // capabilities.md section 16 - `ak.realm.admin` governs `ak.member.state`
    // writes, and section 3.2 lets the Realm owner aggregate stand in for it.
    // Both legs are resolved by the shared governance predicate; the
    // discardable `realm_states[..].owner` mirror is never an allow.
    let realm_id = operation.realm_id.as_str();
    if actor_governs_realm(
        state,
        realm_id,
        actor,
        &[arkret_wire::CapabilityActionId::REALM_ADMIN],
        operation.created_at,
    )
    .await
    {
        return Ok(());
    }
    Err("missing_capability")
}

fn controller_has_bound_agent_memberships(state: &AppState, operation: &Operation) -> bool {
    let Some(controller_actor_id) = membership_target(operation) else {
        return false;
    };
    let projection = state.projections().snapshot();
    let controller_key = controller_actor_id.to_string();
    let Some(controller) = projection.member(operation.realm_id.as_str(), &controller_key) else {
        return false;
    };
    let Some(generation) = controller.membership_event_ref.as_deref() else {
        return false;
    };
    let authority = arkret_wire::AccountId::new(
        controller_actor_id.signing_principal_id().clone(),
        controller_actor_id.route_service_id().clone(),
    );
    projection
        .agent_membership_bindings
        .iter()
        .any(|((realm_id, agent_id), binding)| {
            realm_id == operation.realm_id.as_str()
                && binding.controller_account_id == authority
                && binding.controller_membership_generation_ref.as_str() == generation
                && projection.effective_agent_membership_base(realm_id, agent_id)
        })
}

async fn agent_controlled_by_record(
    state: &AppState,
    agent_id: &arkret_wire::ActorId,
    controller_actor_id: &arkret_wire::ActorId,
) -> Option<soland_services::identity::AgentPairingState> {
    state
        .agent_pairings()
        .agent(agent_id.signing_principal_id().as_str())
        .await
        .ok()
        .flatten()
        .filter(|record| {
            record.controller_principal_id == controller_actor_id.signing_principal_id().as_str()
        })
}

async fn realm_member_is_joined(
    state: &AppState,
    realm_id: &str,
    actor_id: &arkret_wire::ActorId,
) -> bool {
    let actor_key = actor_id.to_string();
    if state
        .projections()
        .snapshot()
        .member(realm_id, &actor_key)
        .is_some_and(|member| member.state == "join")
    {
        return true;
    }
    crate::routing::spaces::space::realm_has_member_by_id(state, realm_id, &actor_key).await
}

async fn has_active_accountability_grant(
    state: &AppState,
    agent_id: &arkret_wire::ActorId,
    controller_actor_id: &arkret_wire::ActorId,
) -> bool {
    let now = chrono::Utc::now();
    state
        .event_queries()
        .accepted_events()
        .await
        .unwrap_or_default()
        .iter()
        .any(|record| {
            record.kind == arkret_wire::event_kind_str::IDENTITY_ACCOUNTABILITY_GRANT
                && record
                    .envelope
                    .get("executed_by")
                    .or_else(|| record.envelope.get("actor_id"))
                    .and_then(|value| {
                        serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok()
                    })
                    .as_ref()
                    == Some(controller_actor_id)
                && accountability_grant_value_active_for(
                    record.envelope.get("payload").unwrap_or(&record.envelope),
                    controller_actor_id.signing_principal_id().as_str(),
                    agent_id.signing_principal_id().as_str(),
                    now,
                )
        })
}

async fn agent_controlled_by(
    state: &AppState,
    agent_id: &arkret_wire::ActorId,
    controller_actor_id: &arkret_wire::ActorId,
    require_active: bool,
) -> bool {
    let Ok(Some(record)) = state
        .agent_pairings()
        .agent(agent_id.signing_principal_id().as_str())
        .await
    else {
        return false;
    };
    record.controller_principal_id == controller_actor_id.signing_principal_id().as_str()
        && (!require_active || record.state == AgentLifecycleState::Active)
}

/// COT-06-004 — capability gate for `ak.realm.set_default_strand`. Mirrors the
/// ban / moderation gates: the actor MUST hold `ak.realm.set_default_strand`
/// (or the broader `ak.realm.admin`) on it.
/// fail-closed `missing_capability` otherwise.
pub(super) async fn validate_set_default_strand_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::RealmSetDefaultStrand)
    {
        return Ok(());
    }
    let actor = &operation.context.sender;
    let realm_id = operation.realm_id.as_str();
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(realm_id, actor, operation.created_at)
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    // A grant of either the precise action or the broad realm-admin action
    // authorizes the write. `ak.realm.admin` aggregates Realm governance, so
    // an admin holder need not also hold the narrow set_default_strand action.
    for action in [
        arkret_wire::CapabilityActionId::REALM_SET_DEFAULT_STRAND,
        arkret_wire::CapabilityActionId::REALM_ADMIN,
    ] {
        if state
            .authorization()
            .check(soland_services::authorization::AuthorizationCheck {
                actor,
                action,
                resource: realm_id,
                realm_id,
                owner: owner.as_deref(),
                members: &members,
                resource_facets: &[],
            })
            .allowed
        {
            return Ok(());
        }
    }
    Err("missing_capability")
}

/// SOL-ORG-07 (model C) — verify the organization-side proof signature against
/// the organization's OWN DID document.
///
/// The signing key MUST be a verification method controlled by `organization_id`
/// (`authorization.verification_method`); soland resolves that document from its
/// own DID store and verifies the detached Ed25519 signature over the
/// SDK-canonical statement transcript
/// ([`arkret_models_collaboration::realm_organization_statement_signing_bytes`]). This is
/// the cryptographic anchor that makes "organization consent" unforgeable: only
/// a holder of the organization's own DID key can produce an accepted statement,
/// and no external party (not even a Realm admin) can forge it.
pub(super) async fn verify_realm_organization_proof_signature(
    state: &AppState,
    payload: &arkret_models_collaboration::RealmOrganizationPayload,
) -> Result<(), &'static str> {
    use base64::Engine as _;

    let proof_b64 = match &payload.authorization.proof {
        arkret_models_collaboration::SignatureMaterial::NonEmptyString(value) => value.as_str(),
        arkret_models_collaboration::SignatureMaterial::Variant1(_) => {
            return Err("organization_statement_unverified");
        }
    };
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(proof_b64.trim())
        .map_err(|_| "organization_statement_unverified")?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| "organization_statement_unverified")?;

    // Resolves the key from the organization's own DID document AND enforces
    // verification-method controller == organization_id (the security anchor).
    let signer_did = arkret_identity::verification_method_did(
        payload.authorization.verification_method.as_str(),
    )
    .map_err(|_| "organization_statement_unverified")?;
    let signer_core_id = arkret_wire::project_did_to_core_id(&signer_did)
        .map_err(|_| "organization_statement_unverified")?;
    if signer_core_id != payload.organization_id {
        return Err("organization_statement_unverified");
    }
    let resolved = crate::jws_verify::resolve_ed25519_verification_key_for_did(
        state,
        &signer_did,
        payload.authorization.verification_method.as_str(),
    )
    .await
    .map_err(|_| "organization_statement_unverified")?;

    let signing_bytes =
        arkret_models_collaboration::realm_organization_statement_signing_bytes(payload)
            .map_err(|_| "organization_statement_unverified")?;
    resolved
        .public_key
        .verify_strict(&signing_bytes, &signature)
        .map_err(|_| "organization_statement_unverified")
}

/// SOL-ORG-03 — two-sided authorization gate for `ak.realm.organization`.
///
///   - **Realm side**: the actor admitting the statement into Realm history MUST hold
///     `ak.realm.admin` on it. A plain OIDC human session only proves the executor's identity; it
///     does not by itself create organization principal control, so the executor still needs the
///     Realm-admin capability. fail-closed `missing_capability` otherwise.
///   - **Organization side**: the statement MUST pass the SDK fail-closed verifier. Delegated
///     issuer roles (`governance_service` / `account_authority`) require a `delegation_ref`;
///     without a runtime delegation resolver wired at this layer they are rejected here
///     (`NoDelegationResolver`), so a Realm admin alone cannot forge organization consent.
pub(super) async fn validate_realm_organization_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::RealmOrganization)
    {
        return Ok(());
    }
    // Organization side — strong-typed parse + SDK verifier (fail-closed).
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::RealmOrganization>()
        .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
    arkret_policy::verify_realm_organization_statement(
        &payload,
        &operation.realm_id,
        chrono::Utc::now(),
        &arkret_policy::NoDelegationResolver,
    )
    .map_err(|_| "organization_statement_unverified")?;

    // Cryptographic organization-side proof verification (model C): the proof
    // MUST be a real detached signature by a verification method in the
    // organization's OWN DID document, which soland (the DID server) hosts and
    // resolves. Skipped in development_mode — consistent with jws_verify's
    // dev/prod split — where statements ride placeholder proofs.
    if !state.config().development_mode {
        verify_realm_organization_proof_signature(state, &payload).await?;
    }

    // Realm side — explicit `ak.realm.admin`. The executor identity comes from
    // the envelope sender / authorization.executed_by; a bare OIDC session is
    // not sufficient on its own.
    let actor = &operation.context.sender;
    let realm_id = operation.realm_id.as_str();
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(realm_id, actor, operation.created_at)
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            action: arkret_wire::CapabilityActionId::REALM_ADMIN,
            resource: realm_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
    {
        return Ok(());
    }
    Err("missing_capability")
}

/// Organization moderation policy authorship is narrower than the generic
/// `ak.policy.manage` capability gate. The semantic author is the Organization
/// service actor named by `payload.organization_id`. A delegated governance
/// service may execute and sign for that author only through the Event's
/// explicit authorization reference, which is verified by the shared
/// capability path.
pub(super) fn validate_organization_moderation_policy_authority(
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::OrganizationModerationPolicy)
    {
        return Ok(());
    }
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::OrganizationModerationPolicy>()
        .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
    if !matches!(
        operation.context.sender,
        arkret_wire::ActorId::Service { .. }
    ) || operation.context.sender.signing_principal_id() != &payload.organization_id
    {
        return Err("organization_policy_author_mismatch");
    }
    if let Some(executor) = operation.context.executed_by.as_ref()
        && (!matches!(executor, arkret_wire::ActorId::Service { .. })
            || operation.context.authorization_ref.is_none())
    {
        return Err("organization_policy_executor_unauthorized");
    }
    Ok(())
}

/// P2 — capability gate for the moderation control-plane events ingested at
/// `/_arkret/self/events` (content-moderation.md §2.6; capability-
/// action-registry.json). Mirrors [`validate_member_state_policy`]'s ban
/// gate: the actor MUST hold the matching moderation capability action on the
/// Realm. Realm ownership alone is not a capability; fail closed with
/// `missing_capability` otherwise.
///
/// Action mapping (capability-action-registry.json):
/// - `ak.moderation.decision`            → governance policy action or narrow decision action
/// - `ak.moderation.decision.lift`       → governance policy action or narrow lift action
pub(super) async fn validate_moderation_event_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    let actions = match &kind {
        arkret_wire::EventKind::ModerationDecision => &[
            arkret_wire::CapabilityActionId::POLICY_MANAGE,
            arkret_wire::CapabilityActionId::MODERATION_DECISION,
        ][..],
        arkret_wire::EventKind::ModerationDecisionLift => &[
            arkret_wire::CapabilityActionId::POLICY_MANAGE,
            arkret_wire::CapabilityActionId::MODERATION_DECISION_LIFT,
        ][..],
        _ => return Ok(()),
    };

    // Peer/service-originated federation operations predate a typed actor
    // envelope; they stay accepted so convergence/backfill keep working
    // (mirrors the ban gate). Direct client submits always carry an actor.
    let Some(actor) = moderation_actor(operation, &kind)? else {
        return Ok(());
    };

    let realm_id = operation.realm_id.as_str();
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(realm_id, actor, operation.created_at)
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if actions.iter().any(|action| {
        state
            .authorization()
            .check(soland_services::authorization::AuthorizationCheck {
                actor,
                action,
                resource: realm_id,
                realm_id,
                owner: owner.as_deref(),
                members: &members,
                resource_facets: &[],
            })
            .allowed
    }) {
        return Ok(());
    }
    Err("missing_capability")
}

pub(super) async fn validate_call_recording_start_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::CallRecordingStart {
        return Ok(());
    }
    let payload = call_recording_start_payload(operation)?;
    let action = call_recording_start_required_action(&payload);
    let actor = &operation.context.sender;
    let realm_id = operation.realm_id.as_str();
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(realm_id, actor, operation.created_at)
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            action,
            resource: realm_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
    {
        return Ok(());
    }
    if action == arkret_wire::CapabilityActionId::CALL_TRANSCRIBE {
        Err(arkret_wire::ReasonCode::TRANSCRIPTION_DENIED)
    } else {
        Err("missing_capability")
    }
}

fn call_recording_start_payload(
    operation: &Operation,
) -> Result<
    arkret_models_collaboration::events_payloads::call::CallRecordingStartPayload,
    &'static str,
> {
    operation
        .typed_payload::<arkret_wire::event_spec::CallRecordingStart>()
        .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
}

pub(super) fn call_recording_start_required_action(
    payload: &arkret_models_collaboration::events_payloads::call::CallRecordingStartPayload,
) -> &'static str {
    match payload.capture_kind {
        arkret_models_collaboration::events_payloads::call::RecordingCaptureKind::Transcript => {
            arkret_wire::CapabilityActionId::CALL_TRANSCRIBE
        }
        arkret_models_collaboration::events_payloads::call::RecordingCaptureKind::Recording => {
            arkret_wire::CapabilityActionId::CALL_RECORD
        }
    }
}

/// Extract the authoring actor for a moderation event from the spec field for
/// that kind. The projection adapter injects envelope.actor_id into
/// payload.sender; when both sender and the kind-specific actor are present
/// they must match so a privileged sender cannot spoof the decision issuer.
pub(super) fn moderation_actor<'a>(
    operation: &'a Operation,
    kind: &arkret_wire::EventKind,
) -> Result<Option<&'a arkret_wire::ActorId>, &'static str> {
    let actor_principal = match kind {
        arkret_wire::EventKind::ModerationDecision => operation
            .payload
            .get("issuer_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_decision_issuer_missing")?,
        arkret_wire::EventKind::ModerationDecisionLift => {
            return Ok(Some(&operation.context.sender));
        }
        _ => return Ok(None),
    };
    if operation.context.sender.signing_principal_id().as_str() != actor_principal {
        return Err("moderation_actor_mismatch");
    }
    Ok(Some(&operation.context.sender))
}

pub(super) fn direct_conversation_member_state_guard(
    state: &AppState,
    operation: &Operation,
) -> Option<&'static str> {
    let membership = operation
        .payload
        .get("membership")
        .and_then(Value::as_str)?;
    if !is_direct_conversation_realm(state, operation.realm_id.as_str()) {
        return None;
    }
    // A DM Realm with no settled binding yet is the founding window: §6.1's
    // four-Event atomic unit carries both explicit `ak.member.state{join}` Events before
    // any `ak.direct_conversation.bound` exists, and §6.2 already pins the
    // membership shape for that unit. The bootstrap join is admitted on that
    // reason alone; anything else that adds a member without a binding is not.
    let Some(binding) = state
        .contacts()
        .settled_direct_binding_for_realm(operation.realm_id.as_str())
    else {
        if membership == "join"
            && operation.payload.get("reason").and_then(Value::as_str)
                == Some("direct_conversation_bootstrap")
        {
            return None;
        }
        return (membership == "join").then_some("direct_conversation_member_count_invalid");
    };
    if binding.participants_unordered.len() != 2 {
        return Some("direct_conversation_member_count_invalid");
    }
    if membership != "join" {
        return None;
    }
    let target = membership_target(operation)?;
    if binding
        .participants_unordered
        .iter()
        .any(|participant| participant == &target.to_string())
    {
        None
    } else {
        Some("direct_conversation_third_party_member_forbidden")
    }
}

pub(in crate::routing::events::operations) fn is_direct_conversation_realm(
    state: &AppState,
    realm_id: &str,
) -> bool {
    state
        .projections()
        .snapshot()
        .realm_is_direct_conversation(realm_id)
}

pub(super) fn active_direct_conversation_binding_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Option<soland_services::identity::DirectConversationBindingRecord> {
    let binding = state
        .contacts()
        .settled_direct_binding_for_realm(realm_id)?;
    crate::routing::identity::account::direct_binding_matches_projection(state, &binding)
        .then_some(binding)
}

#[cfg(test)]
mod organization_moderation_policy_tests {
    use super::*;

    fn policy_operation() -> Operation {
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            arkret_identifiers::RealmId::new(
                "ak:realm:AabIzZyp4D-JzV77DNQ7bIKd7oGAuDD9keT1CyIv6SC6",
            )
            .unwrap(),
            arkret_wire::EventKind::OrganizationModerationPolicy.as_str(),
            serde_json::json!({
                "organization_id": "ak:did_core:web:organization.example",
                "value": {
                    "policy_id": "ak:policy:0198f1a2-4c3d-7e56-8a90-1b2c3d4e5f60",
                    "policy_scope": {"applies_to_owned_realms": true},
                    "rules": [{
                        "target": {
                            "kind": "service",
                            "service_id": "ak:did_core:web:blocked.example"
                        },
                        "action": "deny_federation"
                    }]
                }
            }),
        );
        operation.context.sender = arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new("ak:did_core:web:organization.example").unwrap(),
        );
        operation
    }

    #[test]
    fn policy_subject_must_be_the_organization_service_actor() {
        let mut operation = policy_operation();
        assert_eq!(
            validate_organization_moderation_policy_authority(&operation),
            Ok(())
        );
        operation.context.sender = arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        );
        assert_eq!(
            validate_organization_moderation_policy_authority(&operation),
            Err("organization_policy_author_mismatch")
        );
    }

    #[test]
    fn delegated_policy_executor_requires_a_service_and_authorization_ref() {
        let mut operation = policy_operation();
        operation.context.executed_by = Some(arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new("ak:did_core:web:governance.example").unwrap(),
        ));
        assert_eq!(
            validate_organization_moderation_policy_authority(&operation),
            Err("organization_policy_executor_unauthorized")
        );
        operation.context.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new(
                "ak:grant:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM",
            )
            .unwrap(),
        );
        assert_eq!(
            validate_organization_moderation_policy_authority(&operation),
            Ok(())
        );
    }
}
