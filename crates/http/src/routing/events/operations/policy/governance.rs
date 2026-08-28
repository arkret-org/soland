use arkret_models_collaboration::agent_operations::AgentLifecycleState;

use super::*;

/// Action that authorizes a Realm join / membership review decision.
///
/// Kept in one place so the member-state review branches and the join
/// application surfaces cannot drift into different action sets.
pub(crate) const REALM_MEMBERSHIP_ADMIN_ACTIONS: &[&str] =
    &[arkret_wire::CapabilityActionId::REALM_ADMIN];

pub(super) fn validate_direct_conversation_realm_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !is_direct_conversation_realm(state, operation.realm_id.as_str()) {
        return Ok(());
    }
    // §8.1 — DM coordinates are permanent and successor-free, so an
    // irreversible terminal is refused outright. Reversible `ak.realm.archive`
    // / `ak.realm.freeze` stay available through ordinary Realm authority and
    // only surface as resolver send blockers.
    if matches!(
        kinds::canonical_kind(operation),
        arkret_wire::EventKind::RealmTombstone | arkret_wire::EventKind::RealmDestroy
    ) {
        return Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_TERMINAL_FORBIDDEN);
    }
    let binding = active_direct_conversation_binding_for_realm(state, operation.realm_id.as_str());
    if kinds::operation_is_message_create(operation) && binding.is_none() {
        return Err("direct_conversation_member_count_invalid");
    }
    if kinds::operation_is_invite(operation) {
        return Err("direct_conversation_invite_forbidden");
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
        if let Some(member) = target
            && crate::routing::organizations::organization_policy_blocks_join(
                state,
                operation.realm_id.as_str(),
                member,
            )
            .await
        {
            return Err("organization_policy_denied");
        }
        let actor = operation.context.sender.as_str();
        let Some(target) = target else {
            return Err("invalid_membership_target");
        };
        if actor == target {
            return Ok(());
        }
        if let Some(agent) = native_agent_controlled_by_record(state, target, actor).await {
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
            let current_controller = projection
                .member(operation.realm_id.as_str(), actor)
                .ok_or("not_member")?;
            let current_authority = projection
                .membership_authority(operation.realm_id.as_str(), actor)
                .ok_or("agent_controller_binding_invalid")?;
            if binding.controller_authority != *current_authority
                || binding.controller_authority.principal_id.as_str() != actor
                || current_controller.membership_event_ref.as_deref()
                    != Some(binding.controller_membership_generation_ref.as_str())
                || binding.controller_terminal_event_ref.is_some()
                || operation.payload.get("membership_cause").is_some()
            {
                return Err("agent_controller_binding_invalid");
            }
            drop(projection);
            if !has_active_accountability_grant(state, target, actor).await {
                return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
            }
            if realm_requires_content_encryption(state, operation.realm_id.as_str()).await
                && !crate::routing::mls::has_claimable_realm_membership_keypackage(
                    state,
                    target,
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
            Some(operation.context.principal_server_id.as_str()),
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
        let actor = operation.context.sender.as_str();
        let Some(target) = membership_target(operation) else {
            return Err("invalid_membership_target");
        };
        if actor == target || native_agent_controlled_by(state, target, actor, false).await {
            return Ok(());
        }
        let realm_id = operation.realm_id.as_str();
        if actor_governs_realm(
            state,
            realm_id,
            actor,
            Some(operation.context.principal_server_id.as_str()),
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
    let actor = operation.context.sender.as_str();
    // capabilities.md section 16 - `ak.realm.admin` governs `ak.member.state`
    // writes, and section 3.2 lets the Realm owner aggregate stand in for it.
    // Both legs are resolved by the shared governance predicate; the
    // discardable `realm_states[..].owner` mirror is never an allow.
    let realm_id = operation.realm_id.as_str();
    if actor_governs_realm(
        state,
        realm_id,
        actor,
        Some(operation.context.principal_server_id.as_str()),
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
    let Some(controller_id) = membership_target(operation) else {
        return false;
    };
    let projection = state.projections().snapshot();
    let Some(controller) = projection.member(operation.realm_id.as_str(), controller_id) else {
        return false;
    };
    let Some(generation) = controller.membership_event_ref.as_deref() else {
        return false;
    };
    let Some(authority) =
        projection.membership_authority(operation.realm_id.as_str(), controller_id)
    else {
        return false;
    };
    projection
        .agent_membership_bindings
        .iter()
        .any(|((realm_id, agent_id), binding)| {
            realm_id == operation.realm_id.as_str()
                && binding.controller_authority == *authority
                && binding.controller_membership_generation_ref.as_str() == generation
                && projection.effective_agent_membership_base(realm_id, agent_id)
        })
}

async fn native_agent_controlled_by_record(
    state: &AppState,
    agent_id: &str,
    controller_id: &str,
) -> Option<soland_services::identity::AgentPairingState> {
    state
        .agent_pairings()
        .agent(agent_id)
        .await
        .ok()
        .flatten()
        .filter(|record| record.controller_id == controller_id)
}

async fn realm_member_is_joined(state: &AppState, realm_id: &str, actor_id: &str) -> bool {
    if state
        .projections()
        .snapshot()
        .member(realm_id, actor_id)
        .is_some_and(|member| member.state == "join")
    {
        return true;
    }
    crate::routing::spaces::space::realm_has_member_by_id(state, realm_id, actor_id).await
}

async fn has_active_accountability_grant(
    state: &AppState,
    agent_id: &str,
    controller_id: &str,
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
                    .and_then(Value::as_str)
                    .unwrap_or(record.actor_id.as_str())
                    == controller_id
                && accountability_grant_value_active_for(
                    record.envelope.get("payload").unwrap_or(&record.envelope),
                    controller_id,
                    agent_id,
                    now,
                )
        })
}

async fn native_agent_controlled_by(
    state: &AppState,
    agent_id: &str,
    controller_id: &str,
    require_active: bool,
) -> bool {
    let Ok(Some(record)) = state.agent_pairings().agent(agent_id).await else {
        return false;
    };
    record.controller_id == controller_id
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
    let actor = operation.context.sender.as_str();
    let realm_id = operation.realm_id.as_str();
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(
            realm_id,
            actor,
            operation.context.principal_server_id.as_str(),
            operation.created_at,
        )
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
                actor_principal_server_id: Some(operation.context.principal_server_id.as_str()),
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
    let actor = operation.context.sender.as_str();
    let realm_id = operation.realm_id.as_str();
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(
            realm_id,
            actor,
            operation.context.principal_server_id.as_str(),
            operation.created_at,
        )
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            actor_principal_server_id: Some(operation.context.principal_server_id.as_str()),
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

/// P2 — capability gate for the moderation control-plane events ingested at
/// `/_arkret/self/events` (content-moderation.md §2.6 / §5.5; capability-
/// action-registry.json). Mirrors [`validate_member_state_policy`]'s ban
/// gate: the actor MUST hold the matching moderation capability action on the
/// Realm. Realm ownership alone is not a capability; fail closed with
/// `missing_capability` otherwise.
///
/// Action mapping (capability-action-registry.json and policy-server.md):
/// - `ak.moderation.decision`            → governance policy action or narrow decision action
/// - `ak.moderation.decision.lift`       → governance policy action or narrow lift action
/// - `ak.moderation.appeal.submit`       → action `ak.moderation.appeal.submit`
/// - `ak.moderation.appeal.{review,decision,close}` → action `ak.moderation.appeal.review`
///   (aggregate_admin: one review capability covers review / decision / close — §5.5.1 table note).
///
/// `ak.moderation.appeal.close` additionally admits the appellant-withdrawal
/// path: an appellant closing their own appeal (closer == cell appellant)
/// needs no review capability (§5.5.2).
pub(super) async fn validate_moderation_event_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    let actions = match &kind {
        arkret_wire::EventKind::ModerationDecision => &[
            arkret_wire::CapabilityActionId::REALM_MODERATION_POLICY,
            arkret_wire::CapabilityActionId::POLICY_MANAGE,
            arkret_wire::CapabilityActionId::MODERATION_DECISION,
        ][..],
        arkret_wire::EventKind::ModerationDecisionLift => &[
            arkret_wire::CapabilityActionId::REALM_MODERATION_POLICY,
            arkret_wire::CapabilityActionId::POLICY_MANAGE,
            arkret_wire::CapabilityActionId::MODERATION_DECISION_LIFT,
        ][..],
        arkret_wire::EventKind::ModerationAppealSubmit => {
            &[arkret_wire::CapabilityActionId::MODERATION_APPEAL_SUBMIT][..]
        }
        arkret_wire::EventKind::ModerationAppealReview
        | arkret_wire::EventKind::ModerationAppealDecision
        | arkret_wire::EventKind::ModerationAppealClose => {
            &[arkret_wire::CapabilityActionId::MODERATION_APPEAL_REVIEW][..]
        }
        _ => return Ok(()),
    };

    // Peer/service-originated federation operations predate a typed actor
    // envelope; they stay accepted so convergence/backfill keep working
    // (mirrors the ban gate). Direct client submits always carry an actor.
    let Some(actor) = moderation_actor(operation, &kind)? else {
        return Ok(());
    };

    // §5.5.2 appellant-withdrawal: an appellant MAY close their own appeal
    // without the review capability (closer == cell appellant).
    if kind == arkret_wire::EventKind::ModerationAppealClose
        && moderation_close_is_appellant_withdrawal(state, operation, actor)
    {
        return Ok(());
    }

    let realm_id = operation.realm_id.as_str();
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(
            realm_id,
            actor,
            operation.context.principal_server_id.as_str(),
            operation.created_at,
        )
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if kind == arkret_wire::EventKind::ModerationAppealSubmit
        && members.iter().any(|member| member == actor)
    {
        return Ok(());
    }
    if actions.iter().any(|action| {
        state
            .authorization()
            .check(soland_services::authorization::AuthorizationCheck {
                actor,
                actor_principal_server_id: Some(operation.context.principal_server_id.as_str()),
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

pub(super) async fn validate_realm_policy_server_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::RealmPolicyServer)
    {
        return Ok(());
    }
    let actor = &operation.context.sender;
    let realm_id = operation.realm_id.as_str();
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(
            realm_id,
            actor.as_str(),
            operation.context.principal_server_id.as_str(),
            operation.created_at,
        )
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor: actor.as_str(),
            actor_principal_server_id: Some(operation.context.principal_server_id.as_str()),
            action: arkret_wire::CapabilityActionId::POLICY_MANAGE,
            resource: realm_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
    {
        Ok(())
    } else {
        Err("missing_capability")
    }
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
    let actor = operation.context.sender.as_str();
    let realm_id = operation.realm_id.as_str();
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(
            realm_id,
            actor,
            operation.context.principal_server_id.as_str(),
            operation.created_at,
        )
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            actor_principal_server_id: Some(operation.context.principal_server_id.as_str()),
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
) -> Result<Option<&'a str>, &'static str> {
    let actor = match kind {
        arkret_wire::EventKind::ModerationDecision => operation
            .payload
            .get("issuer")
            .or_else(|| operation.payload.get("decided_by"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_decision_issuer_missing")?,
        arkret_wire::EventKind::ModerationDecisionLift => {
            return Ok(Some(operation.context.sender.as_str()));
        }
        arkret_wire::EventKind::ModerationAppealSubmit => operation
            .payload
            .get("appellant")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_appeal_actor_missing")?,
        arkret_wire::EventKind::ModerationAppealReview
        | arkret_wire::EventKind::ModerationAppealDecision => operation
            .payload
            .get("reviewer")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_appeal_actor_missing")?,
        arkret_wire::EventKind::ModerationAppealClose => operation
            .payload
            .get("closer")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_appeal_actor_missing")?,
        _ => return Ok(None),
    };
    if operation.context.sender.as_str() != actor {
        return Err("moderation_actor_mismatch");
    }
    Ok(Some(actor))
}

/// True when an `appeal.close` is an appellant self-withdrawal: the closer
/// equals the appellant anchored on the projected appeal cell at submit time
/// and the close reason is the canonical withdrawal reason.
pub(super) fn moderation_close_is_appellant_withdrawal(
    state: &AppState,
    operation: &Operation,
    actor: &str,
) -> bool {
    if operation
        .payload
        .get("close_reason")
        .and_then(Value::as_str)
        != Some("appellant_withdrawn")
    {
        return false;
    }
    let Some(appeal_id) = operation.payload.get("appeal_id").and_then(Value::as_str) else {
        return false;
    };
    let appellant = {
        let proj = state.projections().snapshot();
        proj.moderation_appeal_appellant(appeal_id)
    };
    matches!(appellant, Some(appellant) if appellant == actor)
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
        return matches!(membership, "invite" | "join")
            .then_some("direct_conversation_member_count_invalid");
    };
    if binding.participants_unordered.len() != 2 {
        return Some("direct_conversation_member_count_invalid");
    }
    if !matches!(membership, "invite" | "join") {
        return None;
    }
    let target = membership_target(operation)?;
    if binding
        .participants_unordered
        .iter()
        .any(|participant| participant == target)
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
