use super::*;

pub(super) fn validate_direct_conversation_realm_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if active_direct_conversation_binding_for_realm(state, operation.realm_id.as_str()).is_none() {
        return Ok(());
    }
    if kinds::operation_is_invite(operation) {
        return Err("direct_conversation_invite_forbidden");
    }
    if operation_is_space_container(operation) {
        return Err("direct_conversation_space_forbidden");
    }
    Ok(())
}

pub(super) fn operation_is_space_container(operation: &Operation) -> bool {
    matches!(
        kinds::canonical_kind_for_operation(operation),
        Some(
            arkret_sdk::events::kinds::SPACE_CREATE
                | arkret_sdk::events::kinds::SPACE_UPDATE
                | arkret_sdk::events::kinds::SPACE_PARENT
                | arkret_sdk::events::kinds::SPACE_ARCHIVE
                | arkret_sdk::events::kinds::SPACE_RESTORE
                | arkret_sdk::events::kinds::SPACE_TOMBSTONE
        )
    )
}

pub(super) async fn validate_member_state_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_sdk::events::kinds::MEMBER_STATE)
    {
        return Ok(());
    }
    if let Some(reason) = direct_conversation_member_state_guard(state, operation) {
        return Err(reason);
    }
    if operation.payload.get("membership").and_then(Value::as_str) == Some("join") {
        if let Some(member) = membership_target(operation)
            && crate::routing::organizations::organization_policy_blocks_join(
                state,
                operation.realm_id.as_str(),
                member,
            )
            .await
        {
            return Err("organization_policy_denied");
        }
        return Ok(());
    }
    if operation.payload.get("membership").and_then(Value::as_str) != Some("ban") {
        return Ok(());
    }
    let Some(actor) = operation.payload.get("sender").and_then(Value::as_str) else {
        // Peer/service-originated federation operations predate a typed actor
        // envelope. They stay accepted so existing convergence/backfill
        // paths keep working; direct client submits always carry `sender`.
        return Ok(());
    };
    if realm_owner_matches(state, operation.realm_id.as_str(), actor).await {
        return Ok(());
    }
    // P1 — a non-owner MAY ban iff they hold `ak.realm.admin` on this Realm
    // (capabilities.md §16 — `ak.realm.admin` governs `ak.member.state`
    // writes). The owner implicitly holds admin and already returned above;
    // this reads the projected capability grant index via
    // SolandAuthzEngine::check. fail-closed: anything other than an explicit
    // allow keeps the `missing_capability` rejection.
    let realm_id = operation.realm_id.as_str();
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            "ak.realm.admin",
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
        .allowed
    {
        return Ok(());
    }
    Err("missing_capability")
}

/// COT-06-004 — capability gate for `ak.realm.set_default_strand`. Mirrors the
/// ban / moderation gates: the actor MUST own the Realm or hold
/// `ak.realm.set_default_strand` (or the broader `ak.realm.admin`) on it.
/// fail-closed `missing_capability` otherwise. Peer/service-originated
/// federation operations (no `sender`) stay accepted for convergence/backfill.
pub(super) async fn validate_set_default_strand_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_sdk::events::kinds::REALM_SET_DEFAULT_STRAND)
    {
        return Ok(());
    }
    let Some(actor) = operation
        .payload
        .get("sender")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(());
    };
    let realm_id = operation.realm_id.as_str();
    if realm_owner_matches(state, realm_id, actor).await {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    // A grant of either the precise action or the broad realm-admin action
    // authorizes the write. `ak.realm.admin` aggregates Realm governance, so
    // an admin holder need not also hold the narrow set_default_strand action.
    for action in ["ak.realm.set_default_strand", "ak.realm.admin"] {
        if state
            .authz
            .check(
                actor,
                action,
                realm_id,
                realm_id,
                owner.as_deref(),
                &members,
                &[],
            )
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
/// ([`arkret_sdk::models::realm_organization_statement_signing_bytes`]). This is
/// the cryptographic anchor that makes "organization consent" unforgeable: only
/// a holder of the organization's own DID key can produce an accepted statement,
/// and no external party (not even a Realm admin) can forge it.
pub(super) async fn verify_realm_organization_proof_signature(
    state: &AppState,
    payload: &arkret_sdk::models::RealmOrganizationPayload,
) -> Result<(), &'static str> {
    use base64::Engine as _;

    let proof_b64 = match &payload.authorization.proof {
        arkret_sdk::models::SignatureMaterial::NonEmptyString(value) => value.as_str(),
        arkret_sdk::models::SignatureMaterial::Variant1(_) => {
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
    let resolved = crate::jws_verify::resolve_ed25519_verification_key_for_did(
        state,
        &payload.organization_id,
        payload.authorization.verification_method.as_str(),
    )
    .await
    .map_err(|_| "organization_statement_unverified")?;

    let signing_bytes = arkret_sdk::models::realm_organization_statement_signing_bytes(payload)
        .map_err(|_| "organization_statement_unverified")?;
    resolved
        .public_key
        .verify_strict(&signing_bytes, &signature)
        .map_err(|_| "organization_statement_unverified")
}

/// SOL-ORG-03 — two-sided authorization gate for `ak.realm.organization`.
///
///   - **Realm side**: the actor admitting the statement into Realm history MUST own the Realm or
///     hold `ak.realm.admin` on it. A plain OIDC human session only proves the executor's identity;
///     it does not by itself create organization principal control, so the executor still needs the
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
        != Some(arkret_sdk::events::kinds::REALM_ORGANIZATION)
    {
        return Ok(());
    }
    // Organization side — strong-typed parse + SDK verifier (fail-closed).
    let payload: arkret_sdk::models::RealmOrganizationPayload =
        serde_json::from_value(operation.payload.clone())
            .map_err(|_| arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION)?;
    arkret_sdk::models::verify_realm_organization_statement(
        &payload,
        &operation.realm_id,
        chrono::Utc::now(),
        &arkret_sdk::models::NoDelegationResolver,
    )
    .map_err(|_| "organization_statement_unverified")?;

    // Cryptographic organization-side proof verification (model C): the proof
    // MUST be a real detached signature by a verification method in the
    // organization's OWN DID document, which soland (the DID server) hosts and
    // resolves. Skipped in development_mode — consistent with jws_verify's
    // dev/prod split — where statements ride placeholder proofs.
    if !state.config.development_mode {
        verify_realm_organization_proof_signature(state, &payload).await?;
    }

    // Realm side — owner or `ak.realm.admin`. The executor identity comes from
    // the envelope sender / authorization.executed_by; a bare OIDC session is
    // not sufficient on its own.
    let Some(actor) = operation.actor() else {
        return Err("missing_capability");
    };
    let actor = actor.as_str();
    let realm_id = operation.realm_id.as_str();
    if realm_owner_matches(state, realm_id, actor).await {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            "ak.realm.admin",
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
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
/// Realm, or own the Realm. fail-closed `missing_capability` otherwise.
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
    let actions = match kind {
        arkret_sdk::events::kinds::MODERATION_DECISION => &[
            "ak.realm.moderation_policy",
            "ak.policy.manage",
            "ak.moderation.decision",
        ][..],
        arkret_sdk::events::kinds::MODERATION_DECISION_LIFT => &[
            "ak.realm.moderation_policy",
            "ak.policy.manage",
            "ak.moderation.decision.lift",
        ][..],
        arkret_sdk::events::kinds::MODERATION_APPEAL_SUBMIT => &["ak.moderation.appeal.submit"][..],
        arkret_sdk::events::kinds::MODERATION_APPEAL_REVIEW
        | arkret_sdk::events::kinds::MODERATION_APPEAL_DECISION
        | arkret_sdk::events::kinds::MODERATION_APPEAL_CLOSE => {
            &["ak.moderation.appeal.review"][..]
        }
        _ => return Ok(()),
    };

    // Peer/service-originated federation operations predate a typed actor
    // envelope; they stay accepted so convergence/backfill keep working
    // (mirrors the ban gate). Direct client submits always carry an actor.
    let Some(actor) = moderation_actor(operation, kind)? else {
        return Ok(());
    };

    // §5.5.2 appellant-withdrawal: an appellant MAY close their own appeal
    // without the review capability (closer == cell appellant).
    if kind == arkret_sdk::events::kinds::MODERATION_APPEAL_CLOSE
        && moderation_close_is_appellant_withdrawal(state, operation, actor)
    {
        return Ok(());
    }

    let realm_id = operation.realm_id.as_str();
    if realm_owner_matches(state, realm_id, actor).await {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if kind == arkret_sdk::events::kinds::MODERATION_APPEAL_SUBMIT
        && members.iter().any(|member| member == actor)
    {
        return Ok(());
    }
    if actions.iter().any(|action| {
        state
            .authz
            .check(
                actor,
                action,
                realm_id,
                realm_id,
                owner.as_deref(),
                &members,
                &[],
            )
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
    if kinds::canonical_kind_string(operation) != arkret_sdk::events::kinds::CALL_RECORDING_START {
        return Ok(());
    }
    let action = call_recording_start_required_action(operation);
    let Some(actor) = operation.actor() else {
        return Ok(());
    };
    let actor = actor.as_str();
    let realm_id = operation.realm_id.as_str();
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            action,
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
        .allowed
    {
        return Ok(());
    }
    if action == arkret_sdk::CAP_ACTION_CALL_TRANSCRIBE {
        Err(crate::error::reasons::TRANSCRIPTION_DENIED)
    } else {
        Err("missing_capability")
    }
}

pub(super) fn call_recording_start_required_action(operation: &Operation) -> &'static str {
    match operation
        .payload
        .get("capture_kind")
        .and_then(Value::as_str)
        .unwrap_or("recording")
    {
        "transcript" => arkret_sdk::CAP_ACTION_CALL_TRANSCRIBE,
        _ => arkret_sdk::CAP_ACTION_CALL_RECORD,
    }
}

/// Extract the authoring actor for a moderation event from the spec field for
/// that kind. The projection adapter injects envelope.actor_id into
/// payload.sender; when both sender and the kind-specific actor are present
/// they must match so a privileged sender cannot spoof the decision issuer.
pub(super) fn moderation_actor<'a>(
    operation: &'a Operation,
    kind: &str,
) -> Result<Option<&'a str>, &'static str> {
    let actor = match kind {
        arkret_sdk::events::kinds::MODERATION_DECISION => operation
            .payload
            .get("issuer")
            .or_else(|| operation.payload.get("decided_by"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_decision_issuer_missing")?,
        arkret_sdk::events::kinds::MODERATION_DECISION_LIFT => {
            return Ok(operation
                .payload
                .get("sender")
                .or_else(|| operation.payload.get("actor_id"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty()));
        }
        arkret_sdk::events::kinds::MODERATION_APPEAL_SUBMIT => operation
            .payload
            .get("appellant")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_appeal_actor_missing")?,
        arkret_sdk::events::kinds::MODERATION_APPEAL_REVIEW
        | arkret_sdk::events::kinds::MODERATION_APPEAL_DECISION => operation
            .payload
            .get("reviewer")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_appeal_actor_missing")?,
        arkret_sdk::events::kinds::MODERATION_APPEAL_CLOSE => operation
            .payload
            .get("closer")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_appeal_actor_missing")?,
        _ => return Ok(None),
    };
    if operation
        .payload
        .get("sender")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .is_some_and(|sender| sender != actor)
    {
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
        let proj = state.projection.lock();
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
    let binding = active_direct_conversation_binding_for_realm(state, operation.realm_id.as_str())?;
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

pub(super) fn active_direct_conversation_binding_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Option<crate::state::DirectConversationBindingRecord> {
    state
        .direct_conversation_bindings
        .lock()
        .values()
        .find(|binding| binding.state == "active" && binding.realm_id == realm_id)
        .cloned()
}
