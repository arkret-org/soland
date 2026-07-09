use super::*;

/// strand-and-message.md §9.8.2 — a reaction MUST target an object inside its
/// own effective scope. soland's effective scope is the Realm, so a
/// `ck.reaction.*` whose `target_ref` resolves to a Message in a different
/// Realm is rejected with `reaction_scope_mismatch` (a `failed_precondition`
/// sub-reason). The target-kind gate (`reaction_target_unsupported`) already
/// ran in `validate_operation_semantics`; an unknown / not-yet-observed
/// target is left to the reducer's dependency handling.
pub(super) fn validate_reaction_scope_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    if !matches!(
        kind,
        cokret_sdk::events::kinds::REACTION_ADD | cokret_sdk::events::kinds::REACTION_REMOVE
    ) {
        return Ok(());
    }
    let target = REACTION_TARGET_FIELDS.iter().find_map(|field| {
        operation
            .payload
            .get(*field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
    });
    let Some(target) = target else {
        return Ok(());
    };
    let target_realm = {
        let projection = state.projection.lock();
        projection.message_realm(target)
    };
    let Some(target_realm) = target_realm else {
        // Target not yet observed — reducer keeps the reaction pending.
        return Ok(());
    };
    if realm_ids_match(operation.realm_id.as_str(), &target_realm) {
        Ok(())
    } else {
        Err(cokret_sdk::error::REASON_REACTION_SCOPE_MISMATCH)
    }
}

/// circle.md §8 — resolve the Circle a write operation lands content into, if
/// any. Returns the `ck:circle:…` id when the operation introduces, mutates, or
/// tombstones a Circle-scoped object, else `None` (Realm-default scope).
/// Object-carrying creates declare scope inline (`payload.object` /
/// `payload.relation` / top-level `scope_circle_id`); updates and lifecycle
/// writes derive scope from the projected target. `ck.message.create` derives
/// scope from the projected Strand — a Message never self-declares its scope.
pub(super) fn operation_target_scope_circle_id(
    projection: &crate::reducer::ProjectionState,
    operation: &Operation,
) -> Option<String> {
    let top_level_scope = || -> Option<String> {
        operation
            .payload
            .get("scope_circle_id")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("ak:circle:"))
            .map(ToOwned::to_owned)
    };
    let inline_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_object)
            .and_then(|object| object.get("scope_circle_id"))
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("ak:circle:"))
            .map(ToOwned::to_owned)
    };
    let relation_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_str)
            .and_then(|relation_id| projection.relation_scope_circle_id(relation_id))
    };
    let strand_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_str)
            .and_then(|strand_id| projection.strand_scope_circle_id(strand_id))
    };
    let morph_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_str)
            .and_then(|morph_id| projection.morph_scope_circle_id(morph_id))
    };
    match kinds::canonical_kind_for_operation(operation)? {
        cokret_sdk::events::kinds::STRAND_CREATE
        | cokret_sdk::events::kinds::MORPH_CREATE
        | cokret_sdk::events::kinds::SPACE_CREATE => inline_scope("object"),
        cokret_sdk::events::kinds::RELATION_CREATE => inline_scope("relation")
            .or_else(|| inline_scope("object"))
            .or_else(top_level_scope),
        cokret_sdk::events::kinds::RELATION_UPDATE
        | cokret_sdk::events::kinds::RELATION_TOMBSTONE => {
            relation_scope("relation_id").or_else(|| relation_scope("id"))
        }
        cokret_sdk::events::kinds::MESSAGE_CREATE => strand_scope("strand_id"),
        cokret_sdk::events::kinds::STRAND_UPDATE => strand_scope("target_ref"),
        cokret_sdk::events::kinds::MORPH_UPDATE
        | cokret_sdk::events::kinds::MORPH_ARCHIVE
        | cokret_sdk::events::kinds::MORPH_RESTORE => morph_scope("target_ref"),
        cokret_sdk::events::kinds::STRAND_ARCHIVE
        | cokret_sdk::events::kinds::STRAND_RESTORE
        | cokret_sdk::events::kinds::STRAND_MOVE
        | cokret_sdk::events::kinds::STRAND_REORDER => {
            strand_scope("target_ref").or_else(|| strand_scope("strand_id"))
        }
        cokret_sdk::events::kinds::REACTION_ADD | cokret_sdk::events::kinds::REACTION_REMOVE => {
            // A reaction's scope is the target Message's Strand scope — reacting
            // into a Circle is a write into that scope and requires Circle
            // membership just like authoring there. Unknown target (not yet
            // observed) → None: the reducer keeps the reaction pending and a
            // non-member cannot name a Circle message id it never received.
            let target = REACTION_TARGET_FIELDS.iter().find_map(|field| {
                operation
                    .payload
                    .get(*field)
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
            })?;
            let (_, _, thread_id) = projection.message_origin(target)?;
            projection.strand_scope_circle_id(&thread_id)
        }
        _ => None,
    }
}

/// circle.md §8 — the membership half of the two-layer authorization AND for
/// Circle-scoped writes:
///
/// ```text
/// authorized ⇔ capability_grant(actor, action)
///              ∧ (effective_scope.kind == "realm" ∨ actor ∈ Circle.members)
/// ```
///
/// Holding a Realm-wide capability does **not** authorize writing into a Circle:
/// the author MUST also be a member of that Circle. Without this gate any holder
/// of a Realm-wide grant — notably an Applet bot / Ghost Actor
/// (`extensions/applet-integration.md` §3.4.1, which requires a deployment to be
/// able to keep Realm-level automation out of Circles) — could inject Strands /
/// Morphs / Messages into a Circle it never joined. The Sync-side scope filter
/// (`circle_scope_visible_to_actor` in delivery) only hides reads from
/// non-members; it does not stop the write, so membership MUST be enforced at
/// admission too.
///
/// Coverage: object-carrying creates (Strand / Morph / Space / Relation),
/// relation update/tombstone, `ck.message.create`, Strand update / lifecycle,
/// Morph update / lifecycle, and `ck.reaction.add` / `ck.reaction.remove`
/// (scope derived from the target Message's Strand).
///
/// Membership is evaluated against the current Circle projection (soland's
/// convergence frontier), matching the delivery-side check. Peer / service-
/// originated federation operations without a typed actor stay accepted
/// (convergence / backfill), mirroring the ban / moderation gates; direct client
/// and Applet submits always carry an actor and are gated.
pub(super) fn validate_circle_scope_membership(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let projection = state.projection.lock();
    let Some(scope_circle_id) = operation_target_scope_circle_id(&projection, operation) else {
        return Ok(());
    };
    projection.validate_scope_circle_id(&scope_circle_id, operation.realm_id.as_str())?;
    let Some(actor) = operation.actor() else {
        return Ok(());
    };
    let actor = actor.as_str();
    if projection.circle_scope_visible_to_actor(&scope_circle_id, actor) {
        Ok(())
    } else {
        Err("circle_scope_membership_required")
    }
}

/// applet-integration.md §4 / §4b — installing an Applet into a Realm is gated
/// by the machine-readable `ck.realm.admin` capability: the actor submitting a
/// `ck.applet.registration` MUST own the target Realm or hold an active
/// `ck.realm.admin` grant covering it, else reject `applet_registration_unauthorized`.
///
/// The dedicated install aggregate (`POST /_cokret/self/applets/install`) checks
/// this in its own handler and persists the registration projection directly —
/// it does NOT flow through this admission path. This gate closes the *bypass*:
/// a raw `ck.applet.registration` submitted via `/_cokret/self/events` otherwise
/// reaches `apply_applet_registration` with no authorization of its own.
/// Registration staying `service_attested` (carrier authenticity) is orthogonal
/// to "who may install" (§4) — both must hold. Mirrors the ban gate
/// (`validate_member_state_policy`); peer / service-originated federation ops
/// without a typed actor stay accepted for convergence.
pub(super) async fn validate_applet_registration_authz(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(cokret_sdk::events::kinds::APPLET_REGISTRATION)
    {
        return Ok(());
    }
    let Some(actor) = operation.actor() else {
        return Ok(());
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
            "ck.realm.admin",
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
    Err("applet_registration_unauthorized")
}

/// Control-stream events carry their owning principal in `payload.principal_id`.
pub(super) const PRINCIPAL_CONTROL_EVENT_KINDS: &[&str] = &[
    "ck.device.authorize",
    "ck.device.list_update",
    "ck.device.revoke",
    "ck.cross_signing.publish",
    "ck.cross_signing.reset",
];

/// Phase 2 — principal control realm isolation (key-management.md §4.1). A
/// control-stream event MUST land on its principal's deterministic control realm
/// (`principal_control_realm_for_did(payload.principal_id)`); it cannot be
/// written into a collaboration realm or another principal's control realm.
pub(in crate::routing::events::operations) fn validate_principal_control_realm_binding(
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind_string(operation);
    if !PRINCIPAL_CONTROL_EVENT_KINDS.contains(&kind.as_str()) {
        return Ok(());
    }
    let principal = operation
        .payload
        .get("principal_id")
        .and_then(Value::as_str)
        .ok_or("principal_control_event_missing_principal_id")?;
    let expected = crate::routing::identity::recovery::principal_control_realm_for_did(principal);
    if realm_ids_match(operation.realm_id.as_str(), &expected) {
        Ok(())
    } else {
        Err("principal_control_realm_mismatch")
    }
}

pub(crate) fn realm_ids_match(a: &str, b: &str) -> bool {
    a == b
}

/// constraint-schema.md §14.2 — enforce the message edit / redact temporal
/// windows declared on the actor's grants.
///
/// The pure SDK constraint engine cannot run on this path (it needs the
/// target Message `created_at` plus the actor's effective grant set), so
/// soland evaluates the window at admission time. The rules:
///
/// - The window only bites when a grant authorizing the relevant `.own` action carries a `temporal`
///   window field. With no such grant the action is unbounded (default member / owner behaviour is
///   unchanged).
/// - Holding the broader `ck.message.revise` / `ck.message.redact` capability (or `*`), or being
///   the Realm owner, lifts the window entirely (admin override).
/// - `message_redact_window` is authoritative for redact; otherwise redact shares the edit window
///   unless `allow_redact_after_window` is set.
pub(super) async fn validate_message_edit_redact_window_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    let is_redact = matches!(
        kind,
        cokret_sdk::events::kinds::MESSAGE_REDACT | cokret_sdk::events::kinds::REDACTION
    );
    let is_revise = matches!(kind, cokret_sdk::events::kinds::MESSAGE_REVISE);
    if !is_redact && !is_revise {
        return Ok(());
    }
    let Some(actor) = operation.actor() else {
        return Ok(());
    };
    let actor = actor.as_str();
    let realm_id = operation.realm_id.as_str();

    // Realm owner is exempt from the .own window (admin override).
    if realm_owner_matches(state, realm_id, actor).await {
        return Ok(());
    }

    // Resolve the target Message's creation time.
    let target_ref = if is_redact {
        operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("message_id"))
            .or_else(|| operation.payload.get("target_ref"))
            .or_else(|| operation.payload.get("target"))
            .or_else(|| operation.payload.get("redacts"))
            .or_else(|| operation.payload.get("event_id"))
    } else {
        operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("target_ref"))
            .or_else(|| operation.payload.get("revision_of"))
            .or_else(|| operation.payload.get("event_id"))
    }
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty());
    let Some(target_ref) = target_ref else {
        return Ok(());
    };
    let created_at = {
        let projection = state.projection.lock();
        projection.message_origin(target_ref).map(|origin| origin.0)
    };
    let Some(created_at) = created_at else {
        // Unknown target — leave it to the reducer's dependency handling.
        return Ok(());
    };

    let (own_action, broad_action) = if is_redact {
        ("ck.message.redact.own", "ck.message.redact")
    } else {
        ("ck.message.revise.own", "ck.message.revise")
    };

    let grants = state.authz.grants_for_subject(actor, realm_id);

    // Admin override: a broader (non-`.own`) capability is not time-boxed.
    let holds_broad = grants
        .iter()
        .any(|grant| grant.actions.iter().any(|action| action == broad_action));
    if holds_broad {
        return Ok(());
    }

    let age = operation.created_at - created_at;
    let mut saw_window = false;
    let mut permitted = false;
    for grant in &grants {
        let authorizes = grant
            .actions
            .iter()
            .any(|action| action == own_action || action == broad_action);
        if !authorizes {
            continue;
        }
        for constraint in &grant.constraints {
            if let crate::authz::Constraint::Temporal {
                message_edit_window,
                message_redact_window,
                allow_redact_after_window,
                ..
            } = constraint
            {
                if message_edit_window.is_none() && message_redact_window.is_none() {
                    continue; // plain expiry-only temporal constraint
                }
                saw_window = true;
                if message_window_permits(
                    is_redact,
                    age,
                    message_edit_window.as_ref(),
                    message_redact_window.as_ref(),
                    *allow_redact_after_window,
                ) {
                    permitted = true;
                }
            }
        }
    }

    // No window declared anywhere → unbounded. Otherwise allow when at least
    // one authorizing grant's window still permits the action.
    if !saw_window || permitted {
        Ok(())
    } else if is_redact {
        Err("message_redact_window elapsed")
    } else {
        Err("message_edit_window elapsed")
    }
}

/// Decide whether a single grant's window permits the action, per §14.2.
pub(crate) fn message_window_permits(
    is_redact: bool,
    age: chrono::Duration,
    message_edit_window: Option<&cokret_sdk::authz::ConstraintDuration>,
    message_redact_window: Option<&cokret_sdk::authz::ConstraintDuration>,
    allow_redact_after_window: bool,
) -> bool {
    if is_redact {
        // Redact window is authoritative when declared.
        if let Some(window) = message_redact_window {
            return duration_covers_age(window, age);
        }
        // Otherwise redact is coupled to the edit window unless the grant
        // opts out (then recall is unbounded).
        if allow_redact_after_window {
            return true;
        }
        if let Some(window) = message_edit_window {
            return duration_covers_age(window, age);
        }
        return true;
    }
    match message_edit_window {
        Some(window) => duration_covers_age(window, age),
        None => true,
    }
}

/// `true` when `age` is within the constraint window (mirror of the SDK
/// `max_age_contains` helper). Unknown units fail closed.
pub(super) fn duration_covers_age(
    window: &cokret_sdk::authz::ConstraintDuration,
    age: chrono::Duration,
) -> bool {
    let allowed = match window.unit.as_str() {
        "s" => chrono::Duration::seconds(window.value as i64),
        "m" => chrono::Duration::minutes(window.value as i64),
        "h" => chrono::Duration::hours(window.value as i64),
        "d" => chrono::Duration::days(window.value as i64),
        _ => return false,
    };
    age <= allowed
}

pub async fn validate_content_encryption_floor(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
        match kinds::canonical_kind_for_operation(operation) {
            Some(cokret_sdk::events::kinds::REALM_UPDATE)
                if operation_touches_encryption_profile(operation) =>
            {
                return Err(REALM_ENCRYPTION_PROFILE_CREATE_LOCKED);
            }
            Some(cokret_sdk::events::kinds::CIRCLE_UPDATE)
                if operation_touches_encryption_profile(operation) =>
            {
                return Err(CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED);
            }
            Some(cokret_sdk::events::kinds::CIRCLE_CREATE) => {
                if let Some(profile) = operation_circle_encryption_profile(operation)
                    && !encryption_profile_requires_content_encryption(Some(profile))
                    && realm_requires_content_encryption(state, operation.realm_id.as_str()).await
                {
                    return Err(CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR);
                }
            }
            _ => {}
        }
        if strand_operation_carries_plaintext_private_content(operation)
            && realm_content_floor_requires_e2ee(state, operation.realm_id.as_str())
        {
            return Err(CONTENT_ENCRYPTION_FLOOR_VIOLATION);
        }
    }
    Ok(())
}
