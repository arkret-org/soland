use super::*;

/// strand-and-message.md §9.8.2 — a reaction MUST target an object inside its
/// own effective scope. soland's effective scope is the Realm, so a
/// `ak.reaction.*` whose `target_ref` resolves to a Message in a different
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
        arkret_wire::EventKind::REACTION_ADD | arkret_wire::EventKind::REACTION_REMOVE
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
        let projection = state.projections().snapshot();
        projection.message_realm(target)
    };
    let Some(target_realm) = target_realm else {
        // Target not yet observed — reducer keeps the reaction pending.
        return Ok(());
    };
    if realm_ids_match(operation.realm_id.as_str(), &target_realm) {
        Ok(())
    } else {
        Err(arkret_wire::ReasonCode::REACTION_SCOPE_MISMATCH)
    }
}

/// circle.md §8 — resolve the Circle a write operation lands content into, if
/// any. Returns the `ak:circle:…` id when the operation introduces, mutates, or
/// tombstones a Circle-scoped object, else `None` (Realm-default scope).
/// Object-carrying creates declare scope inline (`payload.object` /
/// `payload.relation` / top-level `scope_circle_id`); updates and lifecycle
/// writes derive scope from the projected target. `ak.message.create` derives
/// scope from the projected Strand — a Message never self-declares its scope.
pub(super) fn operation_target_scope_circle_id(
    projection: &soland_services::projection::ProjectionSnapshot,
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
        arkret_wire::EventKind::STRAND_CREATE
        | arkret_wire::EventKind::MORPH_CREATE
        | arkret_wire::EventKind::SPACE_CREATE => inline_scope("object"),
        arkret_wire::EventKind::RELATION_CREATE => inline_scope("relation")
            .or_else(|| inline_scope("object"))
            .or_else(top_level_scope),
        arkret_wire::EventKind::RELATION_UPDATE | arkret_wire::EventKind::RELATION_TOMBSTONE => {
            relation_scope("relation_id")
        }
        arkret_wire::EventKind::MESSAGE_CREATE => strand_scope("strand_id"),
        arkret_wire::EventKind::STRAND_UPDATE => strand_scope("target_ref"),
        arkret_wire::EventKind::MORPH_UPDATE
        | arkret_wire::EventKind::MORPH_ARCHIVE
        | arkret_wire::EventKind::MORPH_RESTORE => morph_scope("target_ref"),
        arkret_wire::EventKind::STRAND_ARCHIVE
        | arkret_wire::EventKind::STRAND_RESTORE
        | arkret_wire::EventKind::STRAND_MOVE
        | arkret_wire::EventKind::STRAND_REORDER => {
            strand_scope("target_ref").or_else(|| strand_scope("strand_id"))
        }
        arkret_wire::EventKind::REACTION_ADD | arkret_wire::EventKind::REACTION_REMOVE => {
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
/// relation update/tombstone, `ak.message.create`, Strand update / lifecycle,
/// Morph update / lifecycle, and `ak.reaction.add` / `ak.reaction.remove`
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
    let projection = state.projections().snapshot();
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
/// by the machine-readable `ak.realm.admin` capability: the actor submitting a
/// `ak.applet.registration` MUST hold an active `ak.realm.admin` grant
/// covering it, else reject `applet_registration_unauthorized`.
///
/// The dedicated install aggregate (`POST /_arkret/self/applets/install`)
/// validates and submits the caller-signed registration Event through the same
/// admission path as a raw `/_arkret/self/events` submission. Both paths
/// therefore apply this capability gate without an internal bypass.
pub(super) async fn validate_applet_registration_authz(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::APPLET_REGISTRATION)
    {
        return Ok(());
    }
    let Some(actor) = operation.actor() else {
        return Ok(());
    };
    let actor = actor.as_str();
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
            action: "ak.realm.admin",
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
    Err("applet_registration_unauthorized")
}

/// Control-stream events carry their owning principal in `payload.principal_id`.
pub(super) const PRINCIPAL_CONTROL_EVENT_KINDS: &[&str] = &[
    "ak.device.authorize",
    "ak.device.list_update",
    "ak.device.revoke",
    "ak.cross_signing.publish",
    "ak.cross_signing.reset",
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
    let expected = soland_services::identity::principal_control_realm_for_did(principal);
    if realm_ids_match(operation.realm_id.as_str(), &expected) {
        Ok(())
    } else {
        Err("principal_control_realm_mismatch")
    }
}

pub(in crate::routing::events::operations) async fn validate_managed_agent_control_realm_binding(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind_string(operation);
    let explicit_agent_control = matches!(
        kind.as_str(),
        "ak.agent.key.authorize"
            | "ak.agent.key.revoke"
            | "ak.self.agent.pause"
            | "ak.self.agent.resume"
            | "ak.self.agent.deactivate"
    );
    let possible_agent_profile_or_genesis = matches!(
        kind.as_str(),
        "ak.realm.create" | "ak.profile.create" | "ak.profile.update"
    );
    if !explicit_agent_control && !possible_agent_profile_or_genesis {
        return Ok(());
    }
    let agent_id = if explicit_agent_control {
        operation
            .payload
            .get("agent_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    } else if kind == "ak.realm.create" {
        operation
            .payload
            .get("object")
            .and_then(|object| object.get("created_by"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    } else {
        operation
            .payload
            .get("object")
            .and_then(|object| object.get("actor_id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| operation.actor().map(|actor| actor.as_str().to_owned()))
    };
    let Some(agent_id) = agent_id else {
        return if explicit_agent_control {
            Err("managed_agent_control_event_missing_agent_id")
        } else {
            Ok(())
        };
    };
    let expected = crate::routing::identity::managed_agent_pcr::resolve_agent_pcr_for_principal(
        state, &agent_id,
    )
    .await
    .map_err(|_| "managed_agent_principal_binding_unavailable")?;
    let expected = match expected {
        Some(expected) => expected,
        None if possible_agent_profile_or_genesis => return Ok(()),
        None => return Err("managed_agent_principal_binding_unavailable"),
    };
    if !realm_ids_match(operation.realm_id.as_str(), &expected) {
        return Err("principal_control_realm_mismatch");
    }
    if kind == "ak.realm.create" {
        let object = operation
            .payload
            .get("object")
            .ok_or("managed_agent_pcr_genesis_object_missing")?;
        crate::routing::identity::managed_agent_pcr::validate_agent_pcr_genesis_object(
            object, &agent_id, &expected,
        )
        .map_err(|_| "principal_control_realm_profile_mismatch")?;
    }
    if kind == "ak.agent.key.authorize" {
        let record = state
            .agent_pairings()
            .agent(&agent_id)
            .await
            .map_err(|_| "managed_agent_principal_binding_unavailable")?
            .ok_or("managed_agent_principal_binding_unavailable")?;
        let recovery =
            crate::routing::identity::managed_agent_pcr::project_agent_pcr_recovery(state, &record)
                .await
                .map_err(|_| "agent_pcr_recovery_not_ready")?;
        if !recovery.is_ready() {
            return Err("agent_pcr_recovery_not_ready");
        }
    }
    Ok(())
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
///   window field. A matching grant without such a constraint is unbounded.
/// - Holding the broader `ak.message.revise` / `ak.message.redact` capability lifts the window.
/// - `message_redact_window` is authoritative for redact; otherwise redact shares the edit window
///   unless `redact_after_window_allowed` is set.
pub(super) async fn validate_message_edit_redact_window_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    let is_redact = matches!(
        kind,
        arkret_wire::EventKind::MESSAGE_REDACT | arkret_wire::EventKind::REDACTION
    );
    let is_revise = matches!(kind, arkret_wire::EventKind::MESSAGE_REVISE);
    if !is_redact && !is_revise {
        return Ok(());
    }
    let Some(actor) = operation.actor() else {
        return Ok(());
    };
    let actor = actor.as_str();
    let realm_id = operation.realm_id.as_str();

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
        let projection = state.projections().snapshot();
        projection.message_origin(target_ref).map(|origin| origin.0)
    };
    let Some(created_at) = created_at else {
        // Unknown target — leave it to the reducer's dependency handling.
        return Ok(());
    };

    let (own_action, broad_action) = if is_redact {
        ("ak.message.redact.own", "ak.message.redact")
    } else {
        ("ak.message.revise.own", "ak.message.revise")
    };

    let grants = state.authorization().grants_for_subject(actor, realm_id);

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
                redact_after_window_allowed,
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
                    *redact_after_window_allowed,
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
    message_edit_window: Option<&arkret_policy::authz::ConstraintDuration>,
    message_redact_window: Option<&arkret_policy::authz::ConstraintDuration>,
    redact_after_window_allowed: bool,
) -> bool {
    if is_redact {
        // Redact window is authoritative when declared.
        if let Some(window) = message_redact_window {
            return duration_covers_age(window, age);
        }
        // Otherwise redact is coupled to the edit window unless the grant
        // opts out (then recall is unbounded).
        if redact_after_window_allowed {
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
    window: &arkret_policy::authz::ConstraintDuration,
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
            Some(arkret_wire::EventKind::REALM_UPDATE)
                if operation_touches_encryption_profile(operation) =>
            {
                return Err(REALM_ENCRYPTION_PROFILE_CREATE_LOCKED);
            }
            Some(arkret_wire::EventKind::CIRCLE_UPDATE)
                if operation_touches_encryption_profile(operation) =>
            {
                return Err(CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED);
            }
            Some(arkret_wire::EventKind::CIRCLE_CREATE) => {
                if let Some(profile) = operation_circle_encryption_profile(operation)
                    && !encryption_profile_requires_content_encryption(Some(profile))
                    && realm_requires_content_encryption(state, operation.realm_id.as_str()).await
                {
                    return Err(arkret_wire::ReasonCode::CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR);
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
