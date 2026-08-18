use super::*;

/// Verify a DataEvent's authorization against the accepted governance basis at
/// its `seal_ref`.
///
/// `event-auth-state-resolution.md` §4.1(3) / §4.3(2): the verifier resolves
/// every capability the `kind`, the scope and the receiver-derived targets need
/// from the `seal_ref` governance state — **the producer does not select
/// candidate grants**. `event-and-patch.md` §2.2 states the same in the
/// negative: `effects` and producer-selected `auth_context.capability_refs` are
/// not v1 wire fields and a receiver MUST answer `schema_violation` when it
/// meets either.
///
/// So the two producer-supplied inputs this check used to read are refused
/// here, and what it reads instead is what v1 actually carries:
///
/// - `derived_cells` — the receiver's own registry projection of `kind + payload`
///   (`arkret_schema::project_registered_cell_writes`), which replaces the producer's `effects[]`
///   as the set the capability must cover;
/// - `refs[]` entries with `role=authorized_by` — semantic, non-authoritative citations that MUST
///   still resolve and be valid at `seal_ref`, exactly as `arkret_state`'s `verify_capability_refs`
///   requires of a Control Move.
pub(in crate::routing::events::event_log) fn validate_data_event_capability_refs(
    state: &AppState,
    actor_id: &str,
    principal_server_id: &str,
    realm_id: &str,
    kind: &str,
    object: &serde_json::Map<String, Value>,
    derived_cells: &[String],
    realm_authority_root_authorized: bool,
) -> Result<(), EventValidationError> {
    let is_data_event = object.contains_key("seal_ref") || object.contains_key("auth_context");
    if !is_data_event {
        return Ok(());
    }
    if object.contains_key("seal_basis") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent must not carry seal_basis",
        ));
    }
    if object.contains_key("effects") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects is not a v1 Event Envelope field; reducer targets are derived from kind + payload",
        ));
    }
    let seal_ref = object
        .get("seal_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                "DataEvent requires seal_ref to resolve the authorization pre-state",
            )
        })?;
    let seal_id = arkret_identifiers::SealId::new(seal_ref.to_owned()).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent seal_ref must be a valid ak:seal id",
        )
    })?;
    let realm = RealmId::new(realm_id.to_owned()).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent realm_id must be a valid ak:realm id",
        )
    })?;
    let auth_context = object
        .get("auth_context")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "DataEvent requires auth_context",
            )
        })?;
    if auth_context.contains_key("capability_refs") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "auth_context is closed over {did, key_id, key_epoch, credential_epoch}; effective capabilities are derived from the governance basis at seal_ref",
        ));
    }
    if derived_cells.is_empty() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent derives no data-plane write from its registered reducer contract",
        ));
    }
    let access = data_event_constraint_context(kind, object).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent patch does not expose a canonical field/track authorization context",
        )
    })?;

    let state_at_ref = data_event_state_at_seal_ref(state, &realm, &seal_id)?;
    let historical_grants = data_event_grants_from_state_at_ref(&state_at_ref);
    let auth_time = state
        .projections()
        .seal_by_id(&seal_id)
        .map_err(|error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent seal_ref lookup failed: {error}"),
            )
        })?
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                "DataEvent seal_ref is not projected",
            )
        })?
        .sealed_at;
    let historical_snapshot: Vec<crate::authz::Grant> =
        historical_grants.values().cloned().collect();
    // An Applet-originated act-on-behalf Event is signed and executed by the
    // installed service while `actor_id` remains the accountable ghost/native
    // principal. Formal install grants are normatively issued to that service
    // (`applet-integration.md` §4b), so the CBA subject is `executed_by`.
    // The Applet-specific validator independently proves the exact
    // registration, namespace and epoch binding; selecting `executed_by` here
    // must never become a generic delegation fallback.
    let capability_subject = if object.contains_key("applet_id") {
        object
            .get("executed_by")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    arkret_wire::ReasonCode::EXECUTED_BY_MISSING,
                    "applet-originated DataEvent requires executed_by",
                )
            })?
    } else {
        actor_id
    };
    let capability_subject_principal_server_id = if object.contains_key("applet_id") {
        capability_subject
    } else {
        principal_server_id
    };
    let effective_by_id = effective_historical_grants_for_subject(
        &historical_grants,
        capability_subject,
        capability_subject_principal_server_id,
        realm_id,
        auth_time,
    );
    let mut used_grant_ids = std::collections::BTreeSet::new();

    // Unlike an ordinary DataEvent, an Applet delegated write carries one
    // mandatory, authoritative `authorization_ref`. It must itself be
    // effective in the Event's frozen Seal view and cover every
    // receiver-derived write; a different service grant in that view cannot
    // substitute for the signed reference.
    if object.contains_key("applet_id") {
        let authorization_ref = object
            .get("authorization_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "authorization_ref_missing",
                    "applet-originated DataEvent requires authorization_ref",
                )
            })?;
        let stored = historical_grants.get(authorization_ref).ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "authorization_ref_inactive",
                format!(
                    "applet authorization_ref {authorization_ref} is not projected at seal_ref"
                ),
            )
        })?;
        if stored.subject != capability_subject
            || stored.subject_principal_server_id.as_deref()
                != Some(capability_subject_principal_server_id)
            || stored.realm_id != realm_id
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "authorization_ref_scope",
                format!(
                    "applet authorization_ref {authorization_ref} does not cover executor/realm"
                ),
            ));
        }
        if crate::authz::grant_revoked_upstream(&historical_snapshot, authorization_ref, auth_time)
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                arkret_wire::ReasonCode::GRANT_REVOKED_UPSTREAM,
                format!("applet authorization_ref {authorization_ref} was revoked upstream"),
            ));
        }
        if stored.revoked || !effective_by_id.contains_key(authorization_ref) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "authorization_ref_inactive",
                format!(
                    "applet authorization_ref {authorization_ref} is revoked, expired, or delegation-broken at seal_ref"
                ),
            ));
        }
        if derived_cells.iter().any(|cell| {
            !grant_covers_data_event_effect(state, stored, kind, realm_id, cell, &access)
        }) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "authorization_ref_scope",
                format!(
                    "applet authorization_ref {authorization_ref} does not cover every derived DataEvent cell"
                ),
            ));
        }
        used_grant_ids.insert(authorization_ref.to_owned());
    }

    // `refs[role=authorized_by]` is a critical semantic citation, not a
    // capability selector: it never widens the effective set, but an entry that
    // does not resolve to a live grant at `seal_ref` MUST fail the Event closed
    // (`event-and-patch.md` §2.2 — unrecognized critical refs fail closed;
    // `arkret_state::verify_capability_refs` applies the same rule on the
    // control plane).
    for reference in data_event_authorized_by_refs(object)? {
        let grant_id = reference.as_str();
        if arkret_identifiers::GrantId::new(grant_id.to_owned()).is_err() {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent refs[role=authorized_by] {grant_id} is not a valid ak:grant id"),
            ));
        }
        let stored = historical_grants.get(grant_id).ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent authorized_by grant {grant_id} is not projected at seal_ref"),
            )
        })?;
        if crate::authz::grant_revoked_upstream(&historical_snapshot, grant_id, auth_time) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                arkret_wire::ReasonCode::GRANT_REVOKED_UPSTREAM,
                format!("DataEvent authorized_by grant {grant_id} was revoked upstream"),
            ));
        }
        if stored.revoked {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent authorized_by grant {grant_id} is revoked"),
            ));
        }
        if stored.subject != capability_subject || stored.realm_id != realm_id {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent authorized_by grant {grant_id} does not cover actor/realm"),
            ));
        }
        if crate::authz::grant_scope_valid(stored).is_err() {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent authorized_by grant {grant_id} has invalid scope"),
            ));
        }
        if !effective_by_id.contains_key(grant_id) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent authorized_by grant {grant_id} is expired or delegation-broken"),
            ));
        }
        used_grant_ids.insert(grant_id.to_owned());
    }

    // Coverage is decided over the whole effective set the governance basis
    // yields for this actor, never over a producer-chosen subset, and over the
    // cells the receiver itself derived, never over a producer-chosen write
    // list.
    // `capabilities.md` section 3.2 - an Event authored under the Realm
    // authority root carries effective `ak.realm.owner`, which is not a grant
    // and therefore has no `ak:grant:*` id to cover a derived cell with. The
    // root claim itself (controller identity, accepted-Seal inclusion proof,
    // registry basis, and whether the owner aggregate may author this Event
    // kind at all) is validated by `realm_authority_root` before this gate
    // runs; here it only replaces the per-cell grant search.
    // The registry's non-capability admission classes are complete
    // authorization regimes of their own. In particular, both branches of
    // `ak.self.moderation.report` are independent of Realm grants: ordinary
    // reports select `self_authored_proof`, while `provenance=mimi_facade`
    // selects `service_attested`. Requiring a covering grant after either
    // proof would make the closed conditional registry row impossible to
    // satisfy because no capability action is registered for this kind.
    let declared_admission = arkret_wire::EventKind::from(kind)
        .descriptor()
        .and_then(|descriptor| descriptor.admission);
    let independently_admitted = matches!(
        declared_admission,
        Some("self_authored_proof" | "service_attested" | "crypto_verifiable")
    ) || (declared_admission == Some("conditional")
        && kind == arkret_wire::event_kind_str::SELF_MODERATION_REPORT);
    if !realm_authority_root_authorized && !independently_admitted {
        // Restrictive effects are global across every effective grant whose
        // action/resource selector matches this operation. A second broad
        // allow grant must not bleach a field-scoped deny, quarantine, or
        // review requirement from another matching grant.
        if derived_cells.iter().any(|cell| {
            effective_by_id.values().any(|grant| {
                grant_matches_data_event_effect(state, grant, kind, realm_id, cell)
                    && grant_has_matching_restrictive_constraint(grant, &access)
            })
        }) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                "a matching capability constraint restricts this DataEvent",
            ));
        }
        for cell in derived_cells {
            let covering_grant = effective_by_id.values().find(|grant| {
                grant_covers_data_event_effect(state, grant, kind, realm_id, cell, &access)
            });
            let Some(covering_grant) = covering_grant else {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "capability_denied",
                    format!(
                        "no capability at seal_ref covers action {kind} on derived cell {cell}"
                    ),
                ));
            };
            used_grant_ids.insert(covering_grant.grant_id.clone());
        }
    }
    validate_data_event_revocation_freshness(
        state,
        &realm,
        &seal_id,
        kind,
        &state_at_ref,
        &used_grant_ids,
    )
}

/// `refs[]` entries carrying `role=authorized_by`.
///
/// `refs[]` is a required envelope member whose items are `SemanticRef`
/// objects; a malformed entry is a schema violation rather than a silently
/// skipped ref.
fn data_event_authorized_by_refs(
    object: &serde_json::Map<String, Value>,
) -> Result<Vec<String>, EventValidationError> {
    let Some(refs) = object.get("refs") else {
        return Ok(Vec::new());
    };
    let refs = refs.as_array().ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "refs must be an array of SemanticRef objects",
        )
    })?;
    let mut authorized_by = Vec::new();
    for reference in refs {
        let reference = reference.as_object().ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "refs[] entries must be SemanticRef objects",
            )
        })?;
        if reference.get("role").and_then(Value::as_str)
            != Some(arkret_wire::event_envelope::EVENT_REF_ROLE_AUTHORIZED_BY)
        {
            continue;
        }
        let id = reference.get("id").and_then(Value::as_str).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "refs[] entries require id",
            )
        })?;
        authorized_by.push(id.to_owned());
    }
    Ok(authorized_by)
}

fn validate_data_event_revocation_freshness(
    state: &AppState,
    realm: &RealmId,
    seal_ref: &arkret_identifiers::SealId,
    kind: &str,
    state_at_ref: &std::collections::BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::lattice::CellState,
    >,
    used_grant_ids: &std::collections::BTreeSet<String>,
) -> Result<(), EventValidationError> {
    if used_grant_ids.is_empty() {
        return Ok(());
    }
    let base_seal = state
        .projections()
        .seal_by_id(seal_ref)
        .map_err(|error| stale_seal_ref_error(format!("seal_ref lookup failed: {error}")))?
        .ok_or_else(|| stale_seal_ref_error("seal_ref is not projected"))?;
    let configured_window = realm_revocation_freshness_window_ms(state_at_ref);
    let effective_window =
        if data_event_authorization_is_high_risk(state_at_ref, used_grant_ids, kind) {
            0
        } else {
            configured_window
        };

    let mut queue = std::collections::VecDeque::from([seal_ref.clone()]);
    let mut visited = std::collections::BTreeSet::new();
    let mut first_revocation: Option<chrono::DateTime<chrono::Utc>> = None;
    while let Some(current) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        for successor in state
            .projections()
            .seal_successors(realm, &current)
            .map_err(|error| {
                stale_seal_ref_error(format!("Seal successor lookup failed: {error}"))
            })?
        {
            if visited.contains(&successor) {
                continue;
            }
            let successor_seal = state
                .projections()
                .seal_by_id(&successor)
                .map_err(|error| {
                    stale_seal_ref_error(format!("successor Seal lookup failed: {error}"))
                })?
                .ok_or_else(|| stale_seal_ref_error("successor Seal is not projected"))?;
            let successor_state = state
                .projections()
                .effective_state_at(std::slice::from_ref(&successor), realm)
                .map_err(|error| {
                    stale_seal_ref_error(format!(
                        "successor control view could not be resolved: {error}"
                    ))
                })?;
            if used_grant_ids.iter().any(|grant_id| {
                grant_invalid_in_state(&successor_state, grant_id, successor_seal.sealed_at)
            }) {
                first_revocation = Some(
                    first_revocation.map_or(successor_seal.sealed_at, |current| {
                        current.min(successor_seal.sealed_at)
                    }),
                );
            } else {
                queue.push_back(successor);
            }
        }
    }

    if let Some(revoked_at) = first_revocation {
        let distance = revoked_at.signed_duration_since(base_seal.sealed_at);
        if distance < chrono::Duration::zero() {
            return Err(stale_seal_ref_error(
                "revocation successor predates seal_ref signed time",
            ));
        }
        let distance_ms = u64::try_from(distance.num_milliseconds()).unwrap_or(u64::MAX);
        if distance_ms > effective_window || effective_window == 0 {
            return Err(stale_seal_ref_error(format!(
                "authorization was revoked {distance_ms}ms after seal_ref (window {effective_window}ms)"
            )));
        }
        return Ok(());
    }

    // A revoked joined view without a descendant revocation means the revoke
    // arrived on a concurrent branch. Such a branch has no linear distance and
    // receives no grace window.
    let leaves = state
        .projections()
        .realm_seal_leaves(realm)
        .map_err(|error| stale_seal_ref_error(format!("joined leaves unavailable: {error}")))?;
    if !leaves.is_empty() {
        let joined = state
            .projections()
            .effective_state_at(&leaves, realm)
            .map_err(|error| {
                stale_seal_ref_error(format!("joined control view unavailable: {error}"))
            })?;
        if used_grant_ids
            .iter()
            .any(|grant_id| grant_invalid_in_state(&joined, grant_id, base_seal.sealed_at))
        {
            return Err(stale_seal_ref_error(
                "authorization is revoked in a concurrent joined control view",
            ));
        }
    }
    Ok(())
}

fn grant_invalid_in_state(
    state: &std::collections::BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::lattice::CellState,
    >,
    grant_id: &str,
    sealed_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    let grants = data_event_grants_from_state_at_ref(state);
    let Some(grant) = grants.get(grant_id) else {
        return true;
    };
    let snapshot = grants.values().cloned().collect::<Vec<_>>();
    grant.revoked || crate::authz::grant_revoked_upstream(&snapshot, grant_id, sealed_at)
}

fn realm_revocation_freshness_window_ms(
    state: &std::collections::BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::lattice::CellState,
    >,
) -> u64 {
    state
        .values()
        .filter_map(|cell| match cell {
            arkret_state::lattice::CellState::Value(value) => value
                .get("revocation_freshness_window_ms")
                .and_then(Value::as_u64),
            arkret_state::lattice::CellState::Bottom(_) => None,
        })
        .next()
        .unwrap_or(86_400_000)
}

fn data_event_authorization_is_high_risk(
    state: &std::collections::BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::lattice::CellState,
    >,
    used_grant_ids: &std::collections::BTreeSet<String>,
    kind: &str,
) -> bool {
    let grants = data_event_grants_from_state_at_ref(state);
    used_grant_ids.iter().any(|grant_id| {
        grants.get(grant_id).is_none_or(|grant| {
            grant.actions.iter().any(|action| {
                arkret_schema::capability_action(action)
                    .map(|descriptor| {
                        descriptor.risk_tier == arkret_schema::CapabilityRiskTier::High
                    })
                    .unwrap_or(true)
            })
        })
    }) || arkret_schema::capability_action(kind)
        .is_some_and(|descriptor| descriptor.risk_tier == arkret_schema::CapabilityRiskTier::High)
}

fn stale_seal_ref_error(message: impl Into<String>) -> EventValidationError {
    event_validation_error(StatusCode::PRECONDITION_FAILED, "seal_ref_stale", message)
}

pub(super) fn data_event_state_at_seal_ref(
    state: &AppState,
    realm: &RealmId,
    seal_id: &arkret_identifiers::SealId,
) -> Result<
    std::collections::BTreeMap<arkret_identifiers::CellRef, arkret_state::lattice::CellState>,
    EventValidationError,
> {
    let seal = state.projections().seal_by_id(seal_id).map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            format!("DataEvent seal_ref lookup failed: {error}"),
        )
    })?;
    let Some(seal) = seal else {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "DataEvent seal_ref is not projected",
        ));
    };
    if seal.realm_id != *realm {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "DataEvent seal_ref does not belong to the event realm",
        ));
    }

    let state_at_ref = state
        .projections()
        .effective_state_at(std::slice::from_ref(seal_id), realm)
        .map_err(|error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent seal_ref pre-state could not be resolved: {error}"),
            )
        })?;

    Ok(state_at_ref)
}

pub(super) fn data_event_grants_from_state_at_ref(
    state_at_ref: &std::collections::BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::lattice::CellState,
    >,
) -> std::collections::BTreeMap<String, crate::authz::Grant> {
    let mut grants = std::collections::BTreeMap::new();
    const CAPABILITY_GRANT_CELL_PREFIX: &str = "ak:cell:ak.component.capability.grant.v1:";
    for (cell_ref, cell_state) in state_at_ref {
        let Some(grant_id) = cell_ref.as_str().strip_prefix(CAPABILITY_GRANT_CELL_PREFIX) else {
            continue;
        };
        if arkret_identifiers::GrantId::new(grant_id.to_owned()).is_err() {
            continue;
        }
        if let Some(grant) = soland_services::projection::engine_grant_from_capability_cell_state(
            grant_id, cell_state,
        ) {
            grants.insert(grant_id.to_owned(), grant);
        }
    }
    grants
}

pub(super) fn effective_historical_grants_for_subject(
    grants: &std::collections::BTreeMap<String, crate::authz::Grant>,
    actor_id: &str,
    principal_server_id: &str,
    realm_id: &str,
    auth_time: chrono::DateTime<chrono::Utc>,
) -> std::collections::BTreeMap<String, crate::authz::Grant> {
    let snapshot: Vec<crate::authz::Grant> = grants.values().cloned().collect();
    snapshot
        .iter()
        .filter(|grant| {
            grant.subject == actor_id
                && grant.subject_principal_server_id.as_deref() == Some(principal_server_id)
                && grant.realm_id == realm_id
                && !grant.revoked
                && crate::authz::grant_scope_valid(grant).is_ok()
                && !crate::authz::is_grant_expired(grant, auth_time)
                && crate::authz::authority_chain_intact(&snapshot, &grant.grant_id, auth_time)
        })
        .map(|grant| (grant.grant_id.clone(), grant.clone()))
        .collect()
}

pub(super) fn grant_covers_data_event_effect(
    state: &AppState,
    grant: &crate::authz::Grant,
    action: &str,
    realm_id: &str,
    cell: &str,
    access: &DataEventConstraintContext,
) -> bool {
    grant_matches_data_event_effect(state, grant, action, realm_id, cell)
        && grant_constraints_cover_data_event(grant, action, access)
}

fn grant_matches_data_event_effect(
    state: &AppState,
    grant: &crate::authz::Grant,
    action: &str,
    realm_id: &str,
    cell: &str,
) -> bool {
    grant.actions.iter().any(|candidate| {
        candidate == action
            || arkret_schema::capability_action(candidate).is_some_and(|descriptor| {
                descriptor.event_mapping_kind != "non_event_surface"
                    && descriptor.target_event_kinds.contains(&action)
            })
    }) && effect_resource_candidates(state, cell, realm_id)
        .iter()
        .any(|resource| crate::authz::resource_matches(&grant.resource, resource))
}

/// Receiver-derived authorization inputs for constraint evaluation.  Patch
/// fields come from the signed payload, never from producer-supplied effects.
/// A base Strand field has no track; only `tracks.<name>.*` contributes a
/// track target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct DataEventConstraintContext {
    write_fields: Vec<String>,
    strand_id: Option<String>,
    strand_tracks: Vec<String>,
}

fn data_event_constraint_context(
    kind: &str,
    object: &serde_json::Map<String, Value>,
) -> Option<DataEventConstraintContext> {
    let payload = object.get("payload")?.as_object()?;
    let mut write_fields = payload
        .get("patch")
        .and_then(Value::as_object)
        .map(|patch| patch.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    write_fields.sort();
    write_fields.dedup();

    let strand_id = payload
        .get("target_ref")
        .or_else(|| payload.get("strand_id"))
        .and_then(Value::as_str)
        .filter(|target| target.starts_with("ak:strand:"))
        .map(str::to_owned);
    let mut strand_tracks = Vec::new();
    for field in &write_fields {
        let mut segments = field.split('.');
        if segments.next() == Some("tracks") {
            let track = segments.next()?;
            if track.is_empty() {
                return None;
            }
            strand_tracks.push(track.to_owned());
        }
    }
    strand_tracks.sort();
    strand_tracks.dedup();

    // Every action registered as field-scoped must expose a non-empty patch
    // write set.  Otherwise accepting it would turn a required constraint
    // into an empty-subset bypass.
    if action_requires_constraint(kind, "allowed_write_fields") && write_fields.is_empty() {
        return None;
    }

    Some(DataEventConstraintContext {
        write_fields,
        strand_id,
        strand_tracks,
    })
}

fn action_requires_constraint(action: &str, required: &str) -> bool {
    arkret_schema::capability_action(action)
        .is_some_and(|descriptor| descriptor.required_constraints.contains(&required))
}

fn grant_constraints_cover_data_event(
    grant: &crate::authz::Grant,
    action: &str,
    access: &DataEventConstraintContext,
) -> bool {
    use crate::authz::{Constraint, GrantDecisionVerdict};

    let mut has_allowed_write_fields = false;
    for constraint in &grant.constraints {
        match constraint {
            Constraint::Decision { decision } => {
                if !matches!(decision, GrantDecisionVerdict::Allow) {
                    return false;
                }
            }
            Constraint::FieldAccess {
                effect,
                allowed_write_fields,
                denied_write_fields,
                condition,
                ..
            } => {
                // Named conditions require verified object state that this
                // admission context does not yet carry, so they fail closed.
                if condition.is_some() {
                    return false;
                }
                match effect {
                    GrantDecisionVerdict::Allow => {
                        if !allowed_write_fields.is_empty() {
                            has_allowed_write_fields = true;
                        }
                        if access.write_fields.iter().any(|field| {
                            denied_write_fields.iter().any(|denied| denied == field)
                                || (!allowed_write_fields.is_empty()
                                    && !allowed_write_fields.iter().any(|allowed| allowed == field))
                        }) {
                            return false;
                        }
                    }
                    GrantDecisionVerdict::Deny
                    | GrantDecisionVerdict::Quarantine
                    | GrantDecisionVerdict::RequireReview => {
                        if field_access_restrictive_effect_matches(
                            *effect,
                            allowed_write_fields,
                            denied_write_fields,
                            access,
                        ) {
                            return false;
                        }
                    }
                }
            }
            Constraint::ScopeLimitation {
                effect,
                allowed_strand_ids,
                denied_strand_ids,
                allowed_tracks,
                denied_tracks,
                ..
            } => match effect {
                GrantDecisionVerdict::Allow => {
                    if !scope_limitation_allows(
                        allowed_strand_ids,
                        denied_strand_ids,
                        allowed_tracks,
                        denied_tracks,
                        access,
                    ) {
                        return false;
                    }
                }
                GrantDecisionVerdict::Deny
                | GrantDecisionVerdict::Quarantine
                | GrantDecisionVerdict::RequireReview => {
                    if scope_limitation_restrictive_effect_matches(
                        *effect,
                        allowed_strand_ids,
                        denied_strand_ids,
                        allowed_tracks,
                        denied_tracks,
                        access,
                    ) {
                        return false;
                    }
                }
            },
            _ => {}
        }
    }

    !action_requires_constraint(action, "allowed_write_fields") || has_allowed_write_fields
}

fn grant_has_matching_restrictive_constraint(
    grant: &crate::authz::Grant,
    access: &DataEventConstraintContext,
) -> bool {
    use crate::authz::{Constraint, GrantDecisionVerdict};

    grant.constraints.iter().any(|constraint| match constraint {
        Constraint::Decision { decision } => !matches!(decision, GrantDecisionVerdict::Allow),
        Constraint::FieldAccess {
            effect,
            allowed_write_fields,
            denied_write_fields,
            condition,
            ..
        } => {
            if condition.is_some() {
                // This operation context cannot prove the named condition.
                // An indeterminate allow only makes this grant unsatisfied;
                // it must not globally block a separate satisfied grant.
                // Indeterminate restrictive effects still fail closed.
                return !matches!(effect, GrantDecisionVerdict::Allow);
            }
            field_access_restrictive_effect_matches(
                *effect,
                allowed_write_fields,
                denied_write_fields,
                access,
            )
        }
        Constraint::ScopeLimitation {
            effect,
            allowed_strand_ids,
            denied_strand_ids,
            allowed_tracks,
            denied_tracks,
            ..
        } => scope_limitation_restrictive_effect_matches(
            *effect,
            allowed_strand_ids,
            denied_strand_ids,
            allowed_tracks,
            denied_tracks,
            access,
        ),
        _ => false,
    })
}

fn field_access_restrictive_effect_matches(
    effect: crate::authz::GrantDecisionVerdict,
    allowed_write_fields: &[String],
    denied_write_fields: &[String],
    access: &DataEventConstraintContext,
) -> bool {
    use crate::authz::GrantDecisionVerdict;

    match effect {
        GrantDecisionVerdict::Allow => false,
        GrantDecisionVerdict::Deny => access
            .write_fields
            .iter()
            .any(|field| denied_write_fields.iter().any(|denied| denied == field)),
        GrantDecisionVerdict::Quarantine | GrantDecisionVerdict::RequireReview => {
            access.write_fields.iter().all(|field| {
                !denied_write_fields.iter().any(|denied| denied == field)
                    && (allowed_write_fields.is_empty()
                        || allowed_write_fields.iter().any(|allowed| allowed == field))
            })
        }
    }
}

fn scope_limitation_allows(
    allowed_strand_ids: &[String],
    denied_strand_ids: &[String],
    allowed_tracks: &[String],
    denied_tracks: &[String],
    access: &DataEventConstraintContext,
) -> bool {
    if let Some(strand_id) = access.strand_id.as_deref()
        && (denied_strand_ids.iter().any(|denied| denied == strand_id)
            || (!allowed_strand_ids.is_empty()
                && !allowed_strand_ids
                    .iter()
                    .any(|allowed| allowed == strand_id)))
    {
        return false;
    }
    // An empty track set means a base Strand operation. In particular,
    // Description `content` is not reclassified as synthesis.
    !access.strand_tracks.iter().any(|track| {
        denied_tracks.iter().any(|denied| denied == track)
            || (!allowed_tracks.is_empty()
                && !allowed_tracks.iter().any(|allowed| allowed == track))
    })
}

fn scope_limitation_restrictive_effect_matches(
    effect: crate::authz::GrantDecisionVerdict,
    allowed_strand_ids: &[String],
    denied_strand_ids: &[String],
    allowed_tracks: &[String],
    denied_tracks: &[String],
    access: &DataEventConstraintContext,
) -> bool {
    use crate::authz::GrantDecisionVerdict;

    match effect {
        GrantDecisionVerdict::Allow => false,
        GrantDecisionVerdict::Deny => {
            access
                .strand_id
                .as_deref()
                .is_some_and(|strand_id| denied_strand_ids.iter().any(|denied| denied == strand_id))
                || access
                    .strand_tracks
                    .iter()
                    .any(|track| denied_tracks.iter().any(|denied| denied == track))
        }
        GrantDecisionVerdict::Quarantine | GrantDecisionVerdict::RequireReview => {
            scope_limitation_allows(
                allowed_strand_ids,
                denied_strand_ids,
                allowed_tracks,
                denied_tracks,
                access,
            )
        }
    }
}

pub(super) fn effect_resource_candidates(
    state: &AppState,
    cell: &str,
    realm_id: &str,
) -> Vec<String> {
    let mut resources = Vec::new();
    let projection = state.projections().snapshot();
    append_authz_resource_candidates(&mut resources, Some(&projection), realm_id, realm_id);
    append_authz_resource_candidates(&mut resources, Some(&projection), realm_id, cell);
    let mut parts = cell.splitn(4, ':');
    if matches!(parts.next(), Some("ak"))
        && matches!(parts.next(), Some("cell"))
        && parts.next().is_some()
        && let Some(subject) = parts.next()
        && subject.starts_with("ak:")
    {
        append_authz_resource_candidates(&mut resources, Some(&projection), realm_id, subject);
    }
    resources.sort();
    resources.dedup();
    resources
}

pub(super) fn append_authz_resource_candidates(
    resources: &mut Vec<String>,
    projection: Option<&soland_services::projection::ProjectionSnapshot>,
    realm_id: &str,
    resource: &str,
) {
    resources.push(resource.to_owned());
    if let Some(projection) = projection {
        for candidate in projection
            .authz_resource_expr(realm_id, resource)
            .split(',')
        {
            let candidate = candidate.trim();
            if !candidate.is_empty() {
                resources.push(candidate.to_owned());
            }
        }
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::authz::{Constraint, GrantDecisionVerdict, projected_grant_fixture};

    const REALM: &str = "ak:realm:AX-N4k3nJ3KKtkbL-adKMKRyKUlTWlwhxQVvjmvEBEVB";
    const STRAND: &str = "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";

    fn grant(constraints: Vec<Constraint>) -> crate::authz::Grant {
        projected_grant_fixture(
            REALM.to_owned(),
            "ak:did_core:web:issuer.example".to_owned(),
            "ak:did_core:web:writer.example".to_owned(),
            STRAND.to_owned(),
            vec![arkret_wire::CapabilityActionId::STRAND_UPDATE.to_owned()],
            constraints,
        )
    }

    fn field_access(fields: &[&str]) -> Constraint {
        Constraint::FieldAccess {
            effect: GrantDecisionVerdict::Allow,
            allowed_write_fields: fields.iter().map(|field| (*field).to_owned()).collect(),
            denied_write_fields: Vec::new(),
            allowed_read_fields: Vec::new(),
            denied_read_fields: Vec::new(),
            condition: None,
        }
    }

    fn access(field: &str) -> DataEventConstraintContext {
        DataEventConstraintContext {
            write_fields: vec![field.to_owned()],
            strand_id: Some(STRAND.to_owned()),
            strand_tracks: field
                .strip_prefix("tracks.")
                .and_then(|suffix| suffix.split('.').next())
                .map(|track| vec![track.to_owned()])
                .unwrap_or_default(),
        }
    }

    #[test]
    fn signed_strand_patch_derives_description_and_synthesis_as_distinct_targets() {
        let description = serde_json::json!({
            "payload": {
                "target_ref": STRAND,
                "patch": { "content": { "$op": "unset" } }
            }
        });
        let description = data_event_constraint_context(
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            description.as_object().unwrap(),
        )
        .unwrap();
        assert_eq!(description.write_fields, ["content"]);
        assert!(description.strand_tracks.is_empty());

        let synthesis = serde_json::json!({
            "payload": {
                "target_ref": STRAND,
                "patch": {
                    "tracks.synthesis.encrypted_content": { "$op": "unset" }
                }
            }
        });
        let synthesis = data_event_constraint_context(
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            synthesis.as_object().unwrap(),
        )
        .unwrap();
        assert_eq!(
            synthesis.write_fields,
            ["tracks.synthesis.encrypted_content"]
        );
        assert_eq!(synthesis.strand_tracks, ["synthesis"]);
    }

    #[test]
    fn description_and_synthesis_write_grants_are_bidirectionally_isolated() {
        let description = grant(vec![field_access(&["content", "encrypted_content"])]);
        assert!(grant_constraints_cover_data_event(
            &description,
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            &access("content"),
        ));
        assert!(!grant_constraints_cover_data_event(
            &description,
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            &access("tracks.synthesis.content"),
        ));

        let synthesis = grant(vec![field_access(&[
            "tracks.synthesis.content",
            "tracks.synthesis.encrypted_content",
        ])]);
        assert!(grant_constraints_cover_data_event(
            &synthesis,
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            &access("tracks.synthesis.content"),
        ));
        assert!(!grant_constraints_cover_data_event(
            &synthesis,
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            &access("content"),
        ));
    }

    #[test]
    fn allowed_tracks_applies_only_to_track_targeted_paths() {
        let grant = grant(vec![
            field_access(&["content", "tracks.synthesis.content"]),
            Constraint::ScopeLimitation {
                effect: GrantDecisionVerdict::Allow,
                allowed_strand_ids: Vec::new(),
                denied_strand_ids: Vec::new(),
                allowed_tracks: vec!["synthesis".to_owned()],
                denied_tracks: Vec::new(),
                allowed_circle_ids: Default::default(),
                allowed_session_ids: Default::default(),
            },
        ]);
        assert!(grant_constraints_cover_data_event(
            &grant,
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            &access("content"),
        ));
        assert!(grant_constraints_cover_data_event(
            &grant,
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            &access("tracks.synthesis.content"),
        ));
        assert!(!grant_constraints_cover_data_event(
            &grant,
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            &access("tracks.discussion.metadata.topic"),
        ));
    }

    #[test]
    fn matching_deny_grant_cannot_be_bleached_by_a_separate_allow_grant() {
        let description_access = access("content");
        let allow = grant(vec![field_access(&["content"])]);
        let deny = grant(vec![Constraint::FieldAccess {
            effect: GrantDecisionVerdict::Deny,
            allowed_write_fields: Vec::new(),
            denied_write_fields: vec!["content".to_owned()],
            allowed_read_fields: Vec::new(),
            denied_read_fields: Vec::new(),
            condition: None,
        }]);

        assert!(grant_constraints_cover_data_event(
            &allow,
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            &description_access,
        ));
        assert!(grant_has_matching_restrictive_constraint(
            &deny,
            &description_access,
        ));

        let synthesis_access = access("tracks.synthesis.content");
        assert!(!grant_has_matching_restrictive_constraint(
            &deny,
            &synthesis_access,
        ));
    }

    #[test]
    fn indeterminate_allow_is_per_grant_not_a_global_restriction() {
        let description_access = access("content");
        let conditional_allow = grant(vec![Constraint::FieldAccess {
            effect: GrantDecisionVerdict::Allow,
            allowed_write_fields: vec!["content".to_owned()],
            denied_write_fields: Vec::new(),
            allowed_read_fields: Vec::new(),
            denied_read_fields: Vec::new(),
            condition: Some(serde_json::json!({"field": "metadata.fields.review_status"})),
        }]);

        assert!(!grant_constraints_cover_data_event(
            &conditional_allow,
            arkret_wire::CapabilityActionId::STRAND_UPDATE,
            &description_access,
        ));
        assert!(!grant_has_matching_restrictive_constraint(
            &conditional_allow,
            &description_access,
        ));
    }
}
