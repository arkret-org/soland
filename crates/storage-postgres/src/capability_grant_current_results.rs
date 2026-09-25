use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, CapabilityGrant, CapabilityGrantStatus, CapabilitySubject,
    GrantConstraintKind, IssuerAuthorityRef,
};
use arkret_wire::{
    ActorId, CommitStreamRef, CommittedEventRef, CurrentRevision, EventId, GrantId, RealmCommitId,
    RealmId, ResourceSelectorKind, WireResourceSelector,
};

use super::{
    AsyncPgConnection, BigInt, CapabilityGrantCurrentResultRecord,
    CapabilityGrantCurrentResultStore, CapabilityGrantCurrentStatus, Jsonb, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, QueryableByName, RunQueryDsl, Text, Timestamptz,
    async_trait, pg_conn, sql_query,
};

pub struct PgCapabilityGrantCurrentResultStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct CapabilityGrantCurrentResultReadRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    grant_id: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Text)]
    current_event_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = Jsonb)]
    current_stream_ref: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct RealmAuthorityRootReadRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    controller_actor_id: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    controller_epoch: i64,
    #[diesel(sql_type = BigInt)]
    authority_generation: i64,
    #[diesel(sql_type = Text)]
    authority_event_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RealmAuthorityRootCurrent {
    realm_id: RealmId,
    controller_actor_id: ActorId,
    controller_epoch: u64,
    authority_generation: u64,
    authority_event_ref: EventId,
}

fn corrupt(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Database(detail.into())
}

fn schema_violation(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.into())
}

fn conflict(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(detail.into())
}

fn u64_from_i64(value: i64, what: &str) -> PersistenceResult<u64> {
    u64::try_from(value).map_err(|_| corrupt(format!("stored {what} is negative")))
}

fn decode_authority_root(
    row: RealmAuthorityRootReadRow,
) -> PersistenceResult<RealmAuthorityRootCurrent> {
    Ok(RealmAuthorityRootCurrent {
        realm_id: RealmId::from_str(&row.realm_id).map_err(|error| {
            corrupt(format!(
                "stored authority-root Realm id is invalid: {error}"
            ))
        })?,
        controller_actor_id: serde_json::from_value(row.controller_actor_id).map_err(|error| {
            corrupt(format!(
                "stored authority-root controller is invalid: {error}"
            ))
        })?,
        controller_epoch: u64_from_i64(row.controller_epoch, "authority-root controller epoch")?,
        authority_generation: u64_from_i64(row.authority_generation, "authority-root generation")?,
        authority_event_ref: EventId::from_str(&row.authority_event_ref).map_err(|error| {
            corrupt(format!(
                "stored authority-root Event ref is invalid: {error}"
            ))
        })?,
    })
}

async fn locked_authority_root(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Option<RealmAuthorityRootCurrent>> {
    sql_query(
        "SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref \
         FROM realm_authority_root_current_results WHERE realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RealmAuthorityRootReadRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_authority_root)
    .transpose()
}

fn safe_i64(value: u64, what: &str) -> PersistenceResult<i64> {
    i64::try_from(value)
        .map_err(|_| schema_violation(format!("{what} exceeds the JSON safe-integer range")))
}

/// Keep the Realm delegation root as a durable typed current result. This is
/// deliberately separate from `realm_authorities`, whose generation belongs
/// to governance-Station tenure and must never invalidate capability grants.
pub(crate) async fn commit_realm_authority_root_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let current = match event.kind {
        arkret_wire::EventKind::RealmCreate => {
            if locked_authority_root(conn, &event.realm_id)
                .await?
                .is_some()
            {
                return Err(conflict("realm_authority_root_conflict"));
            }
            RealmAuthorityRootCurrent {
                realm_id: event.realm_id.clone(),
                controller_actor_id: event.actor_id.clone(),
                controller_epoch: 0,
                authority_generation: 0,
                authority_event_ref: event.event_id.clone(),
            }
        }
        arkret_wire::EventKind::RealmOwnerTransfer => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::realm::RealmOwnerTransferPayload,
            >(serde_json::Value::Object(
                event.payload.clone().into_iter().collect(),
            ))
            .map_err(|error| {
                schema_violation(format!("Realm owner transfer payload is invalid: {error}"))
            })?;
            if payload.realm_id != event.realm_id {
                return Err(schema_violation(
                    "Realm owner transfer targets another Realm",
                ));
            }
            let mut current = locked_authority_root(conn, &event.realm_id)
                .await?
                .ok_or_else(|| conflict("realm_authority_root_missing"))?;
            let digest = arkret_canonical::canonical_sha256(&serde_json::json!({
                "controller_actor_id": current.controller_actor_id,
                "controller_epoch": current.controller_epoch,
                "authority_generation": current.authority_generation,
            }))
            .map_err(PersistenceError::database)?;
            if digest.as_str() != payload.expected_state_digest.as_str() {
                return Err(conflict("realm_authority_root_conflict"));
            }
            current.controller_actor_id = payload.patch.controller_actor_id;
            current.controller_epoch = arkret_models_collaboration::events_payloads::realm::RealmOwnerTransferPayload::successor_controller_epoch(current.controller_epoch)
                .map_err(|_| conflict("realm_authority_root_conflict"))?;
            current
        }
        arkret_wire::EventKind::RealmAuthorityReset => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::realm::RealmAuthorityResetPayload,
            >(serde_json::Value::Object(
                event.payload.clone().into_iter().collect(),
            ))
            .map_err(|error| {
                schema_violation(format!("Realm authority reset payload is invalid: {error}"))
            })?;
            if payload.realm_id != event.realm_id {
                return Err(schema_violation(
                    "Realm authority reset targets another Realm",
                ));
            }
            let mut current = locked_authority_root(conn, &event.realm_id)
                .await?
                .ok_or_else(|| conflict("realm_authority_root_missing"))?;
            let digest = arkret_canonical::canonical_sha256(&serde_json::json!({
                "controller_actor_id": current.controller_actor_id,
                "controller_epoch": current.controller_epoch,
                "authority_generation": current.authority_generation,
            }))
            .map_err(PersistenceError::database)?;
            if digest.as_str() != payload.expected_state_digest.as_str() {
                return Err(conflict("realm_authority_root_conflict"));
            }
            current.authority_generation = arkret_models_collaboration::events_payloads::realm::RealmAuthorityResetPayload::successor_authority_generation(current.authority_generation)
                .map_err(|_| conflict("realm_authority_root_conflict"))?;
            current.authority_event_ref = event.event_id.clone();
            current
        }
        _ => return Ok(()),
    };

    sql_query(
        "INSERT INTO realm_authority_root_current_results \
         (realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref,current_commit_id,current_stream_position,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8) \
         ON CONFLICT(realm_id) DO UPDATE SET controller_actor_id=EXCLUDED.controller_actor_id, \
         controller_epoch=EXCLUDED.controller_epoch,authority_generation=EXCLUDED.authority_generation, \
         authority_event_ref=EXCLUDED.authority_event_ref,current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(current.realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&current.controller_actor_id).map_err(PersistenceError::database)?)
    .bind::<BigInt, _>(safe_i64(current.controller_epoch, "controller_epoch")?)
    .bind::<BigInt, _>(safe_i64(current.authority_generation, "authority_generation")?)
    .bind::<Text, _>(current.authority_event_ref.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(safe_i64(commit.stream_position, "stream_position")?)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

fn decode_row(
    row: CapabilityGrantCurrentResultReadRow,
) -> PersistenceResult<CapabilityGrantCurrentResultRecord> {
    let realm_id = RealmId::from_str(&row.realm_id).map_err(|error| {
        corrupt(format!(
            "stored Capability Grant Realm id is invalid: {error}"
        ))
    })?;
    let grant_id = GrantId::from_str(&row.grant_id)
        .map_err(|error| corrupt(format!("stored Capability Grant id is invalid: {error}")))?;
    let status = CapabilityGrantCurrentStatus::from_str(&row.status)?;
    let stream_position = u64::try_from(row.current_stream_position)
        .map_err(|_| corrupt("stored Capability Grant stream position is negative"))?;
    let commit_id = RealmCommitId::from_str(&row.current_commit_id).map_err(|error| {
        corrupt(format!(
            "stored Capability Grant Commit id is invalid: {error}"
        ))
    })?;
    let event_id = EventId::from_str(&row.current_event_id).map_err(|error| {
        corrupt(format!(
            "stored Capability Grant source Event id is invalid: {error}"
        ))
    })?;
    let stream_ref =
        serde_json::from_value::<CommitStreamRef>(row.current_stream_ref).map_err(|error| {
            corrupt(format!(
                "stored Capability Grant stream ref is invalid: {error}"
            ))
        })?;
    CapabilityGrantCurrentResultRecord::try_new(
        realm_id,
        grant_id,
        status,
        row.value,
        CurrentRevision {
            commit_id: commit_id.clone(),
            stream_position,
        },
        CommittedEventRef {
            event_id,
            commit_id,
            stream_ref,
            stream_position,
        },
    )
}

fn effective_not_before(grant: &CapabilityGrant) -> Option<chrono::DateTime<chrono::Utc>> {
    grant
        .constraints
        .iter()
        .filter(|constraint| constraint.constraint_kind == GrantConstraintKind::Temporal)
        .filter_map(|constraint| constraint.not_before)
        .max()
}

fn effective_expires_at(grant: &CapabilityGrant) -> Option<chrono::DateTime<chrono::Utc>> {
    grant
        .constraints
        .iter()
        .filter(|constraint| constraint.constraint_kind == GrantConstraintKind::Temporal)
        .filter_map(|constraint| constraint.expires_at)
        .min()
}

fn ordinary_authority_control(
    grant: &CapabilityGrant,
) -> Option<&arkret_models_collaboration::governance::grant_constraint::GrantConstraint> {
    grant.constraints.iter().find(|constraint| {
        constraint.constraint_kind == GrantConstraintKind::AuthorityControl
            && constraint.constraint_subkind.is_none()
    })
}

fn selector_covers(parent: &WireResourceSelector, child: &WireResourceSelector) -> bool {
    if parent.kind == ResourceSelectorKind::All {
        return false;
    }
    let parent_value = match serde_json::to_value(parent) {
        Ok(serde_json::Value::Object(value)) => value,
        _ => return false,
    };
    let child_value = match serde_json::to_value(child) {
        Ok(serde_json::Value::Object(value)) => value,
        _ => return false,
    };
    let same_kind = parent.kind == child.kind;
    let realm_parent = parent.kind == ResourceSelectorKind::Realm
        && matches!(
            child.kind,
            ResourceSelectorKind::Realm
                | ResourceSelectorKind::Space
                | ResourceSelectorKind::Circle
                | ResourceSelectorKind::Strand
                | ResourceSelectorKind::Message
                | ResourceSelectorKind::Morph
                | ResourceSelectorKind::Object
                | ResourceSelectorKind::Relation
                | ResourceSelectorKind::View
                | ResourceSelectorKind::Event
                | ResourceSelectorKind::Policy
                | ResourceSelectorKind::Invite
                | ResourceSelectorKind::Notification
                | ResourceSelectorKind::ReadCursor
                | ResourceSelectorKind::Blob
        );
    if !same_kind && !realm_parent {
        return false;
    }
    if let Some(parent_realm) = parent_value.get("realm_id")
        && child_value.get("realm_id") != Some(parent_realm)
        && !(child.kind == ResourceSelectorKind::Realm
            && child_value.get("realm_id") == Some(parent_realm))
    {
        return false;
    }
    if realm_parent {
        return true;
    }
    parent_value.iter().all(|(key, value)| {
        matches!(key.as_str(), "kind" | "match_scope" | "realm_id")
            || child_value.get(key) == Some(value)
    })
}

fn grant_is_active_at(grant: &CapabilityGrant, accepted_at: chrono::DateTime<chrono::Utc>) -> bool {
    grant.status == CapabilityGrantStatus::Active
        && effective_not_before(grant).is_none_or(|value| value <= accepted_at)
        && effective_expires_at(grant).is_none_or(|value| value > accepted_at)
}

/// Whether `actor` may exercise one of `actions` over the whole Realm at this
/// transaction's cut: it is the current Realm root controller, or it is the
/// Actor subject of an active Capability Grant naming one of the actions on a
/// selector that covers the Realm, whose temporal window contains `at`, whose
/// other constraints are absent, and whose issuer chain is intact against the
/// current root.
///
/// The Realm root and every grant are Realm-stream typed current results, so a
/// commit transaction holding the Realm authority lock reads a stable cut, and
/// a REPEATABLE READ snapshot reads the same cut without row locks.
pub(crate) async fn actor_holds_realm_action_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    actor: &ActorId,
    actions: &[&str],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    let Some(root) = sql_query(
        "SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref \
         FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RealmAuthorityRootReadRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_authority_root)
    .transpose()?
    else {
        return Ok(false);
    };
    if &root.controller_actor_id == actor {
        return Ok(true);
    }
    let stored = sql_query(
        "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
         current_stream_position,value FROM capability_grant_current_results \
         WHERE realm_id=$1 ORDER BY grant_id ASC",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut rows = BTreeMap::new();
    for row in stored {
        let record = decode_row(row)?;
        let grant = serde_json::from_value::<CapabilityGrant>(record.value).map_err(|error| {
            corrupt(format!(
                "stored Capability Grant current value is invalid: {error}"
            ))
        })?;
        rows.insert(record.grant_id, grant);
    }
    let realm = WireResourceSelector::realm(realm_id.clone());
    for (grant_id, grant) in &rows {
        let covers = matches!(&grant.subject, CapabilitySubject::Actor(subject) if subject == actor)
            && grant.realm_id.as_ref() == Some(realm_id)
            && grant_is_active_at(grant, at)
            && grant
                .constraints
                .iter()
                .all(|constraint| constraint.constraint_kind == GrantConstraintKind::Temporal)
            && grant
                .actions
                .iter()
                .any(|action| actions.contains(&action.as_str()))
            && grant
                .resources
                .iter()
                .any(|resource| selector_covers(resource, &realm));
        if !covers {
            continue;
        }
        let chain_intact = grant.issuer_authority_refs.iter().all(|authority_ref| {
            match authority_ref {
                IssuerAuthorityRef::RealmRoot {
                    realm_id: root_realm_id,
                    authority_event_ref,
                    authority_generation,
                } => {
                    root_realm_id == realm_id
                        && root.authority_event_ref == *authority_event_ref
                        && root.authority_generation == *authority_generation
                }
                IssuerAuthorityRef::Grant {
                    grant_id: parent_id,
                } => rows.get(parent_id).is_some_and(|parent| {
                    matches!(&parent.subject, CapabilitySubject::Actor(subject) if subject == &grant.issuer_id)
                }) && validate_ancestor_graph(
                    grant_id,
                    parent_id,
                    &rows,
                    &root,
                    realm_id,
                    at,
                    &mut BTreeSet::new(),
                    1,
                )
                .is_ok(),
            }
        });
        if chain_intact && !grant.issuer_authority_refs.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn root_sort_key(root: &AuthorityRootRef) -> PersistenceResult<Vec<u8>> {
    arkret_canonical::canonical_json_bytes(root).map_err(PersistenceError::database)
}

fn sorted_unique_roots(
    roots: impl IntoIterator<Item = AuthorityRootRef>,
) -> PersistenceResult<Vec<AuthorityRootRef>> {
    let mut keyed = roots
        .into_iter()
        .map(|root| Ok((root_sort_key(&root)?, root)))
        .collect::<PersistenceResult<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    Ok(keyed.into_iter().map(|(_, root)| root).collect())
}

fn validate_ancestor_graph(
    child_id: &GrantId,
    current_id: &GrantId,
    rows: &BTreeMap<GrantId, CapabilityGrant>,
    root: &RealmAuthorityRootCurrent,
    realm_id: &RealmId,
    accepted_at: chrono::DateTime<chrono::Utc>,
    visiting: &mut BTreeSet<GrantId>,
    depth: u64,
) -> PersistenceResult<()> {
    if depth > 4 || current_id == child_id || !visiting.insert(current_id.clone()) {
        return Err(conflict("authority_cycle"));
    }
    let parent = rows
        .get(current_id)
        .ok_or_else(|| conflict("grant_exceeds_issuer_authority"))?;
    if parent.realm_id.as_ref() != Some(realm_id) || !grant_is_active_at(parent, accepted_at) {
        return Err(conflict("grant_revoked_upstream"));
    }
    for authority_ref in &parent.issuer_authority_refs {
        match authority_ref {
            IssuerAuthorityRef::RealmRoot {
                realm_id: root_realm_id,
                authority_event_ref,
                authority_generation,
            } => {
                if root_realm_id != realm_id
                    || root.realm_id != *root_realm_id
                    || root.authority_event_ref != *authority_event_ref
                    || root.authority_generation != *authority_generation
                {
                    return Err(conflict("grant_revoked_upstream"));
                }
            }
            IssuerAuthorityRef::Grant { grant_id } => {
                let ancestor = rows
                    .get(grant_id)
                    .ok_or_else(|| conflict("grant_revoked_upstream"))?;
                if !matches!(&ancestor.subject, CapabilitySubject::Actor(actor) if actor == &parent.issuer_id)
                {
                    return Err(conflict("grant_exceeds_issuer_authority"));
                }
                validate_ancestor_graph(
                    child_id,
                    grant_id,
                    rows,
                    root,
                    realm_id,
                    accepted_at,
                    visiting,
                    depth + 1,
                )?;
            }
        }
    }
    visiting.remove(current_id);
    Ok(())
}

fn parent_covers(
    parent: &CapabilityGrant,
    child_action: &str,
    child_resource: &WireResourceSelector,
) -> bool {
    parent.actions.iter().any(|action| {
        arkret_policy::action_grants_authority_for(action, child_action).unwrap_or(false)
    }) && parent
        .resources
        .iter()
        .any(|resource| selector_covers(resource, child_resource))
}

fn validate_parent_constraints(
    parent: &CapabilityGrant,
    child: &arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
) -> PersistenceResult<()> {
    let Some(control) = ordinary_authority_control(parent) else {
        return Err(conflict("authority_regrant_denied"));
    };
    let child_control = child.constraints.iter().find(|constraint| {
        constraint.constraint_kind == GrantConstraintKind::AuthorityControl
            && constraint.constraint_subkind.is_none()
    });
    let regrant_allowed = control.authority_regrant_allowed.unwrap_or(false);
    if control.max_authority_depth == Some(0) {
        return Err(conflict(if regrant_allowed {
            "authority_depth_exceeded"
        } else {
            "authority_regrant_denied"
        }));
    }
    if !regrant_allowed {
        if child_control.is_none_or(|child| {
            child.max_authority_depth != Some(0) || child.authority_regrant_allowed.unwrap_or(false)
        }) {
            return Err(conflict("authority_regrant_denied"));
        }
    } else if let Some(parent_depth) = control.max_authority_depth {
        if child_control
            .and_then(|child| child.max_authority_depth)
            .is_none_or(|child_depth| child_depth > parent_depth.saturating_sub(1))
        {
            return Err(conflict("authority_depth_exceeded"));
        }
    }
    if let Some(parent_expiry) = effective_expires_at(parent) {
        let child_expiry = child
            .constraints
            .iter()
            .filter(|constraint| constraint.constraint_kind == GrantConstraintKind::Temporal)
            .filter_map(|constraint| constraint.expires_at)
            .min();
        if child_expiry.is_none_or(|value| value > parent_expiry) {
            return Err(conflict("authority_expiry_widening"));
        }
    }
    // A complete semantic partial-order over every constraint family belongs
    // in the policy crate. Until it is available, fail closed unless every
    // deny/require/quarantine parent constraint is preserved byte-for-byte.
    for constraint in parent.constraints.iter().filter(|constraint| {
        !matches!(
            constraint.effect,
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintEffect::Allow
        )
    }) {
        if !child.constraints.contains(constraint) {
            return Err(schema_violation("grant constraints widen parent authority"));
        }
    }
    Ok(())
}

enum CapabilityGrantCurrentMutation {
    Create {
        grant_id: GrantId,
        body: arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
    },
    Close {
        grant_id: GrantId,
        expected_revision: CurrentRevision,
        status: CapabilityGrantCurrentStatus,
    },
}

fn mutation_for_event(
    event: &arkret_wire::Event,
) -> PersistenceResult<Option<CapabilityGrantCurrentMutation>> {
    let invalid = |what: &str, error: serde_json::Error| {
        schema_violation(format!(
            "{what} payload violates its typed SDK contract: {error}"
        ))
    };
    let payload_value = || serde_json::Value::Object(event.payload.clone().into_iter().collect());
    match event.kind {
        arkret_wire::EventKind::CapabilityGrant => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::CapabilityGrantPayload,
            >(payload_value())
            .map_err(|error| invalid("Capability Grant", error))?;
            if payload.grant.schema != arkret_wire::SchemaId::CAPABILITY_V1
                || payload.grant.issuer_id != event.actor_id
                || payload
                    .grant
                    .realm_id
                    .as_ref()
                    .is_some_and(|realm_id| realm_id != &event.realm_id)
            {
                return Err(schema_violation(
                    "Capability Grant authoring body does not match its Event envelope",
                ));
            }
            let grant_id = GrantId::from_event_id(&event.event_id);
            Ok(Some(CapabilityGrantCurrentMutation::Create {
                grant_id,
                body: payload.grant,
            }))
        }
        arkret_wire::EventKind::CapabilityRevoke => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::CapabilityRevokePayload,
            >(payload_value())
            .map_err(|error| invalid("Capability Revoke", error))?;
            Ok(Some(CapabilityGrantCurrentMutation::Close {
                grant_id: payload.grant_id,
                expected_revision: payload.expected_revision,
                status: CapabilityGrantCurrentStatus::Revoked,
            }))
        }
        arkret_wire::EventKind::CapabilityRelinquish => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::CapabilityRelinquishPayload,
            >(payload_value())
            .map_err(|error| invalid("Capability Relinquish", error))?;
            Ok(Some(CapabilityGrantCurrentMutation::Close {
                grant_id: payload.grant_id,
                expected_revision: payload.expected_revision,
                status: CapabilityGrantCurrentStatus::Relinquished,
            }))
        }
        _ => Ok(None),
    }
}

fn revision_matches(
    current: &CapabilityGrantCurrentResultRecord,
    expected: &CurrentRevision,
) -> bool {
    current.revision == *expected
}

async fn materialize_capability_grant(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    grant_id: GrantId,
    body: arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
) -> PersistenceResult<serde_json::Value> {
    if body.issuer_authority_refs.is_empty() {
        return Err(schema_violation(
            "Capability Grant authority refs are empty",
        ));
    }
    let child_expiry = body
        .constraints
        .iter()
        .filter(|constraint| constraint.constraint_kind == GrantConstraintKind::Temporal)
        .filter_map(|constraint| constraint.expires_at)
        .min();
    if child_expiry.is_some_and(|expires_at| expires_at <= commit.committed_at) {
        return Err(conflict("grant_exceeds_issuer_authority"));
    }

    // The Realm authority row already serializes commits, while this ordered
    // lock snapshot gives every grant dependency one deterministic database
    // basis. No process-local projection participates in admission.
    let locked_rows = sql_query(
        "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
         current_stream_position,value FROM capability_grant_current_results \
         WHERE realm_id=$1 ORDER BY grant_id ASC FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .load::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut rows = BTreeMap::new();
    for row in locked_rows {
        let record = decode_row(row)?;
        let grant = serde_json::from_value::<CapabilityGrant>(record.value).map_err(|error| {
            corrupt(format!(
                "stored Capability Grant current value is invalid: {error}"
            ))
        })?;
        if rows.insert(record.grant_id, grant).is_some() {
            return Err(corrupt("duplicate Capability Grant current row"));
        }
    }

    let root = locked_authority_root(conn, &event.realm_id)
        .await?
        .ok_or_else(|| conflict("realm_authority_root_missing"))?;

    let mut seen_refs = BTreeSet::new();
    let mut parent_ids = Vec::new();
    let mut roots = Vec::new();
    let mut deepest = 0_u64;
    for authority_ref in &body.issuer_authority_refs {
        let key = arkret_canonical::canonical_json_bytes(authority_ref)
            .map_err(PersistenceError::database)?;
        if !seen_refs.insert(key) {
            return Err(schema_violation(
                "Capability Grant authority refs are duplicated",
            ));
        }
        match authority_ref {
            IssuerAuthorityRef::RealmRoot {
                realm_id,
                authority_event_ref,
                authority_generation,
            } => {
                if realm_id != &event.realm_id {
                    return Err(conflict("grant_exceeds_issuer_authority"));
                }
                if root.realm_id != *realm_id
                    || root.controller_actor_id != body.issuer_id
                    || root.authority_event_ref != *authority_event_ref
                    || root.authority_generation != *authority_generation
                {
                    return Err(conflict("realm_authority_controller_mismatch"));
                }
                roots.push(AuthorityRootRef::RealmRoot {
                    realm_id: realm_id.clone(),
                    authority_event_ref: authority_event_ref.clone(),
                    authority_generation: *authority_generation,
                });
            }
            IssuerAuthorityRef::Grant {
                grant_id: parent_id,
            } => {
                let parent = rows
                    .get(parent_id)
                    .ok_or_else(|| conflict("grant_exceeds_issuer_authority"))?;
                if parent.realm_id.as_ref() != Some(&event.realm_id)
                    || !matches!(&parent.subject, CapabilitySubject::Actor(actor) if actor == &body.issuer_id)
                    || !grant_is_active_at(parent, commit.committed_at)
                {
                    return Err(conflict("grant_exceeds_issuer_authority"));
                }
                validate_parent_constraints(parent, &body)?;
                deepest = deepest.max(parent.authority_depth);
                roots.extend(parent.authority_root_refs.iter().cloned());
                parent_ids.push(parent_id.clone());
            }
        }
    }

    for parent_id in &parent_ids {
        validate_ancestor_graph(
            &grant_id,
            parent_id,
            &rows,
            &root,
            &event.realm_id,
            commit.committed_at,
            &mut BTreeSet::new(),
            1,
        )?;
    }
    let authority_depth = deepest
        .checked_add(1)
        .filter(|depth| *depth <= 4)
        .ok_or_else(|| conflict("authority_depth_exceeded"))?;
    let authority_root_refs = sorted_unique_roots(roots)?;
    if authority_root_refs.is_empty() {
        return Err(conflict("grant_exceeds_issuer_authority"));
    }

    let mut ref_contributed = vec![false; body.issuer_authority_refs.len()];
    for action in &body.actions {
        for resource in &body.resources {
            let mut covered = false;
            for (index, authority_ref) in body.issuer_authority_refs.iter().enumerate() {
                let ref_covers = match authority_ref {
                    IssuerAuthorityRef::RealmRoot { .. } => {
                        arkret_policy::owner_may_grant(action).unwrap_or(false)
                    }
                    IssuerAuthorityRef::Grant { grant_id } => rows
                        .get(grant_id)
                        .is_some_and(|parent| parent_covers(parent, action, resource)),
                };
                if ref_covers {
                    covered = true;
                    ref_contributed[index] = true;
                }
            }
            if !covered {
                return Err(conflict("grant_exceeds_issuer_authority"));
            }
        }
    }
    if ref_contributed.iter().any(|contributed| !contributed) {
        return Err(schema_violation(
            "Capability Grant carries a redundant authority ref",
        ));
    }

    let grant = CapabilityGrant {
        id: grant_id,
        schema: body.schema,
        realm_id: Some(event.realm_id.clone()),
        issuer_id: body.issuer_id,
        subject: body.subject,
        actions: body.actions,
        resources: body.resources,
        constraints: body.constraints,
        issuer_authority_refs: body.issuer_authority_refs,
        authority_depth,
        authority_root_refs,
        issued_at: body.issued_at,
        status: CapabilityGrantStatus::Active,
        updated_by: None,
        updated_at: None,
        revoked_by: None,
        revoked_at: None,
    };
    serde_json::to_value(grant).map_err(PersistenceError::database)
}

/// Materialize one of the four registered `capability_grant` writers inside
/// the same PostgreSQL transaction as its Event and RealmCommit.
pub(crate) async fn commit_capability_grant_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let Some(mutation) = mutation_for_event(event)? else {
        return Ok(());
    };
    let grant_id = match &mutation {
        CapabilityGrantCurrentMutation::Create { grant_id, .. }
        | CapabilityGrantCurrentMutation::Close { grant_id, .. } => grant_id.clone(),
    };
    let lock_key = format!("capability-grant:{}:{}", event.realm_id, grant_id);
    // `pg_advisory_xact_lock` waits until it holds the lock (or the statement
    // fails), and returns `void`, so there is no "not acquired" result to test.
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(&lock_key)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

    let current = sql_query(
        "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
         current_stream_position,value FROM capability_grant_current_results \
         WHERE realm_id=$1 AND grant_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(grant_id.as_str())
    .get_result::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_row)
    .transpose()?;

    let (status, value) = match (mutation, current.as_ref()) {
        (CapabilityGrantCurrentMutation::Create { grant_id, body }, None) => (
            CapabilityGrantCurrentStatus::Active,
            materialize_capability_grant(conn, event, commit, grant_id, body).await?,
        ),
        (CapabilityGrantCurrentMutation::Create { .. }, Some(_)) => {
            return Err(conflict(
                "failed_precondition: Capability Grant current result already exists",
            ));
        }
        (
            CapabilityGrantCurrentMutation::Close {
                grant_id,
                expected_revision,
                status,
            },
            Some(current),
        ) => {
            if current.status != CapabilityGrantCurrentStatus::Active
                || !revision_matches(current, &expected_revision)
            {
                return Err(conflict(
                    "cas_conflict: Capability Grant current revision does not match",
                ));
            }
            let typed = serde_json::from_value::<CapabilityGrant>(current.value.clone()).map_err(
                |error| {
                    corrupt(format!(
                        "stored Capability Grant current value is invalid: {error}"
                    ))
                },
            )?;
            if typed.id != grant_id
                || typed.realm_id.as_ref() != Some(&event.realm_id)
                || typed.status != CapabilityGrantStatus::Active
            {
                return Err(corrupt(
                    "stored Capability Grant current value disagrees with its authoritative row",
                ));
            }
            let mut value = current.value.clone();
            let object = value
                .as_object_mut()
                .ok_or_else(|| corrupt("stored Capability Grant current value is not an object"))?;
            object.insert(
                "status".to_owned(),
                serde_json::Value::String(status.as_str().to_owned()),
            );
            match status {
                CapabilityGrantCurrentStatus::Revoked => {
                    object.insert(
                        "revoked_by".to_owned(),
                        serde_json::to_value(&event.actor_id)
                            .map_err(PersistenceError::database)?,
                    );
                    object.insert(
                        "revoked_at".to_owned(),
                        serde_json::to_value(event.created_at)
                            .map_err(PersistenceError::database)?,
                    );
                }
                CapabilityGrantCurrentStatus::Relinquished => {
                    object.insert(
                        "updated_by".to_owned(),
                        serde_json::to_value(&event.actor_id)
                            .map_err(PersistenceError::database)?,
                    );
                    object.insert(
                        "updated_at".to_owned(),
                        serde_json::to_value(event.created_at)
                            .map_err(PersistenceError::database)?,
                    );
                }
                CapabilityGrantCurrentStatus::Active => unreachable!("close cannot remain active"),
            }
            (status, value)
        }
        (CapabilityGrantCurrentMutation::Close { .. }, None) => {
            return Err(conflict(
                "failed_precondition: Capability Grant current result does not exist",
            ));
        }
    };

    let stream_position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::Internal(
            "Capability Grant stream position exceeds PostgreSQL BIGINT".to_owned(),
        )
    })?;
    let stream_ref =
        serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?;
    sql_query(
        "INSERT INTO capability_grant_current_results \
         (realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
          current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT(realm_id,grant_id) DO UPDATE SET \
           status=EXCLUDED.status,current_event_id=EXCLUDED.current_event_id, \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_ref=EXCLUDED.current_stream_ref, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(grant_id.as_str())
    .bind::<Text, _>(status.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Jsonb, _>(&stream_ref)
    .bind::<BigInt, _>(stream_position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

#[async_trait]
impl CapabilityGrantCurrentResultStore for PgCapabilityGrantCurrentResultStore {
    async fn get(
        &self,
        realm_id: &RealmId,
        grant_id: &GrantId,
    ) -> PersistenceResult<Option<CapabilityGrantCurrentResultRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value \
             FROM capability_grant_current_results WHERE realm_id=$1 AND grant_id=$2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(grant_id.as_str())
        .get_result::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_row)
        .transpose()
    }

    async fn snapshot_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> PersistenceResult<Vec<CapabilityGrantCurrentResultRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value \
             FROM capability_grant_current_results WHERE realm_id=$1 ORDER BY grant_id ASC",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(decode_row)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM_ID: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const GRANT_ID: &str = "ak:grant:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
    const COMMIT_ID: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";

    fn selector(value: serde_json::Value) -> WireResourceSelector {
        serde_json::from_value(value).expect("valid selector")
    }

    #[test]
    fn durable_ceiling_selector_match_is_narrowing_only() {
        let realm = selector(serde_json::json!({"kind":"realm","realm_id":REALM_ID}));
        let exact_realm = selector(serde_json::json!({"kind":"realm","realm_id":REALM_ID}));
        let other_realm = selector(serde_json::json!({
            "kind":"realm",
            "realm_id":"ak:realm:ASm71QhtF54BxHBvRFcIhmLfPFYTrXhTcLnVAEMmqZ5t"
        }));
        assert!(selector_covers(&realm, &exact_realm));
        assert!(!selector_covers(&realm, &other_realm));

        let any_strand = selector(serde_json::json!({"kind":"strand","realm_id":REALM_ID}));
        let exact_strand = selector(serde_json::json!({
            "kind":"strand",
            "realm_id":REALM_ID,
            // A Strand id retypes its creating Event's id.
            "strand_id":arkret_wire::StrandId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x51; 32],
            )),
        }));
        assert!(selector_covers(&any_strand, &exact_strand));
        assert!(!selector_covers(&exact_strand, &any_strand));
    }

    fn row(status: &str) -> CapabilityGrantCurrentResultReadRow {
        CapabilityGrantCurrentResultReadRow {
            realm_id: REALM_ID.to_owned(),
            grant_id: GRANT_ID.to_owned(),
            status: status.to_owned(),
            current_event_id: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x44; 32],
            )
            .to_string(),
            current_commit_id: COMMIT_ID.to_owned(),
            current_stream_ref: serde_json::json!({"kind":"realm","realm_id":REALM_ID}),
            current_stream_position: 7,
            value: serde_json::json!({
                "id": GRANT_ID,
                "schema": "ak.schema.capability.v1",
                "realm_id": REALM_ID,
                "status": status
            }),
        }
    }

    #[test]
    fn reader_returns_value_and_exact_commit_revision_from_one_row() {
        let record = decode_row(row("active")).unwrap();
        assert_eq!(record.status, CapabilityGrantCurrentStatus::Active);
        assert_eq!(record.value["id"], GRANT_ID);
        assert_eq!(record.revision.commit_id.as_str(), COMMIT_ID);
        assert_eq!(record.revision.stream_position, 7);
    }

    #[test]
    fn reader_rejects_lifecycle_or_identity_drift() {
        let mut lifecycle = row("active");
        lifecycle.value["status"] = serde_json::json!("revoked");
        assert!(matches!(
            decode_row(lifecycle),
            Err(PersistenceError::Database(_))
        ));

        let mut identity = row("active");
        identity.value["realm_id"] =
            serde_json::json!("ak:realm:ASm71QhtF54BxHBvRFcIhmLfPFYTrXhTcLnVAEMmqZ5t");
        assert!(matches!(
            decode_row(identity),
            Err(PersistenceError::Database(_))
        ));
    }

    #[test]
    fn reader_rejects_non_commit_revision_material() {
        let mut invalid_commit = row("active");
        invalid_commit.current_commit_id =
            "ak:event:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4".to_owned();
        assert!(matches!(
            decode_row(invalid_commit),
            Err(PersistenceError::Database(_))
        ));

        let mut negative_position = row("active");
        negative_position.current_stream_position = -1;
        assert!(matches!(
            decode_row(negative_position),
            Err(PersistenceError::Database(_))
        ));
    }
}
