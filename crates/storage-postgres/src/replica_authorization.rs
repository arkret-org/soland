//! Read-only authorization from the governing Station's signed typed rows.
//!
//! These rows retain the existing SDK values and source coordinates. They do
//! not manufacture the private admission provenance omitted by snapshots.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, CapabilityGrant, CapabilitySubject, IssuerAuthorityRef,
};
use arkret_wire::{ActorId, CurrentSelector, GrantId, RealmId, ScopeRef, TypedCurrentResult};
use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{AuthorizationOperation, OperationFacts, PersistenceError, PersistenceResult};

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("replica authorization row: {detail}"))
}

pub(crate) fn keeps(_selector: &CurrentSelector) -> bool {
    true
}

/// Save only a verified snapshot or source-committed reducer result. The
/// enclosing replica transaction installs the rows and its anchor together.
pub(crate) async fn save_row(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    entry: &TypedCurrentResult,
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let TypedCurrentResult::Value {
        selector,
        source_stream_ref,
        revision,
        value,
    } = entry
    else {
        return Err(invalid("a stored row must be a value"));
    };
    if !keeps(selector) {
        return Ok(());
    }
    if source_stream_ref.realm_id() != realm {
        return Err(invalid("source stream is outside the Realm"));
    }
    let position = i64::try_from(revision.stream_position)
        .map_err(|_| invalid("source position exceeds PostgreSQL BIGINT"))?;
    diesel::sql_query(
        "INSERT INTO replica_authorization_rows \
         (realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,selector) DO UPDATE SET \
         source_stream_ref=EXCLUDED.source_stream_ref,current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value, \
         updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(selector).map_err(invalid)?)
    .bind::<Jsonb, _>(serde_json::to_value(source_stream_ref).map_err(invalid)?)
    .bind::<Text, _>(revision.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(installed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct StoredRow {
    #[diesel(sql_type = Jsonb)]
    selector: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

/// The Station signature establishes each grant's reducer-derived root refs.
/// The member Station checks their Realm/generation and every live parent,
/// without guessing a root Event ref not disclosed by the root value.
fn intact_chain(
    id: &GrantId,
    grants: &BTreeMap<GrantId, CapabilityGrant>,
    realm: &RealmId,
    generation: u64,
    at: chrono::DateTime<chrono::Utc>,
    visiting: &mut BTreeSet<GrantId>,
    depth: usize,
) -> bool {
    if depth > 4 || !visiting.insert(id.clone()) {
        return false;
    }
    let valid = grants.get(id).is_some_and(|grant| {
        grant.realm_id.as_ref() == Some(realm)
            && crate::capability_grant_current_results::grant_is_active_at(grant, at)
            && !grant.issuer_authority_refs.is_empty()
            && !grant.authority_root_refs.is_empty()
            && grant.authority_root_refs.iter().all(|root| {
                matches!(root, AuthorityRootRef::RealmRoot { realm_id, authority_generation, .. }
                    if realm_id == realm && *authority_generation == generation)
            })
            && grant.issuer_authority_refs.iter().all(|reference| match reference {
                IssuerAuthorityRef::RealmRoot {
                    realm_id,
                    authority_event_ref,
                    authority_generation,
                } => {
                    realm_id == realm
                        && *authority_generation == generation
                        && grant.authority_root_refs.iter().any(|root| {
                            matches!(root, AuthorityRootRef::RealmRoot { realm_id: root_realm,
                                authority_event_ref: root_event, authority_generation: root_generation }
                                if root_realm == realm && root_event == authority_event_ref
                                    && *root_generation == generation)
                        })
                }
                IssuerAuthorityRef::Grant { grant_id } => {
                    grants.get(grant_id).is_some_and(|parent| {
                        matches!(&parent.subject, CapabilitySubject::Actor(subject) if subject == &grant.issuer_id)
                    }) && intact_chain(
                        grant_id,
                        grants,
                        realm,
                        generation,
                        at,
                        visiting,
                        depth + 1,
                    )
                }
            })
    });
    visiting.remove(id);
    valid
}

/// This is a governance metadata read, not ordinary Circle content access.
/// The caller separately proves its hosted membership and anchored stream.
pub(crate) async fn scope_moderator(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    actor: &ActorId,
    scope: &ScopeRef,
    actions: &[&str],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let Some(cut) = verified_head(conn, &realm_stream).await? else {
        return Ok(false);
    };
    let key = crate::authority_commit::stream_key(&realm_stream)?;
    let known = diesel::sql_query(
        "SELECT commit_id AS head_commit_id,stream_position AS head_stream_position FROM realm_commits WHERE stream_key=$1 \
         UNION ALL SELECT anchor_commit_id AS head_commit_id,anchor_stream_position AS head_stream_position FROM replica_stream_anchors \
         WHERE stream_key=$1 AND anchor_commit_id IS NOT NULL ORDER BY head_stream_position DESC LIMIT 1",
    ).bind::<Text, _>(&key).get_result::<CutRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if known.is_some_and(|head| {
        u64::try_from(head.head_stream_position).map_or(true, |position| {
            position > cut.stream_position
                || (position == cut.stream_position
                    && head.head_commit_id != cut.commit_id.as_str())
        })
    }) {
        return Ok(false);
    }
    let rows = diesel::sql_query(
        "SELECT selector,value FROM replica_authorization_rows WHERE realm_id=$1 ORDER BY selector::text",
    )
    .bind::<Text, _>(realm.as_str())
    .load::<StoredRow>(conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut root = None;
    let mut policy_present = false;
    let mut grants = BTreeMap::new();
    for row in rows {
        let selector: CurrentSelector = serde_json::from_value(row.selector).map_err(invalid)?;
        match selector {
            CurrentSelector::RealmAuthorityRoot => root = Some(row.value),
            CurrentSelector::RealmPolicyBundle => {
                serde_json::from_value::<
                    arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload,
                >(row.value)
                .map_err(invalid)?;
                policy_present = true;
            }
            CurrentSelector::CapabilityGrant { grant_id } => {
                let grant: CapabilityGrant = serde_json::from_value(row.value).map_err(invalid)?;
                if grant.id != grant_id || grant.realm_id.as_ref() != Some(realm) {
                    return Err(invalid("grant identity differs from its selector"));
                }
                grants.insert(grant_id, grant);
            }
            CurrentSelector::MemberState { .. } => {}
            _ => {}
        }
    }
    let Some(root) = root.filter(|_| policy_present) else {
        return Ok(false);
    };
    let controller: ActorId = serde_json::from_value(
        root.get("controller_actor_id")
            .cloned()
            .ok_or_else(|| invalid("root controller is absent"))?,
    )
    .map_err(invalid)?;
    root.get("controller_epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("root controller epoch is absent"))?;
    let generation = root
        .get("authority_generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("root generation is absent"))?;
    let target = match scope {
        ScopeRef::Realm { realm_id } if realm_id == realm => {
            if controller == *actor {
                return Ok(true);
            }
            arkret_wire::WireResourceSelector::realm(realm.clone())
        }
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == realm => {
            arkret_wire::WireResourceSelector::circle(realm.clone(), circle_id.clone())
        }
        _ => return Ok(false),
    };
    let effective = grants.iter().filter_map(|(id, grant)| {
        (matches!(&grant.subject, CapabilitySubject::Actor(subject) if subject == actor)
            && intact_chain(id, &grants, realm, generation, at, &mut BTreeSet::new(), 0))
        .then_some(grant)
    });
    let facts = OperationFacts::default();
    Ok(!soland_storage::evaluate_grants(
        &AuthorizationOperation {
            actor,
            actions,
            target: &target,
            at,
            facts: &facts,
        },
        effective,
    )
    .unreserved()
    .is_empty())
}

#[derive(diesel::QueryableByName)]
struct CutRow {
    #[diesel(sql_type=Text)]
    head_commit_id: String,
    #[diesel(sql_type=BigInt)]
    head_stream_position: i64,
}

pub(crate) async fn verified_head(
    conn: &mut AsyncPgConnection,
    stream: &arkret_wire::CommitStreamRef,
) -> PersistenceResult<Option<arkret_wire::CommitStreamHead>> {
    use diesel::OptionalExtension as _;
    diesel::sql_query("SELECT head_commit_id,head_stream_position FROM replica_authorization_cuts WHERE realm_id=$1 AND source_stream_ref=$2")
        .bind::<Text, _>(stream.realm_id().as_str()).bind::<Jsonb, _>(serde_json::to_value(stream).map_err(invalid)?)
        .get_result::<CutRow>(conn).await.optional().map_err(PersistenceError::database)?.map(|row| Ok(arkret_wire::CommitStreamHead { stream_ref:stream.clone(), commit_id:row.head_commit_id.parse().map_err(invalid)?, stream_position:u64::try_from(row.head_stream_position).map_err(invalid)? })).transpose()
}

pub(crate) async fn install_verified_head(
    conn: &mut AsyncPgConnection,
    head: &arkret_wire::CommitStreamHead,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if let Some(previous) = verified_head(conn, &head.stream_ref).await? {
        if previous.stream_position > head.stream_position
            || (previous.stream_position == head.stream_position
                && previous.commit_id != head.commit_id)
        {
            return Err(invalid(
                "snapshot regresses an already verified authorization cut",
            ));
        }
    }
    diesel::sql_query("INSERT INTO replica_authorization_cuts (realm_id,source_stream_ref,head_commit_id,head_stream_position,verified_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(realm_id,source_stream_ref) DO UPDATE SET head_commit_id=EXCLUDED.head_commit_id,head_stream_position=EXCLUDED.head_stream_position,verified_at=EXCLUDED.verified_at")
        .bind::<Text, _>(head.stream_ref.realm_id().as_str()).bind::<Jsonb, _>(serde_json::to_value(&head.stream_ref).map_err(invalid)?).bind::<Text, _>(head.commit_id.as_str()).bind::<BigInt, _>(i64::try_from(head.stream_position).map_err(invalid)?).bind::<Timestamptz, _>(at).execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn advance_verified_head(
    conn: &mut AsyncPgConnection,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let Some(previous) = verified_head(conn, &commit.stream_ref).await? else {
        return Ok(());
    };
    if commit.stream_position <= previous.stream_position {
        return Ok(());
    }
    if commit.previous_commit_ref.as_ref() != Some(&previous.commit_id)
        || commit.stream_position != previous.stream_position + 1
    {
        return Err(invalid("authorization cut tail is not contiguous"));
    }
    install_verified_head(
        conn,
        &arkret_wire::CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        commit.committed_at,
    )
    .await
}
