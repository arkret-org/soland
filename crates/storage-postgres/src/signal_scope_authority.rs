//! Read-only Signal governance from covered canonical cuts, never UI mirrors.
use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::events_payloads::realm::{
    RealmAuthorityResetPayload, RealmOwnerTransferPayload, RealmPolicyBundlePayload,
};
use arkret_models_collaboration::events_payloads::{
    CapabilityGrantPayload, CapabilityRelinquishPayload, CapabilityRevokePayload,
};
use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, CapabilityGrant, CapabilityGrantStatus, CapabilitySubject, IssuerAuthorityRef,
};
use arkret_wire::{
    ActorId, CommitStreamRef, Event, EventId, EventKind, GrantId, RealmCommit, RealmCommitId,
    RealmId, ScopeRef, SignalClass, WireResourceSelector,
};
use chrono::{DateTime, Utc};
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use soland_storage::{
    AuthorizationOperation, OperationFacts, PersistenceError, PersistenceResult,
    SignalScopeAuthority, evaluate_grants,
};

use crate::capability_grant_current_results::{
    RealmAuthorityRootCurrent, grant_is_active_at, validate_ancestor_graph,
};
use crate::{OptionalExtension, PgPool, PgTransactionError, pg_conn};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("Signal governance cut is unavailable: {detail}"))
}
#[derive(diesel::QueryableByName)]
struct Row {
    #[diesel(sql_type=Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    envelope: Option<serde_json::Value>,
}
#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
}
fn payload<T: serde::de::DeserializeOwned>(event: &Event) -> PersistenceResult<T> {
    serde_json::from_value(serde_json::to_value(&event.payload).map_err(unavailable)?)
        .map_err(unavailable)
}

/// An interval is usable only when every position from genesis through the
/// known head has its exact covered accepted Event. A partial replica cannot
/// infer historical authority from an anchor or a newer materialized row.
async fn history(
    conn: &mut AsyncPgConnection,
    stream: &CommitStreamRef,
) -> PersistenceResult<Vec<(RealmCommit, Event)>> {
    let key = crate::authority_commit::stream_key(stream)?;
    let rows=diesel::sql_query("SELECT c.commit_json,e.envelope FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE c.stream_key=$1 ORDER BY c.stream_position")
        .bind::<Text,_>(&key).load::<Row>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut result = Vec::new();
    let mut previous = None;
    for (position, row) in rows.into_iter().enumerate() {
        let commit: RealmCommit = serde_json::from_value(row.commit_json).map_err(unavailable)?;
        let event: Event = serde_json::from_value(
            row.envelope
                .ok_or_else(|| unavailable("missing covered Event"))?,
        )
        .map_err(unavailable)?;
        if commit.stream_ref != *stream
            || commit.stream_position != position as u64
            || commit.previous_commit_ref != previous
            || commit.event_ref != event.event_id
            || commit.realm_id != event.realm_id
        {
            return Err(unavailable(
                "accepted interval is discontinuous or covers another Event",
            ));
        }
        commit.validate_shape().map_err(unavailable)?;
        event
            .verify_event_id_matches_content_with_digest_suite(
                arkret_canonical::DigestSuite::Sha256,
            )
            .map_err(unavailable)?;
        previous = Some(commit.commit_id.clone());
        result.push((commit, event));
    }
    // A verified replica anchor above the held interval is known stale, not
    // permission to reuse the older interval.
    #[derive(diesel::QueryableByName)]
    struct Anchor {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        position: i64,
    }
    let anchor=diesel::sql_query("SELECT MAX(anchor_stream_position) AS position FROM replica_stream_anchors WHERE stream_key=$1 AND anchor_commit_id IS NOT NULL HAVING MAX(anchor_stream_position) IS NOT NULL")
        .bind::<Text,_>(&key).get_result::<Anchor>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if anchor.is_some_and(|a| {
        result
            .last()
            .is_none_or(|(c, _)| u64::try_from(a.position).map_or(true, |p| p > c.stream_position))
    }) {
        return Err(unavailable("known replica head exceeds held interval"));
    }
    #[derive(diesel::QueryableByName)]
    struct Authority {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        generation: i64,
    }
    let authority = diesel::sql_query("SELECT generation FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(stream.realm_id().as_str())
        .get_result::<Authority>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    let authority = authority.ok_or_else(|| unavailable("missing current Realm authority"))?;
    if let Some((head, _)) = result.last() {
        if u64::try_from(authority.generation).ok() != Some(head.governance_generation) {
            return Err(unavailable(
                "held interval is not the current authority generation",
            ));
        }
    }
    Ok(result)
}

#[derive(Default, Clone)]
struct Cut {
    root: Option<RealmAuthorityRootCurrent>,
    members: BTreeMap<String, (ActorId, String)>,
    grants: BTreeMap<GrantId, CapabilityGrant>,
    policy: Option<RealmPolicyBundlePayload>,
    terminal: bool,
    frozen: bool,
    archived: bool,
    direct: bool,
    bound: bool,
    mls: Option<EventId>,
    cipher: Option<String>,
    mls_epoch: Option<u64>,
    genesis: Option<EventId>,
    links: BTreeMap<(RealmId, String), String>,
}
impl Cut {
    fn apply(&mut self, commit: &RealmCommit, event: &Event) -> PersistenceResult<()> {
        match event.kind {
            EventKind::RealmCreate => {
                self.root = Some(RealmAuthorityRootCurrent {
                    realm_id: event.realm_id.clone(),
                    controller_actor_id: event.actor_id.clone(),
                    controller_epoch: 0,
                    authority_generation: 0,
                    authority_event_ref: event.event_id.clone(),
                });
                self.direct = event
                    .payload
                    .get("object")
                    .and_then(|o| o.get("purpose"))
                    .and_then(|v| v.as_str())
                    == Some("direct_conversation");
            }
            EventKind::RealmOwnerTransfer => {
                let p: RealmOwnerTransferPayload = payload(event)?;
                let root = self
                    .root
                    .as_mut()
                    .ok_or_else(|| unavailable("root transfer without genesis"))?;
                root.controller_actor_id = p.patch.controller_actor_id;
                root.controller_epoch =
                    RealmOwnerTransferPayload::successor_controller_epoch(root.controller_epoch)
                        .map_err(unavailable)?;
            }
            EventKind::RealmAuthorityReset => {
                let root = self
                    .root
                    .as_mut()
                    .ok_or_else(|| unavailable("root reset without genesis"))?;
                root.authority_generation =
                    RealmAuthorityResetPayload::successor_authority_generation(
                        root.authority_generation,
                    )
                    .map_err(unavailable)?;
                root.authority_event_ref = event.event_id.clone();
            }
            EventKind::MemberState | EventKind::CircleMemberState => {
                let member: ActorId = serde_json::from_value(
                    event
                        .payload
                        .get("member_id")
                        .cloned()
                        .ok_or_else(|| unavailable("membership omits actor"))?,
                )
                .map_err(unavailable)?;
                let membership = event
                    .payload
                    .get("membership")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| unavailable("membership omits state"))?;
                self.members
                    .insert(member.to_string(), (member, membership.to_owned()));
            }
            EventKind::InviteAccept => {
                self.members.insert(
                    event.actor_id.to_string(),
                    (event.actor_id.clone(), "join".to_owned()),
                );
            }
            EventKind::CapabilityGrant => {
                let p: CapabilityGrantPayload = payload(event)?;
                let b = p.grant;
                let mut roots = Vec::new();
                let mut depth = 1;
                for reference in &b.issuer_authority_refs {
                    match reference {
                        IssuerAuthorityRef::RealmRoot {
                            realm_id,
                            authority_event_ref,
                            authority_generation,
                        } => roots.push(AuthorityRootRef::RealmRoot {
                            realm_id: realm_id.clone(),
                            authority_event_ref: authority_event_ref.clone(),
                            authority_generation: *authority_generation,
                        }),
                        IssuerAuthorityRef::Grant { grant_id } => {
                            let parent = self
                                .grants
                                .get(grant_id)
                                .ok_or_else(|| unavailable("accepted grant parent missing"))?;
                            depth = depth.max(parent.authority_depth + 1);
                            roots.extend(parent.authority_root_refs.clone());
                        }
                    }
                }
                let grant = CapabilityGrant {
                    id: GrantId::from_event_id(&event.event_id),
                    schema: b.schema,
                    realm_id: Some(event.realm_id.clone()),
                    issuer_id: b.issuer_id,
                    subject: b.subject,
                    actions: b.actions,
                    resources: b.resources,
                    constraints: b.constraints,
                    issuer_authority_refs: b.issuer_authority_refs,
                    authority_depth: depth,
                    authority_root_refs: roots,
                    issued_at: b.issued_at,
                    status: CapabilityGrantStatus::Active,
                    updated_by: None,
                    updated_at: None,
                    revoked_by: None,
                    revoked_at: None,
                };
                self.grants.insert(grant.id.clone(), grant);
            }
            EventKind::CapabilityRevoke => {
                let p: CapabilityRevokePayload = payload(event)?;
                let grant = self
                    .grants
                    .get_mut(&p.grant_id)
                    .ok_or_else(|| unavailable("accepted revoke target missing"))?;
                grant.status = CapabilityGrantStatus::Revoked;
                grant.revoked_by = Some(event.actor_id.clone());
                grant.revoked_at = Some(event.created_at);
            }
            EventKind::CapabilityRelinquish => {
                let p: CapabilityRelinquishPayload = payload(event)?;
                let grant = self
                    .grants
                    .get_mut(&p.grant_id)
                    .ok_or_else(|| unavailable("accepted relinquish target missing"))?;
                grant.status = CapabilityGrantStatus::Relinquished;
                grant.updated_by = Some(event.actor_id.clone());
                grant.updated_at = Some(event.created_at);
            }
            EventKind::RealmPolicyBundle => {
                self.policy = Some(payload(event)?);
            }
            EventKind::RealmLink => {
                let target: RealmId = serde_json::from_value(
                    event
                        .payload
                        .get("target_realm_id")
                        .cloned()
                        .ok_or_else(|| unavailable("Realm link target missing"))?,
                )
                .map_err(unavailable)?;
                let kind = event
                    .payload
                    .get("link_kind")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| unavailable("Realm link kind missing"))?;
                let status = event
                    .payload
                    .get("status")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| unavailable("Realm link status missing"))?;
                self.links
                    .insert((target, kind.to_owned()), status.to_owned());
            }
            EventKind::RealmArchive => self.archived = true,
            EventKind::RealmRestore => self.archived = false,
            EventKind::RealmFreeze => self.frozen = true,
            EventKind::RealmUnfreeze => self.frozen = false,
            EventKind::RealmDestroy | EventKind::RealmTombstone => self.terminal = true,
            EventKind::DirectConversationBound => self.bound = true,
            EventKind::MlsGenesis => {
                let p: arkret_models_collaboration::events_payloads::mls::MlsGenesisPayload =
                    payload(event)?;
                p.validate().map_err(unavailable)?;
                if p.effective_scope() != &event.scope_ref
                    || p.mls_group_id().map_err(unavailable)?
                        != event
                            .scope_ref
                            .canonical_mls_group_id()
                            .map_err(unavailable)?
                {
                    return Err(unavailable("MLS genesis scope differs"));
                }
                self.mls = Some(event.event_id.clone());
                self.genesis = Some(event.event_id.clone());
                self.mls_epoch = Some(0);
                self.cipher = Some(p.cipher_suite.as_str().to_owned());
            }
            EventKind::MlsCommit => {
                let p: arkret_models_crypto::MlsCommitPayload = payload(event)?;
                if self.mls.as_ref() != Some(p.base_group_state_ref())
                    || self.mls_epoch != Some(p.base_epoch())
                {
                    return Err(unavailable("MLS winning interval is discontinuous"));
                }
                self.mls = Some(event.event_id.clone());
                self.mls_epoch = Some(p.next_epoch());
            }
            _ => {}
        }
        let _ = commit;
        Ok(())
    }
    fn joined(&self, actor: &ActorId) -> bool {
        self.members
            .get(&actor.to_string())
            .is_some_and(|(_, m)| m == "join")
    }
    fn permits(
        &self,
        realm: &RealmId,
        scope: &ScopeRef,
        actor: &ActorId,
        class: SignalClass,
        at: DateTime<Utc>,
    ) -> bool {
        if !self.joined(actor) || self.terminal || self.frozen || self.archived {
            return false;
        }
        if self.direct {
            // The decrypted product kind is not an outer capability selector.
            // Direct Conversation has no participant moderation action.
            return self.bound && self.members.len() == 2 && class != SignalClass::Moderation;
        }
        // Setup/session contain encrypted product actions. Only moderation
        // has a Station-visible action, evaluated through the shared grant
        // constraint evaluator and intact accepted issuer graph.
        if class != SignalClass::Moderation {
            return true;
        }
        let Some(root) = self.root.as_ref() else {
            return false;
        };
        let target = match scope {
            ScopeRef::Realm { realm_id } => WireResourceSelector::realm(realm_id.clone()),
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
            _ => return false,
        };
        let actions = ["ak.call.moderate"];
        let facts = OperationFacts::default();
        let effective=self.grants.iter().filter(|(id,g)| {
            matches!(&g.subject,CapabilitySubject::Actor(subject) if subject==actor) && grant_is_active_at(g,at) && g.realm_id.as_ref()==Some(realm) && !g.issuer_authority_refs.is_empty() && g.issuer_authority_refs.iter().all(|r|match r {
                IssuerAuthorityRef::RealmRoot{realm_id,authority_event_ref,authority_generation}=>realm_id==realm&&*authority_event_ref==root.authority_event_ref&&*authority_generation==root.authority_generation,
                IssuerAuthorityRef::Grant{grant_id}=>self.grants.get(grant_id).is_some_and(|parent|matches!(&parent.subject,CapabilitySubject::Actor(a) if a==&g.issuer_id))&&validate_ancestor_graph(id,grant_id,&self.grants,root,realm,at,&mut BTreeSet::new(),1).is_ok(),
            })
        }).map(|(_,g)|g);
        let result = evaluate_grants(
            &AuthorizationOperation {
                actor,
                actions: &actions,
                target: &target,
                at,
                facts: &facts,
            },
            effective,
        );
        !result.unreserved().is_empty()
    }
}
fn fold(rows: &[(RealmCommit, Event)], through: u64) -> PersistenceResult<Cut> {
    let mut cut = Cut::default();
    for (c, e) in rows
        .iter()
        .take_while(|(c, _)| c.stream_position <= through)
    {
        cut.apply(c, e)?;
    }
    Ok(cut)
}

pub(crate) async fn read(
    pool: &PgPool,
    scope: &ScopeRef,
    authority_commit_id: &RealmCommitId,
    sender: &ActorId,
    class: SignalClass,
    sent_at: DateTime<Utc>,
    at: DateTime<Utc>,
) -> PersistenceResult<Option<SignalScopeAuthority>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
        read_in_connection(conn, scope, authority_commit_id, sender, class, sent_at, at)
            .await
            .map_err(Into::into)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
async fn read_in_connection(
    conn: &mut AsyncPgConnection,
    scope: &ScopeRef,
    authority_commit_id: &RealmCommitId,
    sender: &ActorId,
    class: SignalClass,
    sent_at: DateTime<Utc>,
    at: DateTime<Utc>,
) -> PersistenceResult<Option<SignalScopeAuthority>> {
    let realm = scope.realm_id();
    let stream = CommitStreamRef::from_scope(scope, None).map_err(unavailable)?;
    let rows = history(conn, &stream).await?;
    let Some((declared, event)) = rows
        .iter()
        .find(|(c, _)| c.commit_id == *authority_commit_id)
    else {
        return Ok(None);
    };
    if declared.realm_id != *realm || event.scope_ref != *scope || declared.committed_at > sent_at {
        return Ok(None);
    }
    let Some((head, _)) = rows.last() else {
        return Ok(None);
    };
    let historical = fold(&rows, declared.stream_position)?;
    let current = fold(&rows, head.stream_position)?;
    // Sidecar and missing complete parent proof stay closed. Circle membership
    // is independent of Realm positions; never compare their scalar positions.
    let realm_rows = if matches!(scope, ScopeRef::Realm { .. }) {
        rows.clone()
    } else {
        history(
            conn,
            &CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
        )
        .await?
    };
    let Some((realm_head, _)) = realm_rows.last() else {
        return Ok(None);
    };
    let parent = fold(&realm_rows, realm_head.stream_position)?;
    if !parent.joined(sender) || !historical.joined(sender) || !current.joined(sender) {
        return Ok(None);
    }
    if matches!(scope, ScopeRef::Circle { .. }) {
        // A complete historical parent cut needs its own registered proof;
        // a newer Realm membership row does not prove a Circle's old cut.
        return Err(unavailable(
            "historical Circle parent membership cut is not proved",
        ));
    }
    if !historical.permits(realm, scope, sender, class, sent_at)
        || !current.permits(realm, scope, sender, class, at)
    {
        return Ok(None);
    }
    if current.direct {
        let profile =
            crate::direct_conversation_admission::direct_conversation_realm_in_connection(
                conn, realm,
            )
            .await?
            .ok_or_else(|| unavailable("accepted founding source missing"))?;
        let Some(pair) = profile.pair() else {
            return Ok(None);
        };
        if pair.len() != 2
            || !pair.contains(&sender)
            || current
                .members
                .values()
                .map(|(a, _)| a.to_string())
                .collect::<BTreeSet<_>>()
                != pair.iter().map(|a| a.to_string()).collect::<BTreeSet<_>>()
        {
            return Ok(None);
        }
        if !profile.pair_grants_direct_message_snapshot(conn).await? {
            return Ok(None);
        }
    }
    let mut recipients = current
        .members
        .values()
        .filter(|(_, m)| m == "join")
        .map(|(a, _)| a.clone())
        .collect::<Vec<_>>();
    // Linked parent membership is authoritative only on the target's current
    // governing Station. Its sources are independently complete accepted cuts.
    if let Some(join) = parent.policy.as_ref().and_then(|p| p.join_policy.as_ref()) {
        use arkret_models_collaboration::events_payloads::join_policy::JoinPolicyGate;
        let mut source_groups = Vec::<BTreeSet<String>>::new();
        for gate in &join.gates {
            let JoinPolicyGate::ParentMembership {
                membership_source_realm_ids,
                ..
            } = gate
            else {
                continue;
            };
            let mut joined = BTreeSet::new();
            for source in membership_source_realm_ids {
                if parent
                    .links
                    .get(&(source.clone(), "join_gate_from".to_owned()))
                    .map(String::as_str)
                    != Some("active")
                {
                    return Ok(None);
                }
                #[derive(diesel::QueryableByName)]
                struct CoGoverned {
                    #[diesel(sql_type=diesel::sql_types::Bool)]
                    same: bool,
                }
                let same=diesel::sql_query("SELECT a.service_id=b.service_id AS same FROM realm_authorities a JOIN realm_authorities b ON b.realm_id=$2 WHERE a.realm_id=$1")
                    .bind::<Text,_>(realm.as_str()).bind::<Text,_>(source.as_str()).get_result::<CoGoverned>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                if !same.is_some_and(|row| row.same) {
                    return Err(unavailable("parent membership authority differs"));
                }
                let source_rows = history(
                    conn,
                    &CommitStreamRef::Realm {
                        realm_id: source.clone(),
                    },
                )
                .await?;
                if let Some((head, _)) = source_rows.last() {
                    joined.extend(
                        fold(&source_rows, head.stream_position)?
                            .members
                            .into_values()
                            .filter(|(_, m)| m == "join")
                            .map(|(a, _)| a.to_string()),
                    );
                }
            }
            source_groups.push(joined);
        }
        if !source_groups.is_empty() {
            let all = match join.combinator.as_str() {
                "all" => true,
                "any" => false,
                _ => return Err(unavailable("unknown parent membership combinator")),
            };
            recipients.retain(|actor| {
                if all {
                    source_groups
                        .iter()
                        .all(|sources| sources.contains(&actor.to_string()))
                } else {
                    source_groups
                        .iter()
                        .any(|sources| sources.contains(&actor.to_string()))
                }
            });
            if !recipients.contains(sender) {
                return Ok(None);
            }
        }
    }
    let key =
        String::from_utf8(arkret_canonical::canonical_json_bytes(scope).map_err(unavailable)?)
            .map_err(unavailable)?;
    let mls = diesel::sql_query("SELECT value FROM mls_group_current_results WHERE scope_key=$1")
        .bind::<Text, _>(&key)
        .get_result::<ValueRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    let Some(mls) = mls else {
        return Ok(None);
    };
    let current_mls: arkret_wire::MlsGroupCurrent =
        serde_json::from_value(mls.value).map_err(unavailable)?;
    let Some(historical_mls_event_ref) = historical.mls else {
        return Ok(None);
    };
    if current.mls.as_ref() != Some(&current_mls.current_mls_commit_event_ref)
        || current.genesis.as_ref() != Some(&current_mls.genesis_event_ref)
        || current.mls_epoch != Some(current_mls.epoch)
        || current_mls.effective_scope != *scope
        || current_mls.covered_key_access_revision < current_mls.current_key_access_revision
    {
        return Ok(None);
    }
    let cipher_suite = current
        .cipher
        .ok_or_else(|| unavailable("accepted MLS cipher suite missing"))?;
    Ok(Some(SignalScopeAuthority {
        recipient_actors: recipients,
        historical_mls_event_ref,
        current_mls,
        cipher_suite,
    }))
}

pub(crate) async fn recipient_realms(
    pool: &PgPool,
    actor: &ActorId,
) -> PersistenceResult<Vec<RealmId>> {
    #[derive(diesel::QueryableByName)]
    struct RealmRow {
        #[diesel(sql_type=Text)]
        realm_id: String,
    }
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(conn).await.map_err(PersistenceError::database)?;
        let rows=diesel::sql_query("SELECT realm_id FROM member_state_current_results WHERE member_id=$1 AND membership='join' ORDER BY realm_id")
            .bind::<Text,_>(actor.to_string()).load::<RealmRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let mut result=Vec::new();
        for row in rows {
            let realm=RealmId::new(row.realm_id).map_err(unavailable)?;
            if crate::authority_commit::accepted_current_member_joined_in_connection(conn,&realm,actor).await? {result.push(realm);}
        }
        Ok(result)
    }).await.map_err(PgTransactionError::into_persistence)
}
