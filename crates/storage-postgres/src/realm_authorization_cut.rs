//! Same-cut authorization of capability-gated Realm Events.
//!
//! The governing Station decides whether an Event's actor may author its kind
//! from four Realm-stream typed current results read inside the accepting
//! transaction: `realm_authority_root`, every `capability_grant` of the Realm,
//! `realm_policy_bundle` and the actor's own `member_state`
//! (`authz/event-auth-state-resolution.md` §1, `authz/capabilities.md` §18).
//!
//! [`authorize_capability_gated_event_in_connection`] first takes the Realm
//! authority row lock. Every writer of those four families commits on the Realm
//! stream through the same row, so the verdict and the Commit it gates are one
//! cut: a grant revoked before this transaction took the lock is observed here,
//! and one revoked after it cannot commit until this transaction has ended.
//! The in-process reducer projection is never an input.
//!
//! The authorizing actions of a kind are exactly the capability actions whose
//! registered `target_event_kinds` list it; there is no second per-kind list.
//! The current root controller holds the effective `ak.realm.owner` aggregate
//! (`authz/capabilities.md` §3.2) and therefore every kind that aggregate
//! lists; any other actor needs an active Capability Grant naming one of the
//! authorizing actions on a selector covering the Realm, with an intact issuer
//! chain. Membership is a required input, never an authorization source.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload;
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, GrantConstraintKind, IssuerAuthorityRef,
};
use arkret_wire::{ActorId, CapabilityActionId, EventKind, GrantId, RealmId, WireResourceSelector};

use super::{
    AsyncPgConnection, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    QueryableByName, RunQueryDsl, Text, sql_query,
};
use crate::capability_grant_current_results::{
    CapabilityGrantCurrentResultReadRow, RealmAuthorityRootCurrent, RealmAuthorityRootReadRow,
    decode_authority_root, decode_row, grant_is_active_at, selector_covers,
    validate_ancestor_graph,
};

#[derive(QueryableByName)]
struct PolicyBundleRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct MembershipRow {
    #[diesel(sql_type = Text)]
    membership: String,
}

#[derive(QueryableByName)]
struct LockedAuthorityRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

fn capability_denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}

/// The four authorization inputs of one actor in one Realm, read at one cut.
pub(crate) struct RealmAuthorizationCut {
    realm_id: RealmId,
    actor: ActorId,
    root: Option<RealmAuthorityRootCurrent>,
    grants: BTreeMap<GrantId, CapabilityGrant>,
    policy_bundle: Option<RealmPolicyBundlePayload>,
    actor_membership: Option<String>,
}

impl RealmAuthorizationCut {
    /// Read the cut on `conn`. The caller fixes the cut: either it holds the
    /// Realm authority row lock inside the accepting transaction, or it reads
    /// inside one REPEATABLE READ snapshot.
    pub(crate) async fn read(
        conn: &mut AsyncPgConnection,
        realm_id: &RealmId,
        actor: &ActorId,
    ) -> PersistenceResult<Self> {
        let root = sql_query(
            "SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,\
             authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<RealmAuthorityRootReadRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_authority_root)
        .transpose()?;
        let stored = sql_query(
            "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
             current_stream_position,value FROM capability_grant_current_results \
             WHERE realm_id=$1 ORDER BY grant_id ASC",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut grants = BTreeMap::new();
        for row in stored {
            let record = decode_row(row)?;
            grants.insert(record.grant_id, record.value);
        }
        let policy_bundle =
            sql_query("SELECT value FROM realm_policy_bundle_current_results WHERE realm_id=$1")
                .bind::<Text, _>(realm_id.as_str())
                .get_result::<PolicyBundleRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?
                .map(|row| {
                    serde_json::from_value::<RealmPolicyBundlePayload>(row.value).map_err(|error| {
                        PersistenceError::Database(format!(
                            "stored realm_policy_bundle current value is invalid: {error}"
                        ))
                    })
                })
                .transpose()?;
        let member_id = actor.to_string();
        let actor_membership = sql_query(
            "SELECT membership FROM member_state_current_results \
             WHERE realm_id=$1 AND member_id=$2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(&member_id)
        .get_result::<MembershipRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| row.membership);
        Ok(Self {
            realm_id: realm_id.clone(),
            actor: actor.clone(),
            root,
            grants,
            policy_bundle,
            actor_membership,
        })
    }

    /// Whether the actor is the current controller of the Realm authority root.
    pub(crate) fn actor_is_root_controller(&self) -> bool {
        self.root
            .as_ref()
            .is_some_and(|root| root.controller_actor_id == self.actor)
    }

    /// Whether the actor's current `member_state` is `join`.
    pub(crate) fn actor_is_joined(&self) -> bool {
        self.actor_membership.as_deref() == Some("join")
    }

    /// Whether an active Capability Grant whose subject is exactly the actor
    /// names one of `actions` on a selector covering the whole Realm, has only
    /// temporal constraints whose window contains `at`, and descends from the
    /// current authority root through an intact issuer chain.
    pub(crate) fn grants_cover_any(
        &self,
        actions: &[&str],
        at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(root) = self.root.as_ref() else {
            return false;
        };
        let realm = WireResourceSelector::realm(self.realm_id.clone());
        self.grants.iter().any(|(grant_id, grant)| {
            let covers = matches!(&grant.subject, CapabilitySubject::Actor(subject) if subject == &self.actor)
                && grant.realm_id.as_ref() == Some(&self.realm_id)
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
            covers
                && !grant.issuer_authority_refs.is_empty()
                && grant
                    .issuer_authority_refs
                    .iter()
                    .all(|authority_ref| match authority_ref {
                        IssuerAuthorityRef::RealmRoot {
                            realm_id: root_realm_id,
                            authority_event_ref,
                            authority_generation,
                        } => {
                            root_realm_id == &self.realm_id
                                && root.authority_event_ref == *authority_event_ref
                                && root.authority_generation == *authority_generation
                        }
                        IssuerAuthorityRef::Grant {
                            grant_id: parent_id,
                        } => {
                            self.grants.get(parent_id).is_some_and(|parent| {
                                matches!(&parent.subject, CapabilitySubject::Actor(subject) if subject == &grant.issuer_id)
                            }) && validate_ancestor_graph(
                                grant_id,
                                parent_id,
                                &self.grants,
                                root,
                                &self.realm_id,
                                at,
                                &mut std::collections::BTreeSet::new(),
                                1,
                            )
                            .is_ok()
                        }
                    })
        })
    }

    /// Whether the actor holds one of the actions authorizing `kind`: the
    /// root controller through its effective `ak.realm.owner`, anyone else
    /// through an active covering grant.
    pub(crate) fn holds_event_kind(
        &self,
        kind: &EventKind,
        at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let actions = arkret_schema::capability_actions_for_event_kind(kind.as_str())
            .map(|descriptor| descriptor.action.as_str())
            .collect::<Vec<_>>();
        (self.actor_is_root_controller() && actions.contains(&CapabilityActionId::REALM_OWNER))
            || self.grants_cover_any(&actions, at)
    }

    /// The complete capability-gated verdict for `kind`: the Realm has an
    /// authority root and a policy bundle, the actor is a joined member, and
    /// the actor holds an authorizing action.
    pub(crate) fn require_event_kind(
        &self,
        kind: &EventKind,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        if self.root.is_none() {
            return Err(PersistenceError::Conflict(
                "failed_precondition: the Realm has no authority root at this cut".to_owned(),
            ));
        }
        if self.policy_bundle.is_none() {
            return Err(PersistenceError::Conflict(
                "dependency_missing: the Realm has no policy bundle at this cut".to_owned(),
            ));
        }
        if !self.actor_is_joined() {
            return Err(capability_denied(format!(
                "{} is not a joined member of the Realm",
                kind.as_str()
            )));
        }
        if !self.holds_event_kind(kind, at) {
            return Err(capability_denied(format!(
                "the actor holds no action authorizing {}",
                kind.as_str()
            )));
        }
        Ok(())
    }
}

/// Take the Realm authority row lock for the accepting transaction. The lock
/// is re-entrant inside one transaction, so a caller that already installed
/// the Commit holds it already and this only proves it.
pub(crate) async fn lock_realm_authorization_cut(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<()> {
    sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<LockedAuthorityRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .filter(|row| row.realm_id == realm_id.as_str())
        .map(|_| ())
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "stale_authority: the Realm has no current governance authority".to_owned(),
            )
        })
}

/// Authorize `event` as a capability-gated Realm Event at the accepting
/// transaction's cut and return that cut for kind-specific rules.
pub(crate) async fn authorize_capability_gated_event_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<RealmAuthorizationCut> {
    lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let cut = RealmAuthorizationCut::read(conn, &event.realm_id, &event.actor_id).await?;
    cut.require_event_kind(&event.kind, at)?;
    Ok(cut)
}
