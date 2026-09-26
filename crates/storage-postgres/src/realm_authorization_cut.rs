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
//!
//! Every grant is judged by [`soland_storage::evaluate_grants`], the single
//! constraint evaluator (`authz/constraint-schema.md` §15.4); a hard quota a
//! satisfied grant owes is reserved on the quota authority inside the same
//! transaction ([`crate::capability_quota`]), so the reservation commits or
//! rolls back with the Event it admits.
//!
//! An action whose registry row lists `required_evaluator_checks` is never
//! sufficient on its own: only a kind-specific caller that discharges those
//! checks may count it. The one such check decided here is
//! `actor_eq_target_author` of the `.own` Message actions
//! ([`RealmAuthorizationCut::require_authored_target_in_connection`]).
//!
//! The Realm authority row lock taken first is the one dependency lock of the
//! cut. Every writer of the root, grant, policy bundle and member rows, and of
//! the Realm's terminal lifecycle, commits on the Realm stream through that
//! row (`authz/capabilities.md` §3.2), so a concurrent change of any of them
//! either committed before the lock was granted and is read here, or waits
//! for this transaction and is decided against its result.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload;
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, IssuerAuthorityRef,
};
use arkret_wire::{
    ActorId, CapabilityActionId, CurrentRevision, EventKind, GrantId, RealmId, StrandId,
    WireResourceSelector,
};
use soland_storage::{
    ActorRealmAuthorization, AuthorizationOperation, EffectiveActorGrant, GrantEvaluation,
    OperationFacts, evaluate_grants,
};

use super::{
    AsyncPgConnection, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    QueryableByName, RunQueryDsl, Text, sql_query,
};
use crate::capability_grant_current_results::{
    CapabilityGrantCurrentResultReadRow, RealmAuthorityRootCurrent, RealmAuthorityRootReadRow,
    decode_authority_root, decode_row, grant_is_active_at, validate_ancestor_graph,
};
use crate::direct_conversation_admission::ProfileAuthority;

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
struct LifecycleRow {
    #[diesel(sql_type = Text)]
    kind: String,
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
    revisions: BTreeMap<GrantId, CurrentRevision>,
    policy_bundle: Option<RealmPolicyBundlePayload>,
    actor_membership: Option<String>,
    lifecycle: RealmLifecycleGates,
    /// The Direct Conversation profile's verdict for the Event this cut was
    /// read for (`contact-and-direct-conversation.md` §8.3/§8.4). `Profile`
    /// means the profile's evaluator or phase mask authorized the Event; no
    /// grant or owner aggregation may substitute it, and none is counted.
    direct_conversation: Option<ProfileAuthority>,
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
        let mut revisions = BTreeMap::new();
        for row in stored {
            let record = decode_row(row)?;
            revisions.insert(record.grant_id.clone(), record.revision);
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
        let lifecycle = RealmLifecycleGates::read(conn, realm_id).await?;
        Ok(Self {
            realm_id: realm_id.clone(),
            actor: actor.clone(),
            root,
            grants,
            revisions,
            policy_bundle,
            actor_membership,
            lifecycle,
            direct_conversation: None,
        })
    }

    /// Read the cut for `event`'s actor together with the Direct
    /// Conversation profile's verdict for `event` at the same cut. A profile
    /// refusal is returned as its registered conflict.
    pub(crate) async fn read_for_event(
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
    ) -> PersistenceResult<Self> {
        let mut cut = Self::read(conn, &event.realm_id, &event.actor_id).await?;
        cut.direct_conversation =
            crate::direct_conversation_admission::profile_authority_in_connection(conn, event)
                .await?;
        Ok(cut)
    }

    /// Whether the cut's Realm is a Direct Conversation, whose Events name
    /// their profile authority source instead of a Realm root or grant.
    pub(crate) fn is_direct_conversation(&self) -> bool {
        self.direct_conversation.is_some()
    }

    fn profile_authorized(&self) -> bool {
        self.direct_conversation == Some(ProfileAuthority::Profile)
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

    /// `constraint-schema.md` §15.4 over the actor's effective grants at `at`.
    pub(crate) fn evaluate<'a>(
        &'a self,
        actions: &'a [&'a str],
        target: &'a WireResourceSelector,
        facts: &'a OperationFacts,
        at: chrono::DateTime<chrono::Utc>,
    ) -> GrantEvaluation<'a> {
        evaluate_grants(
            &AuthorizationOperation {
                actor: &self.actor,
                actions,
                target,
                at,
                facts,
            },
            self.effective_grants(at).map(|(_, grant)| grant),
        )
    }

    /// Whether an effective grant allows one of `actions` over the whole
    /// Realm without owing a quota reservation. A caller that cannot reserve
    /// on the quota authority never counts a quota-bound grant.
    pub(crate) fn grants_cover_any(
        &self,
        actions: &[&str],
        at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let realm = WireResourceSelector::realm(self.realm_id.clone());
        !self
            .evaluate(actions, &realm, &OperationFacts::default(), at)
            .unreserved()
            .is_empty()
    }

    /// Decide inside the accepting transaction whether the actor may exercise
    /// one of `actions` on `target` for the Event `identity`. A refusal
    /// constraint of any named grant refuses; otherwise a satisfied grant owing
    /// no quota, then the owner aggregate when `owner_covers`, then the first
    /// satisfied grant whose quota reservations succeed admits the Event.
    async fn admit_actions_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        actions: &[&str],
        target: &WireResourceSelector,
        facts: &OperationFacts,
        owner_covers: bool,
        identity: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ActionAdmission> {
        let evaluation = self.evaluate(actions, target, facts, at);
        match evaluation {
            GrantEvaluation::Denied => Err(capability_denied(
                "a deny constraint of an effective grant matches the operation",
            )),
            GrantEvaluation::Quarantined | GrantEvaluation::RequiresReview => {
                Err(PersistenceError::Conflict(
                    "failed_precondition: an effective grant requires quarantine or review \
                     evidence this Station does not accept"
                        .to_owned(),
                ))
            }
            GrantEvaluation::Allowed(satisfied) => {
                if satisfied.iter().any(|grant| grant.reservations.is_empty()) || owner_covers {
                    return Ok(ActionAdmission::Admitted);
                }
                for grant in &satisfied {
                    if crate::capability_quota::try_reserve_in_connection(
                        conn,
                        &grant.reservations,
                        identity,
                    )
                    .await?
                    {
                        return Ok(ActionAdmission::Admitted);
                    }
                }
                Err(PersistenceError::Conflict(format!(
                    "{}: every grant allowing the operation has exhausted its quota",
                    soland_storage::ConflictCode::RateLimited
                )))
            }
            GrantEvaluation::Unsatisfied if !owner_covers => {
                Ok(ActionAdmission::NotHeld { named: true })
            }
            GrantEvaluation::Unnamed if !owner_covers => {
                Ok(ActionAdmission::NotHeld { named: false })
            }
            GrantEvaluation::Unsatisfied | GrantEvaluation::Unnamed => {
                Ok(ActionAdmission::Admitted)
            }
        }
    }

    /// Every active grant whose subject is exactly the actor, whose temporal
    /// window contains `at`, and whose issuer chain descends intact from the
    /// current authority root. Actions, resources and non-temporal
    /// constraints are not decided here.
    fn effective_grants(
        &self,
        at: chrono::DateTime<chrono::Utc>,
    ) -> impl Iterator<Item = (&GrantId, &CapabilityGrant)> + '_ {
        let root = self.root.as_ref();
        self.grants.iter().filter(move |(grant_id, grant)| {
            let Some(root) = root else {
                return false;
            };
            matches!(&grant.subject, CapabilitySubject::Actor(subject) if subject == &self.actor)
                && grant.realm_id.as_ref() == Some(&self.realm_id)
                && grant_is_active_at(grant, at)
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

    /// The actor's authorization at `at` as a backend-neutral value: whether
    /// it is the root controller, and every effective grant with the exact
    /// revision of its current result.
    pub(crate) fn actor_authorization(
        &self,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ActorRealmAuthorization> {
        let grants = self
            .effective_grants(at)
            .map(|(grant_id, grant)| {
                let revision = self.revisions.get(grant_id).cloned().ok_or_else(|| {
                    PersistenceError::Database(
                        "Capability Grant current revision is missing from its cut".to_owned(),
                    )
                })?;
                Ok(EffectiveActorGrant {
                    grant: grant.clone(),
                    revision,
                })
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        Ok(ActorRealmAuthorization {
            realm_id: self.realm_id.clone(),
            actor: self.actor.clone(),
            evaluated_at: at,
            root_controller: self.actor_is_root_controller(),
            grants,
        })
    }

    /// The actions that authorize `kind` on their own: those without
    /// registered evaluator checks.
    fn unconditional_actions(kind: &EventKind) -> Vec<&'static str> {
        arkret_schema::capability_actions_for_event_kind(kind.as_str())
            .filter(|descriptor| descriptor.required_evaluator_checks.is_empty())
            .map(|descriptor| descriptor.action.as_str())
            .collect()
    }

    /// `realm-and-space.md` §2.6.0/§2.6.1: after a terminal Event only audit
    /// Events are admitted, and an archived or frozen Realm admits only the
    /// closed exemption set. The terminal refusal code is reserved, so it is
    /// a bare `failed_precondition`.
    pub(crate) fn require_open_lifecycle(
        &self,
        event: &arkret_wire::Event,
    ) -> PersistenceResult<()> {
        if self.lifecycle.terminal && !arkret_wire::events::kinds::is_audit_kind(&event.kind) {
            return Err(PersistenceError::Conflict(format!(
                "failed_precondition: the Realm is terminal and refuses {}",
                event.kind.as_str()
            )));
        }
        if self.lifecycle.archived || self.lifecycle.frozen {
            let payload = serde_json::Value::Object(event.payload.clone().into_iter().collect());
            if !arkret_wire::events::kinds::realm_write_gate_exempt(&event.kind, &payload) {
                return Err(PersistenceError::Conflict(format!(
                    "{}: the Realm is archived or frozen and refuses {}",
                    soland_storage::ConflictCode::RealmFrozen,
                    event.kind.as_str()
                )));
            }
        }
        Ok(())
    }

    /// The Realm has an authority root and a policy bundle at this cut and the
    /// actor is a joined member of it.
    pub(crate) fn require_governed_member(&self, kind: &EventKind) -> PersistenceResult<()> {
        if self.profile_authorized() {
            return if self.actor_is_joined() {
                Ok(())
            } else {
                Err(capability_denied(format!(
                    "{} is not a joined member of the Realm",
                    kind.as_str()
                )))
            };
        }
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
        Ok(())
    }

    /// The complete capability-gated verdict for `event`: the Realm has an
    /// authority root and a policy bundle, the actor is a joined member, and
    /// the actor holds an authorizing action whose constraints admit the
    /// Event, reserving any quota it owes.
    pub(crate) async fn require_event_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let kind = &event.kind;
        self.require_open_lifecycle(event)?;
        self.require_governed_member(kind)?;
        if self.profile_authorized() {
            return Ok(());
        }
        let actions = Self::unconditional_actions(kind);
        let owner =
            self.actor_is_root_controller() && actions.contains(&CapabilityActionId::REALM_OWNER);
        let (target, facts) = self.event_operation(event);
        match self
            .admit_actions_in_connection(
                conn,
                &actions,
                &target,
                &facts,
                owner,
                event.event_id.as_str(),
                at,
            )
            .await?
        {
            ActionAdmission::Admitted => Ok(()),
            ActionAdmission::NotHeld { .. } => Err(capability_denied(format!(
                "the actor holds no action authorizing {}",
                kind.as_str()
            ))),
        }
    }

    /// The capability-gated verdict for an `event` that acts on one authored
    /// object: an unconditional action as in
    /// [`Self::require_event_in_connection`], or, when the actor authored
    /// `target`, an action whose only evaluator check is
    /// `actor_eq_target_author` on a grant whose constraints, including the
    /// self-service windows of `authz/constraint-schema.md` §14.2, admit the
    /// Event. A grant that names the action but no longer admits it is
    /// `failed_precondition`, never a capability grant.
    pub(crate) async fn require_authored_target_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        target: &AuthoredTarget<'_>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let kind = &event.kind;
        self.require_open_lifecycle(event)?;
        self.require_governed_member(kind)?;
        // The profile's participant allowlist carries only the `.own`
        // variants, so its authority reaches only the actor's own object.
        if self.profile_authorized() {
            return if target.author == &self.actor {
                Ok(())
            } else {
                Err(capability_denied(format!(
                    "{} reaches only the actor's own object in a Direct Conversation",
                    kind.as_str()
                )))
            };
        }
        let realm = WireResourceSelector::realm(self.realm_id.clone());
        let facts = OperationFacts {
            strand_id: Some(target.strand_id.to_string()),
            object_kind: Some("message".to_owned()),
            track: Some(DISCUSSION_TRACK.to_owned()),
            target_created_at: Some(target.created_at),
            target_owner: Some(target.author.clone()),
            ..OperationFacts::default()
        };
        let identity = event.event_id.as_str();
        let actions = Self::unconditional_actions(kind);
        let owner =
            self.actor_is_root_controller() && actions.contains(&CapabilityActionId::REALM_OWNER);
        if self
            .admit_actions_in_connection(conn, &actions, &realm, &facts, owner, identity, at)
            .await?
            == ActionAdmission::Admitted
        {
            return Ok(());
        }
        if target.author != &self.actor {
            return Err(capability_denied(format!(
                "the actor holds no action authorizing {} on another author's object",
                kind.as_str()
            )));
        }
        let own_actions = arkret_schema::capability_actions_for_event_kind(kind.as_str())
            .filter(|descriptor| {
                descriptor.required_evaluator_checks == [ACTOR_EQ_TARGET_AUTHOR].as_slice()
            })
            .map(|descriptor| descriptor.action.as_str())
            .collect::<Vec<_>>();
        match self
            .admit_actions_in_connection(conn, &own_actions, &realm, &facts, false, identity, at)
            .await?
        {
            ActionAdmission::Admitted => Ok(()),
            ActionAdmission::NotHeld { named: true } => Err(PersistenceError::Conflict(format!(
                "failed_precondition: the self-service window of {} has elapsed",
                kind.as_str()
            ))),
            ActionAdmission::NotHeld { named: false } => Err(capability_denied(format!(
                "the actor holds no action authorizing {} on this target",
                kind.as_str()
            ))),
        }
    }

    /// The target and operation facts an Event names in its own payload.
    fn event_operation(
        &self,
        event: &arkret_wire::Event,
    ) -> (WireResourceSelector, OperationFacts) {
        let realm = WireResourceSelector::realm(self.realm_id.clone());
        let kind = event.kind.as_str();
        let family = kind
            .strip_prefix("ak.")
            .and_then(|rest| rest.split('.').next())
            .filter(|family| {
                matches!(
                    *family,
                    "strand" | "message" | "morph" | "space" | "circle" | "relation" | "view"
                )
            })
            .map(str::to_owned);
        let payload_id = |field: &str| {
            event
                .payload
                .get(field)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let mut facts = OperationFacts {
            object_kind: family,
            strand_id: payload_id("strand_id"),
            space_id: payload_id("space_id"),
            circle_id: payload_id("circle_id"),
            ..OperationFacts::default()
        };
        if event.kind == EventKind::MessageCreate {
            facts.track = Some(DISCUSSION_TRACK.to_owned());
            if let Some(strand_id) = facts
                .strand_id
                .as_deref()
                .and_then(|value| value.parse::<StrandId>().ok())
            {
                return (
                    WireResourceSelector::strand(self.realm_id.clone(), strand_id),
                    facts,
                );
            }
        }
        (realm, facts)
    }
}

/// The lifecycle gates of `realm-and-space.md` §2.6.0/§2.6.1, folded from the
/// Realm's committed lifecycle Events in stream order. Every one of them
/// commits on the Realm stream under the authority row lock, so the fold read
/// after that lock is the cut's own.
#[derive(Clone, Copy, Debug, Default)]
struct RealmLifecycleGates {
    archived: bool,
    frozen: bool,
    terminal: bool,
}

impl RealmLifecycleGates {
    async fn read(conn: &mut AsyncPgConnection, realm_id: &RealmId) -> PersistenceResult<Self> {
        let events = sql_query(
            "SELECT e.kind FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
             WHERE e.realm_id=$1 AND c.realm_id=e.realm_id AND e.state='committed' \
               AND e.kind IN ('ak.realm.archive','ak.realm.restore','ak.realm.freeze',\
                              'ak.realm.unfreeze','ak.realm.tombstone','ak.realm.destroy') \
             ORDER BY c.stream_position ASC",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<LifecycleRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut gates = Self::default();
        for event in events {
            match event.kind.as_str() {
                "ak.realm.archive" => gates.archived = true,
                "ak.realm.restore" => gates.archived = false,
                "ak.realm.freeze" => gates.frozen = true,
                "ak.realm.unfreeze" => gates.frozen = false,
                _ => gates.terminal = true,
            }
        }
        Ok(gates)
    }
}

/// The track every Message belongs to (`authz/constraint-schema.md` §6.1).
const DISCUSSION_TRACK: &str = "discussion";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionAdmission {
    Admitted,
    /// No grant admits the operation; `named` when some grant names it.
    NotHeld {
        named: bool,
    },
}

const ACTOR_EQ_TARGET_AUTHOR: &str = "actor_eq_target_author";

/// The author and creation time of the object a `.own` action targets.
pub(crate) struct AuthoredTarget<'a> {
    pub(crate) author: &'a ActorId,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) strand_id: &'a StrandId,
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
    let cut = RealmAuthorizationCut::read_for_event(conn, event).await?;
    cut.require_event_in_connection(conn, event, at).await?;
    Ok(cut)
}
