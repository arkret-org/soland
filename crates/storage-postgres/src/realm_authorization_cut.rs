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
//! An action whose registry row lists `required_evaluator_checks` is never
//! sufficient on its own: only a kind-specific caller that discharges those
//! checks may count it. The one such check decided here is
//! `actor_eq_target_author` of the `.own` Message actions
//! ([`RealmAuthorizationCut::require_authored_target_kind`]), together with the
//! self-service windows of `authz/constraint-schema.md` §14.2 that their
//! `required_constraints` name.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload;
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, GrantConstraint, GrantConstraintEffect,
    GrantConstraintKind, GrantConstraintSubkind, IssuerAuthorityRef,
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
        self.covering_grants(actions, at).next().is_some()
    }

    /// Every grant that alone would satisfy [`Self::grants_cover_any`].
    fn covering_grants<'a>(
        &'a self,
        actions: &'a [&'a str],
        at: chrono::DateTime<chrono::Utc>,
    ) -> impl Iterator<Item = &'a CapabilityGrant> + 'a {
        let root = self.root.as_ref();
        let realm = WireResourceSelector::realm(self.realm_id.clone());
        self.grants.iter().filter_map(move |(grant_id, grant)| {
            let root = root?;
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
            (covers
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
                    }))
                .then_some(grant)
        })
    }

    /// Whether the actor holds one of the actions authorizing `kind`: the
    /// root controller through its effective `ak.realm.owner`, anyone else
    /// through an active covering grant.
    ///
    /// Actions with registered evaluator checks are left out: they authorize
    /// only through the caller that discharges those checks.
    pub(crate) fn holds_event_kind(
        &self,
        kind: &EventKind,
        at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let actions = arkret_schema::capability_actions_for_event_kind(kind.as_str())
            .filter(|descriptor| descriptor.required_evaluator_checks.is_empty())
            .map(|descriptor| descriptor.action.as_str())
            .collect::<Vec<_>>();
        (self.actor_is_root_controller() && actions.contains(&CapabilityActionId::REALM_OWNER))
            || self.grants_cover_any(&actions, at)
    }

    /// The Realm has an authority root and a policy bundle at this cut and the
    /// actor is a joined member of it.
    pub(crate) fn require_governed_member(&self, kind: &EventKind) -> PersistenceResult<()> {
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

    /// The complete capability-gated verdict for `kind`: the Realm has an
    /// authority root and a policy bundle, the actor is a joined member, and
    /// the actor holds an authorizing action.
    pub(crate) fn require_event_kind(
        &self,
        kind: &EventKind,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        self.require_governed_member(kind)?;
        if !self.holds_event_kind(kind, at) {
            return Err(capability_denied(format!(
                "the actor holds no action authorizing {}",
                kind.as_str()
            )));
        }
        Ok(())
    }

    /// The capability-gated verdict for a `kind` that acts on one authored
    /// object: an unconditional action as in [`Self::require_event_kind`], or,
    /// when the actor authored `target`, an action whose only evaluator check is
    /// `actor_eq_target_author` on a covering grant whose self-service window
    /// (`authz/constraint-schema.md` §14.2) still contains `at`. A window that
    /// elapsed is `failed_precondition`, never a capability grant.
    pub(crate) fn require_authored_target_kind(
        &self,
        kind: &EventKind,
        target: &AuthoredTarget<'_>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        self.require_governed_member(kind)?;
        if self.holds_event_kind(kind, at) {
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
        let mut window_elapsed = false;
        for action in &own_actions {
            for grant in self.covering_grants(std::slice::from_ref(action), at) {
                if self_service_window_permits(grant, action, target.created_at, at) {
                    return Ok(());
                }
                window_elapsed = true;
            }
        }
        if window_elapsed {
            return Err(PersistenceError::Conflict(format!(
                "failed_precondition: the self-service window of {} has elapsed",
                kind.as_str()
            )));
        }
        Err(capability_denied(format!(
            "the actor holds no action authorizing {} on this target",
            kind.as_str()
        )))
    }
}

const ACTOR_EQ_TARGET_AUTHOR: &str = "actor_eq_target_author";

/// The author and creation time of the object a `.own` action targets.
pub(crate) struct AuthoredTarget<'a> {
    pub(crate) author: &'a ActorId,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
}

/// Seconds of one designator run such as `2W3D` or `1H30M`; each designator
/// appears at most once and in the order of `units`.
fn designator_seconds(part: &str, units: &[(char, i64)]) -> Option<i64> {
    let mut total = 0_i64;
    let mut digits = String::new();
    let mut remaining = units;
    for character in part.chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        let offset = remaining.iter().position(|(unit, _)| *unit == character)?;
        let amount = digits.parse::<i64>().ok()?;
        total = total.checked_add(amount.checked_mul(remaining[offset].1)?)?;
        digits.clear();
        remaining = &remaining[offset + 1..];
    }
    digits.is_empty().then_some(total)
}

/// A registered window `P[nW][nD][T[nH][nM][nS]]`. Year and month designators
/// have no fixed length, so a window spelled with them contains no instant.
fn window_duration(value: &str) -> Option<chrono::TimeDelta> {
    let rest = value.strip_prefix('P').filter(|rest| !rest.is_empty())?;
    let (date, time) = match rest.split_once('T') {
        Some((_, "")) => return None,
        Some((date, time)) => (date, time),
        None => (rest, ""),
    };
    let seconds = designator_seconds(date, &[('W', 7 * 86_400), ('D', 86_400)])?.checked_add(
        designator_seconds(time, &[('H', 3_600), ('M', 60), ('S', 1)])?,
    )?;
    chrono::TimeDelta::try_seconds(seconds)
}

fn within_window(
    created_at: chrono::DateTime<chrono::Utc>,
    window: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> bool {
    window_duration(window)
        .and_then(|window| created_at.checked_add_signed(window))
        .is_some_and(|closes| at >= created_at && at <= closes)
}

/// `authz/constraint-schema.md` §15 for one `.own` action on one grant: every
/// temporal constraint that governs the action must permit it. A constraint
/// that names other actions only is neutral; an edit or redact window without
/// an action gate, or a governing constraint whose effect is not `allow`, fails
/// closed.
fn self_service_window_permits(
    grant: &CapabilityGrant,
    action: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    at: chrono::DateTime<chrono::Utc>,
) -> bool {
    grant
        .constraints
        .iter()
        .all(|constraint| constraint_permits_own_action(constraint, action, created_at, at))
}

fn constraint_permits_own_action(
    constraint: &GrantConstraint,
    action: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    at: chrono::DateTime<chrono::Utc>,
) -> bool {
    if constraint.constraint_kind != GrantConstraintKind::Temporal {
        return false;
    }
    let window_subkind = matches!(
        constraint.constraint_subkind,
        Some(GrantConstraintSubkind::EditWindow | GrantConstraintSubkind::RedactWindow)
    );
    if constraint.applies_to_actions.is_empty() {
        if window_subkind {
            return false;
        }
    } else if !constraint
        .applies_to_actions
        .iter()
        .any(|governed| governed == action)
    {
        return constraint.effect == GrantConstraintEffect::Allow;
    }
    if constraint.effect != GrantConstraintEffect::Allow {
        return false;
    }
    let edit = constraint.message_edit_window.as_deref();
    let redact = constraint.message_redact_window.as_deref();
    match action {
        CapabilityActionId::MESSAGE_REVISE_OWN => {
            edit.is_none_or(|window| within_window(created_at, window, at))
        }
        CapabilityActionId::MESSAGE_REDACT_OWN => match (redact, edit) {
            (Some(window), _) => within_window(created_at, window, at),
            (None, Some(window)) if constraint.redact_after_window_allowed != Some(true) => {
                within_window(created_at, window, at)
            }
            _ => true,
        },
        _ => false,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn at(minutes: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap()
            + chrono::TimeDelta::minutes(minutes)
    }

    fn window(subkind: GrantConstraintSubkind, actions: &[&str]) -> GrantConstraint {
        let mut constraint =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
        constraint.constraint_subkind = Some(subkind);
        constraint.applies_to_actions = actions.iter().map(|action| (*action).to_owned()).collect();
        constraint
    }

    #[test]
    fn registered_windows_have_fixed_lengths_only() {
        for (value, seconds) in [
            ("PT15M", 900),
            ("PT24H", 86_400),
            ("P1W2DT3H4M5S", 9 * 86_400 + 3 * 3_600 + 4 * 60 + 5),
            ("P0D", 0),
        ] {
            assert_eq!(
                window_duration(value),
                chrono::TimeDelta::try_seconds(seconds),
                "{value}"
            );
        }
        for value in [
            "P", "PT", "P1Y", "P1M", "PT1H1H", "PT1M1H", "15M", "P1DT", "PT-1S",
        ] {
            assert_eq!(window_duration(value), None, "{value}");
        }
    }

    #[test]
    fn own_actions_follow_their_own_window_and_ignore_the_other() {
        let revise_own = CapabilityActionId::MESSAGE_REVISE_OWN;
        let redact_own = CapabilityActionId::MESSAGE_REDACT_OWN;
        let mut edit = window(GrantConstraintSubkind::EditWindow, &[revise_own]);
        edit.message_edit_window = Some("PT15M".to_owned());
        assert!(constraint_permits_own_action(
            &edit,
            revise_own,
            at(0),
            at(15)
        ));
        assert!(!constraint_permits_own_action(
            &edit,
            revise_own,
            at(0),
            at(16)
        ));
        // A window gated to another action is neutral.
        assert!(constraint_permits_own_action(
            &edit,
            redact_own,
            at(0),
            at(600)
        ));

        // Redact shares the edit window it is gated by unless it opts out.
        let mut shared = window(
            GrantConstraintSubkind::EditWindow,
            &[revise_own, redact_own],
        );
        shared.message_edit_window = Some("PT15M".to_owned());
        assert!(!constraint_permits_own_action(
            &shared,
            redact_own,
            at(0),
            at(16)
        ));
        shared.redact_after_window_allowed = Some(true);
        assert!(constraint_permits_own_action(
            &shared,
            redact_own,
            at(0),
            at(600)
        ));
        shared.message_redact_window = Some("PT1H".to_owned());
        assert!(!constraint_permits_own_action(
            &shared,
            redact_own,
            at(0),
            at(61)
        ));

        // A window without its action gate, a non-allow governing effect and a
        // non-temporal constraint fail closed.
        let mut ungated = window(GrantConstraintSubkind::EditWindow, &[]);
        ungated.message_edit_window = Some("PT15M".to_owned());
        assert!(!constraint_permits_own_action(
            &ungated,
            revise_own,
            at(0),
            at(1)
        ));
        let mut denying = edit.clone();
        denying.effect = GrantConstraintEffect::Deny;
        assert!(!constraint_permits_own_action(
            &denying,
            revise_own,
            at(0),
            at(1)
        ));
        let quota = GrantConstraint::new(GrantConstraintKind::Quota, GrantConstraintEffect::Allow);
        assert!(!constraint_permits_own_action(
            &quota,
            revise_own,
            at(0),
            at(1)
        ));
    }
}
