//! Same-cut admission of one ordinary `ak.member.state` transition.
//!
//! The Realm membership FSM (`common-fields.md` §4.5, `realm-and-space.md`
//! §2.7) is decided here, inside the Event's RealmCommit transaction, against
//! the locked durable member row, the Realm's typed join rule and join policy
//! and the writer's capability at the accepting cut. The in-memory projection
//! only pre-checks; nothing it holds is authority.
//!
//! Supported writers are the target ActorId itself and a writer holding
//! `ak.realm.admin` at the same cut (the Realm root controller holds every
//! action). Invite acceptance, the Agent controller carve-out, Circle and
//! Strand scoped membership, Direct Conversation profiles and join policies
//! whose proof gates need a same-cut re-evaluation stay closed.

use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use diesel::sql_types::{Bool, Jsonb, Text};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{ConflictCode, PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[derive(diesel::QueryableByName)]
struct CurrentValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct MembershipRow {
    #[diesel(sql_type = Text)]
    membership: String,
}

fn failed_precondition(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::FailedPrecondition))
}

fn capability_denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::CapabilityDenied))
}

fn gate_check_failed() -> PersistenceError {
    PersistenceError::Conflict(ConflictCode::GateCheckFailed.as_str().to_owned())
}

fn unsupported(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::UnsupportedFeature))
}

fn state_name(state: MembershipPayloadState) -> &'static str {
    match state {
        MembershipPayloadState::Join => "join",
        MembershipPayloadState::Knock => "knock",
        MembershipPayloadState::Leave => "leave",
        MembershipPayloadState::Ban => "ban",
    }
}

/// Who may write one listed edge of the shared membership FSM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EdgeWriter {
    /// Only the target ActorId, subject to the join rule.
    SelfEntry,
    /// The target ActorId or an authorized administrator.
    SelfOrAdmin,
    /// Only an authorized administrator.
    Admin,
}

/// The closed edge table of `common-fields.md` §4.5 for an ordinary
/// transition. `leave -> join` by invite acceptance is a separate Event kind
/// and the bootstrap creator slot is its own atomic unit, so neither is here.
fn edge_writer(from: &str, to: &str) -> Option<EdgeWriter> {
    match (from, to) {
        ("leave", "knock" | "join") => Some(EdgeWriter::SelfEntry),
        ("knock", "join") => Some(EdgeWriter::Admin),
        ("knock", "leave") | ("join", "leave") => Some(EdgeWriter::SelfOrAdmin),
        ("leave" | "knock" | "join", "ban") => Some(EdgeWriter::Admin),
        ("ban", "leave") => Some(EdgeWriter::Admin),
        _ => None,
    }
}

async fn realm_current_value(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    family: &str,
) -> PersistenceResult<Option<Value>> {
    Ok(sql_query(
        "SELECT b.value FROM realm_bootstrap_current_results b \
         JOIN realm_commits c ON c.commit_id=b.current_commit_id \
         WHERE b.realm_id=$1 AND b.result_family=$2 \
           AND c.realm_id=b.realm_id AND c.stream_position=b.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=b.realm_id \
         FOR SHARE OF b",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(family)
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(|row| row.value))
}

/// The Realm's join policy component at this cut, if one is declared.
async fn join_policy(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<Value>> {
    Ok(sql_query(
        "SELECT value FROM realm_policy_bundle_current_results WHERE realm_id=$1 FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .and_then(|row| row.value.get("join_policy").cloned()))
}

/// Entry by the target itself (`leave -> join` or `leave -> knock`).
///
/// The rule must open that entry. Every declared gate would have to be
/// re-evaluated at this cut; a policy whose only gates are
/// `parent_membership` is already re-proved by the co-governed dependency
/// transaction, and any other gate stays closed until its proof and replay
/// inputs are read here too.
async fn check_self_entry(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    to: &str,
    has_gate_proofs: bool,
) -> PersistenceResult<()> {
    let rule = realm_current_value(conn, realm_id, "realm_join_rule")
        .await?
        .ok_or_else(gate_check_failed)?;
    let rule = rule.as_str().ok_or_else(gate_check_failed)?;
    let entry_open = match to {
        "join" => rule == "public",
        "knock" => rule == "knock",
        _ => false,
    };
    if !entry_open {
        return Err(gate_check_failed());
    }
    let policy = join_policy(conn, realm_id).await?;
    let gates = policy
        .as_ref()
        .map(|policy| {
            policy
                .get("gates")
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(gate_check_failed)
        })
        .transpose()?
        .unwrap_or_default();
    let only_parent_membership = gates
        .iter()
        .all(|gate| gate.get("kind").and_then(Value::as_str) == Some("parent_membership"));
    if !only_parent_membership || (has_gate_proofs && gates.is_empty()) {
        return Err(gate_check_failed());
    }
    Ok(())
}

async fn holds_realm_admin(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<bool> {
    crate::capability_grant_current_results::actor_holds_realm_action_in_connection(
        conn,
        &event.realm_id,
        &event.actor_id,
        &[arkret_wire::CapabilityActionId::REALM_ADMIN],
        commit.committed_at,
    )
    .await
}

/// Decide one `ak.member.state` Event at its accepting cut.
///
/// Runs before any write of the Event's transaction, after the co-governed
/// `parent_membership` cut (if any) was locked, and takes the member row lock
/// the current writer uses.
pub(crate) async fn admit_member_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::MemberState {
        return Ok(());
    }
    if !matches!(&event.scope_ref, arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &event.realm_id)
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(unsupported(
            "Realm membership is admitted only on the Realm stream",
        ));
    }
    if event.executed_by.is_some() || event.applet_id.is_some() {
        return Err(unsupported(
            "delegated or Applet-authored membership has no same-cut admission",
        ));
    }
    let payload: MembershipPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if payload
        .realm_id
        .as_ref()
        .is_some_and(|realm_id| realm_id != &event.realm_id)
    {
        return Err(PersistenceError::SchemaViolation(
            "member_state realm_id differs from its Event Realm".to_owned(),
        ));
    }
    if payload.strand_id.is_some()
        || payload.invite_ref.is_some()
        || payload.agent_controller_binding.is_some()
        || payload.membership_cause.is_some()
    {
        return Err(unsupported(
            "scoped, invited, Agent-bound or cascade membership has its own admission",
        ));
    }
    let ordinary = sql_query(
        "SELECT EXISTS (SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_position=0 AND e.kind='ak.realm.create' \
           AND e.state='committed' AND e.envelope->'payload'->'object'->>'purpose'='collaboration') AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !ordinary.present {
        return Err(unsupported(
            "membership of this Realm role is governed by its own profile",
        ));
    }
    if let Some(account) = payload.member_id.as_account_id() {
        let agent = sql_query(
            "SELECT EXISTS (SELECT 1 FROM agent_status_current_results WHERE agent_id=$1) AS present",
        )
        .bind::<Text, _>(account.principal_id.as_str())
        .get_result::<PresentRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if agent.present {
            return Err(unsupported(
                "Agent membership needs its controller binding admission",
            ));
        }
    }

    let member_key = payload.member_id.to_string();
    crate::unit_of_work::advisory_lock(
        conn,
        format!(
            "parent-membership:member:{}:{member_key}",
            event.realm_id.as_str()
        ),
    )
    .await?;
    let from = sql_query(
        "SELECT m.membership FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         WHERE m.realm_id=$1 AND m.member_id=$2 \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id \
         FOR UPDATE OF m",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&member_key)
    .get_result::<MembershipRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map_or_else(|| "leave".to_owned(), |row| row.membership);
    let to = state_name(payload.membership);
    let writer = edge_writer(&from, to)
        .ok_or_else(|| failed_precondition("membership transition is not a listed edge"))?;
    let self_authored = event.actor_id == payload.member_id;
    match writer {
        EdgeWriter::SelfEntry => {
            if !self_authored {
                return Err(capability_denied(
                    "only the target itself may enter a Realm by membership state",
                ));
            }
            check_self_entry(conn, &event.realm_id, to, !payload.gate_proofs.is_empty()).await
        }
        EdgeWriter::SelfOrAdmin => {
            if self_authored || holds_realm_admin(conn, event, commit).await? {
                Ok(())
            } else {
                Err(capability_denied(
                    "the writer holds no same-cut Realm administration capability",
                ))
            }
        }
        EdgeWriter::Admin => {
            if holds_realm_admin(conn, event, commit).await? {
                Ok(())
            } else {
                Err(capability_denied(
                    "the writer holds no same-cut Realm administration capability",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EdgeWriter, edge_writer};

    #[test]
    fn only_the_listed_membership_edges_have_a_writer() {
        let states = ["join", "knock", "leave", "ban"];
        let mut listed = Vec::new();
        for from in states {
            for to in states {
                if let Some(writer) = edge_writer(from, to) {
                    listed.push((from, to, writer));
                }
            }
        }
        assert_eq!(
            listed,
            vec![
                ("join", "leave", EdgeWriter::SelfOrAdmin),
                ("join", "ban", EdgeWriter::Admin),
                ("knock", "join", EdgeWriter::Admin),
                ("knock", "leave", EdgeWriter::SelfOrAdmin),
                ("knock", "ban", EdgeWriter::Admin),
                ("leave", "join", EdgeWriter::SelfEntry),
                ("leave", "knock", EdgeWriter::SelfEntry),
                ("leave", "ban", EdgeWriter::Admin),
                ("ban", "leave", EdgeWriter::Admin),
            ]
        );
    }
}
