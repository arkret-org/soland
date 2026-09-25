//! The `moderation_state` typed current writer at the accepting RealmCommit cut.
//!
//! `governance/content-moderation.md` §2.6 makes every committed moderation
//! decision and lift an assertion in the per-target `moderation_state` set:
//! each element is tagged by the accepting Event's `<event_id>:0` dot and
//! carries the complete payload, and neither writer removes an element. The
//! active-decision fold and the queue item status are read-side derivations.
//!
//! The supported carrier is a Realm-scope decision on the Realm stream whose
//! issuer holds the moderation capability at this same cut: the current Realm
//! root controller, or an active Capability Grant naming the issuer for the
//! decision action on this Realm. Circle-scope targets need their own
//! authority cut and remain closed.

use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct StateRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

fn conflict(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(detail.into())
}

fn target_not_found() -> PersistenceError {
    PersistenceError::NotFound("moderation target not found".to_owned())
}

fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("stored moderation_state is invalid: {detail}"))
}

/// The canonical `<event_id>:<write_index>` dot of the single registered
/// `moderation_state` write of `event`.
pub(crate) fn assertion_tag(event_id: &arkret_wire::EventId) -> String {
    format!("{event_id}:0")
}

/// The Event id half of one assertion tag.
pub(crate) fn tag_event_id(tag: &str) -> PersistenceResult<arkret_wire::EventId> {
    let (event_id, index) = tag
        .rsplit_once(':')
        .ok_or_else(|| corrupt("assertion tag has no write index"))?;
    if index != "0" {
        return Err(corrupt("assertion tag names an unregistered write index"));
    }
    arkret_wire::EventId::new(event_id.to_owned()).map_err(corrupt)
}

/// The stored assertions of `target_ref`, locked for this transaction.
async fn locked_state(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    target_ref: &str,
) -> PersistenceResult<Option<StateRow>> {
    diesel::sql_query(
        "SELECT value, current_commit_id, current_stream_position \
         FROM moderation_state_current_results WHERE realm_id=$1 AND target_ref=$2 FOR UPDATE",
    )
    .bind::<Text, _>(realm_id)
    .bind::<Text, _>(target_ref)
    .get_result::<StateRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)
}

fn assertions(value: &Value) -> PersistenceResult<Vec<Value>> {
    value
        .get("assertions")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| corrupt("value has no assertions"))
}

/// A report queue item may be dismissed only by naming an accepted report of
/// this Realm committed strictly before the decision.
async fn ensure_report_target(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    report_event_id: &str,
    before_position: i64,
) -> PersistenceResult<()> {
    let present = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM moderation_report_current_results r \
         JOIN realm_commits c ON c.commit_id=r.current_commit_id \
         WHERE r.realm_id=$1 AND r.report_event_id=$2 AND c.stream_position<$3 \
           AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=r.realm_id) AS present",
    )
    .bind::<Text, _>(realm_id)
    .bind::<Text, _>(report_event_id)
    .bind::<BigInt, _>(before_position)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present;
    if present {
        Ok(())
    } else {
        Err(target_not_found())
    }
}

pub(crate) async fn commit_moderation_state_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let lift = match event.kind {
        arkret_wire::EventKind::ModerationDecision => false,
        arkret_wire::EventKind::ModerationDecisionLift => true,
        _ => return Ok(()),
    };
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    if !matches!(&event.scope_ref, arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &event.realm_id)
        || commit.stream_ref != realm_stream
        || commit.event_ref != event.event_id
    {
        return Err(conflict(
            "moderation_state current writer requires the Realm source stream",
        ));
    }
    if event.executed_by.is_some() || event.applet_id.is_some() {
        return Err(conflict(
            "moderation decision must be directly authored by its issuer",
        ));
    }
    let before = i64::try_from(commit.stream_position)
        .map_err(|_| conflict("invalid moderation decision stream position"))?;
    let action = if lift {
        arkret_wire::CapabilityActionId::MODERATION_DECISION_LIFT
    } else {
        arkret_wire::CapabilityActionId::MODERATION_DECISION
    };
    if !crate::capability_grant_current_results::actor_holds_realm_action_in_connection(
        conn,
        &event.realm_id,
        &event.actor_id,
        &[arkret_wire::CapabilityActionId::POLICY_MANAGE, action],
        commit.committed_at,
    )
    .await?
    {
        return Err(conflict(
            "missing_capability: the moderation issuer holds no same-cut moderation capability",
        ));
    }
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let realm_id = event.realm_id.as_str();
    let target_ref = if lift {
        let typed: arkret_models_collaboration::events_payloads::moderation::ModerationDecisionLiftPayload =
            serde_json::from_value(payload.clone())
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        typed.target_ref
    } else {
        let typed: arkret_models_collaboration::events_payloads::moderation::ModerationDecisionPayload =
            serde_json::from_value(payload.clone())
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if &typed.issuer_id != event.actor_id.signing_principal_id() {
            return Err(conflict(
                "moderation_actor_mismatch: issuer_id is not the signing issuer",
            ));
        }
        if typed.decision == "dismiss" {
            ensure_report_target(conn, realm_id, typed.target_ref.as_str(), before).await?;
        } else {
            crate::moderation_report_current_results::ensure_realm_scope_target(
                conn,
                realm_id,
                typed.target_ref.as_str(),
                before,
            )
            .await?;
        }
        typed.target_ref
    };
    let current = locked_state(conn, realm_id, target_ref.as_str()).await?;
    let mut entries = match &current {
        Some(row) => assertions(&row.value)?,
        None => Vec::new(),
    };
    if lift {
        let typed: arkret_models_collaboration::events_payloads::moderation::ModerationDecisionLiftPayload =
            serde_json::from_value(payload.clone())
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let Some(row) = current.as_ref() else {
            return Err(target_not_found());
        };
        if typed.expected_revision.commit_id.as_str() != row.current_commit_id
            || i64::try_from(typed.expected_revision.stream_position).ok()
                != Some(row.current_stream_position)
        {
            return Err(conflict(
                "cas_conflict: moderation_state moved past the expected revision",
            ));
        }
        let decision_tag = assertion_tag(&typed.decision_ref);
        let decided = entries.iter().any(|entry| {
            entry.get("tag_id").and_then(Value::as_str) == Some(decision_tag.as_str())
                && entry.pointer("/value/decision").is_some()
        });
        let lifted = entries.iter().any(|entry| {
            entry.pointer("/value/decision_ref").and_then(Value::as_str)
                == Some(typed.decision_ref.as_str())
        });
        if !decided || lifted {
            return Err(conflict(
                "failed_precondition: decision_ref names no active decision of this target",
            ));
        }
    }
    let tag = assertion_tag(&event.event_id);
    if entries
        .iter()
        .any(|entry| entry.get("tag_id").and_then(Value::as_str) == Some(tag.as_str()))
    {
        return Err(conflict(
            "duplicate_conflict: moderation assertion already exists",
        ));
    }
    entries.push(json!({"tag_id": tag, "value": payload}));
    entries.sort_by(|left, right| {
        left.get("tag_id")
            .and_then(Value::as_str)
            .cmp(&right.get("tag_id").and_then(Value::as_str))
    });
    let value = json!({"assertions": entries});
    diesel::sql_query(
        "INSERT INTO moderation_state_current_results \
         (realm_id,target_ref,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) \
         ON CONFLICT (realm_id,target_ref) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value, updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(realm_id)
    .bind::<Text, _>(target_ref.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(before)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}
