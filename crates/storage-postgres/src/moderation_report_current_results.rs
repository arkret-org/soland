//! The `moderation_report` typed current writer at the accepting RealmCommit cut.
//!
//! `governance/content-moderation.md` §3.3 makes the accepted
//! `ak.self.moderation.report` Event itself the canonical fact: the subject is
//! the Event's own id and the value is the complete signed payload. The
//! supported carrier is the reporter-authored self report on the Realm stream;
//! Circle-scope reports and MIMI facade reports need their own authority cut
//! and remain closed.

use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[derive(diesel::QueryableByName)]
struct StrandScopeRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn conflict(detail: &'static str) -> PersistenceError {
    PersistenceError::Conflict(detail.to_owned())
}

/// The single anti-oracle answer for an absent, invisible or scope-mismatched
/// target (`ak.self.moderation.command.report.v1` operation mapping).
fn target_not_found() -> PersistenceError {
    PersistenceError::NotFound("moderation target not found".to_owned())
}

fn position(commit: &arkret_wire::RealmCommit) -> PersistenceResult<i64> {
    i64::try_from(commit.stream_position).map_err(|_| conflict("invalid report stream position"))
}

async fn present(
    conn: &mut AsyncPgConnection,
    query: &'static str,
    realm_id: &str,
    subject: &str,
    before_position: i64,
) -> PersistenceResult<bool> {
    Ok(diesel::sql_query(query)
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(subject)
        .bind::<BigInt, _>(before_position)
        .get_result::<PresentRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present)
}

/// Prove the signed `target_ref` names an accepted Realm-scope object of this
/// Realm strictly before the report's own Commit on the same Realm stream.
pub(crate) async fn ensure_realm_scope_target(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    target_ref: &str,
    before_position: i64,
) -> PersistenceResult<()> {
    if target_ref == realm_id {
        return Ok(());
    }
    let kind = target_ref
        .strip_prefix("ak:")
        .and_then(|rest| rest.split_once(':'))
        .map_or("", |(kind, _)| kind);
    let found = match kind {
        "event" => {
            present(
                conn,
                "SELECT EXISTS (SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
                 WHERE c.realm_id=$1 AND c.commit_json->>'event_ref'=$2 AND c.stream_position<$3 \
                   AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=c.realm_id \
                   AND e.state='committed' AND e.envelope->'scope_ref'->>'kind'='realm') AS present",
                realm_id,
                target_ref,
                before_position,
            )
            .await?
        }
        "message" => {
            present(
                conn,
                "SELECT EXISTS (SELECT 1 FROM message_revision_current_results m \
                 JOIN realm_commits c ON c.commit_id=m.current_commit_id \
                 WHERE m.realm_id=$1 AND m.message_id=$2 AND c.stream_position<$3 \
                   AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
                   AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id) AS present",
                realm_id,
                target_ref,
                before_position,
            )
            .await?
        }
        "strand" => {
            let strand = diesel::sql_query(
                "SELECT s.value FROM strand_current_results s \
                 JOIN realm_commits c ON c.commit_id=s.current_commit_id \
                 WHERE s.realm_id=$1 AND s.strand_id=$2 AND c.stream_position<$3 \
                   AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position \
                   AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id \
                 FOR SHARE OF s",
            )
            .bind::<Text, _>(realm_id)
            .bind::<Text, _>(target_ref)
            .bind::<BigInt, _>(before_position)
            .get_result::<StrandScopeRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            strand.is_some_and(|row| {
                row.value
                    .get("scope_circle_id")
                    .is_none_or(Value::is_null)
            })
        }
        // Other object families have no same-cut typed current here yet.
        _ => false,
    };
    if found {
        Ok(())
    } else {
        Err(target_not_found())
    }
}

pub(crate) async fn commit_moderation_report_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::SelfModerationReport {
        return Ok(());
    }
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
            "moderation report current writer requires the Realm source stream",
        ));
    }
    if event.executed_by.is_some() || event.authorization_ref.is_some() || event.applet_id.is_some()
    {
        return Err(conflict(
            "self moderation report must be directly authored by its reporter",
        ));
    }
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let typed: arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload =
        serde_json::from_value(payload.clone())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    typed
        .validate_self_endpoint(event.actor_id.signing_principal_id())
        .map_err(|error| PersistenceError::Conflict(error.to_owned()))?;
    if typed.realm_id != event.realm_id {
        return Err(target_not_found());
    }
    if typed.effective_scope.as_ref().is_some_and(|scope| {
        !matches!(scope, arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &event.realm_id)
    }) {
        return Err(target_not_found());
    }
    let before = position(commit)?;
    // The reporter must be a confirmed joined member at this same cut. The
    // Realm authority row is already locked by the just-installed Commit, so a
    // concurrent membership transition waits for this transaction.
    let member = present(
        conn,
        "SELECT EXISTS (SELECT 1 FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join' \
           AND c.stream_position<$3 \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id) AS present",
        event.realm_id.as_str(),
        &event.actor_id.to_string(),
        before,
    )
    .await?;
    if !member {
        return Err(target_not_found());
    }
    ensure_realm_scope_target(
        conn,
        event.realm_id.as_str(),
        typed.target_ref.as_str(),
        before,
    )
    .await?;
    let inserted = diesel::sql_query(
        "INSERT INTO moderation_report_current_results \
         (realm_id,report_event_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(before)
    .bind::<Jsonb, _>(&payload)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(conflict(
            "duplicate_conflict: moderation report current result already exists",
        ));
    }
    Ok(())
}
