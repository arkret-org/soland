//! Typed current a member Station keeps for a Realm stream it holds as a
//! replica of a Realm another Station governs (`federation.md` §4.1.1,
//! member Station bootstrap).
//!
//! The governing Station's verified bootstrap snapshot is installed once,
//! anchored at its head; every later replica then advances the same result
//! families with the registered result each committed Event derives. A
//! member Station never admits: the governing Station's RealmCommit is the
//! accepted judgement, so these writers carry no capability, CAS or
//! lifecycle gate, only the projection of the committed Event.
//!
//! The member Station keeps the families its recipient re-verification and
//! local reads consume: the Realm singletons (history access, plaintext
//! services, profile), the policy bundle, `member_state`, `strand`, the
//! default Strand pointer, `message_revision` and `object_redaction`. The
//! authority root, capability grants, Invite registers and MLS group state
//! are governing admission inputs whose rows hold Station-private material a
//! snapshot row does not carry (the authority Event ref, the accepting
//! Event id, the public RFC 9420 tracker); a member Station keeps none of
//! them and never reads them.

use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{PersistenceError, PersistenceResult};

/// Every table a member Station projects a replica Realm into.
const MEMBER_STATION_FAMILIES: &[&str] = &[
    "realm_bootstrap_current_results",
    "realm_policy_bundle_current_results",
    "realm_link_current_results",
    "member_state_current_results",
    "strand_current_results",
    "realm_set_default_strand_current_results",
    "message_revision_current_results",
    "object_redaction_current_results",
];

fn position(value: u64) -> PersistenceResult<i64> {
    i64::try_from(value).map_err(|_| {
        PersistenceError::SchemaViolation("stream position exceeds PostgreSQL BIGINT".to_owned())
    })
}

fn malformed(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("bootstrap snapshot row is malformed: {detail}"))
}

struct Revision<'a> {
    commit_id: &'a str,
    stream_position: i64,
    updated_at: chrono::DateTime<chrono::Utc>,
}

async fn upsert_singleton(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    family: &str,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    diesel::sql_query(
        "INSERT INTO realm_bootstrap_current_results \
         (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id,result_family) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(family)
    .bind::<Text, _>(revision.commit_id)
    .bind::<BigInt, _>(revision.stream_position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(revision.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

/// Upsert one row of a family keyed by `(realm_id)` or `(realm_id, key)`.
async fn upsert_keyed(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    table: &'static str,
    key: Option<(&'static str, &str)>,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    let sql = match key {
        Some((column, _)) => format!(
            "INSERT INTO {table} \
             (realm_id,{column},current_commit_id,current_stream_position,value,updated_at) \
             VALUES($1,$6,$2,$3,$4,$5) ON CONFLICT({conflict}) DO UPDATE SET \
             current_commit_id=EXCLUDED.current_commit_id, \
             current_stream_position=EXCLUDED.current_stream_position, \
             value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
            conflict = match table {
                "strand_current_results" => "strand_id",
                "message_revision_current_results" => "message_id",
                _ => "realm_id,target_ref",
            },
        ),
        None => format!(
            "INSERT INTO {table} \
             (realm_id,current_commit_id,current_stream_position,value,updated_at) \
             VALUES($1,$2,$3,$4,$5) ON CONFLICT(realm_id) DO UPDATE SET \
             current_commit_id=EXCLUDED.current_commit_id, \
             current_stream_position=EXCLUDED.current_stream_position, \
             value=EXCLUDED.value,updated_at=EXCLUDED.updated_at"
        ),
    };
    let query = diesel::sql_query(sql)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(revision.commit_id)
        .bind::<BigInt, _>(revision.stream_position)
        .bind::<Jsonb, _>(value)
        .bind::<Timestamptz, _>(revision.updated_at);
    match key {
        Some((_, key)) => query.bind::<Text, _>(key).execute(conn).await,
        None => query.execute(conn).await,
    }
    .map_err(PersistenceError::database)?;
    Ok(())
}

async fn upsert_member_state(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    let membership = value
        .get("membership")
        .and_then(Value::as_str)
        .filter(|membership| matches!(*membership, "join" | "knock" | "leave" | "ban"))
        .ok_or_else(|| malformed("member_state has no closed membership"))?;
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,member_id) DO UPDATE SET \
         membership=EXCLUDED.membership,current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .bind::<Text, _>(membership)
    .bind::<Text, _>(revision.commit_id)
    .bind::<BigInt, _>(revision.stream_position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(revision.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

/// Replace the member Station's typed current of `realm_id` with a verified
/// bootstrap snapshot's rows. Every row must come from the Realm stream at or
/// below `head`; a family this module does not keep is left out, and a
/// selector outside the bootstrap disclosure subset refuses the install.
pub(crate) async fn install_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    head: &arkret_wire::CommitStreamHead,
    entries: &[arkret_wire::TypedCurrentResult],
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    for table in MEMBER_STATION_FAMILIES {
        diesel::sql_query(format!("DELETE FROM {table} WHERE realm_id=$1"))
            .bind::<Text, _>(realm_id.as_str())
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    for entry in entries {
        let arkret_wire::TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = entry
        else {
            return Err(malformed("a row is not a closed typed value"));
        };
        if source_stream_ref != &realm_stream
            || revision.stream_position > head.stream_position
            || (revision.stream_position == head.stream_position
                && revision.commit_id != head.commit_id)
        {
            return Err(malformed(
                "a row is not sourced from the snapshot's Realm stream prefix",
            ));
        }
        let commit_id = revision.commit_id.to_string();
        let row = Revision {
            commit_id: &commit_id,
            stream_position: position(revision.stream_position)?,
            updated_at: installed_at,
        };
        use arkret_wire::CurrentSelector as S;
        let singleton = match selector {
            S::RealmGenesis => Some("realm_genesis"),
            S::RealmProfile => Some("realm_profile"),
            S::RealmJoinRule => Some("realm_join_rule"),
            S::RealmHistoryAccess => Some("realm_history_access"),
            S::RealmDiscovery => Some("realm_discovery"),
            S::RealmAlias => Some("realm_alias"),
            S::RealmPlaintextVisibleServices => Some("realm_plaintext_visible_services"),
            _ => None,
        };
        if let Some(family) = singleton {
            upsert_singleton(conn, realm_id, family, &row, value).await?;
            continue;
        }
        match selector {
            S::RealmPolicyBundle => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "realm_policy_bundle_current_results",
                    None,
                    &row,
                    value,
                )
                .await?;
            }
            S::MemberState { actor_id } => {
                upsert_member_state(conn, realm_id, actor_id, &row, value).await?;
            }
            S::Strand { strand_id } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "strand_current_results",
                    Some(("strand_id", strand_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::RealmSetDefaultStrand => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "realm_set_default_strand_current_results",
                    None,
                    &row,
                    value,
                )
                .await?;
            }
            S::MessageRevision { message_id } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "message_revision_current_results",
                    Some(("message_id", message_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::ObjectRedaction { target_ref } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "object_redaction_current_results",
                    Some(("target_ref", target_ref.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            // Governing admission inputs a member Station never keeps.
            S::RealmAuthorityRoot
            | S::CapabilityGrant { .. }
            | S::InviteLifecycle { .. }
            | S::InviteLiveTarget { .. }
            | S::InviteDirectedInvitee { .. }
            | S::MlsGroup { .. } => {}
            _ => {
                return Err(malformed(
                    "a row family is outside the member bootstrap disclosure subset",
                ));
            }
        }
    }
    Ok(())
}

/// Advance the member Station's typed current with one committed replica
/// that directly follows its anchored held head.
pub(crate) async fn advance_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let commit_id = commit.commit_id.to_string();
    let row = Revision {
        commit_id: &commit_id,
        stream_position: position(commit.stream_position)?,
        updated_at: commit.committed_at,
    };
    let payload = || serde_json::to_value(&event.payload).map_err(PersistenceError::database);
    match event.kind {
        arkret_wire::EventKind::MemberState
        | arkret_wire::EventKind::InviteAccept
        | arkret_wire::EventKind::RealmPolicyBundle
        | arkret_wire::EventKind::RealmLink => {
            crate::unit_of_work::commit_parent_membership_current_results(conn, event, commit)
                .await?;
        }
        arkret_wire::EventKind::StrandCreate => {
            let (strand_id, value) =
                crate::strand_current_results::strand_create_current_value(event)?;
            upsert_keyed(
                conn,
                &event.realm_id,
                "strand_current_results",
                Some(("strand_id", strand_id.as_str())),
                &row,
                &value,
            )
            .await?;
        }
        arkret_wire::EventKind::RealmSetDefaultStrand => {
            let payload: arkret_models_collaboration::events_payloads::strand::RealmSetDefaultStrandPayload =
                serde_json::from_value(payload()?)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            upsert_keyed(
                conn,
                &event.realm_id,
                "realm_set_default_strand_current_results",
                None,
                &row,
                &serde_json::json!({ "default_strand_id": payload.strand_id }),
            )
            .await?;
        }
        arkret_wire::EventKind::MessageCreate => {
            let message_id = arkret_wire::MessageId::from_event_id(&event.event_id);
            upsert_keyed(
                conn,
                &event.realm_id,
                "message_revision_current_results",
                Some(("message_id", message_id.as_str())),
                &row,
                &payload()?,
            )
            .await?;
        }
        arkret_wire::EventKind::MessageRevise => {
            let payload = payload()?;
            let message_id = payload
                .get("message_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PersistenceError::SchemaViolation("Message revise names no Message".to_owned())
                })?
                .to_owned();
            upsert_keyed(
                conn,
                &event.realm_id,
                "message_revision_current_results",
                Some(("message_id", &message_id)),
                &row,
                &payload,
            )
            .await?;
        }
        arkret_wire::EventKind::MessageRedact => {
            let payload: arkret_models_collaboration::events_payloads::message::MessageRedactPayload =
                serde_json::from_value(payload()?)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let message_id = payload.message_id.clone();
            let value = crate::object_redaction_current_results::message_redaction_current_value(
                event, payload,
            )?;
            upsert_keyed(
                conn,
                &event.realm_id,
                "object_redaction_current_results",
                Some(("target_ref", message_id.as_str())),
                &row,
                &serde_json::to_value(&value).map_err(PersistenceError::database)?,
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}
