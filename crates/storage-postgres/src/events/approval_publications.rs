//! Immutable publication dependencies retained before Agent approval finality.

use diesel::sql_types::{BigInt, Binary, Jsonb, SmallInt};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{EventCommitRequest, PersistenceError, PersistenceResult, ids};

#[derive(QueryableByName)]
struct PublicationRow {
    #[diesel(sql_type = Binary)]
    publication_event_id: Vec<u8>,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    approval: serde_json::Value,
    #[diesel(sql_type = SmallInt)]
    digest_suite: i16,
}

fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(error.to_string())
}

pub(super) async fn load(
    conn: &mut AsyncPgConnection,
    approval_event_id: &arkret_wire::EventId,
) -> PersistenceResult<Option<arkret_wire::Event>> {
    let id = ids::parse_event_id(approval_event_id.as_str())
        .ok_or_else(|| invalid("invalid approval EventId"))?;
    let row = sql_query("SELECT publication.publication_event_id, publication.canonical_bytes, approval.envelope AS approval, approval.digest_suite FROM agent_approval_publications publication JOIN canonical_events approval ON approval.pk = publication.approval_event_pk WHERE approval.id = $1 AND approval.state <> 'quarantined'")
        .bind::<Binary, _>(id.to_vec())
        .get_result::<PublicationRow>(conn).await.optional().map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let publication: arkret_wire::Event =
        serde_json::from_slice(&row.canonical_bytes).map_err(invalid)?;
    let canonical = arkret_canonical::canonical_json_bytes(&publication).map_err(invalid)?;
    let approval: arkret_wire::Event = serde_json::from_value(row.approval).map_err(invalid)?;
    let suite = match row.digest_suite {
        1 => arkret_canonical::DigestSuite::Sha256,
        2 => arkret_canonical::DigestSuite::Blake3,
        _ => return Err(invalid("invalid stored approval digest suite")),
    };
    if canonical != row.canonical_bytes
        || approval.event_id != *approval_event_id
        || ids::parse_event_id(publication.event_id.as_str()).map(|id| id.to_vec())
            != Some(row.publication_event_id)
    {
        return Err(invalid(
            "stored approval publication identity or bytes disagree",
        ));
    }
    arkret_wire::event_submission::validate_approval_publication_event(
        &approval,
        Some(&publication),
        suite,
    )
    .map_err(invalid)?;
    Ok(Some(publication))
}

pub(crate) async fn commit(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    request: &EventCommitRequest,
    existing: bool,
) -> PersistenceResult<()> {
    let approval: arkret_wire::Event =
        serde_json::from_value(request.event.envelope.clone()).map_err(invalid)?;
    arkret_wire::event_submission::validate_approval_publication_event(
        &approval,
        request.publication_event.as_ref(),
        request.event.digest_suite,
    )
    .map_err(invalid)?;
    let Some(publication) = &request.publication_event else {
        return Ok(());
    };
    let canonical = arkret_canonical::canonical_json_bytes(publication).map_err(invalid)?;
    if existing {
        let retained = load(conn, &approval.event_id).await?.ok_or_else(|| {
            invalid("pending approval is missing its immutable publication dependency")
        })?;
        if arkret_canonical::canonical_json_bytes(&retained).map_err(invalid)? != canonical {
            return Err(PersistenceError::Conflict(
                "approval publication bytes differ on exact retry".to_owned(),
            ));
        }
        return Ok(());
    }
    let publication_id = ids::parse_event_id(publication.event_id.as_str())
        .ok_or_else(|| invalid("invalid publication EventId"))?;
    sql_query("INSERT INTO agent_approval_publications (approval_event_pk, publication_event_id, canonical_bytes) VALUES ($1, $2, $3)")
        .bind::<BigInt, _>(event_pk).bind::<Binary, _>(publication_id.to_vec()).bind::<Binary, _>(&canonical)
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
