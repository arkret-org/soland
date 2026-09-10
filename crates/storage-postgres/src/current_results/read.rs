//! Indexed primitive for a caller-owned frozen, authorized coverage window.
//! This module does not establish permission or mark a baseline complete.

use diesel::OptionalExtension;
use diesel::sql_types::{Array, Bool};

use super::*;

/// Both fields belong to the continuation: a transaction can publish many
/// selectors at one revision, including selectors spanning consecutive pages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Position {
    pub revision: i64,
    pub selector_key: String,
}

/// The HTTP/window layer must freeze these exact targets with its authority
/// and retention reservation before reading. All keys use their canonical
/// typed encoding; no caller-supplied SQL or textual prefix is interpreted.
pub(crate) struct Selection<'a> {
    pub realm_id: &'a str,
    pub scope_keys: &'a [String],
    /// Candidate mode defers scope authorization to the bounded caller loop.
    pub candidate_scopes: bool,
    pub realm: bool,
    pub strand_ids: &'a [String],
    pub all_members: bool,
    pub actor_keys: &'a [String],
    pub event_ids: &'a [String],
    pub priority_selectors: &'a [String],
}

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type=BigInt)]
    revision: i64,
    #[diesel(sql_type=Text)]
    selector_key: String,
    #[diesel(sql_type=Jsonb)]
    payload: serde_json::Value,
}

/// Fetch one whole selector. Reading one row avoids allocating 100 maximum
/// sized values before the account frame's byte budget can be checked.
/// Priority and ordinary phases are disjoint, using the same frozen set.
pub(crate) async fn next(
    conn: &mut AsyncPgConnection,
    selection: &Selection<'_>,
    cut: i64,
    after: &Position,
    priority: bool,
    snapshot: bool,
) -> PersistenceResult<Option<(Position, CurrentResultEntry)>> {
    if cut < 0 || after.revision < 0 || after.revision > cut {
        return Err(PersistenceError::SchemaViolation(
            "current read position is outside its frozen cut".into(),
        ));
    }
    let row = sql_query(
        "SELECT revision,selector_key,payload FROM current_result_versions
         WHERE realm_id=$1 AND revision<=$2
           AND (NOT $3 OR valid_until IS NULL OR valid_until>$2)
           AND (revision,selector_key)>($4,$5 COLLATE \"C\")
           AND ((selector_key=ANY($6))=$7)
           AND ($14 OR (payload->'selector'->'scope_ref')=ANY(
               SELECT value::jsonb FROM unnest($8::text[]) AS scopes(value)))
           AND ((target_kind='realm' AND $9)
             OR (target_kind='strand' AND target_key=ANY($10))
             OR (target_kind='member' AND ($11 OR target_key=ANY($12)))
             OR (target_kind='event' AND target_key=ANY($13)))
         ORDER BY revision,selector_key COLLATE \"C\" LIMIT 1",
    )
    .bind::<Text, _>(selection.realm_id)
    .bind::<BigInt, _>(cut)
    .bind::<Bool, _>(snapshot)
    .bind::<BigInt, _>(after.revision)
    .bind::<Text, _>(&after.selector_key)
    .bind::<Array<Text>, _>(selection.priority_selectors)
    .bind::<Bool, _>(priority)
    .bind::<Array<Text>, _>(selection.scope_keys)
    .bind::<Bool, _>(selection.realm)
    .bind::<Array<Text>, _>(selection.strand_ids)
    .bind::<Bool, _>(selection.all_members)
    .bind::<Array<Text>, _>(selection.actor_keys)
    .bind::<Array<Text>, _>(selection.event_ids)
    .bind::<Bool, _>(selection.candidate_scopes)
    .get_result::<Row>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    row.map(|row| {
        let entry = CurrentResultEntry::try_from_json(row.payload)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if entry.revision() != row.revision as u64
            || entry
                .selector()
                .canonical_key()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
                != row.selector_key
        {
            return Err(PersistenceError::SchemaViolation(
                "current index row differs from its validated result".into(),
            ));
        }
        Ok((
            Position {
                revision: row.revision,
                selector_key: row.selector_key,
            },
            entry,
        ))
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use diesel_async::AsyncConnection;

    use super::*;

    #[tokio::test]
    async fn same_revision_tail_and_priority_phase_are_not_skipped() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(b"current indexed page realm"),
        ));
        let strands = [b"first".as_slice(), b"second".as_slice()].map(|bytes| {
            arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                arkret_canonical::sha256_bytes(bytes),
            ))
            .to_string()
        });
        let scope = serde_json::to_value(arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        })
        .unwrap();
        let mut entries = Vec::new();
        let revision = conn.transaction::<_,crate::PgTransactionError,_>(async |conn| {
            let revision = super::super::next_revision(conn).await?;
            for strand in &strands {
                entries.push(CurrentResultEntry::try_from_json(serde_json::json!({
                    "selector":{"scope_ref":scope,"cell_id":format!("ak:cell:ak.component.strand.object.v1:{strand}")},
                    "target":{"kind":"strand","strand_id":strand},"revision":revision,
                    "result":{"status":"unavailable","reason":"limit_exceeded"}
                })).unwrap());
            }
            super::super::publish_entries(conn,&entries).await?;
            Ok(revision)
        }).await.map_err(crate::PgTransactionError::into_persistence).unwrap();
        let scope_keys = vec![
            String::from_utf8(arkret_canonical::canonical_json_bytes(&scope).unwrap()).unwrap(),
        ];
        let priorities = vec![entries[0].selector().canonical_key().unwrap()];
        let mut selection = Selection {
            realm_id: realm.as_str(),
            scope_keys: &scope_keys,
            candidate_scopes: false,
            realm: false,
            strand_ids: &strands,
            all_members: false,
            actor_keys: &[],
            event_ids: &[],
            priority_selectors: &[],
        };
        let first = next(
            &mut conn,
            &selection,
            revision as i64,
            &Position::default(),
            false,
            true,
        )
        .await
        .unwrap()
        .unwrap();
        let second = next(
            &mut conn,
            &selection,
            revision as i64,
            &first.0,
            false,
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(first.0.revision, second.0.revision);
        assert_ne!(first.0.selector_key, second.0.selector_key);
        assert!(
            next(
                &mut conn,
                &selection,
                revision as i64,
                &second.0,
                false,
                true
            )
            .await
            .unwrap()
            .is_none()
        );
        selection.priority_selectors = &priorities;
        let prioritized = next(
            &mut conn,
            &selection,
            revision as i64,
            &Position::default(),
            true,
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(prioritized.0.selector_key, priorities[0]);
        let ordinary = next(
            &mut conn,
            &selection,
            revision as i64,
            &Position::default(),
            false,
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_ne!(ordinary.0.selector_key, priorities[0]);
    }
}
