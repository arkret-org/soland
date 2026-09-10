//! Canonical admission and replacement share the existing Realm Seal lock.
use super::*;

#[derive(QueryableByName)]
struct ExistingRealm {
    #[diesel(sql_type = Nullable<Text>)]
    realm_id: Option<String>,
}

pub(crate) async fn lock_canonical_event_inputs(
    conn: &mut AsyncPgConnection,
    records: &[&CanonicalEventRecord],
) -> PersistenceResult<()> {
    let mut ids = Vec::with_capacity(records.len());
    let mut realms = std::collections::BTreeSet::new();
    for record in records {
        let identity = ids::validated_event_identity_parts_for_suite(
            &record.event_id,
            &record.canonical_digest,
            &record.canonical_bytes,
            record.digest_suite,
        )?;
        ids.push(identity.id.to_vec());
        if let Some(realm) = &record.realm_id {
            realms.insert(realm.clone());
        }
    }
    ids.sort();
    ids.dedup();
    let existing = sql_query("SELECT DISTINCT realm_id FROM canonical_events WHERE id=ANY($1)")
        .bind::<Array<Binary>, _>(&ids)
        .load::<ExistingRealm>(conn)
        .await
        .map_err(PersistenceError::database)?;
    realms.extend(existing.into_iter().filter_map(|row| row.realm_id));
    for realm in &realms {
        lock_canonical_realm(conn, realm).await?;
    }
    for id in &ids {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1,'hex'),0))")
            .bind::<Binary, _>(id)
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    // A competing first insert can reveal another collision Realm between
    // discovery and the identity lock. Retry, never take an out-of-order lock.
    let existing = sql_query("SELECT DISTINCT realm_id FROM canonical_events WHERE id=ANY($1)")
        .bind::<Array<Binary>, _>(&ids)
        .load::<ExistingRealm>(conn)
        .await
        .map_err(PersistenceError::database)?;
    if existing
        .into_iter()
        .filter_map(|row| row.realm_id)
        .any(|realm| !realms.contains(&realm))
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: canonical collision Realm changed; retry transaction".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) async fn lock_canonical_realm(
    conn: &mut AsyncPgConnection,
    realm: &str,
) -> PersistenceResult<()> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(realm)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}
