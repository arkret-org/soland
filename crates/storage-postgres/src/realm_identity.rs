use diesel::sql_types::SmallInt;

use super::{
    AsyncPgConnection, BigInt, Binary, PersistenceError, PersistenceResult, QueryableByName,
    RunQueryDsl, Text, ids, sql_query,
};

#[derive(QueryableByName)]
struct RealmPkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

/// Intern a canonical wire Realm identity and return its database-local key.
///
/// `pk` is never serialized. The full 33-byte event-derived identity remains
/// the protocol key; the suite byte is split only for database constraints.
pub(crate) async fn ensure_realm_pk(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
) -> PersistenceResult<i64> {
    let identity = ids::realm_identity_parts(realm_id)?;
    sql_query(
        "INSERT INTO canonical_realms \
         (id, digest_suite, digest, wire_id) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (id) DO UPDATE SET wire_id = EXCLUDED.wire_id \
         RETURNING pk",
    )
    .bind::<Binary, _>(identity.id.to_vec())
    .bind::<SmallInt, _>(i16::from(identity.digest_suite))
    .bind::<Binary, _>(identity.digest.to_vec())
    .bind::<Text, _>(realm_id)
    .get_result::<RealmPkRow>(conn)
    .await
    .map(|row| row.pk)
    .map_err(PersistenceError::database)
}

pub(crate) async fn ensure_optional_realm_pk(
    conn: &mut AsyncPgConnection,
    realm_id: Option<&str>,
) -> PersistenceResult<Option<i64>> {
    match realm_id {
        Some(realm_id) => ensure_realm_pk(conn, realm_id).await.map(Some),
        None => Ok(None),
    }
}
