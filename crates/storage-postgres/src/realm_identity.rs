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
/// `pk` is never serialized. Both Event-derived (`0x0?`) and principal
/// subject-derived (`0x11`) Realms share this table; the header carried by the
/// 33-byte identity is split only to make database constraints and indexes
/// explicit.
pub(crate) async fn ensure_realm_pk(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
) -> PersistenceResult<i64> {
    let identity = ids::realm_identity_parts(realm_id)?;
    sql_query(
        "INSERT INTO canonical_realms \
         (id, derivation_class, digest_suite, digest, wire_id) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (id) DO UPDATE SET wire_id = EXCLUDED.wire_id \
         RETURNING pk",
    )
    .bind::<Binary, _>(identity.id.to_vec())
    .bind::<SmallInt, _>(i16::from(identity.derivation_class))
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
