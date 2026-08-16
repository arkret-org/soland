use super::{
    AccountStatusAuthorityBindingAdvance, AccountStatusAuthorityBindingFloor,
    AccountStatusAuthorityBindingStore, BigInt, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RunQueryDsl, Text, async_trait, pg_conn, sql_query,
};

pub struct PgAccountStatusAuthorityBindingStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct BindingFloorRow {
    #[diesel(sql_type = BigInt)]
    binding_version: i64,
    #[diesel(sql_type = Text)]
    issuer_service_id: String,
    #[diesel(sql_type = Text)]
    principal_control_realm_id: String,
    #[diesel(sql_type = Text)]
    principal_id: String,
}

#[async_trait]
impl AccountStatusAuthorityBindingStore for PgAccountStatusAuthorityBindingStore {
    async fn advance(
        &self,
        candidate: AccountStatusAuthorityBindingFloor,
    ) -> PersistenceResult<AccountStatusAuthorityBindingAdvance> {
        let version = i64::try_from(candidate.binding_version).map_err(|_| {
            PersistenceError::Internal(
                "account-status authority binding_version exceeds PostgreSQL BIGINT".to_owned(),
            )
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let advanced = sql_query(
            "INSERT INTO account_status_authority_binding_floors \
             (account_authority_id, account_id, binding_version, issuer_service_id, \
              principal_control_realm_id, principal_id) VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (account_authority_id, account_id) DO UPDATE SET \
               binding_version = EXCLUDED.binding_version, \
               issuer_service_id = EXCLUDED.issuer_service_id, \
               principal_control_realm_id = EXCLUDED.principal_control_realm_id, \
               principal_id = EXCLUDED.principal_id \
             WHERE EXCLUDED.binding_version > account_status_authority_binding_floors.binding_version \
             RETURNING binding_version, issuer_service_id, principal_control_realm_id, principal_id",
        )
        .bind::<Text, _>(&candidate.account_authority_id)
        .bind::<Text, _>(&candidate.account_id)
        .bind::<BigInt, _>(version)
        .bind::<Text, _>(&candidate.issuer_service_id)
        .bind::<Text, _>(&candidate.principal_control_realm_id)
        .bind::<Text, _>(&candidate.principal_id)
        .get_result::<BindingFloorRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if advanced.is_some() {
            return Ok(AccountStatusAuthorityBindingAdvance::Advanced);
        }
        let current = sql_query(
            "SELECT binding_version, issuer_service_id, principal_control_realm_id, principal_id \
             FROM account_status_authority_binding_floors \
             WHERE account_authority_id = $1 AND account_id = $2",
        )
        .bind::<Text, _>(&candidate.account_authority_id)
        .bind::<Text, _>(&candidate.account_id)
        .get_result::<BindingFloorRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if current.binding_version != version {
            return Ok(AccountStatusAuthorityBindingAdvance::Rollback);
        }
        Ok(
            if current.issuer_service_id == candidate.issuer_service_id
                && current.principal_control_realm_id == candidate.principal_control_realm_id
                && current.principal_id == candidate.principal_id
            {
                AccountStatusAuthorityBindingAdvance::Replay
            } else {
                AccountStatusAuthorityBindingAdvance::Fork
            },
        )
    }
}
