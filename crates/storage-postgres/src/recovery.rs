use super::{
    Array, BigInt, Integer, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RecoveryPolicyRecord, RecoveryPolicyStore,
    RecoverySessionRecord, RecoverySessionStore, RunQueryDsl, SqlUuid, Text, Timestamptz, Uuid,
    Value, async_trait, ids, pg_conn, sql_query,
};
// ── Phase 2 in-memory sub-stores ────────────────────────────────────────────

pub struct PgRecoveryPolicyStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct RecoveryPolicyRow {
    #[diesel(sql_type = SqlUuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Integer)]
    version: i32,
    #[diesel(sql_type = Jsonb)]
    acceptance_basis: Value,
    #[diesel(sql_type = Text)]
    trust_domain: String,
    #[diesel(sql_type = Array<Text>)]
    allowed_proof_kinds: Vec<String>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    supersedes: Option<Uuid>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    issued_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    verification_method: String,
    #[diesel(sql_type = Jsonb)]
    raw_payload: Value,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}
impl TryFrom<RecoveryPolicyRow> for RecoveryPolicyRecord {
    type Error = PersistenceError;

    fn try_from(row: RecoveryPolicyRow) -> Result<Self, Self::Error> {
        let version = u32::try_from(row.version).map_err(|_| {
            PersistenceError::Internal(format!(
                "recovery policy `{}` has invalid version {}",
                row.policy_id, row.version
            ))
        })?;
        let acceptance_basis = serde_json::from_value(row.acceptance_basis).map_err(|error| {
            PersistenceError::Internal(format!(
                "recovery policy `{}` has invalid acceptance_basis: {error}",
                row.policy_id
            ))
        })?;
        Ok(Self {
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            principal_id: row.principal_id,
            version,
            acceptance_basis,
            trust_domain: row.trust_domain,
            allowed_proof_kinds: row.allowed_proof_kinds,
            supersedes: row.supersedes.map(|u| ids::format_typed_uuid("policy", &u)),
            expires_at: row.expires_at,
            issued_at: row.issued_at,
            raw_payload: row.raw_payload,
            accepted_at: row.accepted_at,
            verification_method: row.verification_method,
        })
    }
}
impl PgRecoveryPolicyStore {
    async fn get_by_principal_version(
        &self,
        principal_id: &str,
        version: u32,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS policy_id, principal_id, version, acceptance_basis, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE principal_id = $1 AND version = $2",
        )
        .bind::<Text, _>(principal_id)
        .bind::<Integer, _>(version as i32)
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional().map_err(PersistenceError::database)?
        .map(RecoveryPolicyRecord::try_from)
        .transpose()
    }
}
#[async_trait]
impl RecoveryPolicyStore for PgRecoveryPolicyStore {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS policy_id, principal_id, version, acceptance_basis, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE id = $1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(policy_id))
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional().map_err(PersistenceError::database)?
        .map(RecoveryPolicyRecord::try_from)
        .transpose()
    }

    async fn get_active_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS policy_id, principal_id, version, acceptance_basis, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE principal_id = $1 \
             ORDER BY version DESC, accepted_at DESC LIMIT 1",
        )
        .bind::<Text, _>(principal_id)
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional().map_err(PersistenceError::database)?
        .map(RecoveryPolicyRecord::try_from)
        .transpose()
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT id AS policy_id, principal_id, version, acceptance_basis, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE principal_id = $1 \
             ORDER BY version DESC, accepted_at DESC",
        )
        .bind::<Text, _>(principal_id)
        .get_results::<RecoveryPolicyRow>(&mut *conn)
        .await.map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(RecoveryPolicyRecord::try_from)
            .collect()
    }

    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()> {
        if self
            .get_by_policy_id(&record.policy_id)
            .await
            .map_err(PersistenceError::database)?
            .is_some()
        {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy_id `{}` already exists",
                record.policy_id
            )));
        }
        if self
            .get_by_principal_version(&record.principal_id, record.version)
            .await
            .map_err(PersistenceError::database)?
            .is_some()
        {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy principal/version ({}, {}) already exists",
                record.principal_id, record.version
            )));
        }
        if let Some(active) = self
            .get_active_for_principal(&record.principal_id)
            .await
            .map_err(PersistenceError::database)?
        {
            if record.version <= active.version {
                return Err(PersistenceError::Conflict(format!(
                    "recovery policy version {} is not greater than active {}",
                    record.version, active.version
                )));
            }
            if record.supersedes.as_deref() != Some(active.policy_id.as_str()) {
                return Err(PersistenceError::Conflict(format!(
                    "recovery policy supersedes {:?} does not match active `{}`",
                    record.supersedes, active.policy_id
                )));
            }
        } else if record.version != 1 {
            return Err(PersistenceError::Conflict(format!(
                "recovery genesis policy for `{}` must have version=1",
                record.principal_id
            )));
        }

        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO recovery_policies \
             (id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
              acceptance_basis, expires_at, issued_at, verification_method, raw_payload, accepted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.policy_id))
        .bind::<Text, _>(&record.principal_id)
        .bind::<Integer, _>(record.version as i32)
        .bind::<Text, _>(&record.trust_domain)
        .bind::<Array<Text>, _>(&record.allowed_proof_kinds)
        .bind::<Nullable<SqlUuid>, _>(
            record
                .supersedes
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Jsonb, _>(
            serde_json::to_value(&record.acceptance_basis).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery policy acceptance_basis encode failed: {error}"
                ))
            })?,
        )
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .bind::<Timestamptz, _>(record.issued_at)
        .bind::<Text, _>(&record.verification_method)
        .bind::<Jsonb, _>(&record.raw_payload)
        .bind::<Timestamptz, _>(record.accepted_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
pub struct PgRecoverySessionStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct RecoverySessionRow {
    #[diesel(sql_type = SqlUuid)]
    recovery_session_id: Uuid,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    requesting_device_id: String,
    #[diesel(sql_type = Text)]
    trust_domain: String,
    #[diesel(sql_type = SqlUuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Integer)]
    policy_version: i32,
    #[diesel(sql_type = Text)]
    identity_model: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    ssk_generation: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    current_device_generation_ref: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    device_generation_status: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    registry_head: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    accepted_seal_frontier: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
    #[diesel(sql_type = Jsonb)]
    publication_authority_context: Value,
    #[diesel(sql_type = Text)]
    publication_authority_context_digest: String,
    #[diesel(sql_type = Text)]
    challenge: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    proof_payload: Option<Value>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    transaction_id: Option<Uuid>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}
impl TryFrom<RecoverySessionRow> for RecoverySessionRecord {
    type Error = PersistenceError;

    fn try_from(row: RecoverySessionRow) -> Result<Self, Self::Error> {
        let policy_version = u32::try_from(row.policy_version).map_err(|_| {
            PersistenceError::Internal(format!(
                "recovery session `{}` has invalid policy_version {}",
                row.recovery_session_id, row.policy_version
            ))
        })?;
        let identity_model =
            serde_json::from_value(Value::String(row.identity_model)).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session `{}` has invalid identity_model: {error}",
                    row.recovery_session_id
                ))
            })?;
        let ssk_generation = row
            .ssk_generation
            .map(|generation| {
                u64::try_from(generation).map_err(|_| {
                    PersistenceError::Internal(format!(
                        "recovery session `{}` has invalid ssk_generation {generation}",
                        row.recovery_session_id
                    ))
                })
            })
            .transpose()?;
        let current_device_generation_ref = row
            .current_device_generation_ref
            .map(arkret_wire::NonEmptyString::new)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session `{}` has invalid current_device_generation_ref: {error}",
                    row.recovery_session_id
                ))
            })?;
        let device_generation_status = row
            .device_generation_status
            .map(|status| serde_json::from_value(Value::String(status)))
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session `{}` has invalid device_generation_status: {error}",
                    row.recovery_session_id
                ))
            })?;
        let registry_head = row
            .registry_head
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session `{}` has invalid registry_head: {error}",
                    row.recovery_session_id
                ))
            })?;
        let accepted_seal_frontier = row
            .accepted_seal_frontier
            .map(|value| {
                serde_json::from_value(value).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "recovery session `{}` has invalid accepted_seal_frontier: {error}",
                        row.recovery_session_id
                    ))
                })
            })
            .transpose()?;
        let publication_authority_context =
            serde_json::from_value(row.publication_authority_context).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session `{}` has invalid publication_authority_context: {error}",
                    row.recovery_session_id
                ))
            })?;
        let publication_authority_context_digest = arkret_identifiers::Hash::new(
            row.publication_authority_context_digest,
        )
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "recovery session `{}` has invalid publication_authority_context_digest: {error}",
                row.recovery_session_id
            ))
        })?;
        Ok(Self {
            recovery_session_id: ids::format_typed_uuid(
                "recovery_session",
                &row.recovery_session_id,
            ),
            principal_id: row.principal_id,
            requesting_device_id: row.requesting_device_id,
            trust_domain: row.trust_domain,
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            policy_version,
            identity_model,
            ssk_generation,
            current_device_generation_ref,
            device_generation_status,
            registry_head,
            accepted_seal_frontier,
            policy_payload: row.policy_payload,
            publication_authority_context,
            publication_authority_context_digest,
            challenge: row.challenge,
            state: row.state,
            proof_payload: row.proof_payload,
            transaction_id: row
                .transaction_id
                .map(|id| ids::format_typed_uuid("transaction", &id)),
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
        })
    }
}
const RECOVERY_SESSION_COLUMNS: &str = "id AS recovery_session_id, principal_id, requesting_device_id, \
     trust_domain, policy_id, policy_version, identity_model, ssk_generation, \
     current_device_generation_ref, device_generation_status, registry_head, accepted_seal_frontier, \
     policy_payload, publication_authority_context, publication_authority_context_digest, \
     challenge, state, proof_payload, transaction_id, created_at, updated_at, expires_at";
#[async_trait]
impl RecoverySessionStore for PgRecoverySessionStore {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {RECOVERY_SESSION_COLUMNS} FROM recovery_sessions \
             WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(recovery_session_id))
        .get_result::<RecoverySessionRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(RecoverySessionRecord::try_from)
        .transpose()
    }

    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let ssk_generation = record
            .ssk_generation
            .map(i64::try_from)
            .transpose()
            .map_err(|_| {
                PersistenceError::Internal(
                    "recovery session ssk_generation exceeds PostgreSQL bigint".to_owned(),
                )
            })?;
        let device_generation_status = record.device_generation_status.map(|status| match status {
            arkret_models_crypto::DeviceGenerationStatus::Active => "active",
            arkret_models_crypto::DeviceGenerationStatus::Conflicted => "conflicted",
        });
        sql_query(
            "INSERT INTO recovery_sessions \
             (id, principal_id, requesting_device_id, trust_domain, policy_id, \
              policy_version, identity_model, ssk_generation, current_device_generation_ref, \
              device_generation_status, registry_head, accepted_seal_frontier, policy_payload, \
              publication_authority_context, publication_authority_context_digest, challenge, \
              state, proof_payload, transaction_id, created_at, updated_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
            &record.recovery_session_id,
        ))
        .bind::<Text, _>(&record.principal_id)
        .bind::<Text, _>(&record.requesting_device_id)
        .bind::<Text, _>(&record.trust_domain)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.policy_id))
        .bind::<Integer, _>(record.policy_version as i32)
        .bind::<Text, _>(match record.identity_model {
            arkret_models_crypto::RecoveryIdentityModel::CrossSigning => "cross_signing",
            arkret_models_crypto::RecoveryIdentityModel::EnrollmentAuthority => {
                "enrollment_authority"
            }
        })
        .bind::<Nullable<BigInt>, _>(ssk_generation)
        .bind::<Nullable<Text>, _>(
            record
                .current_device_generation_ref
                .as_ref()
                .map(|value| value.as_str()),
        )
        .bind::<Nullable<Text>, _>(device_generation_status)
        .bind::<Nullable<Text>, _>(record.registry_head.as_ref().map(|value| value.as_str()))
        .bind::<Nullable<Jsonb>, _>(
            record
                .accepted_seal_frontier
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "recovery session accepted_seal_frontier encode failed: {error}"
                    ))
                })?,
        )
        .bind::<Jsonb, _>(&record.policy_payload)
        .bind::<Jsonb, _>(
            serde_json::to_value(&record.publication_authority_context).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session publication_authority_context encode failed: {error}"
                ))
            })?,
        )
        .bind::<Text, _>(record.publication_authority_context_digest.as_str())
        .bind::<Text, _>(&record.challenge)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Jsonb>, _>(record.proof_payload.as_ref())
        .bind::<Nullable<SqlUuid>, _>(
            record
                .transaction_id
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let affected = sql_query(
            "UPDATE recovery_sessions SET \
                state = $2, proof_payload = $3, transaction_id = $4, updated_at = $5, expires_at = $6 \
             WHERE id = $1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
            &record.recovery_session_id,
        ))
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Jsonb>, _>(record.proof_payload.as_ref())
        .bind::<Nullable<SqlUuid>, _>(
            record
                .transaction_id
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if affected == 0 {
            return Err(PersistenceError::NotFound(format!(
                "recovery_session_id `{}` not found",
                record.recovery_session_id
            )));
        }
        Ok(())
    }
}
