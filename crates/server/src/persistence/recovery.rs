use super::*;

/// Durable recovery policy store. Implementations enforce policy_id
/// uniqueness, `(principal_id, version)` uniqueness, and the per-principal
/// supersedes/version monotonicity check before accepting a new snapshot.
#[async_trait]
pub trait RecoveryPolicyStore: Send + Sync {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>>;
    async fn get_active_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>>;
    /// All policies for a principal, newest version first (REC-1 read API /
    /// UI audit history).
    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>>;
    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()>;
}

/// Durable recovery receipt store. `recovery_session_id` is globally unique
/// because it is the replay fence for completed recovery attempts.
#[async_trait]
pub trait RecoveryReceiptStore: Send + Sync {
    async fn get_by_session_id(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoveryReceiptRecord>>;
    /// All receipts for a principal, newest accepted first (REC-1 read API /
    /// recovery history).
    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryReceiptRecord>>;
    async fn insert(&self, record: RecoveryReceiptRecord) -> PersistenceResult<()>;
}

/// C-P2 (REC-1) — recovery session lifecycle store.
///
/// A session is created on `POST recovery-sessions` (snapshot of the active
/// policy + server challenge), read on `GET recovery-sessions/{id}`, and
/// advanced by `POST .../{id}/proofs` (records the submitted proof; C-P3
/// verifies it) and `POST .../{id}/complete` (only when `state == verified`).
#[async_trait]
pub trait RecoverySessionStore: Send + Sync {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>>;
    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
}

#[derive(Default)]
pub(crate) struct MemoryRecoveryPolicyStore {
    data: Mutex<BTreeMap<String, RecoveryPolicyRecord>>,
}

impl MemoryRecoveryPolicyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

fn recovery_active_policy_locked(
    data: &BTreeMap<String, RecoveryPolicyRecord>,
    principal_id: &str,
) -> Option<RecoveryPolicyRecord> {
    data.values()
        .filter(|record| record.principal_id == principal_id)
        .max_by_key(|record| record.version)
        .cloned()
}

#[async_trait]
impl RecoveryPolicyStore for MemoryRecoveryPolicyStore {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        Ok(self.data.lock().get(policy_id).cloned())
    }

    async fn get_active_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let data = self.data.lock();
        Ok(recovery_active_policy_locked(&data, principal_id))
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>> {
        let data = self.data.lock();
        let mut out: Vec<RecoveryPolicyRecord> = data
            .values()
            .filter(|record| record.principal_id == principal_id)
            .cloned()
            .collect();
        out.sort_by_key(|p| std::cmp::Reverse(p.version));
        Ok(out)
    }

    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        if data.contains_key(&record.policy_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy_id `{}` already exists",
                record.policy_id
            )));
        }
        if data.values().any(|existing| {
            existing.principal_id == record.principal_id && existing.version == record.version
        }) {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy principal/version ({}, {}) already exists",
                record.principal_id, record.version
            )));
        }
        if let Some(active) = recovery_active_policy_locked(&data, &record.principal_id) {
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
        data.insert(record.policy_id.clone(), record);
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct MemoryRecoveryReceiptStore {
    by_session: Mutex<BTreeMap<String, RecoveryReceiptRecord>>,
    receipt_ids: Mutex<BTreeSet<String>>,
}

impl MemoryRecoveryReceiptStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RecoveryReceiptStore for MemoryRecoveryReceiptStore {
    async fn get_by_session_id(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoveryReceiptRecord>> {
        Ok(self.by_session.lock().get(recovery_session_id).cloned())
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryReceiptRecord>> {
        let by_session = self.by_session.lock();
        let mut out: Vec<RecoveryReceiptRecord> = by_session
            .values()
            .filter(|record| record.principal_id == principal_id)
            .cloned()
            .collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.accepted_at));
        Ok(out)
    }

    async fn insert(&self, record: RecoveryReceiptRecord) -> PersistenceResult<()> {
        let mut by_session = self.by_session.lock();
        let mut receipt_ids = self.receipt_ids.lock();
        if receipt_ids.contains(&record.receipt_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery receipt_id `{}` already exists",
                record.receipt_id
            )));
        }
        if by_session.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery_session_id `{}` already accepted",
                record.recovery_session_id
            )));
        }
        receipt_ids.insert(record.receipt_id.clone());
        by_session.insert(record.recovery_session_id.clone(), record);
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct MemoryRecoverySessionStore {
    by_id: Mutex<BTreeMap<String, RecoverySessionRecord>>,
}

impl MemoryRecoverySessionStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RecoverySessionStore for MemoryRecoverySessionStore {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>> {
        Ok(self.by_id.lock().get(recovery_session_id).cloned())
    }

    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut by_id = self.by_id.lock();
        if by_id.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery_session_id `{}` already exists",
                record.recovery_session_id
            )));
        }
        by_id.insert(record.recovery_session_id.clone(), record);
        Ok(())
    }

    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut by_id = self.by_id.lock();
        if !by_id.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::NotFound(format!(
                "recovery_session_id `{}` not found",
                record.recovery_session_id
            )));
        }
        by_id.insert(record.recovery_session_id.clone(), record);
        Ok(())
    }
}

// ── Phase 2 in-memory sub-stores ────────────────────────────────────────────

pub(crate) struct PgRecoveryPolicyStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct RecoveryPolicyRow {
    #[diesel(sql_type = SqlUuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Integer)]
    version: i32,
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
        Ok(Self {
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            principal_id: row.principal_id,
            version,
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
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS policy_id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE principal_id = $1 AND version = $2",
        )
        .bind::<Text, _>(principal_id)
        .bind::<Integer, _>(version as i32)
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional()?
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
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS policy_id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE id = $1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(policy_id))
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional()?
        .map(RecoveryPolicyRecord::try_from)
        .transpose()
    }

    async fn get_active_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS policy_id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE principal_id = $1 \
             ORDER BY version DESC, accepted_at DESC LIMIT 1",
        )
        .bind::<Text, _>(principal_id)
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional()?
        .map(RecoveryPolicyRecord::try_from)
        .transpose()
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT id AS policy_id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE principal_id = $1 \
             ORDER BY version DESC, accepted_at DESC",
        )
        .bind::<Text, _>(principal_id)
        .get_results::<RecoveryPolicyRow>(&mut *conn)
        .await?;
        rows.into_iter()
            .map(RecoveryPolicyRecord::try_from)
            .collect()
    }

    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()> {
        if self.get_by_policy_id(&record.policy_id).await?.is_some() {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy_id `{}` already exists",
                record.policy_id
            )));
        }
        if self
            .get_by_principal_version(&record.principal_id, record.version)
            .await?
            .is_some()
        {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy principal/version ({}, {}) already exists",
                record.principal_id, record.version
            )));
        }
        if let Some(active) = self.get_active_for_principal(&record.principal_id).await? {
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

        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO recovery_policies \
             (id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
              expires_at, issued_at, verification_method, raw_payload, accepted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
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
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .bind::<Timestamptz, _>(record.issued_at)
        .bind::<Text, _>(&record.verification_method)
        .bind::<Jsonb, _>(&record.raw_payload)
        .bind::<Timestamptz, _>(record.accepted_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}

pub(crate) struct PgRecoveryReceiptStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct RecoveryReceiptRow {
    #[diesel(sql_type = SqlUuid)]
    receipt_id: Uuid,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = SqlUuid)]
    recovery_session_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Integer)]
    policy_version: i32,
    #[diesel(sql_type = Text)]
    trust_domain: String,
    #[diesel(sql_type = Text)]
    new_device_id: String,
    #[diesel(sql_type = Text)]
    proof_digest: String,
    #[diesel(sql_type = Text)]
    outcome: String,
    #[diesel(sql_type = Timestamptz)]
    started_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    completed_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    verification_method: String,
    #[diesel(sql_type = Jsonb)]
    raw_payload: Value,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<RecoveryReceiptRow> for RecoveryReceiptRecord {
    type Error = PersistenceError;

    fn try_from(row: RecoveryReceiptRow) -> Result<Self, Self::Error> {
        let policy_version = u32::try_from(row.policy_version).map_err(|_| {
            PersistenceError::Internal(format!(
                "recovery receipt `{}` has invalid policy_version {}",
                row.receipt_id, row.policy_version
            ))
        })?;
        Ok(Self {
            receipt_id: ids::format_typed_uuid("receipt", &row.receipt_id),
            principal_id: row.principal_id,
            recovery_session_id: ids::format_typed_uuid(
                "recovery_session",
                &row.recovery_session_id,
            ),
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            policy_version,
            trust_domain: row.trust_domain,
            new_device_id: row.new_device_id,
            proof_digest: row.proof_digest,
            outcome: row.outcome,
            started_at: row.started_at,
            completed_at: row.completed_at,
            raw_payload: row.raw_payload,
            verification_method: row.verification_method,
            accepted_at: row.accepted_at,
        })
    }
}

#[async_trait]
impl RecoveryReceiptStore for PgRecoveryReceiptStore {
    async fn get_by_session_id(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoveryReceiptRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS receipt_id, principal_id, recovery_session_id, policy_id, policy_version, \
                    trust_domain, new_device_id, proof_digest, outcome, started_at, completed_at, \
                    verification_method, raw_payload, accepted_at \
             FROM recovery_receipts WHERE recovery_session_id = $1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(recovery_session_id))
        .get_result::<RecoveryReceiptRow>(&mut *conn)
        .await
        .optional()?
        .map(RecoveryReceiptRecord::try_from)
        .transpose()
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryReceiptRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT id AS receipt_id, principal_id, recovery_session_id, policy_id, policy_version, \
                    trust_domain, new_device_id, proof_digest, outcome, started_at, completed_at, \
                    verification_method, raw_payload, accepted_at \
             FROM recovery_receipts WHERE principal_id = $1 \
             ORDER BY accepted_at DESC",
        )
        .bind::<Text, _>(principal_id)
        .get_results::<RecoveryReceiptRow>(&mut *conn)
        .await?;
        rows.into_iter()
            .map(RecoveryReceiptRecord::try_from)
            .collect()
    }

    async fn insert(&self, record: RecoveryReceiptRecord) -> PersistenceResult<()> {
        if self
            .get_by_session_id(&record.recovery_session_id)
            .await?
            .is_some()
        {
            return Err(PersistenceError::Conflict(format!(
                "recovery_session_id `{}` already accepted",
                record.recovery_session_id
            )));
        }
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO recovery_receipts \
             (id, principal_id, recovery_session_id, policy_id, policy_version, \
              trust_domain, new_device_id, proof_digest, outcome, started_at, completed_at, \
              verification_method, raw_payload, accepted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.receipt_id))
        .bind::<Text, _>(&record.principal_id)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
            &record.recovery_session_id,
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.policy_id))
        .bind::<Integer, _>(record.policy_version as i32)
        .bind::<Text, _>(&record.trust_domain)
        .bind::<Text, _>(&record.new_device_id)
        .bind::<Text, _>(&record.proof_digest)
        .bind::<Text, _>(&record.outcome)
        .bind::<Timestamptz, _>(record.started_at)
        .bind::<Timestamptz, _>(record.completed_at)
        .bind::<Text, _>(&record.verification_method)
        .bind::<Jsonb, _>(&record.raw_payload)
        .bind::<Timestamptz, _>(record.accepted_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}

pub(crate) struct PgRecoverySessionStore {
    pub(crate) pool: PgPool,
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
    #[diesel(sql_type = Integer)]
    ssk_generation: i32,
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
    #[diesel(sql_type = Text)]
    challenge: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    proof_payload: Option<Value>,
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
        let ssk_generation = u32::try_from(row.ssk_generation).map_err(|_| {
            PersistenceError::Internal(format!(
                "recovery session `{}` has invalid ssk_generation {}",
                row.recovery_session_id, row.ssk_generation
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
            ssk_generation,
            policy_payload: row.policy_payload,
            challenge: row.challenge,
            state: row.state,
            proof_payload: row.proof_payload,
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
        })
    }
}

const RECOVERY_SESSION_COLUMNS: &str = "id AS recovery_session_id, principal_id, requesting_device_id, \
     trust_domain, policy_id, policy_version, ssk_generation, policy_payload, challenge, state, \
     proof_payload, created_at, updated_at, expires_at";

#[async_trait]
impl RecoverySessionStore for PgRecoverySessionStore {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {RECOVERY_SESSION_COLUMNS} FROM recovery_sessions \
             WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(recovery_session_id))
        .get_result::<RecoverySessionRow>(&mut *conn)
        .await
        .optional()?
        .map(RecoverySessionRecord::try_from)
        .transpose()
    }

    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO recovery_sessions \
             (id, principal_id, requesting_device_id, trust_domain, policy_id, \
              policy_version, ssk_generation, policy_payload, challenge, state, proof_payload, \
              created_at, updated_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
            &record.recovery_session_id,
        ))
        .bind::<Text, _>(&record.principal_id)
        .bind::<Text, _>(&record.requesting_device_id)
        .bind::<Text, _>(&record.trust_domain)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.policy_id))
        .bind::<Integer, _>(record.policy_version as i32)
        .bind::<Integer, _>(record.ssk_generation as i32)
        .bind::<Jsonb, _>(&record.policy_payload)
        .bind::<Text, _>(&record.challenge)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Jsonb>, _>(record.proof_payload.as_ref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let affected = sql_query(
            "UPDATE recovery_sessions SET \
                state = $2, proof_payload = $3, updated_at = $4, expires_at = $5 \
             WHERE id = $1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
            &record.recovery_session_id,
        ))
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Jsonb>, _>(record.proof_payload.as_ref())
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        if affected == 0 {
            return Err(PersistenceError::NotFound(format!(
                "recovery_session_id `{}` not found",
                record.recovery_session_id
            )));
        }
        Ok(())
    }
}
