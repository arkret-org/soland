use diesel::sql_types::{BigInt, Binary};

use super::{
    Array, BTreeSet, ConsentCellKey, ConsentCellRecord, ConsentCellStore, ContactRecord,
    ContactStore, InviteReceivePolicyStore, Jsonb, MimiConsentCorrelationRecord,
    MimiConsentCorrelationStore, Nullable, OptionalExtension, PersistenceError, PersistenceResult,
    PgPool, QueryableByName, RunQueryDsl, Text, Timestamptz, Value, async_trait, decode_grant_dots,
    encode_grant_dots, ids, pg_conn, sql_query,
};
/// Encode a contact's Event reference for storage.
///
/// The `contacts` Event-reference columns hold the same 33-octet token
/// `canonical_events.id` does, so a malformed wire id is rejected at the
/// storage boundary rather than stored and discovered on read.
fn parse_contact_event_ref(event_ref: Option<&str>) -> PersistenceResult<Option<Vec<u8>>> {
    event_ref
        .map(|value| {
            ids::event_token_part_or_schema_violation(value, "event").map(|token| token.to_vec())
        })
        .transpose()
}

fn format_contact_event_ref(token: &[u8]) -> String {
    ids::format_event_id(
        &<[u8; ids::EVENT_ID_BYTES]>::try_from(token)
            .expect("contacts Event reference is a 33-octet Event id"),
    )
}
// ── Pg-backed contact projection store ───────────────────────────────────
// Durable backing for the holder↔peer `ContactStore`. Mirrors the
// `MemoryContactStore` query shape onto the `contacts` table. Column order
// matches `state::ContactRecord`.
pub struct PgContactStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct ContactRow {
    #[diesel(sql_type = Text)]
    requester: String,
    #[diesel(sql_type = Text)]
    target: String,
    #[diesel(sql_type = Nullable<Text>)]
    basis_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    version: Option<i64>,
    #[diesel(sql_type = Array<Text>)]
    granted_to_target_scopes: Vec<String>,
    #[diesel(sql_type = Array<Text>)]
    granted_to_requester_scopes: Vec<String>,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Binary>)]
    request_event_ref: Option<Vec<u8>>,
    #[diesel(sql_type = Jsonb)]
    request_receipts: Value,
    #[diesel(sql_type = Jsonb)]
    request_mirror_receipts: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    basis_evidence: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    basis_evidence_history: Value,
    #[diesel(sql_type = Jsonb)]
    control_outcomes: Value,
    #[diesel(sql_type = Nullable<Binary>)]
    response_event_ref: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Binary>)]
    tombstone_event_ref: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    message: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    peer_service_id: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    peer_service_resolution: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
fn decode_contact_json<T: serde::de::DeserializeOwned>(
    value: Value,
    field: &str,
) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(|error| {
        PersistenceError::Internal(format!("invalid contacts.{field} JSONB: {error}"))
    })
}

fn encode_contact_json<T: serde::Serialize + ?Sized>(
    value: &T,
    field: &str,
) -> PersistenceResult<Value> {
    serde_json::to_value(value).map_err(|error| {
        PersistenceError::Internal(format!("cannot encode contacts.{field} JSONB: {error}"))
    })
}

fn contact_record_from_row(row: ContactRow) -> PersistenceResult<ContactRecord> {
    Ok(ContactRecord {
        requester: row.requester,
        target: row.target,
        basis_id: row.basis_id,
        version: row.version.map(u64::try_from).transpose().map_err(|_| {
            PersistenceError::Internal("contacts.version contains a negative value".to_owned())
        })?,
        granted_to_target_scopes: row.granted_to_target_scopes,
        granted_to_requester_scopes: row.granted_to_requester_scopes,
        status: row.status,
        request_event_ref: row
            .request_event_ref
            .as_deref()
            .map(format_contact_event_ref),
        request_receipts: decode_contact_json(row.request_receipts, "request_receipts")?,
        request_mirror_receipts: decode_contact_json(
            row.request_mirror_receipts,
            "request_mirror_receipts",
        )?,
        basis_evidence: row
            .basis_evidence
            .map(|value| decode_contact_json(value, "basis_evidence"))
            .transpose()?,
        basis_evidence_history: decode_contact_json(
            row.basis_evidence_history,
            "basis_evidence_history",
        )?,
        control_outcomes: decode_contact_json(row.control_outcomes, "control_outcomes")?,
        response_event_ref: row
            .response_event_ref
            .as_deref()
            .map(format_contact_event_ref),
        tombstone_event_ref: row
            .tombstone_event_ref
            .as_deref()
            .map(format_contact_event_ref),
        message: row.message,
        peer_service_id: row.peer_service_id,
        peer_service_resolution: row.peer_service_resolution,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}
const CONTACT_COLUMNS: &str = "requester_id AS requester, target_id AS target, basis_id, version, granted_to_target_scopes, granted_to_requester_scopes, status, request_event_ref, request_receipts, request_mirror_receipts, basis_evidence, basis_evidence_history, control_outcomes, response_event_ref, tombstone_event_ref, message, peer_service_id AS peer_service_id, peer_service_resolution, created_at, updated_at";
#[async_trait]
impl ContactStore for PgContactStore {
    async fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 AND target_id = $2 \
             LIMIT 1"
        ))
        .bind::<Text, _>(requester)
        .bind::<Text, _>(target)
        .get_result::<ContactRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(contact_record_from_row).transpose()
    }

    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let request_receipts = encode_contact_json(&record.request_receipts, "request_receipts")?;
        let request_mirror_receipts =
            encode_contact_json(&record.request_mirror_receipts, "request_mirror_receipts")?;
        let basis_evidence = record
            .basis_evidence
            .as_ref()
            .map(|value| encode_contact_json(value, "basis_evidence"))
            .transpose()?;
        let basis_evidence_history =
            encode_contact_json(&record.basis_evidence_history, "basis_evidence_history")?;
        let control_outcomes = encode_contact_json(&record.control_outcomes, "control_outcomes")?;
        sql_query(
            "INSERT INTO contacts \
             (id, requester_id, target_id, basis_id, version, granted_to_target_scopes, granted_to_requester_scopes, status, request_event_ref, request_receipts, request_mirror_receipts, basis_evidence, basis_evidence_history, control_outcomes, response_event_ref, tombstone_event_ref, message, peer_service_id, peer_service_resolution, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21) \
             ON CONFLICT (requester_id, target_id) DO UPDATE SET \
                basis_id = EXCLUDED.basis_id, \
                version = EXCLUDED.version, \
                granted_to_target_scopes = EXCLUDED.granted_to_target_scopes, \
                granted_to_requester_scopes = EXCLUDED.granted_to_requester_scopes, \
                status = EXCLUDED.status, \
                request_event_ref = EXCLUDED.request_event_ref, \
                request_receipts = EXCLUDED.request_receipts, \
                request_mirror_receipts = EXCLUDED.request_mirror_receipts, \
                basis_evidence = EXCLUDED.basis_evidence, \
                basis_evidence_history = EXCLUDED.basis_evidence_history, \
                control_outcomes = EXCLUDED.control_outcomes, \
                response_event_ref = EXCLUDED.response_event_ref, \
                tombstone_event_ref = EXCLUDED.tombstone_event_ref, \
                message = EXCLUDED.message, \
                peer_service_id = EXCLUDED.peer_service_id, \
                peer_service_resolution = EXCLUDED.peer_service_resolution, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.requester)
        .bind::<Text, _>(&record.target)
        .bind::<Nullable<Text>, _>(record.basis_id.as_deref())
        .bind::<Nullable<BigInt>, _>(record.version.map(i64::try_from).transpose().map_err(|_| PersistenceError::Internal("Contact version exceeds PostgreSQL BIGINT".to_owned()))?)
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(record.request_event_ref.as_deref())?)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(basis_evidence.as_ref())
        .bind::<Jsonb, _>(&basis_evidence_history)
        .bind::<Jsonb, _>(&control_outcomes)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(record.response_event_ref.as_deref())?)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(
            record.tombstone_event_ref.as_deref(),
        )?)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_service_id.as_deref())
        .bind::<Nullable<Jsonb>, _>(record.peer_service_resolution.as_ref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn put_if_updated_at(
        &self,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
        record: &ContactRecord,
    ) -> PersistenceResult<bool> {
        if record.updated_at <= expected_updated_at {
            return Ok(false);
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let request_receipts = encode_contact_json(&record.request_receipts, "request_receipts")?;
        let request_mirror_receipts =
            encode_contact_json(&record.request_mirror_receipts, "request_mirror_receipts")?;
        let basis_evidence = record
            .basis_evidence
            .as_ref()
            .map(|value| encode_contact_json(value, "basis_evidence"))
            .transpose()?;
        let basis_evidence_history =
            encode_contact_json(&record.basis_evidence_history, "basis_evidence_history")?;
        let control_outcomes = encode_contact_json(&record.control_outcomes, "control_outcomes")?;
        let affected = sql_query(
            "UPDATE contacts SET requester_id = $1, target_id = $2, \
                basis_id = $3, version = $4, granted_to_target_scopes = $5, \
                granted_to_requester_scopes = $6, status = $7, request_event_ref = $8, \
                request_receipts = $9, request_mirror_receipts = $10, basis_evidence = $11, \
                basis_evidence_history = $12, control_outcomes = $13, response_event_ref = $14, \
                tombstone_event_ref = $15, message = $16, peer_service_id = $17, \
                peer_service_resolution = $18, updated_at = $19 \
             WHERE ((requester_id = $1 AND target_id = $2) OR \
                    (requester_id = $2 AND target_id = $1)) AND updated_at = $20",
        )
        .bind::<Text, _>(&record.requester)
        .bind::<Text, _>(&record.target)
        .bind::<Nullable<Text>, _>(record.basis_id.as_deref())
        .bind::<Nullable<BigInt>, _>(record.version.map(i64::try_from).transpose().map_err(
            |_| PersistenceError::Internal("Contact version exceeds PostgreSQL BIGINT".to_owned()),
        )?)
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(
            record.request_event_ref.as_deref(),
        )?)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(basis_evidence.as_ref())
        .bind::<Jsonb, _>(&basis_evidence_history)
        .bind::<Jsonb, _>(&control_outcomes)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(
            record.response_event_ref.as_deref(),
        )?)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(
            record.tombstone_event_ref.as_deref(),
        )?)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_service_id.as_deref())
        .bind::<Nullable<Jsonb>, _>(record.peer_service_resolution.as_ref())
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(expected_updated_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(affected == 1)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 OR target_id = $1 \
             ORDER BY created_at ASC, requester_id ASC, target_id ASC"
        ))
        .bind::<Text, _>(actor)
        .get_results::<ContactRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(contact_record_from_row).collect()
    }

    async fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM contacts WHERE requester_id = $1 AND target_id = $2")
            .bind::<Text, _>(requester)
            .bind::<Text, _>(target)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}

pub struct PgMimiConsentCorrelationStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct MimiConsentCorrelationRow {
    #[diesel(sql_type = Text)]
    consent_id: String,
    #[diesel(sql_type = Text)]
    requester_id: String,
    #[diesel(sql_type = Text)]
    target_kind: String,
    #[diesel(sql_type = Text)]
    target_id: String,
    #[diesel(sql_type = Text)]
    purpose: String,
    #[diesel(sql_type = Nullable<Text>)]
    strand_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    source_service_id: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<MimiConsentCorrelationRow> for MimiConsentCorrelationRecord {
    fn from(row: MimiConsentCorrelationRow) -> Self {
        Self {
            consent_id: row.consent_id,
            requester_id: row.requester_id,
            target_kind: row.target_kind,
            target_id: row.target_id,
            purpose: row.purpose,
            strand_id: row.strand_id,
            source_service_id: row.source_service_id,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}

#[async_trait]
impl MimiConsentCorrelationStore for PgMimiConsentCorrelationStore {
    async fn get(
        &self,
        consent_id: &str,
    ) -> PersistenceResult<Option<MimiConsentCorrelationRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT consent_id, requester_id, target_kind, target_id, purpose, strand_id, \
             source_service_id, created_at, expires_at \
             FROM mimi_consent_correlations WHERE consent_id = $1",
        )
        .bind::<Text, _>(consent_id)
        .get_result::<MimiConsentCorrelationRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MimiConsentCorrelationRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &MimiConsentCorrelationRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO mimi_consent_correlations \
             (consent_id, requester_id, target_kind, target_id, purpose, strand_id, \
              source_service_id, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (consent_id) DO NOTHING",
        )
        .bind::<Text, _>(&record.consent_id)
        .bind::<Text, _>(&record.requester_id)
        .bind::<Text, _>(&record.target_kind)
        .bind::<Text, _>(&record.target_id)
        .bind::<Text, _>(&record.purpose)
        .bind::<Nullable<Text>, _>(record.strand_id.as_deref())
        .bind::<Nullable<Text>, _>(record.source_service_id.as_deref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
// ── Pg-backed invite-receive policy store ────────────────────────────────
// Durable backing for per-subject `invite_receive_policy` overrides. The full
// `InviteReceivePolicy` is persisted as JSONB; `denied_subjects`
// is duplicated into a TEXT[] column for cheap hard-block lookups.
pub struct PgInviteReceivePolicyStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct InviteReceivePolicyRow {
    #[diesel(sql_type = Text)]
    subject_id: String,
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
}
impl InviteReceivePolicyRow {
    fn into_pair(
        self,
    ) -> PersistenceResult<(
        String,
        arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    )> {
        let policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy =
            serde_json::from_value(self.policy_payload)
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "invite_receive_policy `{}` payload decode: {error}",
                    self.subject_id
                ))
            })?;
        Ok((self.subject_id, policy))
    }
}
#[async_trait]
impl InviteReceivePolicyStore for PgInviteReceivePolicyStore {
    async fn get(
        &self,
        subject_id: &str,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
    > {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT subject_id, policy_payload FROM invite_receive_policies WHERE subject_id = $1",
        )
        .bind::<Text, _>(subject_id)
        .get_result::<InviteReceivePolicyRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| row.into_pair().map(|(_, policy)| policy))
            .transpose()
    }

    async fn put(
        &self,
        policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> PersistenceResult<()> {
        let subject_id = policy.subject_id.as_str().to_owned();
        let payload = serde_json::to_value(policy).map_err(|error| {
            PersistenceError::Internal(format!("invite_receive_policy payload encode: {error}"))
        })?;
        let denied_subjects = policy
            .denied_subjects
            .iter()
            .map(|did| did.as_str().to_owned())
            .collect::<Vec<_>>();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO invite_receive_policies \
             (subject_id, policy_payload, denied_subjects, updated_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (subject_id) DO UPDATE SET \
                policy_payload = EXCLUDED.policy_payload, \
                denied_subjects = EXCLUDED.denied_subjects, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(&subject_id)
        .bind::<Jsonb, _>(&payload)
        .bind::<Array<Text>, _>(&denied_subjects)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<
        Vec<(
            String,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    > {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query("SELECT subject_id, policy_payload FROM invite_receive_policies")
            .get_results::<InviteReceivePolicyRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(InviteReceivePolicyRow::into_pair)
            .collect()
    }
}
// ── Pg-backed consent-cell store ─────────────────────────────────────────
// Durable backing for the holder-private consent-cell projection. Column
// order mirrors `state::ConsentCellRecord`; `grant_dots` is persisted as a
// JSONB object `{dot -> {dot, expires_at, granted_at}}` and `revoked_dots` as
// a JSONB string array so the in-memory `BTreeMap`/`BTreeSet` round-trip
// losslessly.
pub struct PgConsentCellStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct ConsentCellRow {
    #[diesel(sql_type = Text)]
    holder: String,
    #[diesel(sql_type = Text)]
    peer: String,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Text)]
    cell_id: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    requested_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Jsonb)]
    grant_dots: Value,
    #[diesel(sql_type = Jsonb)]
    revoked_dots: Value,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
impl ConsentCellRow {
    fn into_pair(self) -> (ConsentCellKey, ConsentCellRecord) {
        let revoked_dots: BTreeSet<String> = self
            .revoked_dots
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let key = ConsentCellKey {
            holder: self.holder.clone(),
            peer: self.peer.clone(),
            scope: self.scope.clone(),
        };
        let record = ConsentCellRecord {
            holder: self.holder,
            peer: self.peer,
            scope: self.scope,
            cell_id: self.cell_id,
            requested_at: self.requested_at,
            grant_dots: decode_grant_dots(&self.grant_dots),
            revoked_dots,
            revoked_at: self.revoked_at,
            updated_at: self.updated_at,
        };
        (key, record)
    }
}
const CONSENT_CELL_COLUMNS: &str = "holder_id AS holder, peer_id AS peer, scope, cell_id, requested_at, grant_dots, \
     revoked_dots, revoked_at, updated_at";
#[async_trait]
impl ConsentCellStore for PgConsentCellStore {
    async fn get(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ConsentCellRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {CONSENT_CELL_COLUMNS} FROM consent_cells \
             WHERE holder_id = $1 AND peer_id = $2 AND scope = $3"
        ))
        .bind::<Text, _>(holder)
        .bind::<Text, _>(peer)
        .bind::<Text, _>(scope)
        .get_result::<ConsentCellRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        Ok(row.map(|row| row.into_pair().1))
    }

    async fn put(&self, record: &ConsentCellRecord) -> PersistenceResult<()> {
        let grant_dots = encode_grant_dots(&record.grant_dots);
        let revoked_dots = Value::Array(
            record
                .revoked_dots
                .iter()
                .map(|dot| Value::String(dot.clone()))
                .collect(),
        );
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO consent_cells \
             (id, holder_id, peer_id, scope, cell_id, requested_at, grant_dots, revoked_dots, revoked_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (holder_id, peer_id, scope) DO UPDATE SET \
                cell_id = EXCLUDED.cell_id, \
                requested_at = EXCLUDED.requested_at, \
                grant_dots = EXCLUDED.grant_dots, \
                revoked_dots = EXCLUDED.revoked_dots, \
                revoked_at = EXCLUDED.revoked_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.holder)
        .bind::<Text, _>(&record.peer)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.cell_id)
        .bind::<Nullable<Timestamptz>, _>(record.requested_at)
        .bind::<Jsonb, _>(&grant_dots)
        .bind::<Jsonb, _>(&revoked_dots)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!("SELECT {CONSENT_CELL_COLUMNS} FROM consent_cells"))
            .get_results::<ConsentCellRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(ConsentCellRow::into_pair).collect())
    }
}
