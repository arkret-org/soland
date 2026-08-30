use arkret_identifiers::{CellRef, DidCoreId, EventId, Hash};
use arkret_wire::ActorId;
use diesel::sql_types::{BigInt, Binary};

use super::{
    Array, BTreeSet, ConsentCellKey, ConsentCellRecord, ConsentCellStore, ContactRecord,
    ContactStore, ContactVerifiedMirrorRecord, ContactVerifiedMirrorStore,
    InviteReceivePolicyStore, Jsonb, MimiConsentCorrelationRecord, MimiConsentCorrelationStore,
    Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName,
    RunQueryDsl, Text, Timestamptz, Value, async_trait, decode_grant_dots, ids, pg_conn, sql_query,
};
/// Encode a contact's Event reference for storage.
///
/// The `contacts` Event-reference columns hold the same 33-octet token
/// `canonical_events.id` does, so a malformed wire id is rejected at the
/// storage boundary rather than stored and discovered on read.
fn parse_contact_event_ref(event_ref: Option<&EventId>) -> PersistenceResult<Option<Vec<u8>>> {
    event_ref
        .map(|value| {
            ids::event_token_part_or_schema_violation(value.as_str(), "event")
                .map(|token| token.to_vec())
        })
        .transpose()
}

fn format_contact_event_ref(token: &[u8]) -> PersistenceResult<EventId> {
    let value = ids::format_event_id(
        &<[u8; ids::EVENT_ID_BYTES]>::try_from(token)
            .expect("contacts Event reference is a 33-octet Event id"),
    );
    EventId::new(value).map_err(|_| {
        PersistenceError::SchemaViolation(
            "stored Contact Event reference is not a canonical EventId".to_owned(),
        )
    })
}
// ── Pg-backed contact projection store ───────────────────────────────────
// Durable backing for the holder↔peer `ContactStore`. Mirrors the
// `MemoryContactStore` query shape onto the `contacts` table. Column order
// matches `state::ContactRecord`.
pub struct PgContactStore {
    pub pool: PgPool,
}

pub struct PgContactVerifiedMirrorStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct ContactVerifiedMirrorRow {
    #[diesel(sql_type = Text)]
    target_holder_id: String,
    #[diesel(sql_type = Text)]
    request_event_id: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Binary)]
    canonical_event_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    source_receipt: Value,
    #[diesel(sql_type = Text)]
    issuer_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Timestamptz)]
    verified_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<ContactVerifiedMirrorRow> for ContactVerifiedMirrorRecord {
    type Error = PersistenceError;

    fn try_from(row: ContactVerifiedMirrorRow) -> Result<Self, Self::Error> {
        Ok(Self {
            target_holder_id: row.target_holder_id,
            request_event_id: row.request_event_id,
            request_digest: row.request_digest,
            canonical_event_bytes: row.canonical_event_bytes,
            source_receipt: serde_json::from_value(row.source_receipt).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "stored Contact request receipt is invalid: {error}"
                ))
            })?,
            issuer_id: row.issuer_id.into_string(),
            verified_at: row.verified_at,
        })
    }
}

const CONTACT_VERIFIED_MIRROR_COLUMNS: &str = "target_holder_id, request_event_id, request_digest, canonical_event_bytes, source_receipt, issuer_id, verified_at";

#[async_trait]
impl ContactVerifiedMirrorStore for PgContactVerifiedMirrorStore {
    async fn get(
        &self,
        target_holder_id: &str,
        request_event_id: &str,
    ) -> PersistenceResult<Option<ContactVerifiedMirrorRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {CONTACT_VERIFIED_MIRROR_COLUMNS} FROM contact_verified_mirrors WHERE target_holder_id = $1 AND request_event_id = $2"
        ))
        .bind::<Text, _>(target_holder_id)
        .bind::<Text, _>(request_event_id)
        .get_result::<ContactVerifiedMirrorRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_digest(
        &self,
        target_holder_id: &str,
        request_digest: &str,
    ) -> PersistenceResult<Option<ContactVerifiedMirrorRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {CONTACT_VERIFIED_MIRROR_COLUMNS} FROM contact_verified_mirrors WHERE target_holder_id = $1 AND request_digest = $2 LIMIT 1"
        ))
        .bind::<Text, _>(target_holder_id)
        .bind::<Text, _>(request_digest)
        .get_result::<ContactVerifiedMirrorRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn put_verified(&self, record: &ContactVerifiedMirrorRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let source_receipt = serde_json::to_value(&record.source_receipt).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "Contact request receipt encode failed: {error}"
            ))
        })?;
        let row = sql_query(format!(
            "INSERT INTO contact_verified_mirrors ({CONTACT_VERIFIED_MIRROR_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (target_holder_id, request_event_id) DO UPDATE SET verified_at = contact_verified_mirrors.verified_at \
             WHERE contact_verified_mirrors.request_digest = EXCLUDED.request_digest \
               AND contact_verified_mirrors.canonical_event_bytes = EXCLUDED.canonical_event_bytes \
               AND contact_verified_mirrors.source_receipt = EXCLUDED.source_receipt \
               AND contact_verified_mirrors.issuer_id = EXCLUDED.issuer_id \
             RETURNING {CONTACT_VERIFIED_MIRROR_COLUMNS}"
        ))
        .bind::<Text, _>(&record.target_holder_id)
        .bind::<Text, _>(&record.request_event_id)
        .bind::<Text, _>(&record.request_digest)
        .bind::<Binary, _>(&record.canonical_event_bytes)
        .bind::<Jsonb, _>(&source_receipt)
        .bind::<Text, _>(&record.issuer_id)
        .bind::<Timestamptz, _>(record.verified_at)
        .get_result::<ContactVerifiedMirrorRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if row.is_none() {
            return Err(PersistenceError::Internal(
                "cas_conflict: Contact verified mirror binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}
#[derive(QueryableByName)]
struct ContactRow {
    #[diesel(sql_type = Text)]
    requester_id: String,
    #[diesel(sql_type = Text)]
    target_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    contact_round_id: Option<Hash>,
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
    contact_round_evidence: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    contact_round_evidence_history: Value,
    #[diesel(sql_type = Jsonb)]
    control_outcomes: Value,
    #[diesel(sql_type = Nullable<Binary>)]
    response_event_ref: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Binary>)]
    tombstone_event_ref: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    message: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    peer_host_id: Option<DidCoreId>,
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
        requester_id: serde_json::from_str(&row.requester_id).map_err(|error| {
            PersistenceError::Internal(format!("invalid contacts.requester_id ActorId: {error}"))
        })?,
        target_id: serde_json::from_str(&row.target_id).map_err(|error| {
            PersistenceError::Internal(format!("invalid contacts.target_id ActorId: {error}"))
        })?,
        contact_round_id: row.contact_round_id,
        version: row.version.map(u64::try_from).transpose().map_err(|_| {
            PersistenceError::Internal("contacts.version contains a negative value".to_owned())
        })?,
        granted_to_target_scopes: row.granted_to_target_scopes,
        granted_to_requester_scopes: row.granted_to_requester_scopes,
        status: row.status,
        request_event_ref: row
            .request_event_ref
            .as_deref()
            .map(format_contact_event_ref)
            .transpose()?,
        request_receipts: decode_contact_json(row.request_receipts, "request_receipts")?,
        request_mirror_receipts: decode_contact_json(
            row.request_mirror_receipts,
            "request_mirror_receipts",
        )?,
        contact_round_evidence: row
            .contact_round_evidence
            .map(|value| decode_contact_json(value, "contact_round_evidence"))
            .transpose()?,
        contact_round_evidence_history: decode_contact_json(
            row.contact_round_evidence_history,
            "contact_round_evidence_history",
        )?,
        control_outcomes: decode_contact_json(row.control_outcomes, "control_outcomes")?,
        response_event_ref: row
            .response_event_ref
            .as_deref()
            .map(format_contact_event_ref)
            .transpose()?,
        tombstone_event_ref: row
            .tombstone_event_ref
            .as_deref()
            .map(format_contact_event_ref)
            .transpose()?,
        message: row.message,
        peer_host_id: row.peer_host_id,
        peer_service_resolution: row.peer_service_resolution,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}
const CONTACT_COLUMNS: &str = "requester_id, target_id, contact_round_id, version, granted_to_target_scopes, granted_to_requester_scopes, status, request_event_ref, request_receipts, request_mirror_receipts, contact_round_evidence, contact_round_evidence_history, control_outcomes, response_event_ref, tombstone_event_ref, message, peer_id AS peer_host_id, peer_service_resolution, created_at, updated_at";
#[async_trait]
impl ContactStore for PgContactStore {
    async fn get(
        &self,
        requester_id: &ActorId,
        target_id: &ActorId,
    ) -> PersistenceResult<Option<ContactRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 AND target_id = $2 \
             LIMIT 1"
        ))
        .bind::<Text, _>(requester_id.to_string())
        .bind::<Text, _>(target_id.to_string())
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
        let contact_round_evidence = record
            .contact_round_evidence
            .as_ref()
            .map(|value| encode_contact_json(value, "contact_round_evidence"))
            .transpose()?;
        let contact_round_evidence_history = encode_contact_json(
            &record.contact_round_evidence_history,
            "contact_round_evidence_history",
        )?;
        let control_outcomes = encode_contact_json(&record.control_outcomes, "control_outcomes")?;
        sql_query(
            "INSERT INTO contacts \
             (id, requester_id, target_id, contact_round_id, version, granted_to_target_scopes, granted_to_requester_scopes, status, request_event_ref, request_receipts, request_mirror_receipts, contact_round_evidence, contact_round_evidence_history, control_outcomes, response_event_ref, tombstone_event_ref, message, peer_id, peer_service_resolution, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21) \
             ON CONFLICT (requester_id, target_id) DO UPDATE SET \
                contact_round_id = EXCLUDED.contact_round_id, \
                version = EXCLUDED.version, \
                granted_to_target_scopes = EXCLUDED.granted_to_target_scopes, \
                granted_to_requester_scopes = EXCLUDED.granted_to_requester_scopes, \
                status = EXCLUDED.status, \
                request_event_ref = EXCLUDED.request_event_ref, \
                request_receipts = EXCLUDED.request_receipts, \
                request_mirror_receipts = EXCLUDED.request_mirror_receipts, \
                contact_round_evidence = EXCLUDED.contact_round_evidence, \
                contact_round_evidence_history = EXCLUDED.contact_round_evidence_history, \
                control_outcomes = EXCLUDED.control_outcomes, \
                response_event_ref = EXCLUDED.response_event_ref, \
                tombstone_event_ref = EXCLUDED.tombstone_event_ref, \
                message = EXCLUDED.message, \
                peer_id = EXCLUDED.peer_id, \
                peer_service_resolution = EXCLUDED.peer_service_resolution, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(record.requester_id.to_string())
        .bind::<Text, _>(record.target_id.to_string())
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_ref())
        .bind::<Nullable<BigInt>, _>(record.version.map(i64::try_from).transpose().map_err(|_| PersistenceError::Internal("Contact version exceeds PostgreSQL BIGINT".to_owned()))?)
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(record.request_event_ref.as_ref())?)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(contact_round_evidence.as_ref())
        .bind::<Jsonb, _>(&contact_round_evidence_history)
        .bind::<Jsonb, _>(&control_outcomes)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(record.response_event_ref.as_ref())?)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(
            record.tombstone_event_ref.as_ref(),
        )?)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_host_id.as_ref())
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
        let contact_round_evidence = record
            .contact_round_evidence
            .as_ref()
            .map(|value| encode_contact_json(value, "contact_round_evidence"))
            .transpose()?;
        let contact_round_evidence_history = encode_contact_json(
            &record.contact_round_evidence_history,
            "contact_round_evidence_history",
        )?;
        let control_outcomes = encode_contact_json(&record.control_outcomes, "control_outcomes")?;
        let affected = sql_query(
            "UPDATE contacts SET requester_id = $1, target_id = $2, \
                contact_round_id = $3, version = $4, granted_to_target_scopes = $5, \
                granted_to_requester_scopes = $6, status = $7, request_event_ref = $8, \
                request_receipts = $9, request_mirror_receipts = $10, contact_round_evidence = $11, \
                contact_round_evidence_history = $12, control_outcomes = $13, response_event_ref = $14, \
                tombstone_event_ref = $15, message = $16, peer_id = $17, \
                peer_service_resolution = $18, updated_at = $19 \
             WHERE ((requester_id = $1 AND target_id = $2) OR \
                    (requester_id = $2 AND target_id = $1)) AND updated_at = $20",
        )
        .bind::<Text, _>(record.requester_id.to_string())
        .bind::<Text, _>(record.target_id.to_string())
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_ref())
        .bind::<Nullable<BigInt>, _>(record.version.map(i64::try_from).transpose().map_err(
            |_| PersistenceError::Internal("Contact version exceeds PostgreSQL BIGINT".to_owned()),
        )?)
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(
            record.request_event_ref.as_ref(),
        )?)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(contact_round_evidence.as_ref())
        .bind::<Jsonb, _>(&contact_round_evidence_history)
        .bind::<Jsonb, _>(&control_outcomes)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(
            record.response_event_ref.as_ref(),
        )?)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(
            record.tombstone_event_ref.as_ref(),
        )?)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_host_id.as_ref())
        .bind::<Nullable<Jsonb>, _>(record.peer_service_resolution.as_ref())
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(expected_updated_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(affected == 1)
    }

    async fn list_for_actor(&self, actor_id: &ActorId) -> PersistenceResult<Vec<ContactRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 OR target_id = $1 \
             ORDER BY created_at ASC, requester_id ASC, target_id ASC"
        ))
        .bind::<Text, _>(actor_id.to_string())
        .get_results::<ContactRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(contact_record_from_row).collect()
    }

    async fn delete(&self, requester_id: &ActorId, target_id: &ActorId) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM contacts WHERE requester_id = $1 AND target_id = $2")
            .bind::<Text, _>(requester_id.to_string())
            .bind::<Text, _>(target_id.to_string())
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
    source_id: Option<String>,
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
            source_id: row.source_id,
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
             source_id, created_at, expires_at \
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
              source_id, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (consent_id) DO NOTHING",
        )
        .bind::<Text, _>(&record.consent_id)
        .bind::<Text, _>(&record.requester_id)
        .bind::<Text, _>(&record.target_kind)
        .bind::<Text, _>(&record.target_id)
        .bind::<Text, _>(&record.purpose)
        .bind::<Nullable<Text>, _>(record.strand_id.as_deref())
        .bind::<Nullable<Text>, _>(record.source_id.as_deref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
// ── Pg-backed invite-receive policy store ────────────────────────────────
// Account ownership is normalized through accounts.pk. The shared wire policy
// is the sole stored policy value; reads verify its binding against the owner.
pub struct PgInviteReceivePolicyStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct InviteReceivePolicyRow {
    #[diesel(sql_type = Text)]
    principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: DidCoreId,
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
}
impl InviteReceivePolicyRow {
    fn into_policy(
        self,
    ) -> PersistenceResult<
        arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    > {
        let policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy =
            serde_json::from_value(self.policy_payload)
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "invite_receive_policy payload decode: {error}"
                ))
            })?;
        if policy.account_id != arkret_wire::AccountId::new(self.principal_id, self.station_id) {
            return Err(PersistenceError::Internal(
                "invite_receive_policy account binding mismatch".to_owned(),
            ));
        }
        Ok(policy)
    }
}

pub(crate) async fn put_invite_receive_policy(
    conn: &mut diesel_async::AsyncPgConnection,
    policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
) -> PersistenceResult<()> {
    let payload = serde_json::to_value(policy).map_err(|error| {
        PersistenceError::Internal(format!("invite_receive_policy payload encode: {error}"))
    })?;
    let written = sql_query(
        "INSERT INTO invite_receive_policies (account_pk, policy_payload, updated_at) \
         SELECT pk, $3, NOW() FROM accounts WHERE principal_id = $1 AND station_id = $2 \
         ON CONFLICT (account_pk) DO UPDATE SET \
         policy_payload = EXCLUDED.policy_payload, updated_at = NOW()",
    )
    .bind::<Text, _>(policy.account_id.principal_id.as_str())
    .bind::<Text, _>(policy.account_id.station_id.as_str())
    .bind::<Jsonb, _>(&payload)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(PersistenceError::Conflict(
            "invite_receive_policy account does not exist".to_owned(),
        ));
    }
    Ok(())
}
#[async_trait]
impl InviteReceivePolicyStore for PgInviteReceivePolicyStore {
    async fn get(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
    > {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT a.principal_id, a.station_id, p.policy_payload FROM invite_receive_policies p \
             JOIN accounts a ON a.pk = p.account_pk \
             WHERE a.principal_id = $1 AND a.station_id = $2",
        )
        .bind::<Text, _>(account_id.principal_id.as_str())
        .bind::<Text, _>(account_id.station_id.as_str())
        .get_result::<InviteReceivePolicyRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(InviteReceivePolicyRow::into_policy).transpose()
    }

    async fn put(
        &self,
        policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        put_invite_receive_policy(&mut conn, policy).await
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<
        Vec<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
    > {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT a.principal_id, a.station_id, p.policy_payload FROM invite_receive_policies p \
             JOIN accounts a ON a.pk = p.account_pk",
        )
        .get_results::<InviteReceivePolicyRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(InviteReceivePolicyRow::into_policy)
            .collect()
    }
}
#[cfg(test)]
mod invite_policy_tests {
    use super::*;

    #[test]
    fn stored_policy_payload_must_match_normalized_account_owner() {
        use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
        let principal_id = DidCoreId::new("ak:did_core:web:holder.example".to_owned()).unwrap();
        let station_id = DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap();
        let policy = InviteReceivePolicy::spec_default(arkret_wire::AccountId::new(
            principal_id.clone(),
            station_id.clone(),
        ));
        let payload = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            InviteReceivePolicyRow {
                principal_id: principal_id.clone(),
                station_id,
                policy_payload: payload.clone(),
            }
            .into_policy()
            .unwrap(),
            policy
        );
        assert!(
            InviteReceivePolicyRow {
                principal_id,
                station_id: DidCoreId::new("ak:did_core:web:other-station.example".to_owned())
                    .unwrap(),
                policy_payload: payload,
            }
            .into_policy()
            .is_err()
        );
    }
}

// ── Pg-backed consent-cell store ─────────────────────────────────────────
// Durable backing for the holder-private consent-cell projection, keyed by
// (holder, cell_id) because `consent_id` is the cell subject. Column order
// mirrors `ConsentCellRecord`; `grant_dots` is persisted as a JSONB object
// `{dot -> {dot, not_before, expires_at, granted_at}}` and `revoked_dots` as a
// JSONB string array so the in-memory `BTreeMap`/`BTreeSet` round-trip
// losslessly. Writes happen only inside the Event commit unit of work.
pub struct PgConsentCellStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct ConsentCellRow {
    #[diesel(sql_type = Text)]
    cell_id: CellRef,
    #[diesel(sql_type = Text)]
    holder_principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    peer_principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    consent_scope: String,
    #[diesel(sql_type = Jsonb)]
    grant_dots: Value,
    #[diesel(sql_type = Jsonb)]
    revoked_dots: Value,
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
            holder_principal_id: self.holder_principal_id.clone(),
            cell_id: self.cell_id.clone(),
        };
        let record = ConsentCellRecord {
            cell_id: self.cell_id,
            holder_principal_id: self.holder_principal_id,
            peer_principal_id: self.peer_principal_id,
            consent_scope: self.consent_scope,
            grant_dots: decode_grant_dots(&self.grant_dots),
            revoked_dots,
            updated_at: self.updated_at,
        };
        (key, record)
    }
}
const CONSENT_CELL_COLUMNS: &str = "cell_id, holder_id AS holder_principal_id, peer_id AS peer_principal_id, consent_scope, grant_dots, revoked_dots, updated_at";
#[async_trait]
impl ConsentCellStore for PgConsentCellStore {
    async fn get(
        &self,
        holder_principal_id: &DidCoreId,
        cell_id: &CellRef,
    ) -> PersistenceResult<Option<ConsentCellRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {CONSENT_CELL_COLUMNS} FROM consent_cells              WHERE holder_id = $1 AND cell_id = $2"
        ))
        .bind::<Text, _>(holder_principal_id)
        .bind::<Text, _>(cell_id)
        .get_result::<ConsentCellRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        Ok(row.map(|row| row.into_pair().1))
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
