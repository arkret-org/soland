//! Durable immutable roots for ordinary account-device signer evidence.
//!
//! Retention verifies the complete historical Service/attestation closure and
//! an exact accepted PCR authorization Event/Commit. Issuing a *current*
//! keys/query row additionally requires the live same-cut generation/status
//! gate; this archive never upgrades an old root to current authority.

use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{AccountId, CommittedEventRef, DeviceId, SignerEvidenceRef};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{
    AccountDeviceSignerEvidenceStore, ConflictCode, ForwardedProducerDeviceEvidence,
};

use crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection;
use crate::{
    AsyncPgConnection, PersistenceError, PersistenceResult, PgPool, PgTransactionError, pg_conn,
};

#[derive(Clone)]
pub struct PgAccountDeviceSignerEvidenceArchive {
    pool: PgPool,
}

#[async_trait::async_trait]
impl AccountDeviceSignerEvidenceStore for PgAccountDeviceSignerEvidenceArchive {
    async fn retain_current(
        &self,
        evidence: &AccountDeviceSignerEvidence,
        authorization_ref: &CommittedEventRef,
    ) -> PersistenceResult<SignerEvidenceRef> {
        PgAccountDeviceSignerEvidenceArchive::retain_current(self, evidence, authorization_ref)
            .await
    }

    async fn get(
        &self,
        account: &AccountId,
        device: &DeviceId,
        reference: &SignerEvidenceRef,
    ) -> PersistenceResult<Option<AccountDeviceSignerEvidence>> {
        PgAccountDeviceSignerEvidenceArchive::get(self, account, device, reference).await
    }
}

#[derive(QueryableByName)]
struct ArchiveRow {
    #[diesel(sql_type = Jsonb)]
    evidence_json: Value,
    #[diesel(sql_type = Text)]
    authorization_commit_id: String,
}

#[derive(QueryableByName)]
struct AcceptedAuthorizationRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

impl PgAccountDeviceSignerEvidenceArchive {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Retain the complete evidence before a usable row can be returned.
    /// The caller must still obtain one current PCR status/generation cut and
    /// compare the signed projection with that cut before disclosure.
    pub async fn retain(
        &self,
        evidence: &AccountDeviceSignerEvidence,
        authorization_ref: &CommittedEventRef,
    ) -> PersistenceResult<SignerEvidenceRef> {
        self.retain_inner(evidence, authorization_ref, false).await
    }

    /// Current issuance must prove one complete PCR status and authority cut
    /// in the very transaction that retains its signed root.
    pub async fn retain_current(
        &self,
        evidence: &AccountDeviceSignerEvidence,
        authorization_ref: &CommittedEventRef,
    ) -> PersistenceResult<SignerEvidenceRef> {
        self.retain_inner(evidence, authorization_ref, true).await
    }

    async fn retain_inner(
        &self,
        evidence: &AccountDeviceSignerEvidence,
        authorization_ref: &CommittedEventRef,
        require_current: bool,
    ) -> PersistenceResult<SignerEvidenceRef> {
        let core = &evidence.device_projection_attestation.attestation;
        let account = &core.account_id;
        let device = &core.device_id;
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(
            evidence, account, device,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if authorization_ref.event_id != core.device_authorize_event_id {
            return Err(PersistenceError::SchemaViolation(
                "account-device evidence names another authorization Event".into(),
            ));
        }
        let reference = evidence
            .signer_evidence_ref()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let reference_json =
            serde_json::to_value(&reference).map_err(PersistenceError::database)?;
        let reference_text = reference_json.as_str().ok_or_else(|| {
            PersistenceError::SchemaViolation("signer evidence ref is not a string".into())
        })?;
        let body = serde_json::to_value(evidence).map_err(PersistenceError::database)?;
        let stream_ref = serde_json::to_value(&authorization_ref.stream_ref)
            .map_err(PersistenceError::database)?;
        let position = i64::try_from(authorization_ref.stream_position).map_err(|_| {
            PersistenceError::SchemaViolation("authorization position exceeds storage range".into())
        })?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<(), PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut *conn)
                .await?;
            // The Event and Commit must be the exact accepted PCR source;
            // neither a caller-provided ref nor a devices mirror is enough.
            let accepted = sql_query(
                "SELECT rc.commit_id, ce.envelope->'payload' AS payload FROM realm_commits rc \
                 JOIN canonical_events ce ON ce.pk=rc.event_pk \
                 JOIN principal_resolutions pr ON pr.pcr_realm_id=rc.realm_id \
                 WHERE pr.principal_id=$1 AND pr.station_id=$2 \
                   AND rc.commit_id=$3 AND rc.stream_ref=$4 \
                   AND rc.stream_position=$5 AND ce.envelope->>'event_id'=$6 \
                   AND ce.kind='ak.device.authorize' AND ce.state='committed' \
                   AND ce.actor_id=$7 AND ce.realm_id=pr.pcr_realm_id \
                   AND ce.envelope->'payload'->>'device_id'=$8 \
                   AND ce.envelope->'payload'->>'authorized_generation_ref'=$9",
            )
            .bind::<Text, _>(account.principal_id.as_str())
            .bind::<Text, _>(account.station_id.as_str())
            .bind::<Text, _>(authorization_ref.commit_id.as_str())
            .bind::<Jsonb, _>(&stream_ref)
            .bind::<diesel::sql_types::BigInt, _>(position)
            .bind::<Text, _>(authorization_ref.event_id.as_str())
            .bind::<Text, _>(arkret_wire::ActorId::account(account.clone()).to_string())
            .bind::<Text, _>(device.as_str())
            .bind::<Text, _>(core.authorized_generation_ref.to_string())
            .get_result::<AcceptedAuthorizationRow>(&mut *conn)
            .await
            .optional()?
            .ok_or_else(|| PersistenceError::SchemaViolation(
                "account-device evidence has no exact accepted PCR authorization Commit".into(),
            ))?;
            if accepted.commit_id != authorization_ref.commit_id.as_str() {
                return Err(PersistenceError::SchemaViolation(
                    "account-device authorization Commit changed".into(),
                ).into());
            }
            let authorized: DeviceAuthorizePayload = serde_json::from_value(accepted.payload)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if authorized.device_id != *device
                || authorized.authorized_generation_ref != core.authorized_generation_ref
                || authorized.device_public_key_did.as_str() != core.device_signing_key_did.as_str()
                || authorized.hpke_key != core.hpke_key
                || authorized.not_before != core.authorization_window.not_before
                || authorized.expires_at.flatten() != core.authorization_window.expires_at
            {
                return Err(PersistenceError::SchemaViolation(
                    "account-device attestation differs from accepted authorization payload".into(),
                ).into());
            }
            if require_current {
                let cut = confirmed_pcr_device_status_cut_in_connection(
                    conn,
                    account,
                    device,
                    core.attested_at,
                )
                .await?
                .ok_or_else(|| PersistenceError::Conflict(format!(
                    "{}: account-device current PCR cut is unavailable",
                    ConflictCode::TemporarilyUnavailable,
                )))?;
                if let Some(code) = cut.admission().error_code() {
                    return Err(PersistenceError::Conflict(format!(
                        "{}: account-device is not active at the confirmed PCR cut",
                        code.as_str(),
                    )).into());
                }
                if cut.authority.authorization.as_ref().is_none_or(|current| {
                        current.source_commit_id.as_str() != authorization_ref.commit_id.as_str()
                            || current.event_id != authorization_ref.event_id
                    })
                    || cut.authority.current_generation != Some(core.authorized_generation_ref)
                {
                    return Err(PersistenceError::Conflict(format!(
                        "{}: account-device attestation is not current at the confirmed PCR cut",
                        ConflictCode::TemporarilyUnavailable,
                    )).into());
                }
            }
            sql_query(
                "INSERT INTO account_device_signer_evidence \
                 (evidence_ref,principal_id,station_id,device_id,authorization_event_id,authorization_commit_id,attested_at,evidence_json) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(evidence_ref) DO NOTHING",
            )
            .bind::<Text, _>(reference_text)
            .bind::<Text, _>(account.principal_id.as_str())
            .bind::<Text, _>(account.station_id.as_str())
            .bind::<Text, _>(device.as_str())
            .bind::<Text, _>(authorization_ref.event_id.as_str())
            .bind::<Text, _>(authorization_ref.commit_id.as_str())
            .bind::<Timestamptz, _>(core.attested_at)
            .bind::<Jsonb, _>(&body)
            .execute(&mut *conn)
            .await?;
            let stored = sql_query(
                "SELECT evidence_json,authorization_commit_id FROM account_device_signer_evidence \
                 WHERE evidence_ref=$1 AND principal_id=$2 AND station_id=$3 AND device_id=$4 FOR SHARE",
            )
            .bind::<Text, _>(reference_text)
            .bind::<Text, _>(account.principal_id.as_str())
            .bind::<Text, _>(account.station_id.as_str())
            .bind::<Text, _>(device.as_str())
            .get_result::<ArchiveRow>(&mut *conn)
            .await
            .optional()?;
            if stored.is_none_or(|row| {
                row.evidence_json != body
                    || row.authorization_commit_id != authorization_ref.commit_id.as_str()
            }) {
                return Err(PersistenceError::Conflict(
                    "signer_evidence_ref_conflicts_with_immutable_root".into(),
                ).into());
            }
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)?;
        Ok(reference)
    }

    /// Exact scoped historical read. The caller must authorize the requesting
    /// member and Event before delivering this private retained root.
    pub async fn get(
        &self,
        account: &AccountId,
        device: &DeviceId,
        reference: &SignerEvidenceRef,
    ) -> PersistenceResult<Option<AccountDeviceSignerEvidence>> {
        let reference_json = serde_json::to_value(reference).map_err(PersistenceError::database)?;
        let reference_text = reference_json.as_str().ok_or_else(|| {
            PersistenceError::SchemaViolation("signer evidence ref is not a string".into())
        })?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT evidence_json,authorization_commit_id FROM account_device_signer_evidence \
             WHERE evidence_ref=$1 AND principal_id=$2 AND station_id=$3 AND device_id=$4",
        )
        .bind::<Text, _>(reference_text)
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .bind::<Text, _>(device.as_str())
        .get_result::<ArchiveRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            let evidence: AccountDeviceSignerEvidence = serde_json::from_value(row.evidence_json)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            evidence
                .validate_binding(account, device)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if !evidence
                .matches_ref(reference)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
            {
                return Err(PersistenceError::SchemaViolation(
                    "stored account-device signer evidence ref differs".into(),
                ));
            }
            arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(
                &evidence, account, device,
            )
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            Ok(evidence)
        })
        .transpose()
    }
}

/// Retain the verified `producer_device_evidence` of a cross-Station
/// human-device producer in the transaction that writes the Event's first
/// `RealmCommit`. The row is audit material only; the object is re-bound to
/// the exact producer and its content address before it is written.
pub(crate) async fn retain_forwarded_producer_evidence_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    retained: &ForwardedProducerDeviceEvidence,
) -> PersistenceResult<()> {
    let invalid = |message: &str| PersistenceError::SchemaViolation(message.to_owned());
    let producer = event
        .human_device_producer()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
        .ok_or_else(|| invalid("forwarded producer evidence requires a human-device producer"))?;
    let core = &retained.evidence.device_projection_attestation.attestation;
    if core.account_id != producer.account_id || core.device_id != producer.device_id {
        return Err(invalid(
            "forwarded producer evidence attests another Account or device",
        ));
    }
    if commit.event_ref != event.event_id
        || !retained
            .evidence
            .matches_ref(&retained.evidence_ref)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
    {
        return Err(invalid(
            "forwarded producer evidence does not bind its Commit or ref",
        ));
    }
    let reference_json =
        serde_json::to_value(&retained.evidence_ref).map_err(PersistenceError::database)?;
    let reference_text = reference_json
        .as_str()
        .ok_or_else(|| invalid("signer evidence ref is not a string"))?;
    let body = serde_json::to_value(&retained.evidence).map_err(PersistenceError::database)?;
    sql_query(
        "INSERT INTO forwarded_producer_device_evidence \
         (commit_id,evidence_ref,principal_id,station_id,device_id,attested_at,evidence_json) \
         VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Text, _>(reference_text)
    .bind::<Text, _>(core.account_id.principal_id.as_str())
    .bind::<Text, _>(core.account_id.station_id.as_str())
    .bind::<Text, _>(core.device_id.as_str())
    .bind::<Timestamptz, _>(core.attested_at)
    .bind::<Jsonb, _>(&body)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}
