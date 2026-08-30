use arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvite;

use super::{
    Binary, Jsonb, Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RealmInviteRecord, RealmInviteStore, RunQueryDsl, Text, Timestamptz, Utc,
    Value, async_trait, ids, pg_conn, sql_query,
};
pub struct PgRealmInviteStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct RealmInviteRow {
    #[diesel(sql_type = Binary)]
    id: Vec<u8>,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    inviter_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Nullable<Text>)]
    invitee_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    introduction_evidence_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    third_party_invite: Option<Value>,
    #[diesel(sql_type = Text)]
    invite_token: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Jsonb)]
    claim_nonces: Value,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl RealmInviteRow {
    /// JSONB adapter boundary: `third_party_invite` is the only column still
    /// stored as raw JSON; it decodes into the authoritative
    /// `ThirdPartyInvite` here. A stored value that fails the closed schema is
    /// data corruption and must fail closed, never fall back to a raw `Value`.
    fn try_into_record(self) -> PersistenceResult<RealmInviteRecord> {
        let third_party_invite = self
            .third_party_invite
            .map(|value| {
                serde_json::from_value::<ThirdPartyInvite>(value).map_err(|error| {
                    PersistenceError::Database(format!(
                        "realm_invites.third_party_invite fails the closed ThirdPartyInvite schema: {error}"
                    ))
                })
            })
            .transpose()?;
        Ok(RealmInviteRecord {
            invite_id: {
                let token: [u8; ids::EVENT_ID_BYTES] =
                    self.id.as_slice().try_into().map_err(|_| {
                        PersistenceError::Database("realm_invites.id must be 33 bytes".to_owned())
                    })?;
                ids::format_event_token("invite", &token)
            },
            realm_id: self.realm_id,
            inviter_id: self.inviter_id.to_string(),
            invitee_id: self.invitee_id,
            introduction_evidence_digest: self.introduction_evidence_digest,
            third_party_invite,
            invite_token: self.invite_token,
            status: self.status,
            claim_nonces: serde_json::from_value(self.claim_nonces).unwrap_or_default(),
            expires_at: self.expires_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}
#[async_trait]
impl RealmInviteStore for PgRealmInviteStore {
    async fn get(&self, invite_id: &str) -> PersistenceResult<Option<RealmInviteRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let invite_id_token =
            ids::event_token_part_or_schema_violation(invite_id, "invite")?.to_vec();
        sql_query(
            "SELECT id, realm_id, inviter_id AS inviter_id, invitee_id AS invitee_id, introduction_evidence_digest, third_party_invite, invite_token, status, claim_nonces, expires_at, created_at, updated_at \
             FROM realm_invites WHERE id = $1",
        )
        .bind::<Binary, _>(invite_id_token)
        .get_result::<RealmInviteRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(RealmInviteRow::try_into_record)
        .transpose()
    }

    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let invite_id_token =
            ids::event_token_part_or_schema_violation(&record.invite_id, "invite")?.to_vec();
        crate::realm_identity::ensure_realm_pk(&mut conn, &record.realm_id).await?;
        let third_party_invite = record
            .third_party_invite
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                PersistenceError::Database(format!(
                    "realm_invites.third_party_invite failed to serialize: {error}"
                ))
            })?;
        sql_query(
            "INSERT INTO realm_invites \
             (id, realm_id, inviter_id, invitee_id, introduction_evidence_digest, third_party_invite, invite_token, status, claim_nonces, expires_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                inviter_id = EXCLUDED.inviter_id, \
                invitee_id = EXCLUDED.invitee_id, \
                introduction_evidence_digest = EXCLUDED.introduction_evidence_digest, \
                third_party_invite = EXCLUDED.third_party_invite, \
                invite_token = EXCLUDED.invite_token, \
                status = EXCLUDED.status, \
                claim_nonces = EXCLUDED.claim_nonces, \
                expires_at = EXCLUDED.expires_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Binary, _>(invite_id_token)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(&record.inviter_id)
        .bind::<Nullable<Text>, _>(&record.invitee_id)
        .bind::<Nullable<Text>, _>(&record.introduction_evidence_digest)
        .bind::<Nullable<Jsonb>, _>(&third_party_invite)
        .bind::<Text, _>(&record.invite_token)
        .bind::<Text, _>(&record.status)
        .bind::<Jsonb, _>(serde_json::to_value(&record.claim_nonces).unwrap_or_default())
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn consume_third_party_token(
        &self,
        token_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<RealmInviteRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let consumed = sql_query(
            "UPDATE realm_invites \
             SET invite_token = '', updated_at = $2 \
             WHERE invite_token = $1 \
               AND third_party_invite IS NOT NULL \
               AND status = 'pending' \
               AND (expires_at IS NULL OR expires_at > $2) \
             RETURNING id, realm_id, inviter_id AS inviter_id, invitee_id AS invitee_id, introduction_evidence_digest, third_party_invite, invite_token, status, claim_nonces, expires_at, created_at, updated_at",
        )
        .bind::<Text, _>(token_digest)
        .bind::<Timestamptz, _>(now)
        .get_result::<RealmInviteRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(RealmInviteRow::try_into_record)
        .transpose()?;
        if consumed.is_some() {
            return Ok(consumed);
        }
        sql_query(
            "UPDATE realm_invites \
             SET status = 'expired', \
                 invite_token = '', \
                 third_party_invite = ((((((third_party_invite - 'token_salt') - 'token_salt_id') - 'lookup_table_ref') - 'pepper') - 'pepper_id') - 'token_commitment'), \
                 updated_at = $2 \
             WHERE invite_token = $1 \
               AND third_party_invite IS NOT NULL \
               AND status = 'pending' \
               AND expires_at IS NOT NULL \
               AND expires_at <= $2",
        )
        .bind::<Text, _>(token_digest)
        .bind::<Timestamptz, _>(now)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)?;
        Ok(None)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, realm_id, inviter_id AS inviter_id, invitee_id AS invitee_id, introduction_evidence_digest, third_party_invite, invite_token, status, claim_nonces, expires_at, created_at, updated_at \
             FROM realm_invites ORDER BY created_at ASC, pk ASC",
        )
        .load::<RealmInviteRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(RealmInviteRow::try_into_record)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::governance::third_party_invite::ThirdPartyInviteOobKind;

    use super::*;

    fn row_with_third_party_invite(third_party_invite: Option<Value>) -> RealmInviteRow {
        RealmInviteRow {
            id: vec![0u8; ids::EVENT_ID_BYTES],
            realm_id: "ak:realm:test".to_owned(),
            inviter_id: arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            invitee_id: None,
            introduction_evidence_digest: None,
            third_party_invite,
            invite_token: String::new(),
            status: "pending".to_owned(),
            claim_nonces: serde_json::json!({}),
            expires_at: None,
            created_at: chrono::DateTime::default(),
            updated_at: None,
        }
    }

    fn offline_token_invite() -> ThirdPartyInvite {
        ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::OfflineToken,
            display_name_hint: None,
            token_commitment: Some(
                arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64)))
                    .expect("valid hash literal"),
            ),
            token_salt_id: Some("salt-1".to_owned()),
            token_entropy_bits: Some(128),
            lookup_table_ref: None,
            pepper_id: None,
            max_claims: 1,
            verification_id: arkret_identifiers::DidCoreId::new(
                "ak:did_core:web:verify.example".to_owned(),
            )
            .expect("valid DID core id literal"),
            verification_public_key: "did:web:verify.example#invite-key".to_owned(),
        }
    }

    fn lookup_invite() -> ThirdPartyInvite {
        ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::Lookup,
            display_name_hint: Some("e-mail".to_owned()),
            token_commitment: None,
            token_salt_id: None,
            token_entropy_bits: None,
            lookup_table_ref: Some("lookup-table-7".to_owned()),
            pepper_id: Some("pepper-3".to_owned()),
            max_claims: 1,
            verification_id: arkret_identifiers::DidCoreId::new(
                "ak:did_core:web:verify.example".to_owned(),
            )
            .expect("valid DID core id literal"),
            verification_public_key: "did:web:verify.example#invite-key".to_owned(),
        }
    }

    #[test]
    fn jsonb_adapter_round_trips_offline_token_mode() {
        let invite = offline_token_invite();
        let jsonb = serde_json::to_value(&invite).expect("ThirdPartyInvite serializes");
        let record = row_with_third_party_invite(Some(jsonb))
            .try_into_record()
            .expect("valid stored value decodes");
        assert_eq!(record.third_party_invite, Some(invite));
    }

    #[test]
    fn jsonb_adapter_round_trips_lookup_mode() {
        let invite = lookup_invite();
        let jsonb = serde_json::to_value(&invite).expect("ThirdPartyInvite serializes");
        let record = row_with_third_party_invite(Some(jsonb))
            .try_into_record()
            .expect("valid stored value decodes");
        assert_eq!(record.third_party_invite, Some(invite));
    }

    #[test]
    fn jsonb_adapter_fails_closed_on_corrupt_stored_value() {
        for corrupt in [
            // Unknown member: the closed schema admits no extension keys.
            serde_json::json!({
                "oob_code_kind": "offline_token",
                "token_commitment": format!("sha256:{}", "a".repeat(64)),
                "token_salt_id": "salt-1",
                "token_entropy_bits": 128,
                "verification_id": "ak:did_core:web:verify.example",
                "verification_public_key": "did:web:verify.example#invite-key",
                "token": "plaintext-secret"
            }),
            // Missing the required discriminator.
            serde_json::json!({
                "token_commitment": format!("sha256:{}", "a".repeat(64)),
                "verification_id": "ak:did_core:web:verify.example",
                "verification_public_key": "did:web:verify.example#invite-key"
            }),
            // Not an object at all.
            serde_json::json!("not-an-object"),
        ] {
            let error = row_with_third_party_invite(Some(corrupt))
                .try_into_record()
                .expect_err("corrupt stored third_party_invite must fail closed");
            assert!(
                matches!(error, PersistenceError::Database(_)),
                "corrupt stored value must surface as a persistence error, got {error}"
            );
        }
    }
}
