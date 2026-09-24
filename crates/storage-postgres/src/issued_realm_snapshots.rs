//! Exact signed Realm snapshots issued to one authenticated Account.
//!
//! Issuance is separate from handoff snapshots: a handoff's private full
//! manifest must never become readable merely because its ID is known.
//! The caller must prove same-cut account disclosure before calling `issue`.

use super::{
    AsyncConnection, Jsonb, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz, Value, pg_conn, sql_query,
};

#[derive(Clone)]
pub struct PgIssuedRealmSnapshotArchive {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct SnapshotJsonRow {
    #[diesel(sql_type = Jsonb)]
    snapshot_json: Value,
}

impl PgIssuedRealmSnapshotArchive {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Preserve one previously signed object and its exact Account grant in
    /// one transaction. A repeated issue is idempotent only for the same body.
    pub async fn issue(
        &self,
        account: &arkret_wire::AccountId,
        snapshot: &arkret_wire::RealmStateSnapshot,
    ) -> PersistenceResult<()> {
        let account_key = account_key(account)?;
        let body = serde_json::to_value(snapshot).map_err(PersistenceError::database)?;
        let snapshot_id = snapshot.snapshot_id.as_str().to_owned();
        let realm_id = snapshot.realm_id.as_str().to_owned();
        let generation = i64::try_from(snapshot.governance_generation).map_err(|_| {
            PersistenceError::SchemaViolation(
                "snapshot generation exceeds storage range".to_owned(),
            )
        })?;
        let created_at = snapshot.created_at;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query(
                "INSERT INTO realm_state_snapshots \
                 (snapshot_id, realm_id, governance_generation, snapshot_json, created_at) \
                 VALUES ($1,$2,$3,$4,$5) ON CONFLICT (snapshot_id) DO NOTHING",
            )
            .bind::<Text, _>(&snapshot_id)
            .bind::<Text, _>(&realm_id)
            .bind::<super::BigInt, _>(generation)
            .bind::<Jsonb, _>(&body)
            .bind::<Timestamptz, _>(created_at)
            .execute(&mut *conn)
            .await?;
            let existing = sql_query(
                "SELECT snapshot_json FROM realm_state_snapshots \
                 WHERE snapshot_id = $1 AND realm_id = $2 FOR SHARE",
            )
            .bind::<Text, _>(&snapshot_id)
            .bind::<Text, _>(&realm_id)
            .get_result::<SnapshotJsonRow>(&mut *conn)
            .await
            .optional()?;
            if existing.is_none_or(|row| row.snapshot_json != body) {
                return Err(PersistenceError::Conflict(
                    "snapshot_ref_conflicts_with_issued_object".to_owned(),
                )
                .into());
            }
            sql_query(
                "INSERT INTO realm_state_snapshot_issuances (snapshot_id, account_id) \
                 VALUES ($1,$2) ON CONFLICT (snapshot_id, account_id) DO NOTHING",
            )
            .bind::<Text, _>(&snapshot_id)
            .bind::<Text, _>(&account_key)
            .execute(&mut *conn)
            .await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    /// Read only the object previously issued to this exact Account. The HTTP
    /// caller must also recheck current Realm and per-row disclosure rights.
    pub async fn by_ref(
        &self,
        account: &arkret_wire::AccountId,
        realm_id: &arkret_wire::RealmId,
        snapshot_id: &arkret_wire::RealmSnapshotId,
    ) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
        let account_key = account_key(account)?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT snapshot.snapshot_json FROM realm_state_snapshots snapshot \
             JOIN realm_state_snapshot_issuances issued \
               ON issued.snapshot_id = snapshot.snapshot_id \
             WHERE snapshot.snapshot_id = $1 AND snapshot.realm_id = $2 \
               AND issued.account_id = $3",
        )
        .bind::<Text, _>(snapshot_id.as_str())
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(&account_key)
        .get_result::<SnapshotJsonRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            let snapshot: arkret_wire::RealmStateSnapshot =
                serde_json::from_value(row.snapshot_json).map_err(PersistenceError::database)?;
            if snapshot.snapshot_id != *snapshot_id || snapshot.realm_id != *realm_id {
                return Err(PersistenceError::Internal(
                    "issued snapshot identity differs from stored index".to_owned(),
                ));
            }
            Ok(snapshot)
        })
        .transpose()
    }
}

fn account_key(account: &arkret_wire::AccountId) -> PersistenceResult<String> {
    String::from_utf8(
        arkret_canonical::canonical_json_bytes(account).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        AccountId, CommitStreamHead, CommitStreamRef, DidCoreId, DidUrl, EventId, HistoryAccess,
        RealmCommitId, RealmId, RealmSnapshotId, RetentionAndHistoryFloor, StreamHistoryFloor,
    };

    use super::*;

    fn account(principal: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn signed_snapshot() -> arkret_wire::RealmStateSnapshot {
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x51; 32],
        ));
        let stream_ref = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let material = soland_storage::RealmStateSnapshotMaterial {
            realm_id,
            governance_generation: 0,
            visible_stream_heads: vec![CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 0,
                commit_id: RealmCommitId::from_digest([0x52; 32]),
            }],
            current_state_entries: Vec::new(),
            retention_and_history_floor: RetentionAndHistoryFloor {
                history_access: HistoryAccess::SinceJoin,
                stream_floors: vec![StreamHistoryFloor {
                    stream_ref,
                    oldest_position: 0,
                }],
            },
        };
        soland_services::authority_commit::build_signed_realm_state_snapshot(
            &material,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &ed25519_dalek::SigningKey::from_bytes(&[0x73; 32]),
            chrono::Utc::now(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn issued_snapshot_is_exact_immutable_and_account_scoped() {
        let database = crate::test_database::TestDatabase::lease().await;
        let archive = PgIssuedRealmSnapshotArchive::new(database.pool());
        let alice = account("ak:did_core:web:alice.example");
        let bob = account("ak:did_core:web:bob.example");
        let snapshot = signed_snapshot();
        let wrong_realm = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x54; 32],
        ));
        let wrong_ref = RealmSnapshotId::from_digest([0x55; 32]);

        assert!(
            archive
                .by_ref(&alice, &snapshot.realm_id, &snapshot.snapshot_id)
                .await
                .unwrap()
                .is_none()
        );
        archive.issue(&alice, &snapshot).await.unwrap();
        archive.issue(&alice, &snapshot).await.unwrap();
        assert_eq!(
            archive
                .by_ref(&alice, &snapshot.realm_id, &snapshot.snapshot_id)
                .await
                .unwrap(),
            Some(snapshot.clone()),
        );
        assert!(
            archive
                .by_ref(&bob, &snapshot.realm_id, &snapshot.snapshot_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            archive
                .by_ref(&alice, &wrong_realm, &snapshot.snapshot_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            archive
                .by_ref(&alice, &snapshot.realm_id, &wrong_ref)
                .await
                .unwrap()
                .is_none()
        );

        let mut forged_same_ref = snapshot.clone();
        forged_same_ref.signature.sig = arkret_wire::Base64UrlString::new("AA").unwrap();
        assert!(matches!(
            archive.issue(&alice, &forged_same_ref).await,
            Err(PersistenceError::Conflict(_)),
        ));
        assert_eq!(
            archive
                .by_ref(&alice, &snapshot.realm_id, &snapshot.snapshot_id)
                .await
                .unwrap(),
            Some(snapshot),
        );
    }
}
