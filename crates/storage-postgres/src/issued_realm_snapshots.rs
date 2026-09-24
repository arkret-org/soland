//! Exact signed Realm snapshots issued to one authenticated Account.
//!
//! Issuance is separate from handoff snapshots: a handoff's private full
//! manifest must never become readable merely because its ID is known.
//! The caller must prove same-cut account disclosure before calling `issue`.

use super::{
    AsyncConnection, AsyncPgConnection, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz,
    Value, pg_conn, sql_query,
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
    /// Production issuance goes through the same-cut `/head` unit instead.
    pub async fn issue(
        &self,
        account: &arkret_wire::AccountId,
        snapshot: &arkret_wire::RealmStateSnapshot,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            issue_in_connection(conn, account, snapshot)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    /// Read only the object previously issued to this exact Account, then
    /// re-prove at the same read cut that it is still disclosable to it.
    pub async fn by_ref(
        &self,
        account: &arkret_wire::AccountId,
        realm_id: &arkret_wire::RealmId,
        snapshot_id: &arkret_wire::RealmSnapshotId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
        let account_key = account_key(account)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            let Some(row) = sql_query(
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
            .optional()?
            else {
                return Ok(None);
            };
            let snapshot: arkret_wire::RealmStateSnapshot =
                serde_json::from_value(row.snapshot_json).map_err(PersistenceError::database)?;
            if snapshot.snapshot_id != *snapshot_id
                || snapshot.realm_id != *realm_id
                || derived_snapshot_id(&snapshot)? != *snapshot_id
            {
                return Err(PersistenceError::Internal(
                    "issued snapshot identity differs from stored index".to_owned(),
                )
                .into());
            }
            recheck_disclosure_in_connection(conn, account, issuer, &snapshot).await?;
            Ok(Some(snapshot))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

/// Persist the exact signed object and the Account issuance on the caller's
/// transaction, so issuance commits or rolls back with its proving cut.
pub(crate) async fn issue_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<()> {
    let account_key = account_key(account)?;
    let body = serde_json::to_value(snapshot).map_err(PersistenceError::database)?;
    let generation = i64::try_from(snapshot.governance_generation).map_err(|_| {
        PersistenceError::SchemaViolation("snapshot generation exceeds storage range".to_owned())
    })?;
    sql_query(
        "INSERT INTO realm_state_snapshots \
         (snapshot_id, realm_id, governance_generation, snapshot_json, created_at) \
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT (snapshot_id) DO NOTHING",
    )
    .bind::<Text, _>(snapshot.snapshot_id.as_str())
    .bind::<Text, _>(snapshot.realm_id.as_str())
    .bind::<super::BigInt, _>(generation)
    .bind::<Jsonb, _>(&body)
    .bind::<Timestamptz, _>(snapshot.created_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let existing = sql_query(
        "SELECT snapshot_json FROM realm_state_snapshots \
         WHERE snapshot_id = $1 AND realm_id = $2 FOR SHARE",
    )
    .bind::<Text, _>(snapshot.snapshot_id.as_str())
    .bind::<Text, _>(snapshot.realm_id.as_str())
    .get_result::<SnapshotJsonRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if existing.is_none_or(|row| row.snapshot_json != body) {
        return Err(PersistenceError::Conflict(
            "snapshot_ref_conflicts_with_issued_object".to_owned(),
        ));
    }
    sql_query(
        "INSERT INTO realm_state_snapshot_issuances (snapshot_id, account_id) \
         VALUES ($1,$2) ON CONFLICT (snapshot_id, account_id) DO NOTHING",
    )
    .bind::<Text, _>(snapshot.snapshot_id.as_str())
    .bind::<Text, _>(&account_key)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

fn derived_snapshot_id(
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<arkret_wire::RealmSnapshotId> {
    let mut identity = serde_json::to_value(snapshot).map_err(PersistenceError::database)?;
    let object = identity
        .as_object_mut()
        .ok_or_else(|| PersistenceError::Internal("snapshot is not an object".to_owned()))?;
    object.remove("signature");
    object.remove("snapshot_id");
    let bytes =
        arkret_canonical::canonical_json_bytes(&identity).map_err(PersistenceError::database)?;
    Ok(arkret_wire::RealmSnapshotId::from_digest(
        arkret_canonical::sha256_bytes(&bytes),
    ))
}

#[derive(QueryableByName)]
struct ReadTenureRow {
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = super::BigInt)]
    generation: i64,
}

#[derive(QueryableByName)]
struct MemberRevisionRow {
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = super::BigInt)]
    current_stream_position: i64,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = super::BigInt)]
    present: i64,
}

fn undisclosable(reason: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(format!(
        "issued snapshot is no longer provably disclosable: {reason}"
    ))
}

/// Re-prove, per row, head, and floor, that the issued object may still be
/// returned. Only the single-member Realm-stream shape admitted by the
/// issuance gate is re-provable: the Account's `join` row in the object must
/// still be its unchanged current membership revision, every head must still
/// be the accepted Commit it names, and this Station must still hold the
/// object's governing term. Anything else is unavailable, never substituted.
async fn recheck_disclosure_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    issuer: &arkret_wire::DidCoreId,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<()> {
    use arkret_wire::{CommitStreamRef, CurrentSelector, TypedCurrentResult};

    let tenure =
        sql_query("SELECT service_id, generation FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(snapshot.realm_id.as_str())
            .get_result::<ReadTenureRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| undisclosable("the Realm has no governing authority"))?;
    if tenure.service_id != issuer.as_str()
        || i64::try_from(snapshot.governance_generation).ok() != Some(tenure.generation)
    {
        return Err(undisclosable(
            "a later or different governing term cannot re-prove this object",
        ));
    }
    let realm_stream = CommitStreamRef::Realm {
        realm_id: snapshot.realm_id.clone(),
    };
    if snapshot
        .visible_stream_heads
        .iter()
        .any(|head| head.stream_ref != realm_stream)
        || snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|floor| floor.stream_ref != realm_stream)
    {
        return Err(undisclosable("a head or floor is outside the Realm stream"));
    }
    let actor = arkret_wire::ActorId::account(account.clone());
    let mut own_membership = None;
    for row in &snapshot.current_state_entries {
        let TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = row
        else {
            return Err(undisclosable(
                "a row family is outside the re-provable subset",
            ));
        };
        if source_stream_ref != &realm_stream {
            return Err(undisclosable("a row source is outside the Realm stream"));
        }
        match selector {
            CurrentSelector::RealmGenesis
            | CurrentSelector::RealmAuthorityRoot
            | CurrentSelector::RealmProfile
            | CurrentSelector::RealmPolicyBundle
            | CurrentSelector::RealmJoinRule
            | CurrentSelector::RealmHistoryAccess
            | CurrentSelector::RealmDiscovery
            | CurrentSelector::Strand { .. }
            | CurrentSelector::RealmSetDefaultStrand => {}
            CurrentSelector::MemberState { actor_id }
                if actor_id == &actor
                    && own_membership.is_none()
                    && value == &serde_json::json!({"membership":"join"}) =>
            {
                own_membership = Some(revision.clone());
            }
            _ => {
                return Err(undisclosable(
                    "a row selector is outside the re-provable subset",
                ));
            }
        }
    }
    let own_membership =
        own_membership.ok_or_else(|| undisclosable("the object has no Account join row"))?;
    let current = sql_query(
        "SELECT membership, current_commit_id, current_stream_position \
         FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(snapshot.realm_id.as_str())
    .bind::<Text, _>(actor.to_string())
    .get_result::<MemberRevisionRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| undisclosable("the Account has no current membership"))?;
    if current.membership != "join"
        || current.current_commit_id != own_membership.commit_id.as_str()
        || u64::try_from(current.current_stream_position).ok()
            != Some(own_membership.stream_position)
    {
        return Err(undisclosable(
            "the Account membership changed after this object was issued",
        ));
    }
    for head in &snapshot.visible_stream_heads {
        let present = sql_query(
            "SELECT count(*) AS present FROM realm_commits \
             WHERE realm_id=$1 AND commit_id=$2 AND stream_position=$3",
        )
        .bind::<Text, _>(snapshot.realm_id.as_str())
        .bind::<Text, _>(head.commit_id.as_str())
        .bind::<super::BigInt, _>(i64::try_from(head.stream_position).map_err(|_| {
            PersistenceError::SchemaViolation("snapshot head position exceeds storage".to_owned())
        })?)
        .get_result::<CountRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if present.present != 1 {
            return Err(undisclosable(
                "a signed head is no longer an accepted Commit",
            ));
        }
    }
    Ok(())
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

    #[test]
    fn complete_signed_body_over_eight_mib_is_rejected_whole() {
        let base = signed_snapshot();
        let sized = |payload: usize| {
            let material = soland_storage::RealmStateSnapshotMaterial {
                realm_id: base.realm_id.clone(),
                governance_generation: 0,
                visible_stream_heads: base.visible_stream_heads.clone(),
                current_state_entries: vec![arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::RealmProfile,
                    source_stream_ref: base.visible_stream_heads[0].stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: base.visible_stream_heads[0].commit_id.clone(),
                        stream_position: 0,
                    },
                    value: serde_json::json!({"title": "x".repeat(payload)}),
                }],
                retention_and_history_floor: base.retention_and_history_floor.clone(),
            };
            soland_services::authority_commit::build_signed_realm_state_snapshot(
                &material,
                DidUrl::new("did:web:station.example#notary-key").unwrap(),
                &ed25519_dalek::SigningKey::from_bytes(&[0x73; 32]),
                base.created_at,
            )
            .unwrap()
        };
        let probe = sized(0);
        let overhead = arkret_canonical::canonical_json_bytes(&probe)
            .unwrap()
            .len();
        let exact = sized(soland_storage::MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES - overhead);
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&exact)
                .unwrap()
                .len(),
            soland_storage::MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES,
        );
        soland_storage::enforce_inline_realm_state_snapshot_capacity(&exact).unwrap();
        let over = sized(soland_storage::MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES - overhead + 1);
        let error =
            soland_storage::enforce_inline_realm_state_snapshot_capacity(&over).unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::SnapshotCapacityExceeded),
        );
    }

    #[tokio::test]
    async fn issued_snapshot_is_exact_immutable_account_scoped_and_rechecked() {
        let database = crate::test_database::TestDatabase::lease().await;
        let archive = PgIssuedRealmSnapshotArchive::new(database.pool());
        let alice = account("ak:did_core:web:alice.example");
        let bob = account("ak:did_core:web:bob.example");
        let issuer = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let snapshot = signed_snapshot();
        let wrong_realm = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x54; 32],
        ));
        let wrong_ref = RealmSnapshotId::from_digest([0x55; 32]);
        let read = |account: &AccountId, realm: &RealmId, id: &RealmSnapshotId| {
            let (archive, account, realm, id, issuer) = (
                archive.clone(),
                account.clone(),
                realm.clone(),
                id.clone(),
                issuer.clone(),
            );
            async move { archive.by_ref(&account, &realm, &id, &issuer).await }
        };

        assert!(
            read(&alice, &snapshot.realm_id, &snapshot.snapshot_id)
                .await
                .unwrap()
                .is_none()
        );
        archive.issue(&alice, &snapshot).await.unwrap();
        archive.issue(&alice, &snapshot).await.unwrap();
        // Issuance alone is not disclosure: this Realm has no governing
        // authority or Account join row at the read cut, so the exact
        // issued object is withheld rather than returned.
        assert!(matches!(
            read(&alice, &snapshot.realm_id, &snapshot.snapshot_id).await,
            Err(PersistenceError::SchemaViolation(_)),
        ));
        for (account, realm, id) in [
            (&bob, &snapshot.realm_id, &snapshot.snapshot_id),
            (&alice, &wrong_realm, &snapshot.snapshot_id),
            (&alice, &snapshot.realm_id, &wrong_ref),
        ] {
            assert!(read(account, realm, id).await.unwrap().is_none());
        }

        let mut forged_same_ref = snapshot.clone();
        forged_same_ref.signature.sig = arkret_wire::Base64UrlString::new("AA").unwrap();
        assert!(matches!(
            archive.issue(&alice, &forged_same_ref).await,
            Err(PersistenceError::Conflict(_)),
        ));
        // A private handoff-style row with no issuance is never exposed.
        let handoff = {
            let mut other = snapshot.clone();
            other.created_at -= chrono::Duration::seconds(1);
            let material = soland_storage::RealmStateSnapshotMaterial {
                realm_id: other.realm_id.clone(),
                governance_generation: other.governance_generation,
                visible_stream_heads: other.visible_stream_heads.clone(),
                current_state_entries: other.current_state_entries.clone(),
                retention_and_history_floor: other.retention_and_history_floor.clone(),
            };
            soland_services::authority_commit::build_signed_realm_state_snapshot(
                &material,
                DidUrl::new("did:web:station.example#notary-key").unwrap(),
                &ed25519_dalek::SigningKey::from_bytes(&[0x73; 32]),
                other.created_at,
            )
            .unwrap()
        };
        let mut conn = pg_conn(&database.pool()).await.unwrap();
        sql_query(
            "INSERT INTO realm_state_snapshots \
             (snapshot_id, realm_id, governance_generation, snapshot_json, created_at) \
             VALUES ($1,$2,0,$3,$4)",
        )
        .bind::<Text, _>(handoff.snapshot_id.as_str())
        .bind::<Text, _>(handoff.realm_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(&handoff).unwrap())
        .bind::<Timestamptz, _>(handoff.created_at)
        .execute(&mut *conn)
        .await
        .unwrap();
        assert!(
            read(&alice, &handoff.realm_id, &handoff.snapshot_id)
                .await
                .unwrap()
                .is_none()
        );
        // The newer Account-issued object never becomes the Realm-wide anchor.
        let store = crate::PgAuthorityCommitStore {
            pool: database.pool(),
        };
        assert_eq!(
            soland_storage::AuthorityCommitStore::latest_snapshot(&store, &snapshot.realm_id)
                .await
                .unwrap(),
            Some(handoff),
        );
    }
}
