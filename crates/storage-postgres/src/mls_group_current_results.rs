//! The `mls_group` typed current at the RealmCommit cut.
//!
//! One row per MLS effective scope (encryption-and-audit.md §2.5). The scope's
//! accepted `ak.mls.genesis` creates it (§5.1), each winning `ak.mls.commit`
//! merges its epoch, current Commit ref and covered key-access revision, and
//! every membership change of the scope advances its current key-access
//! revision (§2.4.1). The accepting transaction of an MLS Event decides here,
//! under the Realm authority row lock, everything its admission depends on:
//! the actor's same-cut authorization, the exact current group the serving
//! layer verified the RFC 9420 public transition against, the key-access
//! revision the binding names, and every Welcome's claim ledger row, recipient
//! authorization and queue capacity. Any refusal rolls the whole Commit back.
//!
//! Only Realm-scope groups have an authority cut here. Circle and Sidecar
//! groups need their own scope membership basis and stay closed.

use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_crypto::MlsCommitPayload;
use arkret_wire::{EventKind, MlsGroupCurrent, ScopeRef};
use diesel::sql_types::{BigInt, Binary, Jsonb, Nullable, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{
    AuthorityCommitTransaction, ConflictCode, MlsGroupCurrentRecord, MlsGroupCurrentStore,
    PersistenceError, PersistenceResult,
};

use crate::{OptionalExtension, PgPool, QueryableByName, async_trait, ids, pg_conn, sql_query};

pub struct PgMlsGroupCurrentStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct GroupRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type = Binary)]
    public_state: Vec<u8>,
}

#[derive(QueryableByName)]
struct HistoryAccessRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct ClaimLedgerRow {
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    claim_expires_at_unix_ms: Option<i64>,
}

#[derive(QueryableByName)]
struct EventPkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

fn refused(code: ConflictCode, detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

fn failed_precondition(detail: impl std::fmt::Display) -> PersistenceError {
    refused(ConflictCode::FailedPrecondition, detail)
}

fn binding_mismatch(detail: impl std::fmt::Display) -> PersistenceError {
    refused(ConflictCode::GovernanceBindingMismatch, detail)
}

/// The primary key of one scope: the canonical JSON of its `ScopeRef`.
fn scope_key(scope: &ScopeRef) -> PersistenceResult<String> {
    String::from_utf8(
        arkret_canonical::canonical_json_bytes(scope).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)
}

fn position(value: u64) -> PersistenceResult<i64> {
    i64::try_from(value).map_err(|_| {
        PersistenceError::SchemaViolation("MLS group stream position exceeds BIGINT".to_owned())
    })
}

fn decode_row(row: GroupRow) -> PersistenceResult<MlsGroupCurrentRecord> {
    let invalid = |what: &str, error: &dyn std::fmt::Display| {
        PersistenceError::Internal(format!("stored mls_group {what} is invalid: {error}"))
    };
    Ok(MlsGroupCurrentRecord {
        realm_id: arkret_wire::RealmId::new(row.realm_id)
            .map_err(|error| invalid("Realm id", &error))?,
        value: serde_json::from_value(row.value).map_err(|error| invalid("value", &error))?,
        current_commit_id: arkret_wire::RealmCommitId::new(row.current_commit_id)
            .map_err(|error| invalid("covering Commit id", &error))?,
        current_stream_position: u64::try_from(row.current_stream_position)
            .map_err(|error| invalid("covering stream position", &error))?,
        public_state: row.public_state,
    })
}

async fn locked_group(
    conn: &mut AsyncPgConnection,
    key: &str,
) -> PersistenceResult<Option<MlsGroupCurrentRecord>> {
    sql_query(
        "SELECT realm_id,current_commit_id,current_stream_position,value,public_state \
         FROM mls_group_current_results WHERE scope_key=$1 FOR UPDATE",
    )
    .bind::<Text, _>(key)
    .get_result::<GroupRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_row)
    .transpose()
}

async fn write_group(
    conn: &mut AsyncPgConnection,
    key: &str,
    realm_id: &arkret_wire::RealmId,
    value: &MlsGroupCurrent,
    public_state: &[u8],
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let group_id = value
        .effective_scope
        .canonical_mls_group_id()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    sql_query(
        "INSERT INTO mls_group_current_results \
         (realm_id,scope_key,mls_group_id,current_commit_id,current_stream_position,value,public_state,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
         ON CONFLICT (scope_key) DO UPDATE SET \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value, public_state=EXCLUDED.public_state, updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(key)
    .bind::<Text, _>(group_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position(commit.stream_position)?)
    .bind::<Jsonb, _>(serde_json::to_value(value).map_err(PersistenceError::database)?)
    .bind::<Binary, _>(public_state)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

/// Install the transition of an accepted `ak.mls.genesis` or `ak.mls.commit`
/// and queue every Welcome it carries, after its Event and RealmCommit were
/// written in the same transaction.
pub(crate) async fn commit_mls_group_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> PersistenceResult<()> {
    let event = &transaction.event;
    if !matches!(event.kind, EventKind::MlsGenesis | EventKind::MlsCommit) {
        return Ok(());
    }
    let commit = &transaction.commit;
    let installation = transaction.mls_state.as_ref().ok_or_else(|| {
        PersistenceError::SchemaViolation(
            "an MLS Event commits only with its verified public transition".to_owned(),
        )
    })?;
    if !matches!(&event.scope_ref, ScopeRef::Realm { realm_id } if realm_id == &event.realm_id) {
        return Err(PersistenceError::Internal(
            "Circle and Sidecar MLS groups have no scope authority cut".to_owned(),
        ));
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    let key = scope_key(&event.scope_ref)?;
    let current = locked_group(conn, &key).await?;
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let next = match event.kind {
        EventKind::MlsGenesis => {
            if current.is_some() {
                return Err(refused(
                    ConflictCode::MlsActivationIrreversible,
                    "the scope's MLS Genesis is already accepted",
                ));
            }
            require_since_join_history(conn, &event.realm_id).await?;
            let payload: MlsGenesisPayload = serde_json::from_value(payload)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let binding = &payload.governance_binding;
            MlsGroupCurrent {
                effective_scope: event.scope_ref.clone(),
                genesis_event_ref: event.event_id.clone(),
                current_mls_commit_event_ref: event.event_id.clone(),
                epoch: binding.next_epoch(),
                current_key_access_revision: binding.key_access_revision(),
                covered_key_access_revision: binding.key_access_revision(),
                public_tree_ref: payload.ratchet_tree_ref.clone(),
            }
        }
        _ => {
            let current = current
                .ok_or_else(|| failed_precondition("the scope has no accepted MLS Genesis"))?;
            let payload: MlsCommitPayload = serde_json::from_value(payload)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let binding = payload.governance_binding();
            let base = installation.base.as_ref().ok_or_else(|| {
                PersistenceError::SchemaViolation(
                    "an MLS Commit installs over one verified base".to_owned(),
                )
            })?;
            let group = &current.value;
            if group.current_mls_commit_event_ref != base.current_mls_commit_event_ref
                || group.epoch != base.epoch
                || payload.base_group_state_ref() != &group.current_mls_commit_event_ref
                || payload.base_epoch() != group.epoch
            {
                return Err(binding_mismatch(
                    "the Commit base is not the scope's current MLS group",
                ));
            }
            if binding.key_access_revision() != group.current_key_access_revision
                || payload.covers_key_access_revision() != group.current_key_access_revision
            {
                return Err(binding_mismatch(
                    "the Commit binding does not name the scope's current key-access revision",
                ));
            }
            MlsGroupCurrent {
                current_mls_commit_event_ref: event.event_id.clone(),
                epoch: payload.next_epoch(),
                covered_key_access_revision: payload.covers_key_access_revision(),
                ..group.clone()
            }
        }
    };
    if next.epoch != installation.epoch {
        return Err(binding_mismatch(
            "the installed public state is not at the Commit's epoch",
        ));
    }
    write_group(
        conn,
        &key,
        &event.realm_id,
        &next,
        &installation.public_state,
        commit,
    )
    .await?;
    if transaction.welcomes.is_empty() {
        return Ok(());
    }
    let token = ids::parse_event_id(event.event_id.as_str()).ok_or_else(|| {
        PersistenceError::SchemaViolation("MLS Commit Event id is not canonical".to_owned())
    })?;
    let event_pk = sql_query("SELECT pk FROM canonical_events WHERE id=$1")
        .bind::<diesel::sql_types::Binary, _>(token.to_vec())
        .get_result::<EventPkRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .pk;
    for welcome in &transaction.welcomes {
        require_joined_recipient(conn, &event.realm_id, &welcome.delivery.recipient_actor_id)
            .await?;
        require_live_claim(conn, welcome, commit.committed_at).await?;
        crate::devices::enqueue_mls_welcome_in_connection(
            conn,
            &welcome.delivery,
            event_pk,
            commit.committed_at,
            transaction.recipient_queue_capacity,
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
    }
    Ok(())
}

/// realm-and-space.md §2.3.A: the first `ak.mls.genesis` of a Realm scope is
/// accepted only while its current `history_access` is `since_join`.
async fn require_since_join_history(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<()> {
    let history = sql_query(
        "SELECT value FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_history_access' FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<HistoryAccessRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if history.as_ref().and_then(|row| row.value.as_str()) != Some("since_join") {
        return Err(failed_precondition(
            "MLS activation requires the Realm history_access since_join",
        ));
    }
    Ok(())
}

/// encryption-and-audit.md §2.2: an Add admits a current member of the scope.
async fn require_joined_recipient(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    recipient: &arkret_wire::ActorId,
) -> PersistenceResult<()> {
    let joined = sql_query(
        "SELECT EXISTS(SELECT 1 FROM member_state_current_results \
         WHERE realm_id=$1 AND member_id=$2 AND membership='join') AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(recipient.to_string())
    .get_result::<crate::ExistsRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present;
    if !joined {
        return Err(failed_precondition(
            "the Welcome recipient is not a joined member of the Realm",
        ));
    }
    Ok(())
}

/// The claim ledger row a Welcome was verified against must still hold the
/// same request and a live claim (device-lifecycle.md, claim ledger rules).
async fn require_live_claim(
    conn: &mut AsyncPgConnection,
    welcome: &soland_storage::VerifiedMlsWelcome,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let row = sql_query(
        "SELECT request_digest,state,claim_expires_at_unix_ms FROM peer_keypackage_claims \
         WHERE source_id=$1 AND claim_request_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(&welcome.claim.source_id)
    .bind::<Text, _>(&welcome.claim.claim_request_id)
    .get_result::<ClaimLedgerRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| failed_precondition("the Welcome's KeyPackage claim is not in the ledger"))?;
    if row.request_digest != welcome.claim.request_digest
        || !matches!(row.state.as_str(), "claimed" | "last_resort_claimed")
        || row
            .claim_expires_at_unix_ms
            .is_none_or(|expires| expires <= at.timestamp_millis())
    {
        return Err(failed_precondition(
            "the Welcome's KeyPackage claim is no longer live",
        ));
    }
    Ok(())
}

/// encryption-and-audit.md §2.4.1: a membership change of the Realm scope
/// strictly advances its current key-access revision, so new application
/// ciphertext waits for a Commit that covers it.
pub(crate) async fn advance_key_access_revision_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if !matches!(event.kind, EventKind::MemberState | EventKind::InviteAccept) {
        return Ok(());
    }
    let scope = ScopeRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    let key = scope_key(&scope)?;
    let Some(current) = locked_group(conn, &key).await? else {
        return Ok(());
    };
    let mut value = current.value;
    value.current_key_access_revision = value
        .current_key_access_revision
        .checked_add(1)
        .ok_or_else(|| {
            PersistenceError::SchemaViolation("MLS key-access revision overflow".to_owned())
        })?;
    write_group(
        conn,
        &key,
        &event.realm_id,
        &value,
        &current.public_state,
        commit,
    )
    .await
}

#[async_trait]
impl MlsGroupCurrentStore for PgMlsGroupCurrentStore {
    async fn current(
        &self,
        effective_scope: &ScopeRef,
    ) -> PersistenceResult<Option<MlsGroupCurrentRecord>> {
        let key = scope_key(effective_scope)?;
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,current_commit_id,current_stream_position,value,public_state \
             FROM mls_group_current_results WHERE scope_key=$1",
        )
        .bind::<Text, _>(key)
        .get_result::<GroupRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_row)
        .transpose()
    }

    async fn realm_currents(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<MlsGroupCurrentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,current_commit_id,current_stream_position,value,public_state \
             FROM mls_group_current_results WHERE realm_id=$1 \
             ORDER BY (value->'effective_scope'->>'kind') <> 'realm', scope_key",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<GroupRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(decode_row)
        .collect()
    }

    #[cfg(any(test, feature = "test-support"))]
    async fn seed_test_current(&self, record: &MlsGroupCurrentRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let key = scope_key(&record.value.effective_scope)?;
        let group_id = record
            .value
            .effective_scope
            .canonical_mls_group_id()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        sql_query(
            "INSERT INTO mls_group_current_results \
             (realm_id,scope_key,mls_group_id,current_commit_id,current_stream_position,value,public_state,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,now()) \
             ON CONFLICT (scope_key) DO UPDATE SET \
               current_commit_id=EXCLUDED.current_commit_id, \
               current_stream_position=EXCLUDED.current_stream_position, \
               value=EXCLUDED.value, public_state=EXCLUDED.public_state, updated_at=now()",
        )
        .bind::<Text, _>(record.realm_id.as_str())
        .bind::<Text, _>(key)
        .bind::<Text, _>(group_id.as_str())
        .bind::<Text, _>(record.current_commit_id.as_str())
        .bind::<BigInt, _>(position(record.current_stream_position)?)
        .bind::<Jsonb, _>(serde_json::to_value(&record.value).map_err(PersistenceError::database)?)
        .bind::<Binary, _>(&record.public_state)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm_id() -> arkret_wire::RealmId {
        arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x61; 32],
        ))
    }

    fn at() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    fn event(kind: EventKind) -> arkret_wire::Event {
        arkret_wire::test_support::raw_event_for_actor_at(
            kind.as_str(),
            ScopeRef::Realm {
                realm_id: realm_id(),
            },
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:mls-bump-member.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:mls-bump-station.example").unwrap(),
            )),
            serde_json::json!({}),
            at(),
        )
        .unwrap()
    }

    fn commit(event: &arkret_wire::Event, position: u64) -> arkret_wire::RealmCommit {
        arkret_wire::RealmCommit {
            commit_id: arkret_wire::RealmCommitId::from_digest([position as u8; 32]),
            realm_id: realm_id(),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id(),
            },
            stream_position: position,
            previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([0x09; 32])),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x61; 32],
                ),
            ),
            committed_at: at(),
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:mls-bump-station.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: at(),
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
            },
        }
    }

    /// encryption-and-audit.md §2.4.1: each membership change of the Realm
    /// scope advances its current key-access revision by exactly one at the
    /// membership Commit, leaving epoch, current MLS Commit and covered
    /// revision unchanged; other kinds and Realms without a group write
    /// nothing.
    #[tokio::test]
    async fn a_membership_change_advances_only_the_current_key_access_revision() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgMlsGroupCurrentStore { pool: pool.clone() };
        let scope = ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let genesis =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x62; 32]);
        let seeded = MlsGroupCurrentRecord {
            realm_id: realm_id(),
            value: MlsGroupCurrent {
                effective_scope: scope.clone(),
                genesis_event_ref: genesis.clone(),
                current_mls_commit_event_ref: genesis,
                epoch: 4,
                current_key_access_revision: 2,
                covered_key_access_revision: 2,
                public_tree_ref: arkret_wire::BlobRef::new(format!(
                    "ak:blob:sha256:{}",
                    "4".repeat(64)
                ))
                .unwrap(),
            },
            current_commit_id: arkret_wire::RealmCommitId::from_digest([0x05; 32]),
            current_stream_position: 5,
            public_state: vec![7],
        };
        store.seed_test_current(&seeded).await.unwrap();
        let mut conn = pool.get().await.unwrap();

        let message = event(EventKind::MessageCreate);
        advance_key_access_revision_in_connection(&mut conn, &message, &commit(&message, 6))
            .await
            .unwrap();
        assert_eq!(store.current(&scope).await.unwrap().unwrap(), seeded);

        let membership = event(EventKind::MemberState);
        let membership_commit = commit(&membership, 7);
        advance_key_access_revision_in_connection(&mut conn, &membership, &membership_commit)
            .await
            .unwrap();
        let advanced = store.current(&scope).await.unwrap().unwrap();
        assert_eq!(advanced.value.current_key_access_revision, 3);
        assert_eq!(
            MlsGroupCurrent {
                current_key_access_revision: 2,
                ..advanced.value.clone()
            },
            seeded.value
        );
        assert_eq!(advanced.current_commit_id, membership_commit.commit_id);
        assert_eq!(advanced.current_stream_position, 7);
        assert_eq!(advanced.public_state, seeded.public_state);
    }
}
