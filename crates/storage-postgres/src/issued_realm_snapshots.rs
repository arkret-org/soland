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

/// A cut that loses a write race with the governing row (a handoff commits
/// after this `REPEATABLE READ` snapshot began, surfacing as SQLSTATE 40001)
/// issued nothing. That is the registered retryable unavailability of the
/// snapshot reads, never an internal fault.
pub(crate) fn snapshot_cut_error(error: diesel::result::Error) -> PersistenceError {
    use diesel::result::{DatabaseErrorKind, Error};
    match error {
        Error::DatabaseError(DatabaseErrorKind::SerializationFailure, info) => {
            PersistenceError::Conflict(format!(
                "{}: the governing cut changed concurrently: {}",
                soland_storage::ConflictCode::TemporarilyUnavailable.as_str(),
                info.message(),
            ))
        }
        other => PersistenceError::database(other),
    }
}

/// [`snapshot_cut_error`] for a whole snapshot-cut transaction.
pub(crate) fn snapshot_transaction_error(error: PgTransactionError) -> PersistenceError {
    match error {
        PgTransactionError::Diesel(error) => snapshot_cut_error(error),
        PgTransactionError::Storage(error) => error,
    }
}

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
    .map_err(snapshot_cut_error)?;
    let existing = sql_query(
        "SELECT snapshot_json FROM realm_state_snapshots \
         WHERE snapshot_id = $1 AND realm_id = $2 FOR SHARE",
    )
    .bind::<Text, _>(snapshot.snapshot_id.as_str())
    .bind::<Text, _>(snapshot.realm_id.as_str())
    .get_result::<SnapshotJsonRow>(&mut *conn)
    .await
    .optional()
    .map_err(snapshot_cut_error)?;
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
    .map_err(snapshot_cut_error)?;
    Ok(())
}

#[derive(QueryableByName)]
struct IssuedCandidateRow {
    #[diesel(sql_type = Jsonb)]
    snapshot_json: Value,
}

/// Issue the signed object of one proved cut to `account`, bounded (0441).
///
/// An object already issued to the Account for exactly this cut (same
/// generation, heads, rows and floors, signed with the same verification
/// method) is reissued instead of archiving `signed`: retries and repeated
/// freezes at one head add no object. The Account's unreserved issuances in
/// this Realm are then trimmed to
/// [`soland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM`],
/// never touching a reserved one or a never-issued handoff object. The
/// caller holds the shared retention lock, so GC cannot interleave.
pub(crate) async fn issue_head_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    material: &soland_storage::RealmStateSnapshotMaterial,
    signed: arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<arkret_wire::RealmStateSnapshot> {
    let account_key = account_key(account)?;
    let generation = i64::try_from(material.governance_generation).map_err(|_| {
        PersistenceError::SchemaViolation("snapshot generation exceeds storage range".to_owned())
    })?;
    let heads =
        serde_json::to_value(&material.visible_stream_heads).map_err(PersistenceError::database)?;
    let candidates = sql_query(
        "SELECT snapshot.snapshot_json FROM realm_state_snapshots snapshot \
         JOIN realm_state_snapshot_issuances issued ON issued.snapshot_id = snapshot.snapshot_id \
         WHERE issued.account_id=$1 AND snapshot.realm_id=$2 \
           AND snapshot.governance_generation=$3 \
           AND snapshot.snapshot_json->'visible_stream_heads' = $4 \
         ORDER BY issued.issued_at DESC, snapshot.snapshot_id \
         LIMIT $5",
    )
    .bind::<Text, _>(&account_key)
    .bind::<Text, _>(material.realm_id.as_str())
    .bind::<super::BigInt, _>(generation)
    .bind::<Jsonb, _>(&heads)
    .bind::<super::BigInt, _>(soland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM)
    .load::<IssuedCandidateRow>(&mut *conn)
    .await
    .map_err(snapshot_cut_error)?;
    let mut issued = None;
    for candidate in candidates {
        let existing: arkret_wire::RealmStateSnapshot =
            serde_json::from_value(candidate.snapshot_json).map_err(PersistenceError::database)?;
        if !soland_storage::signed_snapshot_matches_material(&existing, material)
            || existing.signature.verification_method != signed.signature.verification_method
            || derived_snapshot_id(&existing)? != existing.snapshot_id
        {
            continue;
        }
        let touched = sql_query(
            "UPDATE realm_state_snapshot_issuances SET issued_at = now() \
             WHERE snapshot_id=$1 AND account_id=$2",
        )
        .bind::<Text, _>(existing.snapshot_id.as_str())
        .bind::<Text, _>(&account_key)
        .execute(&mut *conn)
        .await
        .map_err(snapshot_cut_error)?;
        if touched == 1 {
            issued = Some(existing);
            break;
        }
    }
    let issued = match issued {
        Some(existing) => existing,
        None => {
            issue_in_connection(conn, account, &signed).await?;
            signed
        }
    };
    sql_query(
        "WITH doomed AS ( \
           SELECT issued.snapshot_id, issued.account_id \
           FROM realm_state_snapshot_issuances issued \
           JOIN realm_state_snapshots snapshot ON snapshot.snapshot_id = issued.snapshot_id \
           WHERE issued.account_id=$1 AND snapshot.realm_id=$2 AND issued.snapshot_id <> $3 \
             AND NOT EXISTS (SELECT 1 FROM realm_state_snapshot_window_reservations reserved \
                             WHERE reserved.snapshot_id = issued.snapshot_id \
                               AND reserved.account_id = issued.account_id) \
           ORDER BY issued.issued_at DESC, issued.snapshot_id DESC \
           OFFSET $4 \
         ), removed AS ( \
           DELETE FROM realm_state_snapshot_issuances issued USING doomed \
           WHERE issued.snapshot_id = doomed.snapshot_id \
             AND issued.account_id = doomed.account_id \
           RETURNING issued.snapshot_id, issued.account_id \
         ) \
         DELETE FROM realm_state_snapshots snapshot \
         WHERE snapshot.snapshot_id IN (SELECT snapshot_id FROM removed) \
           AND NOT EXISTS ( \
             SELECT 1 FROM realm_state_snapshot_issuances remaining \
             WHERE remaining.snapshot_id = snapshot.snapshot_id \
               AND NOT EXISTS (SELECT 1 FROM removed \
                               WHERE removed.snapshot_id = remaining.snapshot_id \
                                 AND removed.account_id = remaining.account_id))",
    )
    .bind::<Text, _>(&account_key)
    .bind::<Text, _>(material.realm_id.as_str())
    .bind::<Text, _>(issued.snapshot_id.as_str())
    .bind::<super::BigInt, _>(soland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM - 1)
    .execute(&mut *conn)
    .await
    .map_err(snapshot_cut_error)?;
    Ok(issued)
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
struct PresenceRow {
    #[diesel(sql_type = super::Bool)]
    present: bool,
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
/// returned. Only the joined-member Realm-stream shape admitted by the
/// issuance gate is re-provable: the Account's `join` row in the object must
/// still be its unchanged current membership revision, the object's floor
/// must still be the Account's readable floor, no Message row may lie below
/// it, every head must still be the accepted Commit it names, and this
/// Station must still hold the object's governing term. Anything else is
/// unavailable, never substituted.
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
    let current_floor = crate::account_stream_scan::caller_realm_floor_in_connection(
        conn,
        &snapshot.realm_id,
        &actor,
    )
    .await?
    .ok_or_else(|| undisclosable("the Account's readable floor is not provable"))?;
    if snapshot.retention_and_history_floor.stream_floors
        != [arkret_wire::StreamHistoryFloor {
            stream_ref: realm_stream.clone(),
            oldest_position: current_floor.oldest_position,
        }]
    {
        return Err(undisclosable(
            "the object's floor is not the Account's current readable floor",
        ));
    }
    let mut own_membership = None;
    let mut message_targets = Vec::new();
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
            | CurrentSelector::RealmAlias
            | CurrentSelector::RealmPlaintextVisibleServices
            | CurrentSelector::Strand { .. }
            | CurrentSelector::RealmSetDefaultStrand
            | CurrentSelector::InviteLifecycle { .. }
            | CurrentSelector::InviteLiveTarget { .. }
            | CurrentSelector::InviteDirectedInvitee { .. }
            | CurrentSelector::CapabilityGrant { .. }
            | CurrentSelector::ObjectRedaction { .. } => {}
            CurrentSelector::MessageRevision { .. }
                if revision.stream_position < current_floor.oldest_position =>
            {
                return Err(undisclosable("a Message row lies below the readable floor"));
            }
            CurrentSelector::MessageRevision { message_id } => {
                let message_id = message_id.as_str().to_owned();
                message_targets.push(message_id.replacen("ak:message:", "ak:event:", 1));
                message_targets.push(message_id);
            }
            CurrentSelector::MemberState { actor_id }
                if actor_id == &actor
                    && own_membership.is_none()
                    && value == &serde_json::json!({"membership":"join"}) =>
            {
                own_membership = Some(revision.clone());
            }
            CurrentSelector::MemberState { actor_id } if actor_id != &actor => {}
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
    // A Message row carries its content, so it stops being disclosable once
    // retention expires any Event of the Realm or an `object_redaction`
    // assertion names it: the same decision that withholds its committed Event.
    let withdrawn = sql_query(
        "SELECT (EXISTS(SELECT 1 FROM retention_tombstones WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM object_redaction_current_results redaction \
                      WHERE redaction.realm_id=$1 AND redaction.target_ref = ANY($2))) AS present",
    )
    .bind::<Text, _>(snapshot.realm_id.as_str())
    .bind::<super::Array<Text>, _>(&message_targets)
    .get_result::<PresenceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if withdrawn.present {
        return Err(undisclosable(
            "retention or a redaction withdrew a disclosed row",
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

#[derive(QueryableByName)]
struct WindowCommitRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(QueryableByName)]
struct CommitIdRow {
    #[diesel(sql_type = Text)]
    present: String,
}

#[derive(QueryableByName)]
struct ReservedSnapshotRow {
    #[diesel(sql_type = Jsonb)]
    snapshot_json: Value,
    #[diesel(sql_type = super::BigInt)]
    expires_at_ms: i64,
}

fn window_rejected(reason: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("Account window cannot be frozen: {reason}"))
}

/// The basis an exact issued snapshot gives a window whose first row is the
/// Commit after `anchor`: the state after this stream's committed prefix
/// through `anchor`. The snapshot must carry exactly this one stream with
/// its head at the anchor and the caller's readable floor `floor`, at or
/// below the anchor.
fn basis_from_snapshot(
    snapshot: &arkret_wire::RealmStateSnapshot,
    stream_ref: &arkret_wire::CommitStreamRef,
    anchor: &arkret_wire::CommitStreamHead,
    floor: u64,
) -> Option<arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis> {
    use arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis;
    let exact_head = snapshot.visible_stream_heads.as_slice() == std::slice::from_ref(anchor);
    let exact_floor = snapshot
        .retention_and_history_floor
        .stream_floors
        .as_slice()
        == [arkret_wire::StreamHistoryFloor {
            stream_ref: stream_ref.clone(),
            oldest_position: floor,
        }];
    (exact_head
        && exact_floor
        && floor <= anchor.stream_position
        && &anchor.stream_ref == stream_ref)
        .then(|| StreamWindowStartBasis {
            anchor_position: anchor.stream_position,
            anchor_commit_ref: anchor.commit_id.clone(),
            snapshot_ref: snapshot.snapshot_id.clone(),
            governance_generation: snapshot.governance_generation,
            accepted_dependency_refs: None,
        })
}

/// Re-prove an issued object for a basis at the caller's cut. Only a
/// disclosure failure means "not guaranteed"; any other error is a fault.
async fn still_disclosable(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    issuer: &arkret_wire::DidCoreId,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<bool> {
    match recheck_disclosure_in_connection(conn, account, issuer, snapshot).await {
        Ok(()) => Ok(true),
        Err(PersistenceError::SchemaViolation(reason)) => {
            tracing::debug!(%reason, snapshot_id=%snapshot.snapshot_id, "issued snapshot cannot back a window basis");
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// See [`soland_storage::AuthorityCommitStore::freeze_account_realm_window`].
///
/// One `REPEATABLE READ` cut holds, in order: the shared retention lock that
/// excludes issued-snapshot GC, the share-locked governing tenure, the
/// complete joined-member disclosure proof, the delivered rows, and the
/// basis reservation. The window's rows are the live delta after the
/// Account's delivered head when that head is still an accepted ancestor
/// within `window_limit`, otherwise the last `window_limit` Commits of the
/// Realm stream, never below the Account's readable floor; `limited` states
/// whether readable history lies below them. A window above the floor names
/// the committed prefix through its anchor, backed by a snapshot already
/// issued to the Account at that anchor. A window starting exactly at a
/// floor above genesis has no issuable prefix state inside the Account's
/// readable range, so it is `preview_only` without a basis
/// (`sync/client-sync.md` §5.2, decision 0113).
/// The frozen head is issued to the Account in the same cut, so the next
/// delta can name it as its exact basis. Rows are served through the shared
/// committed-event disclosure decision. Issuance reuses the object already
/// issued for an unchanged cut and keeps the Account's unreserved issuances
/// capped; at the live-reservation cap a limited window is preview only.
pub(crate) async fn freeze_account_realm_window(
    pool: &PgPool,
    request: &soland_storage::AccountRealmWindowRequest,
    sign: soland_storage::RealmStateSnapshotSigner<'_>,
) -> PersistenceResult<Option<soland_storage::AccountRealmWindow>> {
    use arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow;

    if request.window_limit > 100 {
        return Err(window_rejected("window_limit exceeds 100"));
    }
    if request.expires_at_ms <= request.now_ms
        || request.expires_at_ms - request.now_ms
            > soland_storage::MAX_ACCOUNT_WINDOW_RESERVATION_MS
    {
        return Err(window_rejected(
            "the consumable deadline is outside the cursor lifetime",
        ));
    }
    arkret_wire::Cursor::new(request.window_cursor.clone())
        .map_err(|_| window_rejected("the window identity is not a cursor value"))?;
    let account_key = account_key(&request.account)?;
    let stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: request.realm_id.clone(),
    };
    let stream_key = crate::authority_commit::stream_key(&stream_ref)?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *conn)
            .await?;
        // Reservations and issued-snapshot GC exclude each other exactly like
        // Account sync reservations and version GC (0441).
        crate::sync_cursor::retention::lock(conn, false).await?;
        let Some(tenure) = sql_query(
            "SELECT service_id, generation FROM realm_authorities \
             WHERE realm_id=$1 FOR SHARE",
        )
        .bind::<Text, _>(request.realm_id.as_str())
        .get_result::<ReadTenureRow>(&mut *conn)
        .await
        .optional()?
        else {
            return Ok(None);
        };
        if tenure.service_id != request.issuer.as_str() {
            return Err(window_rejected("this Station does not hold the governing tenure").into());
        }
        let Some(material) =
            crate::snapshot_disclosure_gate::account_snapshot_material_in_connection(
                conn,
                &request.realm_id,
                &request.account,
            )
            .await?
        else {
            return Ok(None);
        };
        let generation = material.governance_generation;
        if i64::try_from(generation).ok() != Some(tenure.generation) {
            return Err(
                window_rejected("material generation differs from the locked tenure").into(),
            );
        }
        let [head] = material.visible_stream_heads.as_slice() else {
            return Err(window_rejected("the proved cut is not one Realm stream").into());
        };
        let [floor] = material
            .retention_and_history_floor
            .stream_floors
            .as_slice()
        else {
            return Err(window_rejected("the proved cut has no single Realm floor").into());
        };
        let floor = floor.oldest_position;
        let tail_start = (head.stream_position + 1)
            .saturating_sub(u64::from(request.window_limit))
            .max(floor);
        let position = |value: u64| {
            i64::try_from(value).map_err(|_| window_rejected("stream position exceeds storage"))
        };
        let delivered_is_ancestor = match &request.delivered_head {
            Some(delivered)
                if delivered.stream_ref == stream_ref
                    && delivered.stream_position < head.stream_position
                    && delivered.stream_position + 1 >= tail_start =>
            {
                sql_query(
                    "SELECT commit_id AS present FROM realm_commits \
                     WHERE realm_id=$1 AND stream_key=$2 AND stream_position=$3",
                )
                .bind::<Text, _>(request.realm_id.as_str())
                .bind::<Text, _>(&stream_key)
                .bind::<super::BigInt, _>(position(delivered.stream_position)?)
                .get_result::<CommitIdRow>(&mut *conn)
                .await
                .optional()?
                .is_some_and(|row| row.present == delivered.commit_id.as_str())
            }
            _ => false,
        };
        let start = match &request.delivered_head {
            Some(delivered) if delivered_is_ancestor => delivered.stream_position + 1,
            _ => tail_start,
        };
        // Load only the delivered rows and, for a start above genesis, the
        // anchor Commit just below them: never the whole stream history.
        let lowest = start.saturating_sub(1);
        let rows = sql_query(
            "SELECT commit_row.commit_json, event_row.envelope \
             FROM realm_commits commit_row \
             JOIN canonical_events event_row ON event_row.pk=commit_row.event_pk \
             WHERE commit_row.realm_id=$1 AND commit_row.stream_key=$2 \
               AND commit_row.stream_position >= $3 \
             ORDER BY commit_row.stream_position",
        )
        .bind::<Text, _>(request.realm_id.as_str())
        .bind::<Text, _>(&stream_key)
        .bind::<super::BigInt, _>(position(lowest)?)
        .load::<WindowCommitRow>(&mut *conn)
        .await?;
        let mut chain = Vec::with_capacity(rows.len());
        for row in rows {
            let commit: arkret_wire::RealmCommit =
                serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
            let event: arkret_wire::Event =
                serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
            chain.push(arkret_wire::CommittedEventFullView { commit, event });
        }
        let contiguous = chain.iter().enumerate().all(|(offset, view)| {
            view.commit.stream_position == lowest + offset as u64
                && (offset == 0
                    || view.commit.previous_commit_ref.as_ref()
                        == Some(&chain[offset - 1].commit.commit_id))
        });
        let tip = chain
            .last()
            .ok_or_else(|| window_rejected("the proved stream has no Commit"))?;
        if !contiguous
            || tip.commit.stream_position != head.stream_position
            || tip.commit.commit_id != head.commit_id
        {
            return Err(window_rejected("the delivered chain differs from the proved head").into());
        }
        let start_index =
            usize::try_from(start - lowest).map_err(|_| window_rejected("window start"))?;
        let delivered = crate::committed_disclosure::disclose_to_member_in_connection(
            conn,
            chain[start_index..].to_vec(),
            &arkret_wire::ActorId::account(request.account.clone()),
        )
        .await?;
        let encoded = arkret_canonical::canonical_json_bytes(&delivered)
            .map_err(PersistenceError::database)?;
        if encoded.len() > request.byte_budget {
            return Err(window_rejected("the atomic window exceeds its byte budget").into());
        }
        // Readable history lies below the window only above the proved floor.
        let limited = start > floor;
        let mut basis = None;
        let live_reservations = sql_query(
            "SELECT count(*) AS present FROM realm_state_snapshot_window_reservations \
             WHERE account_id=$1 AND stream_key=$2 AND expires_at_ms > $3",
        )
        .bind::<Text, _>(&account_key)
        .bind::<Text, _>(&stream_key)
        .bind::<super::BigInt, _>(request.now_ms)
        .get_result::<CountRow>(&mut *conn)
        .await?
        .present;
        // At the cap no further reservation is taken, so a limited window
        // names no basis and is preview only (0441).
        if start > floor
            && live_reservations < soland_storage::MAX_LIVE_WINDOW_RESERVATIONS_PER_ACCOUNT_STREAM
        {
            let anchor_view = &chain[0];
            let anchor = arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: anchor_view.commit.stream_position,
                commit_id: anchor_view.commit.commit_id.clone(),
            };
            let candidates = sql_query(
                "SELECT snapshot.snapshot_json FROM realm_state_snapshots snapshot \
                 JOIN realm_state_snapshot_issuances issued \
                   ON issued.snapshot_id = snapshot.snapshot_id \
                 WHERE snapshot.realm_id=$1 AND snapshot.governance_generation=$2 \
                   AND issued.account_id=$3 \
                   AND snapshot.snapshot_json->'visible_stream_heads' = $4 \
                 ORDER BY issued.issued_at DESC, snapshot.snapshot_id \
                 LIMIT $5 FOR KEY SHARE OF issued",
            )
            .bind::<Text, _>(request.realm_id.as_str())
            .bind::<super::BigInt, _>(tenure.generation)
            .bind::<Text, _>(&account_key)
            .bind::<Jsonb, _>(
                serde_json::to_value(std::slice::from_ref(&anchor))
                    .map_err(PersistenceError::database)?,
            )
            .bind::<super::BigInt, _>(
                soland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM,
            )
            .load::<SnapshotJsonRow>(&mut *conn)
            .await?;
            for candidate in candidates {
                let snapshot: arkret_wire::RealmStateSnapshot =
                    serde_json::from_value(candidate.snapshot_json)
                        .map_err(PersistenceError::database)?;
                let Some(candidate_basis) =
                    basis_from_snapshot(&snapshot, &stream_ref, &anchor, floor)
                else {
                    continue;
                };
                if derived_snapshot_id(&snapshot)? != snapshot.snapshot_id
                    || !still_disclosable(conn, &request.account, &request.issuer, &snapshot)
                        .await?
                {
                    continue;
                }
                sql_query(
                    "INSERT INTO realm_state_snapshot_window_reservations \
                     (window_cursor, account_id, stream_key, snapshot_id, expires_at_ms) \
                     VALUES ($1,$2,$3,$4,$5)",
                )
                .bind::<Text, _>(&request.window_cursor)
                .bind::<Text, _>(&account_key)
                .bind::<Text, _>(&stream_key)
                .bind::<Text, _>(snapshot.snapshot_id.as_str())
                .bind::<super::BigInt, _>(request.expires_at_ms)
                .execute(&mut *conn)
                .await?;
                basis = Some(candidate_basis);
                break;
            }
        }
        // Issue the frozen head so the next live delta after it has an exact
        // basis. A head beyond the inline snapshot limit issues nothing and
        // that delta is preview only.
        let head_snapshot = sign(&material)?;
        if !soland_storage::signed_snapshot_matches_material(&head_snapshot, &material) {
            return Err(PersistenceError::Internal(
                "snapshot signer changed the proved disclosure material".to_owned(),
            )
            .into());
        }
        if soland_storage::enforce_inline_realm_state_snapshot_capacity(&head_snapshot).is_ok() {
            issue_head_in_connection(conn, &request.account, &material, head_snapshot).await?;
        }
        let window = RealmStreamWindow {
            stream_ref: stream_ref.clone(),
            head_commit_ref: head.commit_id.clone(),
            next_position: head.stream_position + 1,
            limited,
            window_limit: request.window_limit,
            complete: true,
            preview_only: (start > 0 && basis.is_none()).then_some(true),
            window_start_basis: basis,
            e2ee_epoch: None,
        };
        window.validate().map_err(PersistenceError::database)?;
        Ok(Some(soland_storage::AccountRealmWindow {
            governance_generation: generation,
            window,
            committed_events: delivered,
            current_state_entries: material.current_state_entries.clone(),
        }))
    })
    .await
    .map_err(snapshot_transaction_error)
}

/// See [`soland_storage::AuthorityCommitStore::account_window_basis`].
pub(crate) async fn account_window_basis(
    pool: &PgPool,
    realm_id: &arkret_wire::RealmId,
    account: &arkret_wire::AccountId,
    window_cursor: &str,
    stream_ref: &arkret_wire::CommitStreamRef,
    issuer: &arkret_wire::DidCoreId,
    now_ms: i64,
) -> PersistenceResult<
    Option<arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis>,
> {
    let account_key = account_key(account)?;
    let stream_key = crate::authority_commit::stream_key(stream_ref)?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some(row) = sql_query(
            "SELECT snapshot.snapshot_json, reserved.expires_at_ms \
             FROM realm_state_snapshot_window_reservations reserved \
             JOIN realm_state_snapshots snapshot ON snapshot.snapshot_id = reserved.snapshot_id \
             WHERE reserved.window_cursor=$1 AND reserved.account_id=$2 \
               AND reserved.stream_key=$3 AND snapshot.realm_id=$4",
        )
        .bind::<Text, _>(window_cursor)
        .bind::<Text, _>(&account_key)
        .bind::<Text, _>(&stream_key)
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<ReservedSnapshotRow>(&mut *conn)
        .await
        .optional()?
        else {
            return Ok(None);
        };
        if row.expires_at_ms <= now_ms {
            return Ok(None);
        }
        let snapshot: arkret_wire::RealmStateSnapshot =
            serde_json::from_value(row.snapshot_json).map_err(PersistenceError::database)?;
        let [anchor] = snapshot.visible_stream_heads.as_slice() else {
            return Ok(None);
        };
        let [floor] = snapshot
            .retention_and_history_floor
            .stream_floors
            .as_slice()
        else {
            return Ok(None);
        };
        // The recheck below proves this floor is still the Account's own.
        let Some(basis) = basis_from_snapshot(&snapshot, stream_ref, anchor, floor.oldest_position)
        else {
            return Ok(None);
        };
        if !still_disclosable(conn, account, issuer, &snapshot).await? {
            return Ok(None);
        }
        Ok(Some(basis))
    })
    .await
    .map_err(snapshot_transaction_error)
}

/// Reclaim issued snapshots on the retention sweep's exclusive lock (0441).
///
/// Expired window reservations go first. An issuance is then reclaimable only
/// when no live reservation names it and it is older than
/// [`soland_storage::UNRESERVED_ISSUED_SNAPSHOT_RETENTION_MS`]; the signed
/// object goes with its last issuance. A snapshot that was never issued (a
/// private handoff anchor) is never a candidate. Each class is bounded to
/// `batch` rows; the result says whether either class filled its batch.
pub(crate) async fn prune_in_connection(
    conn: &mut AsyncPgConnection,
    now_ms: i64,
    batch: i64,
) -> Result<bool, PgTransactionError> {
    let reservations = sql_query(
        "DELETE FROM realm_state_snapshot_window_reservations WHERE ctid IN \
         (SELECT ctid FROM realm_state_snapshot_window_reservations \
          WHERE expires_at_ms <= $1 ORDER BY expires_at_ms LIMIT $2)",
    )
    .bind::<super::BigInt, _>(now_ms)
    .bind::<super::BigInt, _>(batch)
    .execute(&mut *conn)
    .await?;
    let issuances = sql_query(
        "WITH doomed AS ( \
           SELECT issued.snapshot_id, issued.account_id \
           FROM realm_state_snapshot_issuances issued \
           WHERE issued.issued_at <= to_timestamp(($1 - $2)::double precision / 1000) \
             AND NOT EXISTS (SELECT 1 FROM realm_state_snapshot_window_reservations reserved \
                             WHERE reserved.snapshot_id = issued.snapshot_id \
                               AND reserved.account_id = issued.account_id) \
           ORDER BY issued.issued_at LIMIT $3 \
         ), removed AS ( \
           DELETE FROM realm_state_snapshot_issuances issued USING doomed \
           WHERE issued.snapshot_id = doomed.snapshot_id \
             AND issued.account_id = doomed.account_id \
           RETURNING issued.snapshot_id, issued.account_id \
         ), orphaned AS ( \
           DELETE FROM realm_state_snapshots snapshot \
           WHERE snapshot.snapshot_id IN (SELECT snapshot_id FROM removed) \
             AND NOT EXISTS ( \
               SELECT 1 FROM realm_state_snapshot_issuances remaining \
               WHERE remaining.snapshot_id = snapshot.snapshot_id \
                 AND NOT EXISTS (SELECT 1 FROM removed \
                                 WHERE removed.snapshot_id = remaining.snapshot_id \
                                   AND removed.account_id = remaining.account_id)) \
           RETURNING 1 \
         ) \
         SELECT count(*) AS present FROM removed",
    )
    .bind::<super::BigInt, _>(now_ms)
    .bind::<super::BigInt, _>(soland_storage::UNRESERVED_ISSUED_SNAPSHOT_RETENTION_MS)
    .bind::<super::BigInt, _>(batch)
    .get_result::<CountRow>(&mut *conn)
    .await?
    .present;
    Ok(i64::try_from(reservations).is_ok_and(|rows| rows >= batch) || issuances >= batch)
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
