//! Caller-aware Realm State Snapshot disclosure
//! (`realm-state-snapshot-schema.md` §3, `current-results.md` §1 and §3,
//! `history-visibility.md` §3.1 and §6).
//!
//! The governing Station materializes every typed current result in the same
//! transaction that commits its Event, so the rows, stream heads and floors of
//! a Snapshot are read from those durable families at one `REPEATABLE READ`
//! cut. This module decides, for one requesting Account, which of them it may
//! receive, and refuses the whole cut when any part is not provably
//! disclosable:
//!
//! - every installed `*_current_results` family has a disclosure rule here, and families without
//!   one (moderator-only reports, grants, links, Agent and PCR state) hold no row of this Realm;
//! - every accepted Event of the Realm is of a kind whose result writes land only in disclosed
//!   families, so no admitted Event can have produced state this subset omits;
//! - no Event of the Realm is retention-expired: a `message_revision` row would otherwise carry the
//!   content that committed-event reads withhold, and no typed row states the expiry;
//! - a redacted Message is disclosed as its `object_redaction` row only: its `message_revision` row
//!   carries the content every other read path withholds, so it is outside the caller's visible
//!   range and not part of the disclosed cut (`strand-and-message.md` §9.2);
//! - the Realm has only its Realm stream (Circle and Sidecar visibility is not proved here) and is
//!   in its genesis tenure (a planned handoff import of current families is not proved here);
//! - the Account is currently joined and its readable floor on the Realm stream is proved at this
//!   cut by the same function the Account stream scan uses: the genesis Commit for the founding
//!   member and under `all_history_for_current_members`, its current join Commit under `since_join`
//!   (decision 0108 §1045). The Snapshot floor is exactly that value.
//!
//! Per family, a joined member receives:
//!
//! - every Realm singleton, every `member_state` row, every Realm-scoped Strand and Space (with its
//!   separate parent and child-scope-policy current families), every `invite_lifecycle`,
//!   `invite_live_target`, `invite_directed_invitee` and `capability_grant` row, and the
//!   Realm-scope `mls_group` row (the public MLS group every member's send gate reads,
//!   encryption-and-audit.md §2.5.3). These are Realm-stream state written by durable shared Events
//!   that federation fans out to every joined member (`federation.md` §4.1.1); membership, not a
//!   grant, decides a member's reads (`capabilities.md` §9) and a Realm promises no read isolation
//!   among its joined members (`realm-and-space.md` §1). A row below the caller's floor is current
//!   state the signed Snapshot commits to (`realm-state-snapshot-schema.md` §3);
//! - a `message_revision` row only when its covering Commit is within the caller's readable
//!   interval. Its value is the accepted carrier Event's payload, i.e. history content, and a
//!   Snapshot must satisfy the history policy (`history-visibility.md` §6). A row below the floor
//!   is a selector the caller may not read and is omitted (`current-results.md` §3).

use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CurrentSelector, EventKind, ReadableFloor, RealmId,
    StreamHistoryFloor, TypedCurrentResult,
};
use diesel::sql_types::Text as SqlText;

use super::{
    AsyncConnection, AsyncPgConnection, Bool, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, pg_conn,
    sql_query,
};

/// Event kinds whose admission writes only disclosed current families. Any
/// other accepted kind refuses the cut rather than risk an omitted result.
pub(crate) const DISCLOSED_EVENT_KINDS: &[EventKind] = &[
    EventKind::RealmCreate,
    EventKind::RealmProfile,
    EventKind::RealmPolicyBundle,
    EventKind::RealmJoinRule,
    EventKind::RealmHistoryAccess,
    EventKind::RealmDiscovery,
    EventKind::RealmAlias,
    EventKind::RealmPlaintextVisibleServices,
    EventKind::MemberState,
    EventKind::InviteCreate,
    EventKind::InviteRevoke,
    EventKind::InviteCancel,
    EventKind::InviteAccept,
    EventKind::CapabilityGrant,
    EventKind::CapabilityRevoke,
    EventKind::CapabilityRelinquish,
    EventKind::StrandCreate,
    EventKind::StrandUpdate,
    EventKind::StrandMove,
    EventKind::StrandReorder,
    EventKind::SpaceCreate,
    EventKind::RealmSetDefaultStrand,
    EventKind::MessageCreate,
    EventKind::MessageRevise,
    EventKind::MessageRedact,
    EventKind::MlsGenesis,
    EventKind::MlsCommit,
];

/// Every typed-current table this Station installs. A new family could be
/// written by an admitted Event, so it must be classified here before any
/// Snapshot is signed again.
const AUDITED_FAMILIES: &[&str] = &[
    "relation_current_results",
    "realm_authority_root_current_results",
    "capability_grant_current_results",
    "realm_policy_bundle_current_results",
    // PCR-private Policy documents have no ordinary Realm disclosure rule.
    "policy_current_results",
    "mimi_room_binding_current_results",
    "realm_link_current_results",
    "member_state_current_results",
    // Private child-stream rows are not in the Realm snapshot disclosure
    // subset. Audit the installed tables, then refuse cuts that hold them.
    "circle_current_results",
    "circle_member_state_current_results",
    "sidecar_current_results",
    "sidecar_context_current_results",
    "strand_current_results",
    "strand_watch_current_results",
    "strand_position_current_results",
    "rsvp_current_results",
    "space_current_results",
    "space_parent_current_results",
    "space_child_scope_policy_current_results",
    "realm_set_default_strand_current_results",
    "message_revision_current_results",
    "mls_group_current_results",
    "object_redaction_current_results",
    "invite_lifecycle_current_results",
    "invite_live_target_current_results",
    "invite_directed_invitee_current_results",
    // Moderator-only (content-moderation.md §3.3): these refuse the cut below
    // while any row exists, never silently omitted from a signed cut.
    "moderation_report_current_results",
    "moderation_state_current_results",
    "realm_bootstrap_current_results",
    "agent_status_current_results",
    "agent_key_current_results",
    "key_backup_active_series_current_results",
    "pcr_device_generation_current_results",
    "pcr_device_authorization_current_results",
    // PCR-stream Actor Profile and accountability state: no row of an
    // ordinary collaboration Realm, so any row refuses the cut below.
    "actor_profile_current_results",
    "identity_accountability_current_results",
    // Controller-PCR Agent provisioning state: likewise never in an ordinary
    // collaboration Realm.
    "agent_provisioning_current_results",
    "agent_pcr_genesis_declaration_current_results",
    "agent_selector_claim_current_results",
    // Direct Conversation binding endorsements: `ak.direct_conversation.bound`
    // has no disclosure rule yet, so any row refuses the cut below.
    "direct_conversation_binding_current_results",
    // Holder-private PCR Consent is outside ordinary Realm disclosure.
    "consent_current_results",
];

/// A committed kind of the Realm outside [`DISCLOSED_EVENT_KINDS`].
pub(crate) fn undisclosed_kind_sql() -> String {
    let disclosed_kinds = DISCLOSED_EVENT_KINDS
        .iter()
        .map(|kind| format!("'{}'", kind.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "SELECT kind FROM realm_commit_event_kinds \
         WHERE realm_id=$1 AND kind NOT IN ({disclosed_kinds},'ak.strand.watch.set') LIMIT 1"
    )
}

/// Whether a RealmCommit of the Realm names an Event that is not committed.
pub(crate) const UNSETTLED_COMMIT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM canonical_events \
     event_row JOIN realm_commits commit_row ON commit_row.event_pk = event_row.pk \
     WHERE event_row.realm_id=$1 AND event_row.state <> 'committed') AS present";

#[derive(QueryableByName)]
struct TableNameRow {
    #[diesel(sql_type = SqlText)]
    tablename: String,
}

#[derive(QueryableByName)]
struct TenureRow {
    #[diesel(sql_type = SqlText)]
    service_id: String,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    generation: i64,
}

#[derive(QueryableByName)]
struct PresenceRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[derive(QueryableByName)]
struct KindRow {
    #[diesel(sql_type = SqlText)]
    kind: String,
}

/// What one cut says about the Realm and the caller beyond its candidate
/// material.
pub(crate) struct DisclosureFacts {
    /// The caller's readable floor on the Realm stream, `None` when the caller
    /// is not a currently joined member or the floor is not provable.
    pub(crate) caller_floor: Option<ReadableFloor>,
    /// An accepted Event whose kind is outside [`DISCLOSED_EVENT_KINDS`].
    pub(crate) undisclosed_kind: Option<String>,
    /// A family without a disclosure rule holds a row of this Realm, or an
    /// Event of this Realm is retention-expired.
    pub(crate) undisclosed_family_row: bool,
}

/// Read the candidate material and the disclosure facts from one MVCC cut.
pub async fn account_snapshot_material(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
) -> PersistenceResult<Option<soland_storage::RealmStateSnapshotMaterial>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        account_snapshot_material_in_connection(conn, realm_id, account)
            .await
            .map_err(Into::into)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// Issue the complete signed Snapshot to `account` at one durable cut. The
/// governing row is share-locked first, so no handoff can commit between the
/// tenure check, the disclosure proof, the signature, and the issuance write.
/// An unchanged cut returns the object already issued to the Account for it.
pub async fn issue_account_snapshot(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    issuer: &arkret_wire::DidCoreId,
    sign: soland_storage::RealmStateSnapshotSigner<'_>,
) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *conn)
            .await?;
        // Issuance and issued-snapshot GC exclude each other (0441).
        crate::sync_cursor::retention::lock(conn, false).await?;
        let Some(tenure) = sql_query(
            "SELECT service_id, generation FROM realm_authorities \
             WHERE realm_id=$1 FOR SHARE",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<TenureRow>(&mut *conn)
        .await
        .optional()?
        else {
            return Ok(None);
        };
        if tenure.service_id != issuer.as_str() {
            return Err(rejected("this Station does not hold the current governing tenure").into());
        }
        let Some(material) =
            account_snapshot_material_in_connection(conn, realm_id, account).await?
        else {
            return Ok(None);
        };
        if i64::try_from(material.governance_generation).ok() != Some(tenure.generation) {
            return Err(rejected("material generation differs from the locked tenure").into());
        }
        let snapshot = sign(&material)?;
        if !soland_storage::signed_snapshot_matches_material(&snapshot, &material) {
            return Err(PersistenceError::Internal(
                "snapshot signer changed the proved disclosure material".to_owned(),
            )
            .into());
        }
        soland_storage::enforce_inline_realm_state_snapshot_capacity(&snapshot)?;
        let issued = crate::issued_realm_snapshots::issue_head_in_connection(
            conn, account, &material, snapshot,
        )
        .await?;
        Ok(Some(issued))
    })
    .await
    .map_err(crate::issued_realm_snapshots::snapshot_transaction_error)
}

#[derive(QueryableByName)]
struct JoinPositionRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    current_stream_position: i64,
}

/// Material for `ak.peer.realm_join.read.bootstrap.v1` (`federation.md`
/// §4.1.1, member Station bootstrap): the member Account's complete
/// disclosure at one cut, with the Realm stream floor at the member's own
/// join Commit -- the prefix evidence the member Station anchors its held
/// stream on. `None` unless `membership_commit_id` is still the member's
/// current joined membership.
pub async fn member_station_bootstrap_material(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    membership_commit_id: &arkret_wire::RealmCommitId,
) -> PersistenceResult<Option<soland_storage::RealmStateSnapshotMaterial>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some(join) = sql_query(
            "SELECT current_stream_position FROM member_state_current_results \
             WHERE realm_id=$1 AND member_id=$2 AND membership='join' AND current_commit_id=$3",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(ActorId::account(account.clone()).to_string())
        .bind::<Text, _>(membership_commit_id.as_str())
        .get_result::<JoinPositionRow>(&mut *conn)
        .await
        .optional()?
        else {
            return Ok(None);
        };
        let Some(mut material) =
            account_snapshot_material_in_connection(conn, realm_id, account).await?
        else {
            return Ok(None);
        };
        let join_position = u64::try_from(join.current_stream_position).map_err(|_| {
            PersistenceError::Internal("stored join position is negative".to_owned())
        })?;
        material.current_state_entries.retain(|row| {
            !matches!(
                row,
                TypedCurrentResult::Value {
                    selector: CurrentSelector::MessageRevision { .. },
                    revision,
                    ..
                } if revision.stream_position < join_position
            )
        });
        material.retention_and_history_floor.stream_floors = vec![StreamHistoryFloor {
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            oldest_position: join_position,
        }];
        Ok(Some(material))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// The Account's disclosed material on the caller's cut.
pub(crate) async fn account_snapshot_material_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    account: &AccountId,
) -> PersistenceResult<Option<soland_storage::RealmStateSnapshotMaterial>> {
    let Some(material) =
        crate::authority_commit::realm_state_snapshot_material_in_connection(conn, realm_id)
            .await?
    else {
        return Ok(None);
    };
    let families = sql_query(
        "SELECT tablename FROM pg_catalog.pg_tables \
         WHERE schemaname=current_schema() AND tablename LIKE '%_current_results'",
    )
    .load::<TableNameRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if families
        .iter()
        .any(|family| !AUDITED_FAMILIES.contains(&family.tablename.as_str()))
    {
        return Err(rejected("an unaudited typed-current family is installed"));
    }
    let facts = disclosure_facts_in_connection(conn, realm_id, account).await?;
    disclose_to_account(material, account, &facts).map(Some)
}

async fn disclosure_facts_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    account: &AccountId,
) -> PersistenceResult<DisclosureFacts> {
    let undisclosed_family_row = sql_query(
        "SELECT (EXISTS(SELECT 1 FROM relation_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM circle_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM circle_member_state_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM sidecar_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM sidecar_context_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM rsvp_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM realm_link_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM mimi_room_binding_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM policy_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM agent_status_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM agent_key_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM key_backup_active_series_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM pcr_device_generation_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM actor_profile_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM identity_accountability_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM agent_provisioning_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM agent_pcr_genesis_declaration_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM agent_selector_claim_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM pcr_device_authorization_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM pcr_device_revocation_proposals WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM direct_conversation_binding_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM consent_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM moderation_report_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM moderation_state_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM retention_tombstones WHERE realm_id=$1)) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<PresenceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present;
    // Both reads are bounded by the Realm's distinct kinds and its unsettled
    // Events, never by its committed history (0436).
    let undisclosed_kind = sql_query(undisclosed_kind_sql())
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<KindRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| row.kind);
    let unsettled_commit = sql_query(UNSETTLED_COMMIT_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<PresenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present;
    if unsettled_commit {
        return Err(PersistenceError::SchemaViolation(
            "snapshot cut includes an uncommitted Event".to_owned(),
        ));
    }
    let caller_floor = crate::account_stream_scan::caller_realm_floor_in_connection(
        conn,
        realm_id,
        &ActorId::account(account.clone()),
    )
    .await?;
    Ok(DisclosureFacts {
        caller_floor,
        undisclosed_kind,
        undisclosed_family_row,
    })
}

fn rejected(reason: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("snapshot disclosure is unproved: {reason}"))
}

/// Decide the Account's complete disclosure of one candidate cut, or refuse
/// it whole. The returned material carries the Account's own readable floor
/// and omits only the `message_revision` rows below it.
pub(crate) fn disclose_to_account(
    mut material: soland_storage::RealmStateSnapshotMaterial,
    account: &AccountId,
    facts: &DisclosureFacts,
) -> PersistenceResult<soland_storage::RealmStateSnapshotMaterial> {
    if facts.undisclosed_family_row {
        return Err(rejected(
            "a current family outside the disclosure subset has a row",
        ));
    }
    if let Some(kind) = &facts.undisclosed_kind {
        return Err(rejected(&format!(
            "accepted Event kind {kind} is outside the disclosure subset"
        )));
    }
    if material.governance_generation != 0 {
        return Err(rejected(
            "a handed-off tenure's imported current families are not proved",
        ));
    }
    let caller = ActorId::account(account.clone());
    let Some(floor) = &facts.caller_floor else {
        return Err(rejected(
            "the Account is not a joined member with a provable readable floor",
        ));
    };
    let realm_stream = CommitStreamRef::Realm {
        realm_id: material.realm_id.clone(),
    };
    let head = match material.visible_stream_heads.as_slice() {
        [head] if head.stream_ref == realm_stream => head.clone(),
        _ => {
            return Err(rejected(
                "Circle and Sidecar stream visibility is not proved at this cut",
            ));
        }
    };
    let mut genesis = false;
    let mut root = false;
    let mut history_access = None;
    let mut own_join = false;
    let mut redacted = std::collections::BTreeSet::new();
    let mut below_floor = std::collections::BTreeSet::new();
    let mut space_families = std::collections::BTreeMap::new();
    let mut position_subjects = Vec::new();
    for row in &material.current_state_entries {
        let TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = row
        else {
            return Err(rejected("a current row is not a closed typed value"));
        };
        if source_stream_ref != &realm_stream
            || revision.stream_position > head.stream_position
            || (revision.stream_position == head.stream_position
                && revision.commit_id != head.commit_id)
        {
            return Err(rejected(
                "a current row is not sourced from the disclosed Realm stream prefix",
            ));
        }
        match selector {
            CurrentSelector::RealmGenesis => genesis = true,
            CurrentSelector::RealmAuthorityRoot => root = true,
            CurrentSelector::RealmHistoryAccess => {
                history_access = Some(
                    serde_json::from_value::<arkret_wire::HistoryAccess>(value.clone())
                        .map_err(PersistenceError::database)?,
                );
            }
            CurrentSelector::MemberState { actor_id } => {
                own_join |=
                    actor_id == &caller && value == &serde_json::json!({"membership":"join"});
            }
            CurrentSelector::StrandWatch { .. } => {
                let _: arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentValue = serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
            }
            CurrentSelector::Strand { .. } => {
                if value
                    .get("scope_circle_id")
                    .is_some_and(|circle| !circle.is_null())
                {
                    return Err(rejected(
                        "a Circle-scoped Strand's visibility is not proved",
                    ));
                }
            }
            CurrentSelector::StrandPosition {
                board_space_id,
                strand_id,
            } => {
                let position: Option<
                    arkret_models_collaboration::objects::strand::StrandPositionCurrent,
                > = serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                position_subjects.push((board_space_id, strand_id, position));
            }
            CurrentSelector::Space { space_id } => {
                let space: arkret_models_collaboration::objects::space::Space =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                if space.id.as_ref() != Some(space_id)
                    || space.realm_id != material.realm_id
                    || space.scope_circle_id.is_some()
                    || space.parent_space_id.is_some()
                    || space.child_scope_policy.is_some()
                {
                    return Err(rejected(
                        "Space metadata is not a Realm-scoped registered value",
                    ));
                }
                *space_families.entry(space_id.clone()).or_insert(0_u8) |= 1;
            }
            CurrentSelector::SpaceParent { space_id } => {
                let parent = value
                    .as_object()
                    .filter(|object| object.len() == 1 && object.contains_key("parent_space_id"))
                    .ok_or_else(|| rejected("Space parent value is not closed"))?;
                if !parent["parent_space_id"].is_null() {
                    serde_json::from_value::<arkret_wire::SpaceId>(
                        parent["parent_space_id"].clone(),
                    )
                    .map_err(PersistenceError::database)?;
                }
                *space_families.entry(space_id.clone()).or_insert(0_u8) |= 2;
            }
            CurrentSelector::SpaceChildScopePolicy { space_id } => {
                serde_json::from_value::<
                    Option<arkret_models_collaboration::objects::space::ChildScopePolicy>,
                >(value.clone())
                .map_err(PersistenceError::database)?;
                *space_families.entry(space_id.clone()).or_insert(0_u8) |= 4;
            }
            CurrentSelector::MessageRevision { message_id } => {
                if revision.stream_position < floor.oldest_position {
                    below_floor.insert(message_id.clone());
                }
            }
            CurrentSelector::RealmProfile
            | CurrentSelector::RealmPolicyBundle
            | CurrentSelector::RealmJoinRule
            | CurrentSelector::RealmDiscovery
            | CurrentSelector::RealmAlias
            | CurrentSelector::RealmPlaintextVisibleServices
            | CurrentSelector::RealmSetDefaultStrand
            | CurrentSelector::InviteLifecycle { .. }
            | CurrentSelector::InviteLiveTarget { .. }
            | CurrentSelector::InviteDirectedInvitee { .. }
            | CurrentSelector::CapabilityGrant { .. } => {}
            CurrentSelector::MlsGroup { scope_ref } => {
                if !matches!(scope_ref, arkret_wire::ScopeRef::Realm { realm_id }
                    if realm_id == &material.realm_id)
                {
                    return Err(rejected(
                        "a Circle or Sidecar MLS group's visibility is not proved",
                    ));
                }
            }
            CurrentSelector::ObjectRedaction { target_ref } => {
                let value = serde_json::from_value::<
                    arkret_models_collaboration::events_payloads::redaction::ObjectRedactionCurrentValue,
                >(value.clone())
                .map_err(PersistenceError::database)?;
                value
                    .validate_for_subject(target_ref)
                    .map_err(PersistenceError::database)?;
                if arkret_wire::MessageId::new(target_ref.as_str()).is_err() {
                    return Err(rejected(
                        "a non-Message redaction subject has no disclosure rule",
                    ));
                }
                redacted.insert(target_ref.clone());
            }
            _ => {
                return Err(rejected(
                    "a current row family has no disclosure rule for this Account",
                ));
            }
        }
    }
    if space_families.values().any(|families| *families != 7) {
        return Err(rejected(
            "a Space omits one of its registered sibling families",
        ));
    }
    for (board_id, strand_id, position) in position_subjects {
        let subject_value = |wanted: CurrentSelector| {
            material
                .current_state_entries
                .iter()
                .find_map(|row| match row {
                    TypedCurrentResult::Value {
                        selector, value, ..
                    } if selector == &wanted => Some(value.clone()),
                    _ => None,
                })
                .ok_or_else(|| rejected("a position subject has no disclosed metadata"))
        };
        let strand: arkret_models_collaboration::objects::strand::Strand =
            serde_json::from_value(subject_value(CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            })?)
            .map_err(PersistenceError::database)?;
        if strand.id.as_ref() != Some(strand_id)
            || strand.realm_id != material.realm_id
            || strand.scope_circle_id.is_some()
        {
            return Err(rejected("position Strand visibility is not proved"));
        }
        let board: arkret_models_collaboration::objects::space::Space =
            serde_json::from_value(subject_value(CurrentSelector::Space {
                space_id: board_id.clone(),
            })?)
            .map_err(PersistenceError::database)?;
        if board.kind != "board" {
            return Err(rejected("position Board subject is not a Board"));
        }
        if let Some(position) = position {
            let list: arkret_models_collaboration::objects::space::Space =
                serde_json::from_value(subject_value(CurrentSelector::Space {
                    space_id: position.list_space_id,
                })?)
                .map_err(PersistenceError::database)?;
            if list.kind != "list" {
                return Err(rejected("position List subject is not a List"));
            }
        }
    }
    let Some(history_access) = history_access else {
        return Err(rejected("the cut has no Realm history-access current"));
    };
    if !genesis || !root || !own_join {
        return Err(rejected(
            "the cut omits the genesis, authority root, or the Account's join",
        ));
    }
    material.current_state_entries.retain(|row| {
        if let TypedCurrentResult::Value {
            selector:
                CurrentSelector::StrandWatch {
                    watcher_actor_id, ..
                },
            value,
            ..
        } = row
        {
            // This snapshot has no audit-read pairing. Only the exact watcher
            // or an explicit non-muted public opt-in may disclose the value.
            return watcher_actor_id == &caller
                || (value.get("level_public") == Some(&serde_json::json!(true))
                    && matches!(
                        value.get("level").and_then(serde_json::Value::as_str),
                        Some("all" | "participating")
                    ));
        }
        !matches!(
            row,
            TypedCurrentResult::Value {
                selector: CurrentSelector::MessageRevision { message_id },
                ..
            } if redacted.contains(message_id.as_str()) || below_floor.contains(message_id)
        )
    });
    material.retention_and_history_floor = arkret_wire::RetentionAndHistoryFloor {
        history_access,
        stream_floors: vec![StreamHistoryFloor {
            stream_ref: realm_stream,
            oldest_position: floor.oldest_position,
        }],
    };
    Ok(material)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        CommitStreamHead, CurrentRevision, DidCoreId, HistoryAccess, MessageId,
        ReadableFloorReason, RealmCommitId, RetentionAndHistoryFloor, StrandId,
    };
    use serde_json::{Value, json};

    use super::*;

    fn account(name: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn event_id(byte: u8) -> arkret_wire::EventId {
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
    }

    fn realm_id() -> RealmId {
        RealmId::from_event_id(&event_id(0x11))
    }

    fn row(selector: CurrentSelector, position: u64, value: Value) -> TypedCurrentResult {
        TypedCurrentResult::Value {
            selector,
            source_stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id(),
            },
            revision: CurrentRevision {
                commit_id: RealmCommitId::from_digest([position as u8 + 1; 32]),
                stream_position: position,
            },
            value,
        }
    }

    #[test]
    fn initial_schema_current_families_are_all_explicitly_classified() {
        let schema = include_str!("../migrations/00000000000000_initial/up.sql");
        for line in schema.lines() {
            let Some(table) = line.strip_prefix("CREATE TABLE ") else {
                continue;
            };
            let table = table
                .split_whitespace()
                .next()
                .unwrap()
                .trim_start_matches("public.");
            if table.ends_with("_current_results") {
                assert!(
                    AUDITED_FAMILIES.contains(&table),
                    "unclassified current family: {table}"
                );
            }
        }
    }

    #[test]
    fn watch_snapshot_filters_private_muted_and_cleared_values_by_complete_actor() {
        for (value, public) in [
            (json!({"level":"all"}), false),
            (json!({"level":"all","level_public":false}), false),
            (json!({"level":"all","level_public":true}), true),
            (json!({"level":"participating","level_public":true}), true),
            (json!({"level":"muted","level_public":true}), false),
            (json!({"level":"mentions_only","level_public":true}), false),
            (serde_json::Value::Null, false),
        ] {
            let (caller, mut material, facts) = fixture();
            let strand = material
                .current_state_entries
                .iter()
                .find_map(|entry| match entry {
                    TypedCurrentResult::Value {
                        selector: CurrentSelector::Strand { strand_id },
                        ..
                    } => Some(strand_id.clone()),
                    _ => None,
                })
                .unwrap();
            let other = ActorId::account(account("bob"));
            material.current_state_entries.push(row(
                CurrentSelector::StrandWatch {
                    strand_id: strand.clone(),
                    watcher_actor_id: other,
                },
                7,
                value.clone(),
            ));
            material.current_state_entries.push(row(
                CurrentSelector::StrandWatch {
                    strand_id: strand,
                    watcher_actor_id: ActorId::account(caller.clone()),
                },
                7,
                value,
            ));
            let disclosed = disclose_to_account(material, &caller, &facts).unwrap();
            let watches = disclosed
                .current_state_entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry,
                        TypedCurrentResult::Value {
                            selector: CurrentSelector::StrandWatch { .. },
                            ..
                        }
                    )
                })
                .count();
            assert_eq!(watches, if public { 2 } else { 1 });
        }
    }

    /// The founder's cut after bootstrap, a default Strand and one message.
    fn fixture() -> (
        AccountId,
        soland_storage::RealmStateSnapshotMaterial,
        DisclosureFacts,
    ) {
        let founder = account("alice");
        let actor = ActorId::account(founder.clone());
        let strand = StrandId::from_event_id(&event_id(0x22));
        let rows = vec![
            row(
                CurrentSelector::RealmGenesis,
                0,
                json!({"purpose":"collaboration"}),
            ),
            row(
                CurrentSelector::RealmAuthorityRoot,
                0,
                json!({"controller_actor_id":actor,"controller_epoch":0,"authority_generation":0}),
            ),
            row(CurrentSelector::RealmProfile, 1, json!({"title":"Example"})),
            row(
                CurrentSelector::RealmPolicyBundle,
                2,
                json!({"policy_revision":1}),
            ),
            row(CurrentSelector::RealmJoinRule, 3, json!("invite")),
            row(CurrentSelector::RealmHistoryAccess, 4, json!("since_join")),
            row(CurrentSelector::RealmDiscovery, 5, json!({"listed":false})),
            row(
                CurrentSelector::MemberState {
                    actor_id: actor.clone(),
                },
                6,
                json!({"membership":"join"}),
            ),
            row(
                CurrentSelector::Strand {
                    strand_id: strand.clone(),
                },
                7,
                json!({ "id": strand }),
            ),
            row(
                CurrentSelector::RealmSetDefaultStrand,
                8,
                json!({ "default_strand_id": strand }),
            ),
            row(
                CurrentSelector::MessageRevision {
                    message_id: MessageId::from_event_id(&event_id(0x33)),
                },
                9,
                json!({ "strand_id": strand }),
            ),
        ];
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm_id(),
        };
        let material = soland_storage::RealmStateSnapshotMaterial {
            realm_id: realm_id(),
            governance_generation: 0,
            visible_stream_heads: vec![CommitStreamHead {
                stream_ref: realm_stream.clone(),
                stream_position: 9,
                commit_id: RealmCommitId::from_digest([10; 32]),
            }],
            current_state_entries: rows,
            retention_and_history_floor: RetentionAndHistoryFloor {
                history_access: HistoryAccess::AllHistoryForCurrentMembers,
                stream_floors: vec![StreamHistoryFloor {
                    stream_ref: realm_stream,
                    oldest_position: 3,
                }],
            },
        };
        let facts = DisclosureFacts {
            caller_floor: Some(ReadableFloor {
                oldest_position: 0,
                floor_commit_id: RealmCommitId::from_digest([1; 32]),
                floor_reason: ReadableFloorReason::StreamStart,
            }),
            undisclosed_kind: None,
            undisclosed_family_row: false,
        };
        (founder, material, facts)
    }

    /// The fixture after Alice invites Bob (10), Bob accepts (11), Alice grants
    /// him `ak.message.create` (12) and Bob posts (13), with Bob's facts: his
    /// `since_join` floor is his accepting Commit.
    fn joined_fixture() -> (
        AccountId,
        soland_storage::RealmStateSnapshotMaterial,
        DisclosureFacts,
    ) {
        let (_, mut material, _) = fixture();
        let alice = ActorId::account(account("alice"));
        let bob_account = account("bob");
        let bob = ActorId::account(bob_account.clone());
        let invite_id = arkret_wire::InviteId::from_event_id(&event_id(0x44));
        let grant_id = arkret_wire::GrantId::from_event_id(&event_id(0x45));
        material.current_state_entries.extend([
            row(
                CurrentSelector::InviteDirectedInvitee {
                    invite_id: invite_id.clone(),
                },
                10,
                json!({ "invitee_account_id": bob_account }),
            ),
            row(
                CurrentSelector::InviteLifecycle {
                    invite_id: invite_id.clone(),
                },
                11,
                json!("accepted"),
            ),
            row(
                CurrentSelector::InviteLiveTarget {
                    invitee_account_id: bob_account.clone(),
                },
                11,
                Value::Null,
            ),
            row(
                CurrentSelector::MemberState { actor_id: bob },
                11,
                json!({"membership":"join"}),
            ),
            row(
                CurrentSelector::CapabilityGrant { grant_id },
                12,
                json!({ "issuer_id": alice }),
            ),
            row(
                CurrentSelector::MessageRevision {
                    message_id: MessageId::from_event_id(&event_id(0x46)),
                },
                13,
                json!({ "strand_id": StrandId::from_event_id(&event_id(0x22)) }),
            ),
        ]);
        material.visible_stream_heads[0].stream_position = 13;
        material.visible_stream_heads[0].commit_id = RealmCommitId::from_digest([14; 32]);
        let facts = DisclosureFacts {
            caller_floor: Some(ReadableFloor {
                oldest_position: 11,
                floor_commit_id: RealmCommitId::from_digest([12; 32]),
                floor_reason: ReadableFloorReason::MembershipJoin,
            }),
            undisclosed_kind: None,
            undisclosed_family_row: false,
        };
        (bob_account, material, facts)
    }

    #[test]
    fn joined_member_receives_state_rows_and_only_messages_from_its_floor() {
        let (bob, material, facts) = joined_fixture();
        let disclosed = disclose_to_account(material.clone(), &bob, &facts).unwrap();
        let mut expected = material.current_state_entries.clone();
        expected.remove(10);
        assert_eq!(disclosed.current_state_entries, expected);
        assert_eq!(
            disclosed.retention_and_history_floor.stream_floors,
            vec![StreamHistoryFloor {
                stream_ref: CommitStreamRef::Realm {
                    realm_id: realm_id()
                },
                oldest_position: 11,
            }]
        );
        // The founder's floor is the genesis Commit: every row, both Messages.
        let (founder, _, founder_facts) = fixture();
        let disclosed = disclose_to_account(material.clone(), &founder, &founder_facts).unwrap();
        assert_eq!(
            disclosed.current_state_entries,
            material.current_state_entries
        );
        // Bob's facts never serve an Account without its own join row.
        assert!(disclose_to_account(material, &account("carol"), &facts).is_err());
    }

    #[test]
    fn sole_founder_receives_every_row_with_the_genesis_floor() {
        let (founder, material, facts) = fixture();
        let disclosed = disclose_to_account(material.clone(), &founder, &facts).unwrap();
        assert_eq!(
            disclosed.current_state_entries,
            material.current_state_entries
        );
        assert_eq!(
            disclosed.retention_and_history_floor,
            RetentionAndHistoryFloor {
                history_access: HistoryAccess::SinceJoin,
                stream_floors: vec![StreamHistoryFloor {
                    stream_ref: CommitStreamRef::Realm {
                        realm_id: realm_id()
                    },
                    oldest_position: 0,
                }],
            }
        );
    }

    #[test]
    fn position_disclosure_requires_visible_board_strand_and_list_subjects() {
        use arkret_models_collaboration::objects::space::Space;
        use arkret_models_collaboration::objects::strand::Strand;
        let (founder, mut material, facts) = fixture();
        let actor = ActorId::account(founder.clone());
        let strand_id = StrandId::from_event_id(&event_id(0x22));
        material.current_state_entries[8] = row(
            CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            },
            7,
            serde_json::to_value(Strand::new(
                strand_id.clone(),
                realm_id(),
                "Card",
                actor.clone(),
            ))
            .unwrap(),
        );
        let board_id = arkret_wire::SpaceId::from_event_id(&event_id(0x66));
        let list_id = arkret_wire::SpaceId::from_event_id(&event_id(0x67));
        for (id, kind) in [(&board_id, "board"), (&list_id, "list")] {
            material.current_state_entries.extend([
                row(
                    CurrentSelector::Space {
                        space_id: id.clone(),
                    },
                    7,
                    serde_json::to_value(Space::new(
                        id.clone(),
                        realm_id(),
                        kind,
                        kind,
                        actor.clone(),
                    ))
                    .unwrap(),
                ),
                row(
                    CurrentSelector::SpaceParent {
                        space_id: id.clone(),
                    },
                    7,
                    json!({"parent_space_id":null}),
                ),
                row(
                    CurrentSelector::SpaceChildScopePolicy {
                        space_id: id.clone(),
                    },
                    7,
                    Value::Null,
                ),
            ]);
        }
        material.current_state_entries.push(row(
            CurrentSelector::StrandPosition {
                board_space_id: board_id.clone(),
                strand_id: strand_id.clone(),
            },
            7,
            json!({"list_space_id":list_id,"rank":"a0"}),
        ));
        assert_eq!(
            disclose_to_account(material.clone(), &founder, &facts)
                .unwrap()
                .current_state_entries,
            material.current_state_entries
        );
        let mut null_position = material.clone();
        if let Some(TypedCurrentResult::Value { value, .. }) =
            null_position.current_state_entries.last_mut()
        {
            *value = Value::Null;
        }
        assert!(disclose_to_account(null_position, &founder, &facts).is_ok());
        for missing in [
            CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            },
            CurrentSelector::Space { space_id: board_id },
            CurrentSelector::Space { space_id: list_id },
        ] {
            let mut incomplete = material.clone();
            incomplete.current_state_entries.retain(|entry| {
                !matches!(entry,
                TypedCurrentResult::Value { selector, .. } if selector == &missing)
            });
            assert!(disclose_to_account(incomplete, &founder, &facts).is_err());
        }
        let mut foreign = material;
        if let TypedCurrentResult::Value { value, .. } = &mut foreign.current_state_entries[8] {
            value["realm_id"] = json!(RealmId::from_event_id(&event_id(0x68)));
        }
        assert!(disclose_to_account(foreign, &founder, &facts).is_err());
    }

    #[test]
    fn realm_space_disclosure_requires_complete_siblings_and_rejects_circle_metadata() {
        use arkret_models_collaboration::objects::space::Space;
        let (founder, mut material, facts) = fixture();
        let space_id = arkret_wire::SpaceId::from_event_id(&event_id(0x66));
        let mut space = Space::new(
            space_id.clone(),
            realm_id(),
            "board",
            "Board",
            ActorId::account(founder.clone()),
        );
        material.current_state_entries.extend([
            row(
                CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                7,
                serde_json::to_value(&space).unwrap(),
            ),
            row(
                CurrentSelector::SpaceParent {
                    space_id: space_id.clone(),
                },
                7,
                json!({"parent_space_id":null}),
            ),
            row(
                CurrentSelector::SpaceChildScopePolicy {
                    space_id: space_id.clone(),
                },
                7,
                Value::Null,
            ),
        ]);
        assert_eq!(
            disclose_to_account(material.clone(), &founder, &facts)
                .unwrap()
                .current_state_entries,
            material.current_state_entries,
        );
        let mut incomplete = material.clone();
        incomplete.current_state_entries.pop();
        assert!(disclose_to_account(incomplete, &founder, &facts).is_err());
        space.scope_circle_id = Some(arkret_wire::CircleId::from_event_id(&event_id(0x77)));
        let index = material.current_state_entries.len() - 3;
        material.current_state_entries[index] = row(
            CurrentSelector::Space { space_id },
            7,
            serde_json::to_value(space).unwrap(),
        );
        assert!(disclose_to_account(material, &founder, &facts).is_err());
    }

    fn redaction_row(target: &str, redacted: &MessageId, position: u64) -> TypedCurrentResult {
        row(
            CurrentSelector::ObjectRedaction {
                target_ref: target.to_owned(),
            },
            position,
            json!({"assertions": [{
                "tag_id": format!("{}:0", event_id(0x77)),
                "value": {"message_id": redacted, "reason": "retracted"}
            }]}),
        )
    }

    #[test]
    fn a_redacted_message_is_disclosed_as_its_redaction_only() {
        let (founder, mut material, facts) = fixture();
        let message = MessageId::from_event_id(&event_id(0x33));
        material.current_state_entries[10] = row(
            CurrentSelector::MessageRevision {
                message_id: message.clone(),
            },
            8,
            json!({"message_id": message, "content": {"kind": "ak.content.text", "body": "x", "format": "plain"}}),
        );
        let redaction = redaction_row(message.as_str(), &message, 9);
        material.current_state_entries.push(redaction.clone());
        let disclosed = disclose_to_account(material.clone(), &founder, &facts).unwrap();
        assert!(
            !disclosed.current_state_entries.iter().any(|entry| matches!(
                entry,
                TypedCurrentResult::Value {
                    selector: CurrentSelector::MessageRevision { .. },
                    ..
                }
            ))
        );
        assert_eq!(disclosed.current_state_entries.last(), Some(&redaction));
        assert_eq!(
            disclosed.current_state_entries.len(),
            material.current_state_entries.len() - 1
        );

        let other = MessageId::from_event_id(&event_id(0x34));
        let (founder, mut foreign, facts) = fixture();
        foreign
            .current_state_entries
            .push(redaction_row(message.as_str(), &other, 9));
        assert!(disclose_to_account(foreign, &founder, &facts).is_err());
        let (founder, mut event_subject, facts) = fixture();
        let event_target = event_id(0x33).to_string();
        event_subject.current_state_entries.push(row(
            CurrentSelector::ObjectRedaction {
                target_ref: event_target.clone(),
            },
            9,
            json!({"assertions": [{
                "tag_id": format!("{}:0", event_id(0x77)),
                "value": {"target_ref": event_target}
            }]}),
        ));
        assert!(disclose_to_account(event_subject, &founder, &facts).is_err());
    }

    #[test]
    fn accounts_without_a_join_or_a_provable_floor_are_refused() {
        let (_, material, facts) = fixture();
        assert!(disclose_to_account(material, &account("mallory"), &facts).is_err());
        let (founder, material, mut facts) = fixture();
        facts.caller_floor = None;
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        let (founder, mut material, facts) = fixture();
        if let TypedCurrentResult::Value { value, .. } = &mut material.current_state_entries[7] {
            *value = json!({"membership":"leave"});
        }
        assert!(disclose_to_account(material, &founder, &facts).is_err());
    }

    #[test]
    fn undisclosed_kinds_families_and_selectors_refuse_the_whole_cut() {
        let (founder, material, mut facts) = fixture();
        facts.undisclosed_kind = Some("ak.moderation.decision".to_owned());
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        let (founder, material, mut facts) = fixture();
        facts.undisclosed_family_row = true;
        let error = disclose_to_account(material, &founder, &facts).unwrap_err();
        assert!(error.to_string().contains("outside the disclosure subset"));
        let (founder, mut material, facts) = fixture();
        material.current_state_entries.push(row(
            CurrentSelector::ModerationReport {
                event_id: event_id(0x44),
            },
            9,
            json!({}),
        ));
        assert!(disclose_to_account(material, &founder, &facts).is_err());
    }

    #[test]
    fn hidden_streams_foreign_sources_and_later_tenures_are_refused() {
        let circle = CommitStreamRef::Circle {
            realm_id: realm_id(),
            circle_id: arkret_wire::CircleId::from_event_id(&event_id(0x55)),
        };
        let (founder, mut material, facts) = fixture();
        material.visible_stream_heads.push(CommitStreamHead {
            stream_ref: circle.clone(),
            stream_position: 0,
            commit_id: RealmCommitId::from_digest([0x66; 32]),
        });
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        let (founder, mut material, facts) = fixture();
        if let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = &mut material.current_state_entries[10]
        {
            *source_stream_ref = circle;
        }
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        let (founder, mut material, facts) = fixture();
        if let TypedCurrentResult::Value { revision, .. } = &mut material.current_state_entries[10]
        {
            revision.stream_position = 10;
        }
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        let (founder, mut material, facts) = fixture();
        material.governance_generation = 1;
        assert!(disclose_to_account(material, &founder, &facts).is_err());
    }

    #[test]
    fn circle_strands_and_missing_anchor_rows_are_refused() {
        let (founder, mut material, facts) = fixture();
        if let TypedCurrentResult::Value { value, .. } = &mut material.current_state_entries[8] {
            value["scope_circle_id"] = json!("ak:circle:x");
        }
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        for missing in [0, 1, 5, 7] {
            let (founder, mut material, facts) = fixture();
            material.current_state_entries.remove(missing);
            assert!(
                disclose_to_account(material, &founder, &facts).is_err(),
                "row {missing}"
            );
        }
    }
}
