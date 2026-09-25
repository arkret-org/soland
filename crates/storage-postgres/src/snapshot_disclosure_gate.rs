//! Caller-aware Realm State Snapshot disclosure
//! (`realm-state-snapshot-schema.md` §3, `current-results.md` §1 and §3).
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
//! - the Realm has only its Realm stream (Circle and Sidecar visibility is not proved here) and is
//!   in its genesis tenure (a planned handoff import of current families is not proved here);
//! - the Account is the Realm's founder and its only member, currently joined. The founding join is
//!   admitted in the same atomic bootstrap unit as the genesis Commit, so the founder's readable
//!   interval starts at the genesis Commit (`stream_start`), exactly as the Account stream scan
//!   serves it. Every row of the cut is then within that interval.

use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CurrentSelector, Event, EventKind, RealmId,
    StreamHistoryFloor, TypedCurrentResult,
};
use diesel::sql_types::Text as SqlText;

use super::{
    AsyncConnection, AsyncPgConnection, Bool, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, Value,
    pg_conn, sql_query,
};

/// Event kinds whose admission writes only disclosed current families. Any
/// other accepted kind refuses the cut rather than risk an omitted result.
const DISCLOSED_EVENT_KINDS: &[EventKind] = &[
    EventKind::RealmCreate,
    EventKind::RealmProfile,
    EventKind::RealmPolicyBundle,
    EventKind::RealmJoinRule,
    EventKind::RealmHistoryAccess,
    EventKind::RealmDiscovery,
    EventKind::RealmAlias,
    EventKind::RealmPlaintextVisibleServices,
    EventKind::MemberState,
    EventKind::StrandCreate,
    EventKind::RealmSetDefaultStrand,
    EventKind::MessageCreate,
];

/// Every typed-current table this Station installs. A new family could be
/// written by an admitted Event, so it must be classified here before any
/// Snapshot is signed again.
const AUDITED_FAMILIES: &[&str] = &[
    "relation_current_results",
    "realm_authority_root_current_results",
    "capability_grant_current_results",
    "realm_policy_bundle_current_results",
    "mimi_room_binding_current_results",
    "realm_link_current_results",
    "member_state_current_results",
    "strand_current_results",
    "realm_set_default_strand_current_results",
    "message_revision_current_results",
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
];

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
    #[diesel(sql_type = SqlText)]
    state: String,
}

#[derive(QueryableByName)]
struct EnvelopeRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(QueryableByName)]
struct MemberRow {
    #[diesel(sql_type = SqlText)]
    member_id: String,
    #[diesel(sql_type = SqlText)]
    membership: String,
}

/// What one cut says about the Realm beyond its candidate material.
pub(crate) struct DisclosureFacts {
    /// Actor of the accepted genesis Event at Realm stream position 0.
    pub(crate) founder: ActorId,
    /// Current member-state rows, `(member, membership)`.
    pub(crate) members: Vec<(ActorId, String)>,
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
    let facts = disclosure_facts_in_connection(conn, realm_id).await?;
    disclose_to_account(material, account, &facts).map(Some)
}

async fn disclosure_facts_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<DisclosureFacts> {
    let undisclosed_family_row = sql_query(
        "SELECT (EXISTS(SELECT 1 FROM relation_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM capability_grant_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM realm_link_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM mimi_room_binding_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM agent_status_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM agent_key_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM key_backup_active_series_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM pcr_device_generation_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM pcr_device_authorization_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM pcr_device_revocation_proposals WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM moderation_report_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM moderation_state_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM retention_tombstones WHERE realm_id=$1)) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<PresenceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present;
    let disclosed_kinds = DISCLOSED_EVENT_KINDS
        .iter()
        .map(|kind| format!("'{}'", kind.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    let undisclosed_kind = sql_query(format!(
        "SELECT event_row.kind, event_row.state FROM realm_commits commit_row \
         JOIN canonical_events event_row ON event_row.pk=commit_row.event_pk \
         WHERE commit_row.realm_id=$1 \
           AND (event_row.kind NOT IN ({disclosed_kinds}) OR event_row.state <> 'committed') \
         LIMIT 1"
    ))
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<KindRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let undisclosed_kind = match undisclosed_kind {
        Some(row) if row.state != "committed" => {
            return Err(PersistenceError::SchemaViolation(
                "snapshot cut includes an uncommitted Event".to_owned(),
            ));
        }
        other => other.map(|row| row.kind),
    };
    let realm_stream = crate::authority_commit::stream_key(&CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    })?;
    let genesis = sql_query(
        "SELECT event_row.envelope FROM realm_commits commit_row \
         JOIN canonical_events event_row ON event_row.pk=commit_row.event_pk \
         WHERE commit_row.realm_id=$1 AND commit_row.stream_key=$2 \
           AND commit_row.stream_position=0",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&realm_stream)
    .get_result::<EnvelopeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| rejected("the Realm stream has no accepted genesis Commit"))?;
    let genesis: Event =
        serde_json::from_value(genesis.envelope).map_err(PersistenceError::database)?;
    if genesis.kind != EventKind::RealmCreate
        || &RealmId::from_event_id(&genesis.event_id) != realm_id
    {
        return Err(rejected(
            "the Realm stream genesis is not this Realm's create Event",
        ));
    }
    // Two rows decide sole membership without loading the whole roster.
    let members = sql_query(
        "SELECT member_id, membership FROM member_state_current_results \
         WHERE realm_id=$1 ORDER BY member_id LIMIT 2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<MemberRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .into_iter()
    .map(|row| {
        let member = serde_json::from_str::<ActorId>(&row.member_id).map_err(|error| {
            PersistenceError::Internal(format!("stored member ActorId is invalid: {error}"))
        })?;
        Ok((member, row.membership))
    })
    .collect::<PersistenceResult<Vec<_>>>()?;
    Ok(DisclosureFacts {
        founder: genesis.actor_id,
        members,
        undisclosed_kind,
        undisclosed_family_row,
    })
}

fn rejected(reason: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("snapshot disclosure is unproved: {reason}"))
}

/// Decide the Account's complete disclosure of one candidate cut, or refuse
/// it whole. The returned material carries the Account's own readable floor.
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
    if facts.founder != caller || facts.members.as_slice() != [(caller.clone(), "join".to_owned())]
    {
        return Err(rejected(
            "the Account is not the Realm's sole, joined founding member",
        ));
    }
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
            CurrentSelector::RealmProfile
            | CurrentSelector::RealmPolicyBundle
            | CurrentSelector::RealmJoinRule
            | CurrentSelector::RealmDiscovery
            | CurrentSelector::RealmAlias
            | CurrentSelector::RealmPlaintextVisibleServices
            | CurrentSelector::RealmSetDefaultStrand
            | CurrentSelector::MessageRevision { .. } => {}
            _ => {
                return Err(rejected(
                    "a current row family has no disclosure rule for this Account",
                ));
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
    material.retention_and_history_floor = arkret_wire::RetentionAndHistoryFloor {
        history_access,
        stream_floors: vec![StreamHistoryFloor {
            stream_ref: realm_stream,
            oldest_position: 0,
        }],
    };
    Ok(material)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        CommitStreamHead, CurrentRevision, DidCoreId, HistoryAccess, MessageId, RealmCommitId,
        RetentionAndHistoryFloor, StrandId,
    };
    use serde_json::json;

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
            founder: actor.clone(),
            members: vec![(actor, "join".to_owned())],
            undisclosed_kind: None,
            undisclosed_family_row: false,
        };
        (founder, material, facts)
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
    fn other_accounts_and_shared_rosters_are_refused() {
        let (_, material, facts) = fixture();
        assert!(disclose_to_account(material, &account("mallory"), &facts).is_err());
        let (founder, material, mut facts) = fixture();
        facts
            .members
            .push((ActorId::account(account("bob")), "join".to_owned()));
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        let (founder, material, mut facts) = fixture();
        facts.members[0].1 = "leave".to_owned();
        assert!(disclose_to_account(material, &founder, &facts).is_err());
    }

    #[test]
    fn undisclosed_kinds_families_and_selectors_refuse_the_whole_cut() {
        let (founder, material, mut facts) = fixture();
        facts.undisclosed_kind = Some("ak.capability.grant".to_owned());
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
