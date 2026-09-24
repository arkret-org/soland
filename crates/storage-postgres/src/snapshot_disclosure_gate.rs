//! A deliberately bounded proof that one Account may receive a complete
//! current Snapshot for an ordinary, single-member Realm bootstrap cut.
//!
//! The general snapshot materializer is not caller aware and does not cover
//! every registered current family. This gate admits only the exact producer
//! kinds whose complete result writes it can derive from accepted Events.

use arkret_wire::{
    ActorId, CommitStreamHead, CommitStreamRef, CurrentRevision, CurrentSelector, Event, EventKind,
    RealmCommit, RealmId, TypedCurrentResult,
};
use diesel::sql_types::Text as SqlText;

use super::{
    AsyncConnection, Bool, Jsonb, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    QueryableByName, RunQueryDsl, Text, Value, pg_conn, sql_query,
};

#[derive(QueryableByName)]
struct CommittedRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = SqlText)]
    state: String,
}

#[derive(QueryableByName)]
struct TableNameRow {
    #[diesel(sql_type = SqlText)]
    tablename: String,
}

#[derive(QueryableByName)]
struct PresenceRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        AccountId, Base64UrlString, DetachedObjectSignature, DetachedSignatureAlgorithm,
        DetachedSignatureContext, DidCoreId, DidUrl, Discoverability, GenesisSalt, Hash,
        HistoryAccess, JoinRule, RealmCommitAuthorityRef, RealmCommitId, RetentionAndHistoryFloor,
        ScopeRef, SecurityClass, StreamHistoryFloor, TrustDomainId,
    };
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;

    fn fixture() -> (
        AccountId,
        soland_storage::RealmStateSnapshotMaterial,
        Vec<(RealmCommit, Event)>,
    ) {
        let account = AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let actor = ActorId::account(account.clone());
        let genesis = arkret_models_collaboration::events_payloads::RealmGenesis::new(
            arkret_models_collaboration::events_payloads::RealmPurpose::Collaboration,
            GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            TrustDomainId::new("ak:trust_domain:server.example").unwrap(),
            SecurityClass::Standard,
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            JoinRule::Invite,
            HistoryAccess::SinceJoin,
            Discoverability::Listed,
            None,
            None,
        )
        .unwrap();
        let payloads = [
            (EventKind::RealmCreate, json!({"object":genesis})),
            (EventKind::RealmProfile, json!({"title":"Example"})),
            (EventKind::RealmPolicyBundle, json!({"version":1})),
            (EventKind::RealmJoinRule, json!({"value":"invite"})),
            (EventKind::RealmHistoryAccess, json!({"to":"since_join"})),
            (EventKind::RealmDiscovery, json!({"value":"listed"})),
            (
                EventKind::MemberState,
                json!({"member_id":actor,"membership":"join"}),
            ),
        ];
        let at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let genesis_event = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            actor.clone(),
            payloads[0].1.clone(),
            at,
        )
        .unwrap();
        let realm_id = RealmId::from_event_id(&genesis_event.event_id);
        let stream_ref = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let mut accepted = Vec::new();
        let mut rows = Vec::new();
        for (position, (kind, payload)) in payloads.into_iter().enumerate() {
            let event = if position == 0 {
                genesis_event.clone()
            } else {
                arkret_wire::test_support::raw_event_for_actor_at(
                    kind.as_str(),
                    ScopeRef::Realm {
                        realm_id: realm_id.clone(),
                    },
                    actor.clone(),
                    payload.clone(),
                    at + chrono::Duration::seconds(position as i64),
                )
                .unwrap()
            };
            let commit = RealmCommit {
                commit_id: RealmCommitId::from_digest([position as u8 + 1; 32]),
                realm_id: realm_id.clone(),
                stream_ref: stream_ref.clone(),
                stream_position: position as u64,
                previous_commit_ref: (position > 0)
                    .then(|| RealmCommitId::from_digest([position as u8; 32])),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis_event.event_id.clone(),
                ),
                committed_at: at + chrono::Duration::seconds(position as i64),
                signature: DetachedObjectSignature {
                    context: DetachedSignatureContext::RealmCommit,
                    signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
                    verification_method: DidUrl::new("did:web:station.example#key-1").unwrap(),
                    signed_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
                    created_at: at,
                    sig: Base64UrlString::new("AQ").unwrap(),
                },
            };
            let row = |selector, value| expected_row(selector, value, &stream_ref, &commit);
            match kind {
                EventKind::RealmCreate => {
                    rows.push(row(
                        CurrentSelector::RealmGenesis,
                        payload["object"].clone(),
                    ));
                    rows.push(row(CurrentSelector::RealmAuthorityRoot, json!({
                        "controller_actor_id": actor, "controller_epoch": 0, "authority_generation": 0,
                    })));
                }
                EventKind::RealmProfile => rows.push(row(CurrentSelector::RealmProfile, payload)),
                EventKind::RealmPolicyBundle => {
                    rows.push(row(CurrentSelector::RealmPolicyBundle, payload))
                }
                EventKind::RealmJoinRule => rows.push(row(
                    CurrentSelector::RealmJoinRule,
                    payload["value"].clone(),
                )),
                EventKind::RealmHistoryAccess => rows.push(row(
                    CurrentSelector::RealmHistoryAccess,
                    payload["to"].clone(),
                )),
                EventKind::RealmDiscovery => rows.push(row(
                    CurrentSelector::RealmDiscovery,
                    payload["value"].clone(),
                )),
                EventKind::MemberState => rows.push(row(
                    CurrentSelector::MemberState {
                        actor_id: actor.clone(),
                    },
                    json!({"membership":"join"}),
                )),
                _ => unreachable!(),
            }
            accepted.push((commit, event));
        }
        let material = soland_storage::RealmStateSnapshotMaterial {
            realm_id,
            governance_generation: 0,
            visible_stream_heads: vec![CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 6,
                commit_id: RealmCommitId::from_digest([7; 32]),
            }],
            current_state_entries: rows,
            retention_and_history_floor: RetentionAndHistoryFloor {
                history_access: HistoryAccess::SinceJoin,
                stream_floors: vec![StreamHistoryFloor {
                    stream_ref,
                    oldest_position: 0,
                }],
            },
        };
        (account, material, accepted)
    }

    #[test]
    fn complete_single_member_bootstrap_is_the_only_admitted_cut() {
        let (account, material, accepted) = fixture();
        validate_single_member_bootstrap_cut(&material, &account, &accepted).unwrap();
    }

    #[test]
    fn missing_or_unknown_current_family_rejects_the_entire_cut() {
        let (account, mut material, accepted) = fixture();
        material.current_state_entries.pop();
        assert!(validate_single_member_bootstrap_cut(&material, &account, &accepted).is_err());
        let (account, mut material, accepted) = fixture();
        let extra = material.current_state_entries[0].clone();
        material.current_state_entries.push(extra);
        assert!(validate_single_member_bootstrap_cut(&material, &account, &accepted).is_err());
    }

    #[test]
    fn extra_stream_wrong_actor_and_wrong_source_reject_the_cut() {
        let (account, material, mut accepted) = fixture();
        accepted.push(accepted[6].clone());
        assert!(validate_single_member_bootstrap_cut(&material, &account, &accepted).is_err());
        let (account, material, accepted) = fixture();
        let wrong = AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            account.station_id.clone(),
        );
        assert!(validate_single_member_bootstrap_cut(&material, &wrong, &accepted).is_err());
        let (account, mut material, accepted) = fixture();
        if let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = &mut material.current_state_entries[0]
        {
            *source_stream_ref = CommitStreamRef::Circle {
                realm_id: material.realm_id.clone(),
                circle_id: arkret_wire::CircleId::from_event_id(&accepted[0].1.event_id),
            };
        }
        assert!(validate_single_member_bootstrap_cut(&material, &account, &accepted).is_err());
    }

    #[test]
    fn different_authority_or_scope_cannot_extend_the_founder_chain() {
        let (account, material, mut accepted) = fixture();
        accepted[1].0.authority_ref =
            RealmCommitAuthorityRef::GenesisOrChangeEvent(accepted[1].1.event_id.clone());
        assert!(validate_single_member_bootstrap_cut(&material, &account, &accepted).is_err());
        let (account, material, mut accepted) = fixture();
        accepted[1].1.scope_ref = ScopeRef::RealmGenesis;
        assert!(validate_single_member_bootstrap_cut(&material, &account, &accepted).is_err());
    }
}

/// Read both the candidate material and all permitted accepted Events from
/// one MVCC cut. Ten rows suffice to detect a history larger than the only
/// admitted seven- or nine-Commit shapes.
pub async fn single_member_bootstrap_snapshot_material(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &arkret_wire::AccountId,
) -> PersistenceResult<Option<soland_storage::RealmStateSnapshotMaterial>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some(material) =
            crate::authority_commit::realm_state_snapshot_material_in_connection(conn, realm_id)
                .await?
        else {
            return Ok(None);
        };
        // A new typed-current family could be projected by an admitted Event.
        // Require a fresh schema audit before this closed subset can sign.
        let families = sql_query(
            "SELECT tablename FROM pg_catalog.pg_tables \
             WHERE schemaname=current_schema() AND tablename LIKE '%_current_results'",
        )
        .load::<TableNameRow>(&mut *conn)
        .await?;
        const AUDITED_FAMILIES: &[&str] = &[
            "relation_current_results", "realm_authority_root_current_results",
            "capability_grant_current_results", "realm_policy_bundle_current_results",
            "mimi_room_binding_current_results", "realm_link_current_results",
            "member_state_current_results", "strand_current_results",
            "realm_set_default_strand_current_results", "message_revision_current_results",
            "realm_bootstrap_current_results", "agent_status_current_results",
            "agent_key_current_results", "key_backup_active_series_current_results",
            "pcr_device_generation_current_results", "pcr_device_authorization_current_results",
        ];
        if families.iter().any(|family| !AUDITED_FAMILIES.contains(&family.tablename.as_str())) {
            return Err(rejected("an unaudited typed-current family is installed").into());
        }
        let omitted = sql_query(
            "SELECT (EXISTS(SELECT 1 FROM relation_current_results WHERE realm_id=$1) \
                OR EXISTS(SELECT 1 FROM capability_grant_current_results WHERE realm_id=$1) \
                OR EXISTS(SELECT 1 FROM realm_link_current_results WHERE realm_id=$1) \
                OR EXISTS(SELECT 1 FROM key_backup_active_series_current_results WHERE realm_id=$1) \
                OR EXISTS(SELECT 1 FROM pcr_device_generation_current_results WHERE realm_id=$1) \
                OR EXISTS(SELECT 1 FROM pcr_device_authorization_current_results WHERE realm_id=$1) \
                OR EXISTS(SELECT 1 FROM pcr_device_revocation_proposals WHERE realm_id=$1)) AS present",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<PresenceRow>(&mut *conn)
        .await?;
        if omitted.present {
            return Err(rejected("a current family outside the disclosure subset has a row").into());
        }
        let rows = sql_query(
            "SELECT commit_row.commit_json, event_row.envelope, event_row.state \
             FROM realm_commits commit_row \
             JOIN canonical_events event_row ON event_row.pk=commit_row.event_pk \
             WHERE commit_row.realm_id=$1 \
             ORDER BY commit_row.stream_position, commit_row.commit_id LIMIT 10",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<CommittedRow>(&mut *conn)
        .await?;
        let mut accepted = Vec::with_capacity(rows.len());
        for row in rows {
            if row.state != "committed" {
                return Err(PersistenceError::SchemaViolation(
                    "snapshot cut includes an uncommitted Event".to_owned(),
                )
                .into());
            }
            let commit: RealmCommit =
                serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
            let event: Event =
                serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
            accepted.push((commit, event));
        }
        validate_single_member_bootstrap_cut(&material, account, &accepted)?;
        Ok(Some(material))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

fn rejected(reason: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("snapshot disclosure is unproved: {reason}"))
}

fn payload_value(event: &Event, field: &str) -> PersistenceResult<Value> {
    event
        .payload
        .get(field)
        .cloned()
        .ok_or_else(|| rejected("accepted Event omits its registered result input"))
}

fn expected_row(
    selector: CurrentSelector,
    value: Value,
    stream_ref: &CommitStreamRef,
    commit: &RealmCommit,
) -> TypedCurrentResult {
    TypedCurrentResult::Value {
        selector,
        source_stream_ref: stream_ref.clone(),
        revision: CurrentRevision {
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        value,
    }
}

fn canonical_rows(rows: &[TypedCurrentResult]) -> PersistenceResult<Vec<Vec<u8>>> {
    let mut encoded = rows
        .iter()
        .map(|row| arkret_canonical::canonical_json_bytes(row).map_err(PersistenceError::database))
        .collect::<PersistenceResult<Vec<_>>>()?;
    encoded.sort();
    Ok(encoded)
}

/// Closed subset of the formal reducer registry: the seven-Commit ordinary
/// bootstrap, optionally followed by one StrandCreate/default pair. Optional
/// alias/plaintext-service facets and every unknown kind stay fail closed.
pub(crate) fn validate_single_member_bootstrap_cut(
    material: &soland_storage::RealmStateSnapshotMaterial,
    account: &arkret_wire::AccountId,
    accepted: &[(RealmCommit, Event)],
) -> PersistenceResult<()> {
    let stream_ref = CommitStreamRef::Realm {
        realm_id: material.realm_id.clone(),
    };
    let required = [
        EventKind::RealmCreate,
        EventKind::RealmProfile,
        EventKind::RealmPolicyBundle,
        EventKind::RealmJoinRule,
        EventKind::RealmHistoryAccess,
        EventKind::RealmDiscovery,
        EventKind::MemberState,
    ];
    let allowed_len = accepted.len() == required.len() || accepted.len() == required.len() + 2;
    if !allowed_len || material.governance_generation != 0 {
        return Err(rejected(
            "unsupported governance generation or Event kind count",
        ));
    }
    let actor = ActorId::account(account.clone());
    let genesis_authority =
        arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(accepted[0].1.event_id.clone());
    let mut expected = Vec::new();
    let mut previous = None;
    let mut strand_id = None;
    let mut history_access = None;
    for (index, (commit, event)) in accepted.iter().enumerate() {
        let expected_kind = if index < required.len() {
            &required[index]
        } else if index == required.len() {
            &EventKind::StrandCreate
        } else {
            &EventKind::RealmSetDefaultStrand
        };
        if &event.kind != expected_kind
            || event.actor_id != actor
            || event.realm_id != material.realm_id
            || commit.realm_id != material.realm_id
            || commit.stream_ref != stream_ref
            || commit.stream_position != index as u64
            || commit.previous_commit_ref != previous
            || commit.event_ref != event.event_id
            || commit.governance_generation != 0
            || commit.authority_ref != genesis_authority
            || (index > 0
                && event.scope_ref
                    != arkret_wire::ScopeRef::Realm {
                        realm_id: material.realm_id.clone(),
                    })
        {
            return Err(rejected(
                "accepted Event/Commit history is not the closed single-owner chain",
            ));
        }
        previous = Some(commit.commit_id.clone());
        let row = |selector, value| expected_row(selector, value, &stream_ref, commit);
        match event.kind {
            EventKind::RealmCreate => {
                if material.realm_id != RealmId::from_event_id(&event.event_id)
                    || event.scope_ref != arkret_wire::ScopeRef::RealmGenesis
                {
                    return Err(rejected("genesis Realm identity or scope differs"));
                }
                let value = payload_value(event, "object")?;
                let genesis: arkret_models_collaboration::events_payloads::RealmGenesis =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                genesis.validate().map_err(PersistenceError::database)?;
                if genesis.purpose
                    != arkret_models_collaboration::events_payloads::RealmPurpose::Collaboration
                {
                    return Err(rejected("genesis is not an ordinary collaboration Realm"));
                }
                expected.push(row(CurrentSelector::RealmGenesis, value));
                expected.push(row(
                    CurrentSelector::RealmAuthorityRoot,
                    serde_json::json!({
                        "controller_actor_id": actor,
                        "controller_epoch": 0,
                        "authority_generation": 0,
                    }),
                ));
            }
            EventKind::RealmProfile => expected.push(row(
                CurrentSelector::RealmProfile,
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )),
            EventKind::RealmPolicyBundle => expected.push(row(
                CurrentSelector::RealmPolicyBundle,
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )),
            EventKind::RealmJoinRule => expected.push(row(
                CurrentSelector::RealmJoinRule,
                payload_value(event, "value")?,
            )),
            EventKind::RealmHistoryAccess => {
                let value = payload_value(event, "to")?;
                history_access = Some(
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?,
                );
                expected.push(row(CurrentSelector::RealmHistoryAccess, value));
            }
            EventKind::RealmDiscovery => expected.push(row(
                CurrentSelector::RealmDiscovery,
                payload_value(event, "value")?,
            )),
            EventKind::MemberState => {
                let member: ActorId = serde_json::from_value(payload_value(event, "member_id")?)
                    .map_err(PersistenceError::database)?;
                if member != actor || payload_value(event, "membership")? != "join" {
                    return Err(rejected(
                        "bootstrap membership is not the sole creator join",
                    ));
                }
                expected.push(row(
                    CurrentSelector::MemberState { actor_id: member },
                    serde_json::json!({"membership":"join"}),
                ));
            }
            EventKind::StrandCreate => {
                let payload: arkret_models_collaboration::events_payloads::StrandCreatePayload =
                    serde_json::from_value(
                        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                    )
                    .map_err(PersistenceError::database)?;
                if payload.object.realm_id != material.realm_id
                    || payload.object.created_by != actor
                    || payload.object.id.is_some()
                {
                    return Err(rejected("Strand create cannot be tied to the creator cut"));
                }
                let id = arkret_wire::StrandId::from_event_id(&event.event_id);
                let mut value =
                    serde_json::to_value(payload.object).map_err(PersistenceError::database)?;
                let object = value
                    .as_object_mut()
                    .ok_or_else(|| rejected("Strand value is not an object"))?;
                object.insert(
                    "id".to_owned(),
                    serde_json::to_value(&id).map_err(PersistenceError::database)?,
                );
                object.insert("state".to_owned(), Value::String("active".to_owned()));
                expected.push(row(
                    CurrentSelector::Strand {
                        strand_id: id.clone(),
                    },
                    value,
                ));
                strand_id = Some(id);
            }
            EventKind::RealmSetDefaultStrand => {
                let payload: arkret_models_collaboration::events_payloads::RealmSetDefaultStrandPayload =
                    serde_json::from_value(
                        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                    )
                    .map_err(PersistenceError::database)?;
                if payload.realm_id != material.realm_id
                    || strand_id.as_ref() != Some(&payload.strand_id)
                {
                    return Err(rejected(
                        "default Strand differs from the verified new Strand",
                    ));
                }
                expected.push(row(
                    CurrentSelector::RealmSetDefaultStrand,
                    serde_json::json!({"default_strand_id":payload.strand_id}),
                ));
            }
            _ => return Err(rejected("unregistered Event kind in disclosure subset")),
        }
    }
    let final_commit = &accepted
        .last()
        .ok_or_else(|| rejected("empty Realm history"))?
        .0;
    let expected_head = CommitStreamHead {
        stream_ref: stream_ref.clone(),
        stream_position: final_commit.stream_position,
        commit_id: final_commit.commit_id.clone(),
    };
    if material.visible_stream_heads.as_slice() != [expected_head]
        || material
            .retention_and_history_floor
            .stream_floors
            .as_slice()
            != [arkret_wire::StreamHistoryFloor {
                stream_ref,
                oldest_position: 0,
            }]
        || history_access != Some(material.retention_and_history_floor.history_access)
        || canonical_rows(&material.current_state_entries)? != canonical_rows(&expected)?
    {
        return Err(rejected(
            "snapshot rows, head, floor, or typed reducer values are incomplete",
        ));
    }
    Ok(())
}
