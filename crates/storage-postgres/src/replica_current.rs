//! Typed current a member Station keeps for a Realm stream it holds as a
//! replica of a Realm another Station governs (`federation.md` §4.1.1,
//! member Station bootstrap).
//!
//! The governing Station's verified bootstrap snapshot is installed once,
//! anchored at its head; every later replica then advances the same result
//! families with the registered result each committed Event derives. A
//! member Station never admits: the governing Station's RealmCommit is the
//! accepted judgement, so these writers carry no capability, CAS or
//! lifecycle gate, only the projection of the committed Event.
//!
//! The member Station keeps the families its recipient re-verification and
//! local reads consume: the Realm singletons (history access, plaintext
//! services, profile), the policy bundle, `member_state`, `strand`, the three
//! Space families, the default Strand pointer, `message_revision` and
//! `object_redaction`. The
//! authority root, capability grants, Invite registers and MLS group state
//! are governing admission inputs whose rows hold Station-private material a
//! snapshot row does not carry (the authority Event ref, the accepting
//! Event id, the public RFC 9420 tracker); a member Station keeps none of
//! them and never reads them.

use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{PersistenceError, PersistenceResult};

/// Every table a member Station projects a replica Realm into.
const MEMBER_STATION_FAMILIES: &[&str] = &[
    "space_parent_current_results",
    "space_child_scope_policy_current_results",
    "space_current_results",
    "realm_bootstrap_current_results",
    "realm_policy_bundle_current_results",
    "realm_link_current_results",
    "member_state_current_results",
    "strand_current_results",
    "realm_set_default_strand_current_results",
    "message_revision_current_results",
    "object_redaction_current_results",
];

fn position(value: u64) -> PersistenceResult<i64> {
    i64::try_from(value).map_err(|_| {
        PersistenceError::SchemaViolation("stream position exceeds PostgreSQL BIGINT".to_owned())
    })
}

fn malformed(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("bootstrap snapshot row is malformed: {detail}"))
}

struct Revision<'a> {
    commit_id: &'a str,
    stream_position: i64,
    updated_at: chrono::DateTime<chrono::Utc>,
}

async fn upsert_singleton(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    family: &str,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    diesel::sql_query(
        "INSERT INTO realm_bootstrap_current_results \
         (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id,result_family) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(family)
    .bind::<Text, _>(revision.commit_id)
    .bind::<BigInt, _>(revision.stream_position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(revision.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

/// Upsert one row of a family keyed by `(realm_id)` or `(realm_id, key)`.
async fn upsert_keyed(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    table: &'static str,
    key: Option<(&'static str, &str)>,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    let sql = match key {
        Some((column, _)) => format!(
            "INSERT INTO {table} \
             (realm_id,{column},current_commit_id,current_stream_position,value,updated_at) \
             VALUES($1,$6,$2,$3,$4,$5) ON CONFLICT({conflict}) DO UPDATE SET \
             current_commit_id=EXCLUDED.current_commit_id, \
             current_stream_position=EXCLUDED.current_stream_position, \
             value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
            conflict = match table {
                "strand_current_results" => "strand_id",
                "space_current_results"
                | "space_parent_current_results"
                | "space_child_scope_policy_current_results" => "space_id",
                "message_revision_current_results" => "message_id",
                _ => "realm_id,target_ref",
            },
        ),
        None => format!(
            "INSERT INTO {table} \
             (realm_id,current_commit_id,current_stream_position,value,updated_at) \
             VALUES($1,$2,$3,$4,$5) ON CONFLICT(realm_id) DO UPDATE SET \
             current_commit_id=EXCLUDED.current_commit_id, \
             current_stream_position=EXCLUDED.current_stream_position, \
             value=EXCLUDED.value,updated_at=EXCLUDED.updated_at"
        ),
    };
    let query = diesel::sql_query(sql)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(revision.commit_id)
        .bind::<BigInt, _>(revision.stream_position)
        .bind::<Jsonb, _>(value)
        .bind::<Timestamptz, _>(revision.updated_at);
    match key {
        Some((_, key)) => query.bind::<Text, _>(key).execute(conn).await,
        None => query.execute(conn).await,
    }
    .map_err(PersistenceError::database)?;
    Ok(())
}

async fn upsert_member_state(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    let membership = value
        .get("membership")
        .and_then(Value::as_str)
        .filter(|membership| matches!(*membership, "join" | "knock" | "leave" | "ban"))
        .ok_or_else(|| malformed("member_state has no closed membership"))?;
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,member_id) DO UPDATE SET \
         membership=EXCLUDED.membership,current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .bind::<Text, _>(membership)
    .bind::<Text, _>(revision.commit_id)
    .bind::<BigInt, _>(revision.stream_position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(revision.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

/// Replace the member Station's typed current of `realm_id` with a verified
/// bootstrap snapshot's rows. Every row must come from the Realm stream at or
/// below `head`; a family this module does not keep is left out, and a
/// selector outside the bootstrap disclosure subset refuses the install.
pub(crate) async fn install_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    head: &arkret_wire::CommitStreamHead,
    entries: &[arkret_wire::TypedCurrentResult],
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    for table in MEMBER_STATION_FAMILIES {
        diesel::sql_query(format!("DELETE FROM {table} WHERE realm_id=$1"))
            .bind::<Text, _>(realm_id.as_str())
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    for entry in entries {
        let arkret_wire::TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = entry
        else {
            return Err(malformed("a row is not a closed typed value"));
        };
        if source_stream_ref != &realm_stream
            || revision.stream_position > head.stream_position
            || (revision.stream_position == head.stream_position
                && revision.commit_id != head.commit_id)
        {
            return Err(malformed(
                "a row is not sourced from the snapshot's Realm stream prefix",
            ));
        }
        let commit_id = revision.commit_id.to_string();
        let row = Revision {
            commit_id: &commit_id,
            stream_position: position(revision.stream_position)?,
            updated_at: installed_at,
        };
        use arkret_wire::CurrentSelector as S;
        let singleton = match selector {
            S::RealmGenesis => Some("realm_genesis"),
            S::RealmProfile => Some("realm_profile"),
            S::RealmJoinRule => Some("realm_join_rule"),
            S::RealmHistoryAccess => Some("realm_history_access"),
            S::RealmDiscovery => Some("realm_discovery"),
            S::RealmAlias => Some("realm_alias"),
            S::RealmPlaintextVisibleServices => Some("realm_plaintext_visible_services"),
            _ => None,
        };
        if let Some(family) = singleton {
            upsert_singleton(conn, realm_id, family, &row, value).await?;
            continue;
        }
        match selector {
            S::RealmPolicyBundle => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "realm_policy_bundle_current_results",
                    None,
                    &row,
                    value,
                )
                .await?;
            }
            S::MemberState { actor_id } => {
                upsert_member_state(conn, realm_id, actor_id, &row, value).await?;
            }
            S::Strand { strand_id } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "strand_current_results",
                    Some(("strand_id", strand_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::Space { space_id }
            | S::SpaceParent { space_id }
            | S::SpaceChildScopePolicy { space_id } => {
                let table = match selector {
                    S::Space { .. } => "space_current_results",
                    S::SpaceParent { .. } => "space_parent_current_results",
                    S::SpaceChildScopePolicy { .. } => "space_child_scope_policy_current_results",
                    _ => unreachable!(),
                };
                upsert_keyed(
                    conn,
                    realm_id,
                    table,
                    Some(("space_id", space_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::RealmSetDefaultStrand => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "realm_set_default_strand_current_results",
                    None,
                    &row,
                    value,
                )
                .await?;
            }
            S::MessageRevision { message_id } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "message_revision_current_results",
                    Some(("message_id", message_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::ObjectRedaction { target_ref } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "object_redaction_current_results",
                    Some(("target_ref", target_ref.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            // Governing admission inputs a member Station never keeps.
            S::RealmAuthorityRoot
            | S::CapabilityGrant { .. }
            | S::InviteLifecycle { .. }
            | S::InviteLiveTarget { .. }
            | S::InviteDirectedInvitee { .. }
            | S::MlsGroup { .. } => {}
            _ => {
                return Err(malformed(
                    "a row family is outside the member bootstrap disclosure subset",
                ));
            }
        }
    }
    Ok(())
}

/// Advance the member Station's typed current with one committed replica
/// that directly follows its anchored held head.
pub(crate) async fn advance_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let commit_id = commit.commit_id.to_string();
    let row = Revision {
        commit_id: &commit_id,
        stream_position: position(commit.stream_position)?,
        updated_at: commit.committed_at,
    };
    let payload = || serde_json::to_value(&event.payload).map_err(PersistenceError::database);
    match event.kind {
        arkret_wire::EventKind::MemberState
        | arkret_wire::EventKind::InviteAccept
        | arkret_wire::EventKind::RealmPolicyBundle
        | arkret_wire::EventKind::RealmLink => {
            crate::unit_of_work::commit_parent_membership_current_results(conn, event, commit)
                .await?;
        }
        arkret_wire::EventKind::StrandCreate => {
            let (strand_id, value) =
                crate::strand_current_results::strand_create_current_value(event)?;
            upsert_keyed(
                conn,
                &event.realm_id,
                "strand_current_results",
                Some(("strand_id", strand_id.as_str())),
                &row,
                &value,
            )
            .await?;
        }
        arkret_wire::EventKind::StrandUpdate => {
            // Only the already verified, immediately following RealmCommit
            // reaches this fold. Use the same typed update as the authority;
            // skipping it would leave subsequent CAS guards on a stale value.
            crate::strand_current_results::commit_strand_update_current_result_in_connection(
                conn, event, commit,
            )
            .await?;
        }
        arkret_wire::EventKind::SpaceCreate => {
            let values = crate::space_current_results::space_create_current_values(event)?;
            for (table, value) in [
                ("space_current_results", &values.space),
                ("space_parent_current_results", &values.parent),
                (
                    "space_child_scope_policy_current_results",
                    &values.child_scope_policy,
                ),
            ] {
                upsert_keyed(
                    conn,
                    &event.realm_id,
                    table,
                    Some(("space_id", values.space_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
        }
        arkret_wire::EventKind::RealmSetDefaultStrand => {
            let payload: arkret_models_collaboration::events_payloads::strand::RealmSetDefaultStrandPayload =
                serde_json::from_value(payload()?)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            upsert_keyed(
                conn,
                &event.realm_id,
                "realm_set_default_strand_current_results",
                None,
                &row,
                &serde_json::json!({ "default_strand_id": payload.strand_id }),
            )
            .await?;
        }
        arkret_wire::EventKind::MessageCreate => {
            let message_id = arkret_wire::MessageId::from_event_id(&event.event_id);
            upsert_keyed(
                conn,
                &event.realm_id,
                "message_revision_current_results",
                Some(("message_id", message_id.as_str())),
                &row,
                &payload()?,
            )
            .await?;
        }
        arkret_wire::EventKind::MessageRevise => {
            let payload = payload()?;
            let message_id = payload
                .get("message_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PersistenceError::SchemaViolation("Message revise names no Message".to_owned())
                })?
                .to_owned();
            upsert_keyed(
                conn,
                &event.realm_id,
                "message_revision_current_results",
                Some(("message_id", &message_id)),
                &row,
                &payload,
            )
            .await?;
        }
        arkret_wire::EventKind::MessageRedact => {
            let payload: arkret_models_collaboration::events_payloads::message::MessageRedactPayload =
                serde_json::from_value(payload()?)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let message_id = payload.message_id.clone();
            let value = crate::object_redaction_current_results::message_redaction_current_value(
                event, payload,
            )?;
            upsert_keyed(
                conn,
                &event.realm_id,
                "object_redaction_current_results",
                Some(("target_ref", message_id.as_str())),
                &row,
                &serde_json::to_value(&value).map_err(PersistenceError::database)?,
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    use serde_json::json;

    use super::*;
    use crate::test_database::TestDatabase;

    #[derive(diesel::QueryableByName)]
    struct ValueRow {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }

    #[tokio::test]
    async fn space_families_snapshot_install_keeps_registered_values() {
        let database = TestDatabase::lease().await;
        let realm_id =
            arkret_wire::RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let space_id =
            arkret_wire::SpaceId::new("ak:space:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let commit_id = arkret_wire::RealmCommitId::from_digest([7u8; 32]);
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: commit_id.clone(),
        };
        let revision = arkret_wire::CurrentRevision {
            commit_id,
            stream_position: 7,
        };
        let metadata = json!({
            "id":space_id,
            "realm_id":realm_id,
            "schema":"ak.schema.space.v1",
            "kind":"board",
            "title":"Replica board",
            "state":"active"
        });
        let parent = json!({"parent_space_id":null});
        let policy = Value::Null;
        let entry = |selector, value| arkret_wire::TypedCurrentResult::Value {
            selector,
            source_stream_ref: stream.clone(),
            revision: revision.clone(),
            value,
        };
        // Deliberately put the sibling families before Space metadata. The
        // deferred FK must be satisfied by the complete snapshot transaction.
        let entries = vec![
            entry(
                arkret_wire::CurrentSelector::SpaceParent {
                    space_id: space_id.clone(),
                },
                parent.clone(),
            ),
            entry(
                arkret_wire::CurrentSelector::SpaceChildScopePolicy {
                    space_id: space_id.clone(),
                },
                policy.clone(),
            ),
            entry(
                arkret_wire::CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                metadata.clone(),
            ),
        ];
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        for _ in 0..2 {
            diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
            install_snapshot_in_connection(
                &mut conn,
                &realm_id,
                &head,
                &entries,
                chrono::Utc::now(),
            )
            .await
            .unwrap();
            diesel::sql_query("COMMIT")
                .execute(&mut conn)
                .await
                .unwrap();
        }
        for (table, expected) in [
            ("space_current_results", metadata),
            ("space_parent_current_results", parent),
            ("space_child_scope_policy_current_results", policy),
        ] {
            let row: ValueRow = diesel::sql_query(format!(
                "SELECT value FROM {table} WHERE realm_id=$1 AND space_id=$2"
            ))
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(space_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
            assert_eq!(row.value, expected);
        }

        let at =
            chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
        let author = arkret_wire::DidCoreId::new("ak:did_core:web:replica-author.example").unwrap();
        let station =
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-station.example").unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(author, station));
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.space.create",
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor.clone(),
            json!({"object":{
                "schema":"ak.schema.space.v1",
                "realm_id":realm_id,
                "parent_space_id":space_id,
                "kind":"list",
                "title":"Replicated list",
                "created_by":actor,
                "created_at":at
            }}),
            at,
        )
        .unwrap();
        let digest = arkret_wire::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.producer_proof = Some(arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new("did:web:replica-author.example#key")
                .unwrap(),
            event_digest: digest.clone(),
            created_at: arkret_canonical::normalize_timestamp_canonical(at),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
        });
        let next_id = arkret_wire::SpaceId::from_event_id(&event.event_id);
        let next_commit = arkret_wire::RealmCommit {
            commit_id: arkret_wire::RealmCommitId::from_digest([8u8; 32]),
            realm_id: realm_id.clone(),
            stream_ref: stream,
            stream_position: 8,
            previous_commit_ref: Some(head.commit_id),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.event_id.clone(),
            ),
            committed_at: at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:replica-station.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: at,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
            },
        };
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        advance_in_connection(&mut conn, &event, &next_commit)
            .await
            .unwrap();
        diesel::sql_query("COMMIT")
            .execute(&mut conn)
            .await
            .unwrap();
        let next_parent: ValueRow =
            diesel::sql_query("SELECT value FROM space_parent_current_results WHERE space_id=$1")
                .bind::<Text, _>(next_id.as_str())
                .get_result(&mut conn)
                .await
                .unwrap();
        assert_eq!(next_parent.value, json!({"parent_space_id":space_id}));
        let next_policy: ValueRow = diesel::sql_query(
            "SELECT value FROM space_child_scope_policy_current_results WHERE space_id=$1",
        )
        .bind::<Text, _>(next_id.as_str())
        .get_result(&mut conn)
        .await
        .unwrap();
        assert_eq!(next_policy.value, Value::Null);
    }

    #[tokio::test]
    async fn strand_update_replica_advances_current_and_preserves_stale_cas_rejection() {
        use arkret_models_collaboration::objects::strand::Strand;
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let realm_id =
            arkret_wire::RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let strand_id =
            arkret_wire::StrandId::new("ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-author.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-station.example").unwrap(),
        ));
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let mut strand = Strand::new(strand_id.clone(), realm_id.clone(), "Before", actor.clone());
        strand.created_at = at;
        let before = serde_json::to_value(strand).unwrap();
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
        };
        let entries = [arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            },
            source_stream_ref: stream.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: 7,
            },
            value: before.clone(),
        }];
        install_snapshot_in_connection(&mut conn, &realm_id, &head, &entries, at)
            .await
            .unwrap();
        let expected = arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&before).unwrap(),
        );
        for (position, title, accepted) in [(8, "After", true), (9, "Stale", false)] {
            let mut event = arkret_wire::test_support::raw_event_for_actor_at(
                arkret_wire::EventKind::StrandUpdate.as_str(),
                arkret_wire::ScopeRef::Realm { realm_id: realm_id.clone() }, actor.clone(),
                json!({"target_ref":strand_id,"expected_state_digest":expected,"patch":{"metadata.title":{"$op":"set","value":title}}}), at,
            ).unwrap();
            let digest = arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap();
            // This fold is tested after the replica verifier boundary. The
            // SDK structural proof fixture is not accepted as a live signer.
            event.producer_proof = Some(arkret_wire::ProducerEventProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new("did:web:replica-author.example#key")
                    .unwrap(),
                event_digest: digest.clone(),
                created_at: at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
            });
            let commit = arkret_wire::RealmCommit {
                commit_id: arkret_wire::RealmCommitId::from_digest([position as u8; 32]),
                realm_id: realm_id.clone(),
                stream_ref: stream.clone(),
                stream_position: position,
                previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest(
                    [(position - 1) as u8; 32],
                )),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    event.event_id.clone(),
                ),
                committed_at: at,
                signature: arkret_wire::DetachedObjectSignature {
                    context: arkret_wire::DetachedSignatureContext::RealmCommit,
                    signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: arkret_wire::DidUrl::new(
                        "did:web:replica-station.example#authority",
                    )
                    .unwrap(),
                    signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                        .unwrap(),
                    created_at: at,
                    sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
                },
            };
            diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
            let result = advance_in_connection(&mut conn, &event, &commit).await;
            assert_eq!(result.is_ok(), accepted, "{result:?}");
            diesel::sql_query(if accepted { "COMMIT" } else { "ROLLBACK" })
                .execute(&mut conn)
                .await
                .unwrap();
            let row: ValueRow =
                diesel::sql_query("SELECT value FROM strand_current_results WHERE strand_id=$1")
                    .bind::<Text, _>(strand_id.as_str())
                    .get_result(&mut conn)
                    .await
                    .unwrap();
            assert_eq!(row.value["metadata"]["title"], "After");
        }
    }
}
