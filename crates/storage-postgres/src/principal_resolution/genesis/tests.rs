use arkret_wire::{ActorId, EventKind, Hash};
use soland_storage::{CurrentPrincipalRead, EventStore, PrincipalResolutionStore};

use super::*;

fn unit() -> (
    IdentityAnchorAccountSlot,
    Vec<CanonicalEventRecord>,
    Vec<arkret_wire::ControlProposalAck>,
) {
    let account = AccountId::new(
        "ak:did_core:web:genesis.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    let time = chrono::DateTime::parse_from_rfc3339("2026-09-10T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let create = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::RealmCreate.as_str(), ScopeRef::RealmGenesis, ActorId::account(account.clone()), 1,
        "000000000001-0000-00000000".parse().unwrap(),
        serde_json::json!({"object":{"purpose":"principal_control","initial_resolution":{"did":"did:web:genesis.example","method_history_head":"accepted-head","version_id":"1"}}}), time
    ).unwrap();
    let mut authorize = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::DeviceAuthorize.as_str(),
        ScopeRef::Realm {
            realm_id: create.realm_id.clone(),
        },
        ActorId::account(account.clone()),
        2,
        "000000000002-0000-00000000".parse().unwrap(),
        serde_json::json!({"authorization_binding_kind":"registration_anchor"}),
        time,
    )
    .unwrap();
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize.event_id = authorize
        .derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let slot = IdentityAnchorAccountSlot {
        account_authority_id: account.station_id.to_string(),
        account_subject: "genesis-account".into(),
        account_id: account,
        realm_id: create.realm_id.to_string(),
        create_event_id: create.event_id.to_string(),
    };
    let records = [create, authorize]
        .into_iter()
        .map(|event| CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.canonical_key().unwrap(),
            actor_seq: event.actor_seq,
            realm_id: Some(event.realm_id.to_string()),
            kind: event.kind.as_str().into(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.into(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(event).unwrap(),
            received_at: time,
        })
        .collect::<Vec<_>>();
    // Exercise the existing storage admission carrier, independently of HTTP
    // producer-proof validation. The current-result assertions require no Seal.
    let acks = records
        .iter()
        .map(|r| {
            let mut member = arkret_wire::ControlProposalAuthorityAck {
                realm_id: slot.realm_id.parse().unwrap(),
                proposal_digest: r.canonical_digest.parse().unwrap(),
                received_at: time,
                decision_due_at: time + chrono::Duration::seconds(30),
                absolute_due_at: time + chrono::Duration::seconds(90),
                authority_set_ref: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
                signature: arkret_wire::PayloadSignature {
                    verification_method: arkret_wire::DidUrl::new("did:web:station.example#key")
                        .unwrap(),
                    payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                    created_at: time,
                    jws: "e30..c2ln".into(),
                },
            };
            member.signature.payload_digest = member.authority_ack_digest().unwrap();
            arkret_wire::ControlProposalAck {
                kind: arkret_wire::ControlProposalAckKind::SignedAck,
                realm_id: member.realm_id.clone(),
                proposal_digest: member.proposal_digest.clone(),
                received_at: time,
                decision_due_at: member.decision_due_at,
                absolute_due_at: member.absolute_due_at,
                defer_count: 0,
                authority_set_ref: member.authority_set_ref.clone(),
                authority_acks: vec![member],
            }
        })
        .collect();
    (slot, records, acks)
}

#[tokio::test]
async fn registration_publishes_current_identity_before_seal_and_replay_cannot_restore_unavailable_state()
 {
    let db = crate::test_database::TestDatabase::lease().await;
    let pool = db.pool();
    let store = crate::PgEventStore { pool: pool.clone() };
    let (slot, records, acks) = unit();
    store
        .put_identity_anchor_batch_atomic(
            records.clone(),
            acks.clone(),
            vec![],
            None,
            None,
            Some(slot.clone()),
            None,
            None,
            vec![],
            vec![],
        )
        .await
        .unwrap();
    assert!(
        matches!(current::read(&pool,&slot.account_id).await.unwrap(),CurrentPrincipalRead::Ready{projection,..} if projection.resolution_event_ref==slot.create_event_id)
    );
    let mut conn = pg_conn(&pool).await.unwrap();
    sql_query("INSERT INTO governance_current_ready(realm_id,ready,revision) VALUES($1,TRUE,1)")
        .bind::<Text, _>(&slot.realm_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(
        matches!(current::read(&pool,&slot.account_id).await.unwrap(),CurrentPrincipalRead::Ready{projection,..} if projection.resolution_event_ref==slot.create_event_id),
        "derived readiness cannot establish or suppress the pre-Seal branch"
    );
    let registry =
        soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry().unwrap();
    super::super::PgPrincipalResolutionStore { pool: pool.clone() }
        .current_principal(&slot.account_id, &registry)
        .await
        .unwrap();
    let absent=sql_query("SELECT NOT EXISTS(SELECT 1 FROM governance_current_ready) AND NOT EXISTS(SELECT 1 FROM state_seals) AS applied").get_result::<AppliedRow>(&mut *conn).await.unwrap();
    assert!(
        absent.applied,
        "identity reads before the first Seal must not fabricate a governance frontier"
    );
    // Rows written by the old pre-Seal refresh bug are derived state rather
    // than an accepted governance frontier and must repair on the next read.
    sql_query("INSERT INTO governance_current_ready(realm_id,ready,revision) VALUES($1,FALSE,1)")
        .bind::<Text, _>(&slot.realm_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(
        matches!(
            super::super::PgPrincipalResolutionStore { pool: pool.clone() }
                .current_principal(&slot.account_id, &registry)
                .await
                .unwrap(),
            CurrentPrincipalRead::Ready { projection, .. }
                if projection.resolution_event_ref == slot.create_event_id
        ),
        "a pre-Seal read must repair the obsolete unavailable marker"
    );
    let absent=sql_query("SELECT NOT EXISTS(SELECT 1 FROM governance_current_ready) AND NOT EXISTS(SELECT 1 FROM state_seals) AS applied").get_result::<AppliedRow>(&mut *conn).await.unwrap();
    assert!(absent.applied);
    // An accepted resolution successor is a canonical pending-current fact,
    // so the pre-Seal genesis exception is closed without consulting caches.
    sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,actor_seq,realm_id,kind,schema_id,canonical_bytes,envelope) VALUES(decode('01'||repeat('11',32),'hex'),1,decode(repeat('11',32),'hex'),$1,99,$2,'ak.identity.resolution.update','fixture','x','{}')")
        .bind::<Text, _>(slot.account_id.canonical_key().unwrap())
        .bind::<Text, _>(&slot.realm_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        current::read(&pool, &slot.account_id).await.unwrap(),
        CurrentPrincipalRead::Unavailable
    );
    store
        .put_identity_anchor_batch_atomic(
            records.clone(),
            acks.clone(),
            vec![],
            None,
            None,
            Some(slot.clone()),
            None,
            None,
            vec![],
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(
        current::read(&pool, &slot.account_id).await.unwrap(),
        CurrentPrincipalRead::Unavailable,
        "exact genesis replay cannot reopen the bootstrap exception after a successor"
    );
    sql_query("DELETE FROM canonical_events WHERE id=decode('01'||repeat('11',32),'hex')")
        .execute(&mut *conn)
        .await
        .unwrap();
    // Once a Seal exists, an unavailable governance current must never fall
    // back to the bootstrap projection.
    sql_query("INSERT INTO state_seals(id,digest_suite,realm_id,seal_id_preimage_bytes,accepted_seal_bytes,seal_json,is_genesis) VALUES('ak:seal:test-genesis','sha256',$1,'x','x','{}',TRUE)")
        .bind::<Text, _>(&slot.realm_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("INSERT INTO governance_current_ready(realm_id,ready,revision) VALUES($1,FALSE,1)")
        .bind::<Text, _>(&slot.realm_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    store
        .put_identity_anchor_batch_atomic(
            records,
            acks,
            vec![],
            None,
            None,
            Some(slot.clone()),
            None,
            None,
            vec![],
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(
        current::read(&pool, &slot.account_id).await.unwrap(),
        CurrentPrincipalRead::Unavailable
    );
    sql_query("DELETE FROM governance_current_ready WHERE realm_id=$1")
        .bind::<Text, _>(&slot.realm_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("UPDATE canonical_events SET state='quarantined' WHERE kind='ak.device.authorize'")
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        current::read(&pool, &slot.account_id).await.unwrap(),
        CurrentPrincipalRead::Unavailable
    );
}

#[tokio::test]
async fn current_identity_survives_index_eviction_but_requires_the_initial_current_head() {
    let db = crate::test_database::TestDatabase::lease().await;
    let pool = db.pool();
    let store = crate::PgEventStore { pool: pool.clone() };
    let (slot, records, acks) = unit();
    store
        .put_identity_anchor_batch_atomic(
            records,
            acks,
            vec![],
            None,
            None,
            Some(slot.clone()),
            None,
            None,
            vec![],
            vec![],
        )
        .await
        .unwrap();

    let registry =
        soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry().unwrap();
    let principal_store = super::super::PgPrincipalResolutionStore { pool: pool.clone() };
    let mut conn = pg_conn(&pool).await.unwrap();
    sql_query("DELETE FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2")
        .bind::<Text, _>(slot.account_id.principal_id.as_str())
        .bind::<Text, _>(slot.account_id.station_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(
        matches!(
            principal_store
                .current_principal(&slot.account_id, &registry)
                .await
                .unwrap(),
            CurrentPrincipalRead::Ready { projection, .. }
                if projection.resolution_event_ref == slot.create_event_id
        ),
        "evicting the replaceable principal index must not affect current identity"
    );

    sql_query("DELETE FROM current_result_heads WHERE realm_id=$1")
        .bind::<Text, _>(&slot.realm_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        principal_store
            .current_principal(&slot.account_id, &registry)
            .await
            .unwrap(),
        CurrentPrincipalRead::Unavailable,
        "the immutable slot and accepted source cannot replace a missing current cell"
    );
}

#[tokio::test]
async fn invalid_genesis_resolution_rolls_back_the_whole_registration_unit() {
    let db = crate::test_database::TestDatabase::lease().await;
    let pool = db.pool();
    let store = crate::PgEventStore { pool: pool.clone() };
    let (mut slot, records, acks) = unit();
    slot.account_id.principal_id = "ak:did_core:web:wrong.example".parse().unwrap();
    assert!(
        store
            .put_identity_anchor_batch_atomic(
                records,
                acks,
                vec![],
                None,
                None,
                Some(slot),
                None,
                None,
                vec![],
                vec![]
            )
            .await
            .is_err()
    );
    let mut conn = pg_conn(&pool).await.unwrap();
    let empty=sql_query("SELECT NOT EXISTS(SELECT 1 FROM canonical_events) AND NOT EXISTS(SELECT 1 FROM identity_anchor_account_slots) AND NOT EXISTS(SELECT 1 FROM principal_resolutions) AND NOT EXISTS(SELECT 1 FROM current_result_heads) AND NOT EXISTS(SELECT 1 FROM state_control_events) AS applied").get_result::<AppliedRow>(&mut *conn).await.unwrap();
    assert!(
        empty.applied,
        "failed resolution initialization must leave no partial registration"
    );
}
