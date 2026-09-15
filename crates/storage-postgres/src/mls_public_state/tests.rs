use arkret_canonical::DigestSuite;
use arkret_wire::{AccountId, ActorId, ScopeRef};
use diesel_async::AsyncConnection;
use serde_json::json;

use super::*;

fn genesis() -> EventCommitRequest {
    genesis_with_group().0
}

fn genesis_with_group() -> (EventCommitRequest, arkret_mls::ArkretMlsGroup) {
    let realm: arkret_wire::RealmId = "ak:realm:AdHF2JK9DIDVy_g03wqifslF_vA_Yuy3_0aWvazcsO_b"
        .parse()
        .unwrap();
    let principal: arkret_wire::DidCoreId = "ak:did_core:web:genesis.example".parse().unwrap();
    let device: arkret_wire::DeviceId = "ak:device:01904100-0000-7000-8000-00000000abcd"
        .parse()
        .unwrap();
    let identity =
        arkret_mls::ArkretMlsIdentity::new_test_human_device(principal, device.clone()).unwrap();
    let actor = ActorId::account(AccountId::new(
        "ak:did_core:web:genesis.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    let group_id = arkret_canonical::base64url_encode(realm.as_str().as_bytes());
    let binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        realm.clone(),
        0,
        0,
        format!("sha256:{}", "1".repeat(64)).parse().unwrap(),
        arkret_wire::ContentScheme::MlsRfc9420,
        None,
        arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        arkret_wire::CORE_REDUCER_PROFILE,
    )
    .unwrap();
    let group = identity
        .create_group_with_governance_binding(realm.as_str().as_bytes(), &binding)
        .unwrap();
    let (group_info_bytes, ratchet_tree_bytes) = group.public_group_state_bytes().unwrap();
    let leaf = arkret_mls::validate_public_group_state(
        &group_info_bytes,
        &ratchet_tree_bytes,
        &group_id,
        0,
    )
    .unwrap()
    .remove(0);
    let key: [u8; 32] = arkret_canonical::base64url_decode(leaf.signature_key.as_str())
        .unwrap()
        .try_into()
        .unwrap();
    let producer_signing_key = arkret_wire::DidKey::new(format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key)
    ))
    .unwrap();
    let timestamp = chrono::DateTime::parse_from_rfc3339("2026-09-10T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.mls.genesis", ScopeRef::Realm{realm_id:realm.clone()}, actor.clone(), 1,
        "000000000001-0000-00000000".parse().unwrap(), json!({
            "cipher_suite":arkret_mls::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID,
            "group_info_ref":format!("ak:blob:{}",arkret_canonical::canonical::sha256_digest(&group_info_bytes)),
            "ratchet_tree_ref":format!("ak:blob:{}",arkret_canonical::canonical::sha256_digest(&ratchet_tree_bytes)),
            "governance_binding":binding,"created_at":"2026-09-10T00:00:00.000Z"
        }),timestamp,
    ).unwrap();
    let request = EventCommitRequest {
        publication_event: None,
        mls_public_producer: None,
        mls_public_genesis: Some(soland_storage::MlsPublicGenesisInput {
            group_info_bytes,
            ratchet_tree_bytes,
            producer_signing_key,
            producer_device_id: Some(device),
        }),
        mls_frontier_leaves: None,
        replicated: false,
        event: soland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: actor.canonical_key().unwrap(),
            actor_seq: 1,
            realm_id: Some(realm.to_string()),
            kind: event.kind.as_str().to_owned(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite: DigestSuite::Sha256,
            canonical_digest: event
                .event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(event).unwrap(),
            received_at: timestamp,
        },
        membership_compensation_evidence: None,
        governance_dependencies: vec![],
        device_pairing_authorization: None,
        contact_projection: None,
        consent_projection: None,
        control_proposal_ingress: None,
        device_revocation_transition: None,
        device_revocation_gate: None,
        historical_producer: None,
        projections: vec![],
        idempotency: None,
        outbox: vec![],
    };
    (request, group)
}

#[derive(diesel::QueryableByName)]
struct Pk {
    #[diesel(sql_type=BigInt)]
    pk: i64,
}

async fn persist(pool: &crate::PgPool, request: &EventCommitRequest) -> PersistenceResult<()> {
    let mut conn = crate::pg_conn(pool)
        .await
        .map_err(PersistenceError::database)?;
    conn.transaction::<(),crate::PgTransactionError,_>(async |conn| {
        crate::events::lock_canonical_event_inputs(conn, &[&request.event]).await?;
        let event:arkret_wire::Event=serde_json::from_value(request.event.envelope.clone()).unwrap();
        let token=event.event_id.token_bytes();
        let pk=sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,actor_seq,realm_id,kind,schema_id,canonical_bytes,envelope) VALUES($1,1,$2,$3,$8,$4,$7,'fixture',$5,$6) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id RETURNING pk")
            .bind::<Binary,_>(token.to_vec()).bind::<Binary,_>(token[1..].to_vec()).bind::<Text,_>(&request.event.actor_id)
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Binary,_>(&request.event.canonical_bytes).bind::<Jsonb,_>(&request.event.envelope)
            .bind::<Text,_>(event.kind.as_str()).bind::<BigInt,_>(event.actor_seq as i64)
            .get_result::<Pk>(conn).await?;
        commit_genesis(conn,pk.pk,request).await?;
        Ok(())
    }).await.map_err(crate::PgTransactionError::into_persistence)
}

#[tokio::test]
async fn exact_public_genesis_is_atomic_restorable_and_withdrawal_is_not_readable() {
    let db = crate::test_database::TestDatabase::lease().await;
    let pool = db.pool();
    let request = genesis();
    let event_id: arkret_wire::EventId = request.event.event_id.parse().unwrap();
    let mut bad = request.clone();
    bad.mls_public_genesis.as_mut().unwrap().ratchet_tree_bytes[0] ^= 1;
    assert!(persist(&pool, &bad).await.is_err());
    let mut conn = crate::pg_conn(&pool).await.unwrap();
    assert!(read_genesis(&mut conn, &event_id).await.unwrap().is_none());
    persist(&pool, &request).await.unwrap();
    persist(&pool, &request).await.unwrap();
    let stored = read_genesis(&mut conn, &event_id).await.unwrap().unwrap();
    let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::from_value(serde_json::to_value(&stored.source_event.payload).unwrap())
            .unwrap();
    let group_id = payload.mls_group_id();
    let restored =
        arkret_mls::MlsPublicGroupTracker::restore(&stored.public_state, group_id, 0).unwrap();
    assert_eq!(restored.leaves().unwrap().len(), 1);
    let mut wrong_producer = request.clone();
    wrong_producer
        .mls_public_genesis
        .as_mut()
        .unwrap()
        .producer_device_id = Some(
        "ak:device:01904100-0000-7000-8000-00000000abce"
            .parse()
            .unwrap(),
    );
    assert!(persist(&pool, &wrong_producer).await.is_err());
    let mut winner: serde_json::Value =
        serde_json::from_slice(&request.event.canonical_bytes).unwrap();
    winner["payload"]["created_at"] = json!("2026-09-10T00:00:01.000Z");
    let winner = arkret_canonical::canonical_json_bytes(&winner).unwrap();
    // Exercise the actual accepted-collision replacement entry. Cryptographic
    // collision evidence admission is tested by the fork-resolution suite.
    conn.transaction::<(), crate::PgTransactionError, _>(async |conn| {
        crate::events::admit_collision_winner(
            conn,
            &event_id.token_bytes(),
            request.event.realm_id.as_deref(),
            &winner,
            request.event.received_at.timestamp_millis(),
        )
        .await?;
        Ok(())
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)
    .unwrap();
    assert!(read_genesis(&mut conn, &event_id).await.unwrap().is_none());
    conn.transaction::<(), crate::PgTransactionError, _>(async |conn| {
        crate::events::admit_collision_winner(
            conn,
            &event_id.token_bytes(),
            request.event.realm_id.as_deref(),
            &request.event.canonical_bytes,
            request.event.received_at.timestamp_millis(),
        )
        .await?;
        Ok(())
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)
    .unwrap();
    assert!(read_genesis(&mut conn, &event_id).await.unwrap().is_none());
    persist(&pool, &request).await.unwrap();
    assert!(read_genesis(&mut conn, &event_id).await.unwrap().is_some());
    sql_query("UPDATE canonical_events SET state='quarantined' WHERE id=$1")
        .bind::<Binary, _>(event_id.token_bytes().to_vec())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(read_genesis(&mut conn, &event_id).await.unwrap().is_none());
}

#[tokio::test]
async fn historical_genesis_authority_is_pinned_on_retry_and_withdrawal_hides_it() {
    let db = crate::test_database::TestDatabase::lease().await;
    let pool = db.pool();
    let mut request = genesis();
    let event: arkret_wire::Event = serde_json::from_value(request.event.envelope.clone()).unwrap();
    let account = event.actor_id.as_account_id().unwrap();
    let original = "ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml";
    request.device_revocation_gate = Some(soland_storage::DeviceRevocationGateSelector {
        principal_id: account.principal_id.clone(),
        station_id: account.station_id.clone(),
        device_id: request
            .mls_public_genesis
            .as_ref()
            .unwrap()
            .producer_device_id
            .as_ref()
            .unwrap()
            .to_string(),
        target_device_authorize_event_id: original.into(),
        target_device_generation_ref: 1,
    });
    // This persistence fixture supplies already-verified producer input; live
    // gate authentication is covered by the Event UoW tests, not this helper.
    persist(&pool, &request).await.unwrap();
    let mut conn = crate::pg_conn(&pool).await.unwrap();
    let first = read_authorizations(&mut conn, &event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        first[0]
            .device_authorize_event_id
            .as_ref()
            .unwrap()
            .as_str(),
        original
    );
    request
        .device_revocation_gate
        .as_mut()
        .unwrap()
        .target_device_authorize_event_id =
        "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".into();
    persist(&pool, &request).await.unwrap();
    assert_eq!(
        read_authorizations(&mut conn, &event.event_id)
            .await
            .unwrap()
            .unwrap(),
        first
    );
    sql_query("UPDATE canonical_events SET state='quarantined' WHERE id=$1")
        .bind::<Binary, _>(event.event_id.token_bytes().to_vec())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(
        read_authorizations(&mut conn, &event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}

fn successor(
    template: &EventCommitRequest,
    kind: &str,
    payload: serde_json::Value,
    seq: u64,
) -> EventCommitRequest {
    let original: arkret_wire::Event =
        serde_json::from_value(template.event.envelope.clone()).unwrap();
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        kind,
        original.scope_ref,
        original.actor_id,
        seq,
        "000000000001-0000-00000000".parse().unwrap(),
        payload,
        original.created_at,
    )
    .unwrap();
    let mut request = template.clone();
    request.mls_public_producer = if matches!(kind, "ak.mls.proposal" | "ak.mls.commit") {
        let input = template.mls_public_genesis.as_ref().unwrap();
        Some(soland_storage::MlsPublicHandshakeProducer {
            signing_key: input.producer_signing_key.clone(),
            device_id: input.producer_device_id.clone(),
        })
    } else {
        None
    };
    request.mls_public_genesis = None;
    request.event.event_id = event.event_id.to_string();
    request.event.actor_seq = seq;
    request.event.kind = kind.to_owned();
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(DigestSuite::Sha256)
        .unwrap();
    request.event.canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    request.event.envelope = serde_json::to_value(event).unwrap();
    request
}

fn next_binding(
    template: &EventCommitRequest,
    previous: u64,
    next: u64,
    hash: char,
) -> arkret_models_crypto::MlsGovernanceBindingPayload {
    let event: arkret_wire::Event =
        serde_json::from_value(template.event.envelope.clone()).unwrap();
    arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        event.realm_id,
        previous,
        next,
        format!("sha256:{}", hash.to_string().repeat(64))
            .parse()
            .unwrap(),
        arkret_wire::ContentScheme::MlsRfc9420,
        None,
        arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        arkret_wire::CORE_REDUCER_PROFILE,
    )
    .unwrap()
}

async fn persist_proposals(
    pool: &crate::PgPool,
    template: &EventCommitRequest,
    proposals: &[arkret_models_crypto::MlsProposalEnvelope],
    target: &ActorId,
    join: &str,
    binding: &arkret_models_crypto::MlsGovernanceBindingPayload,
    seq: &mut u64,
) -> Vec<arkret_wire::EventId> {
    let mut refs = Vec::new();
    for proposal in proposals {
        let mut payload = json!({"mls_group_id":proposal.group_id,"base_epoch":proposal.epoch,"proposal_type":proposal.proposal_type,
            "proposal_bytes_b64":proposal.proposal,"proposal_digest":proposal.proposal_digest,"governance_binding":binding});
        if proposal.proposal_type == "add" {
            payload["target_actor_id"] = json!(target);
            payload["target_authorization_incarnation"] =
                json!({"kind":"realm","realm_membership_incarnation_ref":join});
        }
        let request = successor(template, "ak.mls.proposal", payload, *seq);
        *seq += 1;
        persist(pool, &request).await.unwrap();
        refs.push(request.event.event_id.parse().unwrap());
    }
    refs
}

#[derive(diesel::QueryableByName)]
struct Candidate {
    #[diesel(sql_type=Jsonb)]
    transition: serde_json::Value,
    #[diesel(sql_type=Binary)]
    public_state: Vec<u8>,
    #[diesel(sql_type=diesel::sql_types::Bool)]
    source_available: bool,
}
async fn candidate(conn: &mut AsyncPgConnection, id: &str) -> Candidate {
    sql_query("SELECT c.transition,c.public_state,c.source_available FROM mls_public_commit_states c JOIN canonical_events e ON e.pk=c.event_pk WHERE e.id=$1")
        .bind::<Binary,_>(id.parse::<arkret_wire::EventId>().unwrap().token_bytes().to_vec()).get_result(conn).await.unwrap()
}

#[tokio::test]
async fn durable_add_replacement_and_withdrawal_keep_exact_branch_sources() {
    let db = crate::test_database::TestDatabase::lease().await;
    let pool = db.pool();
    let (genesis, mut group) = genesis_with_group();
    let mut sibling = arkret_mls::ArkretMlsGroup::restore_from_state_record(
        &group.export_state_record().unwrap(),
    )
    .unwrap();
    persist(&pool, &genesis).await.unwrap();
    let bob = arkret_mls::ArkretMlsIdentity::new_test_human_device(
        "ak:did_core:web:bob.example".parse().unwrap(),
        "ak:device:01904100-0000-7000-8000-00000000bb00"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let binding = next_binding(&genesis, 0, 1, '2');
    let package = bob.key_package_record().unwrap();
    let added = group
        .add_member_with_governance_binding(&package, &binding)
        .unwrap();
    let target = group
        .verified_leaf_bindings()
        .unwrap()
        .into_iter()
        .find(|b| b.endpoint == package.endpoint)
        .unwrap()
        .actor_id;
    let join = successor(
        &genesis,
        "ak.member.state",
        json!({"member_id":target,"membership":"join"}),
        2,
    );
    persist(&pool, &join).await.unwrap();
    let mut seq = 3;
    let refs = persist_proposals(
        &pool,
        &genesis,
        &added.proposals,
        &target,
        &join.event.event_id,
        &binding,
        &mut seq,
    )
    .await;
    let first_proposal = refs[0].clone();
    let payload = arkret_models_crypto::MlsCommitPayload::new(
        &genesis.event.event_id,
        refs,
        &added.commit,
        binding,
    )
    .unwrap();
    let first = successor(&genesis, "ak.mls.commit", json!(payload), seq);
    seq += 1;
    persist(&pool, &first).await.unwrap();
    persist(&pool, &first).await.unwrap();
    let binding = next_binding(&genesis, 1, 2, '3');
    let replaced = group
        .replace_member_endpoint(&bob.key_package_record().unwrap(), &target, Some(&binding))
        .unwrap();
    let refs = persist_proposals(
        &pool,
        &genesis,
        &replaced.proposals,
        &target,
        &join.event.event_id,
        &binding,
        &mut seq,
    )
    .await;
    let payload = arkret_models_crypto::MlsCommitPayload::new(
        &first.event.event_id,
        refs,
        &replaced.commit,
        binding,
    )
    .unwrap();
    let second = successor(&genesis, "ak.mls.commit", json!(payload), seq);
    seq += 1;
    persist(&pool, &second).await.unwrap();
    let sibling_binding = next_binding(&genesis, 0, 1, '4');
    let commit = sibling.update_governance_binding(&sibling_binding).unwrap();
    let payload = arkret_models_crypto::MlsCommitPayload::new(
        &genesis.event.event_id,
        vec![],
        &commit,
        sibling_binding,
    )
    .unwrap();
    let sibling_request = successor(&genesis, "ak.mls.commit", json!(payload), seq);
    persist(&pool, &sibling_request).await.unwrap();
    let mut conn = crate::pg_conn(&pool).await.unwrap();
    let old = candidate(&mut conn, &first.event.event_id).await;
    let new = candidate(&mut conn, &second.event.event_id).await;
    assert_eq!(new.transition["removed_leaf_indices"], json!([1]));
    assert_eq!(
        old.transition["added"][0]["leaf"],
        new.transition["added"][0]["leaf"]
    );
    assert_ne!(
        old.transition["added"][0]["proposal_event_ref"],
        new.transition["added"][0]["proposal_event_ref"]
    );
    assert_eq!(
        arkret_mls::MlsPublicGroupTracker::restore(&new.public_state, &group.group_id(), 2)
            .unwrap()
            .leaves()
            .unwrap()
            .len(),
        2
    );
    sql_query("UPDATE canonical_events SET state='quarantined' WHERE id=$1")
        .bind::<Binary, _>(first_proposal.token_bytes().to_vec())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(
        !candidate(&mut conn, &first.event.event_id)
            .await
            .source_available
    );
    assert!(
        !candidate(&mut conn, &second.event.event_id)
            .await
            .source_available
    );
    assert!(
        candidate(&mut conn, &sibling_request.event.event_id)
            .await
            .source_available
    );
    assert!(persist(&pool, &second).await.is_err());
}

#[test]
fn delegated_public_sender_binds_executor_without_changing_record_principal() {
    let request = genesis();
    let mut event: arkret_wire::Event = serde_json::from_value(request.event.envelope).unwrap();
    let principal = event.actor_id.clone();
    let executor: arkret_wire::DidCoreId = "ak:did_core:web:executor.example".parse().unwrap();
    event.executed_by = Some(ActorId::service(executor.clone()));
    let input = request.mls_public_genesis.unwrap();
    let key = arkret_canonical::decode_ed25519_multibase(
        input
            .producer_signing_key
            .as_str()
            .strip_prefix("did:key:")
            .unwrap(),
    )
    .unwrap();
    let leaf = arkret_mls::MlsPublicEndpointLeaf {
        leaf_index: 0,
        endpoint_credential: arkret_mls::MlsPublicLeafEndpointCredential::Actor {
            actor_id: executor.clone(),
        },
        credential_ref: arkret_wire::NonEmptyString::new(executor.as_str()).unwrap(),
        signature_key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(&key))
            .unwrap(),
    };
    let producer = soland_storage::MlsPublicHandshakeProducer {
        signing_key: input.producer_signing_key,
        device_id: None,
    };
    super::commit::validate_sender(&event, &producer, Some(&leaf)).unwrap();
    assert_eq!(event.actor_id, principal);
    event.executed_by = None;
    assert!(super::commit::validate_sender(&event, &producer, Some(&leaf)).is_err());
}

#[tokio::test]
async fn standalone_and_batch_wait_for_realm_before_taking_event_identity() {
    use std::time::Duration;

    use soland_storage::EventStore;
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=BigInt)]
        value: i64,
    }
    #[derive(diesel::QueryableByName)]
    struct Lock {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        acquired: bool,
    }
    let db = crate::test_database::TestDatabase::lease().await;
    let pool = db.pool();
    let request = genesis();
    let mut blocker = crate::pg_conn(&pool).await.unwrap();
    sql_query("BEGIN").execute(&mut *blocker).await.unwrap();
    crate::events::lock_canonical_realm(&mut blocker, request.event.realm_id.as_deref().unwrap())
        .await
        .unwrap();
    let standalone_pool = pool.clone();
    let record = request.event.clone();
    let standalone = tokio::spawn(async move {
        crate::PgEventStore {
            pool: standalone_pool,
        }
        .put(record)
        .await
    });
    let batch_pool = pool.clone();
    let batch_request = request.clone();
    let batch = tokio::spawn(async move { persist(&batch_pool, &batch_request).await });
    tokio::time::timeout(Duration::from_secs(10),async {
        loop {
            let pending=sql_query("SELECT count(*)::bigint AS value FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND NOT granted")
                .get_result::<Count>(&mut *blocker).await.unwrap().value;
            if pending>=2 {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("both canonical writers must block on the held Realm lock");
    let id = request
        .event
        .event_id
        .parse::<arkret_wire::EventId>()
        .unwrap();
    let acquired = sql_query(
        "SELECT pg_try_advisory_xact_lock(hashtextextended(encode($1,'hex'),0)) AS acquired",
    )
    .bind::<Binary, _>(id.token_bytes().to_vec())
    .get_result::<Lock>(&mut *blocker)
    .await
    .unwrap()
    .acquired;
    assert!(
        acquired,
        "neither blocked writer may own the Event identity before its Realm"
    );
    sql_query("COMMIT").execute(&mut *blocker).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        standalone.await.unwrap().unwrap();
        batch.await.unwrap().unwrap();
    })
    .await
    .expect("same-identity standalone and batch must complete without deadlock");
}
