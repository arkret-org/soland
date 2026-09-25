//! Direct Conversation founding unit and profile admission table at the
//! governing Station's transaction cut
//! (`contact-and-direct-conversation.md` sections 5.4 to 6.2 and 8.4).
//!
//! The founder is a genuinely admitted PCR founding device, so every producer
//! guard is rechecked against the Station's device current. The pair's Contact
//! round is this Station's durable `contacts` row: only Contact admission
//! writes it in production, and the founding transaction reads it as the
//! current founding authority.

#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;
mod support;

use arkret_models_collaboration::authority_commit::{
    DirectConversationFoundingUnitKind, DirectConversationFoundingUnitSubmission,
};
use arkret_models_collaboration::contact_operations::{
    ContactCurrentProof, ContactPeer, ContactProducerSigner, ContactRound,
    ContactRoundEvidenceBundle, NormalResponseAcceptanceReceipt, RequestAcceptanceReceipt,
    RequestAcceptanceReceiptCore,
};
use arkret_wire::{AccountId, ActorId, DidCoreId, DidUrl, EventKind, Hash, RealmId};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, ConflictCode, ContactStore,
    CurrentRealmAuthority, DirectConversationAdmissionCut, DirectConversationFoundingCommitOutcome,
    DirectConversationFoundingCommitUnit, EventCommitUnitOfWork, PersistenceError,
    SelfProducerCommitGuard,
};
use soland_storage_postgres::{
    Db, PgAuthorityCommitStore, PgContactStore, PgEventCommitUnitOfWork, PgPersistenceStore, PgPool,
};

#[derive(diesel::QueryableByName)]
struct StationRow {
    #[diesel(sql_type = Text)]
    station_id: String,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

const TRUST_DOMAIN: &str = "ak:trust_domain:direct-conversation.example";

/// A founder with an accepted founding device, a same-Station peer and their
/// accepted Contact round, in which the founder is the responder.
struct Pair {
    pool: PgPool,
    station: DidCoreId,
    founder: AccountId,
    founder_method: DidUrl,
    founder_guard: SelfProducerCommitGuard,
    peer: AccountId,
    contact_round_id: Hash,
}

impl Pair {
    fn founder_actor(&self) -> ActorId {
        ActorId::account(self.founder.clone())
    }

    fn peer_actor(&self) -> ActorId {
        ActorId::account(self.peer.clone())
    }

    fn guards(&self) -> [SelfProducerCommitGuard; 4] {
        std::array::from_fn(|_| self.founder_guard.clone())
    }

    fn store(&self) -> PgAuthorityCommitStore {
        PgAuthorityCommitStore {
            pool: self.pool.clone(),
        }
    }
}

fn unique_event_id(seed: &str) -> arkret_wire::EventId {
    arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(format!("{seed}:{}", uuid::Uuid::now_v7()).as_bytes()),
    )
}

fn fixture_hash(byte: char) -> Hash {
    Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
}

fn fixture_signature(
    issuer: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::ProtocolSignature {
    arkret_wire::ProtocolSignature {
        verification_method: DidUrl::new(format!("{issuer}#service-key")).unwrap(),
        created_at: at,
        jws: format!(
            "{}..{}",
            arkret_canonical::base64url_encode(br#"{"alg":"EdDSA"}"#),
            arkret_canonical::base64url_encode([1_u8; 64])
        ),
    }
}

fn producer_signer(account: &AccountId) -> ContactProducerSigner {
    let did = account
        .principal_id
        .as_str()
        .replace("ak:did_core:", "did:");
    ContactProducerSigner::direct(
        DidUrl::new(format!("{did}#device")).unwrap(),
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([7_u8; 32])).unwrap(),
    )
    .unwrap()
}

/// A normal-branch Contact round: `requester` asked, `responder` accepted.
fn normal_round(
    requester: &AccountId,
    responder: &AccountId,
    request_event_ref: &arkret_wire::EventId,
    response_event_ref: &arkret_wire::EventId,
    at: chrono::DateTime<chrono::Utc>,
) -> ContactRoundEvidenceBundle {
    let requester_peer = ContactPeer::Human {
        account_id: requester.clone(),
    };
    let responder_peer = ContactPeer::Human {
        account_id: responder.clone(),
    };
    let mut request_receipt = RequestAcceptanceReceipt {
        core: RequestAcceptanceReceiptCore {
            holder: requester_peer.clone(),
            peer: responder_peer.clone(),
            slot_version: 1,
            slot_predecessor: None,
            previous_terminal_contact_round_id: None,
            request_event_ref: request_event_ref.clone(),
            producer_signer: producer_signer(requester),
            source_checkpoint: fixture_hash('2'),
            accepted_at: at,
            issuer_id: requester.station_id.clone(),
        },
        receipt_digest: fixture_hash('0'),
        signature: fixture_signature("did:web:contact-station.example", at),
    };
    request_receipt.receipt_digest = request_receipt.computed_core_digest().unwrap();
    let request_acceptance_receipt_digest =
        Hash::new(arkret_canonical::canonical_sha256(&request_receipt).unwrap()).unwrap();
    let mut sorted_pair_member_ids = [
        ActorId::account(requester.clone()),
        ActorId::account(responder.clone()),
    ];
    sorted_pair_member_ids.sort();
    let contact_round = ContactRound::Normal {
        sorted_pair_member_ids,
        request_event_ref: request_event_ref.clone(),
        request_acceptance_receipt_digest,
    };
    let mut material = b"ak.contact.round.v1\n".to_vec();
    material.extend(arkret_canonical::canonical_json_bytes(&contact_round).unwrap());
    let contact_round_id = Hash::new(arkret_canonical::sha256_digest(material)).unwrap();
    let proof =
        |subject: &AccountId, peer: ContactPeer, head: &arkret_wire::EventId| ContactCurrentProof {
            contact_round_id: contact_round_id.clone(),
            issuer_id: subject.station_id.clone(),
            peer,
            terminal: false,
            accepted_commit_event_ids: vec![head.clone()],
            head_event_ref: head.clone(),
            complete_through: 1,
            fresh_until: at + chrono::Duration::hours(1),
            signature: fixture_signature("did:web:contact-station.example", at),
        };
    ContactRoundEvidenceBundle {
        contact_round_id: contact_round_id.clone(),
        previous_terminal_contact_round_id: None,
        contact_round,
        request_receipts: vec![request_receipt.clone()],
        normal_response_receipt: Some(NormalResponseAcceptanceReceipt {
            contact_round_id: contact_round_id.clone(),
            request_receipt,
            response_event_ref: response_event_ref.clone(),
            producer_signer: producer_signer(responder),
            outgoing_slot_absence_digest: fixture_hash('5'),
            accepted_at: at,
            issuer_id: responder.station_id.clone(),
            signature: fixture_signature("did:web:contact-station.example", at),
        }),
        glare_concurrency_attestations: None,
        current_proofs: vec![
            proof(requester, responder_peer, request_event_ref),
            proof(responder, requester_peer, response_event_ref),
        ],
        continuity_checkpoint: None,
    }
}

/// Record the pair's accepted Contact the way Contact admission leaves it.
async fn accept_contact(
    pool: &PgPool,
    requester: &AccountId,
    responder: &AccountId,
    status: &str,
) -> Hash {
    let at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let request_event_ref = unique_event_id("contact-request");
    let response_event_ref = unique_event_id("contact-response");
    let evidence = normal_round(
        requester,
        responder,
        &request_event_ref,
        &response_event_ref,
        at,
    );
    let contact_round_id = evidence.contact_round_id.clone();
    PgContactStore { pool: pool.clone() }
        .put(&soland_domain::identity::ContactRecord {
            requester_id: ActorId::account(requester.clone()),
            target_id: ActorId::account(responder.clone()),
            contact_round_id: Some(contact_round_id.clone()),
            version: Some(1),
            granted_to_target_scopes: vec!["direct_message".to_owned()],
            granted_to_requester_scopes: vec!["direct_message".to_owned()],
            status: status.to_owned(),
            pending_incoming_admitted: true,
            request_event_ref: Some(request_event_ref),
            request_slot_states: Vec::new(),
            request_receipts: evidence.request_receipts.clone(),
            request_mirror_receipts: Vec::new(),
            contact_round_evidence: Some(evidence),
            contact_round_evidence_history: Vec::new(),
            control_outcomes: Vec::new(),
            response_event_ref: Some(response_event_ref),
            tombstone_event_ref: None,
            message: None,
            peer_host_id: None,
            peer_service_resolution: None,
            created_at: at,
            updated_at: at,
        })
        .await
        .unwrap();
    contact_round_id
}

async fn pair(pool: &PgPool) -> Pair {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO device_inventory_station(singleton,station_id) \
         VALUES(TRUE,'ak:did_core:web:direct-conversation-contract.example') \
         ON CONFLICT(singleton) DO NOTHING",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    let station =
        diesel::sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
            .get_result::<StationRow>(&mut *conn)
            .await
            .unwrap();
    drop(conn);
    let station = DidCoreId::new(station.station_id).unwrap();
    let pcr = pcr_genesis::PcrGenesisFixture::new(device_authorization_history::did_web_station(
        &station,
    ));
    let selector = pcr
        .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
        .await
        .expect("accepted founder PCR genesis");
    let founder = pcr.history.account.clone();
    let peer = AccountId::new(
        DidCoreId::new(format!(
            "ak:did_core:web:dc-peer-{}.example",
            uuid::Uuid::now_v7().simple()
        ))
        .unwrap(),
        station.clone(),
    );
    let contact_round_id = accept_contact(pool, &peer, &founder, "accepted").await;
    Pair {
        pool: pool.clone(),
        station,
        founder,
        founder_method: pcr.history.device_verification_method.clone(),
        founder_guard: SelfProducerCommitGuard::HumanDevice(selector),
        peer,
        contact_round_id,
    }
}

async fn contract_pool() -> PgPool {
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    Db::connect(Some(&url), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap()
}

/// One Event by `actor` whose structural producer proof names `method`.
fn authored(
    kind: EventKind,
    scope_ref: arkret_wire::ScopeRef,
    actor: ActorId,
    method: &DidUrl,
    payload: serde_json::Value,
    semantic_refs: Vec<arkret_wire::SemanticRef>,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        scope_ref,
        actor,
        payload,
        at,
    )
    .unwrap();
    event.semantic_refs = semantic_refs;
    event
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let digest = Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: method.clone(),
        event_digest: digest.clone(),
        created_at: arkret_canonical::normalize_timestamp_canonical(at),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

/// Knobs a refusal case turns on an otherwise exact founding unit.
#[derive(Clone)]
struct UnitShape {
    author: ActorId,
    other: ActorId,
    salt: String,
    join_rule: &'static str,
    discoverability: &'static str,
    authority_ref: arkret_wire::SemanticRef,
}

impl UnitShape {
    fn exact(pair: &Pair) -> Self {
        Self {
            author: pair.founder_actor(),
            other: pair.peer_actor(),
            salt: salt(),
            join_rule: "closed",
            discoverability: "invite_only",
            authority_ref: arkret_wire::SemanticRef::new(
                pair.contact_round_id.to_string(),
                "direct_conversation_contact_round",
            ),
        }
    }
}

fn salt() -> String {
    arkret_canonical::base64url_encode(arkret_canonical::sha256_bytes(
        uuid::Uuid::now_v7().as_bytes(),
    ))
}

fn founding_unit(
    pair: &Pair,
    shape: &UnitShape,
    idempotency_key: arkret_wire::UuidV7,
    at: chrono::DateTime<chrono::Utc>,
) -> DirectConversationFoundingCommitUnit {
    let create = authored(
        EventKind::RealmCreate,
        arkret_wire::ScopeRef::RealmGenesis,
        shape.author.clone(),
        &pair.founder_method,
        serde_json::json!({"object":{
            "schema":"ak.schema.realm_genesis.v1",
            "purpose":"direct_conversation",
            "genesis_salt":shape.salt,
            "trust_domain":TRUST_DOMAIN,
            "security_class":"standard",
            "governance_station_id":pair.station,
            "initial_join_rule":shape.join_rule,
            "initial_history_access":"since_join",
            "initial_discoverability":shape.discoverability
        }}),
        vec![shape.authority_ref.clone()],
        at,
    );
    let realm_id = RealmId::from_event_id(&create.event_id);
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let join = |member: &ActorId| {
        authored(
            EventKind::MemberState,
            scope.clone(),
            shape.author.clone(),
            &pair.founder_method,
            serde_json::json!({
                "realm_id":realm_id,
                "member_id":member,
                "membership":"join",
                "reason":"direct_conversation_bootstrap"
            }),
            Vec::new(),
            at,
        )
    };
    let founder_join = join(&shape.author);
    let peer_join = join(&shape.other);
    let strand = authored(
        EventKind::StrandCreate,
        scope.clone(),
        shape.author.clone(),
        &pair.founder_method,
        serde_json::json!({"object":{
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Direct conversation"},
            "state":"active",
            "created_by":shape.author,
            "created_at":at
        }}),
        Vec::new(),
        at,
    );
    let events = [create, founder_join, peer_join, strand];
    let authority = CurrentRealmAuthority {
        realm_id: realm_id.clone(),
        generation: 0,
        service_id: pair.station.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            events[0].event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let mut previous: Option<arkret_wire::RealmCommitId> = None;
    let transactions = std::array::from_fn(|index| {
        let event = events[index].clone();
        let commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            format!("{}:{index}:{at}", event.event_id).as_bytes(),
        ));
        let commit = arkret_wire::RealmCommit {
            commit_id: commit_id.clone(),
            realm_id: realm_id.clone(),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            stream_position: index as u64,
            previous_commit_ref: previous.replace(commit_id),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: authority.authority_ref.clone(),
            committed_at: at,
            signature: ordinary_realm::signature(&pair.station, at),
        };
        AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        }
    });
    DirectConversationFoundingCommitUnit {
        submission: DirectConversationFoundingUnitSubmission {
            unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
            idempotency_key,
            events: events.map(arkret_wire::EventAdmissionSubmission::new),
        },
        transactions,
    }
}

fn key() -> arkret_wire::UuidV7 {
    arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap()
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap()
}

async fn count(pool: &PgPool, sql: &str, realm_id: &RealmId) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(sql)
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// Every durable row a founding unit or a later Event can leave for `realm_id`.
async fn footprint(pool: &PgPool, realm_id: &RealmId) -> [i64; 5] {
    [
        count(
            pool,
            "SELECT COUNT(*) AS count FROM realm_authorities WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM canonical_events WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM realm_commits WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM direct_conversation_founding_slots WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM member_state_current_results WHERE realm_id=$1",
            realm_id,
        )
        .await,
    ]
}

fn refusal_code<T: std::fmt::Debug>(outcome: Result<T, PersistenceError>) -> ConflictCode {
    match outcome {
        Err(PersistenceError::Conflict(detail)) => ConflictCode::from_detail(&detail)
            .unwrap_or_else(|| panic!("unregistered refusal {detail}")),
        other => panic!("expected a registered refusal, got {other:?}"),
    }
}

fn realm_of(unit: &DirectConversationFoundingCommitUnit) -> RealmId {
    unit.transactions[0].event.realm_id.clone()
}

#[tokio::test]
async fn founding_unit_commits_four_consecutive_commits_and_exact_retry_replays_them() {
    let pool = contract_pool().await;
    let pair = pair(&pool).await;
    let store = pair.store();
    let idempotency_key = key();
    let shape = UnitShape::exact(&pair);
    let at = now();
    let unit = founding_unit(&pair, &shape, idempotency_key, at);
    let facts = unit.facts().unwrap();
    let realm_id = realm_of(&unit);

    let DirectConversationFoundingCommitOutcome::Committed(commits) = store
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .unwrap()
    else {
        panic!("the first founding unit commits");
    };
    for (position, commit) in commits.iter().enumerate() {
        assert_eq!(commit.stream_position, position as u64);
        assert_eq!(commit.event_ref, unit.transactions[position].event.event_id);
        assert_eq!(
            commit.previous_commit_ref.as_ref(),
            position
                .checked_sub(1)
                .map(|previous| &commits[previous].commit_id)
        );
        let accepted = store
            .committed_event(&commit.event_ref)
            .await
            .unwrap()
            .expect("every founding Event is committed");
        assert_eq!(accepted.commit, *commit);
    }
    assert_eq!(footprint(&pool, &realm_id).await, [1, 4, 4, 1, 2]);
    assert_eq!(facts.realm_id, realm_id);
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) AS count FROM strand_current_results WHERE realm_id=$1",
            &realm_id,
        )
        .await,
        1,
        "the main Strand current is written with the unit"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) AS count FROM realm_bootstrap_current_results \
             WHERE realm_id=$1 AND result_family='realm_genesis'",
            &realm_id,
        )
        .await,
        1
    );

    // Sections 5.5 and 9.1.1: the self carrier takes neither the founding
    // evidence nor any founding receipt or coordinate, and the outcome
    // carries no receipt.
    let carrier = serde_json::to_value(
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::DirectConversationFounding(
            unit.submission.clone(),
        ),
    )
    .unwrap();
    serde_json::from_value::<
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
    >(carrier.clone())
    .expect("the exact carrier parses");
    for (member, value) in [
        (
            "founding_authority_evidence",
            serde_json::json!({"kind":"human"}),
        ),
        ("receipt", serde_json::json!({})),
        ("source_acceptance_receipt", serde_json::json!({})),
        ("realm_id", serde_json::to_value(&realm_id).unwrap()),
    ] {
        let mut injected = carrier.clone();
        injected[member] = value;
        assert!(
            serde_json::from_value::<
                arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
            >(injected)
            .is_err(),
            "{member} is not a member of the self founding carrier"
        );
    }
    let mut outcome = serde_json::to_value(
        arkret_models_collaboration::authority_commit::DirectConversationFoundingAcceptanceOutcome {
            unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
            status: arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed,
            commits: commits.clone(),
        },
    )
    .unwrap();
    outcome["receipt"] = serde_json::json!({});
    assert!(
        serde_json::from_value::<
            arkret_models_collaboration::authority_commit::DirectConversationFoundingAcceptanceOutcome,
        >(outcome)
        .is_err()
    );

    // An exact retry re-signed later still answers with the original four
    // byte-identical Commits; the fourth committed_at never moves.
    let later = at + chrono::Duration::seconds(5);
    let mut retry = unit.clone();
    for transaction in &mut retry.transactions {
        transaction.commit.committed_at = later;
        transaction.commit.signature = ordinary_realm::signature(&pair.station, later);
    }
    assert_eq!(retry.facts().unwrap(), facts);
    let DirectConversationFoundingCommitOutcome::Duplicate(replayed) = store
        .admit_self_direct_conversation_founding_unit(&retry, &pair.guards(), later)
        .await
        .unwrap()
    else {
        panic!("an exact retry is a duplicate");
    };
    assert_eq!(
        serde_json::to_vec(&replayed).unwrap(),
        serde_json::to_vec(&commits).unwrap()
    );
    assert_eq!(replayed[3].committed_at, at);

    // The same key with another unit is a duplicate conflict; another key with
    // another unit for the same pair finds the founder's slot closed.
    let other = UnitShape {
        salt: salt(),
        ..shape.clone()
    };
    let conflicting = founding_unit(&pair, &other, idempotency_key, later);
    assert_eq!(
        refusal_code(
            store
                .admit_self_direct_conversation_founding_unit(&conflicting, &pair.guards(), later)
                .await
        ),
        ConflictCode::DuplicateConflict
    );
    assert_eq!(footprint(&pool, &realm_of(&conflicting)).await, [0; 5]);
    let second = founding_unit(&pair, &other, key(), later);
    assert_eq!(
        refusal_code(
            store
                .admit_self_direct_conversation_founding_unit(&second, &pair.guards(), later)
                .await
        ),
        ConflictCode::DirectConversationSlotAlreadyCommitted
    );
    assert_eq!(footprint(&pool, &realm_of(&second)).await, [0; 5]);
    assert_eq!(footprint(&pool, &realm_id).await, [1, 4, 4, 1, 2]);
}

#[tokio::test]
async fn founding_refusals_decide_authority_at_the_slot_cut_with_zero_writes() {
    let pool = contract_pool().await;
    let pair = pair(&pool).await;
    let store = pair.store();
    let at = now();
    let refuse = async |shape: UnitShape| {
        let unit = founding_unit(&pair, &shape, key(), at);
        let code = refusal_code(
            store
                .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
                .await,
        );
        assert_eq!(footprint(&pool, &realm_of(&unit)).await, [0; 5]);
        code
    };

    // The requester of the normal round is not its founder.
    assert_eq!(
        refuse(UnitShape {
            author: pair.peer_actor(),
            other: pair.founder_actor(),
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::CapabilityDenied
    );
    // Material from another round is stale at the founding cut.
    assert_eq!(
        refuse(UnitShape {
            authority_ref: arkret_wire::SemanticRef::new(
                fixture_hash('9').to_string(),
                "direct_conversation_contact_round",
            ),
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::FailedPrecondition
    );
    // No accepted provision is readable for the controller-Agent branch.
    assert_eq!(
        refuse(UnitShape {
            authority_ref: arkret_wire::SemanticRef::new(
                unique_event_id("agent-provision").to_string(),
                "direct_conversation_agent_provision",
            ),
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::FailedPrecondition
    );
    // The fixed baseline is create-locked: closed, invite_only, since_join.
    assert_eq!(
        refuse(UnitShape {
            join_rule: "invite",
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::DirectConversationFoundingUnitInvalid
    );
    assert_eq!(
        refuse(UnitShape {
            discoverability: "unlisted",
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::DirectConversationFoundingUnitInvalid
    );
    // A pair whose Contact is not accepted has no founding authority.
    let stranger = AccountId::new(
        DidCoreId::new(format!(
            "ak:did_core:web:dc-pending-{}.example",
            uuid::Uuid::now_v7().simple()
        ))
        .unwrap(),
        pair.station.clone(),
    );
    let pending_round = accept_contact(&pool, &stranger, &pair.founder, "pending").await;
    assert_eq!(
        refuse(UnitShape {
            other: ActorId::account(stranger),
            authority_ref: arkret_wire::SemanticRef::new(
                pending_round.to_string(),
                "direct_conversation_contact_round",
            ),
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::FailedPrecondition
    );

    // The exact unit is still admissible afterwards: no refusal left a slot.
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at);
    assert!(matches!(
        store
            .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
            .await
            .unwrap(),
        DirectConversationFoundingCommitOutcome::Committed(_)
    ));
}

#[tokio::test]
async fn profile_admission_table_refuses_in_registered_precedence_with_zero_writes() {
    let pool = contract_pool().await;
    let pair = pair(&pool).await;
    let store = pair.store();
    let at = now();
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at);
    store
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .unwrap();
    let realm_id = realm_of(&unit);
    let facts = unit.facts().unwrap();
    let head = unit.transactions[3].clone();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let third = AccountId::new(
        DidCoreId::new(format!(
            "ak:did_core:web:dc-third-{}.example",
            uuid::Uuid::now_v7().simple()
        ))
        .unwrap(),
        pair.station.clone(),
    );
    let invite = |invitee: &AccountId| {
        serde_json::json!({
            "invitee_account_id":invitee,
            "introduction_evidence_digest":fixture_hash('4'),
            "expires_at":"2099-01-01T00:00:00.000Z"
        })
    };
    let refused = async |kind: EventKind, actor: &AccountId, payload: serde_json::Value| {
        let request = ordinary_realm::next_request(&head, kind, &actor.principal_id, payload, at);
        let code = refusal_code(uow.commit_event(request).await);
        assert_eq!(footprint(&pool, &realm_id).await, [1, 4, 4, 1, 2]);
        code
    };

    // A pair-external invite hits both the third-party and the invite guard;
    // the third-party reason wins.
    assert_eq!(
        refused(EventKind::InviteCreate, &pair.founder, invite(&third)).await,
        ConflictCode::DirectConversationThirdPartyMemberForbidden
    );
    assert_eq!(
        refused(
            EventKind::MemberState,
            &third,
            serde_json::json!({"realm_id":realm_id,"member_id":ActorId::account(third.clone()),"membership":"join"}),
        )
        .await,
        ConflictCode::DirectConversationThirdPartyMemberForbidden
    );
    assert_eq!(
        refused(EventKind::InviteCreate, &pair.founder, invite(&pair.peer)).await,
        ConflictCode::DirectConversationInviteForbidden
    );
    // Removing the peer would lean on the technical root's owner aggregate.
    assert_eq!(
        refused(
            EventKind::MemberState,
            &pair.founder,
            serde_json::json!({"realm_id":realm_id,"member_id":pair.peer_actor(),"membership":"ban"}),
        )
        .await,
        ConflictCode::DirectConversationRootMaskViolation
    );
    // The founder's provisional Message has no accepted group Genesis.
    assert_eq!(
        refused(
            EventKind::MessageCreate,
            &pair.founder,
            ordinary_realm::message_payload(&facts.main_strand_id, "hello"),
        )
        .await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );

    let evaluate = async |kind: EventKind, actor: &AccountId, payload: serde_json::Value| {
        let request = ordinary_realm::next_request(&head, kind, &actor.principal_id, payload, at);
        store
            .direct_conversation_admission(&request.authority_commit.event)
            .await
            .unwrap()
    };
    // Destroy relies on the root too; the terminal reason wins.
    assert_eq!(
        evaluate(
            EventKind::RealmDestroy,
            &pair.founder,
            serde_json::json!({"realm_id":realm_id}),
        )
        .await,
        DirectConversationAdmissionCut::Refused(ConflictCode::DirectConversationTerminalForbidden)
    );
    assert_eq!(
        evaluate(
            EventKind::DirectConversationBound,
            &pair.peer,
            serde_json::json!({
                "pair_key":facts.pair_key,
                "unordered_participant_ids":[pair.founder_actor(), pair.peer_actor()],
                "realm_id":realm_id,
                "main_strand_id":facts.main_strand_id,
                "founding_unit_digest":facts.founding_unit_digest,
                "authorization_basis":{"kind":"accepted_contact","event_refs":[
                    unique_event_id("request"), unique_event_id("response")
                ]},
                "initial_exact_pair_group_state_ref":unique_event_id("group-state"),
                "created_at":at
            }),
        )
        .await,
        DirectConversationAdmissionCut::Refused(ConflictCode::DirectConversationBindingInvalid)
    );

    // A participant who left still counts for the exact-two gate
    // (`contact-and-direct-conversation.md` §8.4): the pair-external invite
    // keeps its third-party reason and the peer's own rejoin passes every
    // profile stage, leaving it to the self-membership authority. The peer's row is moved directly
    // because its own leave is itself refused by the participant evaluator until binding
    // admission exists.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE member_state_current_results \
         SET membership='leave', value=jsonb_set(value,'{membership}','\"leave\"') \
         WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(pair.peer_actor().to_string())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        refused(EventKind::InviteCreate, &pair.founder, invite(&third)).await,
        ConflictCode::DirectConversationThirdPartyMemberForbidden
    );
    assert_eq!(
        evaluate(
            EventKind::MemberState,
            &pair.peer,
            serde_json::json!({"realm_id":realm_id,"member_id":pair.peer_actor(),"membership":"join"}),
        )
        .await,
        DirectConversationAdmissionCut::Passed
    );

    // Once the membership projection no longer resolves the exact pair, a
    // new write fails the exact-two gate before any later stage.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "DELETE FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(pair.peer_actor().to_string())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        evaluate(EventKind::InviteCreate, &pair.founder, invite(&third)).await,
        DirectConversationAdmissionCut::Refused(ConflictCode::DirectConversationMemberCountInvalid)
    );
}
