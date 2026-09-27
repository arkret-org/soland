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
    DirectConversationFoundingCommitUnit, EventCommitUnitOfWork, EventStore, PersistenceError,
    SelfProducerCommitGuard,
};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{
    Db, FoundingProfileAdmissionSpy, PgAuthorityCommitStore, PgContactStore, PgEventStore,
    PgEventCommitUnitOfWork, PgPersistenceStore, PgPool,
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

#[derive(diesel::QueryableByName)]
struct DeliveryRow {
    #[diesel(sql_type = Text)]
    peer_id: String,
    #[diesel(sql_type = Text)]
    payload_json: String,
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

fn station_successor(
    previous: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    offset_seconds: i64,
) -> arkret_wire::RealmCommit {
    let mut commit = previous.clone();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:{}:successor", event.event_id, previous.commit_id).as_bytes(),
    ));
    commit.stream_position = previous.stream_position + 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.event_ref = event.event_id.clone();
    commit.committed_at = previous.committed_at + chrono::TimeDelta::seconds(offset_seconds);
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

fn station_genesis_commit(
    template: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::RealmCommit {
    let realm_id = RealmId::from_event_id(&event.event_id);
    let mut commit = template.clone();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:genesis", event.event_id).as_bytes(),
    ));
    commit.realm_id = realm_id.clone();
    commit.stream_ref = arkret_wire::CommitStreamRef::Realm { realm_id };
    commit.stream_position = 0;
    commit.previous_commit_ref = None;
    commit.event_ref = event.event_id.clone();
    commit.governance_generation = 0;
    commit.authority_ref =
        arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
    commit.committed_at = committed_at;
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

#[allow(clippy::too_many_arguments)]
fn agent_provision_event(
    controller: &AccountId,
    realm_id: &RealmId,
    method: &DidUrl,
    seed: [u8; 32],
    agent_id: &DidCoreId,
    agent_pcr_id: &RealmId,
    controller_authorization_ref: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::AgentProvision.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        controller.principal_id.clone(),
        controller.station_id.clone(),
        serde_json::json!({
            "schema": "ak.schema.agent_provision.v1",
            "agent_id": agent_id,
            "controller_principal_id": controller.principal_id,
            "principal_control_realm_id": agent_pcr_id,
            "controller_authorization_ref": controller_authorization_ref,
            "agent_slug": "direct-helper",
            "accountability_scope": "agent_operator",
            "requested_scope_digest": format!("sha256:{}", "b".repeat(64)),
            "selector_visibility": "private",
            "created_at": arkret_canonical::format_timestamp_canonical(created_at)
        }),
        created_at,
    )
    .unwrap();
    device_authorization_history::sign_event(event, method.clone(), seed)
}

fn agent_control_event(
    controller_method: &DidUrl,
    signing_seed: [u8; 32],
    controller: &AccountId,
    agent: &AccountId,
    agent_pcr: &RealmId,
    authorization_ref: &str,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::AgentKeyAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: agent_pcr.clone(),
        },
        ActorId::account(agent.clone()),
        payload,
        at,
    )
    .unwrap();
    event.executed_by = Some(ActorId::account(controller.clone()));
    event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(authorization_ref.to_owned()).unwrap());
    device_authorization_history::sign_event(event, controller_method.clone(), signing_seed)
}

fn agent_key_authorization(
    agent_did: &arkret_wire::Did,
    controller: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let method = format!("{agent_did}#runtime-1");
    let submit = arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1;
    serde_json::json!({
        "agent_id": arkret_wire::project_did_to_core_id(agent_did).unwrap(),
        "key_id": method,
        "verification_method": method,
        "public_key": {
            "kty": "OKP",
            "kid": method,
            "algorithm": "Ed25519",
            "key": arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]).verifying_key().as_bytes()
            )
        },
        "accountable_principal_id": controller,
        "agent_key_scope": {
            "actions": [submit],
            "resources": [{"kind": "operation", "operation": submit}]
        },
        "audience": ["ak:did_core:web:direct-conversation.example"],
        "issued_at": arkret_canonical::format_timestamp_canonical(at),
        "approval_evidence": {
            "kind": "pairing_request",
            "request_canonical_digest": format!("sha256:{}", "d".repeat(64)),
            "pairing_request_id": format!("agent_pairing_request:{}", uuid::Uuid::now_v7()),
            "approved_by": controller
        }
    })
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
    let join = |member: &ActorId, controller_generation_ref: Option<&arkret_wire::EventId>| {
        let mut payload = serde_json::json!({
            "realm_id":realm_id,
            "member_id":member,
            "membership":"join",
            "reason":"direct_conversation_bootstrap"
        });
        if shape.authority_ref.role == "direct_conversation_agent_provision"
            && member == &shape.other
        {
            payload["agent_controller_binding"] = serde_json::json!({
                "controller_account_id": shape.author.as_account_id().unwrap(),
                "controller_membership_generation_ref": controller_generation_ref.unwrap(),
            });
        }
        authored(
            EventKind::MemberState,
            scope.clone(),
            shape.author.clone(),
            &pair.founder_method,
            payload,
            Vec::new(),
            at,
        )
    };
    let founder_join = join(&shape.author, None);
    let peer_join = join(&shape.other, Some(&founder_join.event_id));
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
async fn cross_station_founding_commits_one_exact_peer_delivery_atomically() {
    let pool = contract_pool().await;
    let mut pair = pair(&pool).await;
    let remote_station = DidCoreId::new(format!(
        "ak:did_core:web:dc-remote-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    pair.peer = AccountId::new(pair.peer.principal_id.clone(), remote_station.clone());
    pair.contact_round_id = accept_contact(&pool, &pair.peer, &pair.founder, "accepted").await;
    let at = now();
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at);
    let commits = match pair
        .store()
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .unwrap()
    {
        DirectConversationFoundingCommitOutcome::Committed(commits) => commits,
        _ => panic!("the cross-Station founding unit must commit once"),
    };
    let mut conn = pool.get().await.unwrap();
    let rows = diesel::sql_query(
        "SELECT peer_id,payload_json FROM federation_outbox WHERE idempotency_key=$1",
    )
    .bind::<Text, _>(format!(
        "direct-conversation-founding:{}",
        unit.facts().unwrap().founding_unit_digest
    ))
    .load::<DeliveryRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].peer_id, remote_station.as_str());
    let request: arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest =
        serde_json::from_str(&rows[0].payload_json).unwrap();
    let arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest::RegisteredAtomicUnit(
        request,
    ) = request
    else {
        panic!("the delivery must use registered_atomic_unit");
    };
    let arkret_models_collaboration::authority_commit::PeerRegisteredAtomicUnit::DirectConversationFounding(
        delivered,
    ) = request.unit
    else {
        panic!("the delivery must carry the founding unit");
    };
    for (index, item) in delivered.committed_events.iter().enumerate() {
        assert_eq!(item.event_submission, unit.submission.events[index]);
        assert_eq!(item.source_commit, commits[index]);
    }
    assert_eq!(footprint(&pool, &realm_of(&unit)).await, [1, 4, 4, 1, 2]);
}

#[tokio::test]
async fn peer_founding_missing_contact_dependency_writes_nothing() {
    let source_pool = contract_pool().await;
    let mut pair = pair(&source_pool).await;
    let peer_station = DidCoreId::new(format!(
        "ak:did_core:web:dc-missing-peer-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    pair.peer = AccountId::new(pair.peer.principal_id.clone(), peer_station.clone());
    pair.contact_round_id =
        accept_contact(&source_pool, &pair.peer, &pair.founder, "accepted").await;
    let at = now();
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at);
    pair.store()
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .expect("source founding");
    let mut conn = source_pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT peer_id,payload_json FROM federation_outbox WHERE idempotency_key=$1",
    )
    .bind::<Text, _>(format!(
        "direct-conversation-founding:{}",
        unit.facts().unwrap().founding_unit_digest
    ))
    .get_result::<DeliveryRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(row.peer_id, peer_station.as_str());
    let submission: arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest =
        serde_json::from_str(&row.payload_json).unwrap();
    let arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest::RegisteredAtomicUnit(request) = submission else {
        panic!("expected registered_atomic_unit");
    };
    let arkret_models_collaboration::authority_commit::PeerRegisteredAtomicUnit::DirectConversationFounding(delivered) = request.unit else {
        panic!("expected direct_conversation_founding");
    };

    // A separate Station database has none of the Contact round required by
    // this unit. Its refusal cannot persist one, two or three source Commits.
    let peer_database = TestDatabase::lease().await;
    let peer_pool = peer_database.pool();
    let peer_store = PgAuthorityCommitStore {
        pool: peer_pool.clone(),
    };
    let realm_id = realm_of(&unit);
    let refuse = || {
        peer_store.materialize_peer_direct_conversation_founding_unit(
            &unit,
            &delivered.founding_authority_evidence,
            &peer_station,
            at,
        )
    };
    assert_eq!(
        refusal_code(refuse().await),
        ConflictCode::DependencyMissing
    );
    assert_eq!(footprint(&peer_pool, &realm_id).await, [0; 5]);
    assert_eq!(
        refusal_code(refuse().await),
        ConflictCode::DependencyMissing
    );
    assert_eq!(footprint(&peer_pool, &realm_id).await, [0; 5]);

    // Install the same accepted Contact evidence on the peer after the
    // dependency refusal. The peer must now materialize exact source facts
    // while the founder's seven-stage profile admission is armed to fail.
    let source_contact = PgContactStore {
        pool: source_pool.clone(),
    }
    .get(&pair.peer_actor(), &pair.founder_actor())
    .await
    .unwrap()
    .expect("source accepted Contact");
    PgContactStore {
        pool: peer_pool.clone(),
    }
    .put(&source_contact)
    .await
    .unwrap();
    let profile_spy = FoundingProfileAdmissionSpy::watch(&realm_id);
    assert_eq!(
        refuse().await.unwrap(),
        arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed,
    );
    assert_eq!(
        profile_spy.hits(),
        0,
        "peer materialization invoked founder profile admission"
    );
    assert_eq!(footprint(&peer_pool, &realm_id).await, [1, 4, 4, 1, 2]);

    // A control call to the founder path with the same Realm proves that the
    // tripwire was active during peer materialization.
    let self_attempt = peer_store
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await;
    assert!(
        matches!(self_attempt, Err(PersistenceError::Internal(ref detail))
        if detail == "test-only founder profile admission spy tripped")
    );
    assert_eq!(profile_spy.hits(), 1);
    assert_eq!(footprint(&peer_pool, &realm_id).await, [1, 4, 4, 1, 2]);
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
async fn controller_owned_agent_founding_reads_provision_and_runtime_key_at_the_slot_cut() {
    use soland_storage::{
        ActorProfileStore, AgentControlAdmissionOutcome, AgentControlAdmissionWrite,
        AgentPcrGenesisAdmissionWrite, AgentProvisionAdmissionWrite,
    };

    let pool = contract_pool().await;
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
    let station_did = device_authorization_history::did_web_station(&station);
    let controller_fixture = pcr_genesis::PcrGenesisFixture::new(station_did.clone());
    let selector = controller_fixture
        .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
        .await
        .unwrap();
    let controller = controller_fixture.history.account.clone();
    let controller_realm = controller_fixture.unit.transactions[0]
        .commit
        .realm_id
        .clone();
    let controller_head = controller_fixture.unit.transactions[1].commit.clone();
    let controller_authority = controller_fixture.unit.transactions[1]
        .expected_authority
        .clone();
    let controller_method = controller_fixture
        .history
        .device_verification_method
        .clone();
    let controller_seed = controller_fixture.history.founding_device_signing_seed;
    let profiles = soland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    let store = PgAuthorityCommitStore { pool: pool.clone() };

    let agent_did = arkret_wire::Did::new(format!(
        "did:web:dc-agent-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    let agent_id = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
    let agent = AccountId::new(agent_id.clone(), station.clone());
    let delegation = format!("{agent_did}#managed-controller");
    let genesis = device_authorization_history::sign_event(
        arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
            payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                agent_id: agent_id.clone(),
                governance_station_id: station.clone(),
                initial_resolution: arkret_models_identity::ResolutionCommitment {
                    did: agent_did.clone(),
                    method_history_head: format!("sha256:{}", "c".repeat(64)),
                    version_id: "1-agent".to_owned(),
                },
                genesis_salt: arkret_wire::GenesisSalt::new(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                )
                .unwrap(),
                trust_domain: arkret_wire::TrustDomainId::new(
                    "ak:trust_domain:pcr-contract.example".to_owned(),
                )
                .unwrap(),
                initial_join_rule: arkret_wire::JoinRule::Closed,
                initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                initial_discoverability: arkret_wire::Discoverability::Secret,
            },
            executed_by: ActorId::account(controller.clone()),
            authorization_ref: arkret_wire::AuthorizationRef::new(delegation.clone()).unwrap(),
            created_at: controller_head.committed_at,
        })
        .unwrap()
        .into_event(),
        controller_method.clone(),
        controller_seed,
    );
    let agent_pcr = RealmId::from_event_id(&genesis.event_id);
    let provision = agent_provision_event(
        &controller,
        &controller_realm,
        &controller_method,
        controller_seed,
        &agent_id,
        &agent_pcr,
        &delegation,
        controller_head.committed_at,
    );
    let provision_commit = station_successor(&controller_head, &provision, &station_did, 1);
    let transaction =
        |authority: CurrentRealmAuthority,
         event: arkret_wire::Event,
         commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority,
            event,
            commit,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };
    profiles
        .admit_agent_provision(AgentProvisionAdmissionWrite {
            commit: transaction(
                controller_authority,
                provision.clone(),
                provision_commit.clone(),
            ),
            queued_at: provision_commit.committed_at,
        })
        .await
        .unwrap();
    let genesis_commit = station_genesis_commit(
        &controller_head,
        &genesis,
        &station_did,
        provision_commit.committed_at + chrono::TimeDelta::seconds(1),
    );
    profiles
        .admit_agent_pcr_genesis(AgentPcrGenesisAdmissionWrite {
            commit: transaction(
                CurrentRealmAuthority {
                    realm_id: agent_pcr.clone(),
                    generation: 0,
                    service_id: station.clone(),
                    authority_ref: genesis_commit.authority_ref.clone(),
                    last_handoff_ref: None,
                },
                genesis.clone(),
                genesis_commit.clone(),
            ),
            queued_at: genesis_commit.committed_at,
        })
        .await
        .unwrap();

    let pair = Pair {
        pool: pool.clone(),
        station: station.clone(),
        founder: controller.clone(),
        founder_method: controller_method.clone(),
        founder_guard: SelfProducerCommitGuard::HumanDevice(selector),
        peer: agent.clone(),
        contact_round_id: fixture_hash('a'),
    };
    let shape = UnitShape {
        author: ActorId::account(controller.clone()),
        other: ActorId::account(agent.clone()),
        authority_ref: arkret_wire::SemanticRef::new(
            provision.event_id.to_string(),
            "direct_conversation_agent_provision",
        ),
        ..UnitShape::exact(&pair)
    };

    // Provision and Agent PCR alone are insufficient: no current runtime key
    // means the controller binding is not live, and the whole unit writes zero.
    let no_key_at = genesis_commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let no_key = founding_unit(&pair, &shape, key(), no_key_at);
    let no_key_result = store
        .admit_self_direct_conversation_founding_unit(&no_key, &pair.guards(), no_key_at)
        .await;
    let no_key_detail = format!("{no_key_result:?}");
    assert_eq!(
        refusal_code(no_key_result),
        ConflictCode::FailedPrecondition,
        "unexpected no-key refusal: {no_key_detail}"
    );
    assert_eq!(footprint(&pool, &realm_of(&no_key)).await, [0; 5]);

    let key_event = agent_control_event(
        &controller_method,
        controller_seed,
        &controller,
        &agent,
        &agent_pcr,
        &delegation,
        agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            genesis_commit.committed_at,
        ),
        genesis_commit.committed_at,
    );
    let key_commit = station_successor(&genesis_commit, &key_event, &station_did, 1);
    assert!(matches!(
        profiles
            .admit_agent_control_event(AgentControlAdmissionWrite {
                commit: transaction(
                    CurrentRealmAuthority {
                        realm_id: agent_pcr.clone(),
                        generation: 0,
                        service_id: station,
                        authority_ref: genesis_commit.authority_ref.clone(),
                        last_handoff_ref: None,
                    },
                    key_event.clone(),
                    key_commit.clone(),
                ),
                queued_at: key_commit.committed_at,
            })
            .await
            .unwrap(),
        AgentControlAdmissionOutcome::Committed(_)
    ));

    let unit_at = key_commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let unit = founding_unit(&pair, &shape, key(), unit_at);
    assert!(matches!(
        store
            .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), unit_at,)
            .await
            .unwrap(),
        DirectConversationFoundingCommitOutcome::Committed(_)
    ));
    assert_eq!(footprint(&pool, &realm_of(&unit)).await, [1, 4, 4, 1, 2]);

    #[derive(diesel::QueryableByName)]
    struct BasisRow {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        authorization_basis: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let basis = diesel::sql_query(
        "SELECT authorization_basis FROM direct_conversation_founding_slots WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_of(&unit).as_str())
    .get_result::<BasisRow>(&mut *conn)
    .await
    .unwrap();
    let refs = basis.authorization_basis["event_refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(basis.authorization_basis["kind"], "agent_controller");
    assert_eq!(
        refs,
        [provision.event_id.as_str(), key_event.event_id.as_str()]
            .into_iter()
            .collect()
    );
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

const PARTICIPANT_SOURCE: &str = "ak.authority.direct_conversation_participant.v1";
const BOOTSTRAP_SOURCE: &str = "ak.authority.direct_conversation_bootstrap_participant.v1";
const REPAIR_SOURCE: &str = "ak.authority.direct_conversation_repair.v1";

/// The authority source and critical ref one Direct Conversation Event cites.
enum Cites<'a> {
    Nothing,
    Bootstrap(&'a arkret_wire::EventId),
    Participant(&'a arkret_wire::EventId),
    Repair(&'a arkret_wire::EventId),
}

/// The next Realm-stream request by `actor` citing `cites`.
fn cited(
    previous: &AuthorityCommitTransaction,
    kind: EventKind,
    actor: ActorId,
    payload: serde_json::Value,
    cites: Cites<'_>,
) -> soland_storage::EventCommitRequest {
    let at = previous.commit.committed_at;
    let mut event = ordinary_realm::event_for_actor(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: previous.event.realm_id.clone(),
        },
        actor,
        payload,
        at,
    );
    let (source, role, reference) = match cites {
        Cites::Nothing => return ordinary_realm::request_for_event(previous, event, at),
        Cites::Bootstrap(reference) => (
            BOOTSTRAP_SOURCE,
            "direct_conversation_founding_unit",
            reference,
        ),
        Cites::Participant(reference) => {
            (PARTICIPANT_SOURCE, "direct_conversation_binding", reference)
        }
        Cites::Repair(reference) => (REPAIR_SOURCE, "direct_conversation_binding", reference),
    };
    event.authorization_ref = Some(arkret_wire::AuthorizationRef::new(source).unwrap());
    event.semantic_refs = vec![arkret_wire::SemanticRef::new(reference.to_string(), role)];
    ordinary_realm::reseal(&mut event);
    ordinary_realm::request_for_event(previous, event, at)
}

/// Attach the verified public MLS transition whose roster holds `principals`.
fn with_group(
    mut request: soland_storage::EventCommitRequest,
    base: Option<(&arkret_wire::EventId, u64)>,
    epoch: u64,
    principals: &[&ActorId],
) -> soland_storage::EventCommitRequest {
    request.authority_commit.mls_state = Some(soland_storage::MlsStateInstallation {
        effective_scope: request.authority_commit.event.scope_ref.clone(),
        base: base.map(|(reference, epoch)| soland_storage::MlsInstalledBase {
            current_mls_commit_event_ref: reference.clone(),
            epoch,
        }),
        epoch,
        public_state: format!("public-state-{epoch}").into_bytes(),
        member_principals: principals.iter().map(|actor| (*actor).clone()).collect(),
        genesis_blobs: Vec::new(),
    });
    request
}

fn mls_genesis_payload(realm_id: &RealmId, at: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
    serde_json::json!({
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref": format!("ak:blob:sha256:{}", "3".repeat(64)),
        "ratchet_tree_ref": format!("ak:blob:sha256:{}", "4".repeat(64)),
        "governance_binding":
            arkret_models_crypto::MlsGovernanceBindingPayload::realm(realm_id.clone(), None, 0, 0, 0)
                .unwrap(),
        "created_at": arkret_canonical::format_timestamp_canonical(at),
    })
}

fn mls_commit_payload(
    realm_id: &RealmId,
    base: &arkret_wire::EventId,
    previous_epoch: u64,
    commit_bytes: &[u8],
) -> serde_json::Value {
    let binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        realm_id.clone(),
        Some(base.clone()),
        previous_epoch,
        previous_epoch + 1,
        0,
    )
    .unwrap();
    let envelope = arkret_models_crypto::MlsCommitEnvelope {
        group_id: binding.mls_group_id().unwrap(),
        epoch: previous_epoch + 1,
        commit: arkret_wire::base64url::base64url_encode(commit_bytes),
        commit_digest: Hash::new(arkret_canonical::sha256_digest(commit_bytes)).unwrap(),
        ratchet_tree: None,
    };
    serde_json::to_value(
        arkret_models_crypto::MlsCommitPayload::new(base.clone(), 0, &envelope, binding).unwrap(),
    )
    .unwrap()
}

/// One MLS ciphertext Message body frozen at `epoch` over `group_state_ref`.
fn ciphertext(
    strand_id: &arkret_wire::StrandId,
    epoch: u64,
    group_state_ref: &arkret_wire::EventId,
) -> serde_json::Value {
    serde_json::json!({
        "strand_id": strand_id,
        "track_name": "discussion",
        "encrypted_content": arkret_models_crypto::EncryptedEnvelope {
            version: "1.0".to_owned(),
            content_type: "application/vnd.arkret.message+json".to_owned(),
            encryption_context: arkret_models_crypto::EncryptedEnvelopeEncryptionContext::standard(
                epoch,
                group_state_ref.clone(),
            ),
            ciphertext: "Y2lwaGVydGV4dA".to_owned(),
        },
    })
}

/// The peer's durable acceptance of its Welcome of `commit`, as the claim,
/// Welcome queue and consume services leave it (their own suites cover how):
/// the claim ledger row consumed, bound to the Welcome, queued to the peer.
async fn consume_peer_welcome(
    pool: &PgPool,
    station: &DidCoreId,
    commit: &soland_storage::EventCommitRequest,
    peer: &ActorId,
) {
    let claim_id = format!("ak:keypackage_claim:{}", uuid::Uuid::now_v7());
    let welcome_id = format!("ak:mls_welcome_delivery:{}", uuid::Uuid::now_v7());
    let request_id = uuid::Uuid::now_v7().simple().to_string();
    let now = chrono::Utc::now();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO peer_keypackage_claims \
         (source_id,claim_request_id,request_digest,key_package_use,keypackage_id,outcome, \
          terminal_receipt,consume_receipt,claim_expires_at_unix_ms,expires_at,state,updated_at) \
         VALUES ($1,$2,$3,'single_use',NULL,'{}'::jsonb,NULL,'{}'::jsonb,$4,$5,'consumed',$6)",
    )
    .bind::<Text, _>(station.as_str())
    .bind::<Text, _>(&request_id)
    .bind::<Text, _>(format!("sha256:{}", "6".repeat(64)))
    .bind::<BigInt, _>(now.timestamp_millis() + 3_600_000)
    .bind::<BigInt, _>(now.timestamp() + 86_400)
    .bind::<BigInt, _>(now.timestamp())
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO mls_welcome_deliveries \
         (welcome_id,realm_id,commit_event_pk,recipient,recipient_endpoint_kind,recipient_device_id,\
          recipient_verification_method,recipient_authorization_event_ref,\
          recipient_device_authorization,keypackage_claim_ref,delivery_json,state,delivered_at) \
         SELECT $1,$2,pk,$3,'device','device-1',NULL,$4,'{}'::jsonb,$5,$6,'delivered',now() \
         FROM canonical_events WHERE envelope->>'event_id'=$7",
    )
    .bind::<Text, _>(&welcome_id)
    .bind::<Text, _>(commit.authority_commit.event.realm_id.as_str())
    .bind::<Text, _>(peer.signing_principal_id().as_str())
    .bind::<Text, _>(unique_event_id("peer-device").as_str())
    .bind::<Text, _>(&claim_id)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({ "recipient_actor_id": peer }))
    .bind::<Text, _>(commit.authority_commit.event.event_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO keypackage_claim_welcome_bindings \
         (claim_id,source_id,claim_request_id,welcome_id,welcome_digest,commit_event_ref) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind::<Text, _>(&claim_id)
    .bind::<Text, _>(station.as_str())
    .bind::<Text, _>(&request_id)
    .bind::<Text, _>(&welcome_id)
    .bind::<Text, _>(format!("sha256:{}", "7".repeat(64)))
    .bind::<Text, _>(commit.authority_commit.event.event_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
}

/// Every row an admitted Direct Conversation Event can leave for `realm_id`.
async fn dc_footprint(pool: &PgPool, realm_id: &RealmId) -> [i64; 8] {
    let [authorities, events, commits, slots, members] = footprint(pool, realm_id).await;
    [
        authorities,
        events,
        commits,
        slots,
        members,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM message_revision_current_results WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COALESCE(SUM(jsonb_array_length(value->'endorsements')),0)::bigint AS count \
             FROM direct_conversation_binding_current_results WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM mls_group_current_results WHERE realm_id=$1",
            realm_id,
        )
        .await,
    ]
}

#[derive(diesel::QueryableByName)]
struct GroupStateRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    current_exact_pair: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    initial_exact_pair_group_state_ref: Option<String>,
}

async fn group_state(pool: &PgPool, realm_id: &RealmId) -> (bool, Option<String>) {
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT current_exact_pair,initial_exact_pair_group_state_ref \
         FROM direct_conversation_group_states WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<GroupStateRow>(&mut *conn)
    .await
    .unwrap();
    (
        row.current_exact_pair,
        row.initial_exact_pair_group_state_ref,
    )
}

/// `contact-and-direct-conversation.md` §7.2, §8.3 and §8.4 at the accepting
/// cut: the root's materialization mask admits the one group Genesis; the
/// bootstrap source's provisional phase lets only the founder send and Add the
/// peer; once the peer's Welcome of the first exact-pair Commit is durable,
/// the completion phase admits only binding endorsements, whose integrity is
/// checked against the founding facts and that Commit; after the first
/// endorsement both phases exit and every participant write names the binding
/// under the participant source, with the pair's Contact still granting
/// `direct_message`. A request authored against an older cut is re-decided
/// at the current one, and every refusal writes nothing.
#[tokio::test]
async fn participant_authority_follows_the_group_and_binding_at_the_cut_with_zero_write_refusals() {
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
    let create_ref = unit.transactions[0].event.event_id.clone();
    let founder = pair.founder_actor();
    let peer = pair.peer_actor();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let refused = async |request: &soland_storage::EventCommitRequest| {
        let before = dc_footprint(&pool, &realm_id).await;
        let code = refusal_code(uow.commit_event(request.clone()).await);
        assert_eq!(dc_footprint(&pool, &realm_id).await, before);
        code
    };

    // realm-and-space.md §2.5 row 5: the founding create fixed history.
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) AS count FROM realm_bootstrap_current_results \
             WHERE realm_id=$1 AND result_family='realm_history_access' AND value='\"since_join\"'",
            &realm_id,
        )
        .await,
        1
    );

    // A bootstrap Message before the group Genesis has no provisional phase.
    let early = cited(
        &unit.transactions[3],
        EventKind::MessageCreate,
        founder.clone(),
        ciphertext(&facts.main_strand_id, 0, &create_ref),
        Cites::Bootstrap(&create_ref),
    );
    assert_eq!(
        refused(&early).await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );

    // The root's materialization mask admits the scope's one Genesis.
    let genesis = with_group(
        cited(
            &unit.transactions[3],
            EventKind::MlsGenesis,
            founder.clone(),
            mls_genesis_payload(&realm_id, at),
            Cites::Nothing,
        ),
        None,
        0,
        &[&founder],
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    assert_eq!(group_state(&pool, &realm_id).await, (false, None));

    // Provisional: the founder alone sends under the bootstrap source.
    let provisional = cited(
        &genesis.authority_commit,
        EventKind::MessageCreate,
        founder.clone(),
        ciphertext(&facts.main_strand_id, 0, &genesis_ref),
        Cites::Bootstrap(&create_ref),
    );
    uow.commit_event(provisional.clone()).await.unwrap();
    let head = provisional.authority_commit.clone();
    for denied in [
        cited(
            &head,
            EventKind::MessageCreate,
            founder.clone(),
            ciphertext(&facts.main_strand_id, 0, &genesis_ref),
            Cites::Nothing,
        ),
        cited(
            &head,
            EventKind::MessageCreate,
            founder.clone(),
            ciphertext(&facts.main_strand_id, 0, &genesis_ref),
            Cites::Bootstrap(&genesis_ref),
        ),
        cited(
            &head,
            EventKind::MessageCreate,
            peer.clone(),
            ciphertext(&facts.main_strand_id, 0, &genesis_ref),
            Cites::Bootstrap(&create_ref),
        ),
    ] {
        assert_eq!(
            refused(&denied).await,
            ConflictCode::DirectConversationParticipantAuthorityDenied
        );
    }

    // The founder's Add makes the roster exactly the pair: the first such
    // Commit is the binding's initial group state.
    let add = with_group(
        cited(
            &head,
            EventKind::MlsCommit,
            founder.clone(),
            mls_commit_payload(&realm_id, &genesis_ref, 0, b"add-peer"),
            Cites::Bootstrap(&create_ref),
        ),
        Some((&genesis_ref, 0)),
        1,
        &[&founder, &peer],
    );
    uow.commit_event(add.clone()).await.unwrap();
    let add_ref = add.authority_commit.event.event_id.clone();
    assert_eq!(
        group_state(&pool, &realm_id).await,
        (true, Some(add_ref.to_string()))
    );

    let basis = {
        #[derive(diesel::QueryableByName)]
        struct BasisRow {
            #[diesel(sql_type = diesel::sql_types::Jsonb)]
            authorization_basis: serde_json::Value,
        }
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT authorization_basis FROM direct_conversation_founding_slots WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<BasisRow>(&mut *conn)
        .await
        .unwrap()
        .authorization_basis
    };
    // The canonical basis is the round's accepted request and accept heads.
    assert_eq!(basis["kind"], "accepted_contact");
    assert_eq!(basis["event_refs"].as_array().unwrap().len(), 2);
    let endorsement = |group_state_ref: &arkret_wire::EventId, seconds: i64| {
        serde_json::json!({
            "pair_key": facts.pair_key,
            "unordered_participant_ids": [founder.clone(), peer.clone()],
            "realm_id": realm_id,
            "main_strand_id": facts.main_strand_id,
            "founding_unit_digest": facts.founding_unit_digest,
            "authorization_basis": basis,
            "initial_exact_pair_group_state_ref": group_state_ref,
            "created_at": arkret_canonical::format_timestamp_canonical(
                at + chrono::Duration::seconds(seconds),
            ),
        })
    };

    // Until the peer's Welcome is durable the Realm stays provisional: no
    // endorsement, while the founder still sends at the new epoch.
    let early_binding = cited(
        &add.authority_commit,
        EventKind::DirectConversationBound,
        peer.clone(),
        endorsement(&add_ref, 1),
        Cites::Bootstrap(&create_ref),
    );
    assert_eq!(
        refused(&early_binding).await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );
    let stale_provisional = cited(
        &add.authority_commit,
        EventKind::MessageCreate,
        founder.clone(),
        ciphertext(&facts.main_strand_id, 1, &add_ref),
        Cites::Bootstrap(&create_ref),
    );
    let later_provisional = cited(
        &add.authority_commit,
        EventKind::MessageCreate,
        founder.clone(),
        ciphertext(&facts.main_strand_id, 1, &add_ref),
        Cites::Bootstrap(&create_ref),
    );
    uow.commit_event(later_provisional.clone()).await.unwrap();

    // Completion: once the peer consumed its Welcome, only an endorsement is
    // admitted. The provisional Message authored at the older cut is re-decided
    // at this one and refused.
    consume_peer_welcome(&pool, &pair.station, &add, &peer).await;
    let head = later_provisional.authority_commit.clone();
    let replayed = ordinary_realm::request_for_event(
        &head,
        stale_provisional.authority_commit.event.clone(),
        head.commit.committed_at,
    );
    assert_eq!(
        refused(&replayed).await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );
    for (mutated, code) in [
        (
            endorsement(&genesis_ref, 1),
            ConflictCode::DirectConversationBindingInvalid,
        ),
        (
            {
                let mut payload = endorsement(&add_ref, 1);
                payload["pair_key"] = serde_json::json!(fixture_hash('9'));
                payload
            },
            ConflictCode::DirectConversationBindingInvalid,
        ),
        (
            {
                let mut payload = endorsement(&add_ref, 1);
                payload["authorization_basis"]["event_refs"][0] =
                    serde_json::json!(unique_event_id("other-head"));
                payload
            },
            ConflictCode::DirectConversationBindingInvalid,
        ),
    ] {
        let request = cited(
            &head,
            EventKind::DirectConversationBound,
            peer.clone(),
            mutated,
            Cites::Bootstrap(&create_ref),
        );
        assert_eq!(refused(&request).await, code);
    }
    let peer_endorsement = cited(
        &head,
        EventKind::DirectConversationBound,
        peer.clone(),
        endorsement(&add_ref, 1),
        Cites::Bootstrap(&create_ref),
    );
    uow.commit_event(peer_endorsement.clone()).await.unwrap();
    let binding_ref = peer_endorsement.authority_commit.event.event_id.clone();

    // Found: a compatible endorsement by the other participant accumulates;
    // the bootstrap source no longer carries a Message.
    let founder_endorsement = cited(
        &peer_endorsement.authority_commit,
        EventKind::DirectConversationBound,
        founder.clone(),
        endorsement(&add_ref, 2),
        Cites::Bootstrap(&create_ref),
    );
    uow.commit_event(founder_endorsement.clone()).await.unwrap();
    let head = founder_endorsement.authority_commit.clone();
    assert_eq!(dc_footprint(&pool, &realm_id).await[6], 2);
    let durable = PgEventStore { pool: pool.clone() }
        .direct_conversation_durable_state(TRUST_DOMAIN, facts.pair_key.as_str())
        .await
        .unwrap()
        .expect("accepted founding slot is durable");
    assert_eq!(durable.founding_slot.realm_id, realm_id.as_str());
    assert_eq!(durable.group_state_ref.as_ref(), Some(&add_ref));
    assert_eq!(durable.group_current_exact_pair, Some(true));
    assert_eq!(durable.members.len(), 2);
    assert!(
        durable
            .members
            .iter()
            .all(|member| member.membership == "join")
    );
    assert_eq!(durable.binding.unwrap().endorsements.len(), 2);
    assert_eq!(
        refused(&cited(
            &head,
            EventKind::MessageCreate,
            founder.clone(),
            ciphertext(&facts.main_strand_id, 1, &add_ref),
            Cites::Bootstrap(&create_ref),
        ))
        .await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );
    // The participant source needs an accepted endorsement as its ref.
    assert_eq!(
        refused(&cited(
            &head,
            EventKind::MessageCreate,
            peer.clone(),
            ciphertext(&facts.main_strand_id, 1, &add_ref),
            Cites::Participant(&add_ref),
        ))
        .await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );
    // The technical root carries no masked action once found.
    let second_genesis = with_group(
        cited(
            &head,
            EventKind::MlsGenesis,
            founder.clone(),
            mls_genesis_payload(&realm_id, at),
            Cites::Nothing,
        ),
        None,
        0,
        &[&founder],
    );
    assert_eq!(
        refused(&second_genesis).await,
        ConflictCode::DirectConversationRootMaskViolation
    );

    // Both participants send under the binding, citing either endorsement.
    let peer_message = cited(
        &head,
        EventKind::MessageCreate,
        peer.clone(),
        ciphertext(&facts.main_strand_id, 1, &add_ref),
        Cites::Participant(&binding_ref),
    );
    uow.commit_event(peer_message.clone()).await.unwrap();
    let founder_message = cited(
        &peer_message.authority_commit,
        EventKind::MessageCreate,
        founder.clone(),
        ciphertext(&facts.main_strand_id, 1, &add_ref),
        Cites::Participant(&founder_endorsement.authority_commit.event.event_id),
    );
    uow.commit_event(founder_message.clone()).await.unwrap();
    let head = founder_message.authority_commit.clone();

    // Membership repair stays on the same stable Realm.  A joined
    // participant may leave only through the participant source; while left,
    // participant authority is inactive and only the repair source can carry
    // that same participant's `leave -> join` edge.
    let leave = cited(
        &head,
        EventKind::MemberState,
        peer.clone(),
        serde_json::json!({"realm_id":realm_id,"member_id":peer,"membership":"leave"}),
        Cites::Participant(&binding_ref),
    );
    uow.commit_event(leave.clone()).await.unwrap();
    assert_eq!(
        refused(&cited(
            &leave.authority_commit,
            EventKind::MemberState,
            peer.clone(),
            serde_json::json!({"realm_id":realm_id,"member_id":peer,"membership":"join"}),
            Cites::Participant(&binding_ref),
        ))
        .await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );
    let rejoin = cited(
        &leave.authority_commit,
        EventKind::MemberState,
        peer.clone(),
        serde_json::json!({"realm_id":realm_id,"member_id":peer,"membership":"join"}),
        Cites::Repair(&binding_ref),
    );
    uow.commit_event(rejoin.clone()).await.unwrap();
    let head = rejoin.authority_commit.clone();

    // A withdrawn directional Contact stops every send at the next cut.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE contacts SET tombstone_event_ref=request_event_ref \
         WHERE (requester_id=$1 AND target_id=$2) OR (requester_id=$2 AND target_id=$1)",
    )
    .bind::<Text, _>(founder.to_string())
    .bind::<Text, _>(peer.to_string())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        refused(&cited(
            &head,
            EventKind::MessageCreate,
            peer.clone(),
            ciphertext(&facts.main_strand_id, 1, &add_ref),
            Cites::Participant(&binding_ref),
        ))
        .await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );
}
