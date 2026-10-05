//! An ordinary collaboration Realm admitted through its registered units.
//!
//! Realm-scope Events such as `ak.message.create` and
//! `ak.self.moderation.report` are admitted only at a confirmed current cut:
//! the Realm was created through the ordinary bootstrap unit, its author is a
//! confirmed joined member, and a Message names an active discussion Strand.
//! A storage fixture that needs such an Event therefore builds that cut the
//! way production does -- the bootstrap unit, then `ak.strand.create` and
//! `ak.realm.set_default_strand` through the Event unit of work -- instead of
//! seeding current rows by hand.
//!
//! Signatures are structural-only; these fixtures exercise the storage
//! boundary, not signature verification.

use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CurrentRealmAuthority, EventCommitRequest,
    EventCommitUnitOfWork, OrdinaryRealmBootstrapCommitUnit,
};
use soland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};

#[path = "human_profile.rs"]
#[allow(dead_code)]
pub mod human_profile;

/// The founder every fixture Realm is created by.
pub const FOUNDER: &str = "ak:did_core:web:ordinary-founder.example";
/// The Station that governs every fixture Realm.
pub const STATION: &str = "ak:did_core:web:ordinary-station.example";

pub fn founder() -> arkret_wire::DidCoreId {
    arkret_wire::DidCoreId::new(FOUNDER).unwrap()
}

pub fn station() -> arkret_wire::DidCoreId {
    arkret_wire::DidCoreId::new(STATION).unwrap()
}

/// One account-authored Event carrying its structural producer proof.
pub fn event(
    kind: arkret_wire::EventKind,
    scope_ref: arkret_wire::ScopeRef,
    actor: &arkret_wire::DidCoreId,
    station: &arkret_wire::DidCoreId,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    event_for_actor(
        kind,
        scope_ref,
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(actor.clone(), station.clone())),
        payload,
        at,
    )
}

/// One Event by the exact `actor`, carrying its structural producer proof.
pub fn event_for_actor(
    kind: arkret_wire::EventKind,
    scope_ref: arkret_wire::ScopeRef,
    actor: arkret_wire::ActorId,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let signer = actor.signing_principal_id().clone();
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        scope_ref,
        actor,
        payload,
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
        verification_method: arkret_wire::DidUrl::new(format!(
            "did:{}#key",
            signer.as_str().strip_prefix("ak:did_core:").unwrap()
        ))
        .unwrap(),
        event_digest: digest.clone(),
        created_at: arkret_canonical::normalize_timestamp_canonical(at),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

/// The current Station's detached signature over a fixture `RealmCommit`.
pub fn signature(
    station: &arkret_wire::DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::DetachedObjectSignature {
    // A did:webvh Core DID keeps only the SCID; any host projects back to it.
    let did = match station.as_str().strip_prefix("ak:did_core:webvh:") {
        Some(scid) => format!("did:webvh:{scid}:station.example"),
        None => station.as_str().replace("ak:did_core:", "did:"),
    };
    signature_for_did(&arkret_wire::Did::new(did).unwrap(), at)
}

pub fn signature_for_did(
    station_did: &arkret_wire::Did,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::DetachedObjectSignature {
    arkret_wire::DetachedObjectSignature {
        context: arkret_wire::DetachedSignatureContext::RealmCommit,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: arkret_wire::DidUrl::new(format!("{station_did}#authority")).unwrap(),
        signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
        created_at: at,
        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
    }
}

/// The ordinary bootstrap unit for a fresh Realm.
///
/// `seed` becomes the genesis salt, so every seed names its own Realm even
/// when two fixtures are built within one millisecond. The governing Station
/// is declared the Realm's plaintext-visible service: a local plain-text
/// Message needs that policy, and a franking notary is that service.
pub fn bootstrap_unit(seed: &str) -> OrdinaryRealmBootstrapCommitUnit {
    bootstrap_unit_with_join_rule(seed, "invite")
}

/// Build the same accepted-state fixture for a test Station whose service DID
/// was generated from its current `did:webvh` registration identity.
pub fn bootstrap_unit_for_station(
    seed: &str,
    governing_station: &arkret_wire::DidCoreId,
    governing_did: &arkret_wire::Did,
) -> OrdinaryRealmBootstrapCommitUnit {
    bootstrap_unit_with_join_rule_for_station(
        seed,
        "invite",
        "since_join",
        None,
        governing_station,
        Some(governing_did),
    )
}

/// [`bootstrap_unit`] whose initial and typed join rule is `join_rule`.
pub fn bootstrap_unit_with_join_rule(
    seed: &str,
    join_rule: &str,
) -> OrdinaryRealmBootstrapCommitUnit {
    bootstrap_unit_with_join_rule_for_station(seed, join_rule, "since_join", None, &station(), None)
}

/// Build a formal bootstrap for a local Station and its chosen history policy.
pub fn bootstrap_unit_with_history_for_station(
    seed: &str,
    join_rule: &str,
    history_access: &str,
    governing_station: &arkret_wire::DidCoreId,
    governing_did: &arkret_wire::Did,
) -> OrdinaryRealmBootstrapCommitUnit {
    bootstrap_unit_with_join_rule_for_station(
        seed,
        join_rule,
        history_access,
        None,
        governing_station,
        Some(governing_did),
    )
}

/// A formal ordinary Realm whose founder is the exact accepted Account.
pub fn bootstrap_unit_for_account(
    seed: &str,
    account: &arkret_wire::AccountId,
    governing_did: &arkret_wire::Did,
) -> OrdinaryRealmBootstrapCommitUnit {
    bootstrap_unit_with_join_rule_for_station(
        seed,
        "public",
        "since_join",
        Some(&account.principal_id),
        &account.station_id,
        Some(governing_did),
    )
}

pub fn bootstrap_unit_with_history_for_account(
    seed: &str,
    join_rule: &str,
    history_access: &str,
    account: &arkret_wire::AccountId,
    governing_did: &arkret_wire::Did,
) -> OrdinaryRealmBootstrapCommitUnit {
    bootstrap_unit_with_join_rule_for_station(
        seed,
        join_rule,
        history_access,
        Some(&account.principal_id),
        &account.station_id,
        Some(governing_did),
    )
}

fn bootstrap_unit_with_join_rule_for_station(
    seed: &str,
    join_rule: &str,
    history_access: &str,
    founding_principal: Option<&arkret_wire::DidCoreId>,
    governing_station: &arkret_wire::DidCoreId,
    governing_did: Option<&arkret_wire::Did>,
) -> OrdinaryRealmBootstrapCommitUnit {
    use arkret_models_collaboration::authority_commit::{
        OrdinaryRealmBootstrapUnitKind, OrdinaryRealmBootstrapUnitSubmission,
        SelfAuthoritySubmitRequest,
    };

    let at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let actor = founding_principal.cloned().unwrap_or_else(founder);
    let station = governing_station.clone();
    let genesis_salt =
        arkret_canonical::base64url_encode(arkret_canonical::sha256_bytes(seed.as_bytes()));
    let genesis = event(
        arkret_wire::EventKind::RealmCreate,
        arkret_wire::ScopeRef::RealmGenesis,
        &actor,
        &station,
        serde_json::json!({"object":{
            "schema":"ak.schema.realm_genesis.v1",
            "purpose":"collaboration",
            "genesis_salt":genesis_salt,
            "trust_domain":"ak:trust_domain:ordinary.example",
            "security_class":"high_assurance",
            "governance_station_id":station,
            "initial_join_rule":join_rule,
            "initial_history_access":history_access,
            "initial_discoverability":"invite_only"
        }}),
        at,
    );
    let realm_id = genesis.realm_id.clone();
    let creator = genesis.actor_id.clone();
    let realm_scope = || arkret_wire::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let mut events = vec![genesis];
    let kinds = vec![
        (
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Fixture Realm"}),
        ),
        (
            arkret_wire::EventKind::RealmPolicyBundle,
            serde_json::json!({"policy_revision":1,"federation_policy":"closed"}),
        ),
        (
            arkret_wire::EventKind::RealmJoinRule,
            serde_json::json!({"value":join_rule}),
        ),
        (
            arkret_wire::EventKind::RealmHistoryAccess,
            serde_json::json!({"from":null,"to":history_access}),
        ),
        (
            arkret_wire::EventKind::RealmDiscovery,
            serde_json::json!({"value":{"discoverability":"invite_only"}}),
        ),
        (
            arkret_wire::EventKind::RealmPlaintextVisibleServices,
            serde_json::json!({"services":[{
                "service_id":station,
                "service_kind":"station",
                "data_classes":["message_content"],
                "purposes":["test"],
                "visibility":"private_plaintext"
            }]}),
        ),
        (
            arkret_wire::EventKind::MemberState,
            serde_json::json!({"member_id":creator,"membership":"join"}),
        ),
    ];
    for (kind, payload) in kinds {
        events.push(event(kind, realm_scope(), &actor, &station, payload, at));
    }
    let authority = CurrentRealmAuthority {
        realm_id: realm_id.clone(),
        generation: 0,
        service_id: station.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            events[0].event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let mut previous = None;
    let transactions = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let commit_id = arkret_wire::RealmCommitId::from_digest(
                arkret_canonical::sha256_bytes(format!("{}:{index}", event.event_id).as_bytes()),
            );
            let transaction = AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: event.clone(),
                commit: arkret_wire::RealmCommit {
                    producer_signer_fact_digest: None,
                    commit_id: commit_id.clone(),
                    realm_id: realm_id.clone(),
                    stream_ref: arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    },
                    stream_position: index as u64,
                    previous_commit_ref: previous.clone(),
                    event_ref: event.event_id.clone(),
                    governance_generation: 0,
                    authority_ref: authority.authority_ref.clone(),
                    committed_at: at,
                    signature: governing_did
                        .map_or_else(|| signature(&station, at), |did| signature_for_did(did, at)),
                },
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            };
            previous = Some(commit_id);
            transaction
        })
        .collect();
    let submission = OrdinaryRealmBootstrapUnitSubmission {
        unit_kind: OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
        events: events
            .into_iter()
            .map(arkret_wire::EventAdmissionSubmission::new)
            .collect(),
    };
    let exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(submission.clone()),
    )
    .unwrap();
    OrdinaryRealmBootstrapCommitUnit {
        submission,
        exact_request_body,
        transactions,
    }
}

/// The next Realm-stream Event after `previous`, as one Event unit of work
/// request that carries its projection record.
///
/// `previous` is either the last bootstrap transaction or the last request
/// this fixture built; both name the stream head the new Event extends.
pub fn next_request(
    previous: &AuthorityCommitTransaction,
    kind: arkret_wire::EventKind,
    actor: &arkret_wire::DidCoreId,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> EventCommitRequest {
    let account = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        actor.clone(),
        previous.expected_authority.service_id.clone(),
    ));
    next_request_for_actor(previous, kind, account, payload, at)
}

/// [`next_request`] for an Event by the exact `actor`, such as the Station's
/// own service-authored franking proof.
pub fn next_request_for_actor(
    previous: &AuthorityCommitTransaction,
    kind: arkret_wire::EventKind,
    actor: arkret_wire::ActorId,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> EventCommitRequest {
    let event = event_for_actor(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: previous.event.realm_id.clone(),
        },
        actor,
        payload,
        at,
    );
    let event = if let Some(fact) = previous
        .producer_signer_fact
        .as_ref()
        .filter(|fact| fact.actor == event.actor_id)
    {
        human_profile::sign_original_device(event, fact.verification_method.clone())
    } else {
        event
    };
    request_for_event(previous, event, at)
}

/// Re-derive `event`'s content-bound identity and structural producer proof
/// after a caller changed its signed content.
pub fn reseal(event: &mut arkret_wire::Event) {
    event
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let digest = arkret_wire::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let proof = event.producer_proof.as_mut().unwrap();
    proof.event_digest = digest.clone();
    proof.jws = arkret_wire::test_support::structural_only_detached_jws(&digest);
}

/// The unit of work request committing the exact `event` on the Realm stream
/// right after `previous`.
pub fn request_for_event(
    previous: &AuthorityCommitTransaction,
    event: arkret_wire::Event,
    at: chrono::DateTime<chrono::Utc>,
) -> EventCommitRequest {
    let realm_id = previous.event.realm_id.clone();
    let station = previous.expected_authority.service_id.clone();
    let mut commit = arkret_wire::RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            format!("{}:{}", event.event_id, previous.commit.stream_position + 1).as_bytes(),
        )),
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position: previous.commit.stream_position + 1,
        previous_commit_ref: Some(previous.commit.commit_id.clone()),
        event_ref: event.event_id.clone(),
        governance_generation: previous.expected_authority.generation,
        authority_ref: previous.expected_authority.authority_ref.clone(),
        committed_at: at,
        signature: signature(&station, at),
    };
    let fact = previous
        .producer_signer_fact
        .as_ref()
        .filter(|fact| fact.actor == event.actor_id)
        .cloned()
        .map(|mut fact| {
            fact.event_id = event.event_id.clone();
            fact
        });
    commit.producer_signer_fact_digest = fact.as_ref().map(|f| f.digest().unwrap());
    if fact.is_some() {
        let identity =
            arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"])
                .unwrap();
        commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&identity).unwrap(),
        ));
        commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap(),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            previous.commit.signature.verification_method.clone(),
            at,
            &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
        )
        .unwrap();
    }
    let projection = soland_storage::ProjectionEventRecord {
        event_id: event.event_id.to_string(),
        realm_id: realm_id.to_string(),
        event_kind: event.kind.as_str().to_owned(),
        operation_kind: "create".to_owned(),
        operation_id: None,
        sender: Some(event.actor_id.to_string()),
        payload: serde_json::to_value(&event.payload).unwrap(),
        created_at: event.created_at,
        received_at: at,
    };
    let record = soland_storage::CanonicalEventRecord {
        event_id: event.event_id.to_string(),
        actor_id: event.actor_id.to_string(),
        realm_id: Some(realm_id.to_string()),
        kind: event.kind.as_str().to_owned(),
        schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        canonical_digest: event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
        canonical_bytes: arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap())
            .unwrap(),
        envelope: serde_json::to_value(&event).unwrap(),
        received_at: at,
    };
    EventCommitRequest {
        authority_commit: AuthorityCommitTransaction {
            expected_authority: previous.expected_authority.clone(),
            event,
            commit,
            producer_signer_fact: fact,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        },
        self_producer_guard: None,
        applet_producer_guard: None,
        widget_token_gate: None,
        forwarded_producer_evidence: None,
        forwarded_agent_producer: None,
        agent_deployment_ceiling:
            arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
        event: record,
        parent_membership_admission: None,
        contact_projection: None,

        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: vec![projection],
        idempotency: None,
        outbox: Vec::new(),
        realm_fanout_source: None,
    }
}

/// A plain-text discussion Message payload the bounded Message writer admits.
pub fn message_payload(strand_id: &arkret_wire::StrandId, body: &str) -> serde_json::Value {
    serde_json::json!({
        "strand_id":strand_id,
        "track_name":"discussion",
        "content":{"kind":"ak.content.text","body":body,"format":"plain"}
    })
}

/// A directly authored self moderation report on `target_ref`.
pub fn report_payload(
    realm_id: &arkret_wire::RealmId,
    target_ref: &str,
    reporter: &arkret_wire::DidCoreId,
) -> serde_json::Value {
    serde_json::json!({
        "realm_id": realm_id,
        "target_ref": target_ref,
        "report_reason_code": "spam",
        "reporter_id": reporter,
        "provenance": "self"
    })
}

/// An admitted ordinary Realm whose default discussion Strand is active.
pub struct Discussion {
    pub unit: OrdinaryRealmBootstrapCommitUnit,
    pub strand_id: arkret_wire::StrandId,
    /// The Realm-stream head after the default Strand was set.
    pub head: EventCommitRequest,
}

impl Discussion {
    pub fn realm_id(&self) -> arkret_wire::RealmId {
        self.unit.transactions[0].event.realm_id.clone()
    }

    pub fn committed_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.unit.transactions[0].commit.committed_at
    }

    /// The founder's next plain-text Message after `previous`.
    pub fn message_after(
        &self,
        previous: &AuthorityCommitTransaction,
        body: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> EventCommitRequest {
        next_request(
            previous,
            arkret_wire::EventKind::MessageCreate,
            self.unit.transactions[0]
                .event
                .actor_id
                .signing_principal_id(),
            message_payload(&self.strand_id, body),
            at,
        )
    }
}

/// Admit an ordinary Realm, create its discussion Strand and make it the
/// default -- the confirmed cut a local Message or self report needs.
pub async fn open_discussion(pool: &PgPool, seed: &str) -> Discussion {
    open_discussion_unit(pool, bootstrap_unit(seed)).await
}

pub async fn open_discussion_with_history(pool: &PgPool, seed: &str, history: &str) -> Discussion {
    let unit = bootstrap_unit_with_history_for_station(
        seed,
        "public",
        history,
        &station(),
        &arkret_wire::Did::new("did:web:ordinary-station.example").unwrap(),
    );
    open_discussion_unit(pool, unit).await
}

pub async fn open_discussion_for_station(
    pool: &PgPool,
    seed: &str,
    station: &arkret_wire::DidCoreId,
    did: &arkret_wire::Did,
) -> Discussion {
    open_discussion_unit(pool, bootstrap_unit_for_station(seed, station, did)).await
}

/// Admit the founder's real PCR and Human Profile before opening discussion.
pub async fn open_human_discussion(pool: &PgPool, seed: &str) -> Discussion {
    let account = human_profile::admit(pool, &station(), "ordinary-founder").await;
    let unit = bootstrap_unit_for_account(seed, &account, &human_profile::station_did(&station()));
    open_discussion_unit(pool, unit).await
}

async fn open_discussion_unit(pool: &PgPool, unit: OrdinaryRealmBootstrapCommitUnit) -> Discussion {
    unit.validate().unwrap();
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .expect("admit ordinary Realm bootstrap");
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let at = last.commit.committed_at;
    let realm_id = last.event.realm_id.clone();
    let creator = last.event.actor_id.clone();
    let strand = next_request(
        last,
        arkret_wire::EventKind::StrandCreate,
        creator.signing_principal_id(),
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Fixture discussion"},
            "state":"active",
            "created_by":creator,
            "created_at":arkret_canonical::format_timestamp_canonical(at),
        }}),
        at,
    );
    uow.commit_event(strand.clone())
        .await
        .expect("create the discussion Strand");
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = next_request(
        &strand.authority_commit,
        arkret_wire::EventKind::RealmSetDefaultStrand,
        creator.signing_principal_id(),
        serde_json::json!({
            "realm_id": realm_id,
            "strand_id": strand_id,
            "expected_default_strand_id": null,
        }),
        at,
    );
    uow.commit_event(default.clone())
        .await
        .expect("make the discussion Strand the Realm default");
    Discussion {
        unit,
        strand_id,
        head: default,
    }
}

#[derive(diesel::QueryableByName)]
struct ParentMembershipRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    current_commit_id: String,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    current_stream_position: i64,
}

/// The exact typed revision of `actor`'s current parent Realm `member_state`,
/// read from the durable current -- the value a Circle join signs as its
/// `parent_membership_revision` (`circle.md` section 9.1).
pub async fn parent_membership_revision(
    pool: &PgPool,
    realm_id: &arkret_wire::RealmId,
    actor: &arkret_wire::ActorId,
) -> serde_json::Value {
    use diesel_async::RunQueryDsl as _;
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT current_commit_id,current_stream_position FROM member_state_current_results \
         WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<diesel::sql_types::Text, _>(realm_id.as_str())
    .bind::<diesel::sql_types::Text, _>(actor.to_string())
    .get_result::<ParentMembershipRow>(&mut conn)
    .await
    .expect("the actor has a parent Realm member_state current");
    serde_json::json!({
        "commit_id": row.current_commit_id,
        "stream_position": row.current_stream_position,
    })
}
