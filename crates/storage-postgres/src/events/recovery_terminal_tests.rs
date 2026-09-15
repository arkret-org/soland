//! Real-PostgreSQL acceptance for `security-transactions.md` section 2.3: the
//! terminal `commit_recovery_unit` step is one database transaction covering the
//! two Events, the first-generation Seal, the recovery session consumption and
//! the security transaction terminal result.
//!
//! The fixture is deliberately storage-shaped. B-model admission, signatures and
//! plan-to-Event cross binding belong to the HTTP layer; what is under test here
//! is the durable boundary, which is the only place "nothing observable before
//! the commit" can be asserted by machine instead of argued from a call graph.

use std::collections::BTreeSet;
use std::sync::Arc;

use arkret_canonical::DigestSuite;
use arkret_identifiers::{CellRef, Hash, Hlc, RealmId, SealId};
use arkret_state::state::CellStateRegistry;
use arkret_state::state::store::{
    AcklessSelfPrincipalIngress, ControlProposalIngress, ControlUnitIngressMember,
};
use arkret_state::state_model::StateWrite;
use arkret_state::state_model::ordered_log::IssuedOp;
use arkret_wire::{
    AccountId, ActorId, EventKind, LatticeOpType, ScopeRef, Seal, SealSignature,
    SecurityTransaction,
};
use diesel::sql_types::{BigInt, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::json;
use soland_storage::{
    CanonicalEventRecord, EventStore, RecoveryTerminalCommitWrite, SecurityTransactionRecord,
    SecurityTransactionStepOutcomeRecord,
};

use crate::state_resolution::{StateResolutionStores, build_state_resolution_stores};

const SUITE: DigestSuite = DigestSuite::Sha256;
const CONTINUE_BYTES: &[u8] = b"{\"canonical\":\"commit_recovery_unit\"}";

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

#[derive(QueryableByName)]
struct TextRow {
    #[diesel(sql_type = Text)]
    value: String,
}

fn fixture_time() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-09-15T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

fn issued(write: StateWrite) -> IssuedOp {
    IssuedOp {
        issuer_id: ActorId::account(AccountId::new(
            arkret_wire::project_did_to_core_id(
                &arkret_wire::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap(),
            )
            .unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )),
        op: write,
    }
}

/// The registered member-state cell for one Account actor. The current-results
/// projection decodes the subject back into an `ActorId`, so the subject has to
/// be the canonical composite, not a bare DID string.
fn member_actor(principal: &str) -> ActorId {
    ActorId::account(AccountId::new(
        principal.parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ))
}

fn member_cell(principal: &str) -> CellRef {
    let actor = member_actor(principal);
    let key = actor.canonical_key().unwrap();
    let subject = arkret_wire::composite_subject(&[key]).unwrap();
    CellRef::new(arkret_wire::subject_cell(
        arkret_wire::CellFamilyId::MEMBER_STATE_V1,
        &subject,
    ))
    .unwrap()
}

/// One membership transition on a dedicated member cell. The registered
/// `sequenced_state` contract is the least entangled cell family available: it
/// needs no typed selector payload, so the fixture can stay about atomicity.
fn join_op(cell: &CellRef, event_digest: &Hash) -> (CellRef, IssuedOp) {
    (
        cell.clone(),
        issued(StateWrite::new(
            event_digest.clone(),
            arkret_wire::LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("leave")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        )),
    )
}

fn seal_over(
    realm: &RealmId,
    predecessor: Option<SealId>,
    delta: Vec<Hash>,
    covered: &BTreeSet<Hash>,
    state_root: Hash,
    notary_seq: u64,
    hlc_marker: &str,
    configuration_ref: &arkret_wire::EventId,
) -> Seal {
    let control_root = arkret_state::state::control_event_set_root(covered, SUITE).unwrap();
    let command_result = arkret_wire::SealCommandOutcome::committed(
        delta[0].clone(),
        delta.clone(),
        Vec::new(),
        SUITE,
    )
    .unwrap();
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap(),
        realm_id: realm.clone(),
        predecessor_ref: predecessor,
        delta,
        data_delta: Vec::new(),
        data_event_set_root: arkret_wire::empty_data_event_set_root(SUITE).unwrap(),
        control_event_set_root: control_root,
        state_root,
        notary_seq,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: SealSignature {
            verification_method: arkret_wire::DidUrl::new("did:key:z6MkFixture#z6MkFixture")
                .unwrap(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
        },
        sealed_at: fixture_time(),
        hlc: Hlc::new(format!("0189c4d2af00-0000-aabbcc{hlc_marker}")).unwrap(),
        configuration_ref: configuration_ref.clone(),
        command_results: vec![command_result],
        authorization_closures: Vec::new(),
        data_closure_announcements: Vec::new(),
        data_closures: Vec::new(),
        existence_anchors: Vec::new(),
    };
    seal.id = seal.derive_id(SUITE).unwrap();
    seal
}

fn canonical_record(event: &arkret_wire::Event) -> CanonicalEventRecord {
    CanonicalEventRecord {
        event_id: event.event_id.to_string(),
        actor_id: event.actor_id.canonical_key().unwrap(),
        actor_seq: event.actor_seq,
        realm_id: Some(event.realm_id.to_string()),
        kind: event.kind.as_str().into(),
        schema_id: arkret_wire::SchemaId::EVENT_V1.into(),
        digest_suite: SUITE,
        canonical_digest: event.event_digest_with_digest_suite(SUITE).unwrap(),
        canonical_bytes: arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap())
            .unwrap(),
        envelope: serde_json::to_value(event).unwrap(),
        received_at: fixture_time(),
    }
}

fn ack_for(record: &CanonicalEventRecord) -> arkret_wire::ControlProposalAck {
    let time = fixture_time();
    let mut ack = arkret_wire::ControlProposalAck {
        kind: arkret_wire::ControlProposalAckKind::SignedAck,
        defer_count: 0,
        realm_id: record.realm_id.clone().unwrap().parse().unwrap(),
        proposal_digest: record.canonical_digest.parse().unwrap(),
        received_at: time,
        decision_due_at: time + chrono::Duration::seconds(30),
        absolute_due_at: time + chrono::Duration::seconds(90),
        authority_set_ref: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
        signature: arkret_wire::PayloadSignature {
            verification_method: arkret_wire::DidUrl::new("did:web:station.example#key").unwrap(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: time,
            jws: "e30..c2ln".into(),
        },
    };
    ack.signature.payload_digest = ack.ack_body_digest().unwrap();
    ack
}

/// One Realm that already carries a confirmed predecessor Seal, plus the
/// candidate anchor unit and the terminal Seal that covers it.
struct Fixture {
    stores: StateResolutionStores,
    registry: Arc<dyn CellStateRegistry>,
    realm: RealmId,
    anchor_records: Vec<CanonicalEventRecord>,
    anchor_acks: Vec<arkret_wire::ControlProposalAck>,
    predecessor_seal: SealId,
    predecessor_covered: BTreeSet<Hash>,
    configuration_ref: arkret_wire::EventId,
    terminal_seal: Seal,
    terminal_ops: Vec<(CellRef, IssuedOp)>,
    terminal_covered: BTreeSet<Hash>,
    transaction_id: String,
    session_id: String,
    policy_id: String,
    marker: char,
    /// The transaction as stored before the terminal step.
    open_transaction: SecurityTransactionRecord,
    /// The completed resource the terminal step proposes.
    completed_transaction: SecurityTransactionRecord,
    step_outcome: SecurityTransactionStepOutcomeRecord,
}

impl Fixture {
    fn marker_prefix(&self) -> String {
        format!("{}recovery", self.marker)
    }

    fn terminal_write(&self, expected_head: Option<SealId>) -> RecoveryTerminalCommitWrite {
        self.terminal_write_with(
            expected_head,
            self.completed_transaction.clone(),
            CONTINUE_BYTES,
        )
    }

    fn terminal_write_with(
        &self,
        expected_head: Option<SealId>,
        transaction: SecurityTransactionRecord,
        canonical_request: &[u8],
    ) -> RecoveryTerminalCommitWrite {
        let mut step_outcome = self.step_outcome.clone();
        step_outcome.canonical_request = canonical_request.to_vec();
        RecoveryTerminalCommitWrite {
            cell_registry: self.registry.clone(),
            seal: self.terminal_seal.clone(),
            seal_digest_suite: SUITE,
            expected_seal_head: expected_head,
            new_ops: self.terminal_ops.clone(),
            covered: self.terminal_covered.clone(),
            seal_governance_dependencies: Vec::new(),
            confirmed_device_control: None,
            transaction,
            step_outcome,
        }
    }
}

/// A Realm-scoped control Event with no registered descriptor, so sealing it
/// exercises the commit path without dragging in a typed payload contract.
fn synthetic_control_event(
    realm: &RealmId,
    marker: char,
    seq: u64,
    hlc: &str,
    member_principal: &str,
) -> arkret_wire::Event {
    arkret_wire::test_support::raw_event_at(
        "ak.test.control",
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        arkret_wire::project_did_to_core_id(
            &arkret_wire::Did::new(format!("did:web:{marker}basis.example")).unwrap(),
        )
        .unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        seq,
        Hlc::new(hlc.to_owned()).unwrap(),
        // The member-state family is a `current` delivery family, so its origin
        // Event must name the member the cell belongs to.
        json!({
            "marker": format!("{marker}{seq}"),
            "member_id": member_actor(member_principal),
        }),
        fixture_time(),
    )
    .unwrap()
}

fn synthetic_recovery_unit_event(
    kind: &str,
    realm: &RealmId,
    account: &AccountId,
    seq: u64,
) -> arkret_wire::Event {
    arkret_wire::test_support::raw_event_for_actor_at(
        kind,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        ActorId::account(account.clone()),
        seq,
        format!("00000000000{seq}-0000-00000000").parse().unwrap(),
        json!({"fixture": kind}),
        fixture_time(),
    )
    .unwrap()
}

async fn build_fixture(pool: &crate::PgPool, marker: char) -> Fixture {
    let registry: Arc<dyn CellStateRegistry> = Arc::new(
        soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry().unwrap(),
    );
    let stores = build_state_resolution_stores(Some(pool.clone()), registry.clone());
    let time = fixture_time();
    let account = AccountId::new(
        format!("ak:did_core:web:{marker}recovery.example")
            .parse()
            .unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );

    // --- the candidate anchor unit -------------------------------------------------
    let create = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::RealmCreate.as_str(),
        ScopeRef::RealmGenesis,
        ActorId::account(account.clone()),
        1,
        "000000000001-0000-00000000".parse().unwrap(),
        json!({"object":{"purpose":"principal_control","initial_resolution":{
            "did": format!("did:web:{marker}recovery.example"),
            "method_history_head":"accepted-head","version_id":"1"}}}),
        time,
    )
    .unwrap();
    let realm = create.realm_id.clone();
    let mut authorize = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::DeviceAuthorize.as_str(),
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        ActorId::account(account.clone()),
        2,
        "000000000002-0000-00000000".parse().unwrap(),
        json!({
            "authorization_binding_kind": "registration_anchor",
            "device_id": "ak:device:01904100-0000-7000-8000-00000000000e",
        }),
        time,
    )
    .unwrap();
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize.event_id = authorize.derive_event_id_with_digest_suite(SUITE).unwrap();
    let anchor_records = vec![canonical_record(&create), canonical_record(&authorize)];
    let anchor_acks = anchor_records.iter().map(ack_for).collect::<Vec<_>>();

    // --- a confirmed predecessor Seal ----------------------------------------------
    // `RecoverySealIntent` forbids a genesis-null basis, so the first
    // new-generation Seal is always a successor.
    let basis_principal = format!("ak:did_core:web:{marker}basis.example");
    let basis_event = synthetic_control_event(
        &realm,
        marker,
        1,
        "0189c4d2af00-0000-aabbcc00",
        &basis_principal,
    );
    let basis_digest = arkret_state::state::control_event_digest(&basis_event, SUITE).unwrap();
    let basis_cell = member_cell(&basis_principal);
    let basis_ops = vec![join_op(&basis_cell, &basis_digest)];
    let predecessor_covered = std::iter::once(basis_digest.clone()).collect::<BTreeSet<_>>();
    let basis_state = crate::state_resolution::effective_state_with_new_ops(
        stores.cell_store.as_ref(),
        registry.as_ref(),
        &realm,
        &predecessor_covered,
        &basis_ops,
    )
    .await
    .unwrap();
    let basis_seal = seal_over(
        &realm,
        None,
        vec![basis_digest.clone()],
        &predecessor_covered,
        arkret_state::state::compute_state_root(
            arkret_state::GovernanceView::new(&basis_state),
            SUITE,
        )
        .unwrap(),
        0,
        "00",
        &create.event_id,
    );
    stores
        .control_event_store
        .put_pending_unit_with_ingress(&[ControlUnitIngressMember {
            event: basis_event,
            digest_suite: SUITE,
            ingress: ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
                device_id: "ak:device:recovery-basis".to_owned(),
                device_authorize_event_id: "ak:event:recovery-basis".to_owned(),
                device_generation_ref: 1,
                seal_basis_digest: format!("sha256:{}", "c".repeat(64)),
            }),
        }])
        .await
        .unwrap();
    assert!(
        stores
            .event_seal_committer
            .commit_if_head(
                &basis_seal,
                SUITE,
                None,
                &basis_ops,
                &predecessor_covered,
                &[],
                None,
            )
            .await
            .unwrap(),
        "predecessor Seal must commit"
    );

    // --- the terminal Seal -----------------------------------------------------------
    // Its delta is a registered two-member control unit rather than the anchor
    // Events themselves. What this fixture exercises is the durable boundary:
    // whether the Events, the Seal, the session and the transaction all land or
    // none of them do. Which Events a recovery Seal is allowed to cover is an
    // admission question, decided by the HTTP-layer candidate overlay.
    let terminal_principal = format!("ak:did_core:web:{marker}terminal.example");
    let terminal_members = [
        synthetic_control_event(
            &realm,
            marker,
            2,
            "0189c4d2af00-0000-aabbcc11",
            &terminal_principal,
        ),
        synthetic_control_event(
            &realm,
            marker,
            3,
            "0189c4d2af00-0000-aabbcc12",
            &terminal_principal,
        ),
    ];
    let terminal_unit_digests = terminal_members
        .iter()
        .map(|event| arkret_state::state::control_event_digest(event, SUITE).unwrap())
        .collect::<Vec<_>>();
    stores
        .control_event_store
        .put_pending_unit_with_ingress(
            &terminal_members
                .iter()
                .map(|event| ControlUnitIngressMember {
                    event: event.clone(),
                    digest_suite: SUITE,
                    ingress: ControlProposalIngress::AcklessSelfPrincipal(
                        AcklessSelfPrincipalIngress {
                            device_id: "ak:device:recovery-terminal".to_owned(),
                            device_authorize_event_id: "ak:event:recovery-terminal".to_owned(),
                            device_generation_ref: 1,
                            seal_basis_digest: format!("sha256:{}", "e".repeat(64)),
                        },
                    ),
                })
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap();
    let terminal_cell = member_cell(&terminal_principal);
    let terminal_ops = vec![join_op(&terminal_cell, &terminal_unit_digests[0])];
    let mut terminal_covered = predecessor_covered.clone();
    terminal_covered.extend(terminal_unit_digests.iter().cloned());
    let terminal_state = crate::state_resolution::effective_state_with_new_ops(
        stores.cell_store.as_ref(),
        registry.as_ref(),
        &realm,
        &terminal_covered,
        &terminal_ops,
    )
    .await
    .unwrap();
    let terminal_seal = seal_over(
        &realm,
        Some(basis_seal.id.clone()),
        terminal_unit_digests.clone(),
        &terminal_covered,
        arkret_state::state::compute_state_root(
            arkret_state::GovernanceView::new(&terminal_state),
            SUITE,
        )
        .unwrap(),
        1,
        "01",
        &create.event_id,
    );

    // --- the security transaction that owns the terminal step -----------------------
    let transaction_id = format!("ak:transaction:0199{marker}100-0000-7000-8000-00000000000a");
    let session_id = format!("ak:recovery_session:0199{marker}100-0000-7000-8000-00000000000b");
    let terminal_receipt_id = format!("ak:receipt:0199{marker}100-0000-7000-8000-00000000000d");
    let policy_id = format!("ak:policy:0199{marker}100-0000-7000-8000-00000000000f");
    let reanchor = synthetic_recovery_unit_event("ak.device.reanchor", &realm, &account, 3);
    let plan_authorize = synthetic_recovery_unit_event("ak.device.authorize", &realm, &account, 4);
    let reanchor_unit = arkret_wire::PreparedEventUnit::new(
        SUITE,
        arkret_wire::EventsSubmitBatchRequestBody {
            events: vec![
                arkret_wire::EventInitialSubmission::online(reanchor.clone()),
                arkret_wire::EventInitialSubmission::online(plan_authorize.clone()),
            ],
        },
    )
    .unwrap();
    let unsigned_body = {
        let mut value = serde_json::to_value(&terminal_seal).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("id");
        object.remove("notary_signature");
        value
    };
    let plan_json = json!({
        "binding": {
            "identity_model": "pcr_policy",
            "recovery_session_id": session_id,
            "replacement_device_id": "ak:device:01904100-0000-7000-8000-00000000000e",
            "reanchor_event_id": reanchor.event_id,
            "authorize_event_id": plan_authorize.event_id,
            "reanchor_batch_receipt_id":
                format!("ak:receipt:0199{marker}100-0000-7000-8000-00000000000c"),
            "first_generation_seal_id": terminal_seal.id,
            "terminal_receipt_id": terminal_receipt_id,
        },
        "recovery_session_snapshot_digest": format!("sha256:{}", "1".repeat(64)),
        "proof_digest": format!("sha256:{}", "2".repeat(64)),
        "previous_model_generation_ref": 1,
        "result_model_generation_ref": 2,
        "reanchor_unit": reanchor_unit,
        "first_generation_seal_intent": {
            "realm_id": realm,
            "predecessor_ref": basis_seal.id,
            "unit_event_digests": terminal_unit_digests,
            "hlc": terminal_seal.hlc,
        },
        "first_generation_seal_body": unsigned_body,
    });
    // Deserialize the closed variant, not the untagged union: an untagged
    // failure reports nothing about which member is wrong.
    let pcr_plan = serde_json::from_value::<arkret_wire::PcrPolicyRecoveryPlan>(plan_json)
        .expect("fixture PCR-policy recovery plan");
    let prepared_plan = arkret_wire::SecurityTransactionPreparedPlan::Recovery(
        arkret_wire::RecoveryPreparedPlan::PcrPolicy(pcr_plan),
    );
    let prepared_plan_digest = Hash::new(arkret_canonical::canonical::digest(
        SUITE,
        &arkret_canonical::canonical_json_bytes(&prepared_plan).unwrap(),
    ))
    .unwrap();
    let mut resource = SecurityTransaction {
        transaction_id: transaction_id.parse().unwrap(),
        kind: arkret_wire::SecurityTransactionKind::Recovery,
        account_id: account.clone(),
        expires_at: time + chrono::Duration::hours(1),
        created_at: time,
        request_digest: Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
        prepared_plan,
        prepared_plan_digest,
        accepted_steps: Vec::new(),
        terminal_result: None,
    };
    resource
        .validate_structural()
        .expect("fixture recovery transaction must be structurally valid");
    let open_transaction = SecurityTransactionRecord {
        canonical_request: b"create".to_vec(),
        resource: resource.clone(),
    };
    resource.accepted_steps.push(arkret_wire::AcceptedStep {
        prepared_material_digest: Hash::new(format!("sha256:{}", "4".repeat(64))).unwrap(),
        acceptor: arkret_wire::SecurityTransactionAcceptor::Principal {
            principal_id: "ak:did_core:web:station.example".parse().unwrap(),
        },
        output_ref: terminal_receipt_id.clone(),
        output_digest: Hash::new(format!("sha256:{}", "5".repeat(64))).unwrap(),
        accepted_at: time,
    });
    // The coordinator signature is not re-verified by the durable ledger, but
    // a completed recovery transaction is structurally required to carry the
    // attestation, so the fixture carries a complete one.
    let completion_attestation =
        serde_json::from_value::<arkret_wire::RecoveryCompletionAttestation>(json!({
            "schema": arkret_wire::SchemaId::RECOVERY_COMPLETION_ATTESTATION_V1,
            "transaction_id": transaction_id,
            "transaction_request_digest": resource.request_digest,
            "prepared_plan_digest": resource.prepared_plan_digest,
            "account_id": account,
            "recovery_session_id": session_id,
            "terminal_receipt_id": terminal_receipt_id,
            "terminal_receipt_digest": format!("sha256:{}", "5".repeat(64)),
            "terminal_commit_digest": format!("sha256:{}", "8".repeat(64)),
            "replacement_device_id": "ak:device:01904100-0000-7000-8000-00000000000e",
            "device_authorization_event_id": plan_authorize.event_id,
            "first_generation_seal_id": terminal_seal.id,
            "result_model_generation_ref": 2,
            "completed_at": "2026-09-15T00:00:00.000Z",
            "auth_data": {
                "verification_method": "did:web:station.example#notary",
                "signature_algorithm": "Ed25519",
                "signature": "AQ",
            },
        }))
        .expect("fixture recovery completion attestation");
    resource.terminal_result = Some(arkret_wire::SecurityTransactionTerminalOutcome {
        result: arkret_wire::SecurityTransactionResultKind::Completed,
        completed_at: time,
        receipt_id: Some(terminal_receipt_id.parse().unwrap()),
        reason_code: None,
        completion_attestation: Some(completion_attestation),
    });
    resource
        .validate_structural()
        .expect("fixture completed recovery transaction must be structurally valid");
    let step_outcome = SecurityTransactionStepOutcomeRecord {
        transaction_id: transaction_id.clone(),
        step: arkret_wire::SecurityTransactionStep::CommitRecoveryUnit,
        canonical_request: CONTINUE_BYTES.to_vec(),
        response: serde_json::to_value(&resource).unwrap(),
        participant_outcome: None,
    };
    let completed_transaction = SecurityTransactionRecord {
        canonical_request: b"create".to_vec(),
        resource,
    };

    Fixture {
        stores,
        registry,
        realm,
        anchor_records,
        anchor_acks,
        predecessor_seal: basis_seal.id,
        predecessor_covered,
        configuration_ref: create.event_id.clone(),
        terminal_seal,
        terminal_ops,
        terminal_covered,
        transaction_id,
        session_id,
        policy_id,
        marker,
        open_transaction,
        completed_transaction,
        step_outcome,
    }
}

/// Store the open transaction and its verified recovery session exactly the way
/// `create` left them, so the terminal commit sees the real pre-state.
/// Store the open transaction, its accepted recovery policy and its verified
/// recovery session exactly the way `create` left them, so the terminal commit
/// sees the real pre-state.
///
/// The policy and proof rows are seeded as already-admitted inputs: what this
/// module tests is consumption inside one transaction, not admission.
async fn seed_transaction_and_session(pool: &crate::PgPool, fixture: &Fixture) {
    let mut conn = crate::pg_conn(pool).await.unwrap();
    let resource = &fixture.open_transaction.resource;
    sql_query(
        "INSERT INTO security_transactions \
         (id, kind, principal_id, station_id, expires_at, created_at, request_digest, \
          prepared_plan, prepared_plan_digest, accepted_steps, terminal_result, canonical_request) \
         VALUES ($1, 'recovery', $2, $3, $4, $5, $6, $7, $8, '[]'::jsonb, NULL, $9)",
    )
    .bind::<diesel::sql_types::Uuid, _>(crate::ids::typed_uuid_part_expect_internal(
        &fixture.transaction_id,
    ))
    .bind::<Text, _>(resource.account_id.principal_id.as_str())
    .bind::<Text, _>(resource.account_id.station_id.as_str())
    .bind::<diesel::sql_types::Timestamptz, _>(resource.expires_at)
    .bind::<diesel::sql_types::Timestamptz, _>(resource.created_at)
    .bind::<Text, _>(resource.request_digest.as_str())
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::to_value(&resource.prepared_plan).unwrap())
    .bind::<Text, _>(resource.prepared_plan_digest.as_str())
    .bind::<diesel::sql_types::Binary, _>(&fixture.open_transaction.canonical_request)
    .execute(&mut *conn)
    .await
    .unwrap();

    let now = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
        .expect("wall clock");
    let policy_expiry = now + chrono::Duration::hours(1);
    let signature = arkret_canonical::base64url_encode([7u8; 64]);
    let verification_method = format!("did:web:{}.example#root", fixture.marker_prefix());
    let policy = json!({
        "schema": "ak.schema.recovery_policy.v1",
        "policy_id": fixture.policy_id,
        "account_id": {
            "principal_id": resource.account_id.principal_id,
            "station_id": resource.account_id.station_id,
        },
        "version": 1,
        "supersedes_id": null,
        "trust_domain": "ak:trust_domain:station.example",
        "methods": [{"kind": "did_root"}],
        "issued_at": (now - chrono::Duration::minutes(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "expires_at": policy_expiry.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signature": signature,
        },
    });
    let proof_payload = json!({
        "proof": {
            "kind": "did_root",
            "challenge": arkret_canonical::base64url_encode([42u8; 32]),
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signature": signature,
        },
    });
    sql_query(
        "INSERT INTO recovery_policies \
         (id, principal_id, station_id, version, acceptance_basis, trust_domain, expires_at, \
          issued_at, verification_method, raw_payload, accepted_at) \
         VALUES ($1, $2, $3, 1, '{}', 'ak:trust_domain:station.example', $4, $5, $6, $7, $5)",
    )
    .bind::<diesel::sql_types::Uuid, _>(crate::ids::typed_uuid_part_expect_internal(
        &fixture.policy_id,
    ))
    .bind::<Text, _>(resource.account_id.principal_id.as_str())
    .bind::<Text, _>(resource.account_id.station_id.as_str())
    .bind::<diesel::sql_types::Timestamptz, _>(policy_expiry)
    .bind::<diesel::sql_types::Timestamptz, _>(now - chrono::Duration::minutes(1))
    .bind::<Text, _>(&verification_method)
    .bind::<diesel::sql_types::Jsonb, _>(&policy)
    .execute(&mut *conn)
    .await
    .unwrap();

    sql_query(
        "INSERT INTO recovery_sessions \
         (id, request_id, create_intent_digest, session_grant_id, session_grant_cnf_jkt, \
          principal_id, station_id, requesting_device_id, requesting_device_public_key_did, \
          trust_domain, policy_id, policy_version, identity_model, current_device_generation_ref, \
          device_generation_status, accepted_seal_frontier, policy_payload, \
          publication_authority_context, publication_authority_context_digest, challenge, \
          state, proof_payload, transaction_id, expires_at, created_at, updated_at) \
         VALUES ($1, 'req', $2, $3, $4, $5, $6, \
          'ak:device:01904100-0000-7000-8000-00000000000e', 'did:key:z6MkReplacement', \
          'ak:trust_domain:station.example', $7, 1, 'pcr_policy', 1, 'active', '{}'::jsonb, $8, \
          '{}'::jsonb, $2, 'challenge', 'verified', $9, $10, $11, $12, $12)",
    )
    .bind::<diesel::sql_types::Uuid, _>(crate::ids::typed_uuid_part_expect_internal(
        &fixture.session_id,
    ))
    .bind::<Text, _>(format!("sha256:{}", "6".repeat(64)))
    .bind::<Text, _>(format!("grant-{}", fixture.session_id))
    .bind::<Text, _>("A".repeat(43))
    .bind::<Text, _>(resource.account_id.principal_id.as_str())
    .bind::<Text, _>(resource.account_id.station_id.as_str())
    .bind::<diesel::sql_types::Uuid, _>(crate::ids::typed_uuid_part_expect_internal(
        &fixture.policy_id,
    ))
    .bind::<diesel::sql_types::Jsonb, _>(&policy)
    .bind::<diesel::sql_types::Jsonb, _>(&proof_payload)
    .bind::<diesel::sql_types::Uuid, _>(crate::ids::typed_uuid_part_expect_internal(
        &fixture.transaction_id,
    ))
    .bind::<diesel::sql_types::Timestamptz, _>(policy_expiry)
    .bind::<diesel::sql_types::Timestamptz, _>(now - chrono::Duration::minutes(1))
    .execute(&mut *conn)
    .await
    .unwrap();
}

async fn count(pool: &crate::PgPool, sql: &str, bind: &str) -> i64 {
    let mut conn = crate::pg_conn(pool).await.unwrap();
    sql_query(sql)
        .bind::<Text, _>(bind)
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .value
}

async fn session_state(pool: &crate::PgPool, session_id: &str) -> String {
    let mut conn = crate::pg_conn(pool).await.unwrap();
    sql_query("SELECT state AS value FROM recovery_sessions WHERE id = $1")
        .bind::<diesel::sql_types::Uuid, _>(crate::ids::typed_uuid_part_expect_internal(session_id))
        .get_result::<TextRow>(&mut *conn)
        .await
        .unwrap()
        .value
}

async fn accepted_event_count(pool: &crate::PgPool, fixture: &Fixture) -> i64 {
    count(
        pool,
        "SELECT COUNT(*)::bigint AS value FROM canonical_events          WHERE realm_id = $1 AND state = 'accepted'            AND kind IN ('ak.realm.create', 'ak.device.authorize')",
        fixture.realm.as_str(),
    )
    .await
}

async fn seal_count(pool: &crate::PgPool, seal_id: &str) -> i64 {
    count(
        pool,
        "SELECT COUNT(*)::bigint AS value FROM state_seals WHERE id = $1",
        seal_id,
    )
    .await
}

async fn step_row_counts(pool: &crate::PgPool, transaction_id: &str) -> (i64, i64, i64) {
    let mut conn = crate::pg_conn(pool).await.unwrap();
    let uuid = crate::ids::typed_uuid_part_expect_internal(transaction_id);
    let attempts = sql_query(
        "SELECT COUNT(*)::bigint AS value FROM security_transaction_step_attempts WHERE transaction_id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(uuid)
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .value;
    let outcomes = sql_query(
        "SELECT COUNT(*)::bigint AS value FROM security_transaction_step_outcomes WHERE transaction_id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(uuid)
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .value;
    let terminal = sql_query(
        "SELECT COUNT(*)::bigint AS value FROM security_transactions \
         WHERE id = $1 AND terminal_result IS NOT NULL",
    )
    .bind::<diesel::sql_types::Uuid, _>(uuid)
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .value;
    (attempts, outcomes, terminal)
}

async fn commit_terminal_unit(
    pool: &crate::PgPool,
    fixture: &Fixture,
    expected_head: Option<SealId>,
) -> soland_storage::PersistenceResult<soland_storage::IdentityAnchorCommitOutcome> {
    let store = crate::PgEventStore { pool: pool.clone() };
    store
        .put_identity_anchor_batch_atomic(
            fixture.anchor_records.clone(),
            fixture.anchor_acks.clone(),
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            Some(fixture.terminal_write(expected_head)),
        )
        .await
}

#[tokio::test]
async fn recovery_terminal_unit_commits_events_seal_session_and_transaction_together() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = build_fixture(&pool, 'a').await;
    seed_transaction_and_session(&pool, &fixture).await;

    assert_eq!(accepted_event_count(&pool, &fixture).await, 0);
    assert_eq!(
        seal_count(&pool, fixture.terminal_seal.id.as_str()).await,
        0
    );
    assert_eq!(session_state(&pool, &fixture.session_id).await, "verified");
    assert_eq!(
        step_row_counts(&pool, &fixture.transaction_id).await,
        (0, 0, 0)
    );

    commit_terminal_unit(&pool, &fixture, Some(fixture.predecessor_seal.clone()))
        .await
        .expect("terminal recovery unit commits");

    assert_eq!(accepted_event_count(&pool, &fixture).await, 2);
    assert_eq!(
        seal_count(&pool, fixture.terminal_seal.id.as_str()).await,
        1
    );
    assert_eq!(session_state(&pool, &fixture.session_id).await, "completed");
    assert_eq!(
        step_row_counts(&pool, &fixture.transaction_id).await,
        (1, 1, 1)
    );
}

/// The compare-and-swap is the linearization point for the whole unit: a rival
/// Seal that took the same predecessor first makes the loser leave nothing —
/// no accepted Event, no Seal, no consumed session, no completed transaction,
/// and no frozen step attempt either.
#[tokio::test]
async fn a_lost_seal_frontier_race_rolls_back_the_whole_recovery_terminal_unit() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = build_fixture(&pool, 'b').await;
    seed_transaction_and_session(&pool, &fixture).await;

    // A rival successor wins the predecessor first.
    let rival_event = synthetic_control_event(
        &fixture.realm,
        'r',
        1,
        "0189c4d2af00-0000-aabbcc02",
        "ak:did_core:web:brivalcell.example",
    );
    let rival_digest = arkret_state::state::control_event_digest(&rival_event, SUITE).unwrap();
    let rival_cell = member_cell("ak:did_core:web:brivalcell.example");
    let rival_ops = vec![join_op(&rival_cell, &rival_digest)];
    let mut rival_covered = fixture.predecessor_covered.clone();
    rival_covered.insert(rival_digest.clone());
    let rival_state = crate::state_resolution::effective_state_with_new_ops(
        fixture.stores.cell_store.as_ref(),
        fixture.registry.as_ref(),
        &fixture.realm,
        &rival_covered,
        &rival_ops,
    )
    .await
    .unwrap();
    let rival_seal = seal_over(
        &fixture.realm,
        Some(fixture.predecessor_seal.clone()),
        vec![rival_digest],
        &rival_covered,
        arkret_state::state::compute_state_root(
            arkret_state::GovernanceView::new(&rival_state),
            SUITE,
        )
        .unwrap(),
        1,
        "02",
        &fixture.configuration_ref,
    );
    fixture
        .stores
        .control_event_store
        .put_pending_unit_with_ingress(&[ControlUnitIngressMember {
            event: rival_event,
            digest_suite: SUITE,
            ingress: ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
                device_id: "ak:device:recovery-rival".to_owned(),
                device_authorize_event_id: "ak:event:recovery-rival".to_owned(),
                device_generation_ref: 1,
                seal_basis_digest: format!("sha256:{}", "d".repeat(64)),
            }),
        }])
        .await
        .unwrap();
    assert!(
        fixture
            .stores
            .event_seal_committer
            .commit_if_head(
                &rival_seal,
                SUITE,
                Some(&fixture.predecessor_seal),
                &rival_ops,
                &rival_covered,
                &[],
                None,
            )
            .await
            .unwrap(),
        "the rival Seal wins the predecessor"
    );

    let error = commit_terminal_unit(&pool, &fixture, Some(fixture.predecessor_seal.clone()))
        .await
        .expect_err("the loser must not commit");
    // The loser must lose at the frontier compare-and-swap and nowhere else,
    // or the rollback below would be proving something weaker.
    assert!(
        matches!(
            &error,
            soland_storage::PersistenceError::Conflict(detail)
                if detail.starts_with("device_generation_fenced:")
        ),
        "unexpected loser error: {error:?}"
    );

    assert_eq!(accepted_event_count(&pool, &fixture).await, 0);
    assert_eq!(
        seal_count(&pool, fixture.terminal_seal.id.as_str()).await,
        0
    );
    assert_eq!(session_state(&pool, &fixture.session_id).await, "verified");
    assert_eq!(
        step_row_counts(&pool, &fixture.transaction_id).await,
        (0, 0, 0)
    );
}

/// `security-transactions.md` section 2.5 — after the commit the exact same
/// canonical request replays the stored result instead of committing twice.
#[tokio::test]
async fn an_exact_retry_of_the_terminal_recovery_unit_replays_the_stored_result() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = build_fixture(&pool, 'c').await;
    seed_transaction_and_session(&pool, &fixture).await;

    commit_terminal_unit(&pool, &fixture, Some(fixture.predecessor_seal.clone()))
        .await
        .expect("first terminal commit");
    commit_terminal_unit(&pool, &fixture, Some(fixture.predecessor_seal.clone()))
        .await
        .expect("exact retry replays");

    assert_eq!(accepted_event_count(&pool, &fixture).await, 2);
    assert_eq!(
        seal_count(&pool, fixture.terminal_seal.id.as_str()).await,
        1
    );
    assert_eq!(session_state(&pool, &fixture.session_id).await, "completed");
    assert_eq!(
        step_row_counts(&pool, &fixture.transaction_id).await,
        (1, 1, 1)
    );
}

/// `security-transactions.md` sections 2.2 and 2.5 — a failed re-verification
/// freezes no step outcome, so a corrected submission with *new* canonical
/// request bytes must still be accepted. The old `begin_step` shape froze the
/// attempt bytes before the authoritative writes and turned every corrected
/// receipt into a `duplicate_conflict`.
#[tokio::test]
async fn a_refused_terminal_commit_freezes_nothing_and_new_receipt_bytes_still_commit() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = build_fixture(&pool, 'd').await;
    seed_transaction_and_session(&pool, &fixture).await;

    // A transaction resource that does not advance its accepted-step prefix is
    // refused by the ledger after the Seal has already been staged.
    let store = crate::PgEventStore { pool: pool.clone() };
    let refused = store
        .put_identity_anchor_batch_atomic(
            fixture.anchor_records.clone(),
            fixture.anchor_acks.clone(),
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            Some(fixture.terminal_write_with(
                Some(fixture.predecessor_seal.clone()),
                fixture.open_transaction.clone(),
                b"{\"canonical\":\"stale-receipt\"}",
            )),
        )
        .await
        .expect_err("a non-advancing ledger write must be refused");
    assert!(
        matches!(
            refused,
            soland_storage::PersistenceError::SchemaViolation(_)
        ),
        "unexpected refusal: {refused:?}"
    );
    assert_eq!(accepted_event_count(&pool, &fixture).await, 0);
    assert_eq!(
        seal_count(&pool, fixture.terminal_seal.id.as_str()).await,
        0
    );
    assert_eq!(session_state(&pool, &fixture.session_id).await, "verified");
    assert_eq!(
        step_row_counts(&pool, &fixture.transaction_id).await,
        (0, 0, 0),
        "a refused attempt must leave no frozen step bytes"
    );

    commit_terminal_unit(&pool, &fixture, Some(fixture.predecessor_seal.clone()))
        .await
        .expect("corrected submission with different canonical bytes commits");
    assert_eq!(accepted_event_count(&pool, &fixture).await, 2);
    assert_eq!(
        seal_count(&pool, fixture.terminal_seal.id.as_str()).await,
        1
    );
    assert_eq!(session_state(&pool, &fixture.session_id).await, "completed");
    assert_eq!(
        step_row_counts(&pool, &fixture.transaction_id).await,
        (1, 1, 1)
    );
}
