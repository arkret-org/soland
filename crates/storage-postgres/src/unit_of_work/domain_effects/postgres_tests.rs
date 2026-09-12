//! Real PostgreSQL Seal consumer tests. Local confirmed-store fixtures do not
//! replace executor, signature, or Contact evidence verification tests.
use std::collections::BTreeSet;
use std::sync::Arc;

use arkret_canonical::DigestSuite;
use arkret_state::state::store::{
    AcklessSelfPrincipalIngress, ControlProposalIngress, ControlUnitIngressMember,
};
use arkret_wire::{Hash, RealmId, ScopeRef, Seal, SealCommandOutcome};
use serde_json::json;
use soland_storage::{ConsentCellStore, ContactStore};

use super::*;

fn actor(name: &str) -> ActorId {
    ActorId::account(AccountId::new(
        format!("ak:did_core:web:{name}.example").parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ))
}
fn event(
    kind: &str,
    realm: &RealmId,
    actor: ActorId,
    seq: u64,
    payload: serde_json::Value,
) -> Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        actor,
        seq,
        "019f00000000-0000-00000001".parse().unwrap(),
        payload,
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    )
    .unwrap();
    event.proofs.push(arkret_wire::ProducerEventProof {
        kind: "Ed25519Signature2020".into(),
        verification_method: "did:web:fixture.example#device".parse().unwrap(),
        event_digest: event.event_id.event_digest(),
        signer_resolution_evidence_ref: None,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "fixture-storage-proof".into(),
    });
    event
}
fn contact(requester: ActorId, target: ActorId, event: &Event) -> ContactRecord {
    ContactRecord {
        requester_id: requester,
        target_id: target,
        contact_round_id: None,
        version: None,
        granted_to_target_scopes: vec!["invite".into()],
        granted_to_requester_scopes: vec![],
        status: "pending".into(),
        pending_incoming_admitted: false,
        request_event_ref: Some(event.event_id.clone()),
        request_slot_states: vec![],
        request_receipts: vec![],
        request_mirror_receipts: vec![],
        contact_round_evidence: None,
        contact_round_evidence_history: vec![],
        control_outcomes: vec![],
        response_event_ref: None,
        tombstone_event_ref: None,
        message: Some("local metadata".into()),
        peer_host_id: None,
        peer_service_resolution: None,
        created_at: event.created_at,
        updated_at: event.created_at,
    }
}
fn seal(events: &[Event], digests: &[Hash], outcome: CommandOutcome) -> Seal {
    let result = match outcome {
        CommandOutcome::Committed => SealCommandOutcome::committed(
            digests[0].clone(),
            digests.to_vec(),
            vec![],
            DigestSuite::Sha256,
        )
        .unwrap(),
        CommandOutcome::Rejected => SealCommandOutcome::rejected(
            digests[0].clone(),
            digests.to_vec(),
            arkret_wire::error_codes::ReasonCode::StateMismatch,
            DigestSuite::Sha256,
        )
        .unwrap(),
    };
    let placeholder: Hash = format!("sha256:{}", "0".repeat(64)).parse().unwrap();
    let mut seal = Seal {
        id: format!("ak:seal:{placeholder}").parse().unwrap(),
        realm_id: events[0].realm_id.clone(),
        predecessor_ref: None,
        delta: vec![],
        control_event_set_root: arkret_state::state::control_event_set_root(
            &BTreeSet::new(),
            DigestSuite::Sha256,
        )
        .unwrap(),
        state_root: arkret_state::state::compute_state_root(
            arkret_state::GovernanceView::new(&BTreeMap::new()),
            DigestSuite::Sha256,
        )
        .unwrap(),
        notary_seq: 0,
        availability_receipt_digests: vec![],
        covered_event_digests: vec![],
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: arkret_wire::SealSignature {
            verification_method: arkret_wire::DidUrl::new("did:web:station.example#notary")
                .unwrap(),
            payload_digest: placeholder,
            jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".into(),
        },
        sealed_at: events[0].created_at,
        hlc: "019f00000000-0000-00000001".parse().unwrap(),
        configuration_ref: events[0].event_id.clone(),
        command_results: vec![result],
        authorization_closures: vec![],
        existence_anchors: vec![],
    };
    seal.id = seal.derive_id(DigestSuite::Sha256).unwrap();
    seal
}

// These fixtures exercise the already-authenticated storage boundary only.
// Cryptographic source verification is covered by the SDK carrier tests.
fn completion_draft_fixture(
    event: &Event,
    peer: &ActorId,
) -> soland_storage::ContactCompletionDraft {
    use arkret_models_collaboration::contact_operations::ContactPeer;
    use arkret_models_collaboration::governance::peer_contact::{
        ContactIntroductionEvidence, PeerContactAddress,
    };
    let holder = ContactPeer::Human {
        account_id: event.actor_id.as_account_id().unwrap().clone(),
    };
    let peer = ContactPeer::Human {
        account_id: peer.as_account_id().unwrap().clone(),
    };
    soland_storage::ContactCompletionDraft {
        event:event.clone(),operation_id:"ak:operation:contact-fixture".parse().unwrap(),holder,
        action:soland_storage::ContactCompletionAction::Request {slot_version:1,slot_predecessor:None},
        response_binding:soland_storage::ContactCompletionBinding {authenticated_actor:event.actor_id.clone(),idempotency_key:format!("contact-commit:{}",event.event_id),request_hash:format!("sha256:{}","b".repeat(64))},
        target:soland_storage::ContactDeliveryTarget {
            contact_address:PeerContactAddress {recipient:peer,service_resolution:arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {resolution_url:"https://station.example/_arkret/open/services/ak%3Adid_core%3Aweb%3Astation.example/resolution".into()},route_assistance:None},
            introduction_evidence:Some(ContactIntroductionEvidence::ExplicitAddress),idempotency_key:format!("contact:{}",event.event_id).parse().unwrap(),
        },local_mirror_target:None,
    }
}
fn fixture_producer(
    event: &Event,
) -> arkret_models_collaboration::contact_operations::ContactProducerSigner {
    arkret_models_collaboration::contact_operations::ContactProducerSigner {
        verification_method: event.proofs[0].verification_method.clone(),
        public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            [7_u8; 32],
        ))
        .unwrap(),
    }
}
fn delivery_fixture(event: &Event, peer: &ActorId) -> soland_storage::ContactCompletionIntent {
    completion_draft_fixture(event, peer)
        .bind_producer(fixture_producer(event))
        .unwrap()
}
fn finalized_fixture(
    intent: &soland_storage::ContactCompletionIntent,
) -> (
    soland_storage::ContactCompletionResult,
    soland_storage::FederationOutboxRecord,
) {
    use arkret_models_collaboration::contact_operations::{
        ContactAcceptedOutcome, RequestAcceptanceReceipt,
    };
    let receipt =
        RequestAcceptanceReceipt::sign_with(intent.request_receipt_core().unwrap(), |_| {
            Ok(arkret_wire::ProtocolSignature {
                verification_method: "did:web:station.example#notary".parse().unwrap(),
                created_at: intent.accepted_at().unwrap(),
                jws: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    [1_u8; 64],
                ))
                .unwrap(),
            })
        })
        .unwrap();
    let outcome = ContactAcceptedOutcome::Request {
        operation_id: intent.plan.operation_id.clone(),
        request_acceptance_receipt: receipt,
    };
    let carrier = intent.finalized_carrier(&outcome).unwrap();
    let target = &intent.plan.target;
    let delivery = soland_storage::FederationOutboxRecord::pending(
        uuid::Uuid::now_v7().to_string(),
        target.contact_address.delivery_station_id().clone(),
        "https://station.example".into(),
        "/_arkret/peer/contacts".into(),
        target.idempotency_key.as_str().into(),
        String::from_utf8(arkret_canonical::canonical_json_bytes(&carrier).unwrap()).unwrap(),
        intent.accepted_at().unwrap().timestamp(),
    );
    (
        soland_storage::ContactCompletionResult::Accepted { outcome },
        delivery,
    )
}

#[tokio::test]
async fn contact_and_consent_mirrors_require_exact_committed_unit_and_replay_in_member_order() {
    for (index, (outcome, remote)) in [
        (CommandOutcome::Committed, true),
        (CommandOutcome::Committed, false),
        (CommandOutcome::Rejected, true),
    ]
    .into_iter()
    .enumerate()
    {
        let database = crate::TestDatabase::lease().await;
        let pool = database.pool();
        let stores = crate::build_state_resolution_stores(
            Some(pool.clone()),
            Arc::new(
                soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry()
                    .unwrap(),
            ),
        );
        let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(format!("domain effects {index}")),
        ));
        let alice = actor("domain-alice");
        let bob = if remote {
            ActorId::account(AccountId::new(
                "ak:did_core:web:domain-bob.example".parse().unwrap(),
                "ak:did_core:web:other-station.example".parse().unwrap(),
            ))
        } else {
            actor("domain-bob")
        };
        let consent_id = "ak:consent:01964137-0000-7000-8000-000000000001";
        let request = event(
            "ak.contact.requested",
            &realm,
            alice.clone(),
            0,
            json!({"peer":{"kind":"human","account_id":bob.as_account_id().unwrap()},"granted_to_peer_scopes":["invite"],"introduction_evidence_digest":format!("sha256:{}","c".repeat(64))}),
        );
        let scope_a = event(
            "ak.contact.scope.update",
            &realm,
            alice.clone(),
            1,
            json!({"peer":{"kind":"human","account_id":bob.as_account_id().unwrap()}}),
        );
        let scope_b = event("ak.contact.scope.update", &realm, bob.clone(), 1, json!({}));
        let grant_a = event(
            "ak.consent.grant",
            &realm,
            alice.clone(),
            2,
            json!({"consent_id":consent_id,"peer":{"kind":"actor","actor_id":bob},"consent_scope":"invite"}),
        );
        let grant_b = event(
            "ak.consent.grant",
            &realm,
            alice.clone(),
            3,
            serde_json::to_value(&grant_a.payload).unwrap(),
        );
        let dot = format!("{}:0", grant_a.event_id);
        let revoke = event(
            "ak.consent.revoke",
            &realm,
            alice.clone(),
            4,
            json!({"consent_id":consent_id,"observed_dot_ids":[dot]}),
        );
        let events = vec![request.clone(), scope_a, scope_b, grant_a, grant_b, revoke];
        let ingress = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
            device_id: "fixture".into(),
            device_authorize_event_id: "fixture".into(),
            device_generation_ref: 1,
            seal_basis_digest: "fixture".into(),
        });
        let digests = stores
            .control_event_store
            .put_pending_unit_with_ingress(
                &events
                    .iter()
                    .cloned()
                    .map(|event| ControlUnitIngressMember {
                        event,
                        digest_suite: DigestSuite::Sha256,
                        ingress: ingress.clone(),
                    })
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        let initial = contact(alice.clone(), bob.clone(), &request);
        let completion_intent = delivery_fixture(&events[0], &bob);
        let mut premature_material = completion_intent.clone();
        premature_material
            .freeze_acceptance_time(request.created_at)
            .unwrap();
        let (completion_result, delivery) = finalized_fixture(&premature_material);
        let delivery_arg = remote.then_some(&delivery);
        let holder = alice.as_account_id().unwrap().clone();
        let cell_id = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.consent.grant.v1:{consent_id}"
        ))
        .unwrap();
        let seed = soland_storage::ConsentCellRecord {
            cell_id: cell_id.clone(),
            holder_account_id: holder.clone(),
            peer: arkret_models_collaboration::account_lifecycle::ConsentPeer::Actor {
                actor_id: bob.clone(),
            },
            consent_scope: "invite".into(),
            active_grants: BTreeMap::new(),
            revoked_grants: BTreeMap::new(),
            updated_at: request.created_at,
        };
        let mut conn = pool.get().await.unwrap();
        for (index, event) in events.iter().enumerate() {
            let mut planned = initial.clone();
            if index == 1 {
                planned.version = Some(2);
                planned.granted_to_target_scopes = vec!["direct_conversation".into()];
            }
            if index == 2 {
                planned.version = Some(3);
                planned.granted_to_requester_scopes = vec!["invite".into()];
            }
            let contact = (index < 3).then_some(ContactProjectionCommit {
                completion_intent: (index == 0).then(|| completion_intent.clone()),
                record: planned,
                expected_updated_at: Some(request.created_at),
                conflict_code: "stale admission CAS must not decide a Seal".into(),
                verified_mirror: None,
                invite_policy: None,
            });
            let consent = (index >= 3).then_some(ConsentProjectionCommit {
                cell: seed.clone(),
                holder_quarantine: None,
            });
            stage_domain_effects(&mut conn, event, digests[index].as_str(), contact, consent)
                .await
                .unwrap();
        }
        // This cache revision is created after admission. Finality must derive
        // invalidation from this current row, never install an old planned CAS.
        let cache_entry = |peer: &ActorId, marker: &str| {
            json!({
                "entry_digest":format!("sha256:{}",marker.repeat(64)), "account_id":holder,
                "source_peer_principal_id":peer.signing_principal_id(), "source_id":holder.station_id,
                "surface_kind":"invite_delivery", "consent_scope":"invite",
                "introduction_kind":"explicit_address", "effective_kind":"explicit_address", "trust_tier":"low",
                "invite_event_id":request.event_id, "request_digest":format!("sha256:{}","c".repeat(64)),
                "idempotency_key_digest":format!("sha256:{}","d".repeat(64)),
                "received_at":arkret_canonical::format_timestamp_canonical(request.created_at),
                "expires_at":arkret_canonical::format_timestamp_canonical(request.created_at+chrono::Duration::days(1)),
            })
        };
        let quarantine = json!({"schema":"ak.schema.holder_quarantine.v1","quarantine_entries":[cache_entry(&bob,"a"),cache_entry(&actor("domain-carol"),"b")],"updated_at":arkret_canonical::format_timestamp_canonical(request.created_at)});
        sql_query("INSERT INTO account_datas (id,actor_id,account_data_key,revision,payload,tombstone,updated_at) VALUES($1,$2,$3,9,$4,FALSE,$5)")
            .bind::<diesel::sql_types::Uuid,_>(uuid::Uuid::now_v7()).bind::<Text,_>(alice.to_string())
            .bind::<Text,_>(arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE).bind::<Jsonb,_>(quarantine)
            .bind::<diesel::sql_types::Timestamptz,_>(request.created_at).execute(&mut conn).await.unwrap();
        drop(conn);
        let contacts = crate::PgContactStore { pool: pool.clone() };
        let consents = crate::PgConsentCellStore { pool: pool.clone() };
        assert!(contacts.get(&alice, &bob).await.unwrap().is_none());
        assert!(consents.get(&holder, &cell_id).await.unwrap().is_none());
        assert!(
            contacts
                .committed_completion_intents(20, None)
                .await
                .unwrap()
                .is_empty()
        );
        let binding = &completion_intent.plan.response_binding;
        let stored_plan = serde_json::to_value(&completion_intent).unwrap();
        assert!(stored_plan.get("outcome").is_none());
        assert_eq!(stored_plan["confirmation"]["state"], "pending");
        assert!(
            completion_intent.request_receipt_core().is_err(),
            "pending has no authorizing receipt core"
        );
        let pending = contacts
            .completion_for_request(
                &binding.authenticated_actor,
                &binding.idempotency_key,
                &binding.request_hash,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.event.event_id, events[0].event_id);
        assert!(pending.result.is_none());
        assert!(
            contacts
                .completion_for_request(
                    &binding.authenticated_actor,
                    &binding.idempotency_key,
                    "different request hash"
                )
                .await
                .is_err()
        );
        let seal = seal(&events, &digests, outcome);
        let premature = soland_storage::CommittedContactCompletionIntent {
            event_digest: digests[0].clone(),
            deciding_seal_id: seal.id.clone(),
            intent: completion_intent.clone(),
        };
        assert!(
            contacts
                .finalize_completion_intent(&premature, &completion_result, delivery_arg)
                .await
                .is_err(),
            "pending cannot enter outbox"
        );

        if outcome == CommandOutcome::Committed {
            let mut invalid_root = seal.clone();
            invalid_root.state_root = format!("sha256:{}", "f".repeat(64)).parse().unwrap();
            invalid_root.id = invalid_root.derive_id(DigestSuite::Sha256).unwrap();
            assert!(
                stores
                    .event_seal_committer
                    .commit_if_head(
                        &invalid_root,
                        DigestSuite::Sha256,
                        None,
                        &[],
                        &BTreeSet::new(),
                        &[]
                    )
                    .await
                    .is_err()
            );
            assert!(
                contacts.get(&alice, &bob).await.unwrap().is_none(),
                "a rejected state root never publishes Contact members"
            );
            assert!(
                consents.get(&holder, &cell_id).await.unwrap().is_none(),
                "a rejected state root never publishes consent and invalidation"
            );
        }
        if outcome == CommandOutcome::Committed {
            // A failure in the final member must undo already-applied mirrors,
            // not just prevent publication before replay starts.
            let mut conn = pool.get().await.unwrap();
            sql_query(
                "UPDATE state_control_events SET pending_domain_effects=$2 WHERE event_digest=$1",
            )
            .bind::<Text, _>(digests.last().unwrap().as_str())
            .bind::<Jsonb, _>(json!({"contact":null,"consent":"corrupt"}))
            .execute(&mut conn)
            .await
            .unwrap();
            drop(conn);
            assert!(
                stores
                    .event_seal_committer
                    .commit_if_head(&seal, DigestSuite::Sha256, None, &[], &BTreeSet::new(), &[])
                    .await
                    .is_err()
            );
            assert!(contacts.get(&alice, &bob).await.unwrap().is_none());
            assert!(consents.get(&holder, &cell_id).await.unwrap().is_none());
            let mut conn = pool.get().await.unwrap();
            sql_query(
                "UPDATE state_control_events SET pending_domain_effects=$2 WHERE event_digest=$1",
            )
            .bind::<Text, _>(digests.last().unwrap().as_str())
            .bind::<Jsonb, _>(json!({"contact":null,"consent":true}))
            .execute(&mut conn)
            .await
            .unwrap();
        }
        assert!(
            stores
                .event_seal_committer
                .commit_if_head(&seal, DigestSuite::Sha256, None, &[], &BTreeSet::new(), &[])
                .await
                .unwrap()
        );
        let ready = contacts
            .committed_completion_intents(20, None)
            .await
            .unwrap();
        if outcome == CommandOutcome::Committed {
            assert_eq!(ready.len(), 1);
            assert_eq!(ready[0].deciding_seal_id, seal.id);
            let installed_before_signature = contacts.get(&alice, &bob).await.unwrap().unwrap();
            assert!(
                installed_before_signature.request_receipts.is_empty(),
                "confirmation must not install signature placeholders"
            );
            let slot = installed_before_signature
                .request_slot_states
                .iter()
                .find(|slot| slot.owner_id == alice)
                .unwrap();
            assert_eq!(
                slot.head_digest,
                ready[0].intent.request_core_digest().unwrap()
            );
            let (completion_result, delivery) = finalized_fixture(&ready[0].intent);
            let delivery_arg = remote.then_some(&delivery);
            if let soland_storage::ContactCompletionResult::Accepted {
                outcome:
                    arkret_models_collaboration::contact_operations::ContactAcceptedOutcome::Request {
                        request_acceptance_receipt,
                        ..
                    },
            } = &completion_result
            {
                assert!(request_acceptance_receipt.core.accepted_at > events[0].created_at);
                assert_eq!(
                    request_acceptance_receipt.receipt_digest,
                    request_acceptance_receipt.computed_core_digest().unwrap()
                );
            }

            let mut altered = completion_result.clone();
            if let soland_storage::ContactCompletionResult::Accepted {
                outcome:
                    arkret_models_collaboration::contact_operations::ContactAcceptedOutcome::Request {
                        request_acceptance_receipt,
                        ..
                    },
            } = &mut altered
            {
                request_acceptance_receipt.core.peer =
                    request_acceptance_receipt.core.holder.clone();
                request_acceptance_receipt.receipt_digest =
                    request_acceptance_receipt.computed_core_digest().unwrap();
            }
            assert!(
                contacts
                    .finalize_completion_intent(&ready[0], &altered, delivery_arg)
                    .await
                    .is_err(),
                "finality cannot rewrite admitted Contact claims"
            );
            let mut wrong_seal = ready[0].clone();
            wrong_seal.deciding_seal_id = format!("ak:seal:sha256:{}", "f".repeat(64))
                .parse()
                .unwrap();
            assert!(
                contacts
                    .finalize_completion_intent(&wrong_seal, &completion_result, delivery_arg)
                    .await
                    .is_err()
            );
            assert_eq!(
                contacts
                    .committed_completion_intents(20, None)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            let mut conn = pool.get().await.unwrap();
            sql_query("CREATE FUNCTION fail_contact_delivery_finalize() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.contact_completion_result IS NOT NULL THEN RAISE EXCEPTION 'test finalize failure'; END IF; RETURN NEW; END $$").execute(&mut conn).await.unwrap();
            sql_query("CREATE TRIGGER fail_contact_delivery_finalize BEFORE UPDATE ON state_control_events FOR EACH ROW EXECUTE FUNCTION fail_contact_delivery_finalize()").execute(&mut conn).await.unwrap();
            drop(conn);
            assert!(
                contacts
                    .finalize_completion_intent(&ready[0], &completion_result, delivery_arg)
                    .await
                    .is_err()
            );
            assert_eq!(
                contacts
                    .committed_completion_intents(20, None)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            let mut conn = pool.get().await.unwrap();
            #[derive(diesel::QueryableByName)]
            struct OutboxCount {
                #[diesel(sql_type=BigInt)]
                count: i64,
            }
            assert_eq!(
                sql_query("SELECT count(*)::bigint AS count FROM federation_outbox")
                    .get_result::<OutboxCount>(&mut conn)
                    .await
                    .unwrap()
                    .count,
                0,
                "failed intent consumption rolls back the outbox insert"
            );
            sql_query("DROP TRIGGER fail_contact_delivery_finalize ON state_control_events")
                .execute(&mut conn)
                .await
                .unwrap();
            sql_query("DROP FUNCTION fail_contact_delivery_finalize()")
                .execute(&mut conn)
                .await
                .unwrap();
            drop(conn);
            assert!(
                contacts
                    .finalize_completion_intent(&ready[0], &completion_result, delivery_arg)
                    .await
                    .unwrap()
            );
            assert!(
                contacts
                    .committed_completion_intents(20, None)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                !contacts
                    .finalize_completion_intent(&ready[0], &completion_result, delivery_arg)
                    .await
                    .unwrap()
            );
            let mut rebound = delivery.clone();
            rebound.payload_json.push(' ');
            assert!(
                contacts
                    .finalize_completion_intent(&ready[0], &completion_result, Some(&rebound))
                    .await
                    .is_err(),
                "an existing key fixes exact bytes"
            );
        } else {
            assert!(ready.is_empty());
            assert!(
                contacts
                    .finalize_completion_intent(&premature, &completion_result, delivery_arg)
                    .await
                    .is_err(),
                "rejected cannot enter outbox"
            );
            let mut conn = pool.get().await.unwrap();
            #[derive(diesel::QueryableByName)]
            struct IntentCount {
                #[diesel(sql_type=BigInt)]
                count: i64,
            }
            assert_eq!(sql_query("SELECT count(*)::bigint AS count FROM state_control_events WHERE contact_completion_intent IS NOT NULL").get_result::<IntentCount>(&mut conn).await.unwrap().count, 0);
        }
        let completed = contacts
            .completion_for_request(
                &binding.authenticated_actor,
                &binding.idempotency_key,
                &binding.request_hash,
            )
            .await
            .unwrap()
            .unwrap()
            .result
            .unwrap();
        match (&completed, outcome) {
            (
                soland_storage::ContactCompletionResult::Accepted { .. },
                CommandOutcome::Committed,
            ) => {}
            (
                soland_storage::ContactCompletionResult::Rejected { problem },
                CommandOutcome::Rejected,
            ) => {
                let reason = serde_json::to_value(problem).unwrap();
                assert_eq!(problem.code(), "failed_precondition");
                assert_eq!(reason["reason_code"], "state_mismatch");
            }
            _ => panic!("completion must preserve exact command outcome"),
        }
        // The private response binding survives the generic HTTP idempotency TTL.
        let mut conn = pool.get().await.unwrap();
        sql_query("DELETE FROM idempotency_keys")
            .execute(&mut conn)
            .await
            .unwrap();
        drop(conn);
        let repeated = contacts
            .completion_for_request(
                &binding.authenticated_actor,
                &binding.idempotency_key,
                &binding.request_hash,
            )
            .await
            .unwrap()
            .unwrap()
            .result
            .unwrap();
        assert_eq!(
            serde_json::to_value(completed).unwrap(),
            serde_json::to_value(repeated).unwrap()
        );
        let contact = contacts.get(&alice, &bob).await.unwrap();
        let consent = consents.get(&holder, &cell_id).await.unwrap();
        if outcome == CommandOutcome::Committed {
            let contact = contact.unwrap();
            assert_eq!(
                contact.granted_to_target_scopes,
                vec!["direct_conversation"]
            );
            assert_eq!(contact.granted_to_requester_scopes, vec!["invite"]);
            assert_eq!(contact.message.as_deref(), Some("local metadata"));
            assert_eq!(contact.request_event_ref, Some(events[1].event_id.clone()));
            assert_eq!(contact.response_event_ref, Some(events[2].event_id.clone()));
            let consent = consent.unwrap();
            assert_eq!(consent.active_grants.len(), 1);
            assert_eq!(
                consent
                    .revoked_grants
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([dot])
            );
        } else {
            assert!(contact.is_none());
            assert!(consent.is_none());
        }
        assert!(
            stores
                .event_seal_committer
                .commit_if_head(&seal, DigestSuite::Sha256, None, &[], &BTreeSet::new(), &[])
                .await
                .unwrap(),
            "exact replay is idempotent"
        );
        let mut conn = pool.get().await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct Cache {
            #[diesel(sql_type=BigInt)]
            revision: i64,
            #[diesel(sql_type=Jsonb)]
            payload: serde_json::Value,
        }
        let cache = sql_query(
            "SELECT revision,payload FROM account_datas WHERE actor_id=$1 AND account_data_key=$2",
        )
        .bind::<Text, _>(alice.to_string())
        .bind::<Text, _>(arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
        .get_result::<Cache>(&mut conn)
        .await
        .unwrap();
        assert_eq!(
            cache.revision,
            if outcome == CommandOutcome::Committed {
                10
            } else {
                9
            }
        );
        assert_eq!(
            cache.payload["quarantine_entries"]
                .as_array()
                .unwrap()
                .len(),
            if outcome == CommandOutcome::Committed {
                1
            } else {
                2
            }
        );
        if outcome == CommandOutcome::Committed {
            assert_eq!(
                cache.payload["quarantine_entries"][0]["source_peer_principal_id"],
                json!(actor("domain-carol").signing_principal_id())
            );
        }
        #[derive(diesel::QueryableByName)]
        struct Remaining {
            #[diesel(sql_type=BigInt)]
            count: i64,
        }
        assert_eq!(sql_query("SELECT count(*)::bigint AS count FROM state_control_events WHERE realm_id=$1 AND pending_domain_effects IS NOT NULL").bind::<Text,_>(realm.as_str()).get_result::<Remaining>(&mut conn).await.unwrap().count,0);
    }
}

#[tokio::test]
async fn contact_normal_absence_is_fixed_at_the_committed_slot_transaction() {
    use arkret_models_collaboration::contact_operations::{
        ContactAcceptedOutcome, ContactPeer, ContactRound, OutgoingRequestState,
        OutgoingSlotAbsenceTranscript,
    };
    use soland_storage::{ContactCompletionAction, ContactCompletionResult};
    let database = crate::TestDatabase::lease().await;
    let pool = database.pool();
    let stores = crate::build_state_resolution_stores(
        Some(pool.clone()),
        Arc::new(
            soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry()
                .unwrap(),
        ),
    );
    let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"contact normal slot acceptance"),
    ));
    let alice = actor("normal-alice");
    let bob = actor("normal-bob");
    let peer = ContactPeer::Human {
        account_id: alice.as_account_id().unwrap().clone(),
    };
    let request = event(
        "ak.contact.requested",
        &realm,
        bob.clone(),
        0,
        json!({"peer":peer,"granted_to_peer_scopes":["invite"],"introduction_evidence_digest":format!("sha256:{}","c".repeat(64))}),
    );
    let mut source = delivery_fixture(&request, &alice);
    source.freeze_acceptance_time(request.created_at).unwrap();
    let (
        ContactCompletionResult::Accepted {
            outcome:
                ContactAcceptedOutcome::Request {
                    request_acceptance_receipt: receipt,
                    ..
                },
        },
        _,
    ) = finalized_fixture(&source)
    else {
        panic!("request fixture")
    };
    let mut pair = [alice.clone(), bob.clone()];
    if arkret_canonical::canonical_json_bytes(&pair[0]).unwrap()
        > arkret_canonical::canonical_json_bytes(&pair[1]).unwrap()
    {
        pair.swap(0, 1);
    }
    let round = ContactRound::Normal {
        sorted_pair_member_ids: pair.clone(),
        request_event_ref: request.event_id.clone(),
        request_acceptance_receipt_digest: receipt.computed_receipt_digest().unwrap(),
    };
    let round_id =
        arkret_models_collaboration::direct_conversation_ops::contact_round_id(&round).unwrap();
    let response = event(
        "ak.contact.accepted",
        &realm,
        alice.clone(),
        1,
        json!({"peer":{"kind":"human","account_id":bob.as_account_id().unwrap()},"contact_round_id":round_id,"version":1,"request_event_ref":request.event_id,"request_acceptance_receipt_digest":receipt.computed_receipt_digest().unwrap(),"granted_to_peer_scopes":["invite"]}),
    );
    let absence = OutgoingSlotAbsenceTranscript {
        sorted_pair_member_ids: pair,
        request_slot_owner: alice.clone(),
        contact_round_id: round_id.clone(),
        slot_predecessor: None,
        cas_sequence: 1,
        cas_frontier: vec![response.event_id.clone()],
        observed_at: request.created_at,
        outgoing_request_state: OutgoingRequestState::Absent,
    };
    let old_digest = absence.digest().unwrap();
    let mut draft = completion_draft_fixture(&response, &bob);
    draft.action = ContactCompletionAction::Response {
        request_receipt: receipt.clone(),
        absence,
    };
    draft.target.introduction_evidence = None;
    let completion = draft.bind_producer(fixture_producer(&response)).unwrap();
    let contacts = crate::PgContactStore { pool: pool.clone() };
    let mut current = contact(bob.clone(), alice.clone(), &request);
    current.request_receipts = vec![receipt];
    contacts.put(&current).await.unwrap();
    let mut planned = current;
    planned.status = "accepted".into();
    planned.contact_round_id = Some(round_id);
    planned.version = Some(1);
    planned.granted_to_requester_scopes = vec!["invite".into()];
    planned.response_event_ref = Some(response.event_id.clone());
    let ingress = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
        device_id: "fixture".into(),
        device_authorize_event_id: "fixture".into(),
        device_generation_ref: 1,
        seal_basis_digest: "fixture".into(),
    });
    let digests = stores
        .control_event_store
        .put_pending_unit_with_ingress(&[ControlUnitIngressMember {
            event: response.clone(),
            digest_suite: DigestSuite::Sha256,
            ingress,
        }])
        .await
        .unwrap();
    let mut conn = pool.get().await.unwrap();
    stage_domain_effects(
        &mut conn,
        &response,
        digests[0].as_str(),
        Some(ContactProjectionCommit {
            completion_intent: Some(completion),
            record: planned,
            expected_updated_at: None,
            conflict_code: "fixture".into(),
            verified_mirror: None,
            invite_policy: None,
        }),
        None,
    )
    .await
    .unwrap();
    drop(conn);
    let seal = seal(&[response], &digests, CommandOutcome::Committed);
    stores
        .event_seal_committer
        .commit_if_head(&seal, DigestSuite::Sha256, None, &[], &BTreeSet::new(), &[])
        .await
        .unwrap();
    let ready = contacts
        .committed_completion_intents(20, None)
        .await
        .unwrap();
    assert_eq!(ready.len(), 1);
    let accepted_at = ready[0].intent.accepted_at().unwrap();
    let ContactCompletionAction::Response { absence, .. } = &ready[0].intent.plan.action else {
        panic!("response plan")
    };
    assert_eq!(absence.observed_at, accepted_at);
    assert!(accepted_at > request.created_at);
    assert_ne!(absence.digest().unwrap(), old_digest);
    let installed = contacts.get(&bob, &alice).await.unwrap().unwrap();
    let slot = installed
        .request_slot_states
        .iter()
        .find(|slot| slot.owner_id == alice)
        .unwrap();
    assert_eq!(slot.head_digest, absence.digest().unwrap());
    assert_eq!(slot.accepted_sequence, 1);
    assert!(
        installed.contact_round_evidence.is_none(),
        "no signed wire evidence exists before completion"
    );
    let mut retry = ready[0].intent.clone();
    assert!(
        retry
            .freeze_acceptance_time(accepted_at + chrono::Duration::seconds(1))
            .is_err()
    );
}
