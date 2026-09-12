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
    arkret_wire::test_support::raw_event_for_actor_at(
        kind,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        actor,
        seq,
        "019f00000000-0000-00000001".parse().unwrap(),
        payload,
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
    )
    .unwrap()
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
            "state_mismatch".parse().unwrap(),
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
        notary_signature: arkret_wire::MultiSignature {
            kind: arkret_wire::MultiSigKind::MultiSig,
            view: 0,
            signatures: vec![arkret_wire::SealSignature {
                verification_method: "did:web:station.example#notary".parse().unwrap(),
                payload_digest: placeholder,
                jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".into(),
            }],
        },
        sealed_at: events[0].created_at,
        hlc: "019f00000000-0000-00000001".parse().unwrap(),
        configuration_ref: events[0].event_id.clone(),
        command_results: vec![result],
        authorization_closures: vec![],
        existence_anchors: vec![],
        transaction_records: vec![],
    };
    seal.id = seal.derive_id(DigestSuite::Sha256).unwrap();
    seal
}

#[tokio::test]
async fn contact_and_consent_mirrors_require_exact_committed_unit_and_replay_in_member_order() {
    for (index, outcome) in [CommandOutcome::Committed, CommandOutcome::Rejected]
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
        let bob = actor("domain-bob");
        let consent_id = "ak:consent:01964137-0000-7000-8000-000000000001";
        let request = event("ak.contact.requested", &realm, alice.clone(), 0, json!({}));
        let scope_a = event(
            "ak.contact.scope.update",
            &realm,
            alice.clone(),
            1,
            json!({}),
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
        let seal = seal(&events, &digests, outcome);
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
