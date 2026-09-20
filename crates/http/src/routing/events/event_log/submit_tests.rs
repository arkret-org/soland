use super::*;

#[test]
fn initial_batch_context_separates_portable_realm_bootstrap_from_native_units() {
    for ordinary_realm_create in [
        serde_json::json!({
            "kind": arkret_wire::EventKind::RealmCreate.as_str(),
            "payload": {"object": {"purpose": "collaboration"}},
            "refs": [],
        }),
        serde_json::json!({
            "kind": arkret_wire::EventKind::RealmCreate.as_str(),
            "payload": {"object": {"purpose": "direct_conversation"}},
            "refs": [],
        }),
        serde_json::json!({
            "kind": arkret_wire::EventKind::RealmCreate.as_str(),
            "payload": {"object": {"purpose": "agent_control"}},
            "refs": [],
        }),
        serde_json::json!({
            "kind": arkret_wire::EventKind::RealmCreate.as_str(),
            "payload": {"object": {"purpose": "applet_managed_control"}},
            "refs": [],
        }),
    ] {
        assert_eq!(
            initial_batch_submit_context(&[ordinary_realm_create]),
            arkret_wire::EventSubmitContext::RealmBootstrap,
        );
    }

    let human_pcr_create = serde_json::json!({
        "kind": arkret_wire::EventKind::RealmCreate.as_str(),
        "refs": [{
            "role": "did_inception",
            "id": "fixture",
            "critical": true,
        }],
    });
    assert_eq!(
        initial_batch_submit_context(&[human_pcr_create]),
        arkret_wire::EventSubmitContext::AnchorUnit,
    );

    let recovery_reanchor = serde_json::json!({
        "kind": arkret_wire::EventKind::DeviceReanchor.as_str(),
        "refs": [],
    });
    assert_eq!(
        initial_batch_submit_context(&[recovery_reanchor]),
        arkret_wire::EventSubmitContext::AnchorUnit,
    );

    assert_eq!(
        initial_batch_submit_context(&[serde_json::json!({
            "kind": arkret_wire::EventKind::RealmProfile.as_str(),
            "refs": [],
        })]),
        arkret_wire::EventSubmitContext::Standard,
    );
}

#[test]
fn identity_creation_proof_allows_bounded_cross_service_clock_skew() {
    let now = chrono::Utc::now();
    let accepted_issued_at =
        now + chrono::Duration::seconds(IDENTITY_CREATION_CONTROL_PROOF_MAX_FUTURE_SKEW_SECONDS);
    let rejected_issued_at = accepted_issued_at + chrono::Duration::milliseconds(1);

    assert!(identity_creation_control_proof_window_valid(
        accepted_issued_at,
        accepted_issued_at + chrono::Duration::minutes(5),
        now,
    ));
    assert!(!identity_creation_control_proof_window_valid(
        rejected_issued_at,
        rejected_issued_at + chrono::Duration::minutes(5),
        now,
    ));
}

mod event_collision_reason_tests {
    use super::*;

    #[test]
    fn storage_collision_maps_to_registered_witness_disagreement_reason() {
        let error = map_event_hash_collision(
            "ak:event:fixture",
            &soland_services::ServiceError::Conflict("event_hash_collision".to_owned()),
        )
        .expect("storage collision must be externally quarantined");

        assert_eq!(error.code(), "witness_disagreement");
        assert_eq!(
            error.quarantine_event_id().as_deref(),
            Some("ak:event:fixture")
        );
    }

    #[test]
    fn semantic_schema_violation_keeps_machine_reason_in_details() {
        let error = SubmitOneError::semantic_schema_violation("private_view_requires_account_data");

        assert_eq!(error.code(), "schema_violation");
        assert_eq!(
            error
                .details()
                .and_then(|details| details.get("reason_code"))
                .and_then(Value::as_str),
            Some("private_view_requires_account_data")
        );
    }
}

mod circle_error_mapping_tests {
    use super::*;

    #[test]
    fn non_realm_member_is_failed_precondition_with_registered_subreason() {
        let error = submit_one_error_to_app_error(
            "circle member admission",
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER.to_owned(),
            "target actor is not a Realm member",
        );

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            error.http_status(),
            soland_http::error::error_http_status(error.code)
        );
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER)
        );
    }

    #[test]
    fn missing_circle_manage_capability_stays_capability_denied() {
        let error = submit_one_error_to_app_error(
            "circle member admission",
            StatusCode::FORBIDDEN,
            "circle_member_manage_capability_required".to_owned(),
            "caller lacks Circle member management authority",
        );

        assert_eq!(error.code, ErrorCode::CapabilityDenied);
        assert_eq!(error.http_status(), StatusCode::FORBIDDEN);
        // Not a registered reason code: the internal discriminator rides the
        // unstable `reason_detail` channel instead of `reason_code`.
        assert_eq!(error.reason_code, None);
        assert_eq!(
            error.reason_detail.as_deref(),
            Some("circle_member_manage_capability_required")
        );
    }
}

mod relation_error_mapping_tests {
    use super::*;

    #[test]
    fn cross_realm_structural_relation_uses_registered_failed_precondition_binding() {
        let error = submit_one_error_to_app_error(
            "relation admission",
            StatusCode::PRECONDITION_FAILED,
            arkret_wire::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION.to_owned(),
            "structural relation endpoints cross Realm boundaries",
        );

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            error.http_status(),
            soland_http::error::error_http_status(error.code)
        );
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION)
        );
    }
}

mod applet_formal_admission_tests {
    use super::*;

    fn session(actor_id: &str) -> SessionRecord {
        let now = Utc::now();
        SessionRecord {
            account_pk: None,
            token_hash: "fixture".to_owned(),
            actor: actor_id.to_owned(),
            device_id: String::new(),
            audience: "ak:did_core:web:ps.example".to_owned(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: now + Duration::minutes(5),
            created_at: now,
            revoked_at: None,
        }
    }

    #[test]
    fn staged_applet_authority_is_exactly_bound_to_event_coordinates_and_method() {
        let actor_id = "ak:did_core:web:applet.example";
        let realm_id = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
        let applet_id =
            arkret_wire::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001".to_owned())
                .unwrap();
        let method =
            arkret_wire::DidUrl::new("did:web:applet.example#event-key".to_owned()).unwrap();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[7_u8; 32]);
        let key = arkret_wire::DidKey::new(format!("did:key:{multibase}")).unwrap();
        let admission = InternalEventAdmission::applet_formal(
            realm_id,
            arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(actor_id).unwrap()),
            arkret_wire::EventKind::ProfileCreate.as_str(),
            "event-exact",
            applet_id.clone(),
            Some((method.clone(), key.clone())),
        );
        let session = session(actor_id);
        let mut object = serde_json::json!({
            "event_id": "event-exact",
            "kind": arkret_wire::EventKind::ProfileCreate.as_str(),
            "actor_id": arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(actor_id).unwrap()),
            "realm_id": realm_id,
            "applet_id": applet_id,
        })
        .as_object()
        .unwrap()
        .clone();

        assert_eq!(
            admission.applet_formal_producer_signing_key(&session, &object, method.as_str(),),
            Some(&key)
        );
        assert!(
            admission
                .applet_formal_producer_signing_key(
                    &session,
                    &object,
                    "did:web:applet.example#other-key",
                )
                .is_none()
        );

        object.insert(
            "event_id".to_owned(),
            Value::String("event-other".to_owned()),
        );
        assert!(
            admission
                .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                .is_none()
        );
        object.insert(
            "event_id".to_owned(),
            Value::String("event-exact".to_owned()),
        );
        object.insert(
            "applet_id".to_owned(),
            Value::String("ak:applet:01974100-0000-7000-8000-000000000002".to_owned()),
        );
        assert!(
            admission
                .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                .is_none()
        );
        object.insert(
            "applet_id".to_owned(),
            Value::String(applet_id.as_str().to_owned()),
        );

        let mut wrong_session_actor = session.clone();
        wrong_session_actor.actor = "ak:did_core:web:other.example".to_owned();
        assert!(
            admission
                .applet_formal_producer_signing_key(&wrong_session_actor, &object, method.as_str(),)
                .is_none()
        );

        let mut wrong_session_device = session.clone();
        wrong_session_device.device_id = "device-other".to_owned();
        assert!(
            admission
                .applet_formal_producer_signing_key(
                    &wrong_session_device,
                    &object,
                    method.as_str(),
                )
                .is_none()
        );

        for (field, wrong_value) in [
            ("realm_id", "ak:realm:Awrong"),
            ("actor_id", "ak:did_core:web:other.example"),
            ("kind", arkret_wire::EventKind::CircleCreate.as_str()),
        ] {
            let original = object
                .insert(field.to_owned(), Value::String(wrong_value.to_owned()))
                .unwrap();
            assert!(
                admission
                    .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                    .is_none(),
                "staged authority must reject a mismatched {field}"
            );
            object.insert(field.to_owned(), original);
        }

        object.remove("realm_id");
        assert!(
            admission
                .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                .is_none(),
            "a non-genesis Event cannot omit its Realm coordinate"
        );

        let genesis_event_id =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [9_u8; 32]);
        let genesis_realm_id = arkret_wire::RealmId::from_event_id(&genesis_event_id);
        let genesis_admission = InternalEventAdmission::applet_formal(
            genesis_realm_id.as_str(),
            arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(actor_id).unwrap()),
            arkret_wire::EventKind::RealmCreate.as_str(),
            genesis_event_id.as_str(),
            applet_id,
            Some((method.clone(), key.clone())),
        );
        object.insert(
            "event_id".to_owned(),
            Value::String(genesis_event_id.to_string()),
        );
        object.insert(
            "kind".to_owned(),
            Value::String(arkret_wire::EventKind::RealmCreate.as_str().to_owned()),
        );
        assert_eq!(
            genesis_admission.applet_formal_producer_signing_key(
                &session,
                &object,
                method.as_str(),
            ),
            Some(&key)
        );

        object.insert(
            "event_id".to_owned(),
            Value::String(
                arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [8_u8; 32],
                )
                .to_string(),
            ),
        );
        assert!(
            genesis_admission
                .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                .is_none(),
            "a genesis Event with a different derived Realm coordinate is rejected"
        );

        object.insert(
            "event_id".to_owned(),
            Value::String(genesis_event_id.to_string()),
        );
        object.insert(
            "realm_id".to_owned(),
            Value::String("ak:realm:Awrong".to_owned()),
        );
        assert!(
            genesis_admission
                .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                .is_none(),
            "an explicitly wrong genesis Realm coordinate is never replaced by derivation"
        );
    }
}

mod federated_producer_event_proof_tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::verify_federated_producer_event_proof;

    fn fixture_event() -> arkret_wire::Event {
        let actor = arkret_wire::Did::new("did:web:alice.example".to_owned()).unwrap();
        let actor_id = arkret_wire::project_did_to_core_id(&actor).unwrap();
        let station_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:remote.example".to_owned()).unwrap();
        let verification_method = arkret_wire::DidUrl::new(format!(
            "{actor}#ak:device:01904100-0000-7000-8000-a11ce0000001"
        ))
        .unwrap();
        let created_at = chrono::Utc::now();
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::MessageCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(
                    "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
                )
                .unwrap(),
            },
            actor_id,
            station_id,
            1,
            arkret_wire::Hlc::new("019041000000-0000-00000000".to_owned()).unwrap(),
            serde_json::json!({
                "strand_id": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "strict proof", "format": "plain"}
            }),
            created_at,
        )
        .unwrap();
        let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            [21_u8; 32],
            actor,
            verification_method.clone(),
        );
        let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            arkret_signatures::SignEventOptions::new(
                arkret_wire::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "11".repeat(32)
                ))
                .unwrap(),
            )
            .with_created_at(created_at),
        )
        .unwrap();
        event.into_event()
    }

    fn sign_with_protected_header(
        proof: &arkret_wire::ProducerEventProof,
        actor_id: &arkret_wire::ActorId,
        key: &SigningKey,
        header: serde_json::Value,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            arkret_canonical::canonical_json_bytes(&header).expect("canonical protected header"),
        );
        let binding = proof
            .canonical_binding_bytes(actor_id)
            .expect("canonical Event proof binding");
        let signing_input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(binding));
        format!(
            "{header}..{}",
            URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()).to_bytes())
        )
    }

    #[test]
    fn federated_producer_uses_strict_event_header_profile() {
        let event = fixture_event();
        let producer = event
            .producer_proof
            .as_ref()
            .expect("producer proof")
            .clone();
        let key = SigningKey::from_bytes(&[21_u8; 32]);

        verify_federated_producer_event_proof(
            &event,
            &producer,
            key.verifying_key().as_bytes(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("ordinary Event protected header verifies");
        let wrong_key = SigningKey::from_bytes(&[22_u8; 32]);
        verify_federated_producer_event_proof(
            &event,
            &producer,
            wrong_key.verifying_key().as_bytes(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect_err("an exact method binding cannot substitute different staged key bytes");

        let mut forbidden_kid = producer.clone();
        forbidden_kid.jws = sign_with_protected_header(
            &forbidden_kid,
            &event.actor_id,
            &key,
            serde_json::json!({
                "alg": "Ed25519",
                "kid": forbidden_kid.verification_method.as_str()
            }),
        );
        verify_federated_producer_event_proof(
            &event,
            &forbidden_kid,
            key.verifying_key().as_bytes(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect_err("Event protected headers must reject kid even with a valid signature");
    }
}

mod received_at_stamp_tests {
    use super::*;

    fn operation_for_kind(kind: impl AsRef<str>, suffix: u32) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{suffix:012x}"
            ))
            .unwrap(),
            RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned())
                .unwrap(),
            kind.as_ref(),
            json!({ "actor_id": "ak:did_core:web:alice.example" }),
        )
    }

    #[test]
    fn received_at_stamp_only_mutates_membership_projection_payloads() {
        let received_at = DateTime::parse_from_rfc3339("2026-07-07T05:20:58.398662Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut device_authorize = operation_for_kind("ak.device.authorize", 1);
        let mut member_state = operation_for_kind(arkret_wire::EventKind::MemberState, 2);
        let mut circle_member_state =
            operation_for_kind(arkret_wire::EventKind::CircleMemberState, 3);

        stamp_projection_operation_received_at(&mut device_authorize, received_at);
        stamp_projection_operation_received_at(&mut member_state, received_at);
        stamp_projection_operation_received_at(&mut circle_member_state, received_at);

        assert!(device_authorize.payload.get("event_received_at").is_none());
        assert_eq!(
            member_state
                .payload
                .get("event_received_at")
                .and_then(Value::as_str),
            Some("2026-07-07T05:20:58.398Z")
        );
        assert_eq!(
            circle_member_state
                .payload
                .get("event_received_at")
                .and_then(Value::as_str),
            Some("2026-07-07T05:20:58.398Z")
        );
    }
}

mod agent_pcr_batch_tests {
    use super::*;

    fn agent_create_value() -> Value {
        let realm_id =
            RealmId::new("ak:realm:AZiVojGkhKKjoBSA6eV96sZAm4u3Ze_3uMmkr30F6ZQZ".to_owned())
                .unwrap();
        let agent_id =
            arkret_identifiers::Did::new("did:webvh:z6mkfixtureagent:agent.example".to_owned())
                .unwrap();
        let agent_actor_id = arkret_wire::project_did_to_core_id(&agent_id).unwrap();
        let genesis = arkret_models_collaboration::events_payloads::RealmGenesis::agent_control(
            arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned())
                .unwrap(),
            arkret_models_identity::ResolutionCommitment {
                did: agent_id.clone(),
                method_history_head: format!("sha256:{}", "8".repeat(64)),
                version_id: "1-Qmfixture".to_owned(),
            },
            arkret_identifiers::TrustDomainId::new("ak:trust_domain:agent-pcr".to_owned()).unwrap(),
            vec!["ak.profile.principal_control_realm.v1".to_owned()],
            arkret_wire::CORE_REDUCER_PROFILE,
            arkret_canonical::DigestSuite::Sha256,
            arkret_wire::SecurityClass::HighAssurance,
            arkret_wire::EncryptionProfile::MlsRfc9420,
            crate::test_notary("did:webvh:z6mkfixtureagent:agent.example", 43),
        )
        .unwrap();
        let payload =
            arkret_models_collaboration::events_payloads::RealmCreatePayload::new(genesis)
                .to_value()
                .unwrap();
        let mut event = crate::test_event::raw_event(
            arkret_wire::EventKind::RealmCreate.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id },
            agent_actor_id,
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce1".to_owned()).unwrap(),
            payload,
        )
        .unwrap();
        event.executed_by = Some(arkret_wire::ActorId::service(crate::test_actor_id_str(
            "did:web:alice.example",
        )));
        event.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );
        event.refs.clear();
        // v1 carries no producer `effects[]`: the router recognises a managed
        // Agent PCR create by whether the registered contract materializes its
        // control material, so the fixture is the bare signed Event.
        serde_json::to_value(event).unwrap()
    }

    #[test]
    fn delegated_agent_create_bypasses_ordinary_bootstrap_router() {
        assert!(batch_is_agent_pcr_create(&[agent_create_value()]));
    }

    #[test]
    fn ordinary_or_multi_event_create_stays_on_ordinary_bootstrap_router() {
        let mut ordinary = agent_create_value();
        ordinary.as_object_mut().unwrap().remove("executed_by");
        assert!(!batch_is_agent_pcr_create(&[ordinary]));

        let managed = agent_create_value();
        assert!(!batch_is_agent_pcr_create(&[managed.clone(), managed,]));
    }
}

mod internal_event_admission_tests {
    use super::*;

    fn internal_session(actor: &str, device_id: &str) -> SessionRecord {
        let now = Utc::now();
        SessionRecord {
            account_pk: None,
            token_hash: "internal-session".to_owned(),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            audience: "soland".to_owned(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: now + Duration::minutes(5),
            created_at: now,
            revoked_at: None,
        }
    }

    fn mimi_session() -> SessionRecord {
        internal_session("ak:did_core:web:mimi.example", "")
    }

    #[test]
    fn mimi_provider_admission_reads_provenance_from_canonical_payload() {
        let admission = InternalEventAdmission::mimi_provider(
            "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
            arkret_wire::ActorId::service(
                arkret_wire::DidCoreId::new("ak:did_core:web:mimi.example").unwrap(),
            ),
            "ak:event:AVF6xfk5EJU6x8wIqKL3WPOsSROVxJPxOu8HiqfxQGD7",
        );
        let object = json!({
            "actor_id": arkret_wire::ActorId::service(arkret_wire::DidCoreId::new("ak:did_core:web:mimi.example").unwrap()),
            "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
            "kind": "ak.message.create",
            "payload": {
                "mimi_provenance": {
                    "provenance": "mimi_facade",
                    "source_provider": "ak:did_core:web:mimi-provider.example",
                    "attributed_sender_actor_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                        arkret_wire::DidCoreId::new("ak:did_core:web:mimi-provider.example").unwrap(),
                    )),
                    "attributed_sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                    "source_envelope_digest": format!("sha256:{}", "1".repeat(64)),
                    "room_binding_ref": "ak:event:AVF6xfk5EJU6x8wIqKL3WPOsSROVxJPxOu8HiqfxQGD7"
                }
            }
        });

        assert!(admission.matches(&mimi_session(), object.as_object().unwrap()));
    }

    #[test]
    fn mimi_agent_reporter_admission_binds_executor_method_and_evidence_freeze_lane() {
        let realm_id = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
        let station_id = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let reporter = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            station_id.clone(),
        ));
        let agent = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice-agent.example").unwrap(),
            station_id,
        ));
        let method = arkret_wire::DidUrl::new("did:web:alice-agent.example#runtime-1").unwrap();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[9_u8; 32]);
        let signing_key = arkret_wire::DidKey::new(format!("did:key:{multibase}")).unwrap();
        let admission = InternalEventAdmission::mimi_reporter(
            realm_id,
            reporter.clone(),
            agent.clone(),
            "",
            method.clone(),
            Some(signing_key.clone()),
        );
        let session = internal_session(agent.signing_principal_id().as_str(), "");
        let object = json!({
            "actor_id": reporter,
            "realm_id": realm_id,
            "kind": arkret_wire::EventKind::SelfModerationReport.as_str(),
            "executed_by": agent,
            "authorization_ref": "did:web:alice-agent.example#authorized-event",
            "producer_proof": {
                "kind": "detached_jws",
                "verification_method": method,
            },
        });
        let object = object.as_object().unwrap();

        assert!(admission.matches(&session, object));
        assert!(admission.is_mimi_agent_reporter());
        assert_eq!(
            admission.mimi_reporter_producer_signing_key(&session, object, method.as_str(),),
            Some(&signing_key)
        );

        let mut wrong_executor = object.clone();
        wrong_executor.insert("executed_by".to_owned(), json!(reporter));
        assert!(!admission.matches(&session, &wrong_executor));

        let mut wrong_method = object.clone();
        wrong_method
            .get_mut("proofs")
            .unwrap()
            .as_array_mut()
            .unwrap()[0]["verification_method"] =
            json!("did:web:alice-agent.example#stale-runtime");
        assert!(!admission.matches(&session, &wrong_method));
    }
}
