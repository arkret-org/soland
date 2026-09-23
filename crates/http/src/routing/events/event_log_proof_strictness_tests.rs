use soland_storage_postgres::Db;

use super::*;
use crate::config::{AppConfig, ObjectStorageConfig};

pub(super) fn make_state(development_mode: bool) -> AppState {
    let config = AppConfig {
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-test")),
        development_mode,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        seed_demo_data: true,
        ..AppConfig::test_default()
    };
    AppState::new(config, Db { pool: None })
}

fn typed_event_envelope(kind: &str, payload: Value) -> Value {
    let event = crate::test_event::raw_event(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
            )
            .unwrap(),
        },
        crate::test_actor_id_str("did:webvh:z6mkfixture:alice.example"),
        7,
        arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
        payload,
    )
    .unwrap();
    serde_json::to_value(event).unwrap()
}

// Match the SDK raw projected-operation fixture's explicit self-Station account.
fn projected_fixture_actor(principal: &str) -> arkret_wire::ActorId {
    let principal = arkret_wire::DidCoreId::new(principal).unwrap();
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(principal.clone(), principal))
}

fn dev_proof_envelope() -> serde_json::Map<String, Value> {
    let mut object = serde_json::Map::new();
    object.insert(
        "actor_id".to_owned(),
        json!(crate::test_account_actor(
            &arkret_wire::Did::new("did:web:alice.example").unwrap()
        )),
    );
    object.insert(
        "proofs".to_owned(),
        json!([{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#dev_alice",
            "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }]),
    );
    object.insert("payload".to_owned(), json!({"body": "hello"}));
    object
}

fn session() -> SessionRecord {
    SessionRecord {
        account_pk: None,
        token_hash: "hash".to_owned(),
        actor: "ak:did_core:web:alice.example".to_owned(),
        device_id: "ak:device:01904100-0000-7000-8000-a11ce0000001".to_owned(),
        audience: crate::test_event::station_id().to_string(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        created_at: chrono::Utc::now(),
        revoked_at: None,
    }
}

/// Test helper: ingest a fresh webvh document for `did` so the high-risk
/// freshness gate passes. put_document stamps fetched_at/expires_at with
/// the ingestion instant.
async fn ingest_fresh_webvh_document(state: &AppState, did: &str) {
    let now = chrono::Utc::now();
    let public_key_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[7u8; 32]);
    state
        .dids()
        .store_document(soland_services::identity::DidDocumentState {
            did: did.to_owned(),
            did_document: json!({
                "id": did,
                "verificationMethod": [{
                    "id": format!("{did}#ak:device:01904100-0000-7000-8000-a11ce0000001"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": public_key_multibase,
                }]
            }),
            key_log_head: Some("sha256:head".to_owned()),
            seq: 1,
            method_evidence: json!({ "mode": "test" }),
            // Placeholder values; put_document overwrites them with the
            // ingestion instant.
            fetched_at: now,
            expires_at: now,
            updated_at: now,
        })
        .await
        .expect("ingest fresh webvh document");
}

fn did_key_for(signing_key: &ed25519_dalek::SigningKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]);
    bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

fn signed_member_identity_payload(signing_key: &ed25519_dalek::SigningKey) -> (String, Value) {
    use ed25519_dalek::Signer as _;

    let did = did_key_for(signing_key);
    let did_key_fragment = did.strip_prefix("did:key:").expect("did:key prefix");
    let verification_method =
        arkret_wire::DidUrl::new(format!("{did}#{did_key_fragment}")).expect("fixture DID URL");
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC".to_owned(),
    )
    .unwrap();
    let actor_id =
        arkret_wire::project_did_to_core_id(&arkret_identifiers::Did::new(did.clone()).unwrap())
            .unwrap();
    let actor = arkret_wire::ActorId::service(actor_id.clone());
    let zero_hash = arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    let mut identity = arkret_models_identity::member_identity::MemberIdentity::new(
        realm_id.clone(),
        actor.clone(),
        actor.clone(),
        arkret_models_identity::member_identity::DisplayProfile {
            display_name: "Alice".to_owned(),
            avatar_blob_ref: None,
        },
        chrono::Utc::now(),
        arkret_models_identity::member_identity::MemberIdentityProof {
            verification_method,
            signature_algorithm:
                arkret_models_identity::member_identity::MemberIdentitySignatureAlgorithm::Ed25519,
            payload_digest: zero_hash,
            signature: "AA".to_owned(),
        },
    );
    let canonical_bytes = identity.canonical_payload_bytes().unwrap();
    identity.proof.payload_digest =
        arkret_identifiers::Hash::new(identity.canonical_payload_sha256().unwrap()).unwrap();
    identity.proof.signature =
        URL_SAFE_NO_PAD.encode(signing_key.sign(&canonical_bytes).to_bytes());
    let payload = json!({
        "realm_id": realm_id.as_str(),
        "actor_id": actor,
        "segment": "member_identity",
        "identity_payload": {
            "member_identity": identity
        }
    });
    (did, payload)
}

#[tokio::test(flavor = "multi_thread")]
async fn member_identity_plaintext_ed25519_proof_verifies() {
    let state = make_state(false);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let (_, payload) = signed_member_identity_payload(&signing_key);

    validate_member_identity_proof(&state, &payload)
        .await
        .expect("valid MemberIdentity proof should verify");
}

#[tokio::test(flavor = "multi_thread")]
async fn member_identity_tampered_payload_fails_closed() {
    let state = make_state(false);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let (_, mut payload) = signed_member_identity_payload(&signing_key);
    payload["identity_payload"]["member_identity"]["display_profile"]["display_name"] =
        json!("Mallory");

    let err = validate_member_identity_proof(&state, &payload)
        .await
        .expect_err("tampered MemberIdentity payload must fail");
    assert_eq!(err.code, "member_identity_proof_invalid");
}

#[tokio::test(flavor = "multi_thread")]
async fn member_identity_unsupported_signature_algorithm_is_422() {
    let state = make_state(false);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (_, mut payload) = signed_member_identity_payload(&signing_key);
    payload["identity_payload"]["member_identity"]["proof"]["signature_algorithm"] = json!("ES256");

    let err = validate_member_identity_proof(&state, &payload)
        .await
        .expect_err("unsupported MemberIdentity signature algorithm must fail closed");
    let code = soland_http::error::ErrorCode::UnsupportedSignatureAlg;
    assert_eq!(err.status, soland_http::error::error_http_status(code));
    assert_eq!(err.code, code.as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn member_identity_encrypted_payload_is_unsupported_fail_closed() {
    let state = make_state(false);
    let payload = json!({
        "realm_id": "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
        "actor_id": "ak:did_core:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP",
        "segment": "member_identity",
        "identity_payload": {
            "encrypted_payload": {
                "encryption_algorithm": "stub"
            }
        }
    });

    let err = validate_member_identity_proof(&state, &payload)
        .await
        .expect_err("encrypted MemberIdentity proof verification is not wired");
    assert_eq!(err.code, "unsupported_feature");
}

#[test]
fn unknown_fail_closed_critical_extension_is_not_implemented() {
    let state = make_state(true);
    let envelope = json!({
        "requirements": {
            "critical_extensions": [{
                "id": "ak.extension.unknown",
                "fail_closed": true
            }]
        }
    });
    let object = envelope.as_object().unwrap();

    let err = validate_event_critical_features(&state, object)
        .expect_err("unknown fail-closed extensions must reject writes");

    assert_eq!(err.status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(err.code, "unsupported_feature");
}

#[test]
fn unknown_advisory_critical_extension_is_ignored() {
    let state = make_state(true);
    let envelope = json!({
        "requirements": {
            "critical_extensions": [{
                "id": "ak.extension.unknown",
                "fail_closed": false
            }]
        }
    });
    let object = envelope.as_object().unwrap();

    validate_event_critical_features(&state, object)
        .expect("non-fail-closed extensions are advisory and may be ignored");
}

#[test]
fn unknown_required_feature_is_unsupported_feature() {
    let state = make_state(true);
    let envelope = json!({
        "requirements": {
            "features": ["ak.feature.mimi_room_passthrough.v1"]
        }
    });
    let object = envelope.as_object().unwrap();

    let err = validate_event_critical_features(&state, object)
        .expect_err("unknown requirements.features entries must fail closed");

    assert_eq!(err.status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(err.code, "unsupported_feature");
}

#[test]
fn declared_required_feature_is_accepted() {
    let state = make_state(true);
    let envelope = json!({
        "requirements": {
            "features": ["ak.feature.blob.resumable_upload.tus.v1"]
        }
    });
    let object = envelope.as_object().unwrap();

    validate_event_critical_features(&state, object)
        .expect("declared ServiceDescribe features may be required by events");
}

#[tokio::test]
async fn policy_bundle_media_plaintext_reads_realm_meta() {
    let state = make_state(true);
    let realm_id = "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC";
    let now = chrono::Utc::now();
    state
        .realms()
        .store_realm_metadata(
            realm_id,
            soland_services::events::RealmMetadata {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "restricted".to_owned(),
                history_access: "since_join".to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::from([state
                    .service_id()
                    .clone()]),
                plaintext_visible_service_classes: std::collections::BTreeMap::from([(
                    state.service_id().clone(),
                    std::collections::BTreeSet::from([
                        arkret_wire::PlaintextDataClassKind::MediaPlaintext,
                    ]),
                )]),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    let payload = json!({ "media_service_decrypts": true });

    assert!(projected_media_plaintext_service_present(&state, realm_id, &payload).await);
}

#[tokio::test]
async fn circle_scoped_write_requires_circle_membership() {
    // circle.md §8 two-layer AND — a Realm-wide capability does NOT let a
    // non-member write into a Circle. The membership conjunct is enforced at
    // admission (`validate_operation_policy`), not only on the delivery side.
    // Regression guard for the gap where a Realm-wide grant (notably an Applet
    // bot / Ghost Actor) could inject content into a Circle it never joined.
    let state = make_state(true);
    let realm_id = "ak:realm:AU3fkxq_f4TuVlpZppN3pSPHhVOTTikXW_-Hw0vr9XCp";
    let circle_id = "ak:circle:AZT0NDzMS5h5Oz8ih_r5JqLxOrZZy4HxcAEY5s1MbM9K";
    let member = "ak:did_core:web:alice.example";
    // An Applet bot that holds a Realm-wide grant but never joined the Circle.
    let non_member = "ak:did_core:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    // Seed an active Circle whose only member is `member`.
    {
        let mut projection = state.test_projection().lock();
        projection.circles.insert(
            circle_id.to_owned(),
            soland_domain::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                profile_ref: None,
                title: "HR-Conf".to_owned(),
                summary: None,
                display: serde_json::json!({"short_name":"HR","color_token":"slate","symbol":{"glyph":"ring"}}),
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_access: "since_join".to_owned(),
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                encryption_profile: "mls_rfc9420".to_owned(),
                content_scheme: Some("mls_rfc9420".to_owned()),
                durability_policy: None,
                mls_group_ref: None,
                state: soland_domain::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([projected_fixture_actor(member).to_string()]),
            },
        );
    }

    let strand_create = |sender: &str, scope: Option<&str>| {
        let mut object = json!({
            "id": "ak:strand:AYTeR35PxnHtaUMXFLoHqGA1yiou3pai07-tzQyViJnt",
            "metadata": {"title": "t"}
        });
        if let Some(scope) = scope {
            object["scope_circle_id"] = json!(scope);
        }
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-57d7d8550abc",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::StrandCreate.as_str(),
            json!({"sender": sender, "object": object}),
        )
    };

    // Member writing into the Circle → allowed by this gate.
    validate_operation_policy(
        &state,
        std::slice::from_ref(&strand_create(member, Some(circle_id))),
    )
    .await
    .unwrap();

    // Non-member (Applet bot) writing into the Circle → rejected fail-closed.
    let err = validate_operation_policy(
        &state,
        std::slice::from_ref(&strand_create(non_member, Some(circle_id))),
    )
    .await
    .unwrap_err();
    assert_eq!(err, "circle_scope_membership_required");

    // Non-member writing a Realm-default Strand (no Circle scope) → unaffected.
    validate_operation_policy(
        &state,
        std::slice::from_ref(&strand_create(non_member, None)),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn circle_scoped_reaction_requires_circle_membership() {
    // circle.md §8 — a reaction is a write into the target Message's Strand
    // scope, so reacting to a Circle message requires Circle membership too.
    let state = make_state(true);
    let realm_id = "ak:realm:Af5kTRq88MZ71EExjwb7Pm9AHmO7tPZB470XwPwDiYge";
    let circle_id = "ak:circle:AS5EmLqkRoAqtHJcDm0xGwZ8A-MgC4120y4IpSAbqFCJ";
    let strand_id = "ak:strand:AekvaCkXy9kgtwfnxzaKIOIIHF_-HZpSbCakATPdwWMH";
    let event_id = "ak:event:ATISmX7h_m-9AlDVmW5cqCG9eM06QsDQFjEjG675Jf3A";
    let member = "ak:did_core:web:alice.example";
    let non_member = "ak:did_core:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    {
        let mut projection = state.test_projection().lock();
        projection.circles.insert(
            circle_id.to_owned(),
            soland_domain::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                profile_ref: None,
                title: "HR-Conf".to_owned(),
                summary: None,
                display: serde_json::json!({"short_name":"HR","color_token":"slate","symbol":{"glyph":"ring"}}),
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_access: "since_join".to_owned(),
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                encryption_profile: "mls_rfc9420".to_owned(),
                content_scheme: Some("mls_rfc9420".to_owned()),
                durability_policy: None,
                mls_group_ref: None,
                state: soland_domain::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([projected_fixture_actor(member).to_string()]),
            },
        );
        // A Strand scoped to the Circle, and a Message inside it.
        projection.strands.insert(
            strand_id.to_owned(),
            soland_domain::reducer::StrandProjection {
                strand_id: strand_id.to_owned(),
                realm_id: realm_id.to_owned(),
                tracks: std::collections::BTreeMap::from([(
                    arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION
                        .to_owned(),
                    arkret_models_collaboration::objects::profiles::StrandTrack::discussion_primary(
                    ),
                )]),
                title: String::new(),
                summary: None,
                content: None,
                encrypted_content: None,
                fields: std::collections::BTreeMap::new(),
                state: soland_domain::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                stage: None,
                stage_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                schema_refs: Vec::new(),
                scope_circle_id: Some(circle_id.to_owned()),
            },
        );
        projection.messages.insert(
            event_id.to_owned(),
            soland_domain::reducer::MessageState {
                event_id: event_id.to_owned(),
                message_id: soland_domain::reducer::message_id_from_event_id(event_id),
                realm_id: realm_id.to_owned(),
                sender: member.to_owned(),
                thread_id: strand_id.to_owned(),
                content: json!({}),
                encrypted: false,
                operation_id: "ak:operation:01904100-0000-7000-8000-c2c2e0000005".to_owned(),
                created_at: now,
                revision_of: None,
                redacted_at: None,
            },
        );
    }

    let reaction = |sender: &str| {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-c2c2e000000a",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::ReactionAdd.as_str(),
            json!({"sender": sender, "target_ref": event_id, "key": "👍"}),
        )
    };

    // Member may react in the Circle.
    validate_operation_policy(&state, std::slice::from_ref(&reaction(member)))
        .await
        .unwrap();

    // Non-member reacting to a Circle message is rejected.
    let err = validate_operation_policy(&state, std::slice::from_ref(&reaction(non_member)))
        .await
        .unwrap_err();
    assert_eq!(err, "circle_scope_membership_required");
}

#[tokio::test]
async fn circle_scoped_morph_update_requires_circle_membership() {
    // circle.md §8 - Morph updates are writes into the Morph's effective
    // scope. A Realm-wide grant is insufficient when the Morph was created
    // under a Circle scope.
    let state = make_state(true);
    let realm_id = "ak:realm:ASTX9r6c7ZMAY74JFAIh5TyBTiwEqs5oy5TCX7ubmLVB";
    let circle_id = "ak:circle:AQIjwhwC5jFHrCd985kMq2m5ahV3nG7qBK-aMMYLbgAt";
    let scoped_morph_id = "ak:morph:AXlXsex0Kgdp6mgmqub7aKP53d1_Zp7PifQwrYfC-8HO";
    let realm_morph_id = "ak:morph:AXg0u_PNFrZzEeHPh_4tFOFF7XNlDbiHiSewgv_unmDK";
    let member = "ak:did_core:web:alice.example";
    let non_member = "ak:did_core:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    {
        let mut projection = state.test_projection().lock();
        projection.circles.insert(
            circle_id.to_owned(),
            soland_domain::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                profile_ref: None,
                title: "HR-Conf".to_owned(),
                summary: None,
                display: serde_json::json!({"short_name":"HR","color_token":"slate","symbol":{"glyph":"ring"}}),
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_access: "since_join".to_owned(),
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                encryption_profile: "mls_rfc9420".to_owned(),
                content_scheme: Some("mls_rfc9420".to_owned()),
                durability_policy: None,
                mls_group_ref: None,
                state: soland_domain::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([projected_fixture_actor(member).to_string()]),
            },
        );
        for (morph_id, scope_circle_id) in [
            (scoped_morph_id, Some(circle_id.to_owned())),
            (realm_morph_id, None),
        ] {
            projection.morphs.insert(
                morph_id.to_owned(),
                soland_domain::reducer::MorphProjection {
                    morph_id: morph_id.to_owned(),
                    realm_id: realm_id.to_owned(),
                    scope_circle_id,
                    morph_kind: "task".to_owned(),
                    title: Some("Task".to_owned()),
                    fields: std::collections::BTreeMap::new(),
                    schema_refs: Vec::new(),
                    facets: BTreeMap::new(),
                    versions: Vec::new(),
                    content: None,
                    encrypted_content: None,
                    state: soland_domain::reducer::ObjectLifecycleState::Active,
                    state_changed_at: None,
                    stage: None,
                    stage_changed_at: None,
                    created_by: member.to_owned(),
                    created_at: now,
                    updated_by: None,
                    updated_at: None,
                },
            );
        }
    }

    let morph_update = |sender: &str, morph_id: &str| {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-c3c3e000000a",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::MorphUpdate.as_str(),
            json!({
                "sender": sender,
                "target_ref": morph_id,
                "patch": {"fields.status": "done"}
            }),
        )
    };

    validate_operation_policy(
        &state,
        std::slice::from_ref(&morph_update(member, scoped_morph_id)),
    )
    .await
    .unwrap();

    let err = validate_operation_policy(
        &state,
        std::slice::from_ref(&morph_update(non_member, scoped_morph_id)),
    )
    .await
    .unwrap_err();
    assert_eq!(err, "circle_scope_membership_required");

    validate_operation_policy(
        &state,
        std::slice::from_ref(&morph_update(non_member, realm_morph_id)),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn applet_registration_requires_realm_admin() {
    // applet-integration.md §4 — `ak.applet.registration` is gated by the
    // machine-readable `ak.realm.admin` capability. The dedicated install
    // aggregate checks this in its handler, but a raw submit via
    // `/_arkret/self/events` reaches `apply_applet_registration` with no authz of
    // its own — this gate closes that bypass. Realm ownership alone is not a
    // capability; an active `ak.realm.admin` grant is required.
    let state = make_state(true);
    let realm_id = "ak:realm:Aaleb4QrS8SxR5KXmKfDQZMNxW8WlSaUaySdeWV2-hVl";
    let owner = "ak:did_core:web:alice.example";
    let outsider = "ak:did_core:web:mallory.example";
    let now = chrono::Utc::now();
    state
        .realms()
        .store_realm_metadata(
            realm_id,
            soland_services::events::RealmMetadata {
                owner: owner.to_owned(),
                deleted: false,
                discoverability: "restricted".to_owned(),
                history_access: "since_join".to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: Default::default(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    let registration = |sender: &str| {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-57d7d855a99e",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::AppletRegistration.as_str(),
            json!({
                "sender": sender,
                "applet_id": "ak:applet:01904100-0000-7000-8000-000000000a01",
                "service_id": "ak:did_core:web:slack-bridge.example",
                "namespace": "slack",
            }),
        )
    };

    let err = validate_operation_policy(&state, std::slice::from_ref(&registration(owner)))
        .await
        .unwrap_err();
    assert_eq!(err, "applet_registration_unauthorized");

    state
        .authorization()
        .upsert_projected_grant(arkret_policy::authz::authority::Grant {
            grant_id: "ak:grant:AalTkzF6-XUhCWUy_4kjpVH_cPBfisUGqmSjxDr-hwGb".to_owned(),
            realm_id: realm_id.to_owned(),
            issuer_id: projected_fixture_actor(owner),
            subject_id: projected_fixture_actor(owner),
            resource: realm_id.to_owned(),
            actions: vec!["ak.realm.admin".to_owned()],
            constraints: Vec::new(),
            revoked: false,
            created_at: now,
            issuer_authority_refs: Vec::new(),
            authority_depth: None,
            authority_root_refs: Vec::new(),
        });
    validate_operation_policy(&state, std::slice::from_ref(&registration(owner)))
        .await
        .unwrap();

    let err = validate_operation_policy(&state, std::slice::from_ref(&registration(outsider)))
        .await
        .unwrap_err();
    assert_eq!(err, "applet_registration_unauthorized");
}

#[test]
fn production_requires_canonical_event_time_fields() {
    let state = make_state(false);
    let mut object = serde_json::Map::new();

    let err =
        validate_event_time_fields(&state, &object).expect_err("production requires created_at");
    assert_eq!(err.code, "param_missing");
    assert!(err.message.contains("created_at"));

    object.insert("created_at".to_owned(), json!("2026-05-17T00:00:00Z"));
    let err = validate_event_time_fields(&state, &object)
        .expect_err("whole-second shorthand is not canonical milliseconds");
    assert_eq!(err.code, "param_invalid");

    object.insert(
        "created_at".to_owned(),
        json!("2026-05-17T00:00:00.000123Z"),
    );
    let err = validate_event_time_fields(&state, &object)
        .expect_err("microseconds are not canonical milliseconds");
    assert_eq!(err.code, "param_invalid");

    object.insert("created_at".to_owned(), json!("2026-05-17T00:00:00.000Z"));
    let err = validate_event_time_fields(&state, &object).expect_err("production requires hlc");
    assert_eq!(err.code, "param_missing");
    assert!(err.message.contains("hlc"));

    object.insert("hlc".to_owned(), json!("019041000000-0000-AABBCCDD"));
    let err =
        validate_event_time_fields(&state, &object).expect_err("uppercase HLC is not canonical");
    assert_eq!(err.code, "param_invalid");

    object.insert("hlc".to_owned(), json!("019041000000-0000-aabbccdd"));
    validate_event_time_fields(&state, &object).expect("canonical timestamps accepted");
}

#[test]
fn development_allows_fixtures_to_omit_time_fields() {
    let state = make_state(true);
    let object = serde_json::Map::new();
    validate_event_time_fields(&state, &object)
        .expect("development fixtures may omit event time fields");
}

#[test]
fn production_requires_requirements_schema() {
    let state = make_state(false);
    let mut object = serde_json::Map::new();

    let err = event_requirements_schema_id(&state, &object)
        .expect_err("production requires requirements.schema[]");
    assert_eq!(err.code, "param_missing");

    object.insert(
        "requirements".to_owned(),
        json!({ "schema": ["ak.schema.event.v1"] }),
    );
    assert_eq!(
        event_requirements_schema_id(&state, &object).unwrap(),
        "ak.schema.event.v1"
    );
}

#[tokio::test]
async fn top_level_effective_scope_is_reducer_managed() {
    let state = make_state(true);
    let session = session();
    let event = crate::test_event::raw_event(
        arkret_wire::EventKind::RealmCreate.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
            )
            .unwrap(),
        },
        arkret_wire::DidCoreId::new(session.actor.clone()).unwrap(),
        1,
        arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
        json!({"object": {"id": "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC"}}),
    )
    .unwrap();
    let mut envelope = serde_json::to_value(event).unwrap();
    envelope["effective_scope"] = json!("ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC");

    let err = validate_event_envelope(&state, &session, &envelope)
        .await
        .expect_err("clients must not supply reducer-managed effective_scope");
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        err.code,
        arkret_wire::ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED
    );
}

#[test]
fn event_canonical_bytes_use_sdk_canonical_json() {
    let mut event = crate::test_event::raw_event(
        "ak.test.canonical",
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
            )
            .unwrap(),
        },
        crate::test_actor_id_str("did:webvh:z6mkfixture:alice.example"),
        7,
        arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
        json!({"z": 1, "a": {"b": 2, "a": 1}}),
    )
    .unwrap();
    event.unsigned.insert("age_ms".to_owned(), json!(10));
    let expected =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    let mut envelope = serde_json::to_value(&event).unwrap();
    envelope["canonical_digest"] = json!("sha256:old");
    let bytes = event_canonical_bytes(&envelope).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text.as_bytes(), expected);
    assert!(text.contains(r#""payload":{"a":{"a":1,"b":2},"z":1}"#));
    assert!(!text.contains("unsigned"));
    assert!(!text.contains("canonical_digest"));
}

#[test]
fn event_canonical_bytes_reject_fractional_numbers() {
    let event = crate::test_event::raw_event(
        "ak.test.canonical",
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
            )
            .unwrap(),
        },
        crate::test_actor_id_str("did:webvh:z6mkfixture:alice.example"),
        7,
        arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
        json!({"rank": 1}),
    )
    .unwrap();
    let mut envelope = serde_json::to_value(event).unwrap();
    envelope["payload"]["rank"] = json!(1.5);
    let err = event_canonical_bytes(&envelope)
        .expect_err("Arkret canonical JSON rejects fractional numbers");
    assert_eq!(err.code, "invalid_event_envelope");
}

#[test]
fn event_payload_validator_rejects_registered_payload_shape_errors() {
    let state = make_state(true);
    let envelope = typed_event_envelope(
        "ak.strand.move",
        json!({
            "strand_id": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC"
        }),
    );
    let object = envelope.as_object().unwrap();
    let err = validate_event_schema_and_payload(
        &state,
        "ak.strand.move",
        "ak.schema.event.v1",
        &envelope,
        object,
    )
    .expect_err("strand.move without target/rank must fail payload validation");
    assert_eq!(err.code, "schema_violation");
}

#[test]
fn schema_define_admission_executes_the_registered_definition_validator_profile() {
    let state = make_state(true);
    let valid = typed_event_envelope(
        arkret_wire::EventKind::SchemaDefine.as_str(),
        json!({
            "value": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "ak.schema.example.v1",
                "type": "string"
            }
        }),
    );
    validate_event_schema_and_payload(
        &state,
        arkret_wire::EventKind::SchemaDefine.as_str(),
        "ak.schema.event.v1",
        &valid,
        valid.as_object().unwrap(),
    )
    .expect("valid Draft 2020-12 schema definition must pass admission");

    for invalid_payload in [
        json!({
            "value": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "string"
            }
        }),
        json!({
            "value": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "ak.schema.example.v1",
                "type": "not_a_json_schema_type"
            }
        }),
    ] {
        let invalid = typed_event_envelope(
            arkret_wire::EventKind::SchemaDefine.as_str(),
            invalid_payload,
        );
        let error = validate_event_schema_and_payload(
            &state,
            arkret_wire::EventKind::SchemaDefine.as_str(),
            "ak.schema.event.v1",
            &invalid,
            invalid.as_object().unwrap(),
        )
        .expect_err("invalid schema definition must fail admission");
        assert_eq!(error.code, "schema_violation");
    }
}

#[test]
fn member_state_join_schema_allows_contextual_invite_ref() {
    let state = make_state(true);
    let valid = typed_event_envelope(
        "ak.member.state",
        json!({
            "member_id": ordinary_event_account("ak:did_core:web:bob.example"),
            "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
            "membership": "join",
            "reason": "invite_accept",
            "invite_ref": "ak:invite:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        }),
    );
    validate_event_schema_and_payload(
        &state,
        "ak.member.state",
        "ak.schema.event.v1",
        &valid,
        valid.as_object().unwrap(),
    )
    .expect("ak.member.state join schema should allow contextual invite_ref");
}

#[test]
fn event_payload_validator_enforces_strand_update_patch_schema() {
    let state = make_state(true);
    let strand_id = "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC";
    let valid = typed_event_envelope(
        "ak.strand.update",
        json!({
            "target_ref": strand_id,
            "patch": {
                "fields.document": {
                    "$op": "set",
                    "value": { "blocks": [] }
                }
            }
        }),
    );
    validate_event_schema_and_payload(
        &state,
        "ak.strand.update",
        "ak.schema.event.v1",
        &valid,
        valid.as_object().unwrap(),
    )
    .expect("canonical ak.strand.update strand_patch_payload should validate");

    let invalid_patch_op = typed_event_envelope(
        "ak.strand.update",
        json!({
            "target_ref": strand_id,
            "patch": {
                "fields.document": {
                    "$op": "replace",
                    "value": { "blocks": [] }
                }
            }
        }),
    );
    let err = validate_event_schema_and_payload(
        &state,
        "ak.strand.update",
        "ak.schema.event.v1",
        &invalid_patch_op,
        invalid_patch_op.as_object().unwrap(),
    )
    .expect_err("ak.strand.update patch operations must match ak.patch.v1 exactly");
    assert_eq!(err.code, "schema_violation");
}

#[test]
fn event_payload_validator_catalog_covers_active_standard_durable_events() {
    const SIBLING_SCHEMA_EVENT_KINDS: &[&str] = &[
        arkret_wire::EventKind::ModerationFrankingProof.as_str(),
        arkret_wire::EventKind::RelationTombstone.as_str(),
    ];
    let catalog = arkret_schema_conformance::event_payload_validator_catalog().unwrap();
    let event_kinds = soland_services::protocol_artifacts::active_durable_event_kinds()
        .iter()
        .map(String::as_str)
        .filter(|kind| arkret_wire::events::is_standard_event_kind(kind))
        .filter(|kind| !SIBLING_SCHEMA_EVENT_KINDS.contains(kind))
        .collect::<Vec<_>>();
    let missing = catalog.missing_payload_validators_for(event_kinds.iter().copied());
    assert!(
        missing.is_empty(),
        "missing payload validators: {missing:?}"
    );
    assert!(
        event_kinds.len() > 20,
        "catalog coverage test should cover the active registry, not a fixture subset"
    );
}

#[test]
fn event_payload_validator_enforces_patch_family_schema() {
    let catalog = arkret_schema_conformance::event_payload_validator_catalog().unwrap();
    let patch_kinds = [
        "ak.strand.update",
        "ak.morph.update",
        "ak.space.update",
        "ak.profile.update",
    ];
    let missing = catalog.missing_payload_validators_for(patch_kinds);
    assert!(
        missing.is_empty(),
        "missing patch payload validators: {missing:?}"
    );

    let payloads = [
        (
            "ak.strand.update",
            json!({
                "target_ref": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "target_ref": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "metadata.title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.morph.update",
            json!({
                "target_ref": "ak:morph:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "target_ref": "ak:morph:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "metadata.title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.space.update",
            json!({
                "space_id": "ak:space:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "space_id": "ak:space:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.profile.update",
            json!({
                "target_ref": "ak:actor_profile:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "target_ref": "ak:actor_profile:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
    ];
    for (event_kind, valid_payload, invalid_payload) in payloads {
        catalog
            .validate_payload(event_kind, &valid_payload)
            .unwrap_or_else(|err| {
                panic!("{event_kind} must accept canonical patch payload: {err}");
            });
        assert!(
            catalog
                .validate_payload(event_kind, &invalid_payload)
                .is_err(),
            "{event_kind} must reject patch ops outside ak.patch.v1"
        );
    }

    // ak.profile.realm_override carries a Realm-scoped override and uses the
    // dedicated profile_realm_override_payload (target_ref + target_realm_id
    // + patch), not the generic object_patch_payload.
    catalog
        .validate_payload(
            "ak.profile.realm_override",
            &json!({
                "target_ref": "ak:actor_profile:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "target_realm_id": "ak:realm:AQqDnmYP2y5kt6ZLD--QatyqmmeXf3WAeSGGrAGZoR-6",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ak.profile.realm_override must accept profile_realm_override_payload: {err}");
        });

    catalog
        .validate_payload(
            "ak.strand.tracks.update",
            &json!({
                "target_ref": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": {
                    "tracks.discussion.enabled": {"$op": "set", "value": true},
                    "tracks.discussion.is_primary": {"$op": "set", "value": true}
                }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ak.strand.tracks.update must accept canonical Strand patch payload: {err}");
        });
    assert!(
        catalog
            .validate_payload(
                "ak.strand.tracks.update",
                &json!({
                    "strand_id": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                    "tracks": {}
                }),
            )
            .is_err(),
        "ak.strand.tracks.update must reject retired strand_id/tracks payloads"
    );
}

#[tokio::test]
async fn production_rejects_dev_proof_type_field() {
    let state = make_state(false);
    let session = session();
    let object = dev_proof_envelope();
    let err = validate_event_proofs(
        &object,
        &state,
        &session,
        "did:web:alice.example",
        "sha256:dead",
        arkret_canonical::DigestSuite::Sha256,
        b"{}",
        &[],
        None,
    )
    .await
    .expect_err("production must reject dev-proof shape");
    // Missing strict-JWS fields trips `invalid_proof` first.
    assert_eq!(err.code, "invalid_proof");
}

#[tokio::test]
async fn development_rejects_dev_proof_type_field_even_when_hash_matches() {
    let state = make_state(true);
    let session = session();
    let mut object = dev_proof_envelope();
    // A matching payload-only hash must not create a development-only
    // durable Event protocol.
    let payload_bytes = canonical::canonical_json_bytes(&object["payload"]).unwrap();
    let payload_digest = arkret_canonical::sha256_digest(&payload_bytes);
    if let Some(proofs) = object.get_mut("proofs").and_then(Value::as_array_mut)
        && let Some(proof) = proofs.first_mut()
        && let Some(map) = proof.as_object_mut()
    {
        map.insert("payload_digest".to_owned(), json!(payload_digest));
    }
    let error = validate_event_proofs(
        &object,
        &state,
        &session,
        "did:web:alice.example",
        "sha256:dead",
        arkret_canonical::DigestSuite::Sha256,
        b"{}",
        &[],
        None,
    )
    .await
    .expect_err("development mode must reject the non-SDK proof shape");
    assert_eq!(error.code, "invalid_proof");
}

#[tokio::test]
async fn production_rejects_full_proof_without_valid_jws_signature() {
    let state = make_state(false);
    let session = session();
    let actor_id = "ak:did_core:web:alice.example";
    // First ingest a fresh webvh document so the high-risk freshness gate
    // passes and this test focuses on JWS signature verification failure.
    ingest_fresh_webvh_document(&state, "did:web:alice.example").await;
    let canonical_bytes =
        br#"{"actor_id":"ak:did_core:web:alice.example","event_id":"ak:event:test"}"#;
    let event_digest = arkret_canonical::sha256_digest(canonical_bytes);
    let mut object = serde_json::Map::new();
    object.insert(
        "actor_id".to_owned(),
        json!(crate::test_account_actor(
            &arkret_wire::Did::new("did:web:alice.example").unwrap()
        )),
    );
    object.insert(
        "proofs".to_owned(),
        json!([{
            "kind": "detached_jws",
            "verification_method": "did:web:alice.example#ak:device:01904100-0000-7000-8000-a11ce0000001",
            "event_digest": event_digest,
            "created_at": "2026-05-17T00:00:00.000Z",
            "jws": "eyJhbGciOiJFZDI1NTE5In0..AAAAAAAA"
        }]),
    );
    object.insert("payload".to_owned(), json!({"body": "hello"}));

    let err = validate_event_proofs(
        &object,
        &state,
        &session,
        actor_id,
        &arkret_canonical::sha256_digest(canonical_bytes),
        arkret_canonical::DigestSuite::Sha256,
        canonical_bytes,
        &[],
        None,
    )
    .await
    .expect_err("production must reject unsigned/fake JWS proofs");
    assert_eq!(err.code, "invalid_proof");
    assert!(
        err.message.contains("JWS verification failed"),
        "unexpected message: {}",
        err.message
    );
}

/// L3 - high-risk event proof paths fail closed when the DID document is
/// stale or has no ingested record, and the freshness gate rejects before
/// JWS verification.
#[tokio::test]
async fn production_event_proof_fails_closed_when_did_document_stale() {
    let state = make_state(false);
    let mut session = session();
    let actor_id = "ak:did_core:web:stale-proof.example";
    session.actor = actor_id.to_owned();
    // Deliberately ingest no webvh document: the actor has no freshness
    // evidence in persistence.
    let canonical_bytes = br#"{"actor_id":"ak:did_core:web:stale-proof.example","event_id":"ak:event:test","kind":"ak.identity.resolution.update"}"#;
    let event_digest = arkret_canonical::sha256_digest(canonical_bytes);
    let mut object = serde_json::Map::new();
    object.insert(
        "actor_id".to_owned(),
        json!(crate::test_account_actor(
            &arkret_wire::Did::new("did:web:stale-proof.example").unwrap()
        )),
    );
    object.insert(
        "proofs".to_owned(),
        json!([{
            "kind": "detached_jws",
            "verification_method": "did:web:stale-proof.example#k1",
            "event_digest": event_digest,
            "created_at": "2026-05-17T00:00:00.000Z",
            "jws": "eyJhbGciOiJFZDI1NTE5In0..AAAAAAAA"
        }]),
    );
    object.insert(
        "kind".to_owned(),
        json!(arkret_wire::EventKind::IdentityResolutionUpdate.as_str()),
    );
    object.insert("payload".to_owned(), json!({"body": "hello"}));

    let err = validate_event_proofs(
        &object,
        &state,
        &session,
        actor_id,
        &arkret_canonical::sha256_digest(canonical_bytes),
        arkret_canonical::DigestSuite::Sha256,
        canonical_bytes,
        &[],
        None,
    )
    .await
    .expect_err("stale/missing DID document must fail closed before JWS verify");
    assert_eq!(err.code, "stale_did_document", "{}", err.message);
}

const ORDINARY_EVENT_REALM: &str = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
const ORDINARY_EVENT_ACTOR: &str = "ak:did_core:web:alice.example";
const ORDINARY_EVENT_STATION: &str = "ak:did_core:web:principal.example";
const ORDINARY_EVENT_STRAND: &str = "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

fn ordinary_event_account(principal: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal.to_owned()).unwrap(),
        arkret_wire::DidCoreId::new(ORDINARY_EVENT_STATION.to_owned()).unwrap(),
    ))
}
/// The MLS group named by every E2EE fixture ciphertext.
fn ordinary_event_placeholder_seal_id() -> arkret_identifiers::SealId {
    arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap()
}

fn ordinary_event_move_id(byte: u8) -> arkret_identifiers::Hash {
    arkret_identifiers::Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn ordinary_event_hash(byte: u8) -> arkret_identifiers::Hash {
    arkret_identifiers::Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn ordinary_event_dummy_signature() -> arkret_wire::SealSignature {
    arkret_wire::SealSignature {
        verification_method: arkret_wire::DidUrl::new("did:web:notary.example#k1").unwrap(),
        payload_digest: ordinary_event_hash(0xff),
        jws: "AAAA.BBBB.CCCC".to_owned(),
    }
}

async fn insert_ordinary_event_seal(
    state: &AppState,
    delta: Vec<arkret_identifiers::Hash>,
) -> String {
    insert_ordinary_event_seal_with(state, None, delta).await
}

async fn insert_ordinary_event_seal_with(
    state: &AppState,
    predecessor_ref: Option<arkret_identifiers::SealId>,
    delta: Vec<arkret_identifiers::Hash>,
) -> String {
    use chrono::TimeZone;

    let realm = arkret_identifiers::RealmId::new(ORDINARY_EVENT_REALM.to_owned()).unwrap();
    let notary_seq = u64::from(predecessor_ref.is_some());
    let command_results = delta
        .iter()
        .cloned()
        .map(|digest| {
            arkret_wire::SealCommandOutcome::committed(
                digest.clone(),
                vec![digest],
                Vec::new(),
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap()
        })
        .collect();
    let mut seal = arkret_wire::Seal {
        id: ordinary_event_placeholder_seal_id(),
        realm_id: realm,
        predecessor_ref,
        delta,
        data_delta: Vec::new(),
        data_event_set_root: arkret_wire::empty_data_event_set_root(
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap(),
        control_event_set_root: ordinary_event_hash(0x22),
        state_root: ordinary_event_hash(0x77),
        notary_seq,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: ordinary_event_dummy_signature(),
        sealed_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        hlc: arkret_identifiers::Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        configuration_ref: arkret_wire::EventId::new(format!("ak:event:A{}", "a".repeat(42)))
            .unwrap(),
        command_results,
        authorization_closures: Vec::new(),
        data_closure_announcements: Vec::new(),
        data_closures: Vec::new(),
        existence_anchors: Vec::new(),
    };
    seal.id = seal
        .derive_id(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let seal_id = seal.id.clone();
    state
        .projections()
        .test_put_seal(&seal, arkret_canonical::DigestSuite::Sha256)
        .await
        .unwrap();
    seal_id.as_str().to_owned()
}

fn ordinary_event_grant(grant_id: &str, action: &str, revoked: bool) -> crate::authz::Grant {
    crate::authz::Grant {
        grant_id: grant_id.to_owned(),
        realm_id: ORDINARY_EVENT_REALM.to_owned(),
        issuer_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:owner.example").unwrap(),
            arkret_wire::DidCoreId::new(ORDINARY_EVENT_STATION).unwrap(),
        )),
        subject_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(ORDINARY_EVENT_ACTOR).unwrap(),
            arkret_wire::DidCoreId::new(ORDINARY_EVENT_STATION).unwrap(),
        )),
        resource: ORDINARY_EVENT_STRAND.to_owned(),
        actions: vec![action.to_owned()],
        constraints: Vec::new(),
        revoked,
        created_at: chrono::Utc::now(),
        issuer_authority_refs: Vec::new(),
        authority_depth: None,
        authority_root_refs: Vec::new(),
    }
}

fn historical_ordinary_event_grant_value(
    grant_id: &str,
    action: &str,
    subject: &str,
    issuer: &str,
    revoked: bool,
    authority_grant_id: Option<&str>,
) -> Value {
    let mut value = json!({
        "grant_id": grant_id,
        "schema": arkret_wire::SchemaId::CAPABILITY_V1,
        "realm_id": ORDINARY_EVENT_REALM,
        "issuer_id": ordinary_event_account(issuer),
        "issuer_authority_refs": [{
            "kind": "realm_root",
            "realm_id": ORDINARY_EVENT_REALM,
            "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
            "controller_epoch_at_issuance": 0,
            "authority_generation": 0
        }],
        "subject": ordinary_event_account(subject),
        "actions": [action],
        "resources": [ORDINARY_EVENT_STRAND],
        "issued_at": "2026-05-08T00:00:00.000Z"
    });
    if let Some(authority_grant_id) = authority_grant_id {
        // A re-grant names the grant it was issued under; the realm_root ref
        // above belongs to a root issue, so it is replaced rather than kept.
        value["issuer_authority_refs"] =
            json!([{ "kind": "grant", "grant_id": authority_grant_id }]);
    }
    if revoked {
        value["revoked"] = Value::Bool(true);
        value["revoked_at"] = Value::String("2026-05-08T00:01:00.000Z".to_owned());
    }
    value
}

async fn insert_historical_ordinary_event_grant(
    state: &AppState,
    grant_id: &str,
    action: &str,
    revoked: bool,
) -> String {
    insert_historical_ordinary_event_grant_for_subject(
        state,
        grant_id,
        action,
        ordinary_event_account(ORDINARY_EVENT_ACTOR),
        revoked,
    )
    .await
}

async fn insert_historical_ordinary_event_grant_for_subject(
    state: &AppState,
    grant_id: &str,
    action: &str,
    subject: arkret_wire::ActorId,
    revoked: bool,
) -> String {
    let realm = arkret_identifiers::RealmId::new(ORDINARY_EVENT_REALM.to_owned()).unwrap();
    let move_id = ordinary_event_move_id(0xab);
    let seal_ref = insert_ordinary_event_seal(state, vec![move_id.clone()]).await;
    let seal_id = arkret_identifiers::SealId::new(seal_ref.clone()).unwrap();
    let cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
    ))
    .unwrap();
    let mut value = historical_ordinary_event_grant_value(
        grant_id,
        action,
        subject.signing_principal_id().as_str(),
        "ak:did_core:web:owner.example",
        revoked,
        None,
    );
    value["subject"] = json!(subject);
    let op = arkret_wire::LatticeOp {
        op_type: arkret_wire::LatticeOpType::Add,
        tag: Some("ak:operation:01904100-0000-7000-8000-000000000999".to_owned()),
        value: Some(value),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    };
    state
        .projections()
        .test_append_confirmed_effects(
            &realm,
            &seal_id,
            &[(
                cell,
                strictness_issued(arkret_state::state_model::StateWrite::new(
                    move_id.clone(),
                    op,
                )),
            )],
        )
        .await
        .unwrap();
    seal_ref
}

async fn insert_ordinary_event_revocation_successor(
    state: &AppState,
    predecessor_ref: &str,
    grant_id: &str,
    action: &str,
    after_hours: i64,
) {
    use chrono::{Duration, TimeZone};

    let realm = arkret_identifiers::RealmId::new(ORDINARY_EVENT_REALM.to_owned()).unwrap();
    let predecessor = arkret_identifiers::SealId::new(predecessor_ref.to_owned()).unwrap();
    let move_id = ordinary_event_move_id(0xae);
    let sealed_at =
        chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap() + Duration::hours(after_hours);
    let mut successor = arkret_wire::Seal {
        id: ordinary_event_placeholder_seal_id(),
        realm_id: realm.clone(),
        predecessor_ref: Some(predecessor),
        delta: vec![move_id.clone()],
        data_delta: Vec::new(),
        data_event_set_root: arkret_wire::empty_data_event_set_root(
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap(),
        control_event_set_root: ordinary_event_hash(0x23),
        state_root: ordinary_event_hash(0x78),
        notary_seq: 2,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: ordinary_event_dummy_signature(),
        sealed_at,
        hlc: arkret_identifiers::Hlc::new("0189c4d2af00-0001-aabbccdd".to_owned()).unwrap(),
        configuration_ref: arkret_wire::EventId::new(format!("ak:event:A{}", "a".repeat(42)))
            .unwrap(),
        command_results: vec![
            arkret_wire::SealCommandOutcome::committed(
                move_id.clone(),
                vec![move_id.clone()],
                Vec::new(),
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap(),
        ],
        authorization_closures: Vec::new(),
        data_closure_announcements: Vec::new(),
        data_closures: Vec::new(),
        existence_anchors: Vec::new(),
    };
    successor.id = successor
        .derive_id(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let successor_id = successor.id.clone();
    state
        .projections()
        .test_put_seal(&successor, arkret_canonical::DigestSuite::Sha256)
        .await
        .unwrap();
    let cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
    ))
    .unwrap();
    let op = arkret_wire::LatticeOp {
        op_type: arkret_wire::LatticeOpType::Add,
        tag: Some("ak:operation:01904100-0000-7000-8000-000000000998".to_owned()),
        value: Some(historical_ordinary_event_grant_value(
            grant_id,
            action,
            ORDINARY_EVENT_ACTOR,
            "ak:did_core:web:owner.example",
            true,
            None,
        )),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    };
    state
        .projections()
        .test_append_confirmed_effects(
            &realm,
            &successor_id,
            &[(
                cell,
                strictness_issued(arkret_state::state_model::StateWrite::new(move_id, op)),
            )],
        )
        .await
        .unwrap();
}

async fn insert_historical_ordinary_event_child_grant_with_revoked_authority(
    state: &AppState,
    authority_grant_id: &str,
    child_grant_id: &str,
    action: &str,
) -> String {
    let realm = arkret_identifiers::RealmId::new(ORDINARY_EVENT_REALM.to_owned()).unwrap();
    let parent_move_id = ordinary_event_move_id(0xac);
    let child_move_id = ordinary_event_move_id(0xad);
    let seal_ref =
        insert_ordinary_event_seal(state, vec![parent_move_id.clone(), child_move_id.clone()])
            .await;
    let seal_id = arkret_identifiers::SealId::new(seal_ref.clone()).unwrap();
    let parent_cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{authority_grant_id}"
    ))
    .unwrap();
    let child_cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{child_grant_id}"
    ))
    .unwrap();
    let parent_value = historical_ordinary_event_grant_value(
        authority_grant_id,
        action,
        "ak:did_core:web:authority.example",
        "ak:did_core:web:owner.example",
        true,
        None,
    );
    let child_value = historical_ordinary_event_grant_value(
        child_grant_id,
        action,
        ORDINARY_EVENT_ACTOR,
        "ak:did_core:web:authority.example",
        false,
        Some(authority_grant_id),
    );
    let parent_op = arkret_wire::LatticeOp {
        op_type: arkret_wire::LatticeOpType::Add,
        tag: Some("ak:operation:01904100-0000-7000-8000-000000000991".to_owned()),
        value: Some(parent_value),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    };
    let child_op = arkret_wire::LatticeOp {
        op_type: arkret_wire::LatticeOpType::Add,
        tag: Some("ak:operation:01904100-0000-7000-8000-000000000992".to_owned()),
        value: Some(child_value),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    };
    state
        .projections()
        .test_append_confirmed_effects(
            &realm,
            &seal_id,
            &[
                (
                    parent_cell,
                    strictness_issued(arkret_state::state_model::StateWrite::new(
                        parent_move_id.clone(),
                        parent_op,
                    )),
                ),
                (
                    child_cell,
                    strictness_issued(arkret_state::state_model::StateWrite::new(
                        child_move_id.clone(),
                        child_op,
                    )),
                ),
            ],
        )
        .await
        .unwrap();
    seal_ref
}

/// The cell an `ak.message.create` in this Realm projects.
///
/// v1 carries no producer `effects[]`; the receiver derives the write set from
/// `kind + payload` and hands it to the capability gate, so the fixture states
/// the derived set directly instead of putting one on the wire.
fn ordinary_event_derived_cells() -> Vec<String> {
    vec![format!(
        "ak:cell:ak.component.strand.discussion.timeline.v1:{ORDINARY_EVENT_STRAND}"
    )]
}

/// A ordinary Event citing `grants` through `semantic_refs[role=authorized_by]`, which is
/// where v1 puts a capability citation — `auth_context` is closed over
/// `{authority_refs}`.
fn ordinary_event_object_with_refs(
    authority_ref: &str,
    grants: Vec<String>,
) -> serde_json::Map<String, Value> {
    json!({
        "actor_id": ordinary_event_account(ORDINARY_EVENT_ACTOR),
        "created_at": "2026-05-08T00:02:00.000Z",
        "semantic_refs": grants
            .into_iter()
            .map(|grant_id| json!({"id": grant_id, "role": "authorized_by", "critical": true}))
            .collect::<Vec<Value>>(),
        "auth_context": {
            "authority_refs": [authority_ref]
        },
        // A ordinary Event carries a payload, and `ordinary_event_constraint_context`
        // resolves the field/track authorization context from it. A
        // payload-less fixture is not an ordinary Event any receiver would see, and
        // it fails before reaching the capability resolution these tests are
        // about.
        "payload": {
            "strand_id": ORDINARY_EVENT_STRAND,
            "track_name": arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION
        }
    })
    .as_object()
    .unwrap()
    .clone()
}

#[tokio::test]
async fn ordinary_event_capability_ref_must_resolve() {
    let state = make_state(true);
    let seal_ref = insert_ordinary_event_seal(&state, Vec::new()).await;
    let object = ordinary_event_object_with_refs(
        &seal_ref,
        vec!["ak:grant:ATPdRBJ7VjotWM8xezzjJYCICc6wTKShqh-oWNC3EGqO".to_owned()],
    );

    let err = validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect_err("unknown capability_ref must reject");

    assert_eq!(err.code, "capability_denied");
    assert!(err.message.contains("not projected"));
}

/// Coverage is judged against the cells the *receiver* derived, over the whole
/// effective set the `seal_ref` basis yields for the actor.
#[tokio::test]
async fn ordinary_event_capability_must_cover_derived_cell() {
    let state = make_state(true);
    let grant_id = "ak:grant:AZjl4ii7409qEbi9w_hFgL2BOAn9txOvjwAf79MHg_i6";
    let seal_ref =
        insert_historical_ordinary_event_grant(&state, grant_id, "ak.message.create", false).await;
    let object = ordinary_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect("matching grant must cover the derived ordinary Event cell");

    let wrong_state = make_state(true);
    let wrong_grant_id = "ak:grant:ARgPcY94c3tMPJStrGtcGWGqWQXLGc-0YDI6darot7h0";
    let wrong_seal_ref = insert_historical_ordinary_event_grant(
        &wrong_state,
        wrong_grant_id,
        "ak.reaction.add",
        false,
    )
    .await;
    let wrong_action_object =
        ordinary_event_object_with_refs(&wrong_seal_ref, vec![wrong_grant_id.to_owned()]);
    let err = validate_ordinary_event_capability_refs(
        &wrong_state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &wrong_action_object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect_err("wrong action must not cover the derived ordinary Event cell");
    assert_eq!(err.code, "capability_denied");
    assert!(err.message.contains("covers action"));
}

/// `event-and-patch.md` §2.2: `effects` and producer-selected
/// `auth_context.capability_refs` are not v1 wire fields, and a receiver MUST
/// answer `schema_violation` when it meets either. These were the two inputs
/// the capability gate used to *require*, so they are asserted refused rather
/// than merely unread.
#[tokio::test]
async fn ordinary_event_rejects_producer_selected_capability_fields() {
    let state = make_state(true);
    let grant_id = "ak:grant:AX37wLeLONzd_JNkw6LJ99yJoWyfGkOl1VRG-QZRvfHs";
    let seal_ref =
        insert_historical_ordinary_event_grant(&state, grant_id, "ak.message.create", false).await;

    let mut with_capability_refs = ordinary_event_object_with_refs(&seal_ref, vec![]);
    with_capability_refs["auth_context"]["capability_refs"] = json!([grant_id]);
    let err = validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &with_capability_refs,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect_err("auth_context.capability_refs must be refused");
    assert_eq!(err.code, "schema_violation");
    assert!(err.message.contains("auth_context is closed over"));

    let mut with_effects = ordinary_event_object_with_refs(&seal_ref, vec![]);
    with_effects.insert(
        "effects".to_owned(),
        json!([{
            "cell_id": format!("ak:cell:ak.component.strand.discussion.timeline.v1:{ORDINARY_EVENT_STRAND}"),
            "op": {"kind": "append"}
        }]),
    );
    let err = validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &with_effects,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect_err("effects must be refused");
    assert_eq!(err.code, "schema_violation");
    assert!(err.message.contains("not a v1 Event Envelope field"));
}

/// A conformant ordinary Event cites nothing: `refs[role=authorized_by]` is
/// optional, and the effective capability set comes from the governance basis
/// at `seal_ref` alone.
#[tokio::test]
async fn ordinary_event_without_authorized_by_refs_uses_the_derived_capability_set() {
    let state = make_state(true);
    let grant_id = "ak:grant:AawcynxQ2o8vL1cUX0ihdXGNoRO0G_nEj-ZtG2fA6Tq-";
    let seal_ref =
        insert_historical_ordinary_event_grant(&state, grant_id, "ak.message.create", false).await;
    let object = ordinary_event_object_with_refs(&seal_ref, vec![]);

    validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect("an ordinary Event citing no grant is authorized by its authority basis");
}

#[tokio::test]
async fn applet_ordinary_event_uses_exact_executed_by_grant_at_seal_ref() {
    const APPLET_SERVICE: &str = "ak:did_core:web:bridge.example";
    let state = make_state(true);
    let grant_id = "ak:grant:AYSBE0hegtYZwGZKvLpOxSBjVkkCzQx36JxTE3ExdEV5";
    let seal_ref = insert_historical_ordinary_event_grant_for_subject(
        &state,
        grant_id,
        "ak.message.create",
        arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new(APPLET_SERVICE.to_owned()).unwrap(),
        ),
        false,
    )
    .await;
    let mut object = ordinary_event_object_with_refs(&seal_ref, vec![]);
    object.insert(
        "applet_id".to_owned(),
        json!("ak:applet:01904100-0000-7000-8000-000000000001"),
    );
    object.insert(
        "executed_by".to_owned(),
        json!(arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new(APPLET_SERVICE.to_owned()).unwrap()
        )),
    );
    object.insert("authorization_ref".to_owned(), json!(grant_id));

    validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect("Applet ordinary Event must use its executor's exact install grant");

    let mut self_action = object.clone();
    let producer = self_action.remove("executed_by").unwrap();
    self_action.insert("actor_id".to_owned(), producer);
    validate_ordinary_event_capability_refs(
        &state,
        APPLET_SERVICE,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &self_action,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect("Applet service acting as itself uses the same exact service grant");

    object.insert(
        "authorization_ref".to_owned(),
        json!("ak:grant:AXt8OgxCpSbRBVYm7b5yaEOTqGwqu3EiAxcRhN7K2raF"),
    );
    let err = validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect_err("another effective grant cannot substitute for authorization_ref");
    assert_eq!(err.code, "authorization_ref_inactive");
    assert!(err.message.contains("not projected at seal_ref"));
}

#[tokio::test]
async fn ordinary_event_capability_ref_must_not_be_revoked() {
    let state = make_state(true);
    let grant_id = "ak:grant:AcQ0lLs0sdXJIIFx89z5MPiZcW4lJ931DNuCAR0tR-W3";
    let seal_ref =
        insert_historical_ordinary_event_grant(&state, grant_id, "ak.message.create", true).await;
    let object = ordinary_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    let err = validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect_err("revoked capability_ref must reject");

    assert_eq!(err.code, "capability_denied");
    assert!(err.message.contains("revoked"));
}

#[tokio::test]
async fn ordinary_event_capability_ref_reports_upstream_revoked_authority() {
    let state = make_state(true);
    let authority_grant_id = "ak:grant:AXtQr1bQ29BYsE_HxdhYVb02wrOy3mDAcmK4juGSwpGE";
    let child_grant_id = "ak:grant:AUClLzOaZSu1iuMPWhnnXcjeH3Kdt15z74i8jhKEonWr";
    let seal_ref = insert_historical_ordinary_event_child_grant_with_revoked_authority(
        &state,
        authority_grant_id,
        child_grant_id,
        "ak.message.create",
    )
    .await;
    let object = ordinary_event_object_with_refs(&seal_ref, vec![child_grant_id.to_owned()]);

    let err = validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect_err("child capability_ref with revoked parent must reject");

    assert_eq!(err.code, "capability_denied");
    assert_eq!(err.message, "capability authority is unavailable");
}

#[tokio::test]
async fn ordinary_event_uses_seal_ref_pre_state_not_live_authz_index() {
    let state = make_state(true);
    let grant_id = "ak:grant:AbNxEyHm2i7kxIWT8d3aeJ0c7n5ujCnlTYJy9aAxH1Fn";
    let seal_ref =
        insert_historical_ordinary_event_grant(&state, grant_id, "ak.message.create", false).await;
    state
        .authorization()
        .upsert_projected_grant(ordinary_event_grant(grant_id, "ak.message.create", true));
    let object = ordinary_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .expect(
        "ordinary Event authz must evaluate its referenced pre-state, not the live authz index",
    );
}

#[tokio::test]
async fn current_revocation_blocks_a_new_ordinary_event_admission() {
    let state = make_state(true);
    let grant_id = "ak:grant:AYSBE0hegtYZwGZKvLpOxSBjVkkCzQx36JxTE3ExdEV5";
    let seal_ref =
        insert_historical_ordinary_event_grant(&state, grant_id, "ak.message.create", false).await;
    insert_ordinary_event_revocation_successor(&state, &seal_ref, grant_id, "ak.message.create", 1)
        .await;
    let object = ordinary_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    let err = validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "capability_denied");
}

#[tokio::test]
async fn current_revocation_blocks_admission_regardless_of_seal_distance() {
    let state = make_state(true);
    let grant_id = "ak:grant:Adtfh7VczxqGjGKRiDCJlBwIw-G-GAX-uATlzwwXLQcQ";
    let seal_ref =
        insert_historical_ordinary_event_grant(&state, grant_id, "ak.message.create", false).await;
    insert_ordinary_event_revocation_successor(
        &state,
        &seal_ref,
        grant_id,
        "ak.message.create",
        24,
    )
    .await;
    let object = ordinary_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    let err = validate_ordinary_event_capability_refs(
        &state,
        ORDINARY_EVENT_ACTOR,
        ORDINARY_EVENT_STATION,
        ORDINARY_EVENT_REALM,
        "ak.message.create",
        &object,
        &ordinary_event_derived_cells(),
        false,
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "capability_denied");
}

/// Attach a fixed issuer to a strictness fixture op; these cells are not
/// ordered-log keyed, so the issuer travels but does not select a slot.
fn strictness_issued(
    op: arkret_state::state_model::StateWrite,
) -> arkret_state::state_model::ordered_log::IssuedOp {
    arkret_state::state_model::ordered_log::IssuedOp {
        issuer_id: arkret_wire::ActorId::service(crate::test_actor_id_str(
            "did:webvh:z6mkfixture:alice.example",
        )),
        op,
    }
}

// `join-policy.md` section 4 rule 4, signature half. The reducer owns the
// binding tuple; these cover the part that needs DID resolution, so a proof
// whose signature does not lead back to a key the gate's provider or issuer
// controls cannot admit anyone.

fn gate_proof_signed_by(
    signing_key: &ed25519_dalek::SigningKey,
    mutate: impl FnOnce(&mut Value),
) -> Value {
    let did = did_key_for(signing_key);
    let did_key_fragment = did.strip_prefix("did:key:").expect("did:key prefix");
    let verification_method = format!("{did}#{did_key_fragment}");
    let created_at = arkret_canonical::format_timestamp_canonical(chrono::Utc::now());

    // Built through the typed carrier so the signed bytes come from the same
    // constructor a conforming producer uses, not from a hand-rolled literal.
    let mut proof: arkret_models_collaboration::governance::membership_invite::JoinGateProof =
        serde_json::from_value(json!({
            "gate_id": "g-captcha",
            "kind": "challenge_response",
            "realm_id": "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
            "applicant_actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:bob.example",
                    "station_id": "ak:did_core:web:station.example"
                }
            },
            "policy_digest": format!("sha256:{}", "c".repeat(64)),
            "created_at": created_at,
            "challenge_kind": "captcha",
            "challenge_id": "chg_01HXY9PM0AB6Y7VN2C7M4WG5KQ",
            "proofs": [{
                "kind": "detached_jws",
                "verification_method": verification_method,
                "payload_digest": format!("sha256:{}", "0".repeat(64)),
                "created_at": created_at,
                "jws": "ZXlKaGJHY2lPaUpGWkRJMU5URTVJbjA..c2ln"
            }]
        }))
        .expect("fixture gate proof parses as the registered carrier");

    // The digest covers the body without `proofs`, so it is stamped before the
    // signature is made over the binding object that carries it.
    proof.proofs[0].payload_digest = proof.payload_digest().expect("fixture payload digest");
    let binding = proof
        .proof_binding_object(&proof.proofs[0].clone())
        .expect("fixture binding object");
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&binding).expect("canonical binding bytes");
    proof.proofs[0].jws =
        arkret_signatures::sign_ed25519_detached_jws(signing_key, &canonical_bytes)
            .expect("fixture detached JWS");

    let mut value = serde_json::to_value(&proof).expect("gate proof serializes");
    mutate(&mut value);
    value
}

fn join_event_with_gate_proof(proof: Value) -> serde_json::Map<String, Value> {
    json!({
        "payload": {
            "membership": "join",
            "gate_proofs": [proof]
        }
    })
    .as_object()
    .expect("fixture event object")
    .clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_correctly_signed_gate_proof_passes_the_signature_gate() {
    let state = make_state(false);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
    let object = join_event_with_gate_proof(gate_proof_signed_by(&signing_key, |_| {}));
    validate_join_gate_proof_signatures(&object, &state)
        .await
        .expect("a gate proof signed by its own verification method verifies");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gate_proof_with_an_invalid_signature_is_refused() {
    let state = make_state(false);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
    let object = join_event_with_gate_proof(gate_proof_signed_by(&signing_key, |proof| {
        proof["proofs"][0]["jws"] = json!("ZXlKaGJHY2lPaUpGWkRJMU5URTVJbjA..c2ln");
    }));
    let error = validate_join_gate_proof_signatures(&object, &state)
        .await
        .expect_err("an unverifiable signature must fail closed");
    assert_eq!(error.message, "gate_check_failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gate_proof_whose_binding_was_altered_after_signing_is_refused() {
    // The signature covers the binding tuple, so moving the proof to another
    // Realm invalidates it even before the reducer compares the field.
    let state = make_state(false);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
    let object = join_event_with_gate_proof(gate_proof_signed_by(&signing_key, |proof| {
        proof["realm_id"] = json!("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb");
    }));
    let error = validate_join_gate_proof_signatures(&object, &state)
        .await
        .expect_err("a proof lifted to another Realm must fail closed");
    assert_eq!(error.message, "gate_check_failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gate_proof_carrying_a_digest_over_another_body_is_refused() {
    // `payload_digest` is recomputed from the body, so a signature made over
    // some other object cannot be presented alongside this one.
    let state = make_state(false);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[24u8; 32]);
    let object = join_event_with_gate_proof(gate_proof_signed_by(&signing_key, |proof| {
        proof["proofs"][0]["payload_digest"] = json!(format!("sha256:{}", "d".repeat(64)));
    }));
    let error = validate_join_gate_proof_signatures(&object, &state)
        .await
        .expect_err("a foreign payload digest must fail closed");
    assert_eq!(error.message, "gate_check_failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gate_proof_with_no_detached_proof_is_refused() {
    // `proofs` is `minItems: 1` in the schema, but a Rust `Vec` has no such
    // floor, so an empty array reaches this pass. Nothing is attested, and the
    // verdict must not default to "no signature to reject".
    let state = make_state(false);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[25u8; 32]);
    let object = join_event_with_gate_proof(gate_proof_signed_by(&signing_key, |proof| {
        proof["proofs"] = json!([]);
    }));
    let error = validate_join_gate_proof_signatures(&object, &state)
        .await
        .expect_err("a gate proof attesting nothing must fail closed");
    assert_eq!(error.message, "gate_check_failed");
}
