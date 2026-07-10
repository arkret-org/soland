use soland_data::Db;

use super::*;
use crate::config::{AppConfig, IceServersConfig, LiveKitConfig, ObjectStorageConfig};

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

fn dev_proof_envelope() -> serde_json::Map<String, Value> {
    let mut object = serde_json::Map::new();
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
        token_hash: "hash".to_owned(),
        actor: "did:web:alice.example".to_owned(),
        device_id: "ak:device:01904100-0000-7000-8000-a11ce0000001".to_owned(),
        audience: "did:web:soland.local".to_owned(),
        session_public_key: None,
        agent_session: None,
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
    state
        .persistence
        .webvh()
        .put_document(crate::state::WebvhDocumentRecord {
            did: did.to_owned(),
            did_document: json!({ "id": did, "verificationMethod": [] }),
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
    let verification_method = format!("{did}#{did_key_fragment}");
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-a11ce0000001".to_owned())
            .unwrap();
    let actor_id = arkret_sdk::Did::new(did.clone()).unwrap();
    let subject_id = actor_id.clone();
    let zero_hash = arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    let mut identity = arkret_sdk::MemberIdentity::new(
        realm_id.clone(),
        actor_id.clone(),
        subject_id,
        arkret_sdk::DisplayProfile {
            display_name: "Alice".to_owned(),
            avatar_blob_ref: None,
        },
        chrono::Utc::now(),
        arkret_sdk::MemberIdentityProof {
            verification_method,
            signature_algorithm: arkret_sdk::MemberIdentitySignatureAlgorithm::Ed25519,
            payload_digest: zero_hash,
            signature: "AA".to_owned(),
        },
    );
    let canonical_bytes = identity.canonical_payload_bytes().unwrap();
    identity.proof.payload_digest =
        arkret_sdk::Hash::new(identity.canonical_payload_sha256().unwrap()).unwrap();
    identity.proof.signature =
        URL_SAFE_NO_PAD.encode(signing_key.sign(&canonical_bytes).to_bytes());
    let payload = json!({
        "realm_id": realm_id.as_str(),
        "actor_id": actor_id.as_str(),
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
    assert_eq!(err.code, "proof_event_digest_mismatch");
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
    let code = crate::error::ErrorCode::UnsupportedSignatureAlg;
    assert_eq!(err.status, crate::error::error_http_status(code));
    assert_eq!(err.code, code.as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn member_identity_encrypted_payload_is_unsupported_fail_closed() {
    let state = make_state(false);
    let payload = json!({
        "realm_id": "ak:realm:01904100-0000-7000-8000-a11ce0000001",
        "actor_id": "did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP",
        "segment": "member_identity",
        "identity_payload": {
            "encrypted_payload": {
                "alg": "stub"
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
async fn policy_components_media_plaintext_reads_realm_meta() {
    let state = make_state(true);
    let realm_id = "ak:realm:01904100-0000-7000-8000-a11ce0000001";
    let now = chrono::Utc::now();
    state
        .persistence
        .realm_meta()
        .put(
            realm_id,
            &crate::state::RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "restricted".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::from([state
                    .config
                    .service_did
                    .clone()]),
                plaintext_visible_service_classes: std::collections::BTreeMap::from([(
                    state.config.service_did.clone(),
                    std::collections::BTreeSet::from([
                        arkret_sdk::PlaintextDataClassKind::MediaPlaintext,
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
async fn minimal_metadata_realm_rejects_non_hidden_aad() {
    // SEC-08 — a minimal-metadata Realm rejects an encrypted message whose
    // aad_visibility_event_id is not `hidden`, and accepts `hidden`.
    let state = make_state(true);
    let realm_id = "ak:realm:01904100-0000-7000-8000-a11ce0000002";
    let now = chrono::Utc::now();
    state
        .persistence
        .realm_meta()
        .put(
            realm_id,
            &crate::state::RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "restricted".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: Default::default(),
                minimal_metadata_realm: true,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    let encrypted_envelope = |visibility: &str| {
        json!({
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000001",
            "track_name": "main",
            "encrypted_content": {
                "scheme": "mls-rfc9420",
                "version": "1.0",
                "group_id": "base64url",
                "epoch": 12,
                "content_type": "application/json",
                "ciphertext": "base64url",
                "aad_visibility_event_id": visibility,
                "aad": {
                    "realm_id": realm_id,
                    "event_kind": "ak.message.create"
                },
                "key_ref": {
                    "algorithm": "MLS",
                    "group_state_ref": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                },
                "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "aad_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }
        })
    };
    let message_op = |payload: serde_json::Value| {
        arkret_sdk::Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_sdk::events::kinds::MESSAGE_CREATE,
            payload,
        )
    };

    // Non-hidden aad → rejected.
    let routing = message_op(encrypted_envelope("routing_digest"));
    let err = validate_operation_policy(&state, std::slice::from_ref(&routing))
        .await
        .unwrap_err();
    assert!(err.contains("aad_visibility_event_id=hidden"));

    // Encrypted envelope with no discriminator → fail closed.
    let mut no_disc = encrypted_envelope("hidden");
    no_disc["encrypted_content"]
        .as_object_mut()
        .unwrap()
        .remove("aad_visibility_event_id");
    let missing = message_op(no_disc);
    assert!(
        validate_operation_policy(&state, std::slice::from_ref(&missing))
            .await
            .is_err()
    );

    // hidden aad → accepted (other policy gates are satisfied here).
    let hidden = message_op(encrypted_envelope("hidden"));
    validate_operation_policy(&state, std::slice::from_ref(&hidden))
        .await
        .unwrap();
}

#[tokio::test]
async fn circle_scoped_write_requires_circle_membership() {
    // circle.md §8 two-layer AND — a Realm-wide capability does NOT let a
    // non-member write into a Circle. The membership conjunct is enforced at
    // admission (`validate_operation_policy`), not only on the delivery side.
    // Regression guard for the gap where a Realm-wide grant (notably an Applet
    // bot / Ghost Actor) could inject content into a Circle it never joined.
    let state = make_state(true);
    let realm_id = "ak:realm:01904100-0000-7000-8000-c1c1e0000001";
    let circle_id = "ak:circle:01904100-0000-7000-8000-c1c1e0000002";
    let member = "did:web:alice.example";
    // An Applet bot that holds a Realm-wide grant but never joined the Circle.
    let non_member = "did:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    // Seed an active Circle whose only member is `member`.
    {
        let mut projection = state.projection.lock();
        projection.circles.insert(
            circle_id.to_owned(),
            crate::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                title: "HR-Conf".to_owned(),
                summary: None,
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_visibility: "joined".to_owned(),
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                encryption_profile: "mls_rfc9420".to_owned(),
                mls_group_ref: None,
                state: crate::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([member.to_owned()]),
            },
        );
    }

    let strand_create = |sender: &str, scope: Option<&str>| {
        let mut object = json!({
            "id": "ak:strand:01904100-0000-7000-8000-000000000abc",
            "metadata": {"title": "t"}
        });
        if let Some(scope) = scope {
            object["scope_circle_id"] = json!(scope);
        }
        arkret_sdk::Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d8550abc")
                .unwrap(),
            arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_sdk::events::kinds::STRAND_CREATE,
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
    let realm_id = "ak:realm:01904100-0000-7000-8000-c2c2e0000001";
    let circle_id = "ak:circle:01904100-0000-7000-8000-c2c2e0000002";
    let strand_id = "ak:strand:01904100-0000-7000-8000-c2c2e0000003";
    let event_id = "ak:event:01904100-0000-7000-8000-c2c2e0000004";
    let member = "did:web:alice.example";
    let non_member = "did:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    {
        let mut projection = state.projection.lock();
        projection.circles.insert(
            circle_id.to_owned(),
            crate::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                title: "HR-Conf".to_owned(),
                summary: None,
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_visibility: "joined".to_owned(),
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                encryption_profile: "mls_rfc9420".to_owned(),
                mls_group_ref: None,
                state: crate::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([member.to_owned()]),
            },
        );
        // A Strand scoped to the Circle, and a Message inside it.
        projection.strands.insert(
            strand_id.to_owned(),
            crate::reducer::StrandProjection {
                strand_id: strand_id.to_owned(),
                realm_id: realm_id.to_owned(),
                tracks: std::collections::BTreeMap::from([(
                    arkret_sdk::STRAND_TRACK_NAME_DISCUSSION.to_owned(),
                    arkret_sdk::StrandTrackConfig::discussion_primary(),
                )]),
                title: String::new(),
                summary: None,
                fields: std::collections::BTreeMap::new(),
                state: crate::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                history_basis_seals: Vec::new(),
                updated_by: None,
                updated_at: None,
                scope_circle_id: Some(circle_id.to_owned()),
            },
        );
        projection.messages.insert(
            event_id.to_owned(),
            crate::reducer::MessageState {
                event_id: event_id.to_owned(),
                message_id: crate::reducer::message_id_from_event_id(event_id),
                realm_id: realm_id.to_owned(),
                sender: member.to_owned(),
                thread_id: strand_id.to_owned(),
                content: json!({}),
                expiry: None,
                encrypted: false,
                operation_id: "ak:operation:01904100-0000-7000-8000-c2c2e0000005".to_owned(),
                created_at: now,
                history_basis_seals: Vec::new(),
                revision_of: None,
                redacted_at: None,
            },
        );
    }

    let reaction = |sender: &str| {
        arkret_sdk::Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-c2c2e000000a")
                .unwrap(),
            arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_sdk::events::kinds::REACTION_ADD,
            json!({"sender": sender, "target_event_id": event_id, "key": "👍"}),
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
    let realm_id = "ak:realm:01904100-0000-7000-8000-c3c3e0000001";
    let circle_id = "ak:circle:01904100-0000-7000-8000-c3c3e0000002";
    let scoped_morph_id = "ak:morph:01904100-0000-7000-8000-c3c3e0000003";
    let realm_morph_id = "ak:morph:01904100-0000-7000-8000-c3c3e0000004";
    let member = "did:web:alice.example";
    let non_member = "did:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    {
        let mut projection = state.projection.lock();
        projection.circles.insert(
            circle_id.to_owned(),
            crate::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                title: "HR-Conf".to_owned(),
                summary: None,
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_visibility: "joined".to_owned(),
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                encryption_profile: "mls_rfc9420".to_owned(),
                mls_group_ref: None,
                state: crate::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([member.to_owned()]),
            },
        );
        for (morph_id, scope_circle_id) in [
            (scoped_morph_id, Some(circle_id.to_owned())),
            (realm_morph_id, None),
        ] {
            projection.morphs.insert(
                morph_id.to_owned(),
                crate::reducer::MorphProjection {
                    morph_id: morph_id.to_owned(),
                    realm_id: realm_id.to_owned(),
                    scope_circle_id,
                    morph_type: "task".to_owned(),
                    title: Some("Task".to_owned()),
                    fields: std::collections::BTreeMap::new(),
                    schema_refs: Vec::new(),
                    facets: Vec::new(),
                    versions: Vec::new(),
                    state: crate::reducer::ObjectLifecycleState::Active,
                    state_changed_at: None,
                    created_by: member.to_owned(),
                    created_at: now,
                    history_basis_seals: Vec::new(),
                    updated_by: None,
                    updated_at: None,
                },
            );
        }
    }

    let morph_update = |sender: &str, morph_id: &str| {
        arkret_sdk::Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-c3c3e000000a")
                .unwrap(),
            arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_sdk::events::kinds::MORPH_UPDATE,
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
    // its own — this gate closes that bypass. The Realm owner may register; an
    // outsider without `ak.realm.admin` may not.
    let state = make_state(true);
    let realm_id = "ak:realm:01904100-0000-7000-8000-a99e70000001";
    let owner = "did:web:alice.example";
    let outsider = "did:web:mallory.example";
    let now = chrono::Utc::now();
    state
        .persistence
        .realm_meta()
        .put(
            realm_id,
            &crate::state::RealmMetaRecord {
                owner: owner.to_owned(),
                deleted: false,
                discoverability: "restricted".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
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
        arkret_sdk::Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d855a99e")
                .unwrap(),
            arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_sdk::events::kinds::APPLET_REGISTRATION,
            json!({
                "sender": sender,
                "applet_id": "ak:applet:01904100-0000-7000-8000-000000000a01",
                "service_did": "did:web:slack-bridge.example",
                "namespace": "slack",
            }),
        )
    };

    // Realm owner may register an Applet.
    validate_operation_policy(&state, std::slice::from_ref(&registration(owner)))
        .await
        .unwrap();

    // An outsider without `ak.realm.admin` is rejected fail-closed — closing the
    // `/_arkret/self/events` bypass of the install-handler gate.
    let err = validate_operation_policy(&state, std::slice::from_ref(&registration(outsider)))
        .await
        .unwrap_err();
    assert_eq!(err, "applet_registration_unauthorized");
}

#[tokio::test]
async fn non_minimal_metadata_realm_allows_any_aad() {
    // SEC-08 — a Realm that did not declare the profile is unaffected: a
    // non-hidden aad encrypted message passes this gate.
    let state = make_state(true);
    let realm_id = "ak:realm:01904100-0000-7000-8000-a11ce0000003";
    let now = chrono::Utc::now();
    state
        .persistence
        .realm_meta()
        .put(
            realm_id,
            &crate::state::RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "restricted".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
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

    let op = arkret_sdk::Operation::create(
        arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c6").unwrap(),
        arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
        arkret_sdk::events::kinds::MESSAGE_CREATE,
        json!({
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000001",
            "track_name": "main",
            "encrypted_content": {
                "scheme": "mls-rfc9420",
                "version": "1.0",
                "group_id": "base64url",
                "epoch": 12,
                "content_type": "application/json",
                "ciphertext": "base64url",
                "aad_visibility_event_id": "routing_digest",
                "aad": {
                    "realm_id": realm_id,
                    "event_kind": "ak.message.create",
                    "event_ref_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                },
                "key_ref": {
                    "algorithm": "MLS",
                    "group_state_ref": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                },
                "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "aad_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }
        }),
    );
    validate_operation_policy(&state, std::slice::from_ref(&op))
        .await
        .unwrap();
}

#[test]
fn policy_components_mls_governance_reads_projection_cell() {
    let state = make_state(true);
    let realm_id = "ak:realm:01904100-0000-7000-8000-a11ce0000001";
    let policy_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    {
        let mut projection = state.projection.lock();
        projection.cells.insert(
            arkret_sdk::CellRef::new(
                "ak:cell:ak.component.mls.epoch.v1:ak:mls_group:unit-test".to_owned(),
            )
            .unwrap(),
            arkret_sdk::lattice::CellState::Value(json!({
                "realm_id": realm_id,
                "epoch": 7,
                "governance_binding": {
                    "policy_root": policy_root
                }
            })),
        );
    }

    let matching = json!({
        "mls_governance_binding": {
            "policy_root": policy_root
        }
    });
    let stale = json!({
        "mls_governance_binding": {
            "policy_root": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
    });

    assert!(projected_mls_governance_binding_covers_policy_root(
        &state, realm_id, &matching
    ));
    assert!(!projected_mls_governance_binding_covers_policy_root(
        &state, realm_id, &stale
    ));
}

#[test]
fn production_requires_canonical_event_time_fields() {
    let state = make_state(false);
    let mut object = serde_json::Map::new();

    let err =
        validate_event_time_fields(&state, &object).expect_err("production requires created_at");
    assert_eq!(err.code, "missing_param");
    assert!(err.message.contains("created_at"));

    object.insert("created_at".to_owned(), json!("2026-05-17T00:00:00Z"));
    let err = validate_event_time_fields(&state, &object).expect_err("production requires hlc");
    assert_eq!(err.code, "missing_param");
    assert!(err.message.contains("hlc"));

    object.insert("hlc".to_owned(), json!("019041000000-0000-AABBCCDD"));
    let err =
        validate_event_time_fields(&state, &object).expect_err("uppercase HLC is not canonical");
    assert_eq!(err.code, "invalid_param");

    object.insert("hlc".to_owned(), json!("019041000000-0000-aabbccdd"));
    validate_event_time_fields(&state, &object).expect("canonical timestamps accepted");
}

#[test]
fn development_keeps_fixture_time_field_compatibility() {
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
    assert_eq!(err.code, "missing_param");

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
    let state = make_state(false);
    let session = session();
    let envelope = json!({
        "event_id": "ak:event:01904100-0000-7000-8000-00000000eff0",
        "kind": arkret_sdk::events::kinds::REALM_CREATE,
        "requirements": { "schema": ["ak.schema.event.v1"] },
        "actor_id": session.actor.clone(),
        "effective_scope": "ak:realm:01904100-0000-7000-8000-a11ce0000001"
    });

    let err = validate_event_envelope(&state, &session, &envelope)
        .await
        .expect_err("clients must not supply reducer-managed effective_scope");
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        err.code,
        crate::error::reasons::EFFECTIVE_SCOPE_REDUCER_MANAGED
    );
}

#[test]
fn event_canonical_bytes_use_sdk_canonical_json() {
    let envelope = json!({
        "z": 1,
        "a": {"b": 2, "a": 1},
        "unsigned": {"age_ms": 10},
        "proofs": [{"type": "dev-proof"}],
        "effective_scope": {
            "kind": "realm",
            "realm_id": "ak:realm:01904100-0000-7000-8000-a11ce0000001"
        },
        "actor_kind": "native",
        "canonical_digest": "sha256:old"
    });
    let bytes = event_canonical_bytes(&envelope).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text, r#"{"a":{"a":1,"b":2},"z":1}"#);
}

#[test]
fn event_canonical_bytes_reject_non_canonical_numbers() {
    let envelope = json!({
        "payload": {"rank": 1.5},
        "proofs": [{"type": "dev-proof"}]
    });
    let err = event_canonical_bytes(&envelope).expect_err("floats are not canonical JSON");
    assert_eq!(err.code, "invalid_event_envelope");
}

#[test]
fn event_payload_validator_rejects_registered_payload_shape_errors() {
    let state = make_state(true);
    let envelope = json!({
        "payload": {
            "strand_id": "ak:strand:01904100-0000-7000-8000-f10dc0000001"
        }
    });
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
fn member_state_invite_accept_uses_canonical_invite_ref() {
    let state = make_state(true);
    let valid = json!({
        "payload": {
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "membership": "join",
            "reason": "invite_accept",
            "invite_ref": "ak:invite:01904100-0000-7000-8000-000000000001",
            "delivery_status": "unroutable"
        }
    });
    validate_event_schema_and_payload(
        &state,
        "ak.member.state",
        "ak.schema.event.v1",
        &valid,
        valid.as_object().unwrap(),
    )
    .expect("ak.member.state invite accept should allow invite_ref");
}

#[test]
fn event_payload_validator_enforces_strand_update_patch_schema() {
    let state = make_state(true);
    let strand_id = "ak:strand:01904100-0000-7000-8000-f10dc0000001";
    let valid = json!({
        "payload": {
            "target_ref": strand_id,
            "patch": {
                "fields.document": {
                    "$op": "set",
                    "value": { "blocks": [] }
                }
            }
        }
    });
    validate_event_schema_and_payload(
        &state,
        "ak.strand.update",
        "ak.schema.event.v1",
        &valid,
        valid.as_object().unwrap(),
    )
    .expect("canonical ak.strand.update strand_patch_payload should validate");

    let invalid_patch_op = json!({
        "payload": {
            "target_ref": strand_id,
            "patch": {
                "fields.document": {
                    "$op": "replace",
                    "value": { "blocks": [] }
                }
            }
        }
    });
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
    let catalog = arkret_sdk::schema::event_payload_validator_catalog().unwrap();
    let event_kinds = artifacts::active_durable_event_kinds()
        .iter()
        .map(String::as_str)
        .filter(|kind| arkret_sdk::events::is_standard_event_kind(kind))
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
    let catalog = arkret_sdk::schema::event_payload_validator_catalog().unwrap();
    let patch_kinds = [
        "ak.realm.update",
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
            "ak.realm.update",
            json!({
                "target_ref": "ak:realm:01904100-0000-7000-8000-f10dc0000001",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "target_ref": "ak:realm:01904100-0000-7000-8000-f10dc0000001",
                "patch": { "title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.strand.update",
            json!({
                "target_ref": "ak:strand:01904100-0000-7000-8000-f10dc0000001",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "target_ref": "ak:strand:01904100-0000-7000-8000-f10dc0000001",
                "patch": { "metadata.title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.morph.update",
            json!({
                "target_ref": "ak:morph:01904100-0000-7000-8000-f10dc0000001",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "target_ref": "ak:morph:01904100-0000-7000-8000-f10dc0000001",
                "patch": { "metadata.title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.space.update",
            json!({
                "space_id": "ak:space:01904100-0000-7000-8000-f10dc0000001",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "space_id": "ak:space:01904100-0000-7000-8000-f10dc0000001",
                "patch": { "title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.profile.update",
            json!({
                "target_ref": "ak:actor_profile:01904100-0000-7000-8000-f10dc0000001",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "target_ref": "ak:actor_profile:01904100-0000-7000-8000-f10dc0000001",
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
                "target_ref": "ak:actor_profile:01904100-0000-7000-8000-f10dc0000001",
                "target_realm_id": "ak:realm:01904100-0000-7000-8000-f10dc0000002",
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
                "strand_id": "ak:strand:01904100-0000-7000-8000-f10dc0000001",
                "tracks": {
                    "discussion": {
                        "enabled": true,
                        "is_primary": true
                    }
                }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ak.strand.tracks.update must accept canonical tracks map payload: {err}");
        });
    assert!(
        catalog
            .validate_payload(
                "ak.strand.tracks.update",
                &json!({
                    "type": "removed_track_update",
                    "strand_id": "ak:strand:01904100-0000-7000-8000-f10dc0000001",
                }),
            )
            .is_err(),
        "ak.strand.tracks.update must still reject retired `type` discriminators"
    );
}

#[test]
fn realm_create_shape_allows_world_readable_encrypted_history() {
    let state = make_state(true);
    let realm_id = "ak:realm:01904100-0000-7000-8000-a11ce0000001";
    let envelope = json!({
        "payload": {
            "object": {
                "id": realm_id,
                "schema": "ak.schema.realm.v1",
                "title": "encrypted public history",
                "created_by": "did:web:alice.example",
                "trust_domain": "ak:trust_domain:soland.local",
                "schema_refs": ["ak.schema.realm.v1"],
                "default_discoverability": "listed",
                "default_join_rule": "invite",
                "history_visibility": "world_readable",
                "encryption_profile": "mls_rfc9420",
                "security_class": "standard",
                "federation_policy": "restricted",
                "notary_profile": "single_did",
                "digest_algorithm": "sha256",
                "notary": {
                    "type": "single_did",
                    "did": "did:web:alice.example",
                    "recovery_members": ["did:web:recovery.example"],
                    "controller_organization": "did:web:organization.primary.example",
                    "recovery_controller_organizations": ["did:web:organization.recovery.example"]
                },
                "created_at": "2026-05-17T00:00:00Z"
            }
        }
    });
    let object = envelope.as_object().unwrap();
    validate_event_schema_and_payload(
        &state,
        "ak.realm.create",
        "ak.schema.event.v1",
        &envelope,
        object,
    )
    .expect("shape validation defers encrypted history scheme compatibility to operation policy");
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
    )
    .await
    .expect_err("production must reject dev-proof shape");
    // Missing strict-JWS fields trips `invalid_proof` first.
    assert_eq!(err.code, "invalid_proof");
}

#[tokio::test]
async fn development_accepts_dev_proof_type_field_when_hash_matches() {
    let state = make_state(true);
    let session = session();
    let mut object = dev_proof_envelope();
    // Use payload-only hash so the dev path's `payload_only_hash_accept`
    // matches; production would still reject this even with the correct
    // payload hash because the proof lacks a JWS.
    let payload_bytes = canonical::canonical_json_bytes(&object["payload"]).unwrap();
    let payload_digest = arkret_sdk::canonical::sha256_digest(&payload_bytes);
    if let Some(proofs) = object.get_mut("proofs").and_then(Value::as_array_mut)
        && let Some(proof) = proofs.first_mut()
        && let Some(map) = proof.as_object_mut()
    {
        map.insert("payload_digest".to_owned(), json!(payload_digest));
    }
    let result = validate_event_proofs(
        &object,
        &state,
        &session,
        "did:web:alice.example",
        "sha256:dead",
    )
    .await;
    assert!(
        result.is_ok(),
        "development mode should accept matching dev-proof: {result:?}"
    );
}

#[tokio::test]
async fn production_rejects_full_proof_without_valid_jws_signature() {
    let state = make_state(false);
    let session = session();
    // First ingest a fresh webvh document so the high-risk freshness gate
    // passes and this test focuses on JWS signature verification failure.
    ingest_fresh_webvh_document(&state, "did:web:alice.example").await;
    let canonical_bytes = br#"{"actor_id":"did:web:alice.example","event_id":"ak:event:test"}"#;
    let event_digest = arkret_sdk::canonical::sha256_digest(canonical_bytes);
    let mut object = serde_json::Map::new();
    object.insert(
        "proofs".to_owned(),
        json!([{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:alice.example#k1",
            "event_digest": event_digest,
            "created_at": "2026-05-17T00:00:00Z",
            "jws": "eyJhbGciOiJFZERTQSJ9..AAAAAAAA"
        }]),
    );
    object.insert("payload".to_owned(), json!({"body": "hello"}));

    let err = validate_event_proofs(
        &object,
        &state,
        &session,
        "did:web:alice.example",
        &arkret_sdk::canonical::sha256_digest(canonical_bytes),
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
    let session = session();
    // Deliberately ingest no webvh document: the actor has no freshness
    // evidence in persistence.
    let canonical_bytes = br#"{"actor_id":"did:web:alice.example","event_id":"ak:event:test"}"#;
    let event_digest = arkret_sdk::canonical::sha256_digest(canonical_bytes);
    let mut object = serde_json::Map::new();
    object.insert(
        "proofs".to_owned(),
        json!([{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:alice.example#k1",
            "event_digest": event_digest,
            "created_at": "2026-05-17T00:00:00Z",
            "jws": "eyJhbGciOiJFZERTQSJ9..AAAAAAAA"
        }]),
    );
    object.insert("payload".to_owned(), json!({"body": "hello"}));

    let err = validate_event_proofs(
        &object,
        &state,
        &session,
        "did:web:alice.example",
        &arkret_sdk::canonical::sha256_digest(canonical_bytes),
    )
    .await
    .expect_err("stale/missing DID document must fail closed before JWS verify");
    assert_eq!(err.code, "stale_did_document");
}

/// T5.3 (Round 22) — pin the SDK production-verifier surface used by
/// soland's federation / event paths. The hand-rolled
/// `dev_proof_in_production` gate above rejects `type == "dev-proof"`
/// and the `"a..b"` / empty placeholder JWS specifically (those are
/// soland-shape concerns the SDK doesn't know about). The SDK
/// `ProductionVerifier::assert_production_proof` enforces the
/// orthogonal rule that the wire `Proof.kind` MUST NOT be in
/// `core::DEV_PROOF_KINDS` (`dev` / `test` / `mock` / `stub` /
/// `dummy`). Together they're the spec's full dev-proof gate. This
/// test asserts the SDK rule still bites on a `kind="dev"` proof —
/// so soland callers that switch to `ProductionVerifier::wrap(...)`
/// inherit the same fail-closed semantics they get inline today.
#[test]
fn soland_dev_proof_gate_matches_sdk_production_verifier() {
    use arkret_sdk::signatures::{ProductionVerifier, build_proof_envelope};
    use arkret_sdk::{Audience, Hash};

    struct Noop;
    impl arkret_sdk::signatures::EventVerifier for Noop {
        fn verify(
            &self,
            _: &[u8],
            _: &[u8],
            _: &arkret_sdk::signatures::PublicKeyMaterial,
        ) -> std::result::Result<(), arkret_sdk::signatures::VerifierError> {
            Ok(())
        }
        fn algorithm(&self) -> &str {
            "EdDSA"
        }
    }
    let verifier = ProductionVerifier::wrap(Noop);
    // A proof with a kind in the SDK's DEV_PROOF_KINDS allowlist —
    // must be rejected with DevProofRejected.
    let dev = build_proof_envelope(
        "dev",
        "EdDSA",
        "did:web:alice.example#k1",
        Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap(),
        None,
        None::<Audience>,
        "a..b",
    );
    let sdk_err = verifier
        .assert_production_proof(&dev)
        .expect_err("SDK ProductionVerifier must reject dev-kind proof");
    assert!(matches!(
        sdk_err,
        arkret_sdk::signatures::VerifierError::DevProofRejected(_)
    ));

    // A proof with kind="detached_jws" — SDK accepts the kind
    // (signature still has to verify separately).
    let prod = build_proof_envelope(
        arkret_sdk::signatures::detached_jws_kind(),
        "EdDSA",
        "did:web:alice.example#k1",
        Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap(),
        None,
        None::<Audience>,
        "header..sig",
    );
    verifier
        .assert_production_proof(&prod)
        .expect("SDK ProductionVerifier must accept detached_jws kind");
}

const DATA_EVENT_REALM: &str = "ak:realm:01904100-0000-7000-8000-000000000001";
const DATA_EVENT_ACTOR: &str = "did:web:alice.example";
const DATA_EVENT_STRAND: &str = "ak:strand:01904100-0000-7000-8000-000000000001";

fn data_event_seal_id() -> arkret_sdk::SealId {
    arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap()
}

fn data_event_move_id(byte: u8) -> arkret_sdk::MoveId {
    arkret_sdk::MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn data_event_hash(byte: u8) -> arkret_sdk::Hash {
    arkret_sdk::Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn data_event_dummy_signature() -> arkret_sdk::MoveSignature {
    use chrono::TimeZone;

    arkret_sdk::MoveSignature {
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:notary.example#k1".to_owned(),
        payload_digest: data_event_hash(0xff),
        created_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        jws: "AAAA.BBBB.CCCC".to_owned(),
    }
}

fn insert_data_event_seal(state: &AppState, covered: Vec<arkret_sdk::MoveId>) -> String {
    use chrono::TimeZone;

    let seal_id = data_event_seal_id();
    let realm = arkret_sdk::RealmId::new(DATA_EVENT_REALM.to_owned()).unwrap();
    let seal = arkret_sdk::Seal {
        id: seal_id.clone(),
        realm_id: realm,
        predecessor_refs: Vec::new(),
        delta: Vec::new(),
        control_event_set_root: data_event_hash(0x22),
        state_root: data_event_hash(0x77),
        completeness_root: data_event_hash(0x33),
        notary_seq: 1,
        data_view_root: None,
        data_event_set_root: None,
        availability_root: None,
        coverage_scope: None,
        covered_event_digests: covered,
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: arkret_sdk::NotarySig::Single(data_event_dummy_signature()),
        sealed_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        hlc: arkret_sdk::Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        kind: arkret_sdk::SealKind::Normal,
    };
    arkret_sdk::state_res::SealStore::put(state.seal_store.as_ref(), &seal).unwrap();
    seal_id.as_str().to_owned()
}

fn data_event_grant(grant_id: &str, action: &str, revoked: bool) -> crate::authz::Grant {
    crate::authz::Grant {
        grant_id: grant_id.to_owned(),
        realm_id: DATA_EVENT_REALM.to_owned(),
        issuer: "did:web:owner.example".to_owned(),
        subject: DATA_EVENT_ACTOR.to_owned(),
        resource: DATA_EVENT_STRAND.to_owned(),
        actions: vec![action.to_owned()],
        constraints: Vec::new(),
        revoked,
        created_at: chrono::Utc::now(),
        delegated_from: None,
        expires_at: None,
    }
}

fn historical_data_event_grant_value(
    grant_id: &str,
    action: &str,
    subject: &str,
    issuer: &str,
    revoked: bool,
    parent_grant_id: Option<&str>,
) -> Value {
    let mut value = json!({
        "grant_id": grant_id,
        "schema": "ak.schema.capability_grant.v1",
        "realm_id": DATA_EVENT_REALM,
        "issuer": issuer,
        "subject": subject,
        "actions": [action],
        "resources": [DATA_EVENT_STRAND],
        "issued_at": "2026-05-08T00:00:00Z"
    });
    if let Some(parent_grant_id) = parent_grant_id {
        value["delegated_from"] = Value::String(parent_grant_id.to_owned());
    }
    if revoked {
        value["revoked"] = Value::Bool(true);
        value["revoked_at"] = Value::String("2026-05-08T00:01:00Z".to_owned());
    }
    value
}

fn insert_historical_data_event_grant(
    state: &AppState,
    grant_id: &str,
    action: &str,
    revoked: bool,
) -> String {
    let realm = arkret_sdk::RealmId::new(DATA_EVENT_REALM.to_owned()).unwrap();
    let seal_id = data_event_seal_id();
    let move_id = data_event_move_id(0xab);
    let cell = arkret_sdk::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
    ))
    .unwrap();
    let value = historical_data_event_grant_value(
        grant_id,
        action,
        DATA_EVENT_ACTOR,
        "did:web:owner.example",
        revoked,
        None,
    );
    let op = arkret_sdk::LatticeOp {
        op_type: arkret_sdk::LatticeOpType::Add,
        tag: Some("ak:operation:01904100-0000-7000-8000-000000000999".to_owned()),
        value: Some(value),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    };
    arkret_sdk::state_res::CellStore::append_sealed_effects(
        state.cell_store.as_ref(),
        &realm,
        &seal_id,
        &[(
            cell,
            arkret_sdk::lattice::SealedOp::new(move_id.clone(), op),
        )],
    )
    .unwrap();
    insert_data_event_seal(state, vec![move_id])
}

fn insert_historical_data_event_delegated_grant_with_revoked_parent(
    state: &AppState,
    parent_grant_id: &str,
    child_grant_id: &str,
    action: &str,
) -> String {
    let realm = arkret_sdk::RealmId::new(DATA_EVENT_REALM.to_owned()).unwrap();
    let seal_id = data_event_seal_id();
    let parent_move_id = data_event_move_id(0xac);
    let child_move_id = data_event_move_id(0xad);
    let parent_cell = arkret_sdk::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{parent_grant_id}"
    ))
    .unwrap();
    let child_cell = arkret_sdk::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{child_grant_id}"
    ))
    .unwrap();
    let parent_value = historical_data_event_grant_value(
        parent_grant_id,
        action,
        "did:web:delegate.example",
        "did:web:owner.example",
        true,
        None,
    );
    let child_value = historical_data_event_grant_value(
        child_grant_id,
        action,
        DATA_EVENT_ACTOR,
        "did:web:delegate.example",
        false,
        Some(parent_grant_id),
    );
    let parent_op = arkret_sdk::LatticeOp {
        op_type: arkret_sdk::LatticeOpType::Add,
        tag: Some("ak:operation:01904100-0000-7000-8000-000000000991".to_owned()),
        value: Some(parent_value),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    };
    let child_op = arkret_sdk::LatticeOp {
        op_type: arkret_sdk::LatticeOpType::Add,
        tag: Some("ak:operation:01904100-0000-7000-8000-000000000992".to_owned()),
        value: Some(child_value),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    };
    arkret_sdk::state_res::CellStore::append_sealed_effects(
        state.cell_store.as_ref(),
        &realm,
        &seal_id,
        &[
            (
                parent_cell,
                arkret_sdk::lattice::SealedOp::new(parent_move_id.clone(), parent_op),
            ),
            (
                child_cell,
                arkret_sdk::lattice::SealedOp::new(child_move_id.clone(), child_op),
            ),
        ],
    )
    .unwrap();
    insert_data_event_seal(state, vec![parent_move_id, child_move_id])
}

fn insert_historical_data_event_grant_with_e2ee_state(
    state: &AppState,
    grant_id: &str,
    include_covered_seal: bool,
    include_relaxed_policy: bool,
) -> String {
    let realm = arkret_sdk::RealmId::new(DATA_EVENT_REALM.to_owned()).unwrap();
    let seal_id = data_event_seal_id();
    let mut move_ids = Vec::new();
    let mut ops = Vec::new();

    let grant_move_id = data_event_move_id(0xb0);
    let grant_cell = arkret_sdk::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
    ))
    .unwrap();
    let grant_op = arkret_sdk::LatticeOp {
        op_type: arkret_sdk::LatticeOpType::Add,
        tag: Some("ak:operation:01904100-0000-7000-8000-0000000009b0".to_owned()),
        value: Some(historical_data_event_grant_value(
            grant_id,
            "ak.message.create",
            DATA_EVENT_ACTOR,
            "did:web:owner.example",
            false,
            None,
        )),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    };
    move_ids.push(grant_move_id.clone());
    ops.push((
        grant_cell,
        arkret_sdk::lattice::SealedOp::new(grant_move_id, grant_op),
    ));

    if include_covered_seal {
        let covered_move_id = data_event_move_id(0xb1);
        let covered_cell = arkret_sdk::mls_move::covered_seals_cell_id(&realm).unwrap();
        let covered_op = arkret_sdk::LatticeOp {
            op_type: arkret_sdk::LatticeOpType::Add,
            tag: Some(seal_id.as_str().to_owned()),
            value: Some(Value::String(seal_id.as_str().to_owned())),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        move_ids.push(covered_move_id.clone());
        ops.push((
            covered_cell,
            arkret_sdk::lattice::SealedOp::new(covered_move_id, covered_op),
        ));
    }

    if include_relaxed_policy {
        let policy_move_id = data_event_move_id(0xb2);
        let policy_cell = arkret_sdk::CellRef::new(format!(
            "ak:cell:ak.component.realm.policy_components.v1:{DATA_EVENT_REALM}"
        ))
        .unwrap();
        let policy_op = arkret_sdk::LatticeOp {
            op_type: arkret_sdk::LatticeOpType::Set,
            tag: None,
            value: Some(json!({
                "profiles": ["ak.profile.e2ee_relaxed.v1"],
                "e2ee_relaxed": {
                    "profile": "ak.profile.e2ee_relaxed.v1",
                    "relaxed_window_max_ms": 30000
                }
            })),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        move_ids.push(policy_move_id.clone());
        ops.push((
            policy_cell,
            arkret_sdk::lattice::SealedOp::new(policy_move_id, policy_op),
        ));
    }

    arkret_sdk::state_res::CellStore::append_sealed_effects(
        state.cell_store.as_ref(),
        &realm,
        &seal_id,
        &ops,
    )
    .unwrap();
    insert_data_event_seal(state, move_ids)
}

fn data_event_object_with_refs(
    seal_ref: &str,
    refs: Vec<String>,
) -> serde_json::Map<String, Value> {
    json!({
        "seal_ref": seal_ref,
        "created_at": "2026-05-08T00:02:00Z",
        "auth_context": {
            "did": DATA_EVENT_ACTOR,
            "key_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "key_epoch": 1,
            "capability_refs": refs
        },
        "effects": [{
            "cell": format!("ak:cell:ak.component.strand.discussion.timeline.v1:{DATA_EVENT_STRAND}"),
            "op": {"kind": "append"}
        }]
    })
    .as_object()
    .unwrap()
    .clone()
}

fn data_event_e2ee_object_with_refs(
    seal_ref: &str,
    refs: Vec<String>,
) -> serde_json::Map<String, Value> {
    let mut object = data_event_object_with_refs(seal_ref, refs);
    object.insert(
        "payload".to_owned(),
        json!({
            "strand_id": DATA_EVENT_STRAND,
            "track_name": "main",
            "encrypted_content": {
                "scheme": "mls-rfc9420",
                "version": "1.0",
                "group_id": "group.01js0mls0000000000000000",
                "epoch": 7,
                "content_type": "application/json",
                "ciphertext": "base64url",
                "aad_visibility_event_id": "hidden",
                "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "aad_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }
        }),
    );
    object
}

#[test]
fn data_event_capability_ref_must_resolve() {
    let state = make_state(true);
    let seal_ref = insert_data_event_seal(&state, Vec::new());
    let object = data_event_object_with_refs(
        &seal_ref,
        vec!["ak:grant:01904100-0000-7000-8000-000000000111".to_owned()],
    );

    let err = validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ak.message.create",
        &object,
    )
    .expect_err("unknown capability_ref must reject");

    assert_eq!(err.code, "capability_denied");
    assert!(err.message.contains("not projected"));
}

#[test]
fn data_event_capability_ref_must_cover_effect_cell() {
    let state = make_state(true);
    let grant_id = "ak:grant:01904100-0000-7000-8000-000000000112";
    let seal_ref = insert_historical_data_event_grant(&state, grant_id, "ak.message.create", false);
    let object = data_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ak.message.create",
        &object,
    )
    .expect("matching grant must cover the DataEvent effect cell");

    let wrong_state = make_state(true);
    let wrong_grant_id = "ak:grant:01904100-0000-7000-8000-000000000113";
    let wrong_seal_ref =
        insert_historical_data_event_grant(&wrong_state, wrong_grant_id, "ak.reaction.add", false);
    let wrong_action_object =
        data_event_object_with_refs(&wrong_seal_ref, vec![wrong_grant_id.to_owned()]);
    let err = validate_data_event_capability_refs(
        &wrong_state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ak.message.create",
        &wrong_action_object,
    )
    .expect_err("wrong action must not cover the DataEvent effect cell");
    assert_eq!(err.code, "capability_denied");
    assert!(err.message.contains("do not cover action"));
}

#[test]
fn data_event_capability_ref_must_not_be_revoked() {
    let state = make_state(true);
    let grant_id = "ak:grant:01904100-0000-7000-8000-000000000114";
    let seal_ref = insert_historical_data_event_grant(&state, grant_id, "ak.message.create", true);
    let object = data_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    let err = validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ak.message.create",
        &object,
    )
    .expect_err("revoked capability_ref must reject");

    assert_eq!(err.code, "capability_denied");
    assert!(err.message.contains("revoked"));
}

#[test]
fn data_event_capability_ref_reports_upstream_revoked_parent() {
    let state = make_state(true);
    let parent_grant_id = "ak:grant:01904100-0000-7000-8000-000000000116";
    let child_grant_id = "ak:grant:01904100-0000-7000-8000-000000000117";
    let seal_ref = insert_historical_data_event_delegated_grant_with_revoked_parent(
        &state,
        parent_grant_id,
        child_grant_id,
        "ak.message.create",
    );
    let object = data_event_object_with_refs(&seal_ref, vec![child_grant_id.to_owned()]);

    let err = validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ak.message.create",
        &object,
    )
    .expect_err("child capability_ref with revoked parent must reject");

    assert_eq!(err.code, crate::authz::REASON_GRANT_REVOKED_UPSTREAM);
    assert!(err.message.contains("revoked upstream"));
}

#[test]
fn data_event_uses_seal_ref_pre_state_not_live_authz_index() {
    let state = make_state(true);
    let grant_id = "ak:grant:01904100-0000-7000-8000-000000000115";
    let seal_ref = insert_historical_data_event_grant(&state, grant_id, "ak.message.create", false);
    state
        .authz
        .upsert_projected_grant(data_event_grant(grant_id, "ak.message.create", true));
    let object = data_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ak.message.create",
        &object,
    )
    .expect("DataEvent authz must evaluate the seal_ref pre-state, not the live authz index");
}

#[test]
fn e2ee_data_event_requires_covered_seals_cell_contains_seal_ref() {
    let state = make_state(true);
    let grant_id = "ak:grant:01904100-0000-7000-8000-000000000118";
    let seal_ref =
        insert_historical_data_event_grant_with_e2ee_state(&state, grant_id, false, false);
    let object = data_event_e2ee_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    let err = validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ak.message.create",
        &object,
    )
    .expect_err("E2EE DataEvent without covered_seals coverage must fail closed");

    assert_eq!(err.code, "failed_precondition");
    assert!(err.message.contains("mls_governance_binding_stale"));
    assert!(err.message.contains("covered_seals_cell"));
}

#[test]
fn e2ee_data_event_accepts_when_covered_seals_contains_seal_ref() {
    let state = make_state(true);
    let grant_id = "ak:grant:01904100-0000-7000-8000-000000000119";
    let seal_ref =
        insert_historical_data_event_grant_with_e2ee_state(&state, grant_id, true, false);
    let object = data_event_e2ee_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ak.message.create",
        &object,
    )
    .expect("covered E2EE DataEvent should pass the covered_seals gate");
}

#[test]
fn relaxed_e2ee_data_event_keeps_capability_gate_without_covered_seals_gate() {
    let state = make_state(true);
    let grant_id = "ak:grant:01904100-0000-7000-8000-00000000011a";
    let seal_ref =
        insert_historical_data_event_grant_with_e2ee_state(&state, grant_id, false, true);
    let object = data_event_e2ee_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ak.message.create",
        &object,
    )
    .expect("relaxed E2EE profile should not require the full covered_seals gate");
}

// ----------------------------------------------------------------------------
// Device-identity B-model (device-lifecycle.md §5.4): service_attested
// ak.device.authorize enrollment-authority binding admission.
// ----------------------------------------------------------------------------

/// Ingest a principal DID document that designates `authority_did` as the
/// ArkretDeviceEnrollmentAuthority via a `service` entry whose `id` is
/// `service_id`.
async fn ingest_principal_with_enrollment_authority(
    state: &AppState,
    principal_did: &str,
    service_id: &str,
    authority_did: &str,
) {
    let now = chrono::Utc::now();
    state
        .persistence
        .webvh()
        .put_document(crate::state::WebvhDocumentRecord {
            did: principal_did.to_owned(),
            did_document: json!({
                "id": principal_did,
                "verificationMethod": [],
                "service": [{
                    "id": service_id,
                    "type": arkret_sdk::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY,
                    "serviceEndpoint": authority_did,
                }],
            }),
            key_log_head: Some("sha256:head".to_owned()),
            seq: 1,
            method_evidence: json!({ "mode": "test" }),
            fetched_at: now,
            expires_at: now,
            updated_at: now,
        })
        .await
        .expect("ingest principal webvh document");
}

/// Build a `service_attested` ak.device.authorize envelope object for
/// `principal_did`, authorized by `authority_did`, with a self-certifying
/// `device_id` derived from `device_pubkey`.
fn service_attested_device_authorize_object(
    principal_did: &str,
    authority_did: &str,
    authorization_ref: &str,
    device_pubkey: &[u8; 32],
) -> serde_json::Map<String, Value> {
    let device_pubkey_mb = arkret_sdk::ed25519_pubkey_to_did_key_multibase(device_pubkey);
    let device_id = arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000d0")
        .expect("valid device id");
    let envelope = json!({
        "kind": "ak.device.authorize",
        "actor_id": principal_did,
        "executed_by": authority_did,
        "authorization_ref": authorization_ref,
        "payload": {
            "principal_id": principal_did,
            "device_id": device_id.as_str(),
            "device_public_key": device_pubkey_mb,
            "authorized_by": authority_did,
            "not_before": "2026-06-17T00:00:00Z",
            "enrollment_authority_binding": {
                "kind": "service_attested",
                "authority_did": authority_did,
                "authorization_ref": authorization_ref,
            }
        }
    });
    envelope.as_object().unwrap().clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn service_attested_device_authorize_accepts_designated_authority() {
    let state = make_state(true);
    let principal_did = "did:webvh:scid:users.soland.local:alice";
    let authority_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    let authority_did = did_key_for(&authority_key);
    let authorization_ref = format!("{principal_did}#enrollment-authority");
    ingest_principal_with_enrollment_authority(
        &state,
        principal_did,
        &authorization_ref,
        &authority_did,
    )
    .await;
    let device_pubkey = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32])
        .verifying_key()
        .to_bytes();
    let object = service_attested_device_authorize_object(
        principal_did,
        &authority_did,
        &authorization_ref,
        &device_pubkey,
    );

    validate_device_enrollment_authority_binding(&state, &object, principal_did)
        .await
        .expect("designated service_attested device.authorize must be accepted");
}

#[tokio::test(flavor = "multi_thread")]
async fn service_attested_device_authorize_rejects_undesignated_authority() {
    let state = make_state(true);
    let principal_did = "did:webvh:scid:users.soland.local:alice";
    let designated_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    let designated_did = did_key_for(&designated_key);
    let authorization_ref = format!("{principal_did}#enrollment-authority");
    ingest_principal_with_enrollment_authority(
        &state,
        principal_did,
        &authorization_ref,
        &designated_did,
    )
    .await;
    // The event names a DIFFERENT authority than the one the DID document
    // designates.
    let imposter_key = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
    let imposter_did = did_key_for(&imposter_key);
    let device_pubkey = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32])
        .verifying_key()
        .to_bytes();
    let object = service_attested_device_authorize_object(
        principal_did,
        &imposter_did,
        &authorization_ref,
        &device_pubkey,
    );

    let err = validate_device_enrollment_authority_binding(&state, &object, principal_did)
        .await
        .expect_err("undesignated authority must reject");
    assert_eq!(err.code, "device_enrollment_authority_not_designated");
    assert_eq!(err.status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn service_attested_device_authorize_rejects_authorization_ref_mismatch() {
    let state = make_state(true);
    let principal_did = "did:webvh:scid:users.soland.local:alice";
    let authority_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    let authority_did = did_key_for(&authority_key);
    let service_id = format!("{principal_did}#enrollment-authority");
    ingest_principal_with_enrollment_authority(&state, principal_did, &service_id, &authority_did)
        .await;
    let device_pubkey = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32])
        .verifying_key()
        .to_bytes();
    // authorization_ref points at a different (non-existent) service entry id.
    let wrong_ref = format!("{principal_did}#some-other-delegation");
    let object = service_attested_device_authorize_object(
        principal_did,
        &authority_did,
        &wrong_ref,
        &device_pubkey,
    );

    let err = validate_device_enrollment_authority_binding(&state, &object, principal_did)
        .await
        .expect_err("authorization_ref not matching the service entry id must reject");
    assert_eq!(err.code, "device_enrollment_authority_not_designated");
}

#[tokio::test(flavor = "multi_thread")]
async fn non_enrollment_device_authorize_passes_through_gate() {
    // A device.authorize that carries no enrollment_authority_binding (e.g. a
    // cross_signing / bootstrap device) is not this gate's concern and must pass
    // through untouched (validated elsewhere).
    let state = make_state(true);
    let principal_did = "did:webvh:scid:users.soland.local:alice";
    let object = json!({
        "kind": "ak.device.authorize",
        "actor_id": principal_did,
        "payload": {
            "principal_id": principal_did,
            "device_id": "ak:device:01904100-0000-8000-8000-000000000001",
            "device_public_key": "z6Mk...",
            "bootstrap_binding": {
                "kind": "inception_self_authorized",
                "did_method_evidence_ref": "did:webvh:.../entry-0"
            }
        }
    });
    let object = object.as_object().unwrap().clone();

    validate_device_enrollment_authority_binding(&state, &object, principal_did)
        .await
        .expect("non-enrollment device.authorize must pass through this gate");
}
