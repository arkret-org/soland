use super::*;
use crate::config::{
    AppConfig, FederationPolicy, IceServersConfig, LiveKitConfig, ObjectStorageConfig,
};
use crate::db::Db;

pub(super) fn make_state(development_mode: bool) -> AppState {
    let config = AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-test")),
        ice: IceServersConfig::default(),
        livekit: LiveKitConfig::default(),
        cors_allow_origin: None,
        account_authority_url: None,
        oidc_client_id: None,
        development_mode,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        notary_signing_key_seed: None,
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        federation_outbound_enabled: false,
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        to_device_queue_capacity: 10_000,
        push_bridge_cache_ttl_seconds: 900,
        push_bridge_trusted_service_dids: Vec::new(),
        resumable_upload_dir: std::path::PathBuf::from("./soland-resumable-uploads"),
        resumable_upload_incomplete_ttl_seconds: 86_400,
        seal_compaction_min_age_seconds: 604_800,
        compaction_min_witnesses: 1,
        compaction_preserve_genesis: true,
        compaction_prune_only_singleton_successors: true,

        compaction_prune_walk_interval_seconds: 0,

        compaction_prune_walk_per_realm_limit: 50,
        seed_demo_data: true,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        receive_policy_constraints: None,
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: crate::config::LogFormat::Plain,
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
        device_id: "ck:device:01904100-0000-7000-8000-a11ce0000001".to_owned(),
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
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-a11ce0000001".to_owned())
            .unwrap();
    let actor_id = cokret_sdk::Did::new(did.clone()).unwrap();
    let subject_id = actor_id.clone();
    let zero_hash = cokret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    let mut identity = cokret_sdk::MemberIdentity::new(
        realm_id.clone(),
        actor_id.clone(),
        subject_id,
        cokret_sdk::DisplayProfile {
            display_name: "Alice".to_owned(),
            avatar_blob_ref: None,
        },
        chrono::Utc::now(),
        cokret_sdk::MemberIdentityProof {
            verification_method,
            signature_algorithm: cokret_sdk::MemberIdentitySignatureAlgorithm::Ed25519,
            payload_digest: zero_hash,
            signature: "AA".to_owned(),
        },
    );
    let canonical_bytes = identity.canonical_payload_bytes().unwrap();
    identity.proof.payload_digest =
        cokret_sdk::Hash::new(identity.canonical_payload_sha256().unwrap()).unwrap();
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
        .expect("valid MemberIdentity proof should verify");
}

#[test]
fn member_identity_tampered_payload_fails_closed() {
    let state = make_state(false);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let (_, mut payload) = signed_member_identity_payload(&signing_key);
    payload["identity_payload"]["member_identity"]["display_profile"]["display_name"] =
        json!("Mallory");

    let err = validate_member_identity_proof(&state, &payload)
        .expect_err("tampered MemberIdentity payload must fail");
    assert_eq!(err.code, "proof_event_digest_mismatch");
}

#[test]
fn member_identity_unsupported_signature_algorithm_is_422() {
    let state = make_state(false);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (_, mut payload) = signed_member_identity_payload(&signing_key);
    payload["identity_payload"]["member_identity"]["proof"]["signature_algorithm"] = json!("ES256");

    let err = validate_member_identity_proof(&state, &payload)
        .expect_err("unsupported MemberIdentity signature algorithm must fail closed");
    let code = crate::error::ErrorCode::UnsupportedSignatureAlg;
    assert_eq!(err.status, crate::error::error_http_status(code));
    assert_eq!(err.code, code.as_str());
}

#[test]
fn member_identity_encrypted_payload_is_unsupported_fail_closed() {
    let state = make_state(false);
    let payload = json!({
        "realm_id": "ck:realm:01904100-0000-7000-8000-a11ce0000001",
        "actor_id": "did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP",
        "segment": "member_identity",
        "identity_payload": {
            "encrypted_payload": {
                "alg": "stub"
            }
        }
    });

    let err = validate_member_identity_proof(&state, &payload)
        .expect_err("encrypted MemberIdentity proof verification is not wired");
    assert_eq!(err.code, "unsupported_feature");
}

#[test]
fn unknown_fail_closed_critical_extension_is_not_implemented() {
    let envelope = json!({
        "requirements": {
            "critical_extensions": [{
                "id": "ck.extension.unknown",
                "fail_closed": true
            }]
        }
    });
    let object = envelope.as_object().unwrap();

    let err = validate_event_critical_features(object)
        .expect_err("unknown fail-closed extensions must reject writes");

    assert_eq!(err.status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(err.code, "unsupported_feature");
}

#[test]
fn unknown_advisory_critical_extension_is_ignored() {
    let envelope = json!({
        "requirements": {
            "critical_extensions": [{
                "id": "ck.extension.unknown",
                "fail_closed": false
            }]
        }
    });
    let object = envelope.as_object().unwrap();

    validate_event_critical_features(object)
        .expect("non-fail-closed extensions are advisory and may be ignored");
}

#[tokio::test]
async fn policy_components_media_plaintext_reads_realm_meta() {
    let state = make_state(true);
    let realm_id = "ck:realm:01904100-0000-7000-8000-a11ce0000001";
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
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::from([state
                    .config
                    .service_did
                    .clone()]),
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
    let realm_id = "ck:realm:01904100-0000-7000-8000-a11ce0000002";
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
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                minimal_metadata_realm: true,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    let encrypted_envelope = |visibility: &str| {
        json!({
            "strand_id": "ck:strand:01904100-0000-7000-8000-000000000001",
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
                    "event_kind": "ck.message.create"
                }
            }
        })
    };
    let message_op = |payload: serde_json::Value| {
        cokret_sdk::Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            kinds::CK_MESSAGE_CREATE,
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
    let realm_id = "ck:realm:01904100-0000-7000-8000-c1c1e0000001";
    let circle_id = "ck:circle:01904100-0000-7000-8000-c1c1e0000002";
    let member = "did:web:alice.example";
    // An Applet bot that holds a Realm-wide grant but never joined the Circle.
    let non_member = "did:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    // Seed an active Circle whose only member is `member`.
    {
        let mut projection = state.projection.lock().unwrap();
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
            "id": "ck:strand:01904100-0000-7000-8000-000000000abc",
            "metadata": {"title": "t"}
        });
        if let Some(scope) = scope {
            object["scope_circle_id"] = json!(scope);
        }
        cokret_sdk::Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d8550abc")
                .unwrap(),
            cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            kinds::CK_STRAND_CREATE,
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
    let realm_id = "ck:realm:01904100-0000-7000-8000-c2c2e0000001";
    let circle_id = "ck:circle:01904100-0000-7000-8000-c2c2e0000002";
    let strand_id = "ck:strand:01904100-0000-7000-8000-c2c2e0000003";
    let event_id = "ck:event:01904100-0000-7000-8000-c2c2e0000004";
    let member = "did:web:alice.example";
    let non_member = "did:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    {
        let mut projection = state.projection.lock().unwrap();
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
                    cokret_sdk::STRAND_TRACK_NAME_DISCUSSION.to_owned(),
                    cokret_sdk::StrandTrackConfig::discussion_primary(),
                )]),
                title: String::new(),
                summary: None,
                fields: std::collections::BTreeMap::new(),
                state: crate::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                scope_circle_id: Some(circle_id.to_owned()),
            },
        );
        projection.messages.insert(
            event_id.to_owned(),
            crate::reducer::MessageState {
                event_id: event_id.to_owned(),
                realm_id: realm_id.to_owned(),
                sender: member.to_owned(),
                thread_id: strand_id.to_owned(),
                content: json!({}),
                expiry: None,
                encrypted: false,
                operation_id: "ck:operation:01904100-0000-7000-8000-c2c2e0000005".to_owned(),
                created_at: now,
                revision_of: None,
                redacted_at: None,
            },
        );
    }

    let reaction = |sender: &str| {
        cokret_sdk::Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-c2c2e000000a")
                .unwrap(),
            cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            kinds::CK_REACTION_ADD,
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
    let realm_id = "ck:realm:01904100-0000-7000-8000-c3c3e0000001";
    let circle_id = "ck:circle:01904100-0000-7000-8000-c3c3e0000002";
    let scoped_morph_id = "ck:morph:01904100-0000-7000-8000-c3c3e0000003";
    let realm_morph_id = "ck:morph:01904100-0000-7000-8000-c3c3e0000004";
    let member = "did:web:alice.example";
    let non_member = "did:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    {
        let mut projection = state.projection.lock().unwrap();
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
                    updated_by: None,
                    updated_at: None,
                },
            );
        }
    }

    let morph_update = |sender: &str, morph_id: &str| {
        cokret_sdk::Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-c3c3e000000a")
                .unwrap(),
            cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            kinds::CK_MORPH_UPDATE,
            json!({
                "sender": sender,
                "morph_id": morph_id,
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
    // applet-integration.md §4 — `ck.applet.registration` is gated by the
    // machine-readable `ck.realm.admin` capability. The dedicated install
    // aggregate checks this in its handler, but a raw submit via
    // `/_cokret/self/events` reaches `apply_applet_registration` with no authz of
    // its own — this gate closes that bypass. The Realm owner may register; an
    // outsider without `ck.realm.admin` may not.
    let state = make_state(true);
    let realm_id = "ck:realm:01904100-0000-7000-8000-a99e70000001";
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
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    let registration = |sender: &str| {
        cokret_sdk::Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d855a99e")
                .unwrap(),
            cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            kinds::CK_APPLET_REGISTRATION,
            json!({
                "sender": sender,
                "applet_id": "ck:applet:01904100-0000-7000-8000-000000000a01",
                "service_did": "did:web:slack-bridge.example",
                "namespace": "slack",
            }),
        )
    };

    // Realm owner may register an Applet.
    validate_operation_policy(&state, std::slice::from_ref(&registration(owner)))
        .await
        .unwrap();

    // An outsider without `ck.realm.admin` is rejected fail-closed — closing the
    // `/_cokret/self/events` bypass of the install-handler gate.
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
    let realm_id = "ck:realm:01904100-0000-7000-8000-a11ce0000003";
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
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    let op = cokret_sdk::Operation::create(
        cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c6").unwrap(),
        cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
        kinds::CK_MESSAGE_CREATE,
        json!({
            "strand_id": "ck:strand:01904100-0000-7000-8000-000000000001",
            "track_name": "main",
            "encrypted_content": {
                "scheme": "mls-rfc9420",
                "version": "1.0",
                "group_id": "base64url",
                "epoch": 12,
                "content_type": "application/json",
                "ciphertext": "base64url",
                "aad_visibility_event_id": "routing_digest",
                "aad": {"realm_id": realm_id, "event_kind": "ck.message.create"}
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
    let realm_id = "ck:realm:01904100-0000-7000-8000-a11ce0000001";
    let policy_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    {
        let mut projection = state.projection.lock().unwrap();
        projection.cells.insert(
            cokret_sdk::CellRef::new(
                "ck:cell:ck.component.mls.epoch.v1:ck:mls_group:unit-test".to_owned(),
            )
            .unwrap(),
            cokret_sdk::lattice::CellState::Value(json!({
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
        json!({ "schema": ["ck.schema.event.v1"] }),
    );
    assert_eq!(
        event_requirements_schema_id(&state, &object).unwrap(),
        "ck.schema.event.v1"
    );
}

#[tokio::test]
async fn top_level_effective_scope_is_reducer_managed() {
    let state = make_state(false);
    let session = session();
    let envelope = json!({
        "event_id": "ck:event:01904100-0000-7000-8000-00000000eff0",
        "kind": crate::kinds::CK_REALM_CREATE,
        "requirements": { "schema": ["ck.schema.event.v1"] },
        "actor_id": session.actor.clone(),
        "effective_scope": "ck:realm:01904100-0000-7000-8000-a11ce0000001"
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
            "strand_id": "ck:strand:01904100-0000-7000-8000-f10dc0000001"
        }
    });
    let object = envelope.as_object().unwrap();
    let err = validate_event_schema_and_payload(
        &state,
        "ck.strand.move",
        "ck.schema.event.v1",
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
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            "membership": "join",
            "reason": "invite_accept",
            "invite_ref": "ck:invite:01904100-0000-7000-8000-000000000001",
            "delivery_status": "unroutable"
        }
    });
    validate_event_schema_and_payload(
        &state,
        "ck.member.state",
        "ck.schema.event.v1",
        &valid,
        valid.as_object().unwrap(),
    )
    .expect("ck.member.state invite accept should allow invite_ref");
}

#[test]
fn event_payload_validator_enforces_strand_update_object_patch_schema() {
    let state = make_state(true);
    let strand_id = "ck:strand:01904100-0000-7000-8000-f10dc0000001";
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
        "ck.strand.update",
        "ck.schema.event.v1",
        &valid,
        valid.as_object().unwrap(),
    )
    .expect("canonical ck.strand.update object_patch_payload should validate");

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
        "ck.strand.update",
        "ck.schema.event.v1",
        &invalid_patch_op,
        invalid_patch_op.as_object().unwrap(),
    )
    .expect_err("ck.strand.update patch operations must match ck.patch.v1 exactly");
    assert_eq!(err.code, "schema_violation");
}

#[test]
fn event_payload_validator_catalog_covers_active_standard_durable_events() {
    let catalog = cokret_sdk::schema::event_payload_validator_catalog();
    let event_kinds = artifacts::active_durable_event_kinds()
        .iter()
        .map(String::as_str)
        .filter(|kind| cokret_sdk::events::is_standard_event_kind(kind))
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
fn event_payload_validator_enforces_object_patch_family_schema() {
    let catalog = cokret_sdk::schema::event_payload_validator_catalog();
    let object_patch_kinds = [
        "ck.realm.update",
        "ck.strand.update",
        "ck.morph.update",
        "ck.space.update",
        "ck.profile.update",
    ];
    let missing = catalog.missing_payload_validators_for(object_patch_kinds);
    assert!(
        missing.is_empty(),
        "missing object_patch validators: {missing:?}"
    );

    for event_kind in object_patch_kinds {
        let patch = if matches!(event_kind, "ck.strand.update" | "ck.morph.update") {
            json!({ "metadata.title": { "$op": "set", "value": "Roadmap" } })
        } else {
            json!({ "title": { "$op": "set", "value": "Roadmap" } })
        };
        catalog
            .validate_payload(
                event_kind,
                &json!({
                        "target_ref": "ck:strand:01904100-0000-7000-8000-f10dc0000001",
                        "patch": patch
                }),
            )
            .unwrap_or_else(|err| {
                panic!("{event_kind} must accept canonical object_patch_payload: {err}");
            });
        assert!(
            catalog
                .validate_payload(
                    event_kind,
                    &json!({
                        "target_ref": "ck:strand:01904100-0000-7000-8000-f10dc0000001",
                        "patch": {
                            "title": { "$op": "replace", "value": "Roadmap" }
                        }
                    }),
                )
                .is_err(),
            "{event_kind} must reject patch ops outside ck.patch.v1"
        );
    }

    // ck.profile.realm_override carries a Realm-scoped override and uses the
    // dedicated profile_realm_override_payload (target_ref + target_realm_id
    // + patch), not the generic object_patch_payload.
    catalog
        .validate_payload(
            "ck.profile.realm_override",
            &json!({
                "target_ref": "ck:actor_profile:01904100-0000-7000-8000-f10dc0000001",
                "target_realm_id": "ck:realm:01904100-0000-7000-8000-f10dc0000002",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ck.profile.realm_override must accept profile_realm_override_payload: {err}");
        });

    catalog
        .validate_payload(
            "ck.strand.tracks.update",
            &json!({
                "strand_id": "ck:strand:01904100-0000-7000-8000-f10dc0000001",
                "tracks": {
                    "discussion": {
                        "enabled": true,
                        "is_primary": true
                    }
                }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ck.strand.tracks.update must accept canonical tracks map payload: {err}");
        });
    assert!(
        catalog
            .validate_payload(
                "ck.strand.tracks.update",
                &json!({
                    "type": "removed_track_update",
                    "strand_id": "ck:strand:01904100-0000-7000-8000-f10dc0000001",
                }),
            )
            .is_err(),
        "ck.strand.tracks.update must still reject retired `type` discriminators"
    );
}

#[test]
fn realm_create_rejects_world_readable_encrypted_history() {
    let state = make_state(true);
    let realm_id = "ck:realm:01904100-0000-7000-8000-a11ce0000001";
    let envelope = json!({
        "payload": {
            "object": {
                "id": realm_id,
                "schema": "ck.schema.realm.v1",
                "title": "encrypted public history",
                "created_by": "did:web:alice.example",
                "trust_domain": "ck:trust_domain:soland.local",
                "schema_refs": ["ck.schema.realm.v1"],
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
    let err = validate_event_schema_and_payload(
        &state,
        "ck.realm.create",
        "ck.schema.event.v1",
        &envelope,
        object,
    )
    .expect_err("encrypted world-readable Realm history must fail closed");
    assert_eq!(err.code, "incompatible_history_with_encryption");
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
    let payload_digest = cokret_sdk::canonical::sha256_digest(&payload_bytes);
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
    let canonical_bytes = br#"{"actor_id":"did:web:alice.example","event_id":"ck:event:test"}"#;
    let event_digest = cokret_sdk::canonical::sha256_digest(canonical_bytes);
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
        &cokret_sdk::canonical::sha256_digest(canonical_bytes),
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
    let canonical_bytes = br#"{"actor_id":"did:web:alice.example","event_id":"ck:event:test"}"#;
    let event_digest = cokret_sdk::canonical::sha256_digest(canonical_bytes);
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
        &cokret_sdk::canonical::sha256_digest(canonical_bytes),
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
    use cokret_sdk::signatures::{ProductionVerifier, build_proof_envelope};
    use cokret_sdk::{Audience, Hash};

    struct Noop;
    impl cokret_sdk::signatures::EventVerifier for Noop {
        fn verify(
            &self,
            _: &[u8],
            _: &[u8],
            _: &cokret_sdk::signatures::PublicKeyMaterial,
        ) -> std::result::Result<(), cokret_sdk::signatures::VerifierError> {
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
        cokret_sdk::signatures::VerifierError::DevProofRejected(_)
    ));

    // A proof with kind="detached_jws" — SDK accepts the kind
    // (signature still has to verify separately).
    let prod = build_proof_envelope(
        cokret_sdk::signatures::detached_jws_kind(),
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

const DATA_EVENT_REALM: &str = "ck:realm:01904100-0000-7000-8000-000000000001";
const DATA_EVENT_ACTOR: &str = "did:web:alice.example";
const DATA_EVENT_STRAND: &str = "ck:strand:01904100-0000-7000-8000-000000000001";

fn data_event_seal_id() -> cokret_sdk::SealId {
    cokret_sdk::SealId::new(format!("ck:seal:sha256:{}", "a".repeat(64))).unwrap()
}

fn data_event_move_id(byte: u8) -> cokret_sdk::MoveId {
    cokret_sdk::MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn data_event_hash(byte: u8) -> cokret_sdk::Hash {
    cokret_sdk::Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn data_event_dummy_signature() -> cokret_sdk::MoveSignature {
    use chrono::TimeZone;

    cokret_sdk::MoveSignature {
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:notary.example#k1".to_owned(),
        payload_digest: data_event_hash(0xff),
        created_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        jws: "AAAA.BBBB.CCCC".to_owned(),
    }
}

fn insert_data_event_seal(state: &AppState, covered: Vec<cokret_sdk::MoveId>) -> String {
    use chrono::TimeZone;

    let seal_id = data_event_seal_id();
    let realm = cokret_sdk::RealmId::new(DATA_EVENT_REALM.to_owned()).unwrap();
    let seal = cokret_sdk::Seal {
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
        notary_signature: cokret_sdk::NotarySig::Single(data_event_dummy_signature()),
        sealed_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        hlc: cokret_sdk::Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        kind: cokret_sdk::SealKind::Normal,
    };
    cokret_sdk::state_res::SealStore::put(state.seal_store.as_ref(), &seal).unwrap();
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

fn insert_historical_data_event_grant(
    state: &AppState,
    grant_id: &str,
    action: &str,
    revoked: bool,
) -> String {
    let realm = cokret_sdk::RealmId::new(DATA_EVENT_REALM.to_owned()).unwrap();
    let seal_id = data_event_seal_id();
    let move_id = data_event_move_id(0xab);
    let cell = cokret_sdk::CellRef::new(format!(
        "ck:cell:ck.component.capability.grant.v1:{grant_id}"
    ))
    .unwrap();
    let mut value = json!({
        "grant_id": grant_id,
        "schema": "ck.schema.capability_grant.v1",
        "realm_id": DATA_EVENT_REALM,
        "issuer": "did:web:owner.example",
        "subject": DATA_EVENT_ACTOR,
        "actions": [action],
        "resources": [DATA_EVENT_STRAND],
        "issued_at": "2026-05-08T00:00:00Z"
    });
    if revoked {
        value["revoked"] = Value::Bool(true);
        value["revoked_at"] = Value::String("2026-05-08T00:01:00Z".to_owned());
    }
    let op = cokret_sdk::LatticeOp {
        op_type: cokret_sdk::LatticeOpType::Add,
        tag: Some("ck:operation:01904100-0000-7000-8000-000000000999".to_owned()),
        value: Some(value),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    };
    cokret_sdk::state_res::CellStore::append_sealed_effects(
        state.cell_store.as_ref(),
        &realm,
        &seal_id,
        &[(
            cell,
            cokret_sdk::lattice::SealedOp::new(move_id.clone(), op),
        )],
    )
    .unwrap();
    insert_data_event_seal(state, vec![move_id])
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
            "key_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "key_epoch": 1,
            "capability_refs": refs
        },
        "effects": [{
            "cell": format!("ck:cell:ck.component.strand.discussion.timeline.v1:{DATA_EVENT_STRAND}"),
            "op": {"kind": "append"}
        }]
    })
    .as_object()
    .unwrap()
    .clone()
}

#[test]
fn data_event_capability_ref_must_resolve() {
    let state = make_state(true);
    let seal_ref = insert_data_event_seal(&state, Vec::new());
    let object = data_event_object_with_refs(
        &seal_ref,
        vec!["ck:grant:01904100-0000-7000-8000-000000000111".to_owned()],
    );

    let err = validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ck.message.create",
        &object,
    )
    .expect_err("unknown capability_ref must reject");

    assert_eq!(err.code, "capability_denied");
    assert!(err.message.contains("not projected"));
}

#[test]
fn data_event_capability_ref_must_cover_effect_cell() {
    let state = make_state(true);
    let grant_id = "ck:grant:01904100-0000-7000-8000-000000000112";
    let seal_ref = insert_historical_data_event_grant(&state, grant_id, "ck.message.create", false);
    let object = data_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ck.message.create",
        &object,
    )
    .expect("matching grant must cover the DataEvent effect cell");

    let wrong_state = make_state(true);
    let wrong_grant_id = "ck:grant:01904100-0000-7000-8000-000000000113";
    let wrong_seal_ref =
        insert_historical_data_event_grant(&wrong_state, wrong_grant_id, "ck.reaction.add", false);
    let wrong_action_object =
        data_event_object_with_refs(&wrong_seal_ref, vec![wrong_grant_id.to_owned()]);
    let err = validate_data_event_capability_refs(
        &wrong_state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ck.message.create",
        &wrong_action_object,
    )
    .expect_err("wrong action must not cover the DataEvent effect cell");
    assert_eq!(err.code, "capability_denied");
    assert!(err.message.contains("do not cover action"));
}

#[test]
fn data_event_capability_ref_must_not_be_revoked() {
    let state = make_state(true);
    let grant_id = "ck:grant:01904100-0000-7000-8000-000000000114";
    let seal_ref = insert_historical_data_event_grant(&state, grant_id, "ck.message.create", true);
    let object = data_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    let err = validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ck.message.create",
        &object,
    )
    .expect_err("revoked capability_ref must reject");

    assert_eq!(err.code, "capability_denied");
    assert!(err.message.contains("revoked"));
}

#[test]
fn data_event_uses_seal_ref_pre_state_not_live_authz_index() {
    let state = make_state(true);
    let grant_id = "ck:grant:01904100-0000-7000-8000-000000000115";
    let seal_ref = insert_historical_data_event_grant(&state, grant_id, "ck.message.create", false);
    state
        .authz
        .upsert_projected_grant(data_event_grant(grant_id, "ck.message.create", true));
    let object = data_event_object_with_refs(&seal_ref, vec![grant_id.to_owned()]);

    validate_data_event_capability_refs(
        &state,
        DATA_EVENT_ACTOR,
        DATA_EVENT_REALM,
        "ck.message.create",
        &object,
    )
    .expect("DataEvent authz must evaluate the seal_ref pre-state, not the live authz index");
}

// ----------------------------------------------------------------------------
// Device-identity B-model (device-lifecycle.md §5.4): service_attested
// ck.device.authorize enrollment-authority binding admission.
// ----------------------------------------------------------------------------

/// Ingest a principal DID document that designates `authority_did` as the
/// CokretDeviceEnrollmentAuthority via a `service` entry whose `id` is
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
                    "type": cokret_sdk::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY,
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

/// Build a `service_attested` ck.device.authorize envelope object for
/// `principal_did`, authorized by `authority_did`, with a self-certifying
/// `device_id` derived from `device_pubkey`.
fn service_attested_device_authorize_object(
    principal_did: &str,
    authority_did: &str,
    authorization_ref: &str,
    device_pubkey: &[u8; 32],
) -> serde_json::Map<String, Value> {
    let device_pubkey_mb = cokret_sdk::ed25519_pubkey_to_did_key_multibase(device_pubkey);
    let device_id = cokret_sdk::DeviceId::new("ck:device:01904100-0000-7000-8000-0000000000d0")
        .expect("valid device id");
    let envelope = json!({
        "kind": "ck.device.authorize",
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
        "kind": "ck.device.authorize",
        "actor_id": principal_did,
        "payload": {
            "principal_id": principal_did,
            "device_id": "ck:device:01904100-0000-8000-8000-000000000001",
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
