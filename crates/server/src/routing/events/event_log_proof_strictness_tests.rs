use super::*;
use crate::config::{AppConfig, FederationPolicy, ObjectStorageConfig};
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
        cors_allow_origin: None,
        auth_server_url: None,
        development_mode,
        oauth_introspection_url: None,
        oauth_introspection_bearer: None,
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
