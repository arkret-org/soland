use cokret_sdk::{Operation, OperationId};
use serde_json::{Value, json};

use super::*;
use crate::config::{AppConfig, IceServersConfig, LiveKitConfig, ObjectStorageConfig};
use crate::db::Db;
use crate::kinds;

struct OperationVector {
    name: &'static str,
    kind: &'static str,
    payload: Value,
    valid: bool,
}

fn test_state() -> AppState {
    AppState::new(
        AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://server".to_owned(),
            service_did: "did:web:soland.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-test-blobs"),
            ),
            ice: IceServersConfig::default(),
            livekit: LiveKitConfig::default(),
            cors_allow_origin: None,
            account_authority_url: None,
            oidc_client_id: None,
            development_mode: true,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            // Tests use fixed-time HLC fixtures (`0189c4d2af00...`) which
            // are years in the past relative to wall-clock; disable
            // replay-window enforcement so they pass.
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            notary_signing_key_seed: None,
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: crate::config::FederationPolicy::Mesh,
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
        },
        Db { pool: None },
    )
}

fn operation(index: usize, kind: &str, payload: Value) -> Operation {
    // Build a deterministic UUIDv7 from the index (last 12 hex pad as hex of the index).
    let payload_part = format!("{:012x}", index);
    let op_id = format!("ck:operation:01904100-0000-7000-8000-{payload_part}");
    let realm_id = "ck:realm:01904100-0000-7000-8000-000000000001".to_owned();
    Operation::create(
        OperationId::new(op_id).unwrap(),
        cokret_sdk::RealmId::new(realm_id).unwrap(),
        kind,
        payload,
    )
}

#[test]
fn builtin_operation_conformance_vectors_cover_registry() {
    let state = test_state();
    let vectors = vec![
        OperationVector {
            name: "message create",
            kind: cokret_sdk::events::kinds::MESSAGE_CREATE,
            payload: json!({
                "message_id": "ck:message:01904100-0000-7000-8000-79a90338768b",
                "strand_id": "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
                "track_name": "discussion",
                "sender": "did:web:alice.example",
                "content": {"kind": "ck.content.text", "body": "hello"}
            }),
            valid: true,
        },
        OperationVector {
            name: "message revise",
            kind: cokret_sdk::events::kinds::MESSAGE_REVISE,
            payload: json!({"target_event_id": "ck:event:01904100-0000-7000-8000-79a90338768b", "content": {"kind": "ck.content.text", "body": "edited"}}),
            valid: true,
        },
        OperationVector {
            name: "message redact",
            kind: cokret_sdk::events::kinds::MESSAGE_REDACT,
            payload: json!({"target_event_id": "ck:event:01904100-0000-7000-8000-79a90338768b"}),
            valid: true,
        },
        OperationVector {
            name: "generic redaction",
            kind: cokret_sdk::events::kinds::REDACTION,
            payload: json!({"redacts": "ck:event:01904100-0000-7000-8000-79a90338768b"}),
            valid: true,
        },
        OperationVector {
            name: "reaction add",
            kind: cokret_sdk::events::kinds::REACTION_ADD,
            payload: json!({"event_id": "ck:event:01904100-0000-7000-8000-79a90338768b", "actor": "did:web:alice.example", "key": "+1"}),
            valid: true,
        },
        OperationVector {
            name: "reaction remove",
            kind: cokret_sdk::events::kinds::REACTION_REMOVE,
            payload: json!({"target_event_id": "ck:event:01904100-0000-7000-8000-79a90338768b", "sender": "did:web:alice.example", "reaction": "+1"}),
            valid: true,
        },
        OperationVector {
            name: "relation create",
            kind: cokret_sdk::events::kinds::RELATION_CREATE,
            payload: json!({"relation_id": "ck:relation:01904100-0000-7000-8000-71604d58ec0b", "relation_kind": "blocks", "from_ref": "ck:strand:01904100-0000-7000-8000-ca33616973bb", "to_ref": "ck:morph:01904100-0000-7000-8000-7191ddd787e5"}),
            valid: true,
        },
        OperationVector {
            name: "relation update",
            kind: cokret_sdk::events::kinds::RELATION_UPDATE,
            payload: json!({"relation_id": "ck:relation:01904100-0000-7000-8000-71604d58ec0b", "fields": {"weight": 1}}),
            valid: true,
        },
        OperationVector {
            name: "relation delete",
            kind: cokret_sdk::events::kinds::RELATION_TOMBSTONE,
            payload: json!({"relation_id": "ck:relation:01904100-0000-7000-8000-71604d58ec0b"}),
            valid: true,
        },
        OperationVector {
            name: "member state join",
            kind: cokret_sdk::events::kinds::MEMBER_STATE,
            payload: json!({"actor_id": "did:web:alice.example", "membership": "join"}),
            valid: true,
        },
        OperationVector {
            name: "member state leave",
            kind: cokret_sdk::events::kinds::MEMBER_STATE,
            payload: json!({"actor_id": "did:web:alice.example", "membership": "leave"}),
            valid: true,
        },
        OperationVector {
            name: "member state ban",
            kind: cokret_sdk::events::kinds::MEMBER_STATE,
            payload: json!({"actor_id": "did:web:bob.example", "membership": "ban"}),
            valid: true,
        },
        OperationVector {
            name: "member state knock",
            kind: cokret_sdk::events::kinds::MEMBER_STATE,
            payload: json!({"actor_id": "did:web:bob.example", "membership": "knock"}),
            valid: true,
        },
        OperationVector {
            name: "read marker missing event_id",
            kind: cokret_sdk::events::kinds::READ_CURSOR_ADVANCE,
            payload: json!({
                "actor_id": "did:web:alice.example",
                "read_scope": {"kind": "realm"},
                "position": {"hlc": "019041000000-0000-00000001"}
            }),
            valid: false,
        },
        OperationVector {
            name: "read marker valid",
            kind: cokret_sdk::events::kinds::READ_CURSOR_ADVANCE,
            payload: json!({
                "actor_id": "did:web:alice.example",
                "read_scope": {"kind": "realm"},
                "position": {
                    "event_id": "ck:event:01904100-0000-7000-8000-79a90338768b",
                    "hlc": "019041000000-0000-00000001"
                }
            }),
            valid: true,
        },
        OperationVector {
            name: "space create",
            kind: cokret_sdk::events::kinds::REALM_CREATE,
            payload: json!({"object": {
                "id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "schema": "ck.schema.realm.v1",
                "title": "Launch",
                "trust_domain": "ck:trust_domain:local",
                "created_by": "did:web:alice.example",
                "schema_refs": ["ck.schema.realm.v1"],
                "default_discoverability": "invite",
                "default_join_rule": "invite",
                "history_visibility": "joined",
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
                "created_at": "2026-05-20T00:00:00Z"
            }}),
            valid: true,
        },
        OperationVector {
            name: "space update",
            kind: cokret_sdk::events::kinds::REALM_UPDATE,
            payload: json!({
                "target_ref": "ck:realm:01904100-0000-7000-8000-000000000001",
                "patch": {
                    "title": "Launch 2"
                }
            }),
            valid: true,
        },
        OperationVector {
            name: "space destroy",
            kind: cokret_sdk::events::kinds::REALM_DESTROY,
            payload: json!({"action": "destroy"}),
            valid: true,
        },
        OperationVector {
            name: "space container archive",
            kind: cokret_sdk::events::kinds::SPACE_ARCHIVE,
            payload: json!({"space_id": "ck:space:01904100-0000-7000-8000-1fb50799ad42"}),
            valid: true,
        },
        OperationVector {
            name: "space container restore",
            kind: cokret_sdk::events::kinds::SPACE_RESTORE,
            payload: json!({"space_id": "ck:space:01904100-0000-7000-8000-1fb50799ad42"}),
            valid: true,
        },
        OperationVector {
            name: "space container tombstone",
            kind: cokret_sdk::events::kinds::SPACE_TOMBSTONE,
            payload: json!({"space_id": "ck:space:01904100-0000-7000-8000-1fb50799ad42"}),
            valid: true,
        },
        OperationVector {
            name: "space container restore missing space_id",
            kind: cokret_sdk::events::kinds::SPACE_RESTORE,
            payload: json!({"reason": "release_reopened"}),
            valid: false,
        },
        // Strand / Morph lifecycle conformance vectors.
        OperationVector {
            name: "strand create",
            kind: cokret_sdk::events::kinds::STRAND_CREATE,
            payload: json!({"object": {"id": "ck:strand:01904100-0000-7000-8000-ca33616973bb", "kind": "discussion", "title": "Launch"}}),
            valid: true,
        },
        OperationVector {
            name: "strand update",
            kind: cokret_sdk::events::kinds::STRAND_UPDATE,
            payload: json!({"target_ref": "ck:strand:01904100-0000-7000-8000-ca33616973bb", "patch": {"metadata.title": { "$op": "set", "value": "Launch v2" }}}),
            valid: true,
        },
        OperationVector {
            name: "strand archive",
            kind: cokret_sdk::events::kinds::STRAND_ARCHIVE,
            payload: json!({"target_ref": "ck:strand:01904100-0000-7000-8000-ca33616973bb"}),
            valid: true,
        },
        OperationVector {
            name: "strand restore",
            kind: cokret_sdk::events::kinds::STRAND_RESTORE,
            payload: json!({"target_ref": "ck:strand:01904100-0000-7000-8000-ca33616973bb"}),
            valid: true,
        },
        OperationVector {
            name: "strand archive missing target_ref",
            kind: cokret_sdk::events::kinds::STRAND_ARCHIVE,
            payload: json!({"reason": "stale_room"}),
            valid: false,
        },
        // Strand position event vectors.
        OperationVector {
            name: "strand move",
            kind: cokret_sdk::events::kinds::STRAND_MOVE,
            payload: json!({
                "strand_id": "ck:strand:01904100-0000-7000-8000-ca33616973bb",
                "board_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000001",
                "target_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002",
                "rank": "a1",
            }),
            valid: true,
        },
        OperationVector {
            name: "strand reorder",
            kind: cokret_sdk::events::kinds::STRAND_REORDER,
            payload: json!({
                "strand_id": "ck:strand:01904100-0000-7000-8000-ca33616973bb",
                "board_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000001",
                "space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002",
                "rank": "a1",
            }),
            valid: true,
        },
        OperationVector {
            name: "strand move missing board_space_id",
            kind: cokret_sdk::events::kinds::STRAND_MOVE,
            payload: json!({"strand_id": "ck:strand:01904100-0000-7000-8000-ca33616973bb"}),
            valid: false,
        },
        OperationVector {
            name: "strand reorder missing strand_id",
            kind: cokret_sdk::events::kinds::STRAND_REORDER,
            payload: json!({"board_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000001", "space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002", "rank": "a1"}),
            valid: false,
        },
        OperationVector {
            name: "morph create",
            kind: cokret_sdk::events::kinds::MORPH_CREATE,
            payload: json!({"object": {"id": "ck:morph:01904100-0000-7000-8000-7191ddd787e5", "morph_type": "task", "metadata": {"title": "Backfill"}, "schema_refs": ["ck.schema.morph.v1"]}}),
            valid: true,
        },
        OperationVector {
            name: "morph update",
            kind: cokret_sdk::events::kinds::MORPH_UPDATE,
            payload: json!({"target_ref": "ck:morph:01904100-0000-7000-8000-7191ddd787e5", "patch": {"metadata.title": "Backfill v2"}}),
            valid: true,
        },
        OperationVector {
            name: "morph archive",
            kind: cokret_sdk::events::kinds::MORPH_ARCHIVE,
            payload: json!({"target_ref": "ck:morph:01904100-0000-7000-8000-7191ddd787e5"}),
            valid: true,
        },
        OperationVector {
            name: "morph restore",
            kind: cokret_sdk::events::kinds::MORPH_RESTORE,
            payload: json!({"target_ref": "ck:morph:01904100-0000-7000-8000-7191ddd787e5"}),
            valid: true,
        },
        OperationVector {
            name: "morph restore missing target_ref",
            kind: cokret_sdk::events::kinds::MORPH_RESTORE,
            payload: json!({"reason": "reopen"}),
            valid: false,
        },
        // Applet protocol family conformance vectors.
        OperationVector {
            name: "applet registration",
            kind: cokret_sdk::events::kinds::APPLET_REGISTRATION,
            payload: json!({
                "service_did": "did:web:applet.example",
                "namespace": "extensions",
                "capabilities": ["read"],
            }),
            valid: true,
        },
        OperationVector {
            name: "applet registration missing namespace",
            kind: cokret_sdk::events::kinds::APPLET_REGISTRATION,
            payload: json!({"service_did": "did:web:applet.example"}),
            valid: false,
        },
        OperationVector {
            name: "applet discovery",
            kind: cokret_sdk::events::kinds::APPLET_DISCOVERY,
            payload: json!({
                "service_did": "did:web:applet.example",
                "manifest": {"version": 1},
            }),
            valid: true,
        },
        OperationVector {
            name: "applet session start",
            kind: cokret_sdk::events::kinds::APPLET_INTEROP_SESSION_START,
            payload: json!({
                "applet_id": "ck:applet:01904100-0000-7000-8000-aa55aa55aa55",
                "session_id": "ck:session:01904100-0000-7000-8000-aa55aa55aa55",
                "params": {},
            }),
            valid: true,
        },
        OperationVector {
            name: "applet session status",
            kind: cokret_sdk::events::kinds::APPLET_INTEROP_SESSION_STATUS,
            payload: json!({
                "session_id": "ck:session:01904100-0000-7000-8000-aa55aa55aa55",
                "status": "running",
                "detail": {},
            }),
            valid: true,
        },
        OperationVector {
            name: "applet bridge error",
            kind: cokret_sdk::events::kinds::APPLET_BRIDGE_ERROR,
            payload: json!({
                "session_id": "ck:session:01904100-0000-7000-8000-aa55aa55aa55",
                "errcode": "bridge_unavailable",
                "message": "no upstream",
            }),
            valid: true,
        },
        // Agent protocol family conformance vectors.
        OperationVector {
            name: "agent endpoint",
            kind: cokret_sdk::events::kinds::AGENT_ENDPOINT,
            payload: json!({
                "agent_id": "did:web:agent.example",
                "endpoints": [{"protocol": "http_custom", "url": "https://agent.example/runtime"}],
            }),
            valid: true,
        },
        OperationVector {
            name: "agent endpoint missing endpoints",
            kind: cokret_sdk::events::kinds::AGENT_ENDPOINT,
            payload: json!({"agent_id": "did:web:agent.example"}),
            valid: false,
        },
        OperationVector {
            name: "agent session start",
            kind: cokret_sdk::events::kinds::AGENT_INTEROP_SESSION_START,
            payload: json!({
                "session_id": "ck:session:01904100-0000-7000-8000-bb66bb66bb66",
                "counterparty_agent": "did:web:agent.example",
                "protocol": "http_custom",
                "capability_grant": "ck:grant:01904100-0000-7000-8000-000000000099",
            }),
            valid: true,
        },
        OperationVector {
            name: "agent session start missing capability_grant",
            kind: cokret_sdk::events::kinds::AGENT_INTEROP_SESSION_START,
            payload: json!({
                "session_id": "ck:session:01904100-0000-7000-8000-bb66bb66bb66",
                "counterparty_agent": "did:web:agent.example",
                "protocol": "http_custom",
            }),
            valid: false,
        },
        OperationVector {
            name: "agent session status",
            kind: cokret_sdk::events::kinds::AGENT_INTEROP_SESSION_STATUS,
            payload: json!({
                "session_id": "ck:session:01904100-0000-7000-8000-bb66bb66bb66",
                "status": "working",
                "detail": {},
            }),
            valid: true,
        },
        OperationVector {
            name: "agent session result",
            kind: cokret_sdk::events::kinds::AGENT_INTEROP_SESSION_RESULT,
            payload: json!({
                "session_id": "ck:session:01904100-0000-7000-8000-bb66bb66bb66",
                "result": {"summary": "ok"},
                "audit_binding": {"merkle_root": "sha256:abc"},
            }),
            valid: true,
        },
        OperationVector {
            name: "agent session result missing audit_binding",
            kind: cokret_sdk::events::kinds::AGENT_INTEROP_SESSION_RESULT,
            payload: json!({
                "session_id": "ck:session:01904100-0000-7000-8000-bb66bb66bb66",
                "result": {"summary": "ok"},
            }),
            valid: false,
        },
        OperationVector {
            name: "unknown kind",
            kind: "ck.unknown.operation",
            payload: json!({"body": "bad"}),
            valid: false,
        },
        OperationVector {
            name: "reaction missing key",
            kind: cokret_sdk::events::kinds::REACTION_ADD,
            payload: json!({"event_id": "ck:event:01904100-0000-7000-8000-79a90338768b", "actor": "did:web:alice.example"}),
            valid: false,
        },
    ];

    for (index, vector) in vectors.into_iter().enumerate() {
        let operation = operation(index, vector.kind, vector.payload);
        let result = validate_operation_semantics(&state, &[operation]);
        assert_eq!(
            result.is_ok(),
            vector.valid,
            "operation conformance vector failed: {} ({:?})",
            vector.name,
            result.err()
        );
    }
}

// --- SEC-09: PSI / contact-discovery timing side-channel defenses ---

#[test]
fn psi_bucket_timestamp_floors_to_bucket_boundary() {
    use crate::state::{AppState, PSI_HIT_BUCKET_SECS};
    // A timestamp mid-bucket floors down to the bucket start; two times in
    // the same bucket map to the same value (hides intra-bucket flip time).
    // Align `base` to a bucket boundary so mid/late share one bucket.
    let base_secs = 1_900_000_000 - 1_900_000_000_i64.rem_euclid(PSI_HIT_BUCKET_SECS);
    let base = chrono::DateTime::<chrono::Utc>::from_timestamp(base_secs, 0).unwrap();
    let mid = base + chrono::Duration::seconds(PSI_HIT_BUCKET_SECS / 2);
    let late = base + chrono::Duration::seconds(PSI_HIT_BUCKET_SECS - 1);
    let bucketed_mid = AppState::psi_bucket_timestamp(mid);
    let bucketed_late = AppState::psi_bucket_timestamp(late);
    assert_eq!(bucketed_mid, bucketed_late, "same bucket → same exposed ts");
    assert_eq!(
        bucketed_mid.timestamp() % PSI_HIT_BUCKET_SECS,
        0,
        "bucketed ts sits on a bucket boundary"
    );
    // Crossing into the next bucket changes the exposed value.
    let next = base + chrono::Duration::seconds(PSI_HIT_BUCKET_SECS);
    assert_ne!(AppState::psi_bucket_timestamp(next), bucketed_mid);
}

#[test]
fn psi_probe_rate_limits_high_frequency_pair() {
    use crate::state::PSI_PROBE_MAX_PER_WINDOW;
    let state = test_state();
    let requester = "did:web:probe.example";
    let holder = "did:web:holder.example";
    // Probes up to the window cap are allowed.
    for _ in 0..PSI_PROBE_MAX_PER_WINDOW {
        let outcome = state.record_psi_probe(requester, holder);
        assert!(!outcome.rate_limited, "within-window probe must pass");
    }
    // The next probe over the cap is rate-limited with a backoff.
    let over = state.record_psi_probe(requester, holder);
    assert!(
        over.rate_limited,
        "probe over window cap must be rate-limited"
    );
    assert!(
        over.retry_after_ms > 0,
        "rate-limited probe must surface backoff"
    );
    // A different (requester, holder) pair is tracked independently.
    let other = state.record_psi_probe("did:web:other.example", holder);
    assert!(!other.rate_limited, "distinct pair has its own window");
}

#[test]
fn key_backup_download_quota_limits_after_daily_cap() {
    // Spec key-management.md §7.8 — per-principal rolling-24h quota on
    // full-ciphertext key-backup downloads.
    let state = test_state();
    let principal = "did:web:alice.example";
    let limit = 4;
    // Downloads up to the cap are allowed.
    for n in 1..=limit {
        let outcome = state.record_key_backup_download(principal, limit);
        assert!(!outcome.rate_limited, "download {n} within quota must pass");
        assert_eq!(outcome.count, n);
    }
    // The next download over the cap is withheld with a backoff hint.
    let over = state.record_key_backup_download(principal, limit);
    assert!(
        over.rate_limited,
        "download over the daily cap must be limited"
    );
    assert!(
        over.retry_after_ms > 0,
        "limited download must surface backoff"
    );
    // A different principal is tracked independently.
    let other = state.record_key_backup_download("did:web:bob.example", limit);
    assert!(!other.rate_limited, "distinct principal has its own window");
}
