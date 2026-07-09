use arkret_sdk::{Operation, OperationId};
use serde_json::{Value, json};
use soland_data::Db;

use super::*;
use crate::config::{AppConfig, IceServersConfig, LiveKitConfig, ObjectStorageConfig};
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
            development_mode: true,
            // Tests use fixed-time HLC fixtures (`0189c4d2af00...`) which
            // are years in the past relative to wall-clock; disable
            // replay-window enforcement so they pass.
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            seed_demo_data: true,
            ..AppConfig::test_default()
        },
        Db { pool: None },
    )
}

fn operation(index: usize, kind: &str, payload: Value) -> Operation {
    // Build a deterministic UUIDv7 from the index (last 12 hex pad as hex of the index).
    let payload_part = format!("{:012x}", index);
    let op_id = format!("ak:operation:01904100-0000-7000-8000-{payload_part}");
    let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001".to_owned();
    Operation::create(
        OperationId::new(op_id).unwrap(),
        arkret_sdk::RealmId::new(realm_id).unwrap(),
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
            kind: arkret_sdk::events::kinds::MESSAGE_CREATE,
            payload: json!({
                "message_id": "ak:message:01904100-0000-7000-8000-79a90338768b",
                "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
                "track_name": "discussion",
                "sender": "did:web:alice.example",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
            valid: true,
        },
        OperationVector {
            name: "message revise",
            kind: arkret_sdk::events::kinds::MESSAGE_REVISE,
            payload: json!({"target_ref": "ak:event:01904100-0000-7000-8000-79a90338768b", "content": {"kind": "ak.content.text", "body": "edited"}}),
            valid: true,
        },
        OperationVector {
            name: "message redact",
            kind: arkret_sdk::events::kinds::MESSAGE_REDACT,
            payload: json!({"target_event_id": "ak:event:01904100-0000-7000-8000-79a90338768b"}),
            valid: true,
        },
        OperationVector {
            name: "generic redaction",
            kind: arkret_sdk::events::kinds::REDACTION,
            // ck.redaction validates its payload against message_redact_payload
            // (anyOf message_id | target_ref | event_id | target_event_id, with
            // additionalProperties=false). The target pointer `redacts` is an
            // event-ENVELOPE field (event-envelope.schema.json), not part of the
            // operation payload, so the payload carries the target via event_id.
            payload: json!({"event_id": "ak:event:01904100-0000-7000-8000-79a90338768b"}),
            valid: true,
        },
        OperationVector {
            name: "reaction add",
            kind: arkret_sdk::events::kinds::REACTION_ADD,
            // reaction_payload: required {target_ref, key}, additionalProperties=false.
            payload: json!({"target_ref": "ak:event:01904100-0000-7000-8000-79a90338768b", "key": "+1"}),
            valid: true,
        },
        OperationVector {
            name: "reaction remove",
            kind: arkret_sdk::events::kinds::REACTION_REMOVE,
            // reaction_payload: same schema as add (remove tombstones the (actor,target_ref,key)
            // add).
            payload: json!({"target_ref": "ak:event:01904100-0000-7000-8000-79a90338768b", "key": "+1"}),
            valid: true,
        },
        OperationVector {
            name: "relation create",
            kind: arkret_sdk::events::kinds::RELATION_CREATE,
            // relation_create_payload: anyOf {relation} | {kind, from_ref, to_ref};
            // additionalProperties=false.
            payload: json!({"kind": "blocks", "from_ref": "ak:strand:01904100-0000-7000-8000-ca33616973bb", "to_ref": "ak:morph:01904100-0000-7000-8000-7191ddd787e5"}),
            valid: true,
        },
        OperationVector {
            name: "relation update",
            kind: arkret_sdk::events::kinds::RELATION_UPDATE,
            // relation_update_payload: anyOf {relation_id, patch} | {target_ref, patch} |
            // {relation_id, status}. patch is a ck.patch.v1 map (path -> patch_value);
            // a plain value is shorthand for {$op:set,value}.
            payload: json!({"relation_id": "ak:relation:01904100-0000-7000-8000-71604d58ec0b", "patch": {"weight": 1}}),
            valid: true,
        },
        OperationVector {
            name: "relation delete",
            kind: arkret_sdk::events::kinds::RELATION_TOMBSTONE,
            // relation.delete resolves to object_lifecycle_payload: required {target_ref},
            // additionalProperties=false.
            payload: json!({"target_ref": "ak:relation:01904100-0000-7000-8000-71604d58ec0b"}),
            valid: true,
        },
        OperationVector {
            name: "member state join",
            kind: arkret_sdk::events::kinds::MEMBER_STATE,
            // membership_payload: membership=join additionally requires realm_id, actor_id,
            // delivery_status; delivery_status=routable would further require
            // delivery_binding, so use unroutable to stay minimal.
            payload: json!({"realm_id": "ak:realm:01904100-0000-7000-8000-000000000001", "actor_id": "did:web:alice.example", "membership": "join", "delivery_status": "unroutable"}),
            valid: true,
        },
        OperationVector {
            name: "member state leave",
            kind: arkret_sdk::events::kinds::MEMBER_STATE,
            payload: json!({"actor_id": "did:web:alice.example", "membership": "leave"}),
            valid: true,
        },
        OperationVector {
            name: "member state ban",
            kind: arkret_sdk::events::kinds::MEMBER_STATE,
            payload: json!({"actor_id": "did:web:bob.example", "membership": "ban"}),
            valid: true,
        },
        OperationVector {
            name: "member state knock",
            kind: arkret_sdk::events::kinds::MEMBER_STATE,
            payload: json!({"actor_id": "did:web:bob.example", "membership": "knock"}),
            valid: true,
        },
        OperationVector {
            name: "read marker missing event_id",
            kind: arkret_sdk::events::kinds::READ_CURSOR_ADVANCE,
            payload: json!({
                "actor_id": "did:web:alice.example",
                "read_scope": {"kind": "realm"},
                "position": {"hlc": "019041000000-0000-00000001"}
            }),
            valid: false,
        },
        OperationVector {
            name: "read marker valid",
            kind: arkret_sdk::events::kinds::READ_CURSOR_ADVANCE,
            payload: json!({
                "actor_id": "did:web:alice.example",
                "read_scope": {"kind": "realm"},
                "position": {
                    "event_id": "ak:event:01904100-0000-7000-8000-79a90338768b",
                    "hlc": "019041000000-0000-00000001"
                }
            }),
            valid: true,
        },
        OperationVector {
            name: "space create",
            kind: arkret_sdk::events::kinds::REALM_CREATE,
            payload: json!({"object": {
                "id": "ak:realm:0196419b-0000-7000-8000-000000000000",
                "schema": "ak.schema.realm.v1",
                "title": "Launch",
                "trust_domain": "ak:trust_domain:local",
                "created_by": "did:web:alice.example",
                "schema_refs": ["ak.schema.realm.v1"],
                "default_discoverability": "invite_only",
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
            kind: arkret_sdk::events::kinds::REALM_UPDATE,
            payload: json!({
                "target_ref": "ak:realm:01904100-0000-7000-8000-000000000001",
                "patch": {
                    "title": "Launch 2"
                }
            }),
            valid: true,
        },
        OperationVector {
            name: "space destroy",
            kind: arkret_sdk::events::kinds::REALM_DESTROY,
            // realm_destroy_payload: required {reason}, additionalProperties=false.
            payload: json!({"reason": "project_completed"}),
            valid: true,
        },
        OperationVector {
            name: "space container archive",
            kind: arkret_sdk::events::kinds::SPACE_ARCHIVE,
            payload: json!({"space_id": "ak:space:01904100-0000-7000-8000-1fb50799ad42"}),
            valid: true,
        },
        OperationVector {
            name: "space container restore",
            kind: arkret_sdk::events::kinds::SPACE_RESTORE,
            payload: json!({"space_id": "ak:space:01904100-0000-7000-8000-1fb50799ad42"}),
            valid: true,
        },
        OperationVector {
            name: "space container tombstone",
            kind: arkret_sdk::events::kinds::SPACE_TOMBSTONE,
            payload: json!({"space_id": "ak:space:01904100-0000-7000-8000-1fb50799ad42"}),
            valid: true,
        },
        OperationVector {
            name: "space container restore missing space_id",
            kind: arkret_sdk::events::kinds::SPACE_RESTORE,
            payload: json!({"reason": "release_reopened"}),
            valid: false,
        },
        // Strand / Morph lifecycle conformance vectors.
        OperationVector {
            name: "strand create",
            kind: arkret_sdk::events::kinds::STRAND_CREATE,
            // strand_create_payload wraps the full Strand object (strand.schema.json):
            // required {id, schema, realm_id, tracks, created_by, created_at}; title lives in
            // metadata.
            payload: json!({"object": {
                "id": "ak:strand:01904100-0000-7000-8000-ca33616973bb",
                "schema": "ak.schema.strand.v1",
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
                "tracks": {"discussion": {}},
                "created_by": "did:web:alice.example",
                "created_at": "2026-05-20T00:00:00Z",
                "metadata": {"title": "Launch"}
            }}),
            valid: true,
        },
        OperationVector {
            name: "strand update",
            kind: arkret_sdk::events::kinds::STRAND_UPDATE,
            payload: json!({"target_ref": "ak:strand:01904100-0000-7000-8000-ca33616973bb", "patch": {"metadata.title": { "$op": "set", "value": "Launch v2" }}}),
            valid: true,
        },
        OperationVector {
            name: "strand archive",
            kind: arkret_sdk::events::kinds::STRAND_ARCHIVE,
            payload: json!({"target_ref": "ak:strand:01904100-0000-7000-8000-ca33616973bb"}),
            valid: true,
        },
        OperationVector {
            name: "strand restore",
            kind: arkret_sdk::events::kinds::STRAND_RESTORE,
            payload: json!({"target_ref": "ak:strand:01904100-0000-7000-8000-ca33616973bb"}),
            valid: true,
        },
        OperationVector {
            name: "strand archive missing target_ref",
            kind: arkret_sdk::events::kinds::STRAND_ARCHIVE,
            payload: json!({"reason": "stale_room"}),
            valid: false,
        },
        // Strand position event vectors.
        OperationVector {
            name: "strand move",
            kind: arkret_sdk::events::kinds::STRAND_MOVE,
            payload: json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-ca33616973bb",
                "board_space_id": "ak:space:01904100-0000-7000-8000-c10dc0000001",
                "target_space_id": "ak:space:01904100-0000-7000-8000-c10dc0000002",
                "rank": "a1",
            }),
            valid: true,
        },
        OperationVector {
            name: "strand reorder",
            kind: arkret_sdk::events::kinds::STRAND_REORDER,
            payload: json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-ca33616973bb",
                "board_space_id": "ak:space:01904100-0000-7000-8000-c10dc0000001",
                "space_id": "ak:space:01904100-0000-7000-8000-c10dc0000002",
                "rank": "a1",
            }),
            valid: true,
        },
        OperationVector {
            name: "strand move missing board_space_id",
            kind: arkret_sdk::events::kinds::STRAND_MOVE,
            payload: json!({"strand_id": "ak:strand:01904100-0000-7000-8000-ca33616973bb"}),
            valid: false,
        },
        OperationVector {
            name: "strand reorder missing strand_id",
            kind: arkret_sdk::events::kinds::STRAND_REORDER,
            payload: json!({"board_space_id": "ak:space:01904100-0000-7000-8000-c10dc0000001", "space_id": "ak:space:01904100-0000-7000-8000-c10dc0000002", "rank": "a1"}),
            valid: false,
        },
        OperationVector {
            name: "morph create",
            kind: arkret_sdk::events::kinds::MORPH_CREATE,
            // morph_create_payload wraps the full Morph object (morph.schema.json):
            // required {id, schema, realm_id, schema_refs, morph_type, stage, created_by,
            // created_at}.
            payload: json!({"object": {
                "id": "ak:morph:01904100-0000-7000-8000-7191ddd787e5",
                "schema": "ak.schema.morph.v1",
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
                "schema_refs": ["ak.schema.morph.v1"],
                "morph_type": "task",
                "stage": "draft",
                "created_by": "did:web:alice.example",
                "created_at": "2026-05-20T00:00:00Z",
                "metadata": {"title": "Backfill"}
            }}),
            valid: true,
        },
        OperationVector {
            name: "morph update",
            kind: arkret_sdk::events::kinds::MORPH_UPDATE,
            payload: json!({"target_ref": "ak:morph:01904100-0000-7000-8000-7191ddd787e5", "patch": {"metadata.title": "Backfill v2"}}),
            valid: true,
        },
        OperationVector {
            name: "morph archive",
            kind: arkret_sdk::events::kinds::MORPH_ARCHIVE,
            payload: json!({"target_ref": "ak:morph:01904100-0000-7000-8000-7191ddd787e5"}),
            valid: true,
        },
        OperationVector {
            name: "morph restore",
            kind: arkret_sdk::events::kinds::MORPH_RESTORE,
            payload: json!({"target_ref": "ak:morph:01904100-0000-7000-8000-7191ddd787e5"}),
            valid: true,
        },
        OperationVector {
            name: "morph restore missing target_ref",
            kind: arkret_sdk::events::kinds::MORPH_RESTORE,
            payload: json!({"reason": "reopen"}),
            valid: false,
        },
        // Applet protocol family conformance vectors.
        OperationVector {
            name: "applet registration",
            kind: arkret_sdk::events::kinds::APPLET_REGISTRATION,
            // applet_registration_payload is now a CLOSED class (additionalProperties=false)
            // with 14 required fields; the generic fallback no longer applies since the
            // exact def exists in the current spec.
            payload: json!({
                "applet_id": "ak:applet:01904100-0000-7000-8000-aa55aa55aa55",
                "service_did": "did:web:applet.example",
                "controller_did": "did:web:applet.example",
                "base_url": "https://applet.example/runtime",
                "bot_actor_id": "did:web:applet.bot.example",
                "protocols": ["http_custom"],
                "namespaces": {"realms": ["*"]},
                "receive_events": true,
                "receive_ephemeral": false,
                "rate_limited": true,
                "requested_scopes": ["read"],
                "registration_epoch": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "webhook_auth": {"key_ref": "did:web:applet.example"},
                "proof": {"signature": "c2ln"},
                "created_at": "2026-05-20T00:00:00Z",
            }),
            valid: true,
        },
        OperationVector {
            name: "applet registration missing namespace",
            kind: arkret_sdk::events::kinds::APPLET_REGISTRATION,
            // Same closed class, but omits the required `namespaces` field.
            payload: json!({
                "applet_id": "ak:applet:01904100-0000-7000-8000-aa55aa55aa55",
                "service_did": "did:web:applet.example",
                "controller_did": "did:web:applet.example",
                "base_url": "https://applet.example/runtime",
                "bot_actor_id": "did:web:applet.bot.example",
                "protocols": ["http_custom"],
                "receive_events": true,
                "receive_ephemeral": false,
                "rate_limited": true,
                "requested_scopes": ["read"],
                "registration_epoch": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "webhook_auth": {"key_ref": "did:web:applet.example"},
                "proof": {"signature": "c2ln"},
                "created_at": "2026-05-20T00:00:00Z",
            }),
            valid: false,
        },
        OperationVector {
            name: "applet discovery",
            kind: arkret_sdk::events::kinds::APPLET_DISCOVERY,
            payload: json!({
                "service_did": "did:web:applet.example",
                "manifest": {"version": 1},
            }),
            valid: true,
        },
        OperationVector {
            name: "applet session start",
            kind: arkret_sdk::events::kinds::APPLET_INTEROP_SESSION_START,
            payload: json!({
                "applet_id": "ak:applet:01904100-0000-7000-8000-aa55aa55aa55",
                "session_id": "ak:session:01904100-0000-7000-8000-aa55aa55aa55",
                "params": {},
            }),
            valid: true,
        },
        OperationVector {
            name: "applet session status",
            kind: arkret_sdk::events::kinds::APPLET_INTEROP_SESSION_STATUS,
            // applet_interop_session_status_payload: required {applet_id, session_id,
            // runtime_status}; runtime_status enum
            // {pending,running,completed,failed,cancelled}; additionalProperties=false.
            payload: json!({
                "applet_id": "ak:applet:01904100-0000-7000-8000-aa55aa55aa55",
                "session_id": "ak:session:01904100-0000-7000-8000-aa55aa55aa55",
                "runtime_status": "running",
                "detail": {},
            }),
            valid: true,
        },
        OperationVector {
            name: "applet bridge error",
            kind: arkret_sdk::events::kinds::APPLET_BRIDGE_ERROR,
            // applet_bridge_error_payload: required {applet_id, realm_id, failed_transaction_ref,
            // error_class, error_code, retriable, visibility_scope}; additionalProperties=false.
            payload: json!({
                "applet_id": "ak:applet:01904100-0000-7000-8000-aa55aa55aa55",
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
                "failed_transaction_ref": "ak:event:01904100-0000-7000-8000-79a90338768b",
                "error_class": "external_network",
                "error_code": "bridge_unavailable",
                "retriable": true,
                "visibility_scope": "realm_admins",
                "message": "no upstream",
            }),
            valid: true,
        },
        // Agent protocol family conformance vectors.
        OperationVector {
            name: "agent endpoint",
            kind: arkret_sdk::events::kinds::AGENT_ENDPOINT,
            payload: json!({
                "agent_id": "did:web:agent.example",
                "endpoints": [{"protocol": "http_custom", "url": "https://agent.example/runtime"}],
            }),
            valid: true,
        },
        OperationVector {
            name: "agent endpoint missing endpoints",
            kind: arkret_sdk::events::kinds::AGENT_ENDPOINT,
            payload: json!({"agent_id": "did:web:agent.example"}),
            valid: false,
        },
        OperationVector {
            name: "agent session start",
            kind: arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_START,
            // agent_interop_session_start_payload: required {session_id, counterparty_agent,
            // protocol, capability_grant}; session_id is a
            // ak:agent_interop_session:<uuidv7>; additionalProperties=false.
            payload: json!({
                "session_id": "ak:agent_interop_session:01904100-0000-7000-8000-bb66bb66bb66",
                "counterparty_agent": "did:web:agent.example",
                "protocol": "http_custom",
                "capability_grant": "ak:grant:01904100-0000-7000-8000-000000000099",
            }),
            valid: true,
        },
        OperationVector {
            name: "agent session start missing capability_grant",
            kind: arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_START,
            // Omits the required capability_grant.
            payload: json!({
                "session_id": "ak:agent_interop_session:01904100-0000-7000-8000-bb66bb66bb66",
                "counterparty_agent": "did:web:agent.example",
                "protocol": "http_custom",
            }),
            valid: false,
        },
        OperationVector {
            name: "agent session status",
            kind: arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_STATUS,
            // agent_interop_session_status_payload: required {session_id, status}; status enum
            // includes "working"; additionalProperties=false (no `detail` field).
            payload: json!({
                "session_id": "ak:agent_interop_session:01904100-0000-7000-8000-bb66bb66bb66",
                "status": "working",
            }),
            valid: true,
        },
        OperationVector {
            name: "agent session result",
            kind: arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_RESULT,
            // agent_interop_session_result_payload: required {session_id, status} + anyOf
            // {result_objects | artifacts | reason_code}; additionalProperties=false.
            payload: json!({
                "session_id": "ak:agent_interop_session:01904100-0000-7000-8000-bb66bb66bb66",
                "status": "completed",
                "result_objects": [{"summary": "ok"}],
            }),
            valid: true,
        },
        OperationVector {
            name: "agent session result missing result content",
            kind: arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_RESULT,
            // Satisfies the top-level required fields but none of the anyOf
            // {result_objects | artifacts | reason_code} completion carriers, so it is invalid.
            payload: json!({
                "session_id": "ak:agent_interop_session:01904100-0000-7000-8000-bb66bb66bb66",
                "status": "completed",
            }),
            valid: false,
        },
        OperationVector {
            name: "unknown kind",
            kind: "ak.unknown.operation",
            payload: json!({"body": "bad"}),
            valid: false,
        },
        OperationVector {
            name: "reaction missing key",
            kind: arkret_sdk::events::kinds::REACTION_ADD,
            // reaction_payload requires {target_ref, key}; this omits the required `key`.
            payload: json!({"target_ref": "ak:event:01904100-0000-7000-8000-79a90338768b"}),
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
