//! Operation envelope + payload validators.
//!
//! Surfaces:
//! - `OperationPayloadSchema` / `PayloadRequirement` — per-kind required / optional / enum field
//!   schemas.
//! - `validate_operation_semantics` / `validate_operation_schema` — the entrypoint validators
//!   called from `event_log::submit_event`, `projection::project_accepted_operations`, and the
//!   federation ingest path.
//! - `validate_operation_policy` — high-level policy gate (plaintext-Space gating + B-09 redact
//!   constraints).
//! - `validate_canonical_json_value` (+ `_inner`) — the canonical-JSON shape gate that operation
//!   payloads MUST pass.
//! - `validate_content_blocks` / `validate_mentions` / `validate_content_block` — message body
//!   shape.
//! - `validate_encrypted_payload_envelope` — `ak.profile.encrypted_envelope.v1` envelope shape (MLS
//!   sender / scheme / version / `key_ref`).
//! - canonical RFC 3339 UTC-Z timestamp shape for `*_at` fields accepts the SDK's ordinary
//!   whole-second profile and the Event-bound fixed-millisecond profile; kind-specific validators
//!   enforce narrower field requirements.
//! - `canonical_json_digest` — sha256 over canonical-JSON bytes.
//!
//! Spec items still pending here are tracked in `_todos.md` (notably
//! Stream-A19 for B-09 redact `actor_seq` preservation, B-22 for
//! encrypted-attachment `key_ref` shape, and the operation-schema gaps
//! around the 100+ event kinds the reducer doesn't cover yet).
//!
//! The implementation is split across submodules to keep each file small:
//! - `semantics` — operation-kind schema dispatch + the `validate_operation_semantics` entrypoint.
//! - `payload_validators` — the per-kind typed payload validators.
//! - `policy` / `policy_extra` — the `validate_operation_policy` gate and its helpers.
//! - `content` — canonical-JSON, content-block, mention, and device-message shape checks.
//! - `payload_schemas` — the static `PayloadRequirement` tables.

use arkret_event_draft::Operation;
use serde_json::Value;
use soland_application::operation_semantics as kinds;

use super::{is_valid_hash_digest, validate_did};
use crate::routing::interop::participant_binding;
use crate::state::AppState;

const ACTIVE_SERIES_ADMISSION_LOCK_SHARDS: usize = 256;

/// Serialize every active-series compare-and-swap lane across local Event,
/// generic Operation, and federation ingestion. Keeping this lock here avoids
/// each ingress surface accidentally using a different mutex pool.
pub(crate) async fn lock_active_series_operations(
    operations: &[Operation],
) -> Vec<tokio::sync::OwnedMutexGuard<()>> {
    use std::collections::BTreeSet;
    use std::hash::{Hash as _, Hasher as _};
    use std::sync::{Arc, OnceLock};

    static LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| {
        (0..ACTIVE_SERIES_ADMISSION_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut shards = BTreeSet::new();
    for operation in operations {
        if kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::events::EventKind::KEY_BACKUP_ACTIVE_SERIES)
        {
            continue;
        }
        let payload = projection_context_stripped_payload(&operation.payload);
        let actor = payload
            .get("actor_id")
            .and_then(Value::as_str)
            .unwrap_or("invalid");
        let class = payload
            .get("backup_class")
            .and_then(Value::as_str)
            .unwrap_or("invalid");
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        format!("{actor}\0{class}").hash(&mut hasher);
        shards.insert((hasher.finish() as usize) % ACTIVE_SERIES_ADMISSION_LOCK_SHARDS);
    }
    let mut guards = Vec::with_capacity(shards.len());
    for shard in shards {
        guards.push(locks[shard].clone().lock_owned().await);
    }
    guards
}

const CROSS_SIGNING_RESET_MAX_CLOCK_SKEW_SECONDS: i64 = 300;
const CONTENT_ENCRYPTION_FLOOR_VIOLATION: &str = "content_encryption_floor_violation";
const REALM_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "realm_encryption_profile_create_locked";
const CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "circle_encryption_profile_create_locked";
const AUDIENCE_MENTION_ALLOWED_AUDIENCES: &[&str] = &[
    "effective_scope_members",
    "strand_participants",
    "strand_watchers",
    "strand_engaged",
    "assigned_actors",
];

mod payload_schemas;
pub(crate) use payload_schemas::*;
mod policy;
pub(crate) use policy::*;
mod policy_extra;
pub(crate) use policy_extra::*;
mod content;
pub(crate) use content::*;
mod semantics;
pub(crate) use semantics::*;
mod payload_validators;
pub(crate) use payload_validators::*;

#[cfg(test)]
mod mention_tests;
#[cfg(test)]
mod participant_binding_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod schema_tests;

#[cfg(test)]
#[path = "operations_minimal_metadata_aad_tests.rs"]
mod minimal_metadata_aad_tests;
#[cfg(test)]
#[path = "operations_strand_tracks_update_tests.rs"]
mod strand_tracks_update_tests;
#[cfg(test)]
#[path = "operations_wire_payload_tests.rs"]
mod wire_payload_tests;
