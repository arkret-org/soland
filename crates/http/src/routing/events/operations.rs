//! Operation envelope + payload validators.
//!
//! Surfaces:
//! - `validate_operation_semantics` — the registry-backed entrypoint validator called from
//!   `event_log::submit_event`, `projection::project_accepted_operations`, and the federation
//!   ingest path.
//! - `validate_operation_policy` — high-level policy gate (plaintext-Space gating + B-09 redact
//!   constraints).
//! - `validate_canonical_json_value` (+ `_inner`) — the canonical-JSON shape gate that operation
//!   payloads MUST pass.
//! - `validate_content_blocks` / `validate_mentions` / `validate_content_block` — message body
//!   shape. Mention admission is canonical-only: the SDK mention models own the `mention` /
//!   `audience_mention` AST node types.
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

use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;
use soland_services::operation_semantics as kinds;

use crate::routing::interop::participant_binding;
use crate::state::AppState;

const ACTIVE_SERIES_ADMISSION_LOCK_SHARDS: usize = 256;

/// Serialize every compare-and-swap lane across local Event, generic
/// Operation, and federation ingestion. Keeping this lock here avoids each
/// ingress surface accidentally using a different mutex pool.
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
            == Some(arkret_wire::EventKind::KeyBackupActiveSeries)
        {
            let payload = &operation.payload;
            let actor = payload
                .get("actor_id")
                .and_then(Value::as_str)
                .unwrap_or("invalid");
            let class = payload
                .get("backup_kind")
                .and_then(Value::as_str)
                .unwrap_or("invalid");
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            format!("active-series\0{actor}\0{class}").hash(&mut hasher);
            shards.insert((hasher.finish() as usize) % ACTIVE_SERIES_ADMISSION_LOCK_SHARDS);
        }
        for cell in operation
            .context
            .preconditions
            .iter()
            .map(|precondition| precondition.cell.as_str())
        {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            format!("cell-cas\0{}\0{cell}", operation.realm_id).hash(&mut hasher);
            shards.insert((hasher.finish() as usize) % ACTIVE_SERIES_ADMISSION_LOCK_SHARDS);
        }
    }
    let mut guards = Vec::with_capacity(shards.len());
    for shard in shards {
        guards.push(locks[shard].clone().lock_owned().await);
    }
    guards
}

const CONTENT_ENCRYPTION_FLOOR_VIOLATION: &str = "content_encryption_floor_violation";
const CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "circle_encryption_profile_create_locked";

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
#[path = "operations_wire_payload_tests.rs"]
mod wire_payload_tests;
