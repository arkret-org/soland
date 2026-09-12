// ════════════════════════════════════════════════════════════════════════
// events.submit discriminated request + admission gates
// (spec B1.6 / T02 / T07 / T08 / T09 / T12 / T23).
// ════════════════════════════════════════════════════════════════════════
pub use arkret_models_collaboration::event_sync::EventsSubmitRequestBody;

use super::*;

pub(super) fn validate_federation_service_binding(
    binding: &FederationServiceBindingRef,
) -> Result<(), (&'static str, String)> {
    let mut seen = std::collections::BTreeSet::new();
    for entry in &binding.membership_frontier {
        if !seen.insert(entry.as_str()) {
            return Err((
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                format!(
                    "membership_frontier contains duplicate entry {:?}",
                    entry.as_str()
                ),
            ));
        }
    }
    if binding.destination_kind.trim().is_empty() {
        return Err((
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            "service_binding_ref.destination_kind MUST be a non-empty string".to_owned(),
        ));
    }
    Ok(())
}

/// Reject receipt objects at the `ak.self.events.command.submit.v1` entrypoint.
///
/// Returns the canonical [`ErrorCode`] + human reason when the kind MUST be
/// rejected; returns `None` when the kind is fine to forward to the
/// existing durable-event validator pipeline.
pub fn events_submit_pre_admit_check(kind: &str) -> Option<(ErrorCode, &'static str)> {
    if arkret_wire::events::is_receipt_object_only(kind) {
        return Some((
            ErrorCode::SchemaViolation,
            "ak.event_batch_receipt is a receipt object only; \
             never accepted as Event.kind",
        ));
    }
    None
}

/// Reject any non-audit-class write on a Realm whose lifecycle state is
/// terminal (`ak.realm.tombstone` or `ak.realm.destroy` applied). Spec T07.
///
/// Returns `Some((ErrorCode::FailedPrecondition, reason))` when the write
/// MUST be rejected; `None` otherwise.
pub fn terminal_realm_check(
    realm_in_terminal_state: bool,
    kind: &str,
) -> Option<(ErrorCode, &'static str)> {
    if realm_in_terminal_state
        && !kind
            .parse::<arkret_wire::EventKind>()
            .is_ok_and(|kind| arkret_wire::events::kinds::is_audit_kind(&kind))
    {
        return Some((
            ErrorCode::FailedPrecondition,
            "Realm has reached ak.realm.tombstone or ak.realm.destroy \
             terminal state; only audit-class events are accepted",
        ));
    }
    None
}

/// Reject ordinary writes on a Realm with the reversible `ak.realm.freeze`
/// facet set. Lifecycle/admin escape hatches remain admissible so an
/// authorized actor can unfreeze, tombstone, or destroy the Realm.
pub fn frozen_realm_check(realm_frozen: bool, kind: &str, payload: &Value) -> Option<&'static str> {
    if realm_frozen
        && !kind
            .parse::<arkret_wire::EventKind>()
            .is_ok_and(|kind| arkret_wire::events::kinds::realm_write_gate_exempt(&kind, payload))
    {
        return Some("Realm is archived or frozen; ordinary writes are not accepted");
    }
    None
}

pub(super) fn policy_bundle_value_from_state_payload(payload: &Value) -> &Value {
    payload.get("value").unwrap_or(payload)
}

/// Validate a `ak.realm.policy_bundle` payload. Spec T09 + T12.
///
/// Checks (in order):
/// 1. `relaxed_window_max_ms <= 300_000` (T09 hard ceiling)
/// 2. advisory MLS pause is not active with an Audit Applet Binding (T09 mutex)
/// 3. When `media_service_decrypts=true`, the service is explicitly authorized for the
///    `media_plaintext` data class (T12). The MLS security-frontier projector binds this accepted
///    policy state into the next Commit.
pub fn realm_policy_bundle_check(
    payload: &Value,
    audit_binding_active: bool,
    media_plaintext_service_present: bool,
) -> Result<(), (ErrorCode, String)> {
    if let Some(join_policy) = payload.get("join_policy") {
        soland_services::operation_semantics::validate_join_policy_payload(join_policy).map_err(
            |reason| {
                (
                    ErrorCode::SchemaViolation,
                    format!("ak.realm.policy_bundle payload path join_policy invalid: {reason}"),
                )
            },
        )?;
    }

    // (1) T09 — relaxed_window_max_ms ceiling.
    if let Some(window) = payload.get("relaxed_window_max_ms").and_then(Value::as_u64) {
        let window_u32 = u32::try_from(window).unwrap_or(u32::MAX);
        if arkret_models_collaboration::governance::audit::validate_relaxed_window_ms(window_u32)
            .is_err()
        {
            return Err((
                ErrorCode::FailedPrecondition,
                format!(
                    "relaxed_window_max_ms={window} exceeds absolute \
                     hard ceiling of {}ms",
                    arkret_models_collaboration::governance::audit::ABSOLUTE_HARD_CEILING_MS
                ),
            ));
        }
    }

    // (2) T09 — policy-derived relaxed mode and active audit binding are mutually exclusive.
    let relaxed_active = payload.get("mls_send_pause").and_then(Value::as_str) == Some("advisory");
    if relaxed_active && audit_binding_active {
        return Err((
            ErrorCode::FailedPrecondition,
            "mls_send_pause=advisory is mutually exclusive with an active Audit Applet Binding"
                .to_owned(),
        ));
    }

    // (3) T12 — media_service_decrypts triple binding.
    if payload
        .get("media_service_decrypts")
        .and_then(Value::as_bool)
        == Some(true)
        && !media_plaintext_service_present
    {
        return Err((
            ErrorCode::FailedPrecondition,
            "media_service_decrypts=true requires the SFU/MCU service DID \
             to be listed in plaintext_visible_services[] with \
             data_classes[] containing media_plaintext"
                .to_owned(),
        ));
    }
    Ok(())
}
