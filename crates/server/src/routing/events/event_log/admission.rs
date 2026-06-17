use super::*;

// ════════════════════════════════════════════════════════════════════════
// events.submit discriminated request + admission gates
// (spec B1.6 / T02 / T07 / T08 / T09 / T12 / T23).
// ════════════════════════════════════════════════════════════════════════

/// Spec B1.6 — discriminated `/_cokret/self/events` POST body. Single is the
/// pre-existing canonical Event Envelope; batch and federation are the new
/// typed shapes.
///
/// Wire-breaking: producers MUST use spec `events[]`; producers that
/// include the `service_binding_ref` are routed to [`Self::Federation`].
/// Client-account writes omit `service_binding_ref`; federation writes are
/// gated by federation authentication.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SolandEventsSubmitRequestBody {
    /// Federation form — `service_binding_ref` is REQUIRED and all 6
    /// fields validated.
    Federation(EventsSubmitFederationRequestBody),
    /// Batch form — multiple envelopes, optional `idempotency_key`.
    Batch(cokret_sdk::EventsSubmitBatchRequestBody),
    /// Single Event Envelope (dominant shape).
    Single(Value),
}

impl SolandEventsSubmitRequestBody {
    /// Spec B1.6 — validate the `service_binding_ref` carried on a
    /// federation submit. All 6 fields MUST be populated and well-shaped
    /// per SDK typed validators (already enforced by deserialisation); we
    /// additionally reject `membership_frontier` and
    /// `delivery_binding_frontier` if they are non-empty arrays containing
    /// duplicates.
    pub fn validate_federation_binding(
        req: &EventsSubmitFederationRequestBody,
    ) -> Result<(), (&'static str, String)> {
        let binding = &req.service_binding_ref;
        for (name, frontier) in [
            ("membership_frontier", &binding.membership_frontier),
            (
                "delivery_binding_frontier",
                &binding.delivery_binding_frontier,
            ),
        ] {
            let mut seen = std::collections::BTreeSet::new();
            for entry in frontier {
                if !seen.insert(entry.as_str()) {
                    return Err((
                        cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION,
                        format!("{name} contains duplicate entry {:?}", entry.as_str()),
                    ));
                }
            }
        }
        if binding.destination_service_type.trim().is_empty() {
            return Err((
                cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION,
                "service_binding_ref.destination_service_type MUST be a non-empty string"
                    .to_owned(),
            ));
        }
        let expected_reducer_digest = cokret_sdk::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST;
        let actual_reducer_digest = binding.reducer_profile_digest.to_string();
        if actual_reducer_digest != expected_reducer_digest {
            return Err((
                cokret_sdk::ERROR_CODE_REDUCER_PROFILE_MISMATCH,
                format!(
                    "service_binding_ref.reducer_profile_digest mismatch: expected {expected_reducer_digest}, got {actual_reducer_digest}"
                ),
            ));
        }
        Ok(())
    }
}

/// Reject any event kind that is ephemeral or receipt-object-only at the
/// `ck.self.events.command.submit` entrypoint. Spec T02 + T23.
///
/// Returns the canonical [`ErrorCode`] + human reason when the kind MUST be
/// rejected; returns `None` when the kind is fine to forward to the
/// existing durable-event validator pipeline.
pub fn events_submit_pre_admit_check(kind: &str) -> Option<(ErrorCode, &'static str)> {
    if cokret_sdk::events::is_ephemeral_kind(kind) {
        return Some((
            ErrorCode::SchemaViolation,
            "ephemeral kind MUST be carried via ck.schema.ephemeral_envelope.v1 \
             (broadcast forms) or ck.schema.device_message.v1 \
             (ck.key.verification.* to-device); not durable ck.self.events.command.submit",
        ));
    }
    if cokret_sdk::events::is_receipt_object_only(kind) {
        return Some((
            ErrorCode::SchemaViolation,
            "ck.event_batch_receipt is a receipt object only; \
             never accepted as Event.kind",
        ));
    }
    if kind == crate::kinds::CK_MORPH_SCHEMA_MIGRATE {
        return Some((
            ErrorCode::SchemaViolation,
            "ck.morph.schema_migrate is not admitted until its reducer projection is implemented",
        ));
    }
    None
}

/// Reject any non-audit-class write on a Realm whose lifecycle state is
/// terminal (`ck.realm.tombstone` or `ck.realm.destroy` applied). Spec T07.
///
/// Returns `Some((ErrorCode::RealmTerminalState, reason))` when the write
/// MUST be rejected; `None` otherwise.
pub fn terminal_realm_check(
    realm_in_terminal_state: bool,
    kind: &str,
) -> Option<(ErrorCode, &'static str)> {
    if realm_in_terminal_state && !crate::kinds::is_audit_kind(kind) {
        return Some((
            ErrorCode::RealmTerminalState,
            "Realm has reached ck.realm.tombstone or ck.realm.destroy \
             terminal state; only audit-class events are accepted",
        ));
    }
    None
}

pub(super) fn policy_components_value_from_state_payload(payload: &Value) -> &Value {
    payload.get("value").unwrap_or(payload)
}

/// `ck.cross_signing.reset` payload trust-domain & reset_event_id check.
/// Spec T08.
///
/// Verification order MUST be:
/// 1. `payload.trust_domain` equals server's configured trust_domain (else
///    `cross_domain_replay_rejected`)
/// 2. `payload.reset_event_id` equals the enclosing Event's id (else `reset_event_id_mismatch`)
/// 3. signature check (existing path; not implemented here)
pub fn cross_signing_reset_replay_check(
    payload: &Value,
    event_id: &str,
    server_trust_domain: &str,
) -> Result<(), (ErrorCode, String)> {
    let payload_td = payload
        .get("trust_domain")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                ErrorCode::SchemaViolation,
                "cross_signing.reset payload missing required `trust_domain` \
                 field (wire-breaking)"
                    .to_owned(),
            )
        })?;
    if TypedTrustDomainId::new(payload_td).is_err() {
        return Err((
            ErrorCode::SchemaViolation,
            "cross_signing.reset.trust_domain must match \
             ck:trust_domain:<scope> per spec"
                .to_owned(),
        ));
    }
    if payload_td != server_trust_domain {
        return Err((
            ErrorCode::CrossDomainReplayRejected,
            "cross_signing.reset.trust_domain does not match this \
             Principal Server's configured trust_domain"
                .to_owned(),
        ));
    }
    let payload_reset_event_id = payload
        .get("reset_event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                ErrorCode::SchemaViolation,
                "cross_signing.reset payload missing required \
                     `reset_event_id` field (wire-breaking)"
                    .to_owned(),
            )
        })?;
    if cokret_sdk::EventId::new(payload_reset_event_id).is_err() {
        return Err((
            ErrorCode::SchemaViolation,
            "cross_signing.reset.reset_event_id must be a ck:event:<uuidv7>".to_owned(),
        ));
    }
    if payload_reset_event_id != event_id {
        return Err((
            ErrorCode::ResetEventIdMismatch,
            "cross_signing.reset.reset_event_id must equal the enclosing \
             Event.event_id"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Validate a `ck.realm.policy_components` payload. Spec T09 + T12 + SEC-03.
///
/// Checks (in order):
/// 1. `relaxed_window_max_ms <= 300_000` (T09 hard ceiling)
/// 2. `ck.profile.e2ee_relaxed.v1` not active with any audit compliance profile (T09 mutex)
/// 3. When `media_service_decrypts=true`, all governance bindings are present (T12).
/// 4. SEC-03 — when `media_service_decrypts=true`, independently recompute the
///    `discussion_metadata_digest` from the §10.5.1 rule 1–3 policy cell value
///    (`media_service_decrypts` + the authorised `plaintext_visible_services`) and fail closed with
///    `mls_governance_binding_stale` when it disagrees with the digest the projected governance
///    binding covers. This is the server-side mirror of `media-service-binding.md` §8.2 rule 5 /
///    negative vector `ck.vector.webrtc.media_plaintext_downgrade.v1` case (d): the fact that media
///    is service-decryptable MUST be derivable from member-visible metadata, not asserted out of
///    band. `binding_discussion_metadata_digest` is the digest the current epoch governance binding
///    covers, as projected from the realm's MLS cell; `None` means the binding carried no digest,
///    in which case only the policy_root coverage gate (check 3) applies.
pub fn realm_policy_components_check(
    payload: &Value,
    active_profiles: &[String],
    media_plaintext_service_present: bool,
    mls_governance_binding_covers_policy_root: bool,
    binding_discussion_metadata_digest: Option<&str>,
) -> Result<(), (ErrorCode, String)> {
    if let Some(join_policy) = payload.get("join_policy") {
        crate::reducer::validate_join_policy_payload(join_policy).map_err(|reason| {
            (
                ErrorCode::SchemaViolation,
                format!("ck.realm.policy_components.join_policy invalid: {reason}"),
            )
        })?;
    }

    // (1) T09 — relaxed_window_max_ms ceiling.
    if let Some(window) = payload
        .pointer("/e2ee_relaxed/relaxed_window_max_ms")
        .and_then(Value::as_u64)
    {
        let window_u32 = u32::try_from(window).unwrap_or(u32::MAX);
        if cokret_sdk::validate_relaxed_window_ms(window_u32).is_err() {
            return Err((
                ErrorCode::RelaxedWindowExceedsCeiling,
                format!(
                    "e2ee_relaxed.relaxed_window_max_ms={window} exceeds absolute \
                     hard ceiling of {}ms",
                    cokret_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS
                ),
            ));
        }
    }

    // (2) T09 — e2ee_relaxed.v1 mutex against audit compliance.
    let relaxed_active = active_profiles
        .iter()
        .any(|p| p == "ck.profile.e2ee_relaxed.v1")
        || payload
            .pointer("/e2ee_relaxed/profile")
            .and_then(Value::as_str)
            == Some("ck.profile.e2ee_relaxed.v1");
    let compliance_active = active_profiles
        .iter()
        .any(|p| crate::kinds::AUDIT_COMPLIANCE_PROFILES.contains(&p.as_str()));
    if relaxed_active && compliance_active {
        return Err((
            ErrorCode::E2eeRelaxedDisallowedInComplianceProfile,
            "ck.profile.e2ee_relaxed.v1 is mutually exclusive with audit \
             compliance profiles (attested_audit.e2ee.v1 / \
             disclosed_audit.e2ee.v1)"
                .to_owned(),
        ));
    }

    // (3) T12 — media_service_decrypts triple binding.
    if payload
        .get("media_service_decrypts")
        .and_then(Value::as_bool)
        == Some(true)
    {
        if !media_plaintext_service_present {
            return Err((
                ErrorCode::MediaPlaintextServiceNotAuthorised,
                "media_service_decrypts=true requires the SFU/MCU service DID \
                 to be listed in plaintext_visible_services[] with \
                 purpose=media_plaintext"
                    .to_owned(),
            ));
        }
        if !mls_governance_binding_covers_policy_root {
            return Err((
                ErrorCode::MlsGovernanceBindingStale,
                "media_service_decrypts=true requires the current MLS epoch \
                 governance binding's policy_root to cover the active media \
                 plaintext policy"
                    .to_owned(),
            ));
        }
        // (4) SEC-03 — independently recompute the discussion_metadata_digest
        // from the §10.5.1 rule 1–3 policy cell value and reject when it
        // disagrees with what the governance binding covers. We only have a
        // digest to compare against when the projected binding actually carried
        // one; absent it, check (3) above is the strongest server-side gate.
        if let Some(covered_digest) = binding_discussion_metadata_digest {
            let recomputed = recompute_media_decrypt_metadata_digest(payload).ok_or((
                ErrorCode::MlsGovernanceBindingStale,
                "media_service_decrypts=true policy cell could not be canonicalised \
                 for discussion_metadata_digest recomputation"
                    .to_owned(),
            ))?;
            let covered = cokret_sdk::Hash::new(covered_digest.to_owned()).map_err(|_| {
                (
                    ErrorCode::MlsGovernanceBindingStale,
                    "governance binding discussion_metadata_digest is not a valid \
                     sha256 hash"
                        .to_owned(),
                )
            })?;
            if cokret_sdk::models::verify_media_decrypt_metadata(&covered, &recomputed).is_err() {
                return Err((
                    ErrorCode::MlsGovernanceBindingStale,
                    "media_service_decrypts=true fact recomputed from the policy \
                     cell value does not match the governance binding's \
                     discussion_metadata_digest (media-service-binding.md §8.2 rule 5)"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// SEC-03 — build a `cokret_sdk::models::MediaDecryptPolicyValue`
/// from a `ck.realm.policy_components` payload and derive its canonical
/// `discussion_metadata_digest`. Returns `None` only when the SDK's canonical
/// digest derivation fails (it never does for well-formed input), so callers
/// treat that as a fail-closed mismatch.
///
/// The recomputed value mirrors §10.5.1 rule 1 (`media_service_decrypts`) and
/// rule 2 (the `purpose=media_plaintext` service DIDs in
/// `plaintext_visible_services[]`). Service-DID extraction matches the shapes
/// [`payload_declares_media_plaintext_service`] already accepts (bare string,
/// `media_plaintext` sentinel, or `{purpose, service_did|did}` object) so the
/// digest input is consistent with the rule-2 presence gate; non-DID / sentinel
/// entries that carry no concrete DID are skipped because the SDK digest is
/// defined over concrete service DIDs.
fn recompute_media_decrypt_metadata_digest(payload: &Value) -> Option<cokret_sdk::Hash> {
    use cokret_sdk::models::{
        MediaDecryptPolicyValue, MediaPlaintextService, derive_media_decrypt_metadata_digest,
    };

    let media_service_decrypts = payload
        .get("media_service_decrypts")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut plaintext_visible_services = Vec::new();
    if let Some(services) = payload
        .pointer("/plaintext_visible_services")
        .and_then(Value::as_array)
    {
        for service in services {
            let did_str = match service {
                // A bare string entry is the service DID itself; the
                // `media_plaintext` sentinel carries no concrete DID.
                Value::String(value) if value != "media_plaintext" => Some(value.as_str()),
                Value::Object(object) => {
                    let purpose_ok =
                        object.get("purpose").and_then(Value::as_str) == Some("media_plaintext");
                    if purpose_ok {
                        object
                            .get("service_did")
                            .or_else(|| object.get("did"))
                            .and_then(Value::as_str)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(did_str) = did_str
                && let Ok(service_did) = cokret_sdk::Did::new(did_str.to_owned())
            {
                plaintext_visible_services.push(MediaPlaintextService { service_did });
            }
        }
    }

    let value = MediaDecryptPolicyValue {
        media_service_decrypts,
        plaintext_visible_services,
    };
    derive_media_decrypt_metadata_digest(&value).ok()
}
