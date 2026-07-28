use super::*;

// ════════════════════════════════════════════════════════════════════════
// events.submit discriminated request + admission gates
// (spec B1.6 / T02 / T07 / T08 / T09 / T12 / T23).
// ════════════════════════════════════════════════════════════════════════

/// Spec B1.6 — discriminated `/_arkret/self/events` POST body. Account-client
/// event envelopes stay as raw JSON Values until proof validation, because
/// `proof.event_digest` binds the producer's canonical envelope bytes. Parsing
/// into SDK `Event` here would reserialize defaults and change the signed
/// object before verification.
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
    /// First durable publication of one Event
    /// (`authz/offline-publication.md` §2.1). The `authorization_lease` is the
    /// only thing that can make this service mint and store an
    /// [`arkret_wire::IngressReceipt`] for the Event, which is in turn the only
    /// evidence that lets the Event be federated later. It is transport
    /// evidence: it is not an Event field and never enters the Event digest.
    ///
    /// Ordered before [`Self::Batch`] and [`Self::Single`] because those two
    /// are strictly more permissive shapes — `Single(Value)` matches any JSON
    /// object at all, so it MUST stay last.
    Initial(arkret_wire::EventInitialSubmission),
    /// Current account-client batch form. Every Event carries its own
    /// authorization lease outside the signed Event envelope.
    InitialBatch(SolandEventsInitialSubmitBatchRequestBody),
    /// Legacy internal batch form retained for implementation-owned callers.
    /// Protocol producers use [`Self::InitialBatch`].
    Batch(SolandEventsSubmitBatchRequestBody),
    /// Single Event Envelope (dominant shape).
    Single(Value),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SolandEventsInitialSubmitBatchRequestBody {
    pub events: Vec<arkret_wire::EventInitialSubmission>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SolandEventsSubmitBatchRequestBody {
    pub events: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

impl SolandEventsSubmitRequestBody {
    /// Spec B1.6 — validate the `service_binding_ref` carried on a
    /// federation submit. All 6 fields MUST be populated and well-shaped
    /// per SDK typed validators (already enforced by deserialisation); we
    /// additionally reject `membership_frontier` and
    /// `delivery_binding_frontier` if they are non-empty arrays containing
    /// duplicates.
    pub fn validate_federation_service_binding(
        binding: &FederationServiceBindingRef,
    ) -> Result<(), (&'static str, String)> {
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
                        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                        format!("{name} contains duplicate entry {:?}", entry.as_str()),
                    ));
                }
            }
        }
        if binding.destination_service_kind.trim().is_empty() {
            return Err((
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                "service_binding_ref.destination_service_kind MUST be a non-empty string"
                    .to_owned(),
            ));
        }
        let expected_reducer_digest =
            arkret_policy::generated::profiles::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST;
        let actual_reducer_digest = binding.reducer_profile_digest.to_string();
        if actual_reducer_digest != expected_reducer_digest {
            return Err((
                arkret_wire::ReasonCode::REDUCER_PROFILE_MISMATCH,
                format!(
                    "service_binding_ref.reducer_profile_digest mismatch: expected {expected_reducer_digest}, got {actual_reducer_digest}"
                ),
            ));
        }
        Ok(())
    }
}

pub fn federation_delivery_binding_frontier_is_current<I>(
    request_frontier: &[EventId],
    current_frontiers: I,
) -> Result<(), &'static str>
where
    I: IntoIterator<Item = String>,
{
    if request_frontier.is_empty() {
        return Err("schema_violation");
    }
    let current = current_frontiers
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if current.is_empty() {
        return Err("delivery_binding_stale");
    }
    if request_frontier
        .iter()
        .any(|event_id| !current.contains(event_id.as_str()))
    {
        return Err("delivery_binding_stale");
    }
    Ok(())
}

/// Reject any event kind that is ephemeral or receipt-object-only at the
/// `ak.self.events.command.submit` entrypoint. Spec T02 + T23.
///
/// Returns the canonical [`ErrorCode`] + human reason when the kind MUST be
/// rejected; returns `None` when the kind is fine to forward to the
/// existing durable-event validator pipeline.
pub fn events_submit_pre_admit_check(kind: &str) -> Option<(ErrorCode, &'static str)> {
    if arkret_wire::events::is_ephemeral_kind(kind) {
        return Some((
            ErrorCode::SchemaViolation,
            "ephemeral kind MUST be carried via ak.schema.ephemeral_envelope.v1 \
             (broadcast forms) or ak.schema.device_message.v1 \
             (ak.key.verification.* to-device); not durable ak.self.events.command.submit",
        ));
    }
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
    if realm_in_terminal_state && !arkret_wire::events::kinds::is_audit_kind(kind) {
        return Some((
            ErrorCode::FailedPrecondition,
            "Realm has reached ak.realm.tombstone or ak.realm.destroy \
             terminal state; only audit-class events are accepted",
        ));
    }
    None
}

fn frozen_realm_write_exempt(kind: &str) -> bool {
    arkret_wire::events::kinds::is_audit_kind(kind)
        || matches!(
            kind,
            arkret_wire::events::EventKind::REALM_ARCHIVE
                | arkret_wire::events::EventKind::REALM_FREEZE
                | arkret_wire::events::EventKind::REALM_TOMBSTONE
                | arkret_wire::events::EventKind::REALM_DESTROY
        )
}

/// Reject ordinary writes on a Realm with the reversible `ak.realm.freeze`
/// facet set. Lifecycle/admin escape hatches remain admissible so an
/// authorized actor can unfreeze, tombstone, or destroy the Realm.
pub fn frozen_realm_check(realm_frozen: bool, kind: &str) -> Option<&'static str> {
    if realm_frozen && !frozen_realm_write_exempt(kind) {
        return Some("Realm is frozen; ordinary writes are not accepted");
    }
    None
}

pub(super) fn policy_bundle_value_from_state_payload(payload: &Value) -> &Value {
    payload.get("value").unwrap_or(payload)
}

/// `ak.cross_signing.reset` payload trust-domain & reset_event_id check.
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
             ak:trust_domain:<scope> per spec"
                .to_owned(),
        ));
    }
    if payload_td != server_trust_domain {
        return Err((
            ErrorCode::Unauthenticated,
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
    if arkret_identifiers::EventId::new(payload_reset_event_id).is_err() {
        return Err((
            ErrorCode::SchemaViolation,
            "cross_signing.reset.reset_event_id must be a ak:event:<uuidv7>".to_owned(),
        ));
    }
    if payload_reset_event_id != event_id {
        return Err((
            ErrorCode::FailedPrecondition,
            "cross_signing.reset.reset_event_id must equal the enclosing \
             Event.event_id"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Validate a `ak.realm.policy_bundle` payload. Spec T09 + T12 + SEC-03.
///
/// Checks (in order):
/// 1. `relaxed_window_max_ms <= 300_000` (T09 hard ceiling)
/// 2. `ak.profile.e2ee_relaxed.v1` not active with any audit compliance profile (T09 mutex)
/// 3. When `media_service_decrypts=true`, all governance bindings are present (T12).
/// 4. SEC-03 — when `media_service_decrypts=true`, independently recompute the
///    `discussion_metadata_digest` from the §10.5.1 rule 1–3 policy cell value
///    (`media_service_decrypts` + the authorised `plaintext_visible_services`) and fail closed with
///    `mls_governance_binding_stale` when it disagrees with the digest the projected governance
///    binding covers. This is the server-side mirror of `media-service-binding.md` §8.2 rule 5 /
///    negative vector `ak.vector.webrtc.media_plaintext_downgrade.v1` case (d): the fact that media
///    is service-decryptable MUST be derivable from member-visible metadata, not asserted out of
///    band. `binding_discussion_metadata_digest` is the digest the current epoch governance binding
///    covers, as projected from the realm's MLS cell; `None` means the binding carried no digest,
///    in which case only the policy_root coverage gate (check 3) applies.
pub fn realm_policy_bundle_check(
    payload: &Value,
    active_profiles: &[String],
    media_plaintext_service_present: bool,
    mls_governance_binding_covers_policy_root: bool,
    binding_discussion_metadata_digest: Option<&str>,
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
    if let Some(window) = payload
        .pointer("/e2ee_relaxed/relaxed_window_max_ms")
        .and_then(Value::as_u64)
    {
        let window_u32 = u32::try_from(window).unwrap_or(u32::MAX);
        if arkret_models_collaboration::governance::audit::validate_relaxed_window_ms(window_u32)
            .is_err()
        {
            return Err((
                ErrorCode::FailedPrecondition,
                format!(
                    "e2ee_relaxed.relaxed_window_max_ms={window} exceeds absolute \
                     hard ceiling of {}ms",
                    arkret_models_collaboration::governance::audit::ABSOLUTE_HARD_CEILING_MS
                ),
            ));
        }
    }

    // (2) T09 — e2ee_relaxed.v1 mutex against audit compliance.
    let relaxed_active = active_profiles
        .iter()
        .any(|p| p == "ak.profile.e2ee_relaxed.v1")
        || payload
            .pointer("/e2ee_relaxed/profile")
            .and_then(Value::as_str)
            == Some("ak.profile.e2ee_relaxed.v1");
    let compliance_active = active_profiles.iter().any(|p| {
        soland_services::operation_semantics::AUDIT_COMPLIANCE_PROFILES.contains(&p.as_str())
    });
    if relaxed_active && compliance_active {
        return Err((
            ErrorCode::FailedPrecondition,
            "ak.profile.e2ee_relaxed.v1 is mutually exclusive with audit \
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
                ErrorCode::FailedPrecondition,
                "media_service_decrypts=true requires the SFU/MCU service DID \
                 to be listed in plaintext_visible_services[] with \
                 data_classes[] containing media_plaintext"
                    .to_owned(),
            ));
        }
        if !mls_governance_binding_covers_policy_root {
            return Err((
                ErrorCode::FailedPrecondition,
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
                ErrorCode::FailedPrecondition,
                "media_service_decrypts=true policy cell could not be canonicalised \
                 for discussion_metadata_digest recomputation"
                    .to_owned(),
            ))?;
            let covered =
                arkret_identifiers::Hash::new(covered_digest.to_owned()).map_err(|_| {
                    (
                        ErrorCode::FailedPrecondition,
                        "governance binding discussion_metadata_digest is not a valid \
                     sha256 hash"
                            .to_owned(),
                    )
                })?;
            if arkret_models_crypto::verify_media_decrypt_metadata(&covered, &recomputed).is_err() {
                return Err((
                    ErrorCode::FailedPrecondition,
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

/// SEC-03 — build a `arkret_models_crypto::MediaDecryptPolicyValue`
/// from a `ak.realm.policy_bundle` payload and derive its canonical
/// `discussion_metadata_digest`. Returns `None` only when the SDK's canonical
/// digest derivation fails (it never does for well-formed input), so callers
/// treat that as a fail-closed mismatch.
///
/// The recomputed value mirrors §10.5.1 rule 1 (`media_service_decrypts`) and
/// rule 2 (service DIDs whose `data_classes[]` contains `media_plaintext` in
/// `plaintext_visible_services[]`). Free-text purposes do not grant authority
/// and are excluded from the digest input.
fn recompute_media_decrypt_metadata_digest(payload: &Value) -> Option<arkret_identifiers::Hash> {
    use arkret_models_crypto::{
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
            let did_str = service.as_object().and_then(|object| {
                let authorizes_media = object
                    .get("data_classes")
                    .and_then(Value::as_array)
                    .is_some_and(|classes| {
                        classes
                            .iter()
                            .any(|class| class.as_str() == Some("media_plaintext"))
                    });
                authorizes_media
                    .then(|| object.get("service_id").and_then(Value::as_str))
                    .flatten()
            });
            if let Some(did_str) = did_str
                && let Ok(service_id) = arkret_identifiers::Did::new(did_str.to_owned())
            {
                plaintext_visible_services.push(MediaPlaintextService { service_id });
            }
        }
    }

    let value = MediaDecryptPolicyValue {
        media_service_decrypts,
        plaintext_visible_services,
    };
    derive_media_decrypt_metadata_digest(&value).ok()
}
