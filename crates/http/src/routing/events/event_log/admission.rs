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
#[derive(Debug, Clone, serde::Serialize)]
// Untagged wire union mirroring the SDK submit bodies; boxing a variant would
// change the public constructor shape without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum SolandEventsSubmitRequestBody {
    /// Federation form — `service_binding_ref` is REQUIRED and all fields are
    /// fields validated.
    Federation(EventsSubmitFederationBatchRequestBody),
    DirectConversationFounding(DirectConversationFoundingUnitSubmission),
    AgentMembershipCascade(
        arkret_models_collaboration::governance::agent_membership_cascade::AgentMembershipCascadeSubmission,
    ),
    /// First durable publication of one Event
    /// (`authz/offline-publication.md` §2.1). The `authorization_lease` is the
    /// only thing that can make this service mint and store an
    /// [`arkret_wire::IngressReceipt`] for the Event, which is in turn the only
    /// evidence that lets the Event be federated later. It is transport
    /// evidence: it is not an Event field and never enters the Event digest.
    ///
    /// Ordered before [`Self::Single`] because that variant is a strictly more
    /// permissive shape — `Single(Value)` matches any JSON object at all, so it
    /// MUST stay last.
    Initial(arkret_wire::EventInitialSubmission),
    /// Account-client batch form. Every Event carries its own authorization
    /// lease outside the signed Event envelope.
    InitialBatch(SolandEventsInitialSubmitBatchRequestBody),
    /// Single Event Envelope (dominant shape).
    Single(Value),
}

impl<'de> serde::Deserialize<'de> for SolandEventsSubmitRequestBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let value = Value::deserialize(deserializer)?;
        let object = value.as_object();
        // `unit_kind` is a protocol discriminator, not an ignorable extension.
        // Dispatch it before the permissive ordinary carriers so a malformed
        // founding unit cannot silently degrade into InitialBatch/Single.
        if object.is_some_and(|object| object.contains_key("unit_kind")) {
            return match object
                .and_then(|object| object.get("unit_kind"))
                .and_then(Value::as_str)
            {
                Some("direct_conversation_founding") => {
                    serde_json::from_value::<DirectConversationFoundingUnitSubmission>(value)
                        .map(Self::DirectConversationFounding)
                        .map_err(D::Error::custom)
                }
                Some("agent_membership_cascade") => serde_json::from_value::<
                    arkret_models_collaboration::governance::agent_membership_cascade::AgentMembershipCascadeSubmission,
                >(value)
                .map(Self::AgentMembershipCascade)
                .map_err(D::Error::custom),
                Some(kind) => Err(D::Error::custom(format!(
                    "unknown registered Event unit_kind {kind:?}"
                ))),
                None => Err(D::Error::custom(
                    "registered Event unit_kind must be a string",
                )),
            };
        }
        if object.is_some_and(|object| object.contains_key("service_binding_ref")) {
            return serde_json::from_value::<EventsSubmitFederationBatchRequestBody>(value)
                .map(Self::Federation)
                .map_err(D::Error::custom);
        }
        if let Ok(initial) =
            serde_json::from_value::<arkret_wire::EventInitialSubmission>(value.clone())
        {
            return Ok(Self::Initial(initial));
        }
        if let Ok(batch) =
            serde_json::from_value::<SolandEventsInitialSubmitBatchRequestBody>(value.clone())
        {
            return Ok(Self::InitialBatch(batch));
        }
        Ok(Self::Single(value))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolandEventsInitialSubmitBatchRequestBody {
    pub events: Vec<arkret_wire::EventInitialSubmission>,
}

impl SolandEventsSubmitRequestBody {
    /// Spec B1.6 — validate the `service_binding_ref` carried on a
    /// federation submit. All fields MUST be populated and well-shaped
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

/// Reject receipt objects at the `ak.self.events.command.submit` entrypoint.
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

fn frozen_realm_write_exempt(kind: &str) -> bool {
    kind.parse::<arkret_wire::EventKind>().is_ok_and(|kind| {
        arkret_wire::events::kinds::is_audit_kind(&kind)
            || matches!(
                kind,
                arkret_wire::EventKind::RealmArchive
                    | arkret_wire::EventKind::RealmFreeze
                    | arkret_wire::EventKind::RealmTombstone
                    | arkret_wire::EventKind::RealmDestroy
            )
    })
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

/// Validate a `ak.realm.policy_bundle` payload. Spec T09 + T12.
///
/// Checks (in order):
/// 1. `relaxed_window_max_ms <= 300_000` (T09 hard ceiling)
/// 2. `ak.profile.e2ee_relaxed.v1` not active with any audit compliance profile (T09 mutex)
/// 3. When `media_service_decrypts=true`, the service is explicitly authorized for the
///    `media_plaintext` data class (T12). The MLS security-frontier projector binds this accepted
///    policy state into the next Commit.
pub fn realm_policy_bundle_check(
    payload: &Value,
    active_profiles: &[String],
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

    // (2) T09 — e2ee_relaxed.v1 mutex against audit compliance.
    let relaxed_active = active_profiles
        .iter()
        .any(|p| p == arkret_wire::ProfileId::E2EE_RELAXED_V1);
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
