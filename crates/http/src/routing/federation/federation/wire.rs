use std::collections::BTreeMap;

use arkret_identifiers::ServiceId;
use serde_json::{Value, json};

// ════════════════════════════════════════════════════════════════════════
// Federation S2S trust-domain headers, idempotency cache key, delivery
// binding handover (spec B1.7 / B1.8 / B1.9 / T14).
// ════════════════════════════════════════════════════════════════════════

/// Spec B1.7 — the two federation trust-domain headers that MUST appear
/// on every inbound federation request.
#[derive(Debug, Clone)]
pub(crate) struct FederationTrustHeaders {
    pub source_trust_domain: arkret_identifiers::TypedTrustDomainId,
    pub destination_trust_domain: arkret_identifiers::TypedTrustDomainId,
}

impl FederationTrustHeaders {
    /// Spec B1.7 — extract + validate the three headers from a salvo
    /// `Request`. Returns the typed pair on success or a
    /// [`HeaderViolation`] on the first missing / malformed header.
    pub(crate) fn from_salvo_request(req: &salvo::http::Request) -> Result<Self, HeaderViolation> {
        let header_value = |name: &str| -> Result<&str, HeaderViolation> {
            let value = req
                .headers()
                .get(name)
                .ok_or_else(|| HeaderViolation::Missing(name.to_owned()))?;
            value
                .to_str()
                .map_err(|_| HeaderViolation::Malformed(name.to_owned()))
        };
        let source = header_value(arkret_wire::constants::HEADER_SOURCE_TRUST_DOMAIN)?.to_owned();
        let destination =
            header_value(arkret_wire::constants::HEADER_DESTINATION_TRUST_DOMAIN)?.to_owned();
        let source = arkret_identifiers::TypedTrustDomainId::new(source).map_err(|_| {
            HeaderViolation::Malformed(
                arkret_wire::constants::HEADER_SOURCE_TRUST_DOMAIN.to_owned(),
            )
        })?;
        let destination =
            arkret_identifiers::TypedTrustDomainId::new(destination).map_err(|_| {
                HeaderViolation::Malformed(
                    arkret_wire::constants::HEADER_DESTINATION_TRUST_DOMAIN.to_owned(),
                )
            })?;
        Ok(Self {
            source_trust_domain: source,
            destination_trust_domain: destination,
        })
    }

    /// Spec B1.7 — verify the inbound `destination_trust_domain` matches
    /// the receiver's configured trust domain. Mismatch →
    /// `cross_domain_replay_rejected`.
    pub(crate) fn verify_destination(
        &self,
        expected: &arkret_identifiers::TypedTrustDomainId,
    ) -> Result<(), &'static str> {
        if self.destination_trust_domain != *expected {
            return Err(arkret_wire::ReasonCode::CROSS_DOMAIN_REPLAY_REJECTED);
        }
        Ok(())
    }
}

/// Spec B1.7 — reasons a federation header check can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeaderViolation {
    Missing(String),
    Malformed(String),
}

impl HeaderViolation {
    pub(crate) fn error_code(&self) -> &'static str {
        arkret_wire::ErrorCode::SCHEMA_VIOLATION
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::Missing(name) => format!("required federation header {name} missing"),
            Self::Malformed(name) => format!("federation header {name} malformed"),
        }
    }
}

/// Spec B1.9 — emit-shape for `delivery_binding_stale` (409). Returned
/// when a peer attempts to push events using a stale delivery binding. The
/// response carries the new recipient service DID and a frontier the sender
/// should replay from after re-binding.
pub(crate) fn delivery_binding_stale_response(
    new_recipient_service_id: &arkret_wire::ServiceId,
    actor_id: &arkret_wire::ActorId,
    new_service_resolution: &arkret_models_identity::ServiceResolutionCarrier,
    handover_frontier: &[arkret_identifiers::EventId],
    witness: Value,
) -> Value {
    let witness = match witness {
        Value::Object(object) => object.into_iter().collect::<BTreeMap<_, _>>(),
        other => BTreeMap::from([("value".to_owned(), other)]),
    };
    let details = arkret_models_identity::artifacts_device_identity::DeliveryBindingStale {
        new_recipient_service_id: new_recipient_service_id.clone(),
        new_service_resolution: new_service_resolution.clone(),
        handover_frontier: handover_frontier.to_vec(),
        handover_proof:
            arkret_models_identity::artifacts_device_identity::DeliveryBindingStaleHandoverProof {
                frontier: handover_frontier.to_vec(),
                recipient_service_id: new_recipient_service_id.clone(),
                actor_id: actor_id.clone(),
                witness: arkret_wire::wire_strings::NonEmptyJsonObject::new(witness)
                    .expect("delivery binding witness must be non-empty"),
                extra: Default::default(),
            },
        extra: Default::default(),
    };
    error_envelope_with_details(
        arkret_wire::ErrorCode::DELIVERY_BINDING_STALE,
        "delivery binding is stale; rebind to the new recipient service",
        details,
    )
}

/// Spec B1.9 — emit-shape for `delivery_binding_handed_over` (409).
/// Returned when the inbound delivery is a duplicate of a binding that has
/// already been handed over to the new recipient.
pub(crate) fn delivery_binding_handed_over_response(new_recipient_service_id: &ServiceId) -> Value {
    error_envelope_with_details(
        arkret_wire::ErrorCode::DELIVERY_BINDING_HANDED_OVER,
        "delivery binding has already been handed over to the new recipient",
        json!({
            "new_recipient_service_id": new_recipient_service_id.as_str(),
        }),
    )
}

fn error_envelope_with_details(
    code: &'static str,
    message: &'static str,
    details: impl serde::Serialize,
) -> Value {
    let details =
        serde_json::to_value(details).unwrap_or_else(|_| Value::Object(Default::default()));
    let mut envelope = arkret_wire::problem_details::ErrorEnvelope::new(code, message);
    if let Some(object) = details.as_object() {
        for (key, value) in object {
            envelope = envelope.with_detail(key.clone(), value.clone());
        }
    }
    serde_json::to_value(envelope).unwrap_or_else(|_| {
        json!({
            "ok": false,
            "error": {
                "code": code,
                "message": message,
            },
            "request_id": "unknown",
        })
    })
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod wire_tests;
