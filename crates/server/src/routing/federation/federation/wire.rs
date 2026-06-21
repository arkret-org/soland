use cokret_sdk::Did;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ════════════════════════════════════════════════════════════════════════
// Federation S2S trust-domain headers, idempotency cache key, delivery
// binding handover (spec B1.7 / B1.8 / B1.9 / T14).
// ════════════════════════════════════════════════════════════════════════

/// Spec B1.7 — the three federation trust-domain headers that MUST appear
/// on every inbound federation request.
#[derive(Debug, Clone)]
pub(crate) struct FederationTrustHeaders {
    pub source_trust_domain: cokret_sdk::TypedTrustDomainId,
    pub destination_trust_domain: cokret_sdk::TypedTrustDomainId,
    pub request_canonical_digest: cokret_sdk::Hash,
}

impl FederationTrustHeaders {
    /// Spec B1.7 — extract + validate the three headers from a salvo
    /// `Request`. Returns the typed triple on success or a
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
        let source = header_value(cokret_sdk::HEADER_SOURCE_TRUST_DOMAIN)?.to_owned();
        let destination = header_value(cokret_sdk::HEADER_DESTINATION_TRUST_DOMAIN)?.to_owned();
        let canonical_hash = header_value(cokret_sdk::HEADER_REQUEST_CANONICAL_DIGEST)?.to_owned();
        let source = cokret_sdk::TypedTrustDomainId::new(source).map_err(|_| {
            HeaderViolation::Malformed(cokret_sdk::HEADER_SOURCE_TRUST_DOMAIN.to_owned())
        })?;
        let destination = cokret_sdk::TypedTrustDomainId::new(destination).map_err(|_| {
            HeaderViolation::Malformed(cokret_sdk::HEADER_DESTINATION_TRUST_DOMAIN.to_owned())
        })?;
        let canonical_hash = cokret_sdk::Hash::new(canonical_hash).map_err(|_| {
            HeaderViolation::Malformed(cokret_sdk::HEADER_REQUEST_CANONICAL_DIGEST.to_owned())
        })?;
        Ok(Self {
            source_trust_domain: source,
            destination_trust_domain: destination,
            request_canonical_digest: canonical_hash,
        })
    }

    /// Spec B1.7 — verify the inbound `destination_trust_domain` matches
    /// the receiver's configured trust domain. Mismatch →
    /// `cross_domain_replay_rejected`.
    pub(crate) fn verify_destination(
        &self,
        expected: &cokret_sdk::TypedTrustDomainId,
    ) -> Result<(), &'static str> {
        if self.destination_trust_domain != *expected {
            return Err(crate::error::reasons::CROSS_DOMAIN_REPLAY_REJECTED);
        }
        Ok(())
    }

    /// Spec B1.7 — build the canonical signing-transcript fragment for
    /// inclusion in the message-signature transcript. Delegates to the SDK
    /// helper to keep producer + consumer byte-for-byte identical.
    pub(crate) fn transcript_fragment(&self) -> String {
        cokret_sdk::federation_trust_domain_transcript_fragment(
            &self.source_trust_domain,
            &self.destination_trust_domain,
            &self.request_canonical_digest,
        )
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
        cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::Missing(name) => format!("required federation header {name} missing"),
            Self::Malformed(name) => format!("federation header {name} malformed"),
        }
    }
}

/// Spec B1.8 — composite idempotency cache key. The pre-existing key did
/// NOT incorporate `request_canonical_digest` or `origin_key_state_digest`;
/// a replay after key revocation could mine fresh side effects. This key
/// mixes both in so a cache hit requires the key state to be unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FederationIdempotencyKey {
    pub source_did: String,
    pub dest_did: String,
    pub request_canonical_digest: String,
    pub idempotency_key: String,
    pub origin_key_state_digest: String,
}

impl FederationIdempotencyKey {
    /// Strict key — equal to a cached entry only when ALL fields match,
    /// including the origin's current key state hash.
    pub(crate) fn strict(&self) -> String {
        let canonical = cokret_sdk::canonical::canonical_json_bytes(&json!({
            "source_did": self.source_did,
            "dest_did": self.dest_did,
            "request_canonical_digest": self.request_canonical_digest,
            "idempotency_key": self.idempotency_key,
            "origin_key_state_digest": self.origin_key_state_digest,
        }))
        .unwrap_or_default();
        cokret_sdk::canonical::sha256_digest(&canonical)
    }

    /// Canonical-replay key — drops `origin_key_state_digest`. Used to
    /// detect a replay AFTER the source service rotated its keys.
    pub(crate) fn canonical_replay(&self) -> String {
        let canonical = cokret_sdk::canonical::canonical_json_bytes(&json!({
            "source_did": self.source_did,
            "dest_did": self.dest_did,
            "request_canonical_digest": self.request_canonical_digest,
            "idempotency_key": self.idempotency_key,
        }))
        .unwrap_or_default();
        cokret_sdk::canonical::sha256_digest(&canonical)
    }
}

/// Spec T14 — fields added to the federation idempotency cache key so a
/// replay after key revoke is recognised as a stale historical request
/// rather than a fresh one.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct FederationIdempotencyServiceBinding {
    pub source_service_did: String,
    pub verification_method: String,
    pub service_binding_ref: String,
    pub origin_key_state_digest: String,
}

/// Spec T14 — marker set on a cached federation response that is replayed
/// after the source service rotated its verification key.
pub(crate) const HISTORICAL_ONLY_MARKER: &str = "historical_only";

/// Spec B1.8 — mark a federation response with
/// `reason_code=historical_only`. Receivers MUST set this whenever the
/// cache hit was a canonical-replay (post-key-rotation) rather than a
/// strict-key hit.
pub(crate) fn mark_response_historical_only(mut response: Value) -> Value {
    if let Some(object) = response.as_object_mut() {
        object.insert(
            "reason_code".to_owned(),
            Value::String(cokret_sdk::ERROR_CODE_HISTORICAL_ONLY.to_owned()),
        );
        object.insert(HISTORICAL_ONLY_MARKER.to_owned(), Value::Bool(true));
    }
    response
}

/// Spec B1.9 — emit-shape for `delivery_binding_stale` (409). Returned
/// when a peer attempts to push events using a stale delivery binding. The
/// response carries the new recipient service DID and a frontier the sender
/// should replay from after re-binding.
#[allow(dead_code)]
pub(crate) fn delivery_binding_stale_response(
    new_recipient_service_did: &Did,
    handover_frontier: &[cokret_sdk::EventId],
) -> Value {
    json!({
        "ok": false,
        "error": {
            "code": cokret_sdk::ERROR_CODE_DELIVERY_BINDING_STALE,
            "message": "delivery binding is stale; rebind to the new recipient service",
            "details": {
                "new_recipient_service_did": new_recipient_service_did.as_str(),
                "handover_frontier": handover_frontier
                    .iter()
                    .map(|e| e.as_str())
                    .collect::<Vec<_>>(),
            }
        }
    })
}

/// Spec B1.9 — emit-shape for `delivery_binding_handed_over` (409).
/// Returned when the inbound delivery is a duplicate of a binding that has
/// already been handed over to the new recipient.
#[allow(dead_code)]
pub(crate) fn delivery_binding_handed_over_response(new_recipient_service_did: &Did) -> Value {
    json!({
        "ok": false,
        "error": {
            "code": cokret_sdk::ERROR_CODE_DELIVERY_BINDING_HANDED_OVER,
            "message": "delivery binding has already been handed over to the new recipient",
            "details": {
                "new_recipient_service_did": new_recipient_service_did.as_str(),
            }
        }
    })
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod wire_tests;
