//! Round 4 (2026-05-20; spec `a77b9958`) wire-breaking implementations.
//!
//! This module consolidates the new typed wire shapes introduced by the
//! round-4 protocol-review closure round. It complements [`crate::round23`]
//! and depends on the SDK's `model::round4` typed surface
//! (`contrix_sdk::*`). Wire-breaking summary (see `_todos.md` §B1):
//!
//! - **ServiceDescribe v2** — 17 required top-level fields including `trust_domain`,
//!   `plaintext_visibility`, `claimed_profiles`, `verified_profiles`. Validated in
//!   [`crate::wire::describe`].
//! - **EventsFrontier 3-way split** — `peer_role` query param routes to `account_client` /
//!   `federation_peer` / `anonymous_health`. The typed response variants are built via
//!   [`build_typed_frontier_response`]. `anonymous_health` MUST NOT carry receipts or
//!   actor_seq_upper_bounds (the type system enforces this).
//! - **EventsSubscribe typed frames** — NDJSON producer emits
//!   [`contrix_sdk::EventsSubscribeFrameBody`]. `Dropped` MUST carry a resume cursor; absence is
//!   downgraded to `ResyncRequired`.
//! - **EventsSubmit discriminated** — `cx.events.submit` accepts `single` / `batch` / `federation`
//!   forms. The federation form MUST carry all 6 fields of
//!   [`contrix_sdk::FederationServiceBindingRef`]; any missing field returns `schema_violation`.
//! - **Federation S2S headers** — `Source-Trust-Domain`, `Destination-Trust-Domain`, and
//!   `Request-Canonical-Digest` MUST be present on every inbound federation request and MUST be
//!   appended to the message-signature transcript via
//!   [`contrix_sdk::federation_trust_domain_transcript_fragment`].
//! - **Federation idempotency cache** — key carries `source_did + dest_did +
//!   request_canonical_digest + idempotency_key + origin_key_state_digest`. Replay after key-state
//!   change emits `reason_code=historical_only` (no side effects).
//! - **`/blob/presign` realm_id** — request MUST carry `realm_id`; for Realm-owned blobs the value
//!   MUST match the blob metadata's `realm_id` field.
//! - **`AuditRywReceipt.trust_domain`** — recompute the policy version hash via the 4-arg SDK
//!   helper [`contrix_sdk::compute_audit_policy_version_digest`].
//! - **`cx.consent.revoke` observed_dots** — required. Implicit cascade is `schema_violation`.
//! - **`cx.cross_signing.publish` CAS** — accept only when `expected_previous_generation ==
//!   current` and `new == current + 1`. Cell_subject via
//!   [`contrix_sdk::cross_signing_publish_cell_subject`].
//! - **`cx.flow.update` / `cx.flow.tracks_patch` cell metadata** — CAS-register, family
//!   `cx.component.flow.metadata.v1`, bottom=reject; subject is the flow_id, via SDK helpers.
//! - **`cx.audit.policy_access access_kind=e2ee_late_recovery`** — carries
//!   `late_recovery_original_event_id`. Validated via
//!   [`contrix_sdk::AuditPolicyAccessPayload::validate_minimal`].
//!
//! Complex internals that are still outside this module's narrow wire
//! helpers (SnapshotBootstrap chunk generator / signature and the full
//! 3PID invite verifier chain) remain in their owning modules; the
//! cross-project wire shape + API paths are correct.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use contrix_sdk::{
    AccessKind, AuditPolicyAccessPayload, ConsentRevokePayload, Did,
    ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED, ERROR_CODE_DELIVERY_BINDING_HANDED_OVER,
    ERROR_CODE_DELIVERY_BINDING_STALE, ERROR_CODE_HISTORICAL_ONLY, ERROR_CODE_SCHEMA_VIOLATION,
    EventId, EventsFrontierAccountClientResponse, EventsFrontierAnonymousHealthResponse,
    EventsFrontierFederationPeerResponse, EventsFrontierResponse, EventsSubmitBatchRequest,
    EventsSubmitFederationRequest, EventsSubscribeFrameBody, FederationServiceBindingRef,
    FrontierPeerRole, HEADER_DESTINATION_TRUST_DOMAIN, HEADER_REQUEST_CANONICAL_DIGEST,
    HEADER_SOURCE_TRUST_DOMAIN, Hash, RealmId, SpaceId, SpaceObjectTombstonePayload,
    SpaceStateTransitionPayload, TypedTrustDomainId, canonical,
    compute_audit_policy_version_digest, cross_signing_publish_cell_subject,
    federation_trust_domain_transcript_fragment, flow_tracks_patch_cell_subject,
    flow_update_cell_subject,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// ════════════════════════════════════════════════════════════════════════
// EventsFrontier 3-way split — typed response builder.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.4) — peer-role discriminator parsing. Returns `None` when
/// `peer_role` is missing (caller should default to
/// [`FrontierPeerRole::AccountClient`]); returns
/// [`FrontierPeerRole`] for the three canonical values; returns
/// `Err(reason)` for an unrecognised value (caller surfaces as
/// `invalid_param`).
pub fn parse_peer_role(value: Option<&str>) -> Result<FrontierPeerRole, &'static str> {
    match value.unwrap_or("account_client") {
        "account_client" => Ok(FrontierPeerRole::AccountClient),
        "federation_peer" => Ok(FrontierPeerRole::FederationPeer),
        "anonymous_health" => Ok(FrontierPeerRole::AnonymousHealth),
        _ => Err("peer_role must be account_client / federation_peer / anonymous_health"),
    }
}

/// Round 4 (B1.4) — convert a per-space frontier table to the typed
/// `BTreeMap<SpaceId, Vec<EventId>>` shape required by
/// [`EventsFrontierAccountClientResponse`] / [`EventsFrontierFederationPeerResponse`].
/// Entries whose ids fail SDK typed-id parsing are silently dropped — this
/// is the server's introspection surface, not the canonical persistence
/// layer, so a single malformed row should not break the whole response.
pub fn typed_space_frontier(
    space_to_event_ids: impl IntoIterator<Item = (String, Vec<String>)>,
) -> std::collections::BTreeMap<SpaceId, Vec<EventId>> {
    let mut out = std::collections::BTreeMap::new();
    for (space, events) in space_to_event_ids {
        let Ok(space_id) = SpaceId::new(space) else {
            continue;
        };
        let typed_events: Vec<EventId> = events
            .into_iter()
            .filter_map(|id| EventId::new(id).ok())
            .collect();
        if !typed_events.is_empty() {
            out.insert(space_id, typed_events);
        }
    }
    out
}

/// Round 4 (B1.4) — convert the actor → seq upper bound table to the
/// typed `BTreeMap<Did, u64>` shape. Entries whose actor strings fail
/// `Did::new` are silently dropped (same rationale as
/// [`typed_space_frontier`]).
pub fn typed_actor_upper_bounds(
    actor_to_seq: impl IntoIterator<Item = (String, u64)>,
) -> std::collections::BTreeMap<Did, u64> {
    let mut out = std::collections::BTreeMap::new();
    for (actor, seq) in actor_to_seq {
        if let Ok(did) = Did::new(actor) {
            out.insert(did, seq);
        }
    }
    out
}

/// Round 4 (B1.4) — build the typed [`EventsFrontierResponse`] for a
/// `peer_role`. The caller passes already-collected `space_frontier`,
/// `actor_upper_bounds`, the service DID (for `anonymous_health`), and
/// for `federation_peer` a [`FederationServiceBindingRef`] +
/// `frontier_root`.
///
/// `anonymous_health` MUST NOT carry receipts or actor_seq_upper_bounds
/// — the type signature enforces this.
///
/// `federation_peer` MUST carry `frontier_root` + `service_binding_ref`;
/// callers should pass a [`FederationFrontierBinding`] produced from the
/// frontier snapshot they are returning.
#[derive(Debug, Clone)]
pub struct FederationFrontierBinding {
    pub service_binding_ref: FederationServiceBindingRef,
    pub frontier_root: Hash,
    pub receipts: Vec<Value>,
    pub signatures: Vec<Value>,
}

pub fn build_typed_frontier_response(
    peer_role: FrontierPeerRole,
    service_did: &Did,
    space_frontier: BTreeMap<SpaceId, Vec<EventId>>,
    actor_upper_bounds: BTreeMap<Did, u64>,
    federation_binding: Option<FederationFrontierBinding>,
) -> EventsFrontierResponse {
    match peer_role {
        FrontierPeerRole::AccountClient => {
            EventsFrontierResponse::AccountClient(EventsFrontierAccountClientResponse {
                peer_role,
                frontier: space_frontier,
                actor_seq_upper_bounds: actor_upper_bounds,
            })
        }
        FrontierPeerRole::FederationPeer => {
            let binding = federation_binding.unwrap_or_else(|| {
                fallback_federation_frontier_binding(&space_frontier, &actor_upper_bounds)
            });
            EventsFrontierResponse::FederationPeer(EventsFrontierFederationPeerResponse {
                peer_role,
                frontier: space_frontier,
                frontier_root: binding.frontier_root,
                service_binding_ref: binding.service_binding_ref,
                receipts: binding.receipts,
                signatures: binding.signatures,
                actor_seq_upper_bounds: actor_upper_bounds,
            })
        }
        FrontierPeerRole::AnonymousHealth => {
            // anonymous_health is a public health probe; type enforces
            // no receipts / upper bounds / per-space frontier are
            // exposed. We only return a yes/no health summary + the
            // service DID + a timestamp for staleness detection.
            EventsFrontierResponse::AnonymousHealth(EventsFrontierAnonymousHealthResponse {
                peer_role,
                service_did: service_did.clone(),
                healthy: true,
                generated_at: Utc::now(),
            })
        }
    }
}

/// Round 4 (B1.4 / federation.md §4.5.1) — compute the deterministic
/// frontier root over the current event heads and sorted per-actor seq
/// upper bounds. Each leaf is first canonical-JSON hashed with a domain
/// tag, then folded as a binary Merkle tree using canonical node JSON.
/// The empty frontier still has a stable non-zero domain-separated root.
pub fn frontier_root(
    space_frontier: &BTreeMap<SpaceId, Vec<EventId>>,
    actor_upper_bounds: &BTreeMap<Did, u64>,
) -> Result<Hash, String> {
    let mut heads = BTreeSet::new();
    for events in space_frontier.values() {
        for event in events {
            heads.insert(event.as_str().to_owned());
        }
    }

    let mut leaves = Vec::new();
    for event_id in heads {
        leaves.push(canonical_hash(&json!({
            "domain": "cx.events.frontier.leaf.v1",
            "kind": "head",
            "event_id": event_id,
        }))?);
    }
    for (actor, seq) in actor_upper_bounds {
        leaves.push(canonical_hash(&json!({
            "domain": "cx.events.frontier.leaf.v1",
            "kind": "actor_seq_upper_bound",
            "actor_id": actor.as_str(),
            "actor_seq": seq,
        }))?);
    }

    if leaves.is_empty() {
        return canonical_hash(&json!({
            "domain": "cx.events.frontier.root.v1",
            "empty": true,
        }));
    }

    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(canonical_hash(&json!({
                "domain": "cx.events.frontier.node.v1",
                "left": pair[0].as_str(),
                "right": right.as_str(),
            }))?);
        }
        leaves = next;
    }
    Ok(leaves.remove(0))
}

/// Build the frontier-derived federation binding reference carried on
/// `peer_role=federation_peer`. The reducer-specific verifier still
/// checks this independently on receive; this helper makes the emitted
/// binding deterministic and tied to the same heads used for
/// `frontier_root`.
pub fn frontier_service_binding_ref(
    realm_id: &RealmId,
    space_frontier: &BTreeMap<SpaceId, Vec<EventId>>,
    actor_upper_bounds: &BTreeMap<Did, u64>,
) -> Result<FederationServiceBindingRef, String> {
    let heads = frontier_heads(space_frontier);
    let space_policy_hash = canonical_hash(&json!({
        "domain": "cx.events.frontier.space_policy_hash.v1",
        "realm_id": realm_id.as_str(),
        "heads": heads.iter().map(EventId::as_str).collect::<Vec<_>>(),
        "actor_seq_upper_bounds": actor_upper_bounds
            .iter()
            .map(|(actor, seq)| json!({
                "actor_id": actor.as_str(),
                "actor_seq": seq,
            }))
            .collect::<Vec<_>>(),
    }))?;
    let reducer_profile_digest = canonical_hash(&json!({
        "domain": "cx.events.frontier.reducer_profile.v1",
        "profile": "cx.reducer.v1",
    }))?;

    Ok(FederationServiceBindingRef {
        realm_id: realm_id.clone(),
        space_policy_hash,
        membership_frontier: heads.clone(),
        delivery_binding_frontier: heads,
        destination_service_type: "principal_server".to_owned(),
        reducer_profile_digest,
    })
}

/// Canonical payload signed by the issuing service for a federation
/// frontier probe. Per federation.md §4.5.1 the signature covers only
/// the root plus `(realm_id, issuer, observed_at)` so peers can compare
/// roots without replaying the whole frontier body.
pub fn frontier_signature_payload(
    realm_id: Option<&RealmId>,
    issuer: &Did,
    observed_at: DateTime<Utc>,
    frontier_root: &Hash,
) -> Value {
    json!({
        "domain": "cx.events.frontier.signature.v1",
        "frontier_root": frontier_root.as_str(),
        "realm_id": realm_id.map(RealmId::as_str),
        "issuer": issuer.as_str(),
        "observed_at": observed_at.to_rfc3339(),
    })
}

/// Build an Ed25519 detached-JWS signature envelope for the canonical
/// frontier signature payload.
pub fn sign_frontier_root(
    service_did: &Did,
    realm_id: Option<&RealmId>,
    observed_at: DateTime<Utc>,
    frontier_root: &Hash,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<Value, String> {
    let signed_payload =
        frontier_signature_payload(realm_id, service_did, observed_at, frontier_root);
    let canonical_bytes =
        canonical::canonical_json_bytes(&signed_payload).map_err(|error| error.to_string())?;
    let payload_digest = canonical::sha256_digest(&canonical_bytes);
    let jws = contrix_sdk::jws::sign_jws_ed25519(&canonical_bytes, signing_key)
        .map_err(|error| error.to_string())?;

    Ok(json!({
        "alg": "EdDSA",
        "typ": "cx.events.frontier.signature.v1",
        "scheme": "ed25519-detached-jws",
        "verification_method": format!("{}#frontier-key", service_did.as_str()),
        "payload_digest": payload_digest,
        "created_at": observed_at.to_rfc3339(),
        "jws": jws,
        "signed_payload": signed_payload,
    }))
}

fn frontier_heads(space_frontier: &BTreeMap<SpaceId, Vec<EventId>>) -> Vec<EventId> {
    let mut heads: BTreeMap<&str, &EventId> = BTreeMap::new();
    for events in space_frontier.values() {
        for event in events {
            heads.insert(event.as_str(), event);
        }
    }
    heads.into_values().cloned().collect()
}

fn canonical_hash(value: &Value) -> Result<Hash, String> {
    let digest = canonical::canonical_sha256(value).map_err(|error| error.to_string())?;
    Hash::new(digest).map_err(|error| error.to_string())
}

fn fallback_federation_frontier_binding(
    space_frontier: &BTreeMap<SpaceId, Vec<EventId>>,
    actor_upper_bounds: &BTreeMap<Did, u64>,
) -> FederationFrontierBinding {
    let realm_id = RealmId::new("cx:realm:00000000-0000-7000-8000-000000000000".to_owned())
        .expect("built-in fallback realm id is valid");
    let frontier_root = frontier_root(space_frontier, actor_upper_bounds)
        .expect("frontier root over typed ids must canonicalize");
    let service_binding_ref =
        frontier_service_binding_ref(&realm_id, space_frontier, actor_upper_bounds)
            .expect("frontier-derived binding must canonicalize");
    FederationFrontierBinding {
        service_binding_ref,
        frontier_root,
        receipts: Vec::new(),
        signatures: Vec::new(),
    }
}

// ════════════════════════════════════════════════════════════════════════
// EventsSubscribe NDJSON typed frames.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.5) — wrap a typed [`EventsSubscribeFrameBody`] in the
/// envelope shape soland emits on the wire (kept distinct from the
/// SDK body type so the per-frame `seq` / `space_id` envelope can
/// evolve independently of the SDK's `kind`-tagged body).
///
/// The envelope serialises a flattened body via `#[serde(flatten)]` so
/// downstream consumers see exactly the SDK [`EventsSubscribeFrameBody`]
/// fields plus the wrapper's `seq` / `space_id` / `cursor` / ts fields
/// at the top level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeFrameEnvelope {
    /// Monotonic per-connection sequence (matches the legacy `seq` field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Originating space (for fan-out frames). Optional; absent on
    /// `heartbeat`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    /// Cursor for the frame, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(flatten)]
    pub body: EventsSubscribeFrameBody,
}

/// Round 4 (B1.5) — when an implementation would emit a `Dropped` frame
/// but cannot supply a resume cursor, the wire-breaking rule downgrades
/// to `ResyncRequired`. Callers use [`dropped_or_resync`] to construct
/// the correct frame body from an optional cursor.
///
/// Note: the cursor type expected by [`EventsSubscribeFrameBody::Dropped`]
/// is the typed-id `contrix_identifiers::Cursor`
/// (`cx:cursor:<base64url>`), NOT the `contrix_sdk::Cursor` struct
/// produced by `cursor::Cursor::new()`. The typed-id is exposed as
/// `contrix_sdk::identifiers::Cursor`.
pub fn dropped_or_resync(
    cursor: Option<contrix_sdk::identifiers::Cursor>,
    reason: impl Into<String>,
    reconnect_after_ms: Option<u64>,
) -> EventsSubscribeFrameBody {
    let reason = reason.into();
    match cursor {
        Some(cursor) => EventsSubscribeFrameBody::Dropped {
            cursor,
            reason,
            reconnect_after_ms,
        },
        None => EventsSubscribeFrameBody::ResyncRequired {
            reason,
            reconnect_after_ms,
        },
    }
}

// ════════════════════════════════════════════════════════════════════════
// EventsSubmit discriminated request.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.6) — discriminated `/api/v1/events` POST body. Single is
/// the pre-existing canonical Event Envelope; batch and federation are
/// the new round-4 shapes.
///
/// Wire-breaking: producers MUST use spec `events[]`; producers that
/// include the `service_binding_ref` are routed to [`Self::Federation`].
/// Client-account writes omit `service_binding_ref`; federation writes are
/// gated by federation authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventsSubmitRequest {
    /// Federation form — `service_binding_ref` is REQUIRED and all 6
    /// fields validated.
    Federation(EventsSubmitFederationRequest),
    /// Batch form — multiple envelopes, optional `idempotency_key`.
    Batch(EventsSubmitBatchRequest),
    /// Single Event Envelope (legacy / dominant shape).
    Single(Value),
}

impl EventsSubmitRequest {
    /// Classify an incoming JSON body without consuming it. Returns the
    /// discriminator name for tracing / metrics.
    pub fn shape(body: &Value) -> &'static str {
        if body.get("service_binding_ref").is_some() {
            "federation"
        } else if body.get("events").is_some() {
            "batch"
        } else {
            "single"
        }
    }

    /// Round 4 (B1.6) — validate the `service_binding_ref` carried on a
    /// federation submit. All 6 fields MUST be populated and
    /// well-shaped per SDK typed validators (already enforced by
    /// deserialisation); we additionally reject `membership_frontier`
    /// and `delivery_binding_frontier` if they are non-empty arrays
    /// containing duplicates.
    ///
    /// `TODO(round4-fed-binding-verify)`: also verify the
    /// `space_policy_hash` and `reducer_profile_digest` against the
    /// receiver's own materialised state (this is the deeper inbound
    /// verification chain).
    pub fn validate_federation_binding(
        req: &EventsSubmitFederationRequest,
    ) -> Result<(), (&'static str, String)> {
        let binding = &req.service_binding_ref;
        // realm_id, space_policy_hash, destination_service_type,
        // reducer_profile_digest — typed values, already non-null. The
        // membership and delivery_binding frontiers are arrays of
        // EventIds; reject duplicates inside a frontier to prevent
        // canonical-JSON drift attacks.
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
                        ERROR_CODE_SCHEMA_VIOLATION,
                        format!("{name} contains duplicate entry {:?}", entry.as_str()),
                    ));
                }
            }
        }
        if binding.destination_service_type.trim().is_empty() {
            return Err((
                ERROR_CODE_SCHEMA_VIOLATION,
                "service_binding_ref.destination_service_type MUST be a non-empty string"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════
// Federation S2S header verification.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.7) — the three federation trust-domain headers that MUST
/// appear on every inbound federation request.
#[derive(Debug, Clone)]
pub struct FederationTrustHeaders {
    pub source_trust_domain: TypedTrustDomainId,
    pub destination_trust_domain: TypedTrustDomainId,
    pub request_canonical_digest: Hash,
}

impl FederationTrustHeaders {
    /// Round 4 (B1.7) — extract + validate the three headers from a
    /// salvo `Request`. Returns the typed triple on success or an
    /// [`HeaderViolation`] on the first missing / malformed header.
    pub fn from_salvo_request(req: &salvo::http::Request) -> Result<Self, HeaderViolation> {
        let header_value = |name: &str| -> Result<&str, HeaderViolation> {
            let value = req
                .headers()
                .get(name)
                .ok_or_else(|| HeaderViolation::Missing(name.to_owned()))?;
            value
                .to_str()
                .map_err(|_| HeaderViolation::Malformed(name.to_owned()))
        };
        let source = header_value(HEADER_SOURCE_TRUST_DOMAIN)?.to_owned();
        let destination = header_value(HEADER_DESTINATION_TRUST_DOMAIN)?.to_owned();
        let canonical_hash = header_value(HEADER_REQUEST_CANONICAL_DIGEST)?.to_owned();
        let source = TypedTrustDomainId::new(source)
            .map_err(|_| HeaderViolation::Malformed(HEADER_SOURCE_TRUST_DOMAIN.to_owned()))?;
        let destination = TypedTrustDomainId::new(destination)
            .map_err(|_| HeaderViolation::Malformed(HEADER_DESTINATION_TRUST_DOMAIN.to_owned()))?;
        let canonical_hash = Hash::new(canonical_hash)
            .map_err(|_| HeaderViolation::Malformed(HEADER_REQUEST_CANONICAL_DIGEST.to_owned()))?;
        Ok(Self {
            source_trust_domain: source,
            destination_trust_domain: destination,
            request_canonical_digest: canonical_hash,
        })
    }

    /// Round 4 (B1.7) — verify the inbound `destination_trust_domain`
    /// matches the receiver's configured trust domain. Mismatch →
    /// `cross_domain_replay_rejected`.
    pub fn verify_destination(&self, expected: &TypedTrustDomainId) -> Result<(), &'static str> {
        if self.destination_trust_domain != *expected {
            return Err(ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED);
        }
        Ok(())
    }

    /// Round 4 (B1.7) — build the canonical signing-transcript fragment
    /// for inclusion in the message-signature transcript. Delegates to
    /// the SDK helper to keep producer + consumer byte-for-byte
    /// identical.
    pub fn transcript_fragment(&self) -> String {
        federation_trust_domain_transcript_fragment(
            &self.source_trust_domain,
            &self.destination_trust_domain,
            &self.request_canonical_digest,
        )
    }
}

/// Round 4 (B1.7) — reasons a federation header check can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderViolation {
    Missing(String),
    Malformed(String),
}

impl HeaderViolation {
    pub fn error_code(&self) -> &'static str {
        // Both shapes map to `schema_violation` at the wire level —
        // the message body carries the header name.
        ERROR_CODE_SCHEMA_VIOLATION
    }

    pub fn message(&self) -> String {
        match self {
            Self::Missing(name) => format!("required federation header {name} missing"),
            Self::Malformed(name) => format!("federation header {name} malformed"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// Federation idempotency cache key.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.8) — composite idempotency cache key. The pre-round-4
/// key did NOT incorporate `request_canonical_digest` or
/// `origin_key_state_digest`; a replay after key revocation could mine
/// fresh side effects. Round 4 mixes both into the key so a cache hit
/// requires the key state to be unchanged.
///
/// When the *key state* has advanced since the cached response was
/// minted, the cache should still match (the request_canonical_digest
/// plus idempotency_key are the same) but the receiver MUST mark the
/// response with `reason_code=historical_only` and MUST NOT trigger
/// fresh side effects. This is implemented by deriving two keys: the
/// strict key (with `origin_key_state_digest`) and the canonical-replay
/// key (without it). The strict key is used for freshness; the
/// canonical-replay key for historical lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FederationIdempotencyKey {
    pub source_did: String,
    pub dest_did: String,
    pub request_canonical_digest: String,
    pub idempotency_key: String,
    pub origin_key_state_digest: String,
}

impl FederationIdempotencyKey {
    /// Strict key — equal to a cached entry only when ALL fields match,
    /// including the origin's current key state hash. Use for "is this
    /// a fresh idempotent replay against the same key state?".
    pub fn strict(&self) -> String {
        let canonical = canonical::canonical_json_bytes(&json!({
            "source_did": self.source_did,
            "dest_did": self.dest_did,
            "request_canonical_digest": self.request_canonical_digest,
            "idempotency_key": self.idempotency_key,
            "origin_key_state_digest": self.origin_key_state_digest,
        }))
        .unwrap_or_default();
        let digest = Sha256::digest(&canonical);
        format!("sha256:{:x}", digest)
    }

    /// Canonical-replay key — drops `origin_key_state_digest`. Used to
    /// detect a replay AFTER the source service rotated its keys; if
    /// the strict key misses but the canonical-replay key hits, the
    /// receiver returns the cached body marked
    /// `reason_code=historical_only` rather than executing fresh side
    /// effects.
    pub fn canonical_replay(&self) -> String {
        let canonical = canonical::canonical_json_bytes(&json!({
            "source_did": self.source_did,
            "dest_did": self.dest_did,
            "request_canonical_digest": self.request_canonical_digest,
            "idempotency_key": self.idempotency_key,
        }))
        .unwrap_or_default();
        let digest = Sha256::digest(&canonical);
        format!("sha256:{:x}", digest)
    }
}

/// Round 4 (B1.8) — mark a federation response with
/// `reason_code=historical_only`. Receivers MUST set this whenever the
/// cache hit was a canonical-replay (post-key-rotation) rather than a
/// strict-key hit.
pub fn mark_response_historical_only(mut response: Value) -> Value {
    if let Some(object) = response.as_object_mut() {
        object.insert(
            "reason_code".to_owned(),
            Value::String(ERROR_CODE_HISTORICAL_ONLY.to_owned()),
        );
        object.insert("historical_only".to_owned(), Value::Bool(true));
    }
    response
}

// ════════════════════════════════════════════════════════════════════════
// Delivery binding handover.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.9) — emit-shape for `delivery_binding_stale` (409). The
/// receiver returns this when a peer attempts to push events using a
/// stale delivery binding (e.g. the recipient service has migrated to
/// a new principal server). The response carries the new recipient
/// service DID and a frontier the sender should replay from after
/// re-binding.
pub fn delivery_binding_stale_response(
    new_recipient_service_did: &Did,
    handover_frontier: &[EventId],
) -> Value {
    json!({
        "ok": false,
        "error": {
            "code": ERROR_CODE_DELIVERY_BINDING_STALE,
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

/// Round 4 (B1.9) — emit-shape for `delivery_binding_handed_over` (409).
/// Returned when the inbound delivery is a duplicate of a binding that
/// has already been handed over to the new recipient; the sender SHOULD
/// stop retrying via the legacy binding.
pub fn delivery_binding_handed_over_response(new_recipient_service_did: &Did) -> Value {
    json!({
        "ok": false,
        "error": {
            "code": ERROR_CODE_DELIVERY_BINDING_HANDED_OVER,
            "message": "delivery binding has already been handed over to the new recipient",
            "details": {
                "new_recipient_service_did": new_recipient_service_did.as_str(),
            }
        }
    })
}

// ════════════════════════════════════════════════════════════════════════
// cross_signing.publish CAS.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.10) — CAS check for `cx.cross_signing.publish`. The
/// reducer accepts the publish only when:
///
/// - `expected_previous_generation == current_generation`, AND
/// - `new_generation == current_generation + 1`.
///
/// The cell_subject for the CAS-register cell is the tuple
/// `(principal_id, expected_previous_generation)`; producers and
/// consumers MUST use [`cross_signing_publish_cell_subject`] from the
/// SDK to keep the canonical form aligned.
pub fn cross_signing_publish_cas_check(
    current_generation: u64,
    expected_previous_generation: u64,
    new_generation: u64,
) -> Result<(), (&'static str, String)> {
    if expected_previous_generation != current_generation {
        return Err((
            "cas_conflict",
            format!(
                "cross_signing.publish expected_previous_generation={expected_previous_generation} \
                 does not match current_generation={current_generation}"
            ),
        ));
    }
    if new_generation != current_generation.saturating_add(1) {
        return Err((
            ERROR_CODE_SCHEMA_VIOLATION,
            format!(
                "cross_signing.publish new_generation={new_generation} must equal \
                 current_generation+1 ({})",
                current_generation.saturating_add(1)
            ),
        ));
    }
    Ok(())
}

/// Round 4 (B1.10) — convenience: build the CAS-register cell_subject
/// string for `cx.cross_signing.publish`. Delegates to the SDK helper.
pub fn publish_cell_subject(principal_id: &Did, expected_previous_generation: u64) -> String {
    cross_signing_publish_cell_subject(principal_id, expected_previous_generation)
}

// ════════════════════════════════════════════════════════════════════════
// /blob/presign realm_id binding.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.11) — request body for `/api/v1/blob/presign`. The
/// `realm_id` field is REQUIRED for Realm-owned blobs. For deployment-
/// owned (anonymous) blobs the field may be omitted; the matching
/// metadata lookup is the only authoritative check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobPresignRequest {
    pub blob_ref: String,
    pub purpose: String,
    /// Round 4 — REQUIRED when the blob's metadata declares a realm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

/// Round 4 (B1.11) — verify the request `realm_id` matches the blob
/// metadata's `realm_id`. Returns `Ok(())` on match (or when the blob
/// has no realm binding); returns `Err((code, msg))` on mismatch.
pub fn verify_blob_presign_realm_binding(
    request_realm_id: Option<&str>,
    blob_metadata_realm_id: Option<&str>,
) -> Result<(), (&'static str, String)> {
    match (request_realm_id, blob_metadata_realm_id) {
        (None, None) => Ok(()),
        (Some(req), Some(meta)) if req == meta => Ok(()),
        (None, Some(meta)) => Err((
            ERROR_CODE_SCHEMA_VIOLATION,
            format!("/blob/presign request MUST carry realm_id={meta:?} for Realm-owned blob"),
        )),
        (Some(req), None) => Err((
            "capability_denied",
            format!("/blob/presign request carries realm_id={req:?} but blob has no realm binding"),
        )),
        (Some(req), Some(meta)) => Err((
            "capability_denied",
            format!(
                "/blob/presign request realm_id={req:?} does not match blob metadata realm_id={meta:?}"
            ),
        )),
    }
}

// ════════════════════════════════════════════════════════════════════════
// AuditRywReceipt trust_domain hash.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.12) — recompute the audit policy version hash using the
/// 4-arg SDK helper. The pre-round-4 2-arg signature is removed; any
/// audit receipt produced by an out-of-tree signer using the old form
/// MUST be re-issued.
pub fn compute_audit_policy_hash(
    realm_id: &RealmId,
    trust_domain: &TypedTrustDomainId,
    audit_disclosure: &Value,
    audit_assurance: &Value,
) -> [u8; 32] {
    compute_audit_policy_version_digest(realm_id, trust_domain, audit_disclosure, audit_assurance)
        .unwrap_or([0u8; 32])
}

// ════════════════════════════════════════════════════════════════════════
// cx.space.archive / restore / tombstone reducer guard.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.13) — parse a `cx.space.archive` / `cx.space.restore`
/// payload into the typed [`SpaceStateTransitionPayload`]. Returns
/// `Err` (with `schema_violation`) when the payload still carries the
/// legacy top-level `target_ref` form (pre-round-4 wire).
pub fn parse_space_state_transition_payload(
    payload: &Value,
) -> Result<SpaceStateTransitionPayload, (&'static str, String)> {
    if payload.get("target_ref").is_some() {
        return Err((
            ERROR_CODE_SCHEMA_VIOLATION,
            "cx.space.archive/restore payload legacy `target_ref` form is wire-broken; \
             use the typed `space_state_transition_payload` shape (space_id, new_state, reason?)"
                .to_owned(),
        ));
    }
    serde_json::from_value::<SpaceStateTransitionPayload>(payload.clone()).map_err(|err| {
        (
            ERROR_CODE_SCHEMA_VIOLATION,
            format!(
                "cx.space.archive/restore payload must match SpaceStateTransitionPayload: {err}"
            ),
        )
    })
}

/// Round 4 (B1.13) — parse a `cx.space.tombstone` payload into the
/// typed [`SpaceObjectTombstonePayload`].
pub fn parse_space_object_tombstone_payload(
    payload: &Value,
) -> Result<SpaceObjectTombstonePayload, (&'static str, String)> {
    if payload.get("target_ref").is_some() {
        return Err((
            ERROR_CODE_SCHEMA_VIOLATION,
            "cx.space.tombstone payload legacy `target_ref` form is wire-broken; \
             use the typed `space_object_tombstone_payload` shape (space_id, tombstone_reason)"
                .to_owned(),
        ));
    }
    serde_json::from_value::<SpaceObjectTombstonePayload>(payload.clone()).map_err(|err| {
        (
            ERROR_CODE_SCHEMA_VIOLATION,
            format!("cx.space.tombstone payload must match SpaceObjectTombstonePayload: {err}"),
        )
    })
}

// ════════════════════════════════════════════════════════════════════════
// cx.consent.revoke observed_dots required.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.14) — validate a `cx.consent.revoke` payload. Empty or
/// missing `observed_dots[]` is `schema_violation` — implicit cascade
/// revoke is forbidden.
pub fn validate_consent_revoke_payload(payload: &Value) -> Result<(), (&'static str, String)> {
    let parsed: ConsentRevokePayload = serde_json::from_value(payload.clone()).map_err(|err| {
        (
            ERROR_CODE_SCHEMA_VIOLATION,
            format!("cx.consent.revoke payload shape is invalid: {err}"),
        )
    })?;
    parsed.validate_minimal().map_err(|err| {
        (
            ERROR_CODE_SCHEMA_VIOLATION,
            format!("cx.consent.revoke payload invariant violation: {err}"),
        )
    })?;
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════
// cx.flow.update / cx.flow.tracks_patch cell metadata.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.15) — cell_subject for `cx.flow.update`. The cell family
/// is `cx.component.flow.metadata.v1` with CAS-register semantics and
/// `bottom=reject`. The subject is the flow_id.
pub fn flow_update_subject(flow_id: &contrix_sdk::FlowId) -> String {
    flow_update_cell_subject(flow_id)
}

/// Round 4 (B1.15) — cell_subject for `cx.flow.tracks_patch`. Same cell
/// family as `cx.flow.update` — they compete via CAS.
pub fn flow_tracks_patch_subject(flow_id: &contrix_sdk::FlowId) -> String {
    flow_tracks_patch_cell_subject(flow_id)
}

// ════════════════════════════════════════════════════════════════════════
// Late key recovery (e2ee_late_recovery) audit access kind.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.16) — build a `cx.audit.policy_access` payload for the
/// late-key-recovery path. `late_recovery_original_event_id` is
/// REQUIRED on this access_kind; the SDK validator catches a missing
/// value but we surface a typed builder for readability.
pub fn build_late_recovery_audit_payload(
    realm_id: RealmId,
    actor: Did,
    original_event_id: EventId,
    observed_at: DateTime<Utc>,
) -> AuditPolicyAccessPayload {
    AuditPolicyAccessPayload {
        realm_id,
        actor,
        access_kind: AccessKind::E2EELateRecovery,
        late_recovery_original_event_id: Some(original_event_id),
        observed_at,
    }
}

// ════════════════════════════════════════════════════════════════════════
// agent_id / applet_id DID validation.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.17) — accept an `agent_id` value. Must be a DID
/// (`did:webvh:...` etc.). Returns the typed DID on success.
pub fn validate_agent_id(value: &str) -> Result<Did, (&'static str, String)> {
    Did::new(value.to_owned()).map_err(|err| {
        (
            ERROR_CODE_SCHEMA_VIOLATION,
            format!("agent_id must be a DID: {err}"),
        )
    })
}

/// Round 4 (B1.17) — accept an `applet_id` value. Must be either a DID
/// or a strictly-validated `cx:applet:<uuidv7>` typed id. Returns the
/// typed wrapper on success.
pub fn validate_applet_id(
    value: &str,
) -> Result<contrix_sdk::AppletIdentifier, (&'static str, String)> {
    // The SDK's `AppletIdentifier` is `enum { Did(Did), Cx(AppletId) }`.
    // We attempt the DID form first (covers `did:webvh:applet.example`
    // and similar), then fall back to the typed `cx:applet:` form.
    if let Ok(did) = Did::new(value.to_owned()) {
        return Ok(contrix_sdk::AppletIdentifier::Did(did));
    }
    if let Ok(applet) = contrix_sdk::AppletId::new(value.to_owned()) {
        return Ok(contrix_sdk::AppletIdentifier::Cx(applet));
    }
    Err((
        ERROR_CODE_SCHEMA_VIOLATION,
        format!("applet_id must be a DID or cx:applet:<uuidv7>: got {value:?}"),
    ))
}

// ════════════════════════════════════════════════════════════════════════
// cx.call.signal v2 validation re-exports.
// ════════════════════════════════════════════════════════════════════════

/// Round 4 (B1.7) — re-export the SDK call.signal envelope validator so
/// soland call sites can use a stable path.
pub use contrix_sdk::validate_call_signal_envelope as validate_call_signal_envelope_v2;

#[cfg(test)]
mod tests {
    use contrix_sdk::identifiers::Cursor;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("cx:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }
    fn td() -> TypedTrustDomainId {
        TypedTrustDomainId::new("cx:trust_domain:soland.local").unwrap()
    }
    fn other_td() -> TypedTrustDomainId {
        TypedTrustDomainId::new("cx:trust_domain:other.example").unwrap()
    }
    fn alice() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }
    fn bob() -> Did {
        Did::new("did:web:bob.example").unwrap()
    }
    fn space() -> SpaceId {
        SpaceId::new("cx:space:01904100-0000-7000-8000-000000000001".to_owned()).unwrap()
    }
    fn event(id: &str) -> EventId {
        EventId::new(id.to_owned()).unwrap()
    }

    #[test]
    fn parse_peer_role_routes_correctly() {
        assert_eq!(
            parse_peer_role(None).unwrap(),
            FrontierPeerRole::AccountClient
        );
        assert_eq!(
            parse_peer_role(Some("federation_peer")).unwrap(),
            FrontierPeerRole::FederationPeer
        );
        assert_eq!(
            parse_peer_role(Some("anonymous_health")).unwrap(),
            FrontierPeerRole::AnonymousHealth
        );
        assert!(parse_peer_role(Some("invalid_role")).is_err());
    }

    #[test]
    fn anonymous_health_response_omits_receipts_and_actor_bounds() {
        let frontier = build_typed_frontier_response(
            FrontierPeerRole::AnonymousHealth,
            &alice(),
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::from_iter(vec![(bob(), 99)]),
            None,
        );
        match frontier {
            EventsFrontierResponse::AnonymousHealth(_) => {}
            other => panic!("expected anonymous_health variant, got {:?}", other),
        }
        // The serialised value MUST NOT carry actor_seq_upper_bounds /
        // receipts / signatures.
        let json = serde_json::to_value(&frontier).unwrap();
        assert!(json.get("actor_seq_upper_bounds").is_none());
        assert!(json.get("receipts").is_none());
        assert!(json.get("signatures").is_none());
    }

    #[test]
    fn federation_frontier_root_is_order_stable() {
        let mut frontier_a = BTreeMap::new();
        frontier_a.insert(
            space(),
            vec![
                event("cx:event:01904100-0000-7000-8000-000000000002"),
                event("cx:event:01904100-0000-7000-8000-000000000001"),
            ],
        );
        let mut frontier_b = BTreeMap::new();
        frontier_b.insert(
            space(),
            vec![
                event("cx:event:01904100-0000-7000-8000-000000000001"),
                event("cx:event:01904100-0000-7000-8000-000000000002"),
            ],
        );
        let actors = BTreeMap::from_iter(vec![(alice(), 7), (bob(), 3)]);

        let root_a = frontier_root(&frontier_a, &actors).unwrap();
        let root_b = frontier_root(&frontier_b, &actors).unwrap();
        assert_eq!(root_a, root_b);
        assert_ne!(
            root_a.as_str(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn federation_frontier_signature_binds_root_tuple() {
        let mut frontier = BTreeMap::new();
        frontier.insert(
            space(),
            vec![event("cx:event:01904100-0000-7000-8000-000000000001")],
        );
        let actors = BTreeMap::from_iter(vec![(alice(), 7)]);
        let root = frontier_root(&frontier, &actors).unwrap();
        let observed_at = chrono::DateTime::parse_from_rfc3339("2026-05-20T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);

        let signature =
            sign_frontier_root(&alice(), Some(&realm()), observed_at, &root, &signing_key).unwrap();
        assert_eq!(signature["alg"], "EdDSA");
        assert_eq!(
            signature["verification_method"],
            "did:web:alice.example#frontier-key"
        );
        assert!(
            signature["jws"]
                .as_str()
                .is_some_and(|jws| jws.contains(".."))
        );
        assert_eq!(signature["signed_payload"]["frontier_root"], root.as_str());
        assert_eq!(
            signature["signed_payload"]["realm_id"],
            "cx:realm:01904100-0000-7000-8000-000000000001"
        );

        let bytes = canonical::canonical_json_bytes(&signature["signed_payload"]).unwrap();
        assert_eq!(
            signature["payload_digest"],
            canonical::sha256_digest(&bytes)
        );
    }

    #[test]
    fn federation_peer_response_carries_root_binding_and_signature() {
        let mut frontier = BTreeMap::new();
        frontier.insert(
            space(),
            vec![event("cx:event:01904100-0000-7000-8000-000000000001")],
        );
        let actors = BTreeMap::from_iter(vec![(alice(), 7)]);
        let root = frontier_root(&frontier, &actors).unwrap();
        let service_binding_ref = frontier_service_binding_ref(&realm(), &frontier, &actors)
            .expect("frontier binding builds");
        let signature = json!({
            "payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });

        let response = build_typed_frontier_response(
            FrontierPeerRole::FederationPeer,
            &alice(),
            frontier,
            actors,
            Some(FederationFrontierBinding {
                service_binding_ref,
                frontier_root: root.clone(),
                receipts: Vec::new(),
                signatures: vec![signature.clone()],
            }),
        );
        let EventsFrontierResponse::FederationPeer(peer) = response else {
            panic!("expected federation_peer response");
        };
        assert_eq!(peer.frontier_root, root);
        assert_eq!(peer.signatures, vec![signature]);
        assert_eq!(peer.service_binding_ref.membership_frontier.len(), 1);
    }

    #[test]
    fn dropped_without_cursor_downgrades_to_resync() {
        let body = dropped_or_resync(None, "broadcast_lag", Some(10_000));
        assert!(matches!(
            body,
            EventsSubscribeFrameBody::ResyncRequired { .. }
        ));
        let cursor = Cursor::new("cx:cursor:resume").unwrap();
        let body = dropped_or_resync(Some(cursor), "broadcast_lag", Some(10_000));
        assert!(matches!(
            body,
            EventsSubscribeFrameBody::Dropped {
                reconnect_after_ms: Some(10_000),
                ..
            }
        ));
    }

    #[test]
    fn events_submit_shape_classifies_three_forms() {
        let single = json!({"event_id": "x"});
        let batch = json!({"events": []});
        let federation = json!({"events": [], "service_binding_ref": {"realm_id": "x"}});
        assert_eq!(EventsSubmitRequest::shape(&single), "single");
        assert_eq!(EventsSubmitRequest::shape(&batch), "batch");
        assert_eq!(EventsSubmitRequest::shape(&federation), "federation");
    }

    #[test]
    fn federation_binding_rejects_duplicate_frontier_entries() {
        let req = EventsSubmitFederationRequest {
            service_binding_ref: FederationServiceBindingRef {
                realm_id: realm(),
                space_policy_hash: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
                membership_frontier: vec![
                    EventId::new("cx:event:01904100-0000-7000-8000-000000000001").unwrap(),
                    EventId::new("cx:event:01904100-0000-7000-8000-000000000001").unwrap(),
                ],
                delivery_binding_frontier: Vec::new(),
                destination_service_type: "principal_server".to_owned(),
                reducer_profile_digest: Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
            },
            events: Vec::new(),
            idempotency_key: None,
        };
        let err = EventsSubmitRequest::validate_federation_binding(&req).unwrap_err();
        assert_eq!(err.0, ERROR_CODE_SCHEMA_VIOLATION);
    }

    #[test]
    fn federation_idempotency_strict_key_changes_with_key_state_digest() {
        let mut key = FederationIdempotencyKey {
            source_did: "did:web:alice.example".to_owned(),
            dest_did: "did:web:bob.example".to_owned(),
            request_canonical_digest: "sha256:abc".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            origin_key_state_digest: "sha256:state-A".to_owned(),
        };
        let strict_a = key.strict();
        let replay_a = key.canonical_replay();
        key.origin_key_state_digest = "sha256:state-B".to_owned();
        let strict_b = key.strict();
        let replay_b = key.canonical_replay();
        // Strict key differs after key state advances.
        assert_ne!(strict_a, strict_b);
        // Canonical-replay key stays stable across key-state changes.
        assert_eq!(replay_a, replay_b);
    }

    #[test]
    fn historical_only_marker_set() {
        let response = mark_response_historical_only(json!({"ok": true}));
        assert_eq!(
            response.get("reason_code").and_then(Value::as_str),
            Some(ERROR_CODE_HISTORICAL_ONLY)
        );
        assert_eq!(
            response.get("historical_only").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn delivery_binding_stale_response_carries_new_service_and_frontier() {
        let response = delivery_binding_stale_response(
            &bob(),
            &[EventId::new("cx:event:01904100-0000-7000-8000-000000000001").unwrap()],
        );
        assert_eq!(
            response.pointer("/error/code").and_then(Value::as_str),
            Some(ERROR_CODE_DELIVERY_BINDING_STALE)
        );
        assert_eq!(
            response
                .pointer("/error/details/new_recipient_service_did")
                .and_then(Value::as_str),
            Some("did:web:bob.example")
        );
    }

    #[test]
    fn cross_signing_publish_cas_check_requires_exact_increment() {
        cross_signing_publish_cas_check(5, 5, 6).unwrap();
        // Wrong previous → cas_conflict.
        assert!(cross_signing_publish_cas_check(5, 4, 6).is_err());
        // Wrong new (skip) → schema_violation.
        assert!(cross_signing_publish_cas_check(5, 5, 7).is_err());
        // Same generation → schema_violation.
        assert!(cross_signing_publish_cas_check(5, 5, 5).is_err());
    }

    #[test]
    fn blob_presign_realm_binding_mismatch_rejects() {
        verify_blob_presign_realm_binding(None, None).unwrap();
        verify_blob_presign_realm_binding(Some("cx:realm:abc"), Some("cx:realm:abc")).unwrap();
        // Blob has realm, request doesn't → schema_violation.
        assert!(verify_blob_presign_realm_binding(None, Some("cx:realm:abc")).is_err());
        // Blob has realm but mismatched → capability_denied.
        let err = verify_blob_presign_realm_binding(Some("cx:realm:abc"), Some("cx:realm:def"))
            .unwrap_err();
        assert_eq!(err.0, "capability_denied");
    }

    #[test]
    fn audit_policy_version_digest_domain_separates() {
        let h1 = compute_audit_policy_hash(
            &realm(),
            &td(),
            &json!({"mode": "strict"}),
            &json!("attested_hardware"),
        );
        let h2 = compute_audit_policy_hash(
            &realm(),
            &other_td(),
            &json!({"mode": "strict"}),
            &json!("attested_hardware"),
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn space_state_transition_accepts_typed_shape() {
        parse_space_state_transition_payload(&json!({
            "space_id": "cx:space:01904100-0000-7000-8000-000000000001",
            "new_state": "archived",
            "reason": "stale",
        }))
        .unwrap();
    }

    #[test]
    fn consent_revoke_empty_observed_dots_rejected() {
        let err = validate_consent_revoke_payload(&json!({
            "consent_id": "cid",
            "peer": "did:web:bob.example",
            "scope": "invite",
            "observed_dots": [],
        }))
        .unwrap_err();
        assert_eq!(err.0, ERROR_CODE_SCHEMA_VIOLATION);
    }

    #[test]
    fn consent_revoke_accepts_non_empty_observed_dots() {
        validate_consent_revoke_payload(&json!({
            "consent_id": "cid",
            "peer": "did:web:bob.example",
            "scope": "invite",
            "observed_dots": [
                {"actor_id": "did:web:alice.example", "actor_seq": 1}
            ],
        }))
        .unwrap();
    }

    #[test]
    fn agent_id_must_be_did() {
        assert!(validate_agent_id("did:web:agent.example").is_ok());
        // Non-DID must reject.
        assert!(validate_agent_id("cx:agent:01904100-0000-7000-8000-000000000001").is_err());
    }

    #[test]
    fn applet_id_accepts_did_or_cx_form() {
        assert!(validate_applet_id("did:web:applet.example").is_ok());
        assert!(validate_applet_id("cx:applet:01904100-0000-7000-8000-000000000001").is_ok());
        assert!(validate_applet_id("not-a-valid-id").is_err());
    }

    #[test]
    fn late_recovery_audit_payload_populates_event_id() {
        let payload = build_late_recovery_audit_payload(
            realm(),
            alice(),
            EventId::new("cx:event:01904100-0000-7000-8000-000000000001").unwrap(),
            Utc::now(),
        );
        assert!(matches!(payload.access_kind, AccessKind::E2EELateRecovery));
        assert!(payload.late_recovery_original_event_id.is_some());
        payload.validate_minimal().unwrap();
    }

    #[test]
    fn flow_cell_subject_helpers_return_flow_id() {
        let flow =
            contrix_sdk::FlowId::new("cx:flow:01904100-0000-7000-8000-000000000001").unwrap();
        assert_eq!(flow_update_subject(&flow), flow.as_str());
        assert_eq!(flow_tracks_patch_subject(&flow), flow.as_str());
    }
}
