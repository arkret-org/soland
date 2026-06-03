//! Typed `/_cokret/self/events/frontier` response builder + federation frontier
//! root / signature helpers (spec B1.4, federation.md §4.5.1).
//!
//! `peer_role` routes the frontier read to one of three typed responses —
//! `account_client` / `federation_peer` / `anonymous_health`. The
//! `anonymous_health` form MUST NOT carry receipts or
//! actor_seq_upper_bounds (the type system enforces this).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use cokret_sdk::{
    Did, EventId, EventsFrontierAccountClientResponse, EventsFrontierAnonymousHealthResponse,
    EventsFrontierFederationPeerResponse, EventsFrontierResponse, FederationServiceBindingRef,
    FrontierPeerRole, Hash, RealmId, canonical,
};
use serde_json::{Value, json};

/// Spec B1.4 — peer-role discriminator parsing. Returns the typed
/// [`FrontierPeerRole`] for the three canonical values (defaulting to
/// `account_client` when absent); returns `Err(reason)` for an
/// unrecognised value (caller surfaces as `invalid_param`).
pub(crate) fn parse_peer_role(value: Option<&str>) -> Result<FrontierPeerRole, &'static str> {
    match value.unwrap_or("account_client") {
        "account_client" => Ok(FrontierPeerRole::AccountClient),
        "federation_peer" => Ok(FrontierPeerRole::FederationPeer),
        "anonymous_health" => Ok(FrontierPeerRole::AnonymousHealth),
        _ => Err("peer_role must be account_client / federation_peer / anonymous_health"),
    }
}

/// Spec B1.4 — convert a per-realm frontier table to the typed
/// `BTreeMap<RealmId, Vec<EventId>>` shape. Entries whose ids fail SDK
/// typed-id parsing are silently dropped — this is the server's
/// introspection surface, not the canonical persistence layer, so a single
/// malformed row should not break the whole response.
pub(crate) fn typed_realm_frontier(
    realm_to_event_ids: impl IntoIterator<Item = (String, Vec<String>)>,
) -> BTreeMap<RealmId, Vec<EventId>> {
    let mut out = BTreeMap::new();
    for (realm, events) in realm_to_event_ids {
        let Ok(realm_id) = RealmId::new(realm) else {
            continue;
        };
        let typed_events: Vec<EventId> = events
            .into_iter()
            .filter_map(|id| EventId::new(id).ok())
            .collect();
        if !typed_events.is_empty() {
            out.insert(realm_id, typed_events);
        }
    }
    out
}

/// Spec B1.4 — convert the actor → seq upper bound table to the typed
/// `BTreeMap<Did, u64>` shape. Entries whose actor strings fail `Did::new`
/// are silently dropped (same rationale as [`typed_realm_frontier`]).
pub(crate) fn typed_actor_upper_bounds(
    actor_to_seq: impl IntoIterator<Item = (String, u64)>,
) -> BTreeMap<Did, u64> {
    let mut out = BTreeMap::new();
    for (actor, seq) in actor_to_seq {
        if let Ok(did) = Did::new(actor) {
            out.insert(did, seq);
        }
    }
    out
}

/// Frontier-derived federation binding reference carried on
/// `peer_role=federation_peer`.
#[derive(Debug, Clone)]
pub(crate) struct FederationFrontierBinding {
    pub service_binding_ref: FederationServiceBindingRef,
    pub frontier_root: Hash,
    pub receipts: Vec<Value>,
    pub signatures: Vec<Value>,
}

/// Spec B1.4 — build the typed [`EventsFrontierResponse`] for a
/// `peer_role`.
///
/// `anonymous_health` MUST NOT carry receipts or actor_seq_upper_bounds —
/// the type signature enforces this.
pub(crate) fn build_typed_frontier_response(
    peer_role: FrontierPeerRole,
    service_did: &Did,
    // NOTE: 该 map 承载的是 Realm 级 frontier(键为 `ck:realm:`)。SDK 的 key 类型
    // 是合并后的边界键 `RealmId`(同时接受 `ck:realm:` / `ck:space:`)。
    realm_frontier: BTreeMap<RealmId, Vec<EventId>>,
    actor_upper_bounds: BTreeMap<Did, u64>,
    federation_binding: Option<FederationFrontierBinding>,
) -> EventsFrontierResponse {
    match peer_role {
        FrontierPeerRole::AccountClient => {
            EventsFrontierResponse::AccountClient(EventsFrontierAccountClientResponse {
                peer_role,
                frontier: realm_frontier,
                actor_seq_upper_bounds: actor_upper_bounds,
            })
        }
        FrontierPeerRole::FederationPeer => {
            let binding = federation_binding.unwrap_or_else(|| {
                fallback_federation_frontier_binding(&realm_frontier, &actor_upper_bounds)
            });
            EventsFrontierResponse::FederationPeer(EventsFrontierFederationPeerResponse {
                peer_role,
                frontier: realm_frontier,
                frontier_root: binding.frontier_root,
                service_binding_ref: binding.service_binding_ref,
                receipts: binding.receipts,
                signatures: binding.signatures,
                actor_seq_upper_bounds: actor_upper_bounds,
            })
        }
        FrontierPeerRole::AnonymousHealth => {
            // anonymous_health is a public health probe; type enforces no
            // receipts / upper bounds / per-space frontier are exposed. We
            // only return a yes/no health summary + the service DID + a
            // timestamp for staleness detection.
            EventsFrontierResponse::AnonymousHealth(EventsFrontierAnonymousHealthResponse {
                peer_role,
                service_did: service_did.clone(),
                healthy: true,
                generated_at: Utc::now(),
            })
        }
    }
}

/// Spec B1.4 / federation.md §4.5.1 — compute the deterministic frontier
/// root over the current event heads and sorted per-actor seq upper bounds.
/// Each leaf is first canonical-JSON hashed with a domain tag, then folded
/// as a binary Merkle tree using canonical node JSON. The empty frontier
/// still has a stable non-zero domain-separated root.
pub(crate) fn frontier_root(
    realm_frontier: &BTreeMap<RealmId, Vec<EventId>>,
    actor_upper_bounds: &BTreeMap<Did, u64>,
) -> Result<Hash, String> {
    let mut heads = BTreeSet::new();
    for events in realm_frontier.values() {
        for event in events {
            heads.insert(event.as_str().to_owned());
        }
    }

    let mut leaves = Vec::new();
    for event_id in heads {
        leaves.push(canonical_hash(&json!({
            "domain": "ck.events.frontier.leaf.v1",
            "kind": "head",
            "event_id": event_id,
        }))?);
    }
    for (actor, seq) in actor_upper_bounds {
        leaves.push(canonical_hash(&json!({
            "domain": "ck.events.frontier.leaf.v1",
            "kind": "actor_seq_upper_bound",
            "actor_id": actor.as_str(),
            "actor_seq": seq,
        }))?);
    }

    if leaves.is_empty() {
        return canonical_hash(&json!({
            "domain": "ck.events.frontier.root.v1",
            "empty": true,
        }));
    }

    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(canonical_hash(&json!({
                "domain": "ck.events.frontier.node.v1",
                "left": pair[0].as_str(),
                "right": right.as_str(),
            }))?);
        }
        leaves = next;
    }
    Ok(leaves.remove(0))
}

/// Build the frontier-derived federation binding reference carried on
/// `peer_role=federation_peer`.
pub(crate) fn frontier_service_binding_ref(
    realm_id: &RealmId,
    realm_frontier: &BTreeMap<RealmId, Vec<EventId>>,
    actor_upper_bounds: &BTreeMap<Did, u64>,
) -> Result<FederationServiceBindingRef, String> {
    let heads = frontier_heads(realm_frontier);
    let space_policy_hash = canonical_hash(&json!({
        "domain": "ck.events.frontier.space_policy_hash.v1",
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
        "domain": "ck.events.frontier.reducer_profile.v1",
        "profile": "ck.reducer.v1",
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
/// frontier probe. Per federation.md §4.5.1 the signature covers only the
/// root plus `(realm_id, issuer, observed_at)` so peers can compare roots
/// without replaying the whole frontier body.
pub(crate) fn frontier_signature_payload(
    realm_id: Option<&RealmId>,
    issuer: &Did,
    observed_at: DateTime<Utc>,
    frontier_root: &Hash,
) -> Value {
    json!({
        "domain": "ck.events.frontier.signature.v1",
        "frontier_root": frontier_root.as_str(),
        "realm_id": realm_id.map(RealmId::as_str),
        "issuer": issuer.as_str(),
        "observed_at": observed_at.to_rfc3339(),
    })
}

/// Build an Ed25519 detached-JWS signature envelope for the canonical
/// frontier signature payload.
pub(crate) fn sign_frontier_root(
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
    let jws = cokret_sdk::jws::sign_jws_ed25519(&canonical_bytes, signing_key)
        .map_err(|error| error.to_string())?;

    Ok(json!({
        "alg": "EdDSA",
        "typ": "ck.events.frontier.signature.v1",
        "scheme": "ed25519-detached-jws",
        "verification_method": format!("{}#frontier-key", service_did.as_str()),
        "payload_digest": payload_digest,
        "created_at": observed_at.to_rfc3339(),
        "jws": jws,
        "signed_payload": signed_payload,
    }))
}

fn frontier_heads(realm_frontier: &BTreeMap<RealmId, Vec<EventId>>) -> Vec<EventId> {
    let mut heads: BTreeMap<&str, &EventId> = BTreeMap::new();
    for events in realm_frontier.values() {
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
    realm_frontier: &BTreeMap<RealmId, Vec<EventId>>,
    actor_upper_bounds: &BTreeMap<Did, u64>,
) -> FederationFrontierBinding {
    let realm_id = RealmId::new("ck:realm:00000000-0000-7000-8000-000000000000".to_owned())
        .expect("built-in fallback realm id is valid");
    let frontier_root = frontier_root(realm_frontier, actor_upper_bounds)
        .expect("frontier root over typed ids must canonicalize");
    let service_binding_ref =
        frontier_service_binding_ref(&realm_id, realm_frontier, actor_upper_bounds)
            .expect("frontier-derived binding must canonicalize");
    FederationFrontierBinding {
        service_binding_ref,
        frontier_root,
        receipts: Vec::new(),
        signatures: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use cokret_sdk::TypedTrustDomainId;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }
    fn alice() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }
    fn bob() -> Did {
        Did::new("did:web:bob.example").unwrap()
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
            BTreeMap::new(),
            BTreeMap::from_iter(vec![(bob(), 99)]),
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
            realm(),
            vec![
                event("ck:event:01904100-0000-7000-8000-000000000002"),
                event("ck:event:01904100-0000-7000-8000-000000000001"),
            ],
        );
        let mut frontier_b = BTreeMap::new();
        frontier_b.insert(
            realm(),
            vec![
                event("ck:event:01904100-0000-7000-8000-000000000001"),
                event("ck:event:01904100-0000-7000-8000-000000000002"),
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
            realm(),
            vec![event("ck:event:01904100-0000-7000-8000-000000000001")],
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
            "ck:realm:01904100-0000-7000-8000-000000000001"
        );

        let bytes = canonical::canonical_json_bytes(&signature["signed_payload"]).unwrap();
        assert_eq!(
            signature["payload_digest"],
            canonical::sha256_digest(&bytes)
        );
        // Keep TypedTrustDomainId import exercised for parity with the
        // federation suite fixtures.
        let _ = TypedTrustDomainId::new("ck:trust_domain:soland.local").unwrap();
    }

    #[test]
    fn federation_peer_response_carries_root_binding_and_signature() {
        let mut frontier = BTreeMap::new();
        frontier.insert(
            realm(),
            vec![event("ck:event:01904100-0000-7000-8000-000000000001")],
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
}
