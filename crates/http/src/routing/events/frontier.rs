//! Federation frontier root and signature helpers for `/_arkret/peer/events/frontier`.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical as canonical;
use arkret_identifiers::{Did, EventId, Hash, RealmId};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

/// Convert a per-realm frontier table to the typed
/// `BTreeMap<RealmId, Vec<EventId>>` shape. Entries whose ids fail SDK
/// typed-id parsing are dropped so one malformed row does not break the
/// whole introspection response.
pub(crate) fn typed_realm_frontier(
    realm_to_event_ids: impl IntoIterator<Item = (String, Vec<String>)>,
) -> BTreeMap<RealmId, Vec<EventId>> {
    let mut out = BTreeMap::new();
    for (realm, events) in realm_to_event_ids {
        let Ok(realm_id) = RealmId::new(realm) else {
            continue;
        };
        let typed_events = events
            .into_iter()
            .filter_map(|id| EventId::new(id).ok())
            .collect::<Vec<_>>();
        if !typed_events.is_empty() {
            out.insert(realm_id, typed_events);
        }
    }
    out
}

/// Convert the actor -> seq upper bound table to the typed
/// `BTreeMap<Did, u64>` shape.
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

/// Compute the deterministic frontier root over current Event heads and
/// sorted per-actor seq upper bounds. Each leaf is domain-separated before
/// being folded into a binary Merkle tree.
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
            "domain": "ak.events.frontier.leaf.v1",
            "kind": "head",
            "event_id": event_id,
        }))?);
    }
    for (actor, seq) in actor_upper_bounds {
        leaves.push(canonical_hash(&json!({
            "domain": "ak.events.frontier.leaf.v1",
            "kind": "actor_seq_upper_bound",
            "actor_id": actor.as_str(),
            "actor_seq": seq,
        }))?);
    }

    if leaves.is_empty() {
        return canonical_hash(&json!({
            "domain": "ak.events.frontier.root.v1",
            "empty": true,
        }));
    }

    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(canonical_hash(&json!({
                "domain": "ak.events.frontier.node.v1",
                "left": pair[0].as_str(),
                "right": right.as_str(),
            }))?);
        }
        leaves = next;
    }
    Ok(leaves.remove(0))
}

/// Canonical payload signed by the issuing service for a federation frontier
/// probe. The signature binds only the root plus `(realm_id, issuer,
/// observed_at)` so peers can compare roots without replaying the whole
/// frontier body.
pub(crate) fn frontier_signature_payload(
    realm_id: Option<&RealmId>,
    issuer: &Did,
    observed_at: DateTime<Utc>,
    frontier_root: &Hash,
) -> Value {
    json!({
        "domain": "ak.events.frontier.signature.v1",
        "frontier_root": frontier_root.as_str(),
        "realm_id": realm_id.map(RealmId::as_str),
        "issuer": issuer.as_str(),
        "observed_at": arkret_canonical::format_timestamp_canonical(observed_at),
    })
}

/// Build an Ed25519 detached-JWS signature envelope for the canonical
/// frontier signature payload.
pub(crate) fn sign_frontier_root(
    service_id: &Did,
    realm_id: Option<&RealmId>,
    observed_at: DateTime<Utc>,
    frontier_root: &Hash,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<Value, String> {
    let signed_payload =
        frontier_signature_payload(realm_id, service_id, observed_at, frontier_root);
    let canonical_bytes =
        canonical::canonical_json_bytes(&signed_payload).map_err(|error| error.to_string())?;
    let payload_digest = canonical::sha256_digest(&canonical_bytes);
    let jws = arkret_signatures::jws::sign_jws_ed25519(&canonical_bytes, signing_key)
        .map_err(|error| error.to_string())?;

    Ok(json!({
        "typ": "ak.events.frontier.signature.v1",
        "scheme": "ed25519-detached-jws",
        "verification_method": format!("{}#frontier-key", service_id.as_str()),
        "payload_digest": payload_digest,
        "created_at": arkret_canonical::format_timestamp_canonical(observed_at),
        "jws": jws,
        "signed_payload": signed_payload,
    }))
}

fn canonical_hash(value: &Value) -> Result<Hash, String> {
    let digest = canonical::canonical_sha256(value).map_err(|error| error.to_string())?;
    Hash::new(digest).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K").unwrap()
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
    fn federation_frontier_root_is_order_stable() {
        let mut frontier_a = BTreeMap::new();
        frontier_a.insert(
            realm(),
            vec![
                event("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"),
                event("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"),
            ],
        );
        let mut frontier_b = BTreeMap::new();
        frontier_b.insert(
            realm(),
            vec![
                event("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"),
                event("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"),
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
            vec![event(
                "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )],
        );
        let actors = BTreeMap::from_iter(vec![(alice(), 7)]);
        let root = frontier_root(&frontier, &actors).unwrap();
        let observed_at = chrono::DateTime::parse_from_rfc3339("2026-05-20T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);

        let signature =
            sign_frontier_root(&alice(), Some(&realm()), observed_at, &root, &signing_key).unwrap();
        assert!(signature.get("alg").is_none());
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
            "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K"
        );

        let bytes = canonical::canonical_json_bytes(&signature["signed_payload"]).unwrap();
        assert_eq!(
            signature["payload_digest"],
            canonical::sha256_digest(&bytes)
        );
    }
}
