//! Federation frontier root and signature helpers for `/_arkret/peer/events/frontier`.

use std::collections::BTreeMap;

use arkret_canonical as canonical;
use arkret_identifiers::{EventId, Hash, RealmId};
use arkret_wire::ActorId;
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
/// `BTreeMap<ActorId, u64>` shape. Stored identities must already be canonical;
/// corrupt or legacy rows must never disappear from a signed commitment.
pub(crate) fn typed_actor_upper_bounds(
    actor_to_seq: impl IntoIterator<Item = (String, u64)>,
) -> Result<BTreeMap<ActorId, u64>, String> {
    let mut out = BTreeMap::new();
    for (actor, seq) in actor_to_seq {
        let actor_id: ActorId = serde_json::from_str(&actor)
            .map_err(|error| format!("stored frontier actor_id is invalid: {error}"))?;
        if actor_id
            .canonical_key()
            .map_err(|error| error.to_string())?
            != actor
        {
            return Err("stored frontier actor_id is noncanonical".to_owned());
        }
        if out.insert(actor_id, seq).is_some() {
            return Err("duplicate stored frontier actor_id".to_owned());
        }
    }
    Ok(out)
}

/// Compute the deterministic frontier root over current Event heads and
/// sorted per-actor seq upper bounds. Each leaf is domain-separated before
/// being folded into a binary Merkle tree.
pub(crate) fn frontier_root(
    realm_frontier: &BTreeMap<RealmId, Vec<EventId>>,
    actor_upper_bounds: &BTreeMap<ActorId, u64>,
) -> Result<Hash, String> {
    let heads = realm_frontier
        .values()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    let leaves = arkret_models_collaboration::event_sync::federation_frontier_leaf_data(
        &heads,
        actor_upper_bounds,
    )
    .map_err(|error| error.to_string())?;
    arkret_state::state::state_root::seal_merkle_root_from_leaf_data(
        &leaves,
        canonical::DigestSuite::Sha256,
    )
    .map_err(|error| error.to_string())
}

/// Sign the SDK-owned transcript using an actual published assertion method.
pub(crate) fn sign_frontier_root(
    frontier: &arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState,
    verification_method: &arkret_wire::DidUrl,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<BTreeMap<String, Value>, String> {
    let signed_payload = frontier
        .signature_payload()
        .map_err(|error| error.to_string())?;
    let canonical_bytes =
        canonical::canonical_json_bytes(&signed_payload).map_err(|error| error.to_string())?;
    let payload_digest = canonical::sha256_digest(&canonical_bytes);
    let jws = arkret_signatures::jws::sign_jws_ed25519(&canonical_bytes, signing_key)
        .map_err(|error| error.to_string())?;
    let envelope = json!({
        "typ": arkret_wire::DomainSeparationId::EVENTS_FRONTIER_SIGNATURE_V1,
        "scheme": "ed25519-detached-jws",
        "verification_method": verification_method,
        "payload_digest": payload_digest,
        "created_at": frontier.observed_at,
        "jws": jws,
        "signed_payload": signed_payload,
    });
    serde_json::from_value(envelope).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{Did, DidCoreId};
    use chrono::Utc;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K").unwrap()
    }

    fn alice() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    fn alice_core() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:alice.example").unwrap()
    }

    fn bob_core() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:bob.example").unwrap()
    }

    fn account_actor(principal_id: DidCoreId, station: &str) -> ActorId {
        ActorId::account(arkret_wire::AccountId::new(
            principal_id,
            DidCoreId::new(station).unwrap(),
        ))
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
        let actors = BTreeMap::from_iter(vec![
            (account_actor(alice_core(), "ak:did_core:web:a.example"), 7),
            (account_actor(bob_core(), "ak:did_core:web:b.example"), 3),
        ]);

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
        let actors = BTreeMap::from_iter(vec![(
            account_actor(alice_core(), "ak:did_core:web:a.example"),
            7,
        )]);
        let root = frontier_root(&frontier, &actors).unwrap();
        let observed_at = chrono::DateTime::parse_from_rfc3339("2026-05-20T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);

        let auth_root = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let policy_root = Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap();
        let membership_root = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        let response = arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState {
            realm_id: realm(),
            head_ids: frontier[&realm()].clone(),
            max_hlc: Some("01970e589d21-0004-a13f9c2e".to_owned()),
            frontier_root: root.clone(),
            auth_state_root: Some(auth_root.clone()),
            policy_frontier_root: Some(policy_root.clone()),
            membership_frontier_root: Some(membership_root.clone()),
            actor_seq_upper_bounds: actors,
            witness_receipts: vec![],
            observed_at: canonical::format_timestamp_canonical(observed_at),
            issuer_id: alice_core(),
            signature: BTreeMap::new(),
        };
        let method = arkret_wire::DidUrl::new(format!("{}#service-key", alice())).unwrap();
        let signature =
            serde_json::to_value(sign_frontier_root(&response, &method, &signing_key).unwrap())
                .unwrap();
        assert!(signature.get("alg").is_none());
        assert_eq!(
            signature["verification_method"],
            "did:web:alice.example#service-key"
        );
        assert!(
            signature["jws"]
                .as_str()
                .is_some_and(|jws| jws.contains(".."))
        );
        assert_eq!(signature["signed_payload"]["frontier_root"], root.as_str());
        assert_eq!(
            signature["signed_payload"]["max_hlc"],
            response.max_hlc.unwrap()
        );
        assert_eq!(
            signature["signed_payload"]["auth_state_root"],
            auth_root.as_str()
        );
        assert_eq!(
            signature["signed_payload"]["policy_frontier_root"],
            policy_root.as_str()
        );
        assert_eq!(
            signature["signed_payload"]["membership_frontier_root"],
            membership_root.as_str()
        );
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

    #[test]
    fn federation_frontier_root_matches_seal_family_full_actor_kat() {
        let first = account_actor(alice_core(), "ak:did_core:web:a.example");
        let second = account_actor(alice_core(), "ak:did_core:web:b.example");
        let actors = BTreeMap::from([(first.clone(), 7), (second.clone(), 3)]);
        let heads = BTreeMap::from([(
            realm(),
            vec![EventId::from_digest(
                canonical::DigestSuite::Sha256,
                [0x42; 32],
            )],
        )]);
        // Independently computed from the three literal SDK leaf preimages:
        // SHA256(01 || SHA256(01 || H(00||actorA) || H(00||actorB)) || H(00||head)).
        assert_eq!(
            frontier_root(&heads, &actors).unwrap().as_str(),
            "sha256:8fa858b5b5a9417816f284625650c12ead84a03c6a4dec21e3cba8f3bea92da5"
        );
        assert_eq!(
            frontier_root(&BTreeMap::new(), &BTreeMap::from([(first.clone(), 7)]))
                .unwrap()
                .as_str(),
            "sha256:632e8690f4ad1b5cfe108bc8ffd80ff7c3b7e779959f235c5bd6639322506b6a"
        );
        assert_eq!(
            frontier_root(&BTreeMap::new(), &BTreeMap::new())
                .unwrap()
                .as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut changed = actors.clone();
        changed.insert(second, 4);
        assert_ne!(
            frontier_root(&heads, &changed).unwrap(),
            frontier_root(&heads, &actors).unwrap()
        );
        changed.remove(&first);
        assert_ne!(
            frontier_root(&heads, &changed).unwrap(),
            frontier_root(&heads, &actors).unwrap()
        );
    }

    #[test]
    fn federation_frontier_actor_conversion_rejects_silent_loss() {
        let first = account_actor(alice_core(), "ak:did_core:web:a.example");
        let second = account_actor(alice_core(), "ak:did_core:web:b.example");
        let bounds =
            typed_actor_upper_bounds([(first.to_string(), 7), (second.to_string(), 3)]).unwrap();
        assert_eq!(bounds.len(), 2);
        assert_eq!(bounds[&first], 7);
        assert_eq!(bounds[&second], 3);
        assert!(typed_actor_upper_bounds([(alice_core().to_string(), 7)]).is_err());
        assert!(typed_actor_upper_bounds([(format!(" {first}"), 7)]).is_err());
        assert!(
            typed_actor_upper_bounds([(first.to_string(), 7), (first.to_string(), 8)]).is_err()
        );
    }
}
