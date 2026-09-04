use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState;
use arkret_wire::ActorId;
use soland_services::events::AcceptedEvent;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReductionPlan {
    Equal,
    Disjoint,
    Challenge(Vec<ActorId>),
}

/// Both inputs are immutable. Only a locally verified policy may populate
/// required actors; a remote assertion never establishes disclosure authority.
pub(super) fn plan(
    local: &[AcceptedEvent],
    visible: &[AcceptedEvent],
    remote: &EventsFrontierFederationPeerState,
    required: &BTreeSet<String>,
) -> Result<ReductionPlan, String> {
    let disclosed = remote
        .actor_seq_upper_bounds
        .keys()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if !required.is_subset(&disclosed) {
        return Err("schema_violation:required_actor_omitted".to_owned());
    }
    if super::frontier_exchange::local_frontier_root(visible, remote.realm_id.as_str())?
        == remote.frontier_root.as_str()
    {
        return Ok(ReductionPlan::Equal);
    }
    let local_actors = local
        .iter()
        .filter(|record| record.realm_id.as_deref() == Some(remote.realm_id.as_str()))
        .map(|record| record.actor_id.as_str())
        .collect::<BTreeSet<_>>();
    let actors = remote
        .actor_seq_upper_bounds
        .keys()
        .filter(|actor| local_actors.contains(actor.to_string().as_str()))
        .cloned()
        .collect::<Vec<_>>();
    Ok(if actors.is_empty() {
        ReductionPlan::Disjoint
    } else {
        ReductionPlan::Challenge(actors)
    })
}

/// Canonical sibling sets contain every accepted sibling, without selecting a
/// winner or assuming that different disclosure scopes eventually become equal.
pub(super) fn sibling_sets(
    records: &[AcceptedEvent],
    realm_id: &str,
    actors: &BTreeSet<String>,
) -> Result<BTreeMap<(String, u64), BTreeSet<(String, String, String)>>, String> {
    let mut sets: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
    for record in records.iter().filter(|record| {
        record.realm_id.as_deref() == Some(realm_id) && actors.contains(&record.actor_id)
    }) {
        let event: arkret_wire::Event = serde_json::from_value(record.envelope.clone())
            .map_err(|error| format!("stored_event_invalid:{error}"))?;
        let prev = arkret_wire::prev_frontier_digest(&event.prev_refs)
            .map_err(|error| error.to_string())?;
        sets.entry((record.actor_id.clone(), record.actor_seq))
            .or_default()
            .insert((
                record.event_id.clone(),
                record.canonical_digest.clone(),
                prev,
            ));
    }
    Ok(sets)
}

pub(super) fn snapshot_changed(
    before: &[AcceptedEvent],
    after: &[AcceptedEvent],
    admitted: &BTreeSet<String>,
    realm_id: &str,
) -> bool {
    let fingerprint = |records: &[AcceptedEvent]| {
        records
            .iter()
            .filter(|record| {
                record.realm_id.as_deref() == Some(realm_id) && !admitted.contains(&record.event_id)
            })
            .map(|record| (record.event_id.as_str(), record.canonical_digest.as_str()))
            .map(|(id, digest)| (id.to_owned(), digest.to_owned()))
            .collect::<BTreeSet<_>>()
    };
    fingerprint(before) != fingerprint(after)
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;

    use super::*;

    fn event(station: &str, seq: u64, seed: u8) -> AcceptedEvent {
        let event = arkret_wire::test_support::raw_event_at(
            "ak.test.data",
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(
                    "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                )
                .unwrap(),
            },
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new(station).unwrap(),
            seq,
            arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
            serde_json::json!({"seed": seed}),
            chrono::Utc::now(),
        )
        .unwrap();
        AcceptedEvent {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            actor_seq: seq,
            realm_id: Some(event.realm_id.to_string()),
            kind: event.kind.to_string(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            digest_suite: DigestSuite::Sha256,
            canonical_digest: event
                .event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(&event).unwrap(),
            received_at: event.created_at,
        }
    }

    fn remote(records: &[AcceptedEvent]) -> EventsFrontierFederationPeerState {
        let realm = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
        let mut bounds = BTreeMap::<String, u64>::new();
        for record in records {
            bounds
                .entry(record.actor_id.clone())
                .and_modify(|seq| *seq = (*seq).max(record.actor_seq))
                .or_insert(record.actor_seq);
        }
        let mut heads = records
            .iter()
            .filter(|record| bounds[&record.actor_id] == record.actor_seq)
            .map(|record| record.event_id.clone())
            .collect::<Vec<_>>();
        heads.sort();
        heads.dedup();
        serde_json::from_value(serde_json::json!({
            "realm_id": realm, "issuer_id": "ak:did_core:web:peer.example", "head_ids": heads,
            "actor_seq_upper_bounds": bounds,
            "frontier_root": super::super::frontier_exchange::local_frontier_root(records, realm).unwrap(),
            "observed_at": "2026-08-31T00:00:00.000Z", "signature": {}
        })).unwrap()
    }

    #[test]
    fn frontier_reduction_keeps_complete_actor_scope_and_required_disclosure() {
        let a = event("ak:did_core:web:a.example", 0, 1);
        let b = event("ak:did_core:web:b.example", 0, 2);
        let local = vec![a.clone()];
        assert_eq!(
            plan(&local, &local, &remote(&local), &BTreeSet::new()).unwrap(),
            ReductionPlan::Equal
        );
        assert_eq!(
            plan(&local, &local, &remote(&[b]), &BTreeSet::new()).unwrap(),
            ReductionPlan::Disjoint
        );
        assert!(
            plan(
                &local,
                &local,
                &remote(&[]),
                &BTreeSet::from([a.actor_id.clone()])
            )
            .unwrap_err()
            .contains("required_actor_omitted")
        );
        let sibling = event("ak:did_core:web:a.example", 0, 3);
        assert!(
            matches!(plan(&local, &local, &remote(&[sibling]), &BTreeSet::new()).unwrap(), ReductionPlan::Challenge(actors) if actors.len() == 1)
        );
    }

    #[test]
    fn frontier_reduction_preserves_union_and_detects_concurrent_snapshot_changes() {
        let a = event("ak:did_core:web:a.example", 0, 1);
        let b = event("ak:did_core:web:a.example", 0, 2);
        let records = vec![a.clone(), b.clone(), a.clone()];
        let realm = a.realm_id.as_deref().unwrap();
        let actors = BTreeSet::from([a.actor_id.clone()]);
        let sets = sibling_sets(&records, realm, &actors).unwrap();
        assert_eq!(sets.values().next().unwrap().len(), 2);
        let mut reversed = records.clone();
        reversed.reverse();
        assert_eq!(sets, sibling_sets(&reversed, realm, &actors).unwrap());
        assert!(!snapshot_changed(
            std::slice::from_ref(&a),
            &records,
            &BTreeSet::from([b.event_id.clone()]),
            realm
        ));
        assert!(snapshot_changed(
            std::slice::from_ref(&a),
            &records,
            &BTreeSet::new(),
            realm
        ));
    }
}
