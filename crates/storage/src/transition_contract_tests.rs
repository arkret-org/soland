use std::collections::BTreeMap;

use chrono::{Duration, TimeZone, Utc};

use crate::{MultisigPendingRecord, MultisigPendingStore};

/// Shared Memory/PostgreSQL oracle for the multisig watchdog lease machine.
///
/// The adapter is responsible only for making each command atomic. All
/// expected outcomes below are backend-neutral business semantics.
pub async fn assert_multisig_lease_contract(store: &dyn MultisigPendingStore, namespace: &str) {
    let now = Utc
        .with_ymd_and_hms(2026, 9, 1, 0, 0, 0)
        .single()
        .expect("valid contract timestamp");
    let missing_id = format!("{namespace}-missing");
    assert_eq!(
        store
            .try_claim(&missing_id, "node-a", now, now + Duration::minutes(1),)
            .await
            .expect("classify missing row"),
        (false, 0)
    );

    let seal_id = format!("{namespace}-lease");
    store
        .upsert(MultisigPendingRecord {
            seal_id: seal_id.clone(),
            realm_id: "ak:realm:AXVdykmiwmiUakQOqyMoYAwL8Eh63mpQHFaMczNjNT5p".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            threshold_k: 2,
            threshold_n: 3,
            members: vec![
                "did:web:signer-a.example".to_owned(),
                "did:web:signer-b.example".to_owned(),
                "did:web:signer-c.example".to_owned(),
            ],
            canonical_b64: "dHJhbnNpdGlvbi1jb250cmFjdA==".to_owned(),
            partials: BTreeMap::new(),
            created_at: now,
            expires_at: now + Duration::hours(1),
            claimed_by_node_id: None,
            claimed_until: None,
            claim_seq: 0,
        })
        .await
        .expect("insert contract row");

    assert_eq!(
        store
            .try_claim(&seal_id, "node-a", now, now + Duration::minutes(10),)
            .await
            .expect("claim unowned row"),
        (true, 1)
    );
    assert_eq!(
        store
            .try_claim(
                &seal_id,
                "node-b",
                now + Duration::minutes(1),
                now + Duration::minutes(11),
            )
            .await
            .expect("reject live competing claim"),
        (false, 1)
    );
    assert!(
        !store
            .renew_claim(&seal_id, "node-b", 1, now + Duration::minutes(12),)
            .await
            .expect("reject wrong-owner renewal")
    );
    assert!(
        store
            .renew_claim(&seal_id, "node-a", 1, now + Duration::minutes(12),)
            .await
            .expect("renew exact fence")
    );
    assert_eq!(
        store
            .try_claim(
                &seal_id,
                "node-b",
                now + Duration::minutes(12),
                now + Duration::minutes(22),
            )
            .await
            .expect("claim at exact expiry boundary"),
        (true, 2)
    );
    assert!(
        !store
            .delete_with_fence(&seal_id, "node-a", 1)
            .await
            .expect("reject stale fenced delete")
    );
    store
        .release_claim(&seal_id, "node-a")
        .await
        .expect("wrong-owner release is an idempotent no-op");
    let retained = store
        .get(&seal_id)
        .await
        .expect("read retained row")
        .expect("stale commands must retain the row");
    assert_eq!(retained.claimed_by_node_id.as_deref(), Some("node-b"));
    assert_eq!(retained.claim_seq, 2);
    assert!(
        store
            .delete_with_fence(&seal_id, "node-b", 2)
            .await
            .expect("delete with current fence")
    );
    assert!(
        !store
            .delete_with_fence(&seal_id, "node-b", 2)
            .await
            .expect("deleted row remains an idempotent miss")
    );
}
