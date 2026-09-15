//! Real-database regressions for the timeline projection order index. These
//! exercise the same transaction helper the Event unit of work calls.
use arkret_canonical::DigestSuite;
use arkret_wire::{AccountId, ActorId, Event, Hlc, RealmId, ScopeRef};
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel_async::AsyncConnection;
use serde_json::json;

use super::*;

#[derive(diesel::QueryableByName)]
struct FixtureEventPk {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

fn actor(principal: &str) -> ActorId {
    ActorId::account(AccountId::new(
        principal.parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ))
}

fn event(realm: &RealmId, actor: &ActorId, seq: u64, hlc: Option<&str>, prev: &[&Event]) -> Event {
    let at = chrono::DateTime::parse_from_rfc3339("2026-09-15T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        actor.clone(),
        seq,
        Hlc::new("01970e589d00-0000-a13f9c2e").unwrap(),
        json!({"body": format!("event {seq}")}),
        at,
    )
    .unwrap();
    event.hlc = hlc.map(|hlc| Hlc::new(hlc).unwrap());
    event.prev_refs = prev.iter().map(|prev| prev.event_id.clone()).collect();
    event.event_id = arkret_wire::EventId::from_digest(
        DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(
            format!(
                "timeline-order-fixture-{}-{seq}",
                actor.canonical_key().unwrap()
            )
            .as_bytes(),
        ),
    );
    event
}

async fn persist(pool: &crate::PgPool, event: &Event) -> PersistenceResult<()> {
    let mut conn = pool.get().await.map_err(PersistenceError::database)?;
    conn.transaction::<(), crate::PgTransactionError, _>(async |conn| {
        let token = event.event_id.token_bytes();
        let bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        let realm_pk = crate::realm_identity::ensure_realm_pk(conn, event.realm_id.as_str()).await?;
        let event_pk = sql_query(
            "INSERT INTO canonical_events\
             (id,digest_suite,digest,actor_id,actor_seq,realm_id,realm_pk,kind,schema_id,canonical_bytes,envelope) \
             VALUES($1,1,$2,$3,$4,$5,$6,$7,'fixture',$8,$9) RETURNING pk",
        )
        .bind::<Binary, _>(token.to_vec())
        .bind::<Binary, _>(token[1..].to_vec())
        .bind::<Text, _>(event.actor_id.canonical_key().unwrap())
        .bind::<BigInt, _>(event.actor_seq as i64)
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<BigInt, _>(realm_pk)
        .bind::<Text, _>(event.kind.as_str())
        .bind::<Binary, _>(bytes)
        .bind::<Jsonb, _>(serde_json::to_value(event).unwrap())
        .get_result::<FixtureEventPk>(&mut *conn)
        .await?
        .pk;
        commit_order_key(conn, event_pk, realm_pk, event).await?;
        Ok(())
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)
}

#[tokio::test]
async fn projection_order_pages_by_depth_then_absent_last_hlc_without_reading_the_realm() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"timeline order realm"),
    ));
    let alice = actor("ak:did_core:web:alice.example");
    let bob = actor("ak:did_core:web:bob.example");

    // Two roots at depth 0: one carries an HLC, one does not. encoding.md 7.3
    // makes the absent one sort last, which the derived Option order would get
    // backwards.
    let with_hlc = event(&realm, &alice, 1, Some("01970e589d21-0000-a13f9c2e"), &[]);
    let without_hlc = event(&realm, &bob, 1, None, &[]);
    // A successor of the HLC-bearing root: depth 1 outranks both roots.
    let deeper = event(
        &realm,
        &alice,
        2,
        Some("01970e589d20-0000-a13f9c2e"),
        &[&with_hlc],
    );
    persist(&pool, &with_hlc).await.unwrap();
    persist(&pool, &without_hlc).await.unwrap();
    persist(&pool, &deeper).await.unwrap();

    let mut conn = pool.get().await.unwrap();
    let newest = timeline_page(&mut conn, realm.as_str(), None, 2)
        .await
        .unwrap();
    assert_eq!(
        newest
            .iter()
            .map(|row| row.event_id.as_str())
            .collect::<Vec<_>>(),
        vec![deeper.event_id.as_str(), without_hlc.event_id.as_str()],
        "newest-first is depth desc, then absent HLC ahead of a present one"
    );
    assert_eq!(newest[0].causal_depth, 1);
    assert_eq!(newest[1].causal_depth, 0);
    assert!(newest[1].hlc.is_none());

    // The keyset continues strictly past the page's oldest row and never
    // repeats it, which is what makes a window bounded instead of a full read.
    let older = timeline_page(&mut conn, realm.as_str(), newest.last(), 10)
        .await
        .unwrap();
    assert_eq!(
        older
            .iter()
            .map(|row| row.event_id.as_str())
            .collect::<Vec<_>>(),
        vec![with_hlc.event_id.as_str()]
    );
    assert!(
        timeline_page(&mut conn, realm.as_str(), older.last(), 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn an_unresolved_predecessor_marks_the_order_provisional_and_propagates() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"timeline provisional realm"),
    ));
    let alice = actor("ak:did_core:web:alice.example");
    let bob = actor("ak:did_core:web:bob.example");

    let root = event(&realm, &alice, 1, Some("01970e589d21-0000-a13f9c2e"), &[]);
    persist(&pool, &root).await.unwrap();

    // Names a predecessor this Station never accepted. 7.3 requires the depth
    // to be provisional: an edge the receiver cannot see is an edge it cannot
    // have closed over, so the order around it is not final.
    let mut orphan = event(&realm, &bob, 1, Some("01970e589d22-0000-a13f9c2e"), &[]);
    orphan.prev_refs = vec![arkret_wire::EventId::from_digest(
        DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"never accepted here"),
    )];
    persist(&pool, &orphan).await.unwrap();

    // A successor of the provisional Event inherits the flag.
    let child = event(
        &realm,
        &bob,
        2,
        Some("01970e589d23-0000-a13f9c2e"),
        &[&orphan],
    );
    persist(&pool, &child).await.unwrap();

    let mut conn = pool.get().await.unwrap();
    let rows = timeline_page(&mut conn, realm.as_str(), None, 10)
        .await
        .unwrap();
    let by_id = rows
        .iter()
        .map(|row| (row.event_id.as_str(), row))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert!(!by_id[root.event_id.as_str()].provisional);
    let orphan_row = by_id[orphan.event_id.as_str()];
    assert!(orphan_row.provisional);
    assert_eq!(
        orphan_row.causal_depth, 0,
        "an unresolved predecessor contributes no depth; it only makes the order provisional"
    );
    let child_row = by_id[child.event_id.as_str()];
    assert!(
        child_row.provisional,
        "provisional depth propagates forward"
    );
    assert_eq!(child_row.causal_depth, 1);
}
