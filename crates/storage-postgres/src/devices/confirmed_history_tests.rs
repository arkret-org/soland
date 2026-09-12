//! The history fixture verifies real inception, Event and Seal signatures.
//! Direct Seal insertion below seeds an already-confirmed store for the
//! persistence boundary; it does not assert HTTP admission coverage.
use super::*;

#[path = "../../../test-support/src/device_authorization_history.rs"]
mod fixture;

async fn insert_seal(pool: &PgPool, seal: &arkret_wire::Seal) {
    let mut conn = pool.get().await.unwrap();
    sql_query("INSERT INTO state_seals(id,digest_suite,realm_id,seal_id_preimage_bytes,accepted_seal_bytes,seal_json,predecessor_ref,is_genesis) VALUES($1,'sha256',$2,$3,$4,$5,$6,$7)")
        .bind::<Text,_>(seal.id.as_str()).bind::<Text,_>(seal.realm_id.as_str())
        .bind::<sql_types::Binary,_>(seal.canonical_bytes_for_id().unwrap())
        .bind::<sql_types::Binary,_>(arkret_wire::seal::seal_canonical_bytes(seal).unwrap())
        .bind::<Jsonb,_>(serde_json::to_value(seal).unwrap())
        .bind::<Nullable<Text>,_>(seal.predecessor_ref.as_ref().map(|id| id.as_str()))
        .bind::<Bool,_>(seal.predecessor_ref.is_none()).execute(&mut *conn).await.unwrap();
}

#[tokio::test]
async fn confirmed_device_history_installation_is_exact_atomic_and_recoverable() {
    let database = crate::TestDatabase::lease().await;
    let pool = database.pool();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:device-history.example").unwrap();
    {
        let mut conn = pool.get().await.unwrap();
        sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
            .bind::<Text, _>(station.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    let store = PgDeviceInventoryStore { pool: pool.clone() };
    let mut source = fixture::DeviceHistoryFixture::new(station);
    let original = source.verify().unwrap();
    assert!(
        store.install_confirmed_history(&original).await.is_err(),
        "uninstalled Seal cannot grant device authority"
    );
    insert_seal(&pool, &source.seals[0]).await;
    store.install_confirmed_history(&original).await.unwrap();
    let first = store
        .get(
            source.account.principal_id.as_str(),
            fixture::device(1).as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.verification_state, "verified");
    assert_eq!(
        first.payload["authorized_generation_ref"],
        serde_json::json!(1)
    );

    let second = source.event(arkret_wire::EventKind::DeviceAuthorize, serde_json::to_value(fixture::possession(&source.account,2,arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::AcceptedDevice)).unwrap());
    source.append(vec![second]);
    let updated = source.verify().unwrap();
    insert_seal(&pool, source.seals.last().unwrap()).await;
    assert!(
        store.install_confirmed_history(&original).await.is_err(),
        "older verified prefix cannot reinstall after head advancement"
    );
    {
        let mut conn = pool.get().await.unwrap();
        sql_query("ALTER TABLE devices ADD CONSTRAINT device_history_failure CHECK(device_id <> 'ak:device:01904100-0000-7000-8000-000000000002')")
            .execute(&mut *conn).await.unwrap();
    }
    assert!(store.install_confirmed_history(&updated).await.is_err());
    {
        let mut conn = pool.get().await.unwrap();
        let marker = sql_query("SELECT to_jsonb(confirmed_head) AS payload FROM device_history_projections WHERE principal_id=$1")
            .bind::<Text,_>(source.account.principal_id.as_str()).get_result::<JsonPayloadRow>(&mut *conn).await.unwrap();
        assert_eq!(
            marker.payload,
            serde_json::json!(original.confirmed_head()),
            "failed mirror installation cannot advance its durable progress marker"
        );
    }

    assert_eq!(
        store
            .get(
                source.account.principal_id.as_str(),
                fixture::device(1).as_str()
            )
            .await
            .unwrap()
            .unwrap()
            .payload,
        first.payload,
        "failed batch rolls back invalidation and every partial mirror write"
    );
    {
        let mut conn = pool.get().await.unwrap();
        sql_query("ALTER TABLE devices DROP CONSTRAINT device_history_failure")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    store.install_confirmed_history(&updated).await.unwrap();
    use soland_storage::{DeviceRevocationStore, SessionStore};
    let sessions = crate::PgSessionStore { pool: pool.clone() };
    let account_pk = {
        let mut conn = pool.get().await.unwrap();
        sql_query("INSERT INTO accounts(principal_id,station_id) VALUES($1,$2) RETURNING to_jsonb(pk) AS payload")
            .bind::<Text,_>(source.account.principal_id.as_str()).bind::<Text,_>(source.account.station_id.as_str())
            .get_result::<JsonPayloadRow>(&mut *conn).await.unwrap().payload.as_i64().unwrap()
    };
    let session = soland_storage::SessionRecord {
        token_hash: "frozen-device-instance".into(),
        account_pk: soland_storage::AccountPk(account_pk),
        actor: source.account.principal_id.to_string(),
        device_id: fixture::device(2).to_string(),
        audience: source.account.station_id.to_string(),
        session_public_key: None,
        agent_session: None,
        expires_at: first.created_at + chrono::Duration::days(1),
        created_at: first.created_at,
        revoked_at: None,
    };
    sessions.put(&session).await.unwrap();
    let session_binding = sessions
        .device_authorization(&session.token_hash)
        .await
        .unwrap()
        .unwrap();
    let gates = crate::device_revocations::PgDeviceRevocationStore { pool: pool.clone() };
    assert_eq!(
        gates.gate_status(&session_binding).await.unwrap(),
        DeviceRevocationGateStatus::Active
    );
    let old_authorize = updated
        .authorizations()
        .last()
        .unwrap()
        .authorization_event_id()
        .clone();
    let revoke = source.event(arkret_wire::EventKind::DeviceRevoke, serde_json::json!({"device_id":fixture::device(2),"revoked_by":fixture::device(1),"revoked_at":"2026-09-12T00:00:00.000Z","reason":"user_requested"}));
    source.append(vec![revoke]);
    insert_seal(&pool, source.seals.last().unwrap()).await;
    store
        .install_confirmed_history(&source.verify().unwrap())
        .await
        .unwrap();
    assert_eq!(
        store
            .get(
                source.account.principal_id.as_str(),
                fixture::device(2).as_str()
            )
            .await
            .unwrap()
            .unwrap()
            .verification_state,
        "unverified"
    );
    store
        .put_metadata(&soland_storage::DeviceInventoryMetadata {
            actor: source.account.principal_id.to_string(),
            device_id: fixture::device(2).to_string(),
            display_name: Some("renamed after revoke".into()),
            last_seen_at: Some(first.created_at),
            last_key_upload_at: Some(first.updated_at),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .get(
                source.account.principal_id.as_str(),
                fixture::device(2).as_str()
            )
            .await
            .unwrap()
            .unwrap()
            .verification_state,
        "unverified",
        "a delayed metadata writer cannot revive authority"
    );
    let successor = source.event(arkret_wire::EventKind::DeviceAuthorize, serde_json::to_value(fixture::possession(&source.account,2,arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::AcceptedDevice)).unwrap());
    let successor_id = successor.event_id.clone();
    source.append(vec![successor]);
    insert_seal(&pool, source.seals.last().unwrap()).await;
    let newest = source.verify().unwrap();
    store.install_confirmed_history(&newest).await.unwrap();
    store.install_confirmed_history(&newest).await.unwrap();
    let active = store
        .get(
            source.account.principal_id.as_str(),
            fixture::device(2).as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        active.payload["device_authorize_event_id"],
        serde_json::json!(successor_id)
    );
    assert_ne!(old_authorize, successor_id);
    sessions.put(&session).await.unwrap();
    assert_eq!(
        sessions
            .device_authorization(&session.token_hash)
            .await
            .unwrap(),
        Some(session_binding.clone()),
        "persisting an old session cannot relabel it with the successor authorization"
    );
    assert_eq!(
        gates.gate_status(&session_binding).await.unwrap(),
        DeviceRevocationGateStatus::AuthorityMismatch,
        "the same DeviceId does not inherit its previous session authorization"
    );
    let mut different_holder = session.clone();
    different_holder.device_id = fixture::device(1).to_string();
    assert!(
        sessions.put(&different_holder).await.is_err(),
        "a token cannot switch its immutable holder"
    );
    let mut revoked_session = session.clone();
    revoked_session.revoked_at = Some(first.created_at);
    sessions.put(&revoked_session).await.unwrap();
    sessions.put(&session).await.unwrap();
    assert!(
        sessions
            .get(&session.token_hash)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some(),
        "stale session writes cannot undo durable revocation"
    );

    assert_eq!(
        active.payload["display_name"],
        serde_json::json!("renamed after revoke")
    );
    assert_eq!(
        active.payload["last_seen_at"],
        serde_json::json!(first.created_at)
    );
    assert_eq!(
        active.payload["last_key_upload_at"],
        serde_json::json!(first.updated_at)
    );
    let restored_store = PgDeviceInventoryStore { pool: pool.clone() };
    restored_store
        .install_confirmed_history(&newest)
        .await
        .unwrap();
    assert_eq!(
        restored_store
            .get(
                source.account.principal_id.as_str(),
                fixture::device(2).as_str()
            )
            .await
            .unwrap()
            .unwrap()
            .updated_at,
        active.updated_at,
        "restarting the installer at an already installed head is a read-only exact replay"
    );

    assert!(store.install_confirmed_history(&updated).await.is_err());
    assert_eq!(
        store
            .get(
                source.account.principal_id.as_str(),
                fixture::device(2).as_str()
            )
            .await
            .unwrap()
            .unwrap()
            .payload,
        active.payload
    );
    source.append(source.reanchor(false));
    insert_seal(&pool, source.seals.last().unwrap()).await;
    let generation_two = source.verify().unwrap();
    store
        .install_confirmed_history(&generation_two)
        .await
        .unwrap();
    assert_eq!(
        store
            .get(
                source.account.principal_id.as_str(),
                fixture::device(1).as_str()
            )
            .await
            .unwrap()
            .unwrap()
            .verification_state,
        "unverified"
    );
    let replacement = store
        .get(
            source.account.principal_id.as_str(),
            fixture::device(3).as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replacement.verification_state, "verified");
    assert_eq!(
        replacement.payload["authorized_generation_ref"],
        serde_json::json!(2)
    );
    assert!(store.install_confirmed_history(&newest).await.is_err());
}
