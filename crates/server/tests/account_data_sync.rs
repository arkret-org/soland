use arkret_identifiers::{DidCoreId, DidFullId, RealmId};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland_http::config::{AppConfig, ObjectStorageConfig};
use soland_http::service;
use soland_http::state::{AppState, RealmDirectoryEntry};
use soland_storage::RealmMetaRecord;
use soland_test_support::AppStateTestExt as _;

fn test_event_signer_did() -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&[21_u8; 32]);
    format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
    )
}

fn actor_core_id(actor: &str) -> DidCoreId {
    arkret_wire::project_full_id_to_core_id(
        &DidFullId::new(actor.to_owned()).expect("fixture actor full DID"),
    )
    .expect("fixture actor full DID projects to a core id")
}

fn test_config() -> AppConfig {
    AppConfig {
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-account-data-sync-blobs"),
        ),
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        ..soland_test_support::app_config()
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

async fn dev_token(state: AppState, actor: &str, device_id: &str, display_name: &str) -> String {
    let actor_core = arkret_wire::project_full_id_to_core_id(
        &DidFullId::new(actor.to_owned()).expect("fixture actor full DID"),
    )
    .expect("fixture actor core id");
    let mut response = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor_core,
            "device_id": device_id,
            "display_name": display_name,
        }))
        .send(&app_from_state(state))
        .await;
    let status = response.status_code;
    let login: Value = response
        .take_json()
        .await
        .unwrap_or_else(|error| panic!("dev-login did not return JSON: {error:?}"));
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "dev-login failed for {actor} / {device_id}: {login}"
    );
    login["session_credential"]
        .as_str()
        .unwrap_or_else(|| panic!("dev-login response missing session_credential: {login}"))
        .to_owned()
}

async fn account_subscribe_frame(state: AppState, token: &str, query: &str) -> Value {
    let url = if query.is_empty() {
        "http://server/_arkret/self/account/subscribe".to_owned()
    } else {
        format!("http://server/_arkret/self/account/subscribe?{query}")
    };
    let body = TestClient::get(url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_string()
        .await
        .unwrap();
    serde_json::from_str(body.lines().next().unwrap()).unwrap()
}

async fn put_account_data(
    state: AppState,
    token: &str,
    actor: &str,
    device_id: &str,
    account_data_key: &str,
    expected_revision: u64,
    content: Value,
) -> (StatusCode, Value) {
    let set_event = signed_account_data_submission(
        state.clone(),
        token,
        actor,
        device_id,
        account_data_key,
        expected_revision,
        Some(content),
        false,
    )
    .await;
    let mut response = TestClient::put(format!(
        "http://server/_arkret/self/account_data/{account_data_key}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&json!({"set_event": set_event}))
    .send(&app_from_state(state))
    .await;
    let status = response.status_code.expect("account_data PUT status");
    let body = response
        .take_json()
        .await
        .expect("account_data PUT JSON response");
    (status, body)
}

#[allow(clippy::too_many_arguments)]
async fn signed_account_data_submission(
    state: AppState,
    token: &str,
    actor: &str,
    device_id: &str,
    account_data_key: &str,
    expected_revision: u64,
    content: Option<Value>,
    tombstone: bool,
) -> arkret_wire::EventInitialSubmission {
    let realm_id = soland_test_support::fixture_principal_control_realm(actor);
    let actor_core = arkret_wire::project_full_id_to_core_id(
        &DidFullId::new(actor.to_owned()).expect("fixture actor full DID"),
    )
    .expect("fixture actor full DID projects to a core id");
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"actor_id": actor_core, "realm_id": realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state))
            .await
            .take_json()
            .await
            .expect("typed actor Realm frontier");
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
        frontier.frontier
    else {
        panic!("combined Realm+actor selector returned the wrong variant");
    };
    frontier.validate().expect("valid actor Realm frontier");
    let mut payload = json!({
        "key": account_data_key,
        "expected_revision": expected_revision,
        "owner": actor_core,
        "updated_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
    });
    if let Some(content) = content {
        payload["body"] = content;
    }
    if tombstone {
        payload["tombstone"] = Value::Bool(true);
    }
    let event = signed_actor_private_event_envelope(
        actor,
        device_id,
        &realm_id,
        arkret_wire::EventKind::AccountDataSet,
        payload,
        frontier.next_actor_seq,
        frontier.frontier_event_ids,
    );
    arkret_wire::EventInitialSubmission::online(
        serde_json::from_value(event).expect("signed account_data Event"),
    )
}

/// Stand a plaintext Realm up through its canonical `ak.realm.create`.
///
/// `realm-and-space.md` §2.5 makes the genesis Event the sole writer of the
/// Realm's seven registered cells, and admission resolves every later Event's
/// reducer profile from one of them (`ak.component.realm.reducer_profile.v1`).
/// A fixture that writes only the Realm directory and the `realm_meta`
/// projection leaves that cell unmaterialized, so the server correctly answers
/// `dependency_missing` for every ordinary Event in the Realm.
///
/// [`soland_test_support::cba_basis::seed_realm_genesis_event`] authors that
/// genesis Event and folds it through the same reducer the submit path uses,
/// so all seven cells — reducer profile, authority root, metadata, notary,
/// create log, creator membership — are derived from the Event rather than
/// hand-seeded. The directory entry and `realm_meta` row that follow are
/// soland-local read projections, and they restate the genesis object rather
/// than inventing values it does not carry.
async fn create_plaintext_realm(state: AppState, owner: &str, title: &str) -> String {
    let realm_id = soland_test_support::cba_basis::seed_event_derived_realm_genesis_event(
        &state, owner, title,
    )
    .await;
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    let owner = DidFullId::new(owner.to_owned()).unwrap();
    let now = chrono::Utc::now();

    let mut entry = RealmDirectoryEntry::new(
        typed_realm_id,
        title,
        soland_services::events::DirectoryProvenance::LocalOnly,
    );
    entry.description = Some("G3.S6 account-private sync fixture".to_owned());
    entry
        .members
        .insert(arkret_wire::project_full_id_to_core_id(&owner).unwrap());
    state.test_realms().lock().upsert(entry);
    state
        .test_persistence()
        .realm_meta()
        .put(
            &realm_id,
            &RealmMetaRecord {
                owner: owner.as_str().to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("none".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::from([
                    "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service".to_owned(),
                ]),
                plaintext_visible_service_classes: std::collections::BTreeMap::from([(
                    "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service".to_owned(),
                    std::collections::BTreeSet::from([
                        arkret_wire::PlaintextDataClassKind::MessageContent,
                    ]),
                )]),
                minimal_metadata_realm: false,
                aad_visibility_ceiling: Default::default(),
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();
    realm_id
}

async fn add_realm_member(state: AppState, _token: &str, realm_id: &str, member: &str) {
    let typed_realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let member_did = DidFullId::new(member.to_owned()).unwrap();
    let mut realms = state.test_realms().lock();
    let entry = realms
        .get(&typed_realm_id)
        .cloned()
        .expect("seeded test realm exists before member add");
    let mut updated = entry;
    let member_core = arkret_wire::project_full_id_to_core_id(&member_did).unwrap();
    updated.members.insert(member_core.clone());
    assert!(updated.members.contains(&member_core));
    realms.upsert(updated);
}

fn signed_actor_private_event_envelope(
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: impl AsRef<str>,
    payload: Value,
    actor_seq: u64,
    prev_refs: Vec<arkret_wire::EventId>,
) -> Value {
    let kind = kind.as_ref();
    let now = chrono::Utc::now();
    let actor_id = arkret_identifiers::DidFullId::new(actor.to_owned()).expect("fixture actor DID");
    let verification_method = arkret_wire::DidUrl::new(format!("{actor}#{device_id}"))
        .expect("fixture verification method is a DID URL");
    let mut event = arkret_wire::test_support::raw_event_at(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
                .expect("fixture Realm id"),
        },
        arkret_wire::project_full_id_to_core_id(&actor_id).unwrap(),
        soland_test_support::fixture_principal_server_id(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-00000000",
            now.timestamp_millis().max(0) as u64
        ))
        .expect("fixture HLC"),
        payload,
        now,
    )
    .expect("SDK Event builder accepts actor-private fixture");
    event.prev_refs = prev_refs;
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        arkret_signatures::development_signing_key_seed(verification_method.as_str()),
        actor_id,
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .expect("SDK Event signer accepts actor-private fixture");
    // `id-kind-registry.json` gives the `operation` kind `id_form:
    // producer_allocated`, so the Operation id is the producer's to mint and a
    // receiver cannot derive one from the content-bound full-digest Event id.
    // Every real submitter carries it in this slot — that is what
    // `arkret_event_draft::ProjectedEventOperation::into_event_envelope` writes, after the
    // proofs, because `unsigned` is outside the signed canonical transcript.
    // Without it soland has no Operation for the Event and skips both the
    // kind's registered payload validator and the reducer projection, so the
    // fixture has to submit it the way a client does.
    event.unsigned.insert(
        "local_operation_idempotency_alias".to_owned(),
        Value::String(arkret_identifiers::new_prefixed_uuid7("ak:operation:")),
    );
    serde_json::to_value(event).expect("SDK Event serializes")
}

async fn submit_actor_private_event(
    state: AppState,
    token: &str,
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Value {
    let actor_core = arkret_wire::project_full_id_to_core_id(
        &DidFullId::new(actor.to_owned()).expect("fixture actor full DID"),
    )
    .expect("fixture actor full DID projects to a core id");
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"actor_id": actor_core, "realm_id": realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .expect("typed actor Realm frontier");
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
        frontier.frontier
    else {
        panic!("combined Realm+actor selector returned the wrong variant");
    };
    frontier.validate().expect("valid actor Realm frontier");
    let event = signed_actor_private_event_envelope(
        actor,
        device_id,
        realm_id,
        kind,
        payload,
        frontier.next_actor_seq,
        frontier.frontier_event_ids,
    );
    TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap()
}

fn account_data_entry<'a>(sync: &'a Value, key: &str) -> Option<&'a Value> {
    sync["account_data"]["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| entry["payload"]["key"] == key)
}

fn read_cursor_payload(
    actor: &str,
    device_id: &str,
    realm_id: &str,
    event_id: &str,
    hlc: &str,
) -> Value {
    let actor_id = actor_core_id(actor);
    json!({
        "id": arkret_identifiers::new_prefixed_uuid7("ak:read_cursor:"),
        "schema": "ak.schema.read_cursor.v1",
        "actor_id": actor_id,
        "device_id": device_id,
        "realm_id": realm_id,
        "read_scope": {
            "kind": "strand",
            "container_ref": strand_id_for_realm(realm_id),
            "track_name": "discussion"
        },
        "position": {
            "event_id": event_id,
            "hlc": hlc
        },
        "updated_at": "2026-05-21T00:00:00.000Z",
    })
}

fn projected_read_markers(state: &AppState, actor: &str, realm_id: Option<&str>) -> Vec<Value> {
    let projection = state.test_projection().lock();
    projection
        .read_cursors
        .values()
        .filter(|marker| {
            marker.actor_id.as_str() == actor
                && realm_id.is_none_or(|realm_id| marker.realm_id.as_str() == realm_id)
        })
        .map(|marker| {
            json!({
                "realm_id": marker.realm_id.clone(),
                "actor_id": marker.actor_id.clone(),
                "device_id": marker.device_id.clone(),
                "read_scope": marker.read_scope.clone(),
                "position": marker.position.clone(),
                "updated_at": arkret_canonical::format_timestamp_canonical(
                    marker.updated_at
                ),
            })
        })
        .collect()
}

fn encrypted_account_data_value(
    actor_id: &DidCoreId,
    account_data_key: &str,
    plaintext: &Value,
) -> Value {
    serde_json::to_value(
        arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
            &[7u8; 32],
            actor_id,
            account_data_key,
            plaintext,
            [9u8; 24],
        )
        .unwrap(),
    )
    .unwrap()
}

fn strand_id_for_realm(realm_id: &str) -> String {
    arkret_identifiers::RealmId::new(realm_id.to_owned())
        .map(|realm_id| {
            arkret_identifiers::StrandId::from_event_id(&realm_id.event_id()).to_string()
        })
        .unwrap_or_else(|_| "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC".to_owned())
}

#[tokio::test]
async fn rest_account_data_overwrite_syncs_latest_canonical_event_and_tombstones() {
    let state = soland_test_support::app_state(test_config());
    let actor = test_event_signer_did();
    let actor_core = actor_core_id(&actor);
    // Principal Control Realms use their distinct subject-derived bootstrap
    // path. Materialize its create-locked reducer cells through the SDK's PCR
    // genesis builder rather than through an ordinary Realm bootstrap.
    soland_test_support::cba_basis::seed_realm_genesis_event(
        &state,
        &soland_test_support::fixture_principal_control_realm(&actor),
        &actor,
    )
    .await;
    let desktop = dev_token(
        state.clone(),
        &actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000011",
        "Alice Desktop",
    )
    .await;
    let phone = dev_token(
        state.clone(),
        &actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000012",
        "Alice Phone",
    )
    .await;
    let account_data_key = "client.complement_probe.scalar";

    let (first_status, first) = put_account_data(
        state.clone(),
        &desktop,
        &actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000011",
        account_data_key,
        0,
        json!({ "version": 1, "label": "first" }),
    )
    .await;
    assert_eq!(first_status, StatusCode::CREATED, "first PUT: {first}");
    assert_eq!(first["content"]["version"], 1);

    let (second_status, second) = put_account_data(
        state.clone(),
        &desktop,
        &actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000011",
        account_data_key,
        first["revision"].as_u64().unwrap(),
        json!("second"),
    )
    .await;
    assert_eq!(second_status, StatusCode::OK, "second PUT: {second}");
    assert_eq!(second["content"], "second");

    let (stale_status, stale) = put_account_data(
        state.clone(),
        &desktop,
        &actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000011",
        account_data_key,
        first["revision"].as_u64().unwrap(),
        json!("stale retry"),
    )
    .await;
    assert_eq!(stale_status, StatusCode::CONFLICT, "{stale}");
    assert_eq!(stale["error"]["code"], "cas_conflict");
    assert_eq!(
        stale["error"]["details"]["account_data_key"],
        account_data_key
    );
    assert_eq!(
        stale["error"]["details"]["current_revision"],
        second["revision"]
    );
    assert_eq!(
        stale["error"]["details"]["current_entry"]["content"],
        "second"
    );

    let phone_sync = account_subscribe_frame(state.clone(), &phone, "catchup=true").await;
    let event = account_data_entry(&phone_sync, account_data_key)
        .unwrap_or_else(|| panic!("latest account_data Event missing: {phone_sync}"));
    assert_eq!(
        event["kind"],
        arkret_wire::EventKind::AccountDataSet.as_str()
    );
    assert_eq!(event["actor_id"].as_str(), Some(actor_core.as_str()));
    assert_eq!(event["payload"]["owner"], actor_core.as_str());
    assert_eq!(event["payload"]["expected_revision"], 1);
    assert_eq!(event["payload"]["body"], "second");
    assert!(
        event["proofs"]
            .as_array()
            .is_some_and(|proofs| !proofs.is_empty())
    );
    assert!(!event.to_string().contains("first"));
    serde_json::from_value::<arkret_wire::Event>(event.clone())
        .expect("sync account_data entry is a typed canonical Event");

    let rebuilt_sync = account_subscribe_frame(state.clone(), &phone, "catchup=true").await;
    assert_eq!(
        account_data_entry(&rebuilt_sync, account_data_key).map(|entry| &entry["payload"]["body"]),
        Some(&json!("second")),
        "initial baseline must come from the durable Event store"
    );

    let delete_event = signed_account_data_submission(
        state.clone(),
        &desktop,
        &actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000011",
        account_data_key,
        second["revision"].as_u64().unwrap(),
        None,
        true,
    )
    .await;
    let mut delete = TestClient::delete(format!(
        "http://server/_arkret/self/account_data/{account_data_key}"
    ))
    .add_header("authorization", format!("Bearer {desktop}"), true)
    .json(&json!({"set_event": delete_event}))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(delete.status_code, Some(StatusCode::OK));
    let delete_body: Value = delete.take_json().await.unwrap();
    assert_eq!(delete_body["ok"], true);
    assert_eq!(delete_body["revision"], 3);

    let after_delete = account_subscribe_frame(state.clone(), &phone, "catchup=true").await;
    assert!(account_data_entry(&after_delete, account_data_key).is_none());
    let latest = state
        .test_persistence()
        .events()
        .snapshot_all()
        .await
        .unwrap()
        .into_iter()
        .filter(|record| {
            record.kind == arkret_wire::EventKind::AccountDataSet.as_str()
                && record
                    .envelope
                    .get("payload")
                    .and_then(|payload| payload.get("key"))
                    .and_then(Value::as_str)
                    == Some(account_data_key)
        })
        .max_by_key(|record| record.received_at)
        .expect("account_data tombstone Event remains durable");
    assert_eq!(latest.envelope["payload"]["tombstone"], true);
}

#[tokio::test]
async fn blocklist_account_data_requires_encrypted_carrier_and_fans_out_opaque() {
    let state = soland_test_support::app_state(test_config());
    let alice_actor = test_event_signer_did();
    let alice_actor_core = actor_core_id(&alice_actor);
    let alice_desktop = dev_token(
        state.clone(),
        &alice_actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let alice_phone = dev_token(
        state.clone(),
        &alice_actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000002",
        "Alice Phone",
    )
    .await;
    let bob = dev_token(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob",
    )
    .await;
    let realm_id = create_plaintext_realm(state.clone(), &alice_actor, "Blocklist Fixture").await;
    add_realm_member(
        state.clone(),
        &alice_desktop,
        &realm_id,
        "did:web:bob.example",
    )
    .await;

    let plaintext_blocklist = json!({
        "version": 1,
        "entries": [{
            "target": {
                "kind": "actor",
                "did": "did:web:bob.example"
            },
            "mode": "block",
            "applies_to": ["messages", "mentions", "notifications"],
            "created_at": "2026-05-21T00:00:00.000Z"
        }]
    });
    let put = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        &alice_actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        "ak.account_data.set",
        json!({
            "key": "ak.account.blocklist",
            "expected_revision": 0,
            "owner": alice_actor_core.as_str(),
            "body": plaintext_blocklist,
            "updated_at": "2026-05-21T00:00:00.000Z",
        }),
    )
    .await;
    // Asserting only "not accepted" would pass for any error at all, including
    // one raised before the payload was ever looked at. The floor this case
    // exists for is `discovery/client-preferences.md` §3.5: `ak.account.blocklist`
    // is a registered encrypted account-data key, so the carrier — not just the
    // outcome — is what has to fail.
    assert_eq!(
        put["error"]["code"],
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        "plaintext blocklist must be rejected: {put}"
    );
    assert!(
        put["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("encrypted")),
        "plaintext blocklist must be rejected by the encrypted-carrier floor, \
         not by an unrelated error: {put}"
    );

    let encrypted_blocklist = encrypted_account_data_value(
        &alice_actor_core,
        "ak.account.blocklist",
        &plaintext_blocklist,
    );
    let put = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        &alice_actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        "ak.account_data.set",
        json!({
            "key": "ak.account.blocklist",
            "expected_revision": 0,
            "owner": alice_actor_core.as_str(),
            "body": encrypted_blocklist.clone(),
            "updated_at": "2026-05-21T00:00:00.000Z",
        }),
    )
    .await;
    assert_eq!(
        put["status"], "accepted",
        "encrypted blocklist event: {put}"
    );
    let stored_account_data = state
        .test_persistence()
        .account_data()
        .list_for_actor(alice_actor_core.as_str())
        .await
        .unwrap();
    assert!(
        stored_account_data
            .iter()
            .any(|record| record.account_data_key == "ak.account.blocklist"),
        "account_data projection must persist encrypted blocklist after accepted event: {stored_account_data:?}"
    );
    let stale = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        &alice_actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        "ak.account_data.set",
        json!({
            "key": "ak.account.blocklist",
            "expected_revision": 0,
            "owner": alice_actor_core.as_str(),
            "body": encrypted_account_data_value(
                &alice_actor_core,
                "ak.account.blocklist",
                &json!({"version": 1, "entries": []}),
            ),
            "updated_at": "2026-05-21T00:00:01.000Z",
        }),
    )
    .await;
    assert_eq!(stale["error"]["code"], "cas_conflict", "{stale}");
    assert_eq!(
        stale["error"]["details"]["account_data_key"],
        "ak.account.blocklist"
    );
    assert_eq!(stale["error"]["details"]["current_revision"], 1);
    assert_eq!(
        stale["error"]["details"]["current_entry"]["content"],
        encrypted_blocklist
    );
    let current = state
        .test_persistence()
        .account_data()
        .get(alice_actor_core.as_str(), "ak.account.blocklist")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, 1);
    assert_eq!(current.payload, encrypted_blocklist);

    let phone_sync = account_subscribe_frame(
        state.clone(),
        &alice_phone,
        "catchup=true&set_presence=online",
    )
    .await;
    let phone_account_data = account_data_entry(&phone_sync, "ak.account.blocklist")
        .expect("blocklist account_data visible to Alice's sibling device");
    assert_eq!(phone_account_data["payload"]["body"], encrypted_blocklist);

    let phone_messages: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {alice_phone}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let phone_events = phone_messages["messages"].as_array().unwrap();
    let blocklist_event = phone_events
        .iter()
        .find(|event| event["kind"] == "ak.account.blocklist.update")
        .expect("blocklist update fanout reaches Alice's sibling device");
    assert_eq!(
        blocklist_event["content"]["account_data_key"],
        "ak.account.blocklist"
    );
    assert_eq!(blocklist_event["content"]["content"], encrypted_blocklist);

    let bob_messages: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(bob_messages["messages"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn read_cursor_fans_out_per_realm_without_cross_actor_leakage() {
    let state = soland_test_support::app_state(test_config());
    let alice_actor = test_event_signer_did();
    let alice_actor_core = actor_core_id(&alice_actor);
    let alice_desktop = dev_token(
        state.clone(),
        &alice_actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let alice_phone = dev_token(
        state.clone(),
        &alice_actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000002",
        "Alice Phone",
    )
    .await;
    let bob = dev_token(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob",
    )
    .await;
    let realm_a = create_plaintext_realm(state.clone(), &alice_actor, "Parent Realm").await;
    let realm_b = create_plaintext_realm(state.clone(), &alice_actor, "Discussion Realm").await;
    let event_a = "ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml";
    let event_b = "ak:event:AQ5uuUVXlrGqR79MEUmEPOIMYQIdRhgBIsTAtH3mgNpC";

    let marker_a = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        &alice_actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_a,
        "ak.read_cursor.advance",
        read_cursor_payload(
            &alice_actor,
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
            &realm_a,
            event_a,
            "019041000000-0001-a11ce001",
        ),
    )
    .await;
    assert_eq!(
        marker_a["status"], "accepted",
        "marker_a response: {marker_a}"
    );

    let marker_b = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        &alice_actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_b,
        "ak.read_cursor.advance",
        read_cursor_payload(
            &alice_actor,
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
            &realm_b,
            event_b,
            "019041000000-0001-a11ce002",
        ),
    )
    .await;
    assert_eq!(
        marker_b["status"], "accepted",
        "marker_b response: {marker_b}"
    );

    let markers_a = projected_read_markers(&state, alice_actor_core.as_str(), Some(&realm_a));
    assert_eq!(markers_a.len(), 1);
    assert_eq!(markers_a[0]["position"]["event_id"], event_a);
    assert_eq!(markers_a[0]["realm_id"], realm_a);
    assert_eq!(markers_a[0]["read_scope"]["track_name"], "discussion");

    let markers_b = projected_read_markers(&state, alice_actor_core.as_str(), Some(&realm_b));
    assert_eq!(markers_b.len(), 1);
    assert_eq!(markers_b[0]["position"]["event_id"], event_b);
    assert_eq!(markers_b[0]["realm_id"], realm_b);

    let phone_messages: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {alice_phone}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let read_cursor_fanouts = phone_messages["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "ak.read_cursor.update")
        .collect::<Vec<_>>();
    assert_eq!(read_cursor_fanouts.len(), 2);
    assert!(read_cursor_fanouts.iter().any(|event| {
        event["content"]["realm_id"] == realm_a
            && event["content"]["position"]["event_id"] == event_a
    }));
    assert!(read_cursor_fanouts.iter().any(|event| {
        event["content"]["realm_id"] == realm_b
            && event["content"]["position"]["event_id"] == event_b
    }));

    let bob_actor_core = actor_core_id("did:web:bob.example");
    let bob_markers = projected_read_markers(&state, bob_actor_core.as_str(), None);
    assert!(bob_markers.is_empty());
    let bob_messages: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(bob_messages["messages"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn push_blind_wakeup_rejects_e2ee_stable_identifiers() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let registered: Value = TestClient::post("http://server/_arkret/edge/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "push_gateway": "https://push.example",
            "push_key": "opaque",
            "platform": "desktop",
            "app_id": "inkson"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(registered["ok"], true);
    let push_target_id = registered["registration_id"]
        .as_str()
        .expect("register-device returns push target registration id");

    let rejected = TestClient::post("http://server/_arkret/edge/push/notify")
        .json(&json!({
            "notification": {
                "push_target_id": push_target_id,
                "wakeup_kind": "message",
                "timing_profile_hint": "default",
                "event_id": "ak:event:AT4Mf1sJBtwy4lOrQHfsPt7KtsUYo1LogrjcZnl5oAco",
                "realm_id": "ak:realm:AWRb-Bbhs1lJYMdAAkBJQ7GGxWqzFGTYiQRGUA3wq0Z5",
                "sender_actor_id": "did:web:bob.example",
                "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001"}]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(rejected.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));

    // `push-operations.schema.json#/$defs/push_notify_outcome` is a closed
    // response whose only members are `push_target_id` and a conserved
    // `outcomes[]` — one entry per requested device, each carrying its own
    // `gateway_status`. There is no top-level rejected array to read, and the
    // per-device status is the stronger assertion anyway: it says the sanitized
    // blind wakeup was accepted *for this device*, not merely that some list
    // stayed empty.
    let accepted: arkret_models_integration::models_push::PushNotifyOutcome =
        TestClient::post("http://server/_arkret/edge/push/notify")
            .json(&json!({
                "notification": {
                    "push_target_id": push_target_id,
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001"}]
                }
            }))
            .send(&app_from_state(state))
            .await
            .take_json()
            .await
            .expect("typed push notify outcome");
    assert_eq!(accepted.push_target_id, push_target_id);
    assert_eq!(
        accepted
            .outcomes
            .iter()
            .map(|outcome| (outcome.device_id.as_str(), outcome.gateway_status))
            .collect::<Vec<_>>(),
        vec![(
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
            arkret_models_integration::models_push::PushNotifyGatewayStatus::Accepted
        )]
    );
    assert!(
        accepted
            .outcomes
            .iter()
            .all(|outcome| outcome.reason_code.is_none()),
        "{:?}",
        accepted.outcomes
    );
}
