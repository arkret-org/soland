use std::collections::BTreeSet;
use std::sync::LazyLock;

use arkret_identifiers::{Did, RealmId, new_prefixed_uuid7};
use arkret_wire::PlaintextDataClassKind;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland_domain::reducer::{
    CircleLifecycleState, CircleMembershipState, CircleProjection, ObjectLifecycleState,
    SolandMembershipState, StrandProjection,
};
use soland_http::config::AppConfig;
use soland_http::service;
use soland_http::state::{AppState, RealmDirectoryEntry};
use soland_storage::{RealmInviteRecord, RealmMetaRecord};
use soland_test_support::AppStateTestExt as _;

/// The data-plane actions this suite's DataEvents exercise.
///
/// `capability_refs.rs::validate_data_event_capability_refs` decides coverage
/// per receiver-derived cell over the effective grants the governance basis at
/// `seal_ref` yields for the actor, so the fixture basis has to name every
/// data-plane kind this suite submits and nothing beyond it. None of them are
/// reachable from the owner bootstrap grant: `ak.realm.admin`'s registry
/// `target_event_kinds` are Realm-facet Control Moves only.
const DATA_PLANE_GRANT_ACTIONS: [&str; 3] =
    ["ak.message.create", "ak.reaction.add", "ak.reaction.remove"];

static ALICE_DID: LazyLock<String> = LazyLock::new(|| test_signer_did([21_u8; 32]));
static BOB_DID: LazyLock<String> = LazyLock::new(|| test_signer_did([22_u8; 32]));
static CAROL_DID: LazyLock<String> = LazyLock::new(|| test_signer_did([23_u8; 32]));
static MALLORY_DID: LazyLock<String> = LazyLock::new(|| test_signer_did([24_u8; 32]));

fn test_signer_did(seed: [u8; 32]) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
    )
}

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        seed_demo_data: true,
        ..soland_test_support::app_config()
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

async fn account_subscribe_frame(state: AppState, token: &str, query: &str) -> Value {
    let body = TestClient::get(format!(
        "http://server/_arkret/self/account/subscribe?{query}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await
    .take_string()
    .await
    .unwrap();
    serde_json::from_str(body.lines().next().unwrap()).unwrap()
}

async fn dev_token(state: AppState, actor: &str, device_suffix: &str) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor,
            "device_id": format!("ak:device:01904100-0000-7000-8000-{device_suffix}"),
            "display_name": actor,
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

/// Seed a Realm directly via AppState so the tests can focus on downstream
/// sync behaviour through the canonical `POST /_arkret/self/events` path.
async fn seed_realm(
    state: &AppState,
    owner: &str,
    title: &str,
    history_visibility: &str,
) -> String {
    let realm_id = soland_test_support::fixture_content_bound_id("ak:realm:");
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    let owner_did = Did::new(owner.to_owned()).unwrap();
    let now = chrono::Utc::now();

    let mut entry = RealmDirectoryEntry::new(
        typed_realm_id,
        title,
        soland_services::events::DirectoryProvenance::LocalOnly,
    );
    entry.description = Some("history visibility fixture".to_owned());
    entry.public = true;
    entry.members.insert(owner_did);
    state.test_realms().lock().upsert(entry);
    state
        .test_projection()
        .lock()
        .realm_join_rules
        .insert(realm_id.clone(), "public".to_owned());

    state
        .test_persistence()
        .realm_meta()
        .put(
            &realm_id,
            &RealmMetaRecord {
                owner: owner.to_owned(),
                deleted: false,
                discoverability: "public".to_owned(),
                history_visibility: history_visibility.to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: std::collections::BTreeSet::from([
                    "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service".to_owned(),
                ]),
                plaintext_visible_service_classes: std::collections::BTreeMap::from([(
                    "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service".to_owned(),
                    std::collections::BTreeSet::from([PlaintextDataClassKind::MessageContent]),
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

async fn allow_service_message_plaintext(state: &AppState, realm_id: &str) {
    let service_id = state.service_id().clone();
    let mut meta = state
        .test_persistence()
        .realm_meta()
        .get(realm_id)
        .await
        .unwrap()
        .unwrap();
    meta.plaintext_visible_services.insert(service_id.clone());
    meta.plaintext_visible_service_classes.insert(
        service_id,
        BTreeSet::from([arkret_wire::PlaintextDataClassKind::MessageContent]),
    );
    meta.updated_at = chrono::Utc::now();
    state
        .test_persistence()
        .realm_meta()
        .put(realm_id, &meta)
        .await
        .unwrap();
}

/// Have the owner admit a new member by submitting a
/// `ak.member.state{membership:"join", actor_id: new_member}` event. The
/// projection layer records `member.joined_at` (used by sync's
/// history_visibility gate) and updates `state.test_realms().members` via
/// `project_member_state`. The owner is already a member (seeded by
/// `seed_realm`), so the event-log preflight `realm_has_member` check
/// admits the event.
async fn admit_member(
    state: AppState,
    owner_token: &str,
    owner_did: &str,
    owner_device_id: &str,
    new_member_did: &str,
    realm_id: &str,
) {
    let payload = json!({
        "realm_id": realm_id,
        "actor_id": new_member_did,
        "membership": "join",
        "delivery_status": "unroutable",
    });
    let event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let event = signed_event(SignedEvent {
        state: &state,
        token: owner_token,
        event_id: &event_id,
        actor_id: owner_did,
        device_id: owner_device_id,
        realm_id,
        kind: "ak.member.state",
        payload,
    })
    .await;
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {owner_token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        resp["accepted"][0].is_string(),
        "ak.member.state{{join}} admit failed: {resp:?}"
    );
}

async fn seed_pending_invite(
    state: &AppState,
    realm_id: &str,
    inviter: &str,
    invitee: &str,
) -> String {
    let now = chrono::Utc::now();
    let invite_id = new_prefixed_uuid7("ak:invite:");
    state
        .test_persistence()
        .realm_invites()
        .put(RealmInviteRecord {
            invite_id: invite_id.clone(),
            realm_id: realm_id.to_owned(),
            inviter: inviter.to_owned(),
            invitee: Some(invitee.to_owned()),
            invite_delivery_target: Some(json!({
                "recipient_service_id": state.service_id().clone(),
                "recipient_service_kind": "principal_server"
            })),
            introduction_evidence_digest: Some(format!("sha256:{}", "1".repeat(64))),
            third_party_id: None,
            join_rule_snapshot: Some(json!({"join_rule": "invite"})),
            invite_token: new_prefixed_uuid7("ak:invite-token:"),
            status: "pending".to_owned(),
            claim_nonces: std::collections::BTreeMap::new(),
            expires_at: Some(now + chrono::Duration::days(1)),
            created_at: now,
            updated_at: None,
        })
        .await
        .unwrap();
    state.test_projection().lock().members.insert(
        (realm_id.to_owned(), invitee.to_owned()),
        SolandMembershipState {
            member: invitee.to_owned(),
            realm_id: realm_id.to_owned(),
            state: "invite".to_owned(),
            role: "member".to_owned(),
            delivery_status: Some("routable".to_owned()),
            recipient_service_id: Some(state.service_id().to_string()),
            membership_event_ref: None,
            delivery_binding_frontier: None,
            invited_at: Some(now),
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
    invite_id
}

async fn accept_invite(
    state: AppState,
    token: &str,
    actor_did: &str,
    device_id: &str,
    realm_id: &str,
    invite_id: &str,
) {
    let payload = json!({
        "invite_id": invite_id,
    });
    let event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let event = signed_event(SignedEvent {
        state: &state,
        token,
        event_id: &event_id,
        actor_id: actor_did,
        device_id,
        realm_id,
        kind: "ak.invite.accept",
        payload,
    })
    .await;
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        resp["accepted"][0].is_string(),
        "ak.invite.accept failed: {resp:?}"
    );
}

async fn send_message(state: AppState, token: &str, realm_id: &str, body: &str) {
    let payload = json!({
        "strand_id": strand_id_for_realm(realm_id),
        "track_name": "discussion",
        "content": {
            "kind": "ak.content.text",
            "body": body,
            "format": "plain"
        }
    });
    let event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let event = signed_event(SignedEvent {
        state: &state,
        token,
        event_id: &event_id,
        actor_id: ALICE_DID.as_str(),
        device_id: "ak:device:01904100-0000-7000-8000-a11ce0000001",
        realm_id,
        kind: "ak.message.create",
        payload,
    })
    .await;
    let sent: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(sent["accepted"][0].is_string(), "send failed: {sent:?}");
}

fn install_projected_circle_scope(
    state: &AppState,
    realm_id: &str,
    circle_id: &str,
    created_by: &str,
    members: &[&str],
) {
    let now = chrono::Utc::now();
    let members = members
        .iter()
        .map(|member| (*member).to_owned())
        .collect::<BTreeSet<_>>();
    state.test_projection().lock().circles.insert(
        circle_id.to_owned(),
        CircleProjection {
            circle_id: circle_id.to_owned(),
            realm_id: realm_id.to_owned(),
            profile_ref: None,
            title: "Need to know".to_owned(),
            summary: None,
            display: serde_json::json!({"short_name":"Need","color_token":"slate","symbol":{"glyph":"ring"}}),
            directory_visibility: "members".to_owned(),
            join_rule: "invite".to_owned(),
            history_visibility: "joined".to_owned(),
            content_encryption_floor: Some("e2ee_required".to_owned()),
            metadata_encryption_floor: Some("e2ee_required".to_owned()),
            encryption_profile: "mls_rfc9420".to_owned(),
            mls_group_ref: Some(format!("ak:mls:mls_rfc9420:{circle_id}")),
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: created_by.to_owned(),
            created_at: now,
            updated_by: None,
            updated_at: None,
            members,
        },
    );
    let mut projection = state.test_projection().lock();
    for member in projection
        .circles
        .get(circle_id)
        .expect("circle projection inserted")
        .members
        .iter()
        .cloned()
        .collect::<Vec<_>>()
    {
        projection.circle_memberships.insert(
            (circle_id.to_owned(), member.clone()),
            CircleMembershipState {
                circle_id: circle_id.to_owned(),
                member,
                state: "join".to_owned(),
                invited_at: Some(now),
                joined_at: now,
                updated_at: now,
            },
        );
    }
}

/// AKP-0007 — bind a Strand to a Circle scope in the projection. A message
/// posted to this Strand inherits the Circle scope server-side (spec:
/// `scope_circle_id` is a Strand field, never carried on the message).
fn install_projected_strand_scope(
    state: &AppState,
    realm_id: &str,
    strand_id: &str,
    circle_id: &str,
    created_by: &str,
) {
    let now = chrono::Utc::now();
    state.test_projection().lock().strands.insert(
        strand_id.to_owned(),
        StrandProjection {
            strand_id: strand_id.to_owned(),
            realm_id: realm_id.to_owned(),
            tracks: std::collections::BTreeMap::from([(
                arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION.to_owned(),
                arkret_models_collaboration::objects::profiles::StrandTrackConfig::discussion_primary(),
            )]),
            title: "Confidential discussion".to_owned(),
            summary: None,
            fields: Default::default(),
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            created_by: created_by.to_owned(),
            created_at: now,
            history_basis_seals: Vec::new(),
            updated_by: None,
            updated_at: None,
            schema_refs: Vec::new(),
            schedule_revision_heads: Vec::new(),
            scope_circle_id: Some(circle_id.to_owned()),
        },
    );
}

async fn send_circle_scoped_encrypted_message(
    state: AppState,
    token: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
) -> String {
    let event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    // Spec-conforming encrypted message: `encrypted_content` (not the retired
    // `encrypted_payload`), `track_name`, and an aad carrying ONLY realm_id +
    // event_kind. The message does NOT carry scope_circle_id — its circle
    // scope is derived server-side from the Strand (install_projected_strand_scope).
    let payload = json!({
        "strand_id": strand_id_for_realm(realm_id),
        "track_name": "discussion",
        "encrypted_content": {
            "scheme": "mls_rfc9420",
            "version": "1.0",
            "group_id": soland_test_support::cba_basis::FIXTURE_MLS_GROUP_ID,
            "epoch": 1,
            "content_type": "application/json",
            "ciphertext": "Q2lyY2xlQ2lwaGVydGV4dA",
            "aad_visibility_event_id": "hidden",
            "aad": {
                "realm_id": realm_id,
                "event_kind": "ak.message.create"
            },
            "key_ref": {
                "algorithm": "MLS",
                "group_state_ref": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            },
            "aad_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "payload_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
        }
    });
    let event = signed_event(SignedEvent {
        state: &state,
        token,
        event_id: &event_id,
        actor_id,
        device_id,
        realm_id,
        kind: "ak.message.create",
        payload,
    })
    .await;
    let sent: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        sent["accepted"][0], event["event_id"],
        "circle scoped encrypted message submit failed: {sent:?}"
    );
    event["event_id"].as_str().unwrap().to_owned()
}

async fn submit_projection_event(
    state: AppState,
    token: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> String {
    let event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let event = signed_event(SignedEvent {
        state: &state,
        token,
        event_id: &event_id,
        actor_id,
        device_id,
        realm_id,
        kind,
        payload,
    })
    .await;
    let sent: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        sent["accepted"][0].as_str() == Some(event_id.as_str()),
        "{kind} submit failed: {sent:?}"
    );
    event_id
}

async fn submit_projection_event_status(
    state: AppState,
    token: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> (u16, String) {
    let event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let event = signed_event(SignedEvent {
        state: &state,
        token,
        event_id: &event_id,
        actor_id,
        device_id,
        realm_id,
        kind,
        payload,
    })
    .await;
    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.unwrap().as_u16();
    let body = response.take_string().await.unwrap_or_default();
    (status, body)
}

struct SignedEvent<'a> {
    state: &'a AppState,
    token: &'a str,
    event_id: &'a str,
    actor_id: &'a str,
    device_id: &'a str,
    realm_id: &'a str,
    kind: &'a str,
    payload: Value,
}

async fn signed_event(input: SignedEvent<'_>) -> Value {
    let SignedEvent {
        state,
        token,
        event_id,
        actor_id,
        device_id,
        realm_id,
        kind,
        payload,
    } = input;
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        TestClient::get(format!(
            "http://server/_arkret/self/events/frontier?actor_id={actor_id}&realm_id={realm_id}"
        ))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .expect("typed discussion actor Realm frontier");
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
        frontier.frontier
    else {
        panic!("combined Realm+actor selector returned the wrong variant");
    };
    let actor_seq = frontier.next_actor_seq;
    let prev_refs = frontier.frontier_event_ids;
    let now = chrono::Utc::now();
    let actor = arkret_identifiers::Did::new(actor_id.to_owned()).expect("fixture actor DID");
    let verification_method =
        arkret_wire::DidUrl::new(actor_id.strip_prefix("did:key:").map_or_else(
            || format!("{actor_id}#{device_id}"),
            |key| format!("{actor_id}#{key}"),
        ))
        .expect("fixture verification method is a DID URL");
    let scope_ref = derived_scope_ref(state, realm_id, kind, &payload);
    let mut event = arkret_wire::Event::new_with_id_at(
        arkret_wire::EventId::new(event_id.to_owned()).expect("fixture Event id"),
        kind,
        scope_ref,
        actor.clone(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-00000000",
            now.timestamp_millis().max(0) as u64
        ))
        .expect("fixture HLC"),
        payload,
        now,
    )
    .expect("SDK Event builder accepts discussion fixture");
    event.prev_refs = prev_refs;
    // `seed_realm` writes the Realm straight into `AppState` instead of
    // bootstrapping it through `ak.realm.create`, so the Realm owns no sealed
    // governance state of its own. Every reducer-input Event still has to be a
    // DataEvent or a Control Move (`event-auth-state-resolution.md` §5), and a
    // DataEvent's `seal_ref` has to resolve to a Seal whose covered state
    // authorizes the receiver-derived writes — so the genesis unit is sealed
    // here, per author, before the envelope names it.
    soland_test_support::cba_basis::seed_realm_basis(
        state,
        realm_id,
        actor_id,
        &DATA_PLANE_GRANT_ACTIONS,
    )
    .await;
    soland_test_support::cba_basis::apply_registered_cba_plane(
        &mut event,
        &verification_method,
        &DATA_PLANE_GRANT_ACTIONS,
    );
    let seed = if actor_id == BOB_DID.as_str() {
        [22_u8; 32]
    } else if actor_id == CAROL_DID.as_str() {
        [23_u8; 32]
    } else if actor_id == MALLORY_DID.as_str() {
        [24_u8; 32]
    } else {
        [21_u8; 32]
    };
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        seed,
        actor,
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .expect("SDK Event signer accepts discussion fixture");
    serde_json::to_value(event).expect("SDK Event serializes")
}

/// The producer-signed security scope of an Event, derived the way a receiver
/// derives it.
///
/// `event-envelope.schema.json` makes `scope_ref` a required producer-signed
/// member that enters `proof.event_digest`, and states that reducers
/// independently derive the Realm/Circle scope from the schema-validated
/// payload and accepted references, failing closed on any unequal field. For
/// `ak.message.create` that derivation is the message's Strand: a Strand bound
/// to a Circle scopes every message on it to that Circle. So the fixture reads
/// the same Strand binding the server reads instead of hardcoding a Realm
/// scope, which for a Circle-bound Strand would be a scope a conformant
/// receiver has to reject.
fn derived_scope_ref(
    state: &AppState,
    realm_id: &str,
    kind: &str,
    payload: &Value,
) -> arkret_wire::ScopeRef {
    let typed_realm_id = RealmId::new(realm_id.to_owned()).expect("fixture Realm id");
    let circle_id = (kind == "ak.message.create")
        .then(|| payload.get("strand_id").and_then(Value::as_str))
        .flatten()
        .and_then(|strand_id| {
            state
                .test_projection()
                .lock()
                .strand_scope_circle_id(strand_id)
        });
    match circle_id {
        Some(circle_id) => arkret_wire::ScopeRef::Circle {
            realm_id: typed_realm_id,
            circle_id: arkret_identifiers::CircleId::new(circle_id).expect("fixture Circle id"),
        },
        None => arkret_wire::ScopeRef::Realm {
            realm_id: typed_realm_id,
        },
    }
}

fn strand_id_for_realm(realm_id: &str) -> String {
    realm_id
        .strip_prefix("ak:realm:")
        .map(|suffix| format!("ak:strand:{suffix}"))
        .unwrap_or_else(|| "ak:strand:01904100-0000-8000-8000-f10dc0000001".to_owned())
}

fn sync_bodies(sync: &Value, realm_id: &str) -> Vec<String> {
    sync["realms"][realm_id]["timeline"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("sync response has no timeline events for {realm_id}: {sync:?}"))
        .iter()
        .filter_map(|event| {
            event["payload"]["content"]["body"]
                .as_str()
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn event_query_bodies(events: &Value) -> Vec<String> {
    events["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| {
            event["payload"]["content"]["body"]
                .as_str()
                .map(ToOwned::to_owned)
        })
        .collect()
}

#[tokio::test]
async fn joined_history_hides_pre_join_messages_from_sync_and_events_query() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let _bob_session_device = dev_token(state.clone(), bob_did, "b0b000000000").await;
    let bob = _bob_session_device;
    let realm_id = seed_realm(&state, alice_did, "joined history", "joined").await;

    send_message(state.clone(), &alice, &realm_id, "before bob joined").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &realm_id,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    send_message(state.clone(), &alice, &realm_id, "after bob joined").await;

    let sync = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    let bodies = sync_bodies(&sync, &realm_id);
    assert!(
        !bodies.contains(&"before bob joined".to_owned()),
        "{bodies:?}"
    );
    assert!(
        bodies.contains(&"after bob joined".to_owned()),
        "{bodies:?}"
    );

    let events: Value = TestClient::get(format!(
        "http://server/_arkret/self/events?realms={realm_id}&limit=20"
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let bodies = event_query_bodies(&events);
    assert!(
        !bodies.contains(&"before bob joined".to_owned()),
        "{bodies:?}"
    );
    assert!(
        bodies.contains(&"after bob joined".to_owned()),
        "{bodies:?}"
    );
}

#[tokio::test]
async fn joined_member_initial_sync_includes_current_pre_join_encryption_policy() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob = dev_token(state.clone(), bob_did, "b0b000000021").await;
    let realm_id = seed_realm(&state, alice_did, "joined security baseline", "joined").await;

    let mut meta = state
        .test_persistence()
        .realm_meta()
        .get(&realm_id)
        .await
        .unwrap()
        .unwrap();
    meta.encryption_profile = Some("mls_rfc9420".to_owned());
    state
        .test_persistence()
        .realm_meta()
        .put(&realm_id, &meta)
        .await
        .unwrap();

    let old_policy_event_id = submit_projection_event(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
        "ak.realm.policy_bundle",
        json!({
            "content_encryption_floor": "e2ee_required",
            "content_scheme": "mls_rfc9420",
            "metadata_encryption_floor": "e2ee_required",
            "policy_revision": 1
        }),
    )
    .await;
    let policy_event_id = submit_projection_event(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
        "ak.realm.policy_bundle",
        json!({
            "content_encryption_floor": "e2ee_required",
            "content_scheme": "mls_exporter_aead_v1",
            "metadata_encryption_floor": "e2ee_required",
            "policy_revision": 2
        }),
    )
    .await;
    send_message(
        state.clone(),
        &alice,
        &realm_id,
        "pre-join content remains hidden",
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &realm_id,
    )
    .await;

    let sync = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    assert!(
        !sync_bodies(&sync, &realm_id).contains(&"pre-join content remains hidden".to_owned()),
        "joined history must continue to hide pre-join data events: {sync:?}"
    );
    let state_events = sync["realms"][&realm_id]["state"]["events"]
        .as_array()
        .expect("initial state baseline");
    assert!(
        state_events
            .iter()
            .all(|event| event["event_id"] != old_policy_event_id),
        "initial security baseline must not leak superseded pre-join policy revisions"
    );
    let policy = state_events
        .iter()
        .find(|event| event["event_id"] == policy_event_id)
        .expect("current pre-join policy-components event must be in the member baseline");
    assert_eq!(policy["payload"]["content_scheme"], "mls_exporter_aead_v1");
}

#[tokio::test]
async fn joined_history_incremental_sync_includes_post_join_messages_after_cursor() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob = dev_token(state.clone(), bob_did, "b0b000000020").await;
    let realm_id = seed_realm(&state, alice_did, "joined incremental history", "joined").await;

    send_message(state.clone(), &alice, &realm_id, "before bob joined").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &realm_id,
    )
    .await;

    let baseline = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    let baseline_bodies = sync_bodies(&baseline, &realm_id);
    assert!(
        !baseline_bodies.contains(&"before bob joined".to_owned()),
        "{baseline:?}"
    );
    let cursor = baseline["cursor"]
        .as_str()
        .expect("baseline cursor")
        .to_owned();

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    send_message(state.clone(), &alice, &realm_id, "after bob baseline").await;

    let delta =
        account_subscribe_frame(state.clone(), &bob, &format!("catchup=true&after={cursor}")).await;
    let delta_bodies = sync_bodies(&delta, &realm_id);
    assert!(
        delta_bodies.contains(&"after bob baseline".to_owned()),
        "{delta:?}"
    );
}

#[tokio::test]
async fn invite_accept_member_receives_joined_history_messages_after_accept() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob_device_id = "ak:device:01904100-0000-7000-8000-b0b000000003";
    let bob = dev_token(state.clone(), bob_did, "b0b000000003").await;
    let realm_id = seed_realm(&state, alice_did, "invite accept joined history", "joined").await;

    let invite_id = seed_pending_invite(&state, &realm_id, alice_did, bob_did).await;
    accept_invite(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        &invite_id,
    )
    .await;
    assert!(
        state
            .test_projection()
            .lock()
            .member(&realm_id, bob_did)
            .is_some_and(|member| member.state == "join"),
        "ak.invite.accept must project joined membership"
    );
    assert_eq!(
        state
            .test_persistence()
            .realm_invites()
            .get(&invite_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        "accepted",
        "ak.invite.accept must close the invite lifecycle"
    );
    assert!(
        state
            .test_realms()
            .lock()
            .get(&RealmId::new(realm_id.clone()).unwrap())
            .is_some_and(|realm| realm
                .members
                .contains(&Did::new(bob_did.to_owned()).unwrap())),
        "ak.invite.accept must add the invitee to the Realm directory"
    );

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    send_message(
        state.clone(),
        &alice,
        &realm_id,
        "after invite accept joined history",
    )
    .await;

    let sync = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    assert!(
        sync_bodies(&sync, &realm_id).contains(&"after invite accept joined history".to_owned()),
        "{sync:?}"
    );
}

#[tokio::test]
async fn shared_history_allows_late_joiner_to_backfill_prior_messages() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob = dev_token(state.clone(), bob_did, "b0b000000002").await;
    let realm_id = seed_realm(&state, alice_did, "shared history", "shared").await;

    send_message(state.clone(), &alice, &realm_id, "shared before join").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &realm_id,
    )
    .await;

    let sync = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    assert!(
        sync_bodies(&sync, &realm_id).contains(&"shared before join".to_owned()),
        "{sync:?}"
    );

    let events: Value = TestClient::get(format!(
        "http://server/_arkret/self/events?realms={realm_id}&limit=20"
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(
        event_query_bodies(&events).contains(&"shared before join".to_owned()),
        "{events:?}"
    );
}

#[tokio::test]
async fn circle_scoped_encrypted_message_is_hidden_from_realm_member_outside_circle() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000010";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000010").await;
    let bob_did = BOB_DID.as_str();
    let bob = dev_token(state.clone(), bob_did, "b0b000000010").await;
    let mallory_did = MALLORY_DID.as_str();
    let mallory = dev_token(state.clone(), mallory_did, "ca2010000010").await;
    let realm_id = seed_realm(&state, alice_did, "circle scoped e2ee", "shared").await;
    for actor in [alice_did, bob_did, mallory_did] {
        admit_member(
            state.clone(),
            &alice,
            alice_did,
            alice_device_id,
            actor,
            &realm_id,
        )
        .await;
    }

    let circle_id = soland_test_support::fixture_content_bound_id("ak:circle:");
    install_projected_circle_scope(
        &state,
        &realm_id,
        &circle_id,
        alice_did,
        &[alice_did, bob_did],
    );
    // Bind the discussion Strand to the Circle. The message posted below carries
    // NO scope_circle_id — soland derives its effective scope from this Strand.
    install_projected_strand_scope(
        &state,
        &realm_id,
        &strand_id_for_realm(&realm_id),
        &circle_id,
        alice_did,
    );
    let event_id = send_circle_scoped_encrypted_message(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
    )
    .await;

    let bob_sync = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    let bob_events = bob_sync["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    let bob_event = bob_events
        .iter()
        .find(|event| event["event_id"].as_str() == Some(event_id.as_str()))
        .unwrap_or_else(|| panic!("Circle member did not receive scoped event: {bob_sync:?}"));
    // The v1 Event Envelope has no `effective_scope` member — soland refuses a
    // client-supplied one as reducer-managed
    // (`envelope_core.rs`: "envelope.effective_scope is reducer-managed"), and
    // `event-envelope.schema.json` closes the envelope over `scope_ref`
    // instead. `scope_ref` is the producer-signed security scope that enters
    // `proof.event_digest`, so the Circle scope is now inside the signed
    // transcript rather than stamped on beside it.
    assert_eq!(
        bob_event["scope_ref"],
        json!({
            "kind": "circle",
            "realm_id": realm_id,
            "circle_id": circle_id,
        })
    );
    assert!(bob_event["payload"]["encrypted_content"].is_object());

    let mallory_sync = account_subscribe_frame(state.clone(), &mallory, "catchup=true").await;
    let mallory_events = mallory_sync["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert!(
        mallory_events
            .iter()
            .all(|event| event["event_id"].as_str() != Some(event_id.as_str())),
        "Realm member outside Circle must not receive Circle-scoped ciphertext: {mallory_sync:?}"
    );

    let bob_read: Value = TestClient::get(format!("http://server/_arkret/self/events/{event_id}"))
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(bob_read["event"]["event_id"], event_id);
    // The Circle scope rides in the signed `scope_ref` — NOT inside the
    // encrypted envelope's aad (spec: messages don't carry scope_circle_id).
    // The server-derived half of the same fact is the Strand→Circle binding
    // the visibility gate reads: it is what hid this Event from Mallory above,
    // and it is what a conformant receiver re-derives `scope_ref` from.
    assert_eq!(
        bob_read["event"]["scope_ref"],
        json!({
            "kind": "circle",
            "realm_id": realm_id,
            "circle_id": circle_id,
        })
    );
    assert_eq!(
        state
            .test_projection()
            .lock()
            .strand_scope_circle_id(&strand_id_for_realm(&realm_id)),
        Some(circle_id.clone()),
        "the Circle scope the server derives for this Strand"
    );
    assert!(
        bob_read["event"]["payload"]["encrypted_content"]["aad"]
            .get("scope_circle_id")
            .is_none(),
        "encrypted message aad MUST NOT carry scope_circle_id (spec): {bob_read:?}"
    );

    let mallory_read = TestClient::get(format!("http://server/_arkret/self/events/{event_id}"))
        .add_header("authorization", format!("Bearer {mallory}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(mallory_read.status_code.unwrap().as_u16(), 404);
}

#[tokio::test]
async fn chat_projection_exposes_reactions_reply_and_mention_routing() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob_device_id = "ak:device:01904100-0000-7000-8000-b0b000000011";
    let bob = dev_token(state.clone(), bob_did, "b0b000000011").await;
    let realm_id = seed_realm(&state, alice_did, "chat projection metadata", "shared").await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &realm_id,
    )
    .await;

    let root_event_id = submit_projection_event(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
        "ak.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.text",
                "body": "root mentions bob",
                "mention_routing_hint": {
                    "mentioned": [bob_did]
                },
                "mentions": [{
                    "subject_id": bob_did,
                    "mention_text_original": "@bob"
                }]
            }
        }),
    )
    .await;
    let root_message_ref = root_event_id.replacen("ak:event:", "ak:message:", 1);
    let reply_event_id = submit_projection_event(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ak.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "reply_to": root_message_ref.clone(),
            "content": {
                "kind": "ak.content.text",
                "body": "reply to root"
            }
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
        "ak.reaction.add",
        json!({
            "target_ref": root_message_ref.clone(),
            "key": "+1"
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ak.reaction.add",
        json!({
            "target_ref": root_message_ref.clone(),
            "key": "+1"
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ak.reaction.remove",
        json!({
            "target_ref": root_message_ref.clone(),
            "key": "+1"
        }),
    )
    .await;

    let sync = account_subscribe_frame(state.clone(), &alice, "catchup=true").await;
    let timeline = sync["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .expect("timeline events");
    let root = timeline
        .iter()
        .find(|event| event["event_id"] == root_event_id)
        .unwrap_or_else(|| panic!("root message missing from sync projection: {timeline:?}"));
    assert_eq!(
        root["payload"]["content"]["mention_routing_hint"]["mentioned"],
        json!([bob_did])
    );
    assert_eq!(
        root["payload"]["content"]["mentions"][0]["subject_id"],
        bob_did
    );

    {
        let projection = state.test_projection().lock();
        let reactions = projection.reactions_for_event(&root_event_id);
        assert!(
            reactions.iter().any(|reaction| {
                reaction.actor == alice_did && reaction.key == "+1" && reaction.active
            }),
            "{reactions:?}"
        );
        assert!(
            reactions.iter().all(|reaction| reaction.actor != bob_did),
            "{reactions:?}"
        );
    }

    let reply = timeline
        .iter()
        .find(|event| event["event_id"] == reply_event_id)
        .unwrap_or_else(|| panic!("reply message missing from sync projection: {timeline:?}"));
    assert_eq!(reply["payload"]["reply_to"], root_message_ref);
}

#[tokio::test]
async fn poll_content_projection_replaces_votes_and_rejects_after_close() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob_device_id = "ak:device:01904100-0000-7000-8000-b0b000000022";
    let bob = dev_token(state.clone(), bob_did, "b0b000000022").await;
    let carol_did = CAROL_DID.as_str();
    let carol_device_id = "ak:device:01904100-0000-7000-8000-ca2010000022";
    let carol = dev_token(state.clone(), carol_did, "ca2010000022").await;
    let realm_id = seed_realm(&state, alice_did, "poll content reducer", "shared").await;
    allow_service_message_plaintext(&state, &realm_id).await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &realm_id,
    )
    .await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        carol_did,
        &realm_id,
    )
    .await;

    let poll_event_id = submit_projection_event(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
        "ak.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.poll",
                "body": "Which window?",
                "poll": {
                    "kind": "disclosed",
                    "max_selections": 1,
                    "answers": [
                        {"id": "now", "text": {"kind": "ak.content.text", "body": "Now"}},
                        {"id": "backup", "text": {"kind": "ak.content.text", "body": "After backup"}}
                    ]
                }
            }
        }),
    )
    .await;
    let poll_ref = poll_event_id.replacen("ak:event:", "ak:message:", 1);
    submit_projection_event(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ak.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.poll.response",
                "body": "poll response",
                "poll_response": {
                    "poll_ref": poll_ref,
                    "selections": ["now"]
                }
            }
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ak.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.poll.response",
                "body": "poll response",
                "poll_response": {
                    "poll_ref": poll_ref,
                    "selections": ["backup"]
                }
            }
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &carol,
        carol_did,
        carol_device_id,
        &realm_id,
        "ak.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.poll.response",
                "body": "poll response",
                "poll_response": {
                    "poll_ref": poll_ref,
                    "selections": ["backup"]
                }
            }
        }),
    )
    .await;

    let sync = account_subscribe_frame(state.clone(), &alice, "catchup=true").await;
    let timeline = sync["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .expect("timeline events");
    let poll = timeline
        .iter()
        .find(|event| event["event_id"] == poll_event_id)
        .unwrap_or_else(|| panic!("poll missing from sync projection: {timeline:?}"));
    assert_eq!(poll["payload"]["content"]["kind"], "ak.content.poll");
    {
        let projection = state.test_projection().lock();
        let poll_state = projection.poll(&poll_ref).expect("poll projection");
        assert!(
            poll_state
                .votes
                .values()
                .all(|choices| !choices.contains("now")),
            "{poll_state:?}"
        );
        let mut expected_backup_voters = vec![bob_did, carol_did];
        expected_backup_voters.sort_unstable();
        assert_eq!(
            poll_state
                .votes
                .iter()
                .filter(|(_, choices)| choices.contains("backup"))
                .map(|(actor, _)| actor.as_str())
                .collect::<Vec<_>>(),
            expected_backup_voters
        );
    }

    submit_projection_event(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
        "ak.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.poll.close",
                "body": "poll closed",
                "poll_id": poll_ref
            }
        }),
    )
    .await;
    let (status, body) = submit_projection_event_status(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ak.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.poll.response",
                "body": "poll response",
                "poll_response": {
                    "poll_ref": poll_ref,
                    "selections": ["now"]
                }
            }
        }),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("poll_closed"), "{body}");
}
