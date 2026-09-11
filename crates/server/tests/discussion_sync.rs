use std::collections::BTreeSet;
use std::sync::LazyLock;

use arkret_identifiers::{Did, EventId, InviteId, RealmId, new_prefixed_uuid7};
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

fn core_actor_id(actor: &str) -> String {
    arkret_wire::project_did_to_core_id(&Did::new(actor.to_owned()).expect("fixture actor DID"))
        .expect("fixture actor core id")
        .to_string()
}

fn local_account_id(state: &AppState, principal: &str) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(core_actor_id(principal)).expect("fixture principal core id"),
        state.service_core_id().clone(),
    )
}

fn local_actor_id(state: &AppState, principal: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(local_account_id(state, principal))
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
    .add_header(
        "Arkret-Operation",
        arkret_wire::generated::operation_ids::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1,
        true,
    )
    .send(&app_from_state(state))
    .await
    .take_string()
    .await
    .unwrap();
    serde_json::from_str(body.lines().next().unwrap()).unwrap()
}

async fn dev_token(state: AppState, actor: &str, device_suffix: &str) -> String {
    let actor_core = core_actor_id(actor);
    let device_id = format!("ak:device:01904100-0000-7000-8000-{device_suffix}");
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor_core,
            "device_id": device_id,
            "display_name": actor,
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let token = login["session_credential"].as_str().unwrap().to_owned();
    let verification_method = format!("{actor}#{device_id}");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        &arkret_signatures::development_signing_key_seed(&verification_method),
    );
    soland_test_support::project_authorized_principal_device(
        &state,
        actor,
        &device_id,
        &signing_key,
    )
    .await;
    token
}

/// Author the Realm genesis Event, then seed local read projections so the
/// tests can focus on downstream sync behaviour through the canonical
/// `POST /_arkret/self/events` path.
async fn seed_realm(state: &AppState, owner: &str, title: &str, history_access: &str) -> String {
    let realm_id =
        soland_test_support::cbs_basis::seed_event_derived_realm_genesis_event_with_history_access(
            state,
            owner,
            title,
            history_access.parse().expect("fixture history policy"),
        )
        .await;
    assert_eq!(
        state
            .test_projection()
            .lock()
            .realm_history_access(&realm_id),
        Some(history_access.to_owned()),
        "the accepted bootstrap cell must carry the requested initial history policy"
    );
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    let owner_id = arkret_identifiers::DidCoreId::new(core_actor_id(owner)).unwrap();
    let now = chrono::Utc::now();
    let owner_actor = local_actor_id(state, owner).to_string();

    let mut entry = RealmDirectoryEntry::new(
        typed_realm_id,
        title,
        soland_services::events::DirectoryProvenance::LocalOnly,
    );
    entry.description = Some("history access fixture".to_owned());
    entry.public = true;
    entry.members.insert(owner_id);
    state.test_realms().lock().upsert(entry);
    state
        .test_projection()
        .lock()
        .realm_join_rules
        .insert(realm_id.clone(), "public".to_owned());
    // Membership authorization requires the exact Actor index; the
    // principal-only Realm directory above is discovery data, not authority.
    state.test_projection().lock().members.insert(
        (realm_id.clone(), owner_actor.clone()),
        SolandMembershipState {
            member: owner_actor.clone(),
            realm_id: realm_id.clone(),
            state: "join".to_owned(),
            role: "owner".to_owned(),
            membership_event_ref: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );

    state
        .test_persistence()
        .realm_meta()
        .put(
            &realm_id,
            &RealmMetaRecord {
                owner: owner_actor,
                deleted: false,
                discoverability: "public".to_owned(),
                history_access: history_access.to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: std::collections::BTreeSet::from([state
                    .service_id()
                    .clone()]),
                plaintext_visible_service_classes: std::collections::BTreeMap::from([(
                    state.service_id().clone(),
                    std::collections::BTreeSet::from([PlaintextDataClassKind::MessageContent]),
                )]),
                minimal_metadata_realm: false,
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
/// `ak.member.state{membership:"join", member_id: new_member}` event. The
/// projection layer records `member.joined_at` (used by sync's
/// history_access gate) and updates `state.test_realms().members` via
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
        "member_id": local_actor_id(&state, new_member_did),
        "membership": "join",
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
        causal_refs: Vec::new(),
    })
    .await;
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {owner_token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            true,
        )
        .json(&serde_json::json!({"event": event}))
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
    inviter_id: &str,
    invitee_id: &str,
) -> String {
    let now = chrono::Utc::now();
    let inviter_account = local_account_id(state, inviter_id);
    let invitee_account = local_account_id(state, invitee_id);
    let invitee_actor = arkret_wire::ActorId::account(invitee_account.clone()).to_string();
    let invite_event_id = EventId::new(soland_test_support::fixture_content_bound_id("ak:event:"))
        .expect("fixture invite producer Event id");
    let invite_id = InviteId::from_event_id(&invite_event_id).to_string();
    state
        .test_persistence()
        .realm_invites()
        .put(RealmInviteRecord {
            invite_id: invite_id.clone(),
            realm_id: realm_id.to_owned(),
            inviter_id: inviter_account.to_string(),
            invitee_id: Some(invitee_account.to_string()),
            introduction_evidence_digest: Some(format!("sha256:{}", "1".repeat(64))),
            third_party_invite: None,
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
        (realm_id.to_owned(), invitee_actor.clone()),
        SolandMembershipState {
            member: invitee_actor,
            realm_id: realm_id.to_owned(),
            state: "invite".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
            invited_at: Some(now),
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
    // The read-model row alone is not the Realm's state. `ak.invite.accept`
    // resolves its registered pre-state from the invite lifecycle cell and
    // releases the invitee's live-target slot, so a fixture that seeded only
    // the row would be admitting an Event against a Realm that never claimed
    // the slot (`governance-objects.md` section 5.3).
    state.test_projections().cache_cell(
        arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.invite.lifecycle.v1:{invite_id}"
        ))
        .expect("fixture invite lifecycle cell"),
        json!("pending"),
    );
    state.test_projections().cache_cell(
        arkret_schema::invite_live_target_cell(&invitee_account)
            .expect("registered live-target subject rule"),
        json!(invite_event_id.as_str()),
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
    // A directed accept carries the stored invitee: it is the only signed
    // source the live-target release write can derive its subject from, and the
    // registered pre-state requirement rejects an accept that omits it.
    let payload = json!({
        "invite_id": invite_id,
        "invitee_account_id": local_account_id(&state, actor_did),
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
        causal_refs: Vec::new(),
    })
    .await;
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            true,
        )
        .json(&serde_json::json!({"event": event}))
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
        causal_refs: Vec::new(),
    })
    .await;
    let sent: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            true,
        )
        .json(&serde_json::json!({"event": event}))
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
        .map(|member| local_actor_id(state, member).to_string())
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
            history_access: "since_join".to_owned(),
            content_encryption_floor: Some("e2ee_required".to_owned()),
            metadata_encryption_floor: Some("e2ee_required".to_owned()),
            encryption_profile: "mls_rfc9420".to_owned(),
            content_scheme: Some("mls_rfc9420".to_owned()),
            durability_policy: None,
            mls_group_ref: Some(format!("ak:mls:mls_rfc9420:{circle_id}")),
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: local_actor_id(state, created_by).to_string(),
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
            object_revision_heads: Vec::new(),
            tracks: std::collections::BTreeMap::from([(
                arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION
                    .to_owned(),
                arkret_models_collaboration::objects::profiles::StrandTrack::discussion_primary(),
            )]),
            title: "Confidential discussion".to_owned(),
            summary: None,
            content: None,
            encrypted_content: None,
            fields: Default::default(),
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            stage: None,
            stage_changed_at: None,
            created_by: local_actor_id(state, created_by).to_string(),
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
    // The message does not carry scope_circle_id. Its Circle scope, purpose,
    // group id and AAD are reconstructed from the signed outer Event and the
    // exact winning group-state Event.
    let payload = json!({
        "strand_id": strand_id_for_realm(realm_id),
        "track_name": "discussion",
        "encrypted_content": {
            "version": "1.0",
            "content_type": "application/vnd.arkret.message+json",
            "encryption_context": {
                "epoch": 1,
                "group_state_ref": soland_test_support::fixture_content_bound_id("ak:event:")
            },
            "ciphertext": "Q2lyY2xlQ2lwaGVydGV4dA"
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
        causal_refs: Vec::new(),
    })
    .await;
    let sent: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            true,
        )
        .json(&serde_json::json!({"event": event}))
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
    let (accepted_event_id, sent) =
        submit_projection_event_result(state, token, actor_id, device_id, realm_id, kind, payload)
            .await;
    assert!(
        sent["accepted"][0].as_str() == Some(accepted_event_id.as_str()),
        "{kind} submit failed: {sent:?}"
    );
    accepted_event_id
}

#[allow(
    clippy::too_many_arguments,
    reason = "the integration helper mirrors the full signed Event submission envelope"
)]
async fn submit_projection_event_with_causal_refs(
    state: AppState,
    token: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    causal_refs: Vec<arkret_identifiers::Hash>,
) -> String {
    let (accepted_event_id, sent) = submit_projection_event_result_with_causal_refs(
        state,
        token,
        actor_id,
        device_id,
        realm_id,
        kind,
        payload,
        causal_refs,
    )
    .await;
    assert!(
        sent["accepted"][0].as_str() == Some(accepted_event_id.as_str()),
        "{kind} causal submit failed: {sent:?}"
    );
    accepted_event_id
}

async fn submit_projection_event_result(
    state: AppState,
    token: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> (String, Value) {
    submit_projection_event_result_with_causal_refs(
        state,
        token,
        actor_id,
        device_id,
        realm_id,
        kind,
        payload,
        Vec::new(),
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "the integration helper mirrors the full signed Event submission envelope"
)]
async fn submit_projection_event_result_with_causal_refs(
    state: AppState,
    token: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    causal_refs: Vec<arkret_identifiers::Hash>,
) -> (String, Value) {
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
        causal_refs,
    })
    .await;
    let accepted_event_id = event["event_id"]
        .as_str()
        .expect("signed projection Event id")
        .to_owned();
    let sent: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            true,
        )
        .json(&serde_json::json!({"event": event}))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    (accepted_event_id, sent)
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
    causal_refs: Vec<arkret_identifiers::Hash>,
}

async fn signed_event(input: SignedEvent<'_>) -> Value {
    let SignedEvent {
        state,
        token,
        event_id: _event_id,
        actor_id,
        device_id,
        realm_id,
        kind,
        payload,
        causal_refs,
    } = input;
    let actor_did = Did::new(actor_id.to_owned()).expect("fixture actor DID");
    let actor = arkret_wire::project_did_to_core_id(&actor_did)
        .expect("fixture actor DID projects to a core id");
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierState =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"actor_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(actor.clone(), state.service_core_id())), "realm_id": realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_EVENTS_READ_FRONTIER_V1,
                true,
            )
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
    let verification_method = arkret_wire::DidUrl::new(format!("{actor_id}#{device_id}"))
        .expect("fixture verification method is a DID URL");
    let scope_ref = derived_scope_ref(state, realm_id, kind, &payload);
    let mut event = arkret_wire::test_support::raw_event_at(
        kind,
        scope_ref,
        actor.clone(),
        state.service_core_id().clone(),
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
    event.causal_refs = causal_refs;
    // `seed_realm` writes the Realm straight into `AppState` instead of
    // bootstrapping it through `ak.realm.create`, so the Realm owns no sealed
    // governance state of its own. Every reducer-input Event still has to be a
    // DataEvent or a Control Move (`event-auth-state-resolution.md` §5), and a
    // DataEvent's `seal_ref` has to resolve to a Seal whose covered state
    // authorizes the receiver-derived writes — so the genesis unit is sealed
    // here, per author, before the envelope names it.
    let fixture_basis =
        soland_test_support::cbs_basis::FixtureBasis::shared(&DATA_PLANE_GRANT_ACTIONS);
    soland_test_support::cbs_basis::seed_realm_basis(state, realm_id, actor_id, fixture_basis)
        .await;
    soland_test_support::cbs_basis::apply_registered_cbs_plane(
        &mut event,
        &verification_method,
        fixture_basis,
    );
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        arkret_signatures::development_signing_key_seed(verification_method.as_str()),
        actor_did,
        verification_method.clone(),
    );
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .expect("SDK Event signer accepts discussion fixture");
    let event = event.into_event();
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
    arkret_identifiers::RealmId::new(realm_id.to_owned())
        .map(|realm_id| {
            arkret_identifiers::StrandId::from_event_id(&realm_id.event_id()).to_string()
        })
        .unwrap_or_else(|_| "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC".to_owned())
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
        .unwrap_or_else(|| panic!("event query response has no events collection: {events:?}"))
        .iter()
        .filter_map(|event| {
            event["payload"]["content"]["body"]
                .as_str()
                .map(ToOwned::to_owned)
        })
        .collect()
}

#[test]
fn since_join_hides_pre_join_messages_from_sync_and_events_query() {
    run_discussion_sync_test_on_deep_stack(
        since_join_hides_pre_join_messages_from_sync_and_events_query_body,
    );
}

async fn since_join_hides_pre_join_messages_from_sync_and_events_query_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let _bob_session_device = dev_token(state.clone(), bob_did, "b0b000000000").await;
    let bob = _bob_session_device;
    let realm_id = seed_realm(&state, alice_did, "since-join history", "since_join").await;

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

    let events: Value = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"realm_ids": [realm_id], "limit": 20}))
        .add_header("authorization", format!("Bearer {bob}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::generated::operation_ids::ServiceOperationId::SELF_EVENTS_READ_SCAN_V1,
            true,
        )
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

#[test]
fn since_join_incremental_sync_includes_post_join_messages_after_cursor() {
    run_discussion_sync_test_on_deep_stack(
        since_join_incremental_sync_includes_post_join_messages_after_cursor_body,
    );
}

async fn since_join_incremental_sync_includes_post_join_messages_after_cursor_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob = dev_token(state.clone(), bob_did, "b0b000000020").await;
    let realm_id = seed_realm(
        &state,
        alice_did,
        "since-join incremental history",
        "since_join",
    )
    .await;

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

#[test]
fn invite_accept_member_receives_since_join_messages_after_accept() {
    run_discussion_sync_test_on_deep_stack(
        invite_accept_member_receives_since_join_messages_after_accept_body,
    );
}

async fn invite_accept_member_receives_since_join_messages_after_accept_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob_device_id = "ak:device:01904100-0000-7000-8000-b0b000000003";
    let bob = dev_token(state.clone(), bob_did, "b0b000000003").await;
    let realm_id = seed_realm(
        &state,
        alice_did,
        "invite accept since-join history",
        "since_join",
    )
    .await;

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
    let bob_actor = local_actor_id(&state, bob_did).to_string();
    assert!(
        state
            .test_projection()
            .lock()
            .member(&realm_id, &bob_actor)
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
            .is_some_and(|realm| realm.members.contains(
                &arkret_wire::project_did_to_core_id(&Did::new(bob_did.to_owned()).unwrap(),)
                    .unwrap(),
            )),
        "ak.invite.accept must add the invitee_id to the Realm directory"
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

#[test]
fn shared_history_allows_late_joiner_to_backfill_prior_messages() {
    run_discussion_sync_test_on_deep_stack(
        shared_history_allows_late_joiner_to_backfill_prior_messages_body,
    );
}

async fn shared_history_allows_late_joiner_to_backfill_prior_messages_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob = dev_token(state.clone(), bob_did, "b0b000000002").await;
    let realm_id = seed_realm(
        &state,
        alice_did,
        "shared history",
        "all_history_for_current_members",
    )
    .await;

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

    let events: Value = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"realm_ids": [realm_id], "limit": 20}))
        .add_header("authorization", format!("Bearer {bob}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::generated::operation_ids::ServiceOperationId::SELF_EVENTS_READ_SCAN_V1,
            true,
        )
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

#[test]
fn circle_scoped_encrypted_message_is_hidden_from_realm_member_outside_circle() {
    run_discussion_sync_test_on_deep_stack(
        circle_scoped_encrypted_message_is_hidden_from_realm_member_outside_circle_body,
    );
}

async fn circle_scoped_encrypted_message_is_hidden_from_realm_member_outside_circle_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000010";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000010").await;
    let bob_did = BOB_DID.as_str();
    let bob = dev_token(state.clone(), bob_did, "b0b000000010").await;
    let mallory_did = MALLORY_DID.as_str();
    let mallory = dev_token(state.clone(), mallory_did, "ca2010000010").await;
    let realm_id = seed_realm(
        &state,
        alice_did,
        "circle scoped e2ee",
        "all_history_for_current_members",
    )
    .await;
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
        .add_header(
            "Arkret-Operation",
            arkret_wire::generated::operation_ids::ServiceOperationId::SELF_EVENTS_RESOURCE_GET_V1,
            true,
        )
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
    let encrypted_content = bob_read["event"]["payload"]["encrypted_content"]
        .as_object()
        .expect("encrypted_content object");
    assert_eq!(
        encrypted_content
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "ciphertext",
            "content_type",
            "encryption_context",
            "version"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        "encrypted message MUST use the minimal closed wire: {bob_read:?}"
    );

    let mallory_read = TestClient::get(format!("http://server/_arkret/self/events/{event_id}"))
        .add_header("authorization", format!("Bearer {mallory}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::generated::operation_ids::ServiceOperationId::SELF_EVENTS_RESOURCE_GET_V1,
            true,
        )
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(mallory_read.status_code.unwrap().as_u16(), 404);
}

#[test]
fn chat_projection_exposes_reactions_reply_and_mentions() {
    run_discussion_sync_test_on_deep_stack(
        chat_projection_exposes_reactions_reply_and_mentions_body,
    );
}

async fn chat_projection_exposes_reactions_reply_and_mentions_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob_account = local_account_id(&state, bob_did);
    let bob_actor = local_actor_id(&state, bob_did).to_string();
    let bob_device_id = "ak:device:01904100-0000-7000-8000-b0b000000011";
    let bob = dev_token(state.clone(), bob_did, "b0b000000011").await;
    let realm_id = seed_realm(
        &state,
        alice_did,
        "chat projection metadata",
        "all_history_for_current_members",
    )
    .await;
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
                "mentions": [{
                    "kind": "mention",
                    "subject_account_id": bob_account,
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
            "reply_to_id": root_message_ref.clone(),
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
        root["payload"]["content"]["mentions"][0]["subject_account_id"],
        serde_json::to_value(&bob_account).expect("encode mention subject account"),
    );

    {
        let projection = state.test_projection().lock();
        let reactions = projection.reactions_for_event(&root_event_id);
        assert!(
            reactions.iter().any(|reaction| {
                reaction.actor == local_actor_id(&state, alice_did).to_string()
                    && reaction.key == "+1"
                    && reaction.active
            }),
            "{reactions:?}"
        );
        assert!(
            reactions.iter().all(|reaction| reaction.actor != bob_actor),
            "{reactions:?}"
        );
    }

    let reply = timeline
        .iter()
        .find(|event| event["event_id"] == reply_event_id)
        .unwrap_or_else(|| panic!("reply message missing from sync projection: {timeline:?}"));
    assert_eq!(reply["payload"]["reply_to_id"], root_message_ref);
}

#[test]
fn poll_content_projection_replaces_votes() {
    run_discussion_sync_test_on_deep_stack(poll_content_projection_replaces_votes_body);
}

/// These deep Event admission/projection futures exceed libtest's default Windows thread stack.
fn run_discussion_sync_test_on_deep_stack<F>(body: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    let joined = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build discussion sync test runtime")
                .block_on(body());
        })
        .expect("spawn discussion sync test thread")
        .join();
    if let Err(payload) = joined {
        std::panic::resume_unwind(payload);
    }
}

async fn poll_content_projection_replaces_votes_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_did = ALICE_DID.as_str();
    let alice_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = BOB_DID.as_str();
    let bob_actor = local_actor_id(&state, bob_did).to_string();
    let bob_device_id = "ak:device:01904100-0000-7000-8000-b0b000000022";
    let bob = dev_token(state.clone(), bob_did, "b0b000000022").await;
    let carol_did = CAROL_DID.as_str();
    let carol_actor = local_actor_id(&state, carol_did).to_string();
    let carol_device_id = "ak:device:01904100-0000-7000-8000-ca2010000022";
    let carol = dev_token(state.clone(), carol_did, "ca2010000022").await;
    let realm_id = seed_realm(
        &state,
        alice_did,
        "poll content reducer",
        "all_history_for_current_members",
    )
    .await;
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
    let (invalid_event_id, invalid) = submit_projection_event_result(
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
                "body": "invalid poll response",
                "poll_response": {
                    "poll_ref": poll_ref,
                    "selections": ["unknown"]
                }
            }
        }),
    )
    .await;
    assert!(
        invalid["accepted"].as_array().is_none_or(|accepted| {
            !accepted
                .iter()
                .any(|id| id.as_str() == Some(invalid_event_id.as_str()))
        }),
        "invalid Poll response entered the canonical Event log: {invalid:?}"
    );
    assert!(
        invalid.to_string().contains("poll_selection_unknown"),
        "invalid Poll response did not expose the semantic rejection: {invalid:?}"
    );
    assert!(
        state
            .test_persistence()
            .events()
            .realm_events_newest_first(&realm_id)
            .await
            .expect("canonical Realm Event log")
            .iter()
            .all(|record| record.event_id.as_str() != invalid_event_id.as_str()),
        "invalid Poll response was durably written before semantic rejection"
    );

    let first_bob_response_event_id = submit_projection_event(
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
    let first_bob_response_digest = state
        .test_persistence()
        .events()
        .realm_events_newest_first(&realm_id)
        .await
        .expect("canonical Realm Event log after first Poll response")
        .into_iter()
        .find(|record| record.event_id == first_bob_response_event_id)
        .expect("first Poll response is durable")
        .canonical_digest;
    submit_projection_event_with_causal_refs(
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
        vec![
            arkret_identifiers::Hash::new(first_bob_response_digest)
                .expect("first Poll response digest parses"),
        ],
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
                .all(|choices| !choices.selections.contains("now")),
            "{poll_state:?}"
        );
        let mut expected_backup_voters = vec![bob_actor.clone(), carol_actor.clone()];
        expected_backup_voters.sort_unstable();
        let mut backup_voters = poll_state
            .votes
            .iter()
            .filter(|(_, choices)| choices.selections.contains("backup"))
            .map(|(actor, _)| actor.to_string())
            .collect::<Vec<_>>();
        backup_voters.sort_unstable();
        assert_eq!(backup_voters, expected_backup_voters, "{poll_state:?}");
    }

    let restarted = soland_test_support::app_state_with_persistence(
        test_config(),
        state.test_persistence().clone(),
    )
    .await;
    restarted.hydrate().await.expect("restart hydration");
    assert!(
        restarted
            .test_persistence()
            .events()
            .realm_events_newest_first(&realm_id)
            .await
            .expect("restarted canonical Realm Event log")
            .iter()
            .all(|record| record.event_id.as_str() != invalid_event_id.as_str()),
        "invalid Poll response appeared in the canonical Event log after restart"
    );
    {
        let projection = restarted.test_projection().lock();
        let poll_state = projection
            .poll(&poll_ref)
            .expect("valid Poll rehydrates from the canonical Event log");
        assert!(
            poll_state
                .votes
                .values()
                .all(|vote| vote.selections == BTreeSet::from(["backup".to_owned()])),
            "restart rehydrated a rejected or superseded Poll vote: {poll_state:?}"
        );
        let mut voters = poll_state
            .votes
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        voters.sort_unstable();
        let mut expected_voters = vec![bob_actor.clone(), carol_actor.clone()];
        expected_voters.sort_unstable();
        assert_eq!(voters, expected_voters);
    }
}
