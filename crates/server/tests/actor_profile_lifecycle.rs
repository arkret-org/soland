//! Account Actor Profile create/update and the one authorized cross-principal
//! read of the result.
//!
//! Both halves are covered here because they are one contract seen from two
//! sides: `ak.profile.create` and `ak.profile.update` write the same registered
//! cell in the owner's Principal Control Realm
//! (`zh/discovery/profiles-presence.md` section 2.3), and
//! `ak.self.actor_profile.read.resolve.v1` is the only way another participant
//! reaches that cell's value plus the exact signed Event behind it
//! (`zh/sync/service-http-binding.md` section 3.3.1.1).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use arkret_identifiers::{ActorProfileId, Did, DidCoreId, RealmId};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland_domain::reducer::SolandMembershipState;
use soland_http::config::{AppConfig, ObjectStorageConfig};
use soland_http::service;
use soland_http::state::{AppState, RealmDirectoryEntry};
use soland_storage::RealmMetaRecord;
use soland_test_support::AppStateTestExt as _;

/// Only the two profile kinds ride the data-plane grant this fixture seals.
const PROFILE_GRANT_ACTIONS: [&str; 2] = ["ak.profile.create", "ak.profile.update"];

const AVATAR_BLOB: &str =
    "ak:blob:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static ALICE_DID: LazyLock<String> = LazyLock::new(|| fixture_did([21_u8; 32]));
static BOB_DID: LazyLock<String> = LazyLock::new(|| fixture_did([22_u8; 32]));
static CAROL_DID: LazyLock<String> = LazyLock::new(|| fixture_did([23_u8; 32]));
static DAVE_DID: LazyLock<String> = LazyLock::new(|| fixture_did([24_u8; 32]));

fn fixture_did(seed: [u8; 32]) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
    )
}

fn run_large_stack_async_test<F, Fut>(test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .name("actor-profile-lifecycle-test".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build actor profile test runtime")
                .block_on(test());
        })
        .expect("spawn actor profile test thread")
        .join()
        .expect("actor profile test thread panicked");
}

fn test_config() -> AppConfig {
    AppConfig {
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-actor-profile-blobs"),
        ),
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: BTreeMap::new(),
        ..soland_test_support::app_config()
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

/// Operation bodies are byte-for-byte canonical JSON, so a fixture serializes
/// them the same way a conformant client does.
fn canonical_request_body<T: serde::Serialize>(value: &T) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical request body")
}

fn core_id(did: &str) -> DidCoreId {
    arkret_wire::project_did_to_core_id(&Did::new(did.to_owned()).expect("fixture DID"))
        .expect("fixture DID projects to a core id")
}

fn local_actor(state: &AppState, did: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        core_id(did),
        state.service_core_id().clone(),
    ))
}

/// One stable device per fixture principal. `ak:device:` ids are UUIDv7, so the
/// node field carries the fixture's seed byte rather than text from its DID.
fn device_id_for(did: &str) -> String {
    let seed = FIXTURES
        .iter()
        .find(|(fixture, _)| fixture.as_str() == did)
        .map(|(_, seed)| *seed)
        .expect("device ids exist only for the declared fixture principals");
    format!("ak:device:01904100-0000-7000-8000-0000000000{seed:02x}")
}

/// Every fixture principal and the seed byte that names both its signing key
/// and its one device.
static FIXTURES: LazyLock<[(String, u8); 4]> = LazyLock::new(|| {
    [
        (ALICE_DID.clone(), 21),
        (BOB_DID.clone(), 22),
        (CAROL_DID.clone(), 23),
        (DAVE_DID.clone(), 24),
    ]
});

async fn dev_token(state: AppState, did: &str) -> String {
    let device_id = device_id_for(did);
    let mut response = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": core_id(did),
            "device_id": device_id,
            "display_name": "fixture",
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code;
    let login: Value = response
        .take_json()
        .await
        .unwrap_or_else(|error| panic!("dev-login did not return JSON: {error:?}"));
    assert_eq!(status, Some(StatusCode::OK), "dev-login failed: {login}");
    let token = login["session_credential"]
        .as_str()
        .expect("dev-login session credential")
        .to_owned();
    let verification_method = format!("{did}#{device_id}");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        &arkret_signatures::development_signing_key_seed(&verification_method),
    );
    soland_test_support::project_authorized_principal_device(&state, did, &device_id, &signing_key)
        .await;
    token
}

/// Stand up a shared Collaboration Realm owned by `owner`, with local read
/// projections seeded the way the other HTTP fixtures do.
async fn seed_shared_realm(state: &AppState, owner: &str, title: &str) -> String {
    let realm_id =
        soland_test_support::cbs_basis::seed_event_derived_realm_genesis_event(state, owner, title)
            .await;
    let typed_realm_id = RealmId::new(realm_id.clone()).expect("fixture Realm id");
    let now = chrono::Utc::now();
    let owner_actor = local_actor(state, owner).to_string();

    let mut entry = RealmDirectoryEntry::new(
        typed_realm_id,
        title,
        soland_services::events::DirectoryProvenance::LocalOnly,
    );
    entry.public = true;
    entry.members.insert(core_id(owner));
    state.test_realms().lock().upsert(entry);
    join_member(state, &realm_id, owner, "owner").await;

    state
        .test_persistence()
        .realm_meta()
        .put(
            &realm_id,
            &RealmMetaRecord {
                owner: owner_actor,
                deleted: false,
                discoverability: "public".to_owned(),
                history_access: "since_join".to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: BTreeSet::from([state.service_id().clone()]),
                plaintext_visible_service_classes: BTreeMap::from([(
                    state.service_id().clone(),
                    BTreeSet::from([arkret_wire::PlaintextDataClassKind::MessageContent]),
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

/// Record one joined membership in the Actor-indexed membership projection,
/// which is the index `realm_has_member` authorizes against.
async fn join_member(state: &AppState, realm_id: &str, did: &str, role: &str) {
    let now = chrono::Utc::now();
    let actor = local_actor(state, did).to_string();
    state.test_projection().lock().members.insert(
        (realm_id.to_owned(), actor.clone()),
        SolandMembershipState {
            member: actor,
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: role.to_owned(),
            membership_event_ref: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
}

fn pcr_of(did: &str) -> String {
    soland_test_support::fixture_principal_control_realm(did)
}

/// Author and sign one profile Event against the owner's PCR, continuing that
/// actor's Realm chain from the frontier the server reports.
async fn signed_profile_event(
    state: &AppState,
    token: &str,
    did: &str,
    kind: &str,
    payload: Value,
    causal_refs: Vec<arkret_identifiers::Hash>,
) -> arkret_wire::Event {
    let realm_id = pcr_of(did);
    let actor_did = Did::new(did.to_owned()).expect("fixture actor DID");
    let actor = core_id(did);
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierState =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&json!({
                "actor_id": local_actor(state, did),
                "realm_id": realm_id,
            }))
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header(
                "Arkret-Operation",
                "retired-event-frontier",
                true,
            )
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
    let now = chrono::Utc::now();
    let device_id = device_id_for(did);
    let verification_method = arkret_wire::DidUrl::new(format!("{did}#{device_id}"))
        .expect("fixture verification method is a DID URL");
    let mut event = arkret_wire::test_support::raw_event_at(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(realm_id.clone()).expect("fixture PCR id"),
        },
        actor,
        state.service_core_id().clone(),
        frontier.next_actor_seq,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-00000000",
            u64::try_from(now.timestamp_millis().max(0)).expect("non-negative epoch millis")
        ))
        .expect("fixture HLC"),
        payload,
        now,
    )
    .expect("SDK Event builder accepts the profile fixture");
    event.prev_refs = frontier.frontier_event_ids;
    event.causal_refs = causal_refs;
    let fixture_basis =
        soland_test_support::cbs_basis::FixtureBasis::shared(&PROFILE_GRANT_ACTIONS);
    let basis_seal =
        soland_test_support::cbs_basis::seed_realm_basis(state, &realm_id, did, fixture_basis)
            .await;
    soland_test_support::cbs_basis::apply_registered_cbs_plane_seal(&mut event, basis_seal.clone());
    // An ordinary Event names the data-plane basis it observed separately from
    // the authority basis its capability check reads.
    event.data_basis = Some(basis_seal);
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
        arkret_signatures::SignEventOptions::new(soland_test_support::fixture_signer_evidence_ref())
            .with_created_at(now),
    )
    .expect("SDK Event signer accepts the profile fixture");
    event.into_event()
}

async fn post_profile_event(
    state: &AppState,
    token: &str,
    event: &arkret_wire::Event,
) -> (StatusCode, Value) {
    let mut response = TestClient::post("http://server/_arkret/self/account/profile")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1,
            true,
        )
        .body(canonical_request_body(&json!({
            "profile_event": arkret_wire::EventInitialSubmission::online(event.clone()),
        })))
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.expect("profile POST status");
    let body = response.take_json().await.expect("profile POST JSON");
    (status, body)
}

async fn create_profile(
    state: &AppState,
    token: &str,
    did: &str,
    display_name: &str,
) -> (ActorProfileId, arkret_wire::Event, Value) {
    let event = signed_profile_event(
        state,
        token,
        did,
        "ak.profile.create",
        json!({
            "object": {
                "schema": "ak.schema.actor_profile.v1",
                "realm_id": pcr_of(did),
                "principal_id": core_id(did),
                "actor_kind": "user",
                "display_name": display_name,
                "avatar_blob_ref": AVATAR_BLOB,
                "profile_fields": {"bio": "ships the reducer"},
                "created_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
            }
        }),
        Vec::new(),
    )
    .await;
    let (status, body) = post_profile_event(state, token, &event).await;
    assert_eq!(status, StatusCode::OK, "profile create failed: {body}");
    let profile_id = ActorProfileId::from_event_id(&event.event_id);
    assert_eq!(
        body["profile"]["id"],
        json!(profile_id),
        "the materialized id must be the retyped create Event id, not a server choice"
    );
    assert_eq!(body["profile"]["realm_id"], json!(pcr_of(did)));
    (profile_id, event, body)
}

fn profile_cell(profile_id: &ActorProfileId) -> arkret_identifiers::CellRef {
    arkret_identifiers::CellRef::new(format!(
        "ak:cell:{}:{profile_id}",
        arkret_wire::CellFamilyId::PROFILE_CREATE_V1
    ))
    .expect("registered profile cell id")
}

async fn resolve_actor_profiles(
    state: &AppState,
    token: &str,
    realm_id: &str,
    actor_ids: Vec<arkret_wire::ActorId>,
) -> (StatusCode, Value) {
    let request = arkret_models_identity::actor_profile_operations::ActorProfileResolveRequest::new(
        RealmId::new(realm_id.to_owned()).expect("fixture Realm id"),
        actor_ids,
    );
    let mut response = TestClient::post("http://server/_arkret/self/actor-profiles/query")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACTOR_PROFILE_READ_RESOLVE_V1,
            true,
        )
        .body(canonical_request_body(&request))
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.expect("resolve status");
    let body = response.take_json().await.expect("resolve JSON");
    (status, body)
}

#[test]
#[ignore = "no soland fixture can submit an ordinary data-plane Event yet: the producer-proof gate requires a retained AuthenticatedSignerResolutionEvidence and neither DeviceHistoryFixture nor project_authorized_principal_device persists one. Owned by tasks/impl-active/2026-09-13-0848-confirmed-device-history-test-fixture-migration."]
fn create_and_update_share_one_cell_and_a_patch_is_a_delta() {
    run_large_stack_async_test(create_and_update_share_one_cell_and_a_patch_is_a_delta_body);
}

async fn create_and_update_share_one_cell_and_a_patch_is_a_delta_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone(), &ALICE_DID).await;
    let (profile_id, create_event, created) =
        create_profile(&state, &alice, &ALICE_DID, "Alice Zhang").await;
    assert_eq!(
        created["profile"]["profile_fields"]["bio"],
        json!("ships the reducer")
    );
    assert_eq!(created["profile"]["avatar_blob_ref"], json!(AVATAR_BLOB));

    let cell = profile_cell(&profile_id);
    let settled = state
        .test_projection()
        .lock()
        .realm_cell(&pcr_of(&ALICE_DID), &cell)
        .and_then(|cell| cell.settled_value().cloned())
        .expect("ak.profile.create materializes its registered cell");
    assert_eq!(settled["display_name"], json!("Alice Zhang"));

    // One patch renames and clears the avatar while saying nothing about `bio`.
    // A whole-object write would drop `bio`; a delta keeps it.
    let update_event = signed_profile_event(
        &state,
        &alice,
        &ALICE_DID,
        "ak.profile.update",
        json!({
            "target_ref": profile_id,
            "patch": {
                "display_name": {"$op": "set", "value": "Alice C."},
                "avatar_blob_ref": {"$op": "unset"}
            }
        }),
        vec![create_event.event_id.clone().event_digest()],
    )
    .await;
    let (status, updated) = post_profile_event(&state, &alice, &update_event).await;
    assert_eq!(status, StatusCode::OK, "profile update failed: {updated}");
    assert_eq!(
        updated["profile"]["id"],
        json!(profile_id),
        "an update keeps the create-derived id instead of minting a second profile"
    );
    assert_eq!(updated["profile"]["display_name"], json!("Alice C."));
    assert_eq!(
        updated["profile"]["profile_fields"]["bio"],
        json!("ships the reducer"),
        "a patch is a delta: an unmentioned field survives"
    );
    assert!(
        updated["profile"].get("avatar_blob_ref").is_none(),
        "$op unset removes the field instead of storing null: {updated}"
    );

    let settled = state
        .test_projection()
        .lock()
        .realm_cell(&pcr_of(&ALICE_DID), &cell)
        .and_then(|cell| cell.settled_value().cloned())
        .expect("ak.profile.update writes the same registered cell");
    assert_eq!(
        settled["display_name"],
        json!("Alice C."),
        "both kinds write one cell, so the create cell carries the updated value"
    );
}

#[test]
#[ignore = "no soland fixture can submit an ordinary data-plane Event yet: the producer-proof gate requires a retained AuthenticatedSignerResolutionEvidence and neither DeviceHistoryFixture nor project_authorized_principal_device persists one. Owned by tasks/impl-active/2026-09-13-0848-confirmed-device-history-test-fixture-migration."]
fn a_stale_expected_state_digest_refuses_the_profile_update() {
    run_large_stack_async_test(a_stale_expected_state_digest_refuses_the_profile_update_body);
}

async fn a_stale_expected_state_digest_refuses_the_profile_update_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone(), &ALICE_DID).await;
    let (profile_id, create_event, created) =
        create_profile(&state, &alice, &ALICE_DID, "Alice Zhang").await;
    let observed_prestate = arkret_canonical::sha256_digest(
        arkret_canonical::canonical_json_bytes(&created["profile"]).expect("canonical profile"),
    );

    let first = signed_profile_event(
        &state,
        &alice,
        &ALICE_DID,
        "ak.profile.update",
        json!({
            "target_ref": profile_id,
            "patch": {"display_name": {"$op": "set", "value": "Alice C."}},
            "expected_state_digest": observed_prestate,
        }),
        vec![create_event.event_id.clone().event_digest()],
    )
    .await;
    let (status, body) = post_profile_event(&state, &alice, &first).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the guard must accept the pre-state the writer actually observed: {body}"
    );

    // The same signed guard is now stale: it names a value that is no longer a
    // source for this cell.
    let second = signed_profile_event(
        &state,
        &alice,
        &ALICE_DID,
        "ak.profile.update",
        json!({
            "target_ref": profile_id,
            "patch": {"display_name": {"$op": "set", "value": "Alice From The Past"}},
            "expected_state_digest": observed_prestate,
        }),
        vec![first.event_id.clone().event_digest()],
    )
    .await;
    let (status, body) = post_profile_event(&state, &alice, &second).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a stale signed expected_state_digest must not apply: {body}"
    );
    let (_, current) = post_profile_event(&state, &alice, &first).await;
    assert_eq!(
        current["profile"]["display_name"],
        json!("Alice C."),
        "the refused update left the accepted value alone: {current}"
    );
}

#[test]
#[ignore = "no soland fixture can submit an ordinary data-plane Event yet: the producer-proof gate requires a retained AuthenticatedSignerResolutionEvidence and neither DeviceHistoryFixture nor project_authorized_principal_device persists one. Owned by tasks/impl-active/2026-09-13-0848-confirmed-device-history-test-fixture-migration."]
fn an_authorized_co_member_resolves_the_exact_signed_profile_event() {
    run_large_stack_async_test(
        an_authorized_co_member_resolves_the_exact_signed_profile_event_body,
    );
}

async fn an_authorized_co_member_resolves_the_exact_signed_profile_event_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone(), &ALICE_DID).await;
    let bob = dev_token(state.clone(), &BOB_DID).await;
    let _carol = dev_token(state.clone(), &CAROL_DID).await;
    let dave = dev_token(state.clone(), &DAVE_DID).await;

    let shared = seed_shared_realm(&state, &ALICE_DID, "profile resolve fixture").await;
    join_member(&state, &shared, &BOB_DID, "member").await;
    join_member(&state, &shared, &CAROL_DID, "member").await;

    let (profile_id, create_event, _) =
        create_profile(&state, &alice, &ALICE_DID, "Alice Zhang").await;
    let update_event = signed_profile_event(
        &state,
        &alice,
        &ALICE_DID,
        "ak.profile.update",
        json!({
            "target_ref": profile_id,
            "patch": {"display_name": {"$op": "set", "value": "Alice C."}}
        }),
        vec![create_event.event_id.clone().event_digest()],
    )
    .await;
    let (status, body) = post_profile_event(&state, &alice, &update_event).await;
    assert_eq!(status, StatusCode::OK, "profile update failed: {body}");

    // Dave has a profile of his own but shares no Realm with Bob's selector.
    let (..) = create_profile(&state, &dave, &DAVE_DID, "Dave Unrelated").await;

    let alice_actor = local_actor(&state, &ALICE_DID);
    let carol_actor = local_actor(&state, &CAROL_DID);
    let dave_actor = local_actor(&state, &DAVE_DID);
    let unknown_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        core_id("did:web:unknown.example"),
        state.service_core_id().clone(),
    ));
    let (status, body) = resolve_actor_profiles(
        &state,
        &bob,
        &shared,
        vec![
            alice_actor.clone(),
            carol_actor.clone(),
            dave_actor.clone(),
            unknown_actor.clone(),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resolve failed: {body}");

    let outcome: arkret_models_identity::actor_profile_operations::ActorProfileResolveOutcome =
        serde_json::from_value(body.clone()).unwrap_or_else(|error| {
            panic!("typed resolve outcome failed: {body}: {error}");
        });
    arkret_models_collaboration::actor_profile_resolution::validate_actor_profile_resolve_outcome(
        &outcome,
        &[
            alice_actor.clone(),
            carol_actor.clone(),
            dave_actor.clone(),
            unknown_actor.clone(),
        ],
    )
    .expect("every returned row binds its Event, projection and actor");

    assert_eq!(
        outcome.profiles.len(),
        1,
        "only Alice has a resolvable profile: {body}"
    );
    let row = &outcome.profiles[0];
    assert_eq!(row.actor_id, alice_actor);
    assert_eq!(row.actor_profile.display_name, "Alice C.");
    assert_eq!(
        serde_json::to_value(&row.profile_event).unwrap(),
        serde_json::to_value(&update_event).unwrap(),
        "the row must carry the exact signed Event, byte-for-byte"
    );
    assert!(
        body["profiles"][0].get("accepted_seal").is_none(),
        "ordinary profile state has no covering Seal to return: {body}"
    );

    // Carol is a co-member with no profile, Dave has a profile but no shared
    // Realm, and the unknown actor never existed. All three must be one value.
    let failures: BTreeMap<String, String> = outcome
        .failures
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|failure| {
            (
                failure.actor_id.to_string(),
                serde_json::to_value(failure.reason)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        })
        .collect();
    for actor in [&carol_actor, &dave_actor, &unknown_actor] {
        assert_eq!(
            failures.get(&actor.to_string()).map(String::as_str),
            Some("profile_unavailable"),
            "missing profile, non-member and unknown actor must be indistinguishable: {body}"
        );
    }
}

#[test]
fn a_caller_without_membership_gets_one_not_found_for_the_whole_request() {
    run_large_stack_async_test(
        a_caller_without_membership_gets_one_not_found_for_the_whole_request_body,
    );
}

async fn a_caller_without_membership_gets_one_not_found_for_the_whole_request_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone(), &ALICE_DID).await;
    let dave = dev_token(state.clone(), &DAVE_DID).await;
    let shared = seed_shared_realm(&state, &ALICE_DID, "profile resolve fixture").await;
    let alice_actor = local_actor(&state, &ALICE_DID);

    // Dave is not a member of the selector Realm, so the request has no
    // authorization basis at all and must not degrade into a per-actor answer.
    // Whether Alice has a profile is deliberately irrelevant here: the refusal
    // must not depend on the target, or its absence would leak one.
    let (status, body) =
        resolve_actor_profiles(&state, &dave, &shared, vec![alice_actor.clone()]).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-member caller: {body}");

    // A Principal Control Realm is never a relationship selector, not even for
    // its own owner, and it fails the same way.
    let (status, body) =
        resolve_actor_profiles(&state, &alice, &pcr_of(&ALICE_DID), vec![alice_actor]).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "PCR selector: {body}");
}

#[test]
fn unknown_missing_and_non_member_actors_are_one_indistinguishable_failure() {
    run_large_stack_async_test(
        unknown_missing_and_non_member_actors_are_one_indistinguishable_failure_body,
    );
}

async fn unknown_missing_and_non_member_actors_are_one_indistinguishable_failure_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone(), &ALICE_DID).await;
    let _bob = dev_token(state.clone(), &BOB_DID).await;
    let _dave = dev_token(state.clone(), &DAVE_DID).await;
    let shared = seed_shared_realm(&state, &ALICE_DID, "profile resolve fixture").await;
    join_member(&state, &shared, &BOB_DID, "member").await;

    // Bob is a co-member with no accepted profile, Dave is an existing account
    // that shares no Realm with the selector, and the third actor never
    // existed. The response must not let the caller tell them apart.
    let bob_actor = local_actor(&state, &BOB_DID);
    let dave_actor = local_actor(&state, &DAVE_DID);
    let unknown_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        core_id("did:web:unknown.example"),
        state.service_core_id().clone(),
    ));
    let requested = vec![bob_actor, dave_actor, unknown_actor];
    let (status, body) = resolve_actor_profiles(&state, &alice, &shared, requested.clone()).await;
    assert_eq!(status, StatusCode::OK, "resolve failed: {body}");

    let outcome: arkret_models_identity::actor_profile_operations::ActorProfileResolveOutcome =
        serde_json::from_value(body.clone()).unwrap_or_else(|error| {
            panic!("typed resolve outcome failed: {body}: {error}");
        });
    arkret_models_collaboration::actor_profile_resolution::validate_actor_profile_resolve_outcome(
        &outcome, &requested,
    )
    .expect("every requested actor is accounted for exactly once");
    assert!(
        outcome.profiles.is_empty(),
        "no actor has a profile: {body}"
    );
    let reasons: BTreeSet<String> = outcome
        .failures
        .unwrap_or_default()
        .into_iter()
        .map(|failure| {
            serde_json::to_value(failure.reason)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        reasons,
        BTreeSet::from(["profile_unavailable".to_owned()]),
        "the per-actor vocabulary is single-valued: {body}"
    );
}
