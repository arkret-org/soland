//! Integration tests — private invite delivery dispatch.
//!
//! `ak.self.invites.command.dispatch` (`POST /_arkret/self/invites/dispatch`)
//! per `zh/sync/invite-addressing.md` §7: three closed `invite_event`
//! preconditions, then a local target replays the peer receive chain from
//! step 4 while a remote target enters the durable exact-body outbox.

use arkret_models_collaboration::governance::invite_addressing::{
    IntroductionEvidence, InviteAddress, InviteDeliveryRequestBody, InviteReceivePolicy,
};
use arkret_models_identity::ServiceResolutionCarrier;

use super::common::*;

fn canonical_body(value: &impl serde::Serialize) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical invite dispatch body")
}

const ALICE: &str = "did:web:alice.example";
const ALICE_DEVICE: &str = "01904100-0000-7000-8000-a11ce0000001";
const BOB: &str = "did:web:bob.example";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-b0b000000001";
/// A syntactically valid Event id this service never accepted.
const UNKNOWN_EVENT_ID: &str = "ak:event:AbMdINsWEW01xiLsvC3anbe65njppPPCVoNeYM6ES_E2";

struct DispatchFixture {
    state: AppState,
    alice_token: String,
    bob_token: String,
    invite_event: arkret_wire::Event,
    invite_address: InviteAddress,
    evidence: IntroductionEvidence,
}

impl DispatchFixture {
    fn delivery(&self, idempotency_key: &str) -> InviteDeliveryRequestBody {
        InviteDeliveryRequestBody::new(
            self.invite_event.clone(),
            self.invite_address.clone(),
            self.evidence.clone(),
            idempotency_key,
        )
    }

    async fn dispatch(
        &self,
        token: &str,
        delivery: &InviteDeliveryRequestBody,
    ) -> (StatusCode, Value) {
        let mut response = TestClient::post("http://server/_arkret/self/invites/dispatch")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(delivery))
            .send(&app_from_state(self.state.clone()))
            .await;
        let status = response.status_code.expect("dispatch status");
        let body: Value = response.take_json().await.expect("dispatch body");
        (status, body)
    }

    async fn quarantine_entries(&self) -> Vec<Value> {
        self.state
            .test_persistence()
            .account_data()
            .get(
                fixture_actor_core_id(BOB).as_str(),
                arkret_wire::AccountDataKey::ACCOUNT_INVITE_QUARANTINE,
            )
            .await
            .expect("invite quarantine account data read")
            .and_then(|record| {
                record
                    .payload
                    .get("entries")
                    .and_then(Value::as_array)
                    .cloned()
            })
            .unwrap_or_default()
    }
}

fn local_service_resolution(state: &AppState) -> ServiceResolutionCarrier {
    ServiceResolutionCarrier::CurrentRecordUrl {
        current_record_url: format!(
            "https://soland.local{}",
            arkret_models_identity::canonical_service_current_record_path(
                &DidCoreId::new(state.service_id().to_owned())
                    .expect("configured service id is a core DID")
            )
        ),
        pinned_record_digest: None,
    }
}

fn explicit_address_evidence(_realm_id: &str) -> IntroductionEvidence {
    IntroductionEvidence::ExplicitAddress
}

fn shared_realm_evidence(realm_id: &str) -> IntroductionEvidence {
    IntroductionEvidence::SharedRealm {
        realm_id: RealmId::new(realm_id.to_owned()).expect("shared realm evidence realm id"),
        inviter_member_ref: arkret_identifiers::EventId::new(UNKNOWN_EVENT_ID.to_owned())
            .expect("inviter member ref"),
        invitee_member_ref: arkret_identifiers::EventId::new(UNKNOWN_EVENT_ID.to_owned())
            .expect("invitee member ref"),
    }
}

/// Seed an accepted local `ak.invite.create` for Bob and read it back through
/// `ak.self.events.read.resolve`, which is the only way §7 lets a client fill
/// `invite_event`.
///
/// The evidence is chosen from the seeded Realm id because
/// `introduction_evidence_digest` in the durable Event has to commit to the
/// exact evidence the delivery later carries (§6).
async fn seed_dispatch_fixture(
    evidence_for_realm: impl FnOnce(&str) -> IntroductionEvidence,
) -> DispatchFixture {
    let state = soland_test_support::app_state(test_config());
    let alice_token = dev_token(state.clone()).await;
    let bob_token = register_account(state.clone(), BOB, "bob", BOB_DEVICE).await;
    let seeded = seed_test_realm(
        &state,
        ALICE,
        "Private invite dispatch",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let realm_id = seeded["realm_id"]
        .as_str()
        .expect("seeded realm id")
        .to_owned();
    let evidence = evidence_for_realm(&realm_id);
    let service_resolution = local_service_resolution(&state);
    let evidence_digest =
        arkret_canonical::canonical_sha256(&evidence).expect("introduction evidence digest");
    let payload = serde_json::json!({
        "invitee": fixture_actor_core_id(BOB),
        "invite_delivery_target": {
            "recipient_service_id": state.service_id(),
            "service_resolution": serde_json::to_value(&service_resolution)
                .expect("service resolution carrier serializes"),
            "recipient_service_kind": "principal_server"
        },
        "introduction_evidence_digest": evidence_digest,
        "expires_at": "2099-01-01T00:00:00.000Z"
    });
    let mut event = signed_canonical_event(
        UNKNOWN_EVENT_ID,
        "ak.invite.create",
        ALICE,
        ALICE_DEVICE,
        &realm_id,
        0,
        Vec::new(),
        payload,
    );
    move_event_to_actor_realm_frontier(&state, &alice_token, ALICE, &realm_id, &mut event).await;
    event["seal_basis"] = seeded["seal_basis"].clone();
    resign_canonical_event(&mut event);
    let event_id = authored_event_id(&event).to_owned();

    let submitted: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .expect("invite create submit body");
    assert_eq!(
        submitted["status"], "accepted",
        "invite create submit: {submitted}"
    );

    // §7 — the client MUST read the accepted Event back from the server view
    // instead of re-authoring it, so the fixture does exactly that.
    let resolved: Value = TestClient::query("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(
            &arkret_models_collaboration::http_bodies::EventsResolveRequestBody {
                event_ids: vec![
                    arkret_identifiers::EventId::new(event_id.clone()).expect("accepted Event id"),
                ],
                event_digests: Vec::new(),
                include_payload: Some(true),
                history_traversal_access: None,
                max_response_bytes: None,
            },
        )
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .expect("events resolve body");
    let invite_event: arkret_wire::Event = serde_json::from_value(resolved["events"][0].clone())
        .unwrap_or_else(|error| {
            panic!("accepted invite Event is not resolvable: {error}; {resolved}")
        });

    let invite_address = InviteAddress::principal_server(
        fixture_actor_core_id(BOB),
        DidCoreId::new(state.service_id().to_owned()).expect("service id core DID"),
        service_resolution,
    );
    DispatchFixture {
        state,
        alice_token,
        bob_token,
        invite_event,
        invite_address,
        evidence,
    }
}

/// Bind the fail-closed §5 default policy to Bob so the receive chain has an
/// effective policy to evaluate.
async fn bind_default_receive_policy(fixture: &DispatchFixture) {
    let policy = InviteReceivePolicy::spec_default(fixture_actor_core_id(BOB));
    let mut response = TestClient::put("http://server/_arkret/self/invite-receive-policy")
        .add_header(
            "authorization",
            format!("Bearer {}", fixture.bob_token),
            true,
        )
        .add_header("content-type", "application/json", true)
        .body(canonical_body(&policy))
        .send(&app_from_state(fixture.state.clone()))
        .await;
    let status = response.status_code;
    let rendered = response.take_string().await;
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "invite receive policy replace: {rendered:?}"
    );
}

#[test]
fn self_invite_dispatch_to_a_local_target_runs_the_receive_chain_and_notifies() {
    run_on_deep_stack(
        "self_invite_dispatch_to_a_local_target_runs_the_receive_chain_and_notifies",
        self_invite_dispatch_to_a_local_target_runs_the_receive_chain_and_notifies_body,
    );
}

async fn self_invite_dispatch_to_a_local_target_runs_the_receive_chain_and_notifies_body() {
    // `shared_realm` is high trust (§2) and is on the §5 fail-closed default
    // allowlist, so the effective receive action is notify and §5.1 lets the
    // high-trust disclosure echo the real outcome.
    let fixture = seed_dispatch_fixture(shared_realm_evidence).await;
    bind_default_receive_policy(&fixture).await;

    let delivery = fixture.delivery("ak:idempotency:local-notify");
    let (status, body) = fixture.dispatch(&fixture.alice_token, &delivery).await;
    assert_eq!(status, StatusCode::OK, "dispatch response: {body}");
    assert_eq!(body["status"], "accepted", "dispatch response: {body}");
    assert_eq!(
        body["disclosed_outcome"], "delivered",
        "high-trust disclosure MUST echo the real outcome: {body}"
    );
    assert!(
        fixture.quarantine_entries().await.is_empty(),
        "a notified invite MUST NOT enter the holder quarantine inbox"
    );
}

#[test]
fn self_invite_dispatch_quarantine_is_deferred_and_idempotent_per_idempotency_key() {
    run_on_deep_stack(
        "self_invite_dispatch_quarantine_is_deferred_and_idempotent_per_idempotency_key",
        self_invite_dispatch_quarantine_is_deferred_and_idempotent_per_idempotency_key_body,
    );
}

async fn self_invite_dispatch_quarantine_is_deferred_and_idempotent_per_idempotency_key_body() {
    // `explicit_address` is low trust and is not on the §5 default allowlist,
    // so the effective behavior is quarantine. §5.1 pins that to
    // `status=deferred` with no `disclosed_outcome` in every disclosure tier.
    let fixture = seed_dispatch_fixture(explicit_address_evidence).await;
    bind_default_receive_policy(&fixture).await;

    let delivery = fixture.delivery("ak:idempotency:local-quarantine");
    let (status, body) = fixture.dispatch(&fixture.alice_token, &delivery).await;
    assert_eq!(status, StatusCode::OK, "dispatch response: {body}");
    assert_eq!(body["status"], "deferred", "dispatch response: {body}");
    assert!(
        body.get("disclosed_outcome").is_none(),
        "quarantine MUST NOT be disclosed to the inviter: {body}"
    );
    assert_eq!(fixture.quarantine_entries().await.len(), 1);

    let (replay_status, replay_body) = fixture.dispatch(&fixture.alice_token, &delivery).await;
    assert_eq!(replay_status, StatusCode::OK, "replay: {replay_body}");
    assert_eq!(replay_body["status"], "deferred", "replay: {replay_body}");
    assert!(replay_body.get("disclosed_outcome").is_none());
    assert_eq!(
        fixture.quarantine_entries().await.len(),
        1,
        "a replay under the same idempotency_key MUST NOT add a second quarantine entry"
    );
}

#[test]
fn self_invite_dispatch_rejects_an_invite_event_this_service_never_accepted() {
    run_on_deep_stack(
        "self_invite_dispatch_rejects_an_invite_event_this_service_never_accepted",
        self_invite_dispatch_rejects_an_invite_event_this_service_never_accepted_body,
    );
}

async fn self_invite_dispatch_rejects_an_invite_event_this_service_never_accepted_body() {
    let fixture = seed_dispatch_fixture(explicit_address_evidence).await;
    bind_default_receive_policy(&fixture).await;

    let mut delivery = fixture.delivery("ak:idempotency:unaccepted");
    delivery.invite_event.event_id =
        arkret_identifiers::EventId::new(UNKNOWN_EVENT_ID.to_owned()).expect("unknown Event id");
    let (status, body) = fixture.dispatch(&fixture.alice_token, &delivery).await;
    assert_eq!(status, StatusCode::CONFLICT, "dispatch response: {body}");
    assert_eq!(body["error"]["code"], "failed_precondition", "{body}");
    assert_eq!(
        body["error"]["details"]["reason_code"], "invite_event_unaccepted",
        "{body}"
    );
    assert!(
        fixture.quarantine_entries().await.is_empty(),
        "a closed precondition rejection MUST NOT produce a holder-private write"
    );
}

#[test]
fn self_invite_dispatch_rejects_an_invite_event_signed_by_another_actor() {
    run_on_deep_stack(
        "self_invite_dispatch_rejects_an_invite_event_signed_by_another_actor",
        self_invite_dispatch_rejects_an_invite_event_signed_by_another_actor_body,
    );
}

async fn self_invite_dispatch_rejects_an_invite_event_signed_by_another_actor_body() {
    let fixture = seed_dispatch_fixture(explicit_address_evidence).await;
    bind_default_receive_policy(&fixture).await;

    // The Event is accepted here and unmodified; only the authenticated
    // session actor differs from its signing actor.
    let delivery = fixture.delivery("ak:idempotency:actor-mismatch");
    let (status, body) = fixture.dispatch(&fixture.bob_token, &delivery).await;
    assert_eq!(status, StatusCode::CONFLICT, "dispatch response: {body}");
    assert_eq!(body["error"]["code"], "failed_precondition", "{body}");
    assert_eq!(
        body["error"]["details"]["reason_code"], "invite_event_actor_mismatch",
        "{body}"
    );
    assert!(
        fixture.quarantine_entries().await.is_empty(),
        "a closed precondition rejection MUST NOT produce a holder-private write"
    );
}

#[test]
fn self_invite_dispatch_rejects_an_invite_event_that_is_not_the_stored_canonical_bytes() {
    run_on_deep_stack(
        "self_invite_dispatch_rejects_an_invite_event_that_is_not_the_stored_canonical_bytes",
        self_invite_dispatch_rejects_an_invite_event_that_is_not_the_stored_canonical_bytes_body,
    );
}

async fn self_invite_dispatch_rejects_an_invite_event_that_is_not_the_stored_canonical_bytes_body()
{
    let fixture = seed_dispatch_fixture(explicit_address_evidence).await;
    bind_default_receive_policy(&fixture).await;

    // Keep the accepted `event_id` and the signing actor, and change only the
    // signed content: the canonical Event bytes no longer equal the stored
    // ones, which is exactly what a locally re-authored Event looks like.
    let mut delivery = fixture.delivery("ak:idempotency:bytes-mismatch");
    delivery.invite_event.created_at += chrono::Duration::milliseconds(1);
    let (status, body) = fixture.dispatch(&fixture.alice_token, &delivery).await;
    assert_eq!(status, StatusCode::CONFLICT, "dispatch response: {body}");
    assert_eq!(body["error"]["code"], "failed_precondition", "{body}");
    assert_eq!(
        body["error"]["details"]["reason_code"], "invite_event_bytes_mismatch",
        "{body}"
    );
    assert!(
        fixture.quarantine_entries().await.is_empty(),
        "a closed precondition rejection MUST NOT produce a holder-private write"
    );
}
