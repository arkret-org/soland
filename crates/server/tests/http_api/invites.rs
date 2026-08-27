//! Integration tests — private invite delivery dispatch.
//!
//! `ak.self.invites.command.dispatch.v1` (`POST /_arkret/self/invites/dispatch`)
//! per `zh/sync/invite-addressing.md` §7: closed accepted-event lookup and actor
//! preconditions, then a local target replays the peer receive chain from
//! step 4 while a remote target enters the durable exact-body outbox.

use std::sync::Arc;

use arkret_models_collaboration::governance::invite_addressing::{
    IntroductionEvidence, InviteAddress, InviteReceivePolicy, SelfInviteDispatchRequestBody,
};
use arkret_models_identity::{
    ResolutionCommitment, ServiceResolutionCarrier, ServiceResolutionRecord,
    ServiceResolutionRecordCore,
};
use async_trait::async_trait;
use soland_services::ServiceResult;
use soland_services::service_route::{
    RouteSource, ServiceRouteFetcher, VerifiedRouteCandidate, VerifiedServiceDescribeMetadata,
};

use super::common::*;

fn canonical_body(value: &impl serde::Serialize) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical invite dispatch body")
}

const ALICE: &str = "did:web:alice.example";
const ALICE_DEVICE: &str = "01904100-0000-7000-8000-a11ce0000001";
const BOB: &str = "did:web:bob.example";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-b0b000000001";
const REMOTE_SERVICE_FULL_ID: &str = "did:web:remote.example";
const REMOTE_SERVICE_ID: &str = "ak:did_core:web:remote.example";
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

struct RemoteCarrierFetcher {
    service_id: DidCoreId,
    candidate: VerifiedRouteCandidate,
}

#[async_trait]
impl ServiceRouteFetcher for RemoteCarrierFetcher {
    async fn fetch_carrier(
        &self,
        _carrier: &ServiceResolutionCarrier,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok((service_id == &self.service_id
            && service_kind == arkret_wire::ServiceKind::PrincipalServer.as_str())
        .then(|| self.candidate.clone()))
    }

    async fn fetch_current(
        &self,
        _service_id: &DidCoreId,
        _service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok(None)
    }

    async fn fetch_notice_candidate(
        &self,
        _service_id: &DidCoreId,
        _service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok(None)
    }
}

fn remote_route_candidate() -> (DidCoreId, ServiceResolutionCarrier, VerifiedRouteCandidate) {
    let full_id =
        DidFullId::new(REMOTE_SERVICE_FULL_ID.to_owned()).expect("remote service full DID");
    let service_id = arkret_wire::project_full_id_to_core_id(&full_id)
        .expect("remote service core DID projection");
    assert_eq!(service_id.as_str(), REMOTE_SERVICE_ID);
    let service_kind = arkret_wire::ServiceKind::PrincipalServer;
    let base_url = "https://remote.example/";
    let issued_at = chrono::Utc::now();
    let method_history_head = format!("sha256:{}", "1".repeat(64));
    let version_id = "fixture-route-v1".to_owned();
    let resolution = ResolutionCommitment {
        full_id: full_id.clone(),
        method_history_head: method_history_head.clone(),
        version_id: version_id.clone(),
    };
    let describe_digest = arkret_models_identity::route_binding_describe_digest(
        &service_id,
        service_kind.as_str(),
        &resolution,
        base_url,
    )
    .expect("remote route binding digest");
    let current_record_url = format!(
        "{}{}",
        base_url.trim_end_matches('/'),
        arkret_models_identity::canonical_service_current_record_path(&service_id)
    );
    let candidate = VerifiedRouteCandidate {
        source: RouteSource::CurrentRecord,
        record: ServiceResolutionRecord {
            record: ServiceResolutionRecordCore {
                service_id: service_id.clone(),
                service_kind: service_kind.as_str().to_owned(),
                full_id: full_id.clone(),
                method_history_head,
                version_id,
                resolution_event_ref: "fixture-verified-route".to_owned(),
                record_sequence: 0,
                previous_record_digest: None,
                current_record_url: current_record_url.clone(),
                base_url: base_url.to_owned(),
                describe_digest: describe_digest.clone(),
                issued_at,
                refresh_after: issued_at + chrono::Duration::hours(1),
                expires_at: issued_at + chrono::Duration::hours(2),
            },
            proof: arkret_wire::ProtocolSignature {
                verification_method: arkret_wire::DidUrl::new(format!("{full_id}#assertion-1"))
                    .expect("remote verification method"),
                created_at: issued_at,
                jws: arkret_wire::Base64UrlString::new("AA").expect("fixture proof bytes"),
            },
        },
        description: VerifiedServiceDescribeMetadata {
            service_id: service_id.clone(),
            service_kind: service_kind.as_str().to_owned(),
            service_resolution: resolution,
            http_json_base_url: base_url.to_owned(),
            route_binding_digest: describe_digest,
            trust_domain: arkret_identifiers::TrustDomainId::new(
                "ak:trust_domain:remote.example".to_owned(),
            )
            .expect("remote trust domain"),
            protocol_version: arkret_wire::PROTOCOL_VERSION.to_owned(),
        },
    };
    (
        service_id,
        ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url,
            pinned_record_digest: None,
        },
        candidate,
    )
}

impl DispatchFixture {
    fn delivery(&self, idempotency_key: &str) -> SelfInviteDispatchRequestBody {
        SelfInviteDispatchRequestBody {
            schema: arkret_wire::SchemaId::INVITE_DELIVERY_REQUEST_V1.to_owned(),
            invite_event_id: self.invite_event.event_id.clone(),
            invite_address: self.invite_address.clone(),
            introduction_evidence: self.evidence.clone(),
            idempotency_key: idempotency_key.to_owned(),
        }
    }

    async fn dispatch(
        &self,
        token: &str,
        delivery: &SelfInviteDispatchRequestBody,
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
/// `ak.self.events.read.resolve.v1`, which is the only way §7 lets a client fill
/// `invite_event`.
///
/// The evidence is chosen from the seeded Realm id because
/// `introduction_evidence_digest` in the durable Event has to commit to the
/// exact evidence the delivery later carries (§6).
async fn seed_dispatch_fixture(
    evidence_for_realm: impl FnOnce(&str) -> IntroductionEvidence,
) -> DispatchFixture {
    seed_dispatch_fixture_for_target(evidence_for_realm, None).await
}

async fn seed_dispatch_fixture_for_target(
    evidence_for_realm: impl FnOnce(&str) -> IntroductionEvidence,
    target: Option<(DidCoreId, ServiceResolutionCarrier)>,
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
    let (recipient_service_id, service_resolution) = target.unwrap_or_else(|| {
        (
            DidCoreId::new(state.service_id().to_owned()).expect("service id core DID"),
            local_service_resolution(&state),
        )
    });
    let evidence_digest =
        arkret_canonical::canonical_sha256(&evidence).expect("introduction evidence digest");
    let payload = serde_json::json!({
        "invitee": fixture_actor_core_id(BOB),
        "invite_delivery_target": {
            "recipient_service_id": recipient_service_id.clone(),
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
        recipient_service_id,
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
fn self_invite_dispatch_to_a_remote_target_enqueues_the_exact_accepted_envelope_once() {
    run_on_deep_stack(
        "self_invite_dispatch_to_a_remote_target_enqueues_the_exact_accepted_envelope_once",
        self_invite_dispatch_to_a_remote_target_enqueues_the_exact_accepted_envelope_once_body,
    );
}

async fn self_invite_dispatch_to_a_remote_target_enqueues_the_exact_accepted_envelope_once_body() {
    let (remote_service_id, service_resolution, candidate) = remote_route_candidate();
    let fixture = seed_dispatch_fixture_for_target(
        explicit_address_evidence,
        Some((remote_service_id.clone(), service_resolution)),
    )
    .await;
    fixture
        .state
        .test_install_service_route_fetcher(Arc::new(RemoteCarrierFetcher {
            service_id: remote_service_id,
            candidate,
        }));

    let accepted = fixture
        .state
        .test_persistence()
        .events()
        .get(fixture.invite_event.event_id.as_str())
        .await
        .expect("accepted invite Event lookup")
        .expect("accepted invite Event exists");
    assert_eq!(
        accepted.envelope["event_id"],
        fixture.invite_event.event_id.as_str(),
        "the durable accepted envelope must carry its content-bound Event id"
    );
    let digest_preimage: Value = serde_json::from_slice(&accepted.canonical_bytes)
        .expect("accepted invite digest preimage is JSON");
    assert!(
        digest_preimage.get("event_id").is_none(),
        "the digest preimage is deliberately not a wire Event carrier: {digest_preimage}"
    );

    let delivery = fixture.delivery("ak:idempotency:remote-exact-envelope");
    let (status, outcome) = fixture.dispatch(&fixture.alice_token, &delivery).await;
    assert_eq!(status, StatusCode::OK, "remote dispatch: {outcome}");
    assert_eq!(outcome["status"], "accepted", "remote dispatch: {outcome}");

    let rows = fixture
        .state
        .test_persistence()
        .federation_outbox()
        .snapshot_all()
        .await
        .expect("remote invite outbox snapshot");
    assert_eq!(
        rows.len(),
        1,
        "one dispatch produces one durable row: {rows:?}"
    );
    let first = &rows[0];
    let payload: Value =
        serde_json::from_str(&first.payload_json).expect("durable remote invite payload is JSON");
    assert_eq!(
        payload["invite_event"], accepted.envelope,
        "the outbox must carry the complete accepted envelope, including event_id"
    );
    assert_eq!(payload["invite_event"]["event_id"], accepted.event_id);
    assert_eq!(payload["idempotency_key"], delivery.idempotency_key);
    let first_id = first.id.clone();
    let first_idempotency_key = first.idempotency_key.clone();
    let first_payload_bytes = first.payload_json.as_bytes().to_vec();

    let (replay_status, replay_outcome) = fixture.dispatch(&fixture.alice_token, &delivery).await;
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "remote replay: {replay_outcome}"
    );
    assert_eq!(
        replay_outcome["status"], "duplicate",
        "remote replay: {replay_outcome}"
    );
    let replay_rows = fixture
        .state
        .test_persistence()
        .federation_outbox()
        .snapshot_all()
        .await
        .expect("remote replay outbox snapshot");
    assert_eq!(
        replay_rows.len(),
        1,
        "an exact retry must reuse the existing durable outbox row"
    );
    assert_eq!(replay_rows[0].id, first_id);
    assert_eq!(replay_rows[0].idempotency_key, first_idempotency_key);
    assert_eq!(
        replay_rows[0].payload_json.as_bytes(),
        first_payload_bytes,
        "an exact retry must retain byte-identical canonical request bytes"
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
    delivery.invite_event_id =
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
