use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use soland_services::events::CanonicalEventRecord;
use soland_services::identity::{
    DirectConversationCoordinatesRecord, DirectConversationEndorsement,
};
use soland_storage_postgres::Db;

use super::*;

const ALICE_FULL_ID: &str = "did:webvh:z6mkalice:alice.example";
const ALICE_CORE_ID: &str = "ak:did_core:webvh:z6mkalice";
const AGENT_CORE_ID: &str = "ak:did_core:webvh:z6mkfixtureagent";
const AGENT_CONTROLLER_MEMBERSHIP_EVENT_ID: &str =
    "ak:event:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim";

fn test_config() -> crate::config::AppConfig {
    crate::config::AppConfig {
        object_storage: crate::config::ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-direct-conversation-policy-test-blobs"),
        ),
        development_mode: true,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        notary_signing_key_seed: Some([9u8; 32]),
        seed_demo_data: true,
        ..crate::config::AppConfig::test_default()
    }
}

fn state_with_direct_binding() -> (AppState, arkret_identifiers::RealmId) {
    let state = AppState::new(test_config(), Db { pool: None });
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AabIzZyp4D-JzV77DNQ7bIKd7oGAuDD9keT1CyIv6SC6".to_owned(),
    )
    .unwrap();
    let now = chrono::Utc::now();
    let alice_full = arkret_identifiers::DidFullId::new(ALICE_FULL_ID.to_owned()).unwrap();
    let alice = crate::test_actor_id(&alice_full);
    let bob = crate::test_actor_id_str("did:webvh:z6mkbob:bob.example");
    let mut realm_create = op(
        realm_id.clone(),
        "000000000691",
        arkret_wire::EventKind::RealmCreate,
        serde_json::to_value(arkret_models_collaboration::objects::direct_conversation::direct_conversation_realm_create_payload(
            arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            state.config().trust_domain.clone(),
            arkret_models_collaboration::objects::realm::NotaryProfile::SingleDid,
            arkret_wire::notary::NotaryValue::single_did(alice.clone()),
            arkret_policy::current_capability_action_registry_digest().unwrap(),
            now,
        ).unwrap())
        .unwrap(),
    );
    let realm_create_event_id =
        arkret_identifiers::EventId::new(realm_id.as_str().replacen("ak:realm:", "ak:event:", 1))
            .unwrap();
    realm_create.context.sender = alice.clone();
    realm_create.context.event_id = realm_create_event_id.clone();
    realm_create.context.accepted_event_id = realm_create_event_id;
    let mut peer_join = op(
        realm_id.clone(),
        "000000000692",
        arkret_wire::EventKind::MemberState,
        arkret_models_collaboration::objects::direct_conversation::direct_conversation_member_join_payload(
            realm_id.clone(),
            bob,
            arkret_models_identity::DeliveryStatus::Unroutable,
        )
        .to_value()
        .unwrap(),
    );
    peer_join.context.sender = alice.clone();
    let peer_join_event_id =
        arkret_identifiers::EventId::new("ak:event:AbuDfbb-uv82LvhWbTydj5wUDvzph0PSFjJTtTJxq7P5")
            .unwrap();
    peer_join.context.event_id = peer_join_event_id.clone();
    peer_join.context.accepted_event_id = peer_join_event_id;
    let mut strand_create = op(
        realm_id.clone(),
        "000000000693",
        arkret_wire::EventKind::StrandCreate,
        serde_json::to_value(arkret_models_collaboration::objects::direct_conversation::direct_conversation_main_strand_create_payload(
            realm_id.clone(),
            alice.clone(),
            now,
        ))
        .unwrap(),
    );
    // `ak.strand.create` derives the Strand id from the Event
    // (`retype(event_id)`); an Operation without `event_id` is rejected with
    // `strand_create_missing_event_id` and the Strand never materializes.
    let strand_create_event_id =
        arkret_identifiers::EventId::new("ak:event:AZXoIs9BRSgujgrZ-dLgogRh6YCdLWfJAZWdPXg8qD9D")
            .unwrap();
    strand_create.context.event_id = strand_create_event_id.clone();
    strand_create.context.accepted_event_id = strand_create_event_id;
    // `contact-and-direct-conversation.md` §6.1 closes the founding unit at
    // exactly four Events: `ak.realm.create` -> peer `ak.member.state{join}`
    // -> main `ak.strand.create` -> founder `ak.member.state{join}`. The
    // genesis payload does not imply creator membership, so the founder slot
    // is what puts Alice in the Realm member set.
    let mut founder_join = op(
        realm_id.clone(),
        "000000000694",
        arkret_wire::EventKind::MemberState,
        arkret_models_collaboration::objects::direct_conversation::direct_conversation_member_join_payload(
            realm_id.clone(),
            alice.clone(),
            arkret_models_identity::DeliveryStatus::Unroutable,
        )
        .to_value()
        .unwrap(),
    );
    founder_join.context.sender = alice;
    let founder_join_event_id =
        arkret_identifiers::EventId::new("ak:event:AU6CWyScSLnnHmi5-Yxv-n_v4-cC1vgdBdubYasL9BgQ")
            .unwrap();
    founder_join.context.event_id = founder_join_event_id.clone();
    founder_join.context.accepted_event_id = founder_join_event_id;
    {
        let mut projection = state.test_projection().lock();
        apply_with_registered_cell_writes(&mut projection, &realm_create, 0, state.hlc());
        apply_with_registered_cell_writes(&mut projection, &peer_join, 1, state.hlc());
        apply_with_registered_cell_writes(&mut projection, &strand_create, 2, state.hlc());
        apply_bootstrap_membership_with_registered_cell_writes(&mut projection, &founder_join, 3);
    }
    state.contacts().install_direct_binding(
        "sha256:00000000000000000000000000000000000000000000000000000000000006a1".to_owned(),
        "sha256:0000000000000000000000000000000000000000000000000000000000000601",
        DirectConversationCoordinatesRecord {
            participants_unordered: vec![
                ALICE_CORE_ID.to_owned(),
                "ak:did_core:webvh:z6mkbob".to_owned(),
            ],
            realm_id: realm_id.to_string(),
            main_strand_id: "ak:strand:AZXoIs9BRSgujgrZ-dLgogRh6YCdLWfJAZWdPXg8qD9D".to_owned(),
            created_at: now,
        },
        DirectConversationEndorsement {
            actor_id: ALICE_CORE_ID.to_owned(),
            binding_event_ref: "ak:event:AZXoIs9BRSgujgrZ-dLgogRh6YCdLWfJAZWdPXg8qD9D".to_owned(),
        },
    );
    (state, realm_id)
}

fn registered_projection_inputs(
    operation: &Operation,
    actor_seq: u64,
) -> (
    arkret_event_draft::ProjectedEventOperation,
    Vec<arkret_wire::cba::ProjectedCellWrite>,
) {
    let mut event = crate::test_event::raw_event_at(
        operation.event_kind.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: operation.realm_id.clone(),
        },
        operation.context.sender.clone(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!("019041000000-{actor_seq:04x}-aabbccdd")).unwrap(),
        operation.payload.clone(),
        operation.created_at,
    )
    .unwrap();
    event.event_id = operation.context.event_id.clone();
    let projected = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
        operation.operation_id.clone(),
        operation.operation_kind.clone(),
        operation.object_id.clone(),
        &event,
    )
    .unwrap();
    let writes = arkret_schema::project_registered_cell_writes(
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    (projected, writes)
}

fn assert_projected(effect: soland_domain::reducer::ProjectionEffect) {
    assert!(
        !matches!(
            effect,
            soland_domain::reducer::ProjectionEffect::Rejected { .. }
        ),
        "canonical fixture projection rejected: {effect:?}"
    );
}

fn apply_with_registered_cell_writes(
    projection: &mut soland_domain::reducer::ProjectionState,
    operation: &Operation,
    actor_seq: u64,
    server_hlc: &soland_domain::hlc::ServerHlc,
) {
    let (projected, writes) = registered_projection_inputs(operation, actor_seq);
    assert_projected(projection.apply_projected(&projected, &writes, server_hlc));
}

/// Apply the founder's own `ak.member.state{join}` — the closing slot of a
/// genesis bootstrap unit — through the reducer admission actually uses for it.
///
/// A self-authored join is refused by the ordinary entry gate whenever the
/// Realm's join rule is `invite` or `closed`, which is exactly the Direct
/// Conversation profile. Genesis membership is admitted as part of the
/// validated bootstrap unit instead.
fn apply_bootstrap_membership_with_registered_cell_writes(
    projection: &mut soland_domain::reducer::ProjectionState,
    operation: &Operation,
    actor_seq: u64,
) {
    let (projected, writes) = registered_projection_inputs(operation, actor_seq);
    assert_projected(projection.apply_validated_realm_bootstrap_membership(&projected, &writes));
}

fn op(
    realm_id: arkret_identifiers::RealmId,
    seed: &str,
    kind: impl AsRef<str>,
    mut payload: serde_json::Value,
) -> Operation {
    if let Some(payload) = payload.as_object_mut()
        && let Some(accepted_event_id) = payload.remove("accepted_event_id")
    {
        payload.insert("event_id".to_owned(), accepted_event_id);
    }
    let executed_by = payload
        .as_object_mut()
        .and_then(|payload| payload.remove("executed_by"));
    let sender = payload
        .as_object_mut()
        .and_then(|payload| payload.remove("sender"));
    let mut operation = arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!(
            "ak:operation:01904100-0000-7000-8000-{seed}"
        ))
        .unwrap(),
        realm_id,
        kind.as_ref(),
        payload,
    );
    operation.context.principal_server_id = crate::test_event::principal_server_id();
    if let Some(executed_by) = executed_by {
        operation.context.executed_by = Some(serde_json::from_value(executed_by).unwrap());
    }
    if let Some(sender) = sender {
        let sender = match sender.as_str().unwrap() {
            "ak:did_core:web:alice.example" => ALICE_CORE_ID,
            "ak:did_core:web:agent.example" => AGENT_CORE_ID,
            sender => sender,
        };
        operation.context.sender = arkret_identifiers::DidCoreId::new(sender.to_owned()).unwrap();
    }
    operation
}

fn canonical_event_storage_identity(
    digest_payload: &serde_json::Value,
) -> (String, String, Vec<u8>) {
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(digest_payload).expect("canonical fixture bytes");
    let canonical_digest =
        arkret_canonical::canonical_sha256(digest_payload).expect("canonical fixture digest");
    let digest =
        arkret_identifiers::Hash::new(canonical_digest.clone()).expect("fixture digest is typed");
    let event_id = arkret_identifiers::EventId::from_event_digest(&digest)
        .expect("SHA-256 is a registered Event digest suite")
        .to_string();
    (event_id, canonical_digest, canonical_bytes)
}

fn accountability_grant_payload(status: &str, expires_at: &str) -> serde_json::Value {
    json!({
        "schema": "ak.schema.accountability_grant.v1",
        "sender": ALICE_CORE_ID,
        "issuer": ALICE_CORE_ID,
        "subject": AGENT_CORE_ID,
        "accountability_scope": "agent_operator",
        "not_before": "2026-01-01T00:00:00.000Z",
        "expires_at": expires_at,
        "grant_status": status,
        "proof": {
            "kind": "detached_jws",
            "verification_method": format!("{ALICE_FULL_ID}#key-1"),
            "payload_digest": format!("sha256:{}", "3".repeat(64)),
            "created_at": "2026-01-01T00:00:00.000Z",
            "jws": "AAAA.BBBB.CCCC"
        }
    })
}

#[test]
fn view_admission_rejects_retired_collection_and_actor_lifecycle_fields() {
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:AY95PK0h663rCWpc7Z3rVOJ17tol-scPCV546wg6AoVD")
            .unwrap();
    for definition in [
        json!({"collection": {"page_size": 50}}),
        json!({"collection": {"selection_policy": "multiple"}}),
        json!({"collection": {"grouping": {"wip_limit_enforcement": "warn"}}}),
        json!({"state": "tombstoned", "state_changed_at": "2026-07-17T00:00:00.000Z"}),
    ] {
        let operation = op(
            realm_id.clone(),
            "000000000611",
            arkret_wire::EventKind::ViewUpdate,
            json!({
                "view_id": "ak:view:AfNNPHw8rPLcSH3j2BXOmYhEGZkLo7yx1Wcc_ah5qVyn",
                "patch": definition
            }),
        );
        assert_eq!(
            validate_view_payload(&operation),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );
    }
    let current = op(
        realm_id,
        "000000000612",
        arkret_wire::EventKind::ViewUpdate,
        json!({
            "view_id": "ak:view:AfNNPHw8rPLcSH3j2BXOmYhEGZkLo7yx1Wcc_ah5qVyn",
            "patch": {"state": "tombstoned"}
        }),
    );
    validate_view_payload(&current).unwrap();
}

#[test]
fn shared_view_events_never_carry_a_private_view() {
    // `models/views.md` §3.1: a `visibility="private"` View lives only in
    // `ak.views.private.<view_id>` account data. Admission is what keeps the
    // shared surface clean — a private View that is refused entry to the Event
    // log can never surface from a shared View query, so this is the read-side
    // guarantee as well as the write-side one.
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:AcRoZR8_hwxZ-nwNkJO-TrgIrOADX-V8ZP_ETuQAFZNc")
            .unwrap();
    let private_view = json!({
        "id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
        "schema": "ak.schema.view.v1",
        "realm_id": realm_id.as_str(),
        "kind": "collection",
        "visibility": "private",
        "title": "personal board",
        "query": {"realm_id": realm_id.as_str()},
        "created_by": "did:web:alice.example",
        "created_at": "2026-07-30T00:00:00.000Z"
    });
    for (seed, kind, payload) in [
        (
            "000000000613",
            arkret_wire::EventKind::ViewCreate,
            json!({
                "view_id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
                "object": private_view.clone()
            }),
        ),
        (
            "000000000614",
            arkret_wire::EventKind::ViewUpdate,
            json!({
                "view_id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
                "patch": {"visibility": "private"}
            }),
        ),
        (
            "000000000615",
            arkret_wire::EventKind::ViewReconcile,
            json!({
                "view_id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
                "definition": private_view.clone()
            }),
        ),
        (
            "000000000616",
            arkret_wire::EventKind::ViewUpdate,
            json!({
                "view_id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
                "visibility": "private"
            }),
        ),
    ] {
        let operation = op(realm_id.clone(), seed, kind.clone(), payload);
        assert_eq!(
            validate_view_payload(&operation),
            Err("private_view_requires_account_data"),
            "{kind} must refuse a private View on the shared Event surface"
        );
    }

    // The same shapes with the shared visibility are admitted, so the rejection
    // above is about `visibility`, not about the payload shape.
    let mut shared_view = private_view;
    shared_view["visibility"] = json!("shared");
    let shared = op(
        realm_id,
        "000000000617",
        arkret_wire::EventKind::ViewCreate,
        json!({
            "view_id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
            "object": shared_view
        }),
    );
    validate_view_payload(&shared).unwrap();
}

fn test_state() -> AppState {
    AppState::new(test_config(), Db { pool: None })
}

fn install_projected_grant(
    authorization: &soland_services::authorization::AuthorizationService,
    realm_id: String,
    issuer: String,
    subject: String,
    resource: String,
    actions: Vec<String>,
    constraints: Vec<crate::authz::Constraint>,
) -> crate::authz::Grant {
    let mut grant = crate::authz::projected_grant_fixture(
        realm_id,
        issuer,
        subject,
        resource,
        actions,
        constraints,
    );
    let principal_server_id = crate::test_event::principal_server_id().into_string();
    grant.issuer_principal_server_id = principal_server_id.clone();
    grant.subject_principal_server_id = Some(principal_server_id);
    authorization.upsert_projected_grant(grant.clone());
    grant
}

fn signed_device_authorize_payload(
    device_signer: &SigningKey,
    signing_key: &SigningKey,
) -> arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceOrPrincipalRef, UnsignedDeviceAuthorizePayload,
    };

    let device_public_key = format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            device_signer.verifying_key().as_bytes(),
        )
    );
    let principal_id = crate::test_actor_id_str(ALICE_FULL_ID);
    let unsigned = UnsignedDeviceAuthorizePayload::new(
        principal_id.clone(),
        arkret_identifiers::DeviceId::new("ak:device:019eefcb-5882-7861-bc30-3033fa32dcf6")
            .unwrap(),
        arkret_wire::NonEmptyString::new(device_public_key).unwrap(),
        arkret_wire::NonEmptyString::new("z6LSgy7T8CEsMDMzk1e4EBFVX8CDXWWzvkFZWSXhsC97zjcM")
            .unwrap(),
        vec![
            arkret_wire::NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap(),
            arkret_wire::NonEmptyString::new("ak.mls.v1").unwrap(),
        ],
        Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
        DeviceOrPrincipalRef::Principal(principal_id),
        None,
        "2026-06-22T14:45:51Z".parse().unwrap(),
        None,
        DeviceAuthorizationBindingKind::RegistrationAnchor,
        None,
    )
    .expect("valid unsigned device authorization");
    let input = unsigned
        .device_possession_signature_input()
        .expect("device signature input");
    let signature = signing_key.sign(&input);
    unsigned
        .attach_signature(
            arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
                .unwrap(),
        )
        .expect("signed typed device authorize payload")
}

#[test]
fn device_authorize_validates_device_possession_signature() {
    let state = test_state();
    let device_signer = SigningKey::from_bytes(&[7u8; 32]);
    let payload = signed_device_authorize_payload(&device_signer, &device_signer);

    crate::routing::identity::device_signing::validate_device_authorize_binding(&state, &payload)
        .unwrap();
}

#[test]
fn device_authorize_rejects_signature_from_wrong_device_key() {
    let state = test_state();
    let device_signer = SigningKey::from_bytes(&[7u8; 32]);
    let wrong_signer = SigningKey::from_bytes(&[8u8; 32]);
    let payload = signed_device_authorize_payload(&device_signer, &wrong_signer);

    assert_eq!(
        crate::routing::identity::device_signing::validate_device_authorize_binding(
            &state, &payload
        ),
        Err("device_authorize_device_signature_invalid")
    );
}

fn grant_circle_action(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    circle_id: &str,
    actor: &str,
    action: &str,
) {
    install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:owner.example".to_owned(),
        actor.to_owned(),
        circle_id.to_owned(),
        vec![action.to_owned()],
        vec![crate::authz::Constraint::AllowedCircleIds {
            allowed_circle_ids: std::collections::BTreeSet::from([
                arkret_identifiers::CircleId::new(circle_id.to_owned()).expect("valid circle id"),
            ]),
        }],
    );
}

fn grant_moderation_decision(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    actor: &str,
) {
    install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:owner.example".to_owned(),
        actor.to_owned(),
        realm_id.to_string(),
        vec![
            arkret_wire::EventKind::ModerationDecision
                .as_str()
                .to_owned(),
        ],
        Vec::new(),
    );
}

fn grant_call_action(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    actor: &str,
    action: &str,
) {
    install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:owner.example".to_owned(),
        actor.to_owned(),
        realm_id.to_string(),
        vec![action.to_owned()],
        Vec::new(),
    );
}

fn seed_read_receipt_inheritance(
    state: &AppState,
    parent_realm_id: &str,
    child_realm_id: &str,
    parent_policy: serde_json::Value,
) {
    use arkret_state::lattice::CellState;

    let now = chrono::Utc::now();
    let mut projection = state.test_projection().lock();
    let cell_id = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.realm.read_receipt_policy.v1:{parent_realm_id}"
    ))
    .expect("valid read receipt policy cell ref");
    projection
        .cells
        .insert(cell_id, CellState::Value(parent_policy));
    projection
        .realm_links
        .entry(child_realm_id.to_owned())
        .or_default()
        .push(soland_domain::reducer::RealmLinkState {
            realm_id: child_realm_id.to_owned(),
            target_realm_id: parent_realm_id.to_owned(),
            link_kind: "governed_by".to_owned(),
            status: "active".to_owned(),
            label: None,
            commitment: None,
            created_at: now,
            updated_at: now,
        });
    projection.realm_inheritance_policies.insert(
        child_realm_id.to_owned(),
        soland_domain::reducer::RealmInheritancePolicyState {
            realm_id: child_realm_id.to_owned(),
            operation_id: "ak:operation:01904100-0000-7000-8000-000000009901".to_owned(),
            source_realm_id: parent_realm_id.to_owned(),
            allowed_policies: vec!["ak.realm.read_receipt_policy".to_owned()],
            allowed_capability_bundles: Vec::new(),
            max_depth: 1,
            updated_at: now,
        },
    );
}

#[tokio::test]
async fn read_receipt_child_policy_rejects_visibility_loosening() {
    let state = test_state();
    let parent_realm = "ak:realm:AayvHPIGaKmFumB-RpzVb9nydQtJilnjIY_0iphEtH50";
    let child_realm = arkret_identifiers::RealmId::new(
        "ak:realm:Ab-7DmdacX9m9iDoiewbvr1Th3bssb88zDPYsGOFvT77".to_owned(),
    )
    .unwrap();
    seed_read_receipt_inheritance(
        &state,
        parent_realm,
        child_realm.as_str(),
        json!({
            "disclosure": "optional",
            "visibility": "private",
            "scope_overrides_allowed": true
        }),
    );

    let child_policy = op(
        child_realm,
        "000000009913",
        arkret_wire::EventKind::RealmReadReceiptPolicy,
        json!({
            "disclosure": "optional",
            "visibility": "public"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[child_policy])
            .await
            .unwrap_err(),
        "policy_denied"
    );
}

#[tokio::test]
async fn read_receipt_child_policy_rejects_required_floor_without_escape() {
    let state = test_state();
    let parent_realm = "ak:realm:AatPxC-EqrbW4gPLx8kUdsCQdH5-3Uf5Vhx_nTaFmHiO";
    let child_realm = arkret_identifiers::RealmId::new(
        "ak:realm:AUz7tgcJ6ro47-4OhYOy75LdmXCYRnTUkLWvviuxYFld".to_owned(),
    )
    .unwrap();
    seed_read_receipt_inheritance(
        &state,
        parent_realm,
        child_realm.as_str(),
        json!({
            "disclosure": "required",
            "visibility": "members",
            "scope_overrides_allowed": true
        }),
    );

    let child_policy = op(
        child_realm,
        "000000009923",
        arkret_wire::EventKind::RealmReadReceiptPolicy,
        json!({
            "disclosure": "disabled",
            "visibility": "private"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[child_policy])
            .await
            .unwrap_err(),
        arkret_wire::ErrorCode::READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED
    );
}

#[tokio::test]
async fn read_receipt_child_policy_allows_required_floor_escape() {
    let state = test_state();
    let parent_realm = "ak:realm:AW-shobY6yowKV0Qvkhu1m9aYiJhgJnjVwpo17W-zUUA";
    let child_realm = arkret_identifiers::RealmId::new(
        "ak:realm:AaxSFmZIEvN6XVXnYnkDhe61AlMNo3BOvykm7pFOnj_k".to_owned(),
    )
    .unwrap();
    seed_read_receipt_inheritance(
        &state,
        parent_realm,
        child_realm.as_str(),
        json!({
            "disclosure": "required",
            "visibility": "members",
            "scope_overrides_allowed": true,
            "receipt_compliance_opt_in": {
                "child_privacy_tightening_against_required": true
            }
        }),
    );

    let child_policy = op(
        child_realm,
        "000000009933",
        arkret_wire::EventKind::RealmReadReceiptPolicy,
        json!({
            "disclosure": "disabled",
            "visibility": "private"
        }),
    );
    validate_operation_policy(&state, &[child_policy])
        .await
        .expect("parent escape allows compliance-floor privacy tightening");
}

#[tokio::test]
async fn read_receipt_child_policy_rejects_any_change_when_overrides_disabled() {
    let state = test_state();
    let parent_realm = "ak:realm:AWmEIzkE4XrcUfjV5Sih-8UONowvK9ezo3bWR157AaF4";
    let child_realm = arkret_identifiers::RealmId::new(
        "ak:realm:ARJq-x3T6BN8drHWBoEM6LmDMvq7MTwEO6LAXUqSwsA7".to_owned(),
    )
    .unwrap();
    seed_read_receipt_inheritance(
        &state,
        parent_realm,
        child_realm.as_str(),
        json!({
            "disclosure": "optional",
            "visibility": "members",
            "scope_overrides_allowed": false
        }),
    );

    let child_policy = op(
        child_realm,
        "000000009943",
        arkret_wire::EventKind::RealmReadReceiptPolicy,
        json!({
            "disclosure": "disabled",
            "visibility": "private"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[child_policy])
            .await
            .unwrap_err(),
        "policy_denied"
    );
}

async fn put_agent_participation_ceiling(
    state: &AppState,
    scope_kind: &str,
    scope_key: String,
    realm_id: &str,
    reply: bool,
    accept_third_party_mention: bool,
    act_on_behalf: bool,
) {
    state
        .agent_participations()
        .store_ceiling(json!({
            "scope_kind": scope_kind,
            "scope_key": scope_key,
            "realm_id": realm_id,
            "reply_message": reply,
            "reaction_add": false,
            "reaction_remove": false,
            "accept_third_party_mention": accept_third_party_mention,
            "act_on_behalf": act_on_behalf,
        }))
        .await
        .expect("agent participation ceiling");
}

#[tokio::test]
async fn strand_agent_participation_ceiling_cannot_widen_circle_parent() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AS1XvoEwEve7yjNY6nVsquBYDGIKDIrmFJeSCVjzcASh".to_owned(),
    )
    .unwrap();
    let circle_id = "ak:circle:AYzqeQ1hbLexQxBuFmhDzV2R1jsnUEvB0ELJR10hOgtK";
    let strand_id = "ak:strand:Afi2EiRHW33xFiFy_zIBtdd1aCF7PHRGPjpsj-e4AWBC";
    put_agent_participation_ceiling(
        &state,
        "circle",
        crate::routing::agent_participation::circle_scope_key(realm_id.as_str(), circle_id),
        realm_id.as_str(),
        true,
        false,
        false,
    )
    .await;

    let strand_create = op(
        realm_id,
        "000000009954",
        arkret_wire::EventKind::StrandCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "object": {
                "id": strand_id,
                "realm_id": "ak:realm:AS1XvoEwEve7yjNY6nVsquBYDGIKDIrmFJeSCVjzcASh",
                "scope_circle_id": circle_id,
                "metadata": {"title": "Scoped"},
                "agent_participation": {
                    "native_agent": {
                        "reply_message": true,
                        "reaction_add": false,
                        "reaction_remove": false,
                        "accept_third_party_mention": true,
                        "act_on_behalf": false
                    }
                }
            }
        }),
    );

    assert_eq!(
        validate_agent_participation_ceiling(&state, &[strand_create])
            .await
            .unwrap_err(),
        "agent_participation_ceiling_widen"
    );
}

#[tokio::test]
async fn strand_selection_is_capped_by_enclosing_circle_ceiling() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AXwMLE98Oc2dOnJY9S9B1SAxdb1aEynHmeXriuZR3FXU".to_owned(),
    )
    .unwrap();
    let circle_id = "ak:circle:AaUAN_rEJJKU7XaSLZMiAC3dbFtb6rKXV-89cGay4X9e";
    let strand_id = arkret_identifiers::StrandId::new(
        "ak:strand:Ab1XwDyGoarexWM5f2N9k9zOpOIkgMjf0Ky-ngz87YjD".to_owned(),
    )
    .unwrap();
    {
        let mut projection = state.test_projection().lock();
        projection.strands.insert(
            strand_id.as_str().to_owned(),
            soland_domain::reducer::StrandProjection {
                strand_id: strand_id.as_str().to_owned(),
                realm_id: realm_id.to_string(),
                tracks: Default::default(),
                title: "Scoped".to_owned(),
                summary: None,
                content: None,
                encrypted_content: None,
                fields: Default::default(),
                state: soland_domain::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: "did:web:alice.example".to_owned(),
                created_at: chrono::Utc::now(),
                history_basis_seals: Vec::new(),
                updated_by: None,
                updated_at: None,
                schema_refs: Vec::new(),
                schedule_revision_heads: Vec::new(),
                scope_circle_id: Some(circle_id.to_owned()),
            },
        );
    }
    put_agent_participation_ceiling(
        &state,
        "circle",
        crate::routing::agent_participation::circle_scope_key(realm_id.as_str(), circle_id),
        realm_id.as_str(),
        true,
        false,
        false,
    )
    .await;

    let scope_keys = crate::routing::agent_participation::scope_keys_for_message(
        &state,
        realm_id.as_str(),
        Some(strand_id.as_str()),
    )
    .expect("strand scope keys resolve");
    let ceiling = crate::routing::agent_participation::resolve_effective_ceiling_for_scope_keys(
        &state,
        &scope_keys,
    )
    .await;
    assert!(!ceiling.accept_third_party_mention);
    let selection =
        arkret_models_collaboration::governance::agent_participation::ParticipationBits {
            reply_message: true,
            reaction_add: true,
            reaction_remove: false,
            accept_third_party_mention: true,
            act_on_behalf: false,
        };
    let effective =
        arkret_models_collaboration::governance::agent_participation::effective_participation(
            ceiling, selection,
        );
    assert!(selection.accept_third_party_mention);
    assert!(!effective.accept_third_party_mention);
}

async fn register_agent_selection(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    agent_id: &str,
    reply: bool,
    act_on_behalf: bool,
) {
    let mut record = soland_services::identity::AgentPairingState::new(
        agent_id.to_owned(),
        ALICE_CORE_ID.to_owned(),
        "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
        arkret_wire::DidUrl::new(format!("{ALICE_FULL_ID}#managed-controller")).unwrap(),
        AgentLifecycleState::Active,
        chrono::Utc::now(),
    );
    record.display_name = Some("Summary".to_owned());
    record.agent_slug = Some("summary".to_owned());
    state
        .agent_pairings()
        .save_agent(record)
        .await
        .expect("agent record");
    assert!(
        state
            .agent_participations()
            .compare_and_swap_selection(
                json!({
                    "agent_id": agent_id,
                    "scope_kind": "realm",
                    "scope_key": crate::routing::agent_participation::realm_scope_key(realm_id.as_str()),
                    "realm_id": realm_id.as_str(),
                    "scope": { "kind": "realm", "realm_id": realm_id.as_str() },
                    "version": 1,
                    "reply_message": reply,
                    "reaction_add": false,
                    "reaction_remove": false,
                    "accept_third_party_mention": false,
                    "act_on_behalf": act_on_behalf,
                }),
                0
            )
            .await
            .expect("agent participation selection")
    );
}

async fn register_native_agent_membership_context(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    encrypted: bool,
    with_claimable_keypackage: bool,
) {
    let controller = ALICE_CORE_ID;
    let agent = AGENT_CORE_ID;
    let now = chrono::Utc::now();
    let mut record = soland_storage::AgentPrincipalRecord::new(
        agent.to_owned(),
        controller.to_owned(),
        "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
        arkret_wire::DidUrl::new(format!("{ALICE_FULL_ID}#managed-controller")).unwrap(),
        AgentLifecycleState::Active,
        now,
    );
    record.agent_slug = Some("summary".to_owned());
    let verification_method = "did:webvh:z6mkfixtureagent:agent.example#runtime-1";
    let (authorize_event_id, authorize_canonical_digest, authorize_canonical_bytes) =
        canonical_event_storage_identity(&json!({
            "kind": arkret_wire::EventKind::AgentKeyAuthorize,
            "realm_id": realm_id.as_str(),
            "agent_id": agent,
            "verification_method": verification_method
        }));
    if with_claimable_keypackage {
        record.authorized_event_ref = Some(authorize_event_id.clone());
        record.authorized_verification_method = Some(verification_method.to_owned());
    }
    state
        .test_persistence()
        .agents()
        .put(record)
        .await
        .expect("agent record");
    let accountability_grant_payload = json!({
        "schema": "ak.schema.accountability_grant.v1",
        "issuer": controller,
        "subject": agent,
        "accountability_scope": "agent_operator",
        "grant_status": "active",
        "not_before": "2026-01-01T00:00:00.000Z",
        "expires_at": "2099-01-01T00:00:00.000Z",
        "proof": {
            "kind": "detached_jws",
            "verification_method": format!("{ALICE_FULL_ID}#key-1"),
            "payload_digest": format!("sha256:{}", "3".repeat(64)),
            "created_at": "2026-01-01T00:00:00.000Z",
            "jws": "test"
        }
    });
    serde_json::from_value::<
        arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload,
    >(accountability_grant_payload.clone())
    .expect("standard accountability grant payload");
    let accountability_envelope = json!({
        "actor_id": controller,
        "executed_by": controller,
        "kind": "ak.identity.accountability_grant",
        "payload": accountability_grant_payload
    });
    let (accountability_event_id, accountability_digest, accountability_bytes) =
        canonical_event_storage_identity(&accountability_envelope);
    state
        .test_persistence()
        .events()
        .put(soland_storage::CanonicalEventRecord {
            event_id: accountability_event_id,
            actor_id: controller.to_owned(),
            actor_seq: 1,
            realm_id: Some("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned()),
            kind: "ak.identity.accountability_grant".to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            canonical_digest: accountability_digest,
            canonical_bytes: accountability_bytes,
            envelope: accountability_envelope,
            received_at: now,
        })
        .await
        .expect("accountability grant");
    state
        .test_persistence()
        .realm_meta()
        .put(
            realm_id.as_str(),
            &soland_storage::RealmMetaRecord {
                owner: controller.to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: encrypted.then(|| "mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: std::collections::BTreeMap::new(),
                minimal_metadata_realm: false,
                aad_visibility_ceiling: Default::default(),
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("realm meta");
    let controller_authority = arkret_wire::PrincipalAuthorityKey {
        principal_id: arkret_identifiers::DidCoreId::new(controller.to_owned()).unwrap(),
        principal_server_id: crate::test_event::principal_server_id(),
    };
    let mut projection = state.test_projection().lock();
    projection.members.insert(
        (realm_id.to_string(), controller.to_owned()),
        soland_domain::reducer::SolandMembershipState {
            member: controller.to_owned(),
            realm_id: realm_id.to_string(),
            state: "join".to_owned(),
            role: "owner".to_owned(),
            delivery_status: Some("unroutable".to_owned()),
            recipient_service_id: None,
            recipient_service_resolution: None,
            membership_event_ref: Some(AGENT_CONTROLLER_MEMBERSHIP_EVENT_ID.to_owned()),
            delivery_binding_frontier: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
    projection.membership_authorities.insert(
        (realm_id.to_string(), controller.to_owned()),
        controller_authority,
    );
    drop(projection);

    if !with_claimable_keypackage {
        return;
    }
    let device_id = "ak:device:01904100-0000-7000-8000-0000000007d1";
    let authorize_payload = json!({
        "agent_id": agent,
        "key_id": "ak:agent_key:01904100-0000-7000-8000-0000000007d2",
        "verification_method": verification_method,
        "public_key_digest": format!("sha256:{}", "4".repeat(64)),
        "accountable_principal_id": controller,
        "agent_key_scope": {"actions": ["ak.message.create"]},
        "audience": [state.service_id().as_str()],
        "issued_at": "2026-01-01T00:00:00.000Z",
        "expires_at": "2099-01-01T00:00:00.000Z"
    });
    let authorize_event = crate::test_event::raw_event(
        arkret_wire::EventKind::AgentKeyAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        arkret_wire::DidCoreId::new(agent.to_owned()).unwrap(),
        1,
        arkret_identifiers::Hlc::new("019041000000-0001-000007d2").unwrap(),
        authorize_payload.clone(),
    )
    .unwrap();
    let mut authorize_envelope = serde_json::to_value(authorize_event).unwrap();
    authorize_envelope["event_id"] = json!(authorize_event_id);
    state
        .test_persistence()
        .events()
        .put(soland_storage::CanonicalEventRecord {
            event_id: authorize_event_id.clone(),
            actor_id: agent.to_owned(),
            actor_seq: 1,
            realm_id: Some(realm_id.to_string()),
            kind: arkret_wire::EventKind::AgentKeyAuthorize
                .as_str()
                .to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            canonical_digest: authorize_canonical_digest,
            canonical_bytes: authorize_canonical_bytes,
            envelope: authorize_envelope,
            received_at: now,
        })
        .await
        .expect("Agent key authorization Event");
    let authorize_projection = op(
        realm_id.clone(),
        "0000000007d4",
        arkret_wire::EventKind::AgentKeyAuthorize,
        json!({
            "agent_id": agent,
            "key_id": "ak:agent_key:01904100-0000-7000-8000-0000000007d2",
            "accepted_event_id": authorize_event_id,
            "verification_method": verification_method,
        }),
    );
    state
        .test_projection()
        .lock()
        .apply(&authorize_projection, state.hlc());
    state.test_projection().lock().mls_key_packages.insert(
        "keypackage-01904100-0000-7000-8000-0000000007d1".to_owned(),
        soland_domain::reducer::MlsKeyPackage {
            id: "keypackage-01904100-0000-7000-8000-0000000007d1".to_owned(),
            keypackage_ref: "keypackage-01904100-0000-7000-8000-0000000007d1".to_owned(),
            keypackage_digest: format!("sha256:{}", "1".repeat(64)),
            actor_id: agent.to_owned(),
            device_id: device_id.to_owned(),
            lifetime: soland_domain::reducer::KeyPackageLifetime {
                not_before: now.timestamp() - 60,
                not_after: now.timestamp() + 3600,
            },
            key_package_bytes: vec![1, 2, 3],
            capabilities: vec!["mimi.content.v1".to_owned(), "ak.content.v1".to_owned()],
            capabilities_digest: format!("sha256:{}", "2".repeat(64)),
            device_signature: json!({"kid": "test", "sig": "test"}),
            last_resort: false,
            last_resort_realm_id: None,
            claimed_by: None,
            device_authorize_event_id: None,
            agent_key_authorize_event_id: Some(authorize_event_id.to_owned()),
            claimed_at: None,
            claim_expires_at_unix_ms: None,
            consumed_at: None,
            created_at: now.timestamp(),
        },
    );
}

fn native_agent_controller_binding() -> serde_json::Value {
    serde_json::to_value(
        arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding {
            controller_authority: arkret_wire::PrincipalAuthorityKey {
                principal_id: arkret_identifiers::DidCoreId::new(ALICE_CORE_ID.to_owned()).unwrap(),
                principal_server_id: crate::test_event::principal_server_id(),
            },
            controller_membership_generation_ref: arkret_identifiers::EventId::new(
                AGENT_CONTROLLER_MEMBERSHIP_EVENT_ID.to_owned(),
            )
            .unwrap(),
            controller_terminal_event_ref: None,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn encrypted_realm_native_agent_join_requires_claimable_keypackage() {
    let state = test_state();
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:Aa60MQP_oVAtFU0QOgJEKNdlwd3cd0d4XPjxPSbZSUzn")
            .unwrap();
    register_native_agent_membership_context(&state, &realm_id, true, false).await;
    let operation = op(
        realm_id,
        "0000000007d1",
        arkret_wire::EventKind::MemberState,
        json!({
            "sender": ALICE_CORE_ID,
            "actor_id": AGENT_CORE_ID,
            "membership": "join",
            "reason": "controller_add_agent",
            "delivery_status": "unroutable",
            "agent_controller_binding": native_agent_controller_binding()
        }),
    );

    assert_eq!(
        validate_member_state_policy_for_test(&state, &operation)
            .await
            .unwrap_err(),
        soland_services::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND
    );
}

#[tokio::test]
async fn encrypted_realm_native_agent_join_accepts_standard_claimable_keypackage() {
    let state = test_state();
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:AZAcSymeqCpuCXSyTlXUWIeJRNAz-V1BNJ0uNg_hgSZD")
            .unwrap();
    register_native_agent_membership_context(&state, &realm_id, true, true).await;
    let operation = op(
        realm_id,
        "0000000007d2",
        arkret_wire::EventKind::MemberState,
        json!({
            "sender": ALICE_CORE_ID,
            "actor_id": AGENT_CORE_ID,
            "membership": "join",
            "reason": "controller_add_agent",
            "delivery_status": "unroutable",
            "agent_controller_binding": native_agent_controller_binding()
        }),
    );

    validate_member_state_policy_for_test(&state, &operation)
        .await
        .expect("standard claimable KeyPackage satisfies encrypted admission precondition");
}

#[tokio::test]
async fn plaintext_realm_native_agent_join_does_not_require_keypackage() {
    let state = test_state();
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:ASNBn0fPSkl6VgQFEvleAz9gyjryUEn0sB6JXO38MDRY")
            .unwrap();
    register_native_agent_membership_context(&state, &realm_id, false, false).await;
    let operation = op(
        realm_id,
        "0000000007d3",
        arkret_wire::EventKind::MemberState,
        json!({
            "sender": ALICE_CORE_ID,
            "actor_id": AGENT_CORE_ID,
            "membership": "join",
            "reason": "controller_add_agent",
            "delivery_status": "unroutable",
            "agent_controller_binding": native_agent_controller_binding()
        }),
    );

    validate_member_state_policy_for_test(&state, &operation)
        .await
        .expect("plaintext Realm membership does not require MLS material");
}

fn agent_context(agent_id: &str, authorization_ref: &str) -> serde_json::Value {
    json!({
        "agent_id": agent_id,
        "operator_or_controller": ALICE_CORE_ID,
        "authorization_ref": authorization_ref,
        "execution_purpose": "test_action",
    })
}

fn reply_message(
    realm_id: arkret_identifiers::RealmId,
    seed: &str,
    agent_id: &str,
    authorization_ref: &str,
) -> Operation {
    op(
        realm_id,
        seed,
        arkret_wire::EventKind::MessageCreate,
        json!({
            "sender": agent_id,
            "content": [{"type": "text", "text": "agent reply"}],
            "agent_context": agent_context(agent_id, authorization_ref),
        }),
    )
}

fn act_on_behalf_message(
    realm_id: arkret_identifiers::RealmId,
    seed: &str,
    agent_id: &str,
    authorization_ref: Option<&str>,
    approval: Option<(&str, &str)>,
) -> Operation {
    let mut payload = json!({
        "sender": "ak:did_core:web:alice.example",
        "executed_by": agent_id,
        "content": [{"type": "text", "text": "approved"}],
    });
    if let Some(authorization_ref) = authorization_ref {
        let object = payload.as_object_mut().expect("payload object");
        object.insert("authorization_ref".to_owned(), json!(authorization_ref));
        object.insert(
            "agent_context".to_owned(),
            agent_context(agent_id, authorization_ref),
        );
    }
    if let Some((request_id, approval_nonce)) = approval {
        let object = payload.as_object_mut().expect("payload object");
        object.insert("approval_request_id".to_owned(), json!(request_id));
        object.insert("approval_nonce".to_owned(), json!(approval_nonce));
    }
    op(
        realm_id,
        seed,
        arkret_wire::EventKind::MessageCreate,
        payload,
    )
}

fn insert_approved_agent_action(
    state: &AppState,
    message: &Operation,
    request_id: &str,
    agent_id: &str,
    approval_nonce: &str,
) {
    let payload_digest = arkret_canonical::canonical_sha256(&message.payload).unwrap();
    state.test_projection().lock().agent_action_requests.insert(
        request_id.to_owned(),
        soland_domain::reducer::AgentActionRequestProjection {
            request_id: request_id.to_owned(),
            agent_id: agent_id.to_owned(),
            status: soland_domain::reducer::AgentActionRequestStatus::Approved,
            requested_at: message.created_at - chrono::Duration::minutes(1),
            resolved_at: Some(message.created_at),
            resolution_event_id: Some(
                "ak:event:AbuDfbb-uv82LvhWbTydj5wUDvzph0PSFjJTtTJxq7P5".to_owned(),
            ),
            cancel_reason: None,
            approval: Some(soland_domain::reducer::AgentActionApprovalProjection {
                approval_id: "ak:agent_approval:01904100-0000-7000-8000-0000000007aa".to_owned(),
                proposed_action: kinds::canonical_kind(message).as_str().to_owned(),
                target: json!({
                    "kind": "realm",
                    "realm_id": message.realm_id.as_str(),
                }),
                approved_payload_digest: payload_digest,
                approval_nonce: approval_nonce.to_owned(),
                expires_at: message.created_at + chrono::Duration::minutes(10),
            }),
        },
    );
}

#[tokio::test]
async fn active_direct_conversation_rejects_invite_space_and_third_party_member() {
    let (state, realm_id) = state_with_direct_binding();

    let invite = op(
        realm_id.clone(),
        "000000000601",
        arkret_wire::EventKind::InviteCreate,
        json!({
            "invitee": "did:web:charlie.example",
            "invite_delivery_target": {
                "recipient_service_id": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
                "recipient_service_kind": "principal_server"
            },
            "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "expires_at": "2026-08-05T10:00:00.000Z"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[invite])
            .await
            .unwrap_err(),
        "direct_conversation_invite_forbidden"
    );

    let space_create = op(
        realm_id.clone(),
        "000000000602",
        arkret_wire::EventKind::SpaceCreate,
        json!({
            "space_id": "ak:space:AfBl2v9EFciTUTWf3Pyvb2ZNjC04y8l-AW2bp6dJAZn1",
            "title": "Third participant space"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[space_create])
            .await
            .unwrap_err(),
        "direct_conversation_space_forbidden"
    );

    let member_add = op(
        realm_id,
        "000000000603",
        arkret_wire::EventKind::MemberState,
        json!({
            "actor_id": "did:web:charlie.example",
            "membership": "invite",
            "sender": "ak:did_core:web:alice.example"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[member_add])
            .await
            .unwrap_err(),
        "direct_conversation_third_party_member_forbidden"
    );
}

#[tokio::test]
async fn direct_conversation_role_fails_closed_when_binding_cache_is_missing() {
    let (state, realm_id) = state_with_direct_binding();
    state.contacts().clear_runtime_direct_bindings();

    let invite = op(
        realm_id.clone(),
        "000000000604",
        arkret_wire::EventKind::InviteCreate,
        json!({
            "invitee": "ak:did_core:web:charlie.example",
            "invite_delivery_target": {
                "recipient_service_id": "ak:did_core:web:local.host",
                "service_resolution": {
                    "current_record_url": "https://local.host/_arkret/open/services/ak%3Adid_core%3Aweb%3Alocal.host/resolution"
                },
                "recipient_service_kind": "principal_server"
            },
            "introduction_evidence_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "expires_at": "2026-08-05T10:00:00.000Z"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[invite])
            .await
            .unwrap_err(),
        "direct_conversation_invite_forbidden"
    );

    let member_add = op(
        realm_id,
        "000000000605",
        arkret_wire::EventKind::MemberState,
        json!({
            "actor_id": "did:web:charlie.example",
            "membership": "join",
            "sender": "ak:did_core:web:alice.example"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[member_add])
            .await
            .unwrap_err(),
        "direct_conversation_member_count_invalid"
    );
}

/// §8.1 — DM coordinates are permanent and successor-free, so an irreversible
/// terminal is refused. The reversible archive/freeze facets stay available.
#[tokio::test]
async fn direct_conversation_realm_refuses_tombstone_and_destroy() {
    let (state, realm_id) = state_with_direct_binding();

    for (seed, kind) in [
        ("000000000606", arkret_wire::EventKind::RealmTombstone),
        ("000000000607", arkret_wire::EventKind::RealmDestroy),
    ] {
        let terminal = op(
            realm_id.clone(),
            seed,
            kind.clone(),
            json!({ "sender": "ak:did_core:web:alice.example" }),
        );
        assert_eq!(
            validate_operation_policy(&state, &[terminal])
                .await
                .unwrap_err(),
            arkret_wire::ReasonCode::DIRECT_CONVERSATION_TERMINAL_FORBIDDEN,
            "{kind} must be refused on a canonical DM Realm"
        );
    }

    // The reversible facets are ordinary Realm authority, not a terminal.
    let archive = op(
        realm_id,
        "000000000608",
        arkret_wire::EventKind::RealmArchive,
        json!({ "sender": "ak:did_core:web:alice.example" }),
    );
    assert!(
        !matches!(
            validate_operation_policy(&state, &[archive]).await,
            Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_TERMINAL_FORBIDDEN)
        ),
        "ak.realm.archive is reversible and must not hit the terminal guard"
    );
}

/// §8.3 — the binding cell is an or_set keyed by `(binding_digest, actor_id)`.
/// Both participants endorsing the same coordinates are compatible adds: the
/// pair stays settled and MUST NOT join to bottom.
#[tokio::test]
async fn both_participants_endorsing_the_same_coordinates_stay_settled() {
    let (state, realm_id) = state_with_direct_binding();
    let pair_key = "sha256:00000000000000000000000000000000000000000000000000000000000006a1";

    state.contacts().install_direct_binding(
        pair_key.to_owned(),
        "sha256:0000000000000000000000000000000000000000000000000000000000000601",
        DirectConversationCoordinatesRecord {
            participants_unordered: vec![
                "did:web:alice.example".to_owned(),
                "did:web:bob.example".to_owned(),
            ],
            realm_id: realm_id.to_string(),
            main_strand_id: "ak:strand:AZXoIs9BRSgujgrZ-dLgogRh6YCdLWfJAZWdPXg8qD9D".to_owned(),
            created_at: chrono::Utc::now(),
        },
        DirectConversationEndorsement {
            actor_id: "did:web:bob.example".to_owned(),
            binding_event_ref: "ak:event:AfBl2v9EFciTUTWf3Pyvb2ZNjC04y8l-AW2bp6dJAZn1".to_owned(),
        },
    );

    assert!(
        !state.contacts().direct_binding_is_conflicted(pair_key),
        "two endorsements of one digest are compatible adds, not a conflict"
    );
    let settled = state
        .contacts()
        .direct_binding(pair_key)
        .expect("the pair stays settled");
    assert_eq!(settled.realm_id, realm_id.to_string());
    assert_eq!(
        settled.binding_event_ref, "ak:event:AZXoIs9BRSgujgrZ-dLgogRh6YCdLWfJAZWdPXg8qD9D",
        "the named endorsement is the lowest actor id's, so replicas agree"
    );
    assert!(
        state
            .contacts()
            .settled_direct_binding_for_realm(realm_id.as_ref())
            .is_some(),
        "the realm lookup must see the settled pair"
    );
    assert!(
        crate::routing::identity::account::direct_binding_matches_projection(&state, &settled),
        "the fixture projection must agree with the settled coordinates"
    );
}

/// §5.7 / §8.3 — two *distinct* digests for one pair freeze it. Nothing picks a
/// winner by digest order, arrival order or UUID.
#[tokio::test]
async fn two_distinct_endorsement_digests_freeze_the_pair() {
    let (state, realm_id) = state_with_direct_binding();
    let pair_key = "sha256:00000000000000000000000000000000000000000000000000000000000006a1";

    state.contacts().install_direct_binding(
        pair_key.to_owned(),
        "sha256:00000000000000000000000000000000000000000000000000000000000006ff",
        DirectConversationCoordinatesRecord {
            participants_unordered: vec![
                "did:web:alice.example".to_owned(),
                "did:web:bob.example".to_owned(),
            ],
            realm_id: "ak:realm:ARM1n3PTeYfi_CEquXWAA_goRY85bAGIYUrIFzp-2oey".to_owned(),
            main_strand_id: "ak:strand:AT6xmJ4IEcjdlEtitHIX86tdmTshioIpLxndx9E3KtoK".to_owned(),
            created_at: chrono::Utc::now(),
        },
        DirectConversationEndorsement {
            actor_id: "did:web:bob.example".to_owned(),
            binding_event_ref: "ak:event:AT6xmJ4IEcjdlEtitHIX86tdmTshioIpLxndx9E3KtoK".to_owned(),
        },
    );

    assert!(
        state.contacts().direct_binding_is_conflicted(pair_key),
        "a second distinct digest is a materialization conflict"
    );
    assert!(
        state.contacts().direct_binding(pair_key).is_none(),
        "a frozen pair has no settled coordinates; neither side may be served"
    );
    assert!(
        state
            .contacts()
            .settled_direct_binding_for_realm(realm_id.as_ref())
            .is_none(),
        "the realm lookup must not resurrect one side of a frozen pair"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_requires_participation_bit() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AT2g1B8NlsTQnu9kxPR0nPvh-bVNWGGMseceRnfLYwih".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
        Vec::new(),
    );
    let message = act_on_behalf_message(
        realm_id,
        "000000000701",
        agent,
        Some(grant.grant_id.as_str()),
        None,
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[message])
            .await
            .unwrap_err(),
        "agent_act_on_behalf_not_permitted"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_requires_authorization_ref_covering_action() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AZeoe8skvYdUZma_1pH3dCWvAy7ap4MWYRpM5f16O5yw".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::ReactionAdd.as_str().to_owned()],
        Vec::new(),
    );
    let message = act_on_behalf_message(
        realm_id,
        "000000000702",
        agent,
        Some(grant.grant_id.as_str()),
        None,
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[message])
            .await
            .unwrap_err(),
        "agent_act_on_behalf_authorization_ref_scope"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_non_message_write_requires_authorization_ref() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AVRRrROGV2ARk6OPXu6lATgiM5XQyZ_JcgwRjMC3Im1B".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let operation = op(
        realm_id,
        "0000000007a2",
        arkret_wire::EventKind::StrandCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "executed_by": agent,
            "object": {
                "id": "ak:strand:AVdfqhxRnk4959EgJEklIslgnTpVrvncd17v-s916y6P",
                "metadata": {"title": "Work"}
            }
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_act_on_behalf_authorization_ref_missing"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_strand_write_requires_agent_context() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AUfNT7qSwkDpB8SgZULB6UEnLA6DCqyGx6yfhKn-RnJj".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::StrandCreate.as_str().to_owned()],
        Vec::new(),
    );
    let operation = op(
        realm_id,
        "0000000007c1",
        arkret_wire::EventKind::StrandCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant.grant_id,
            "object": {
                "id": "ak:strand:AS9MRCiS8US6IL2jyf4nBx20bazdnIA8RcwS3yCwHc-h",
                "metadata": {"title": "Work"}
            }
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_context_missing"
    );
}

#[tokio::test]
async fn native_agent_member_target_uses_sender_for_agent_write_detection() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AeMbHcOGMt3VgaQzdMnK0nUaMYOGvt35z9V139HW8NEU".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let operation = op(
        realm_id,
        "0000000007b1",
        arkret_wire::EventKind::MemberState,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "actor_id": agent,
            "membership": "join",
            "realm_id": "ak:realm:AeMbHcOGMt3VgaQzdMnK0nUaMYOGvt35z9V139HW8NEU",
            "delivery_status": "unroutable"
        }),
    );

    validate_agent_reply_participation(&state, &[operation])
        .await
        .expect("membership target must not be treated as the executing agent");
}

#[tokio::test]
async fn act_on_behalf_agent_relation_write_rejects_context_authorization_mismatch() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ASX9zvSqYNXNYx7VQIbISCPKKTvGMcKOCnY1RxTDpEgU".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let envelope_grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::RelationCreate.as_str().to_owned()],
        Vec::new(),
    );
    let context_grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::RelationCreate.as_str().to_owned()],
        Vec::new(),
    );
    let operation = op(
        realm_id,
        "0000000007c2",
        arkret_wire::EventKind::RelationCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "executed_by": agent,
            "authorization_ref": envelope_grant.grant_id,
            "agent_context": agent_context(agent, context_grant.grant_id.as_str()),
            "relation_id": "ak:relation:AT9MgV4wqtfFSX-ooCQnZocjO8g6OURDSEk1JujmyrNf",
            "relation_kind": "references",
            "from_ref": "ak:strand:AT9MgV4wqtfFSX-ooCQnZocjO8g6OURDSEk1JujmyrNf",
            "to_ref": "ak:strand:AXDTq-UrA4iZU_0Xw6aOv4uWM8yGmnIpTstlVPn9zSLd"
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_context_authorization_ref_mismatch"
    );
}

#[tokio::test]
async fn provenance_actor_kind_agent_unknown_action_fails_closed_before_context() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AXzeZ-Ew-5O_W5FC1b8TyxqwA3twPkBPtlQ6j3xWqBYN".to_owned(),
    )
    .unwrap();
    let operation = op(
        realm_id,
        "0000000007c3",
        arkret_wire::EventKind::RelationCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "provenance": {
                "actor_kind": "agent"
            },
            "relation_id": "ak:relation:AXDTq-UrA4iZU_0Xw6aOv4uWM8yGmnIpTstlVPn9zSLd",
            "relation_kind": "references",
            "from_ref": "ak:strand:AaV0Wjp3LhZKUfcpa_CaAadjRsbPDxliKCkc9QbmZsyu",
            "to_ref": "ak:strand:AVlYG1Uzsm35_Y5x72KDPQXIcI3zCL4H2HF_bh3DgMMy"
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_participation_action_unknown"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_view_write_allows_valid_agent_context_and_approval() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AXlr1KB1QbTZsNhXulSUBNz9IMWJGKWMVdYyTD28xF4T".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::ViewCreate.as_str().to_owned()],
        Vec::new(),
    );
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c4",
        arkret_wire::EventKind::ViewCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant_id.as_str(),
            "agent_context": agent_context(agent, grant_id.as_str()),
            "view_id": "ak:view:AaV0Wjp3LhZKUfcpa_CaAadjRsbPDxliKCkc9QbmZsyu",
            "approval_request_id": "request-7c4",
            "approval_nonce": "nonce-7c4"
        }),
    );
    insert_approved_agent_action(&state, &operation, "request-7c4", agent, "nonce-7c4");

    validate_agent_reply_participation(&state, &[operation])
        .await
        .expect("valid agent_context must allow non-message act-on-behalf writes");
}

#[tokio::test]
async fn act_on_behalf_agent_unknown_kind_rejects_authorization_action() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AUKn_6c6DSK-7snjal8Dk5AtaL1dGSwfNAhvsig6jsbY".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec!["*".to_owned()],
        Vec::new(),
    );
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c5",
        "ak.agent.unknown.write",
        json!({
            "sender": "ak:did_core:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant_id.as_str(),
            "agent_context": agent_context(agent, grant_id.as_str()),
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_act_on_behalf_authorization_action_unsupported"
    );
}

#[tokio::test]
async fn reply_agent_unknown_kind_fails_closed_at_participation_registry() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AeAr0dq27Y12394LKAb3Xv0CnKBcTVG6R0EQTJCQbIe6".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec!["*".to_owned()],
        Vec::new(),
    );
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c6",
        "ak.agent.unknown.reply",
        json!({
            "sender": agent,
            "agent_context": agent_context(agent, grant_id.as_str()),
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_participation_action_unknown"
    );
}

#[tokio::test]
async fn reply_agent_lifecycle_state_blocks_writes_even_with_participation() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:Ad_TMwzMUtHlpgBlzEjvQtjThJ2GNykuHvEjDxchCErV".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
        Vec::new(),
    );
    let mut record = state
        .agent_pairings()
        .agent(agent)
        .await
        .expect("agent lookup")
        .expect("agent record");
    record.state = AgentLifecycleState::Paused;
    state
        .agent_pairings()
        .save_agent(record)
        .await
        .expect("agent record update");
    let operation = reply_message(realm_id, "0000000007c7", agent, grant.grant_id.as_str());

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_paused"
    );
}

#[tokio::test]
async fn reply_agent_projected_deactivation_blocks_writes_even_with_active_record() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AVvje1NQM-IzvlES2WgCeHRlHlw9b_oeEp3ZmYauIeIj".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
        Vec::new(),
    );
    state.test_projection().lock().agent_lifecycles.insert(
        agent.to_owned(),
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated,
    );
    let operation = reply_message(realm_id, "0000000007c8", agent, grant.grant_id.as_str());

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_deactivated"
    );
}

#[tokio::test]
async fn profile_accountable_principal_requires_active_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ARHX7LGKk2svV3upZ10pEmGoLdgEaEPI06-04trUQQdu".to_owned(),
    )
    .unwrap();
    let profile = op(
        realm_id,
        "0000000007a3",
        "ak.profile.create",
        json!({
            "principal_id": "did:web:agent.example",
            "display_name": "Agent",
            "accountable_principal_ids": ["did:web:alice.example"]
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[profile])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn profile_accountable_principal_rejects_batch_grant_signed_by_other_actor() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AcDBmaLJmexYp8de9kbZez_sjHqo3WTTKGdS8F_Tamb6".to_owned(),
    )
    .unwrap();
    let profile = op(
        realm_id.clone(),
        "0000000007a4",
        "ak.profile.create",
        json!({
            "sender": "ak:did_core:web:agent.example",
            "principal_id": "did:web:agent.example",
            "display_name": "Agent",
            "accountable_principal_ids": ["did:web:alice.example"]
        }),
    );
    let fake_grant = op(
        realm_id,
        "0000000007a5",
        "ak.identity.accountability_grant",
        json!({
            "sender": "ak:did_core:web:mallory.example",
            "issuer": "did:web:alice.example",
            "subject": "did:web:agent.example",
            "grant_status": "active",
            "not_before": "2026-01-01T00:00:00.000Z",
            "expires_at": "2099-01-01T00:00:00.000Z"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[fake_grant, profile])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn profile_accountable_principal_accepts_active_atomic_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AWT48tEXpBf1y4S4objnI4XLvPGbMAHzCgphs0-WDJPH".to_owned(),
    )
    .unwrap();
    let grant = op(
        realm_id.clone(),
        "0000000007a8",
        arkret_wire::EventKind::IdentityAccountabilityGrant,
        accountability_grant_payload("active", "2099-01-01T00:00:00.000Z"),
    );
    let profile = op(
        realm_id,
        "0000000007a9",
        "ak.profile.create",
        json!({
            "sender": AGENT_CORE_ID,
            "principal_id": AGENT_CORE_ID,
            "display_name": "Agent",
            "accountable_principal_ids": [ALICE_CORE_ID]
        }),
    );

    validate_operation_policy(&state, &[grant, profile])
        .await
        .expect("active atomic grant must satisfy the profile");
}

#[tokio::test]
async fn profile_accountable_principal_atomic_revoke_wins() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AaajU0E3YekQlILA6KFwZaoB7JHYohg-O0crFYr4hwuS".to_owned(),
    )
    .unwrap();
    let grant = op(
        realm_id.clone(),
        "0000000007aa",
        arkret_wire::EventKind::IdentityAccountabilityGrant,
        accountability_grant_payload("active", "2099-01-01T00:00:00.000Z"),
    );
    let revoke = op(
        realm_id.clone(),
        "0000000007ab",
        arkret_wire::EventKind::IdentityAccountabilityGrant,
        accountability_grant_payload("revoked", "2099-01-01T00:00:00.000Z"),
    );
    let profile = op(
        realm_id,
        "0000000007ac",
        "ak.profile.update",
        json!({
            "sender": "ak:did_core:web:agent.example",
            "principal_id": "did:web:agent.example",
            "display_name": "Agent",
            "accountable_principal_ids": ["did:web:alice.example"]
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[grant, revoke, profile])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn profile_accountability_uses_signed_frozen_time() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ASQslZEMbgHWd6DWpeEhQbJIgft2QchUND7vZal60zaI".to_owned(),
    )
    .unwrap();
    let grant = op(
        realm_id.clone(),
        "0000000007ad",
        arkret_wire::EventKind::IdentityAccountabilityGrant,
        accountability_grant_payload("active", "2026-06-01T00:00:00.000Z"),
    );
    let mut profile = op(
        realm_id,
        "0000000007ae",
        "ak.profile.update",
        json!({
            "sender": AGENT_CORE_ID,
            "principal_id": AGENT_CORE_ID,
            "display_name": "Agent",
            "accountable_principal_ids": [ALICE_CORE_ID]
        }),
    );
    profile.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    validate_operation_policy(&state, &[grant, profile])
        .await
        .expect("grant validity must use the profile Event's signed time, not wall clock");
}

#[tokio::test]
async fn profile_accountable_principal_rejects_stored_grant_signed_by_other_actor() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AVL-lH-YPO6V6QqApOt_nAmCdrWn3Wi6XOHl91H653O5".to_owned(),
    )
    .unwrap();
    let grant_envelope = json!({
        "actor_id": "did:web:mallory.example",
        "kind": "ak.identity.accountability_grant",
        "realm_id": realm_id.to_string(),
        "payload": {
            "issuer": "did:web:alice.example",
            "subject": "did:web:agent.example",
            "grant_status": "active",
            "not_before": "2026-01-01T00:00:00.000Z",
            "expires_at": "2099-01-01T00:00:00.000Z"
        }
    });
    let (grant_event_id, grant_digest, grant_bytes) =
        canonical_event_storage_identity(&grant_envelope);
    state
        .event_queries()
        .store_canonical_event(CanonicalEventRecord {
            event_id: grant_event_id,
            actor_id: "did:web:mallory.example".to_owned(),
            actor_seq: 1,
            realm_id: Some(realm_id.to_string()),
            kind: "ak.identity.accountability_grant".to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            canonical_digest: grant_digest,
            canonical_bytes: grant_bytes,
            envelope: grant_envelope,
            received_at: chrono::Utc::now(),
        })
        .await
        .expect("store fake accountability grant");
    let profile = op(
        realm_id,
        "0000000007a7",
        "ak.profile.create",
        json!({
            "sender": "ak:did_core:web:agent.example",
            "principal_id": "did:web:agent.example",
            "display_name": "Agent",
            "accountable_principal_ids": ["did:web:alice.example"]
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[profile])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn circle_member_manage_rejects_forged_verdict_without_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ASzMBU92ndTUgCFayN1yKHiZ3dJ7Irh18ENIqLIELrIQ".to_owned(),
    )
    .unwrap();
    let member_add = op(
        realm_id,
        "000000000881",
        arkret_wire::EventKind::CircleMemberState,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "circle_id": "ak:circle:AQzkNesVRZE45KCCmROpUPRV8VQzC-oUQQK8ytMOq1yO",
            "actor_id": "did:web:bob.example",
            "membership": "join",
            "manage_capability_verified": true,
            "actor_capability": {
                "action": "ak.circle.member.manage",
                "circle_id": "ak:circle:AQzkNesVRZE45KCCmROpUPRV8VQzC-oUQQK8ytMOq1yO",
                "allowed": true
            }
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[member_add])
            .await
            .unwrap_err(),
        "circle_member_manage_capability_required"
    );
}

#[tokio::test]
async fn circle_member_manage_allows_explicit_circle_scoped_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AW2Ebs3FRn6VzpiCswpoViFTHh-iDZrF_UzakuV14ZSm".to_owned(),
    )
    .unwrap();
    let circle_id = "ak:circle:AbPMdhKXl6Pe1lcCeCC_k_V5tvHDt1LAFRB6g6WrpDLJ";
    grant_circle_action(
        &state,
        &realm_id,
        circle_id,
        ALICE_CORE_ID,
        "ak.circle.member.manage",
    );
    let member_add = op(
        realm_id,
        "000000000882",
        arkret_wire::EventKind::CircleMemberState,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "circle_id": circle_id,
            "actor_id": "did:web:bob.example",
            "membership": "join",
            "manage_capability_verified": true,
            "actor_capability": {
                "action": "ak.circle.member.manage",
                "circle_id": circle_id,
                "allowed": true
            }
        }),
    );

    validate_operation_policy(&state, &[member_add])
        .await
        .expect("circle-scoped grant authorizes member management");
}

#[tokio::test]
async fn circle_lifecycle_requires_circle_manage_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ASS8zG4z3bNJuUr3YrKuhVUKUOTpX3PhfV-JrJ56QMzs".to_owned(),
    )
    .unwrap();
    let circle_id = "ak:circle:AT2LoQ65P6bU2ZDxq9XbubTSMDrqzlK8EFJNmM_pxt62";
    let tombstone = op(
        realm_id.clone(),
        "000000000883",
        arkret_wire::EventKind::CircleTombstone,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "circle_id": circle_id
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, std::slice::from_ref(&tombstone))
            .await
            .unwrap_err(),
        "circle_manage_capability_required"
    );

    grant_circle_action(
        &state,
        &realm_id,
        circle_id,
        ALICE_CORE_ID,
        "ak.circle.manage",
    );
    validate_operation_policy(&state, &[tombstone])
        .await
        .expect("circle-scoped manage grant authorizes lifecycle");
}

#[tokio::test]
async fn act_on_behalf_agent_allows_effective_selection_and_active_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AY3EjcWF5Gxh89mCnOZzpF_bpwVEmMWIXv9IkSHmVmMD".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
        Vec::new(),
    );
    let message = act_on_behalf_message(
        realm_id,
        "000000000703",
        agent,
        Some(grant.grant_id.as_str()),
        Some(("request-703", "nonce-703")),
    );
    insert_approved_agent_action(&state, &message, "request-703", agent, "nonce-703");

    validate_agent_reply_participation(&state, &[message])
        .await
        .expect("effective act-on-behalf grant should pass");
}

#[tokio::test]
async fn act_on_behalf_agent_requires_fresh_approval_request() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AXmGXr7blOycfvMmgehmJJCEpeYG165UnBvugl6pO_40".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
        Vec::new(),
    );
    let message = act_on_behalf_message(
        realm_id,
        "000000000704",
        agent,
        Some(grant.grant_id.as_str()),
        Some(("request-704", "nonce-704")),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[message])
            .await
            .unwrap_err(),
        "agent_act_on_behalf_approval_request_missing"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_consumes_approval_nonce_once() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AXaV71ycRWgQPn3H4tFrOYekLOPFiR6LNl9sGqWBs1T2".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
        Vec::new(),
    );
    let message = act_on_behalf_message(
        realm_id,
        "000000000705",
        agent,
        Some(grant.grant_id.as_str()),
        Some(("request-705", "nonce-705")),
    );
    insert_approved_agent_action(&state, &message, "request-705", agent, "nonce-705");

    validate_agent_reply_participation(&state, std::slice::from_ref(&message))
        .await
        .expect("first approval nonce use should pass");
    assert_eq!(
        validate_agent_reply_participation(&state, &[message])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED
    );
}

#[tokio::test]
async fn circle_scoped_relation_update_and_delete_require_circle_membership() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AaGPy5t1BAnukci5lpGNiOlo7TufaF-ociC1LVnQpv5B".to_owned(),
    )
    .unwrap();
    let circle_id = "ak:circle:AfF5Vi42N83lUBU2d9UbQFWzHxX2vlXkKpR-Ctx0Oh6D";
    let relation_id = "ak:relation:AfF5Vi42N83lUBU2d9UbQFWzHxX2vlXkKpR-Ctx0Oh6D";
    let now = chrono::Utc::now();
    {
        let mut projection = state.test_projection().lock();
        let mut members = std::collections::BTreeSet::new();
        members.insert(ALICE_CORE_ID.to_owned());
        projection.circles.insert(
            circle_id.to_owned(),
            soland_domain::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_string(),
                profile_ref: None,
                title: "Private".to_owned(),
                summary: None,
                display: serde_json::json!({"short_name":"Private","color_token":"slate","symbol":{"glyph":"ring"}}),
                directory_visibility: "private".to_owned(),
                join_rule: "invite".to_owned(),
                history_visibility: "joined".to_owned(),
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                encryption_profile: "none".to_owned(),
                mls_group_ref: None,
                state: soland_domain::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: ALICE_CORE_ID.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members,
            },
        );
        projection.relations.insert(
            relation_id.to_owned(),
            soland_domain::reducer::SolandRelationState {
                relation_id: relation_id.to_owned(),
                realm_id: realm_id.to_string(),
                relation_kind: "confidential_discussion_of".to_owned(),
                scope_circle_id: Some(circle_id.to_owned()),
                from_ref: Some("ak:strand:AYmJuuenMIJ2dTgMqUL3AoeJJOHo5Iap70ImQUPzbJhY".to_owned()),
                to_ref: Some("ak:strand:AcTTTDFcIiz-Tmjh-sPdibSEwAhireChqYZJzVM0K1MY".to_owned()),
                fields: Default::default(),
                state: "active".to_owned(),
                source_event_id: Some(
                    "ak:event:AfF5Vi42N83lUBU2d9UbQFWzHxX2vlXkKpR-Ctx0Oh6D".to_owned(),
                ),
                source_event_digest: Some(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_owned(),
                ),
                created_at: now,
                history_basis_seals: Vec::new(),
                updated_at: now,
            },
        );
    }

    let bob_update = op(
        realm_id.clone(),
        "000000000802",
        arkret_wire::EventKind::RelationUpdate,
        json!({
            "relation_id": relation_id,
            "sender": "ak:did_core:web:bob.example",
            "patch": {"fields.label": "nope"}
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[bob_update])
            .await
            .unwrap_err(),
        "circle_scope_membership_required"
    );

    let alice_update = op(
        realm_id.clone(),
        "000000000803",
        arkret_wire::EventKind::RelationUpdate,
        json!({
            "relation_id": relation_id,
            "sender": "ak:did_core:web:alice.example",
            "patch": {"fields.label": "ok"}
        }),
    );
    validate_operation_policy(&state, &[alice_update])
        .await
        .expect("circle member can update scoped relation");

    let bob_delete = op(
        realm_id,
        "000000000804",
        arkret_wire::EventKind::RelationTombstone,
        json!({
            "relation_id": relation_id,
            "sender": "ak:did_core:web:bob.example"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[bob_delete])
            .await
            .unwrap_err(),
        "circle_scope_membership_required"
    );
}

#[tokio::test]
async fn moderation_decision_checks_issuer_capability_not_sender_spoof() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ARkNLd10PLFU6nWXwpfON7eQhZGezakXw3pvJ5cRGc0Q".to_owned(),
    )
    .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000901",
        arkret_wire::EventKind::ModerationDecision,
        json!({
            "sender": "ak:did_core:web:moderator.example",
            "issuer": "did:web:impostor.example",
            "target_ref": "ak:message:AXvyk2cSPhfYUHVSaDoVqdjSO3t5IXRAqpG-6hQjjUAx",
            "decision": "quarantine",
            "request_canonical_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[decision])
            .await
            .unwrap_err(),
        "moderation_actor_mismatch"
    );
}

#[tokio::test]
async fn moderation_decision_allows_authorized_issuer() {
    const MODERATOR: &str = "ak:did_core:web:moderator.example";
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AUYLjBoI0xYRjG5SKmFPOh3Agj-mEAcV6cmiVPn4KB64".to_owned(),
    )
    .unwrap();
    grant_moderation_decision(&state, &realm_id, MODERATOR);
    let decision = op(
        realm_id,
        "000000000902",
        arkret_wire::EventKind::ModerationDecision,
        json!({
            "actor_id": MODERATOR,
            "sender": MODERATOR,
            "issuer": MODERATOR,
            "target_ref": "ak:message:AR9_0Dn3PqKpHpxvh0C4oIGwx_MZWw6y7PjVc300c93v",
            "decision": "quarantine",
            "request_canonical_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }),
    );

    validate_operation_policy(&state, &[decision])
        .await
        .expect("issuer with matching moderation capability should pass");
}

#[tokio::test]
async fn moderation_decision_rejects_missing_issuer_even_with_sender_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AQsAANkzbRAod6oC5lFzs1OxsLEt5mVJ35YGKc4cf_Vn".to_owned(),
    )
    .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000903",
        arkret_wire::EventKind::ModerationDecision,
        json!({
            "sender": "ak:did_core:web:moderator.example",
            "target_ref": "ak:message:AW8-c0F9KfRq5YWdUYT1ilfjIDzjU3jCt-GT8KmVIeCA",
            "decision": "quarantine",
            "request_canonical_digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[decision])
            .await
            .unwrap_err(),
        "moderation_decision_issuer_missing"
    );
}

#[tokio::test]
async fn call_recording_start_defaults_to_record_capability() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AfBbfcm-ayz4ms4IjZtpa_UeR-zkx9xDxFy3_SgyqMkh".to_owned(),
    )
    .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "ak:did_core:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_RECORD,
    );
    let start = op(
        realm_id,
        "000000000904",
        arkret_wire::EventKind::CallRecordingStart,
        json!({
            "sender": "ak:did_core:web:recorder.example",
            "call_id": "ak:call:AVy0_LisG9qoB26NeUHZ9StFVOl5nqsG2uOx425ecJtu",
            "recording_id": "recording-904",
            "recording_agent": "ak:did_core:web:recorder.example",
            "capture_kind": "recording",
            "mode": "audio_video",
            "visible_notice": true,
            "result": {
                "retention": {"consent_confirmed": true}
            }
        }),
    );

    validate_operation_policy(&state, &[start])
        .await
        .expect("ak.call.record should authorize recording capture");
}

#[tokio::test]
async fn call_recording_start_transcript_requires_transcribe_capability() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AbvPRiXVavzVHJKCDG8HK7s2PlyJBga3olAriX06ZGPZ".to_owned(),
    )
    .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "ak:did_core:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_RECORD,
    );
    let start = op(
        realm_id,
        "000000000905",
        arkret_wire::EventKind::CallRecordingStart,
        json!({
            "sender": "ak:did_core:web:recorder.example",
            "call_id": "ak:call:AbxEzmCDUuUSMHiCmmGdUzGwHpMTRY2ziLp69rH4QcVj",
            "recording_id": "transcript-905",
            "recording_agent": "ak:did_core:web:recorder.example",
            "capture_kind": "transcript",
            "mode": "audio",
            "visible_notice": true,
            "result": {
                "retention": {"consent_confirmed": true}
            }
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[start])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::TRANSCRIPTION_DENIED
    );
    assert_eq!(
        operation_policy_reason_code(arkret_wire::ReasonCode::TRANSCRIPTION_DENIED),
        (
            salvo::http::StatusCode::FORBIDDEN,
            arkret_wire::ReasonCode::TRANSCRIPTION_DENIED
        )
    );
}

#[tokio::test]
async fn call_recording_start_transcript_allows_transcribe_capability() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AYMs5egM4i4NiSry19jn62Jo_3_cXrETY3yjnsupOeTI".to_owned(),
    )
    .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "ak:did_core:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_TRANSCRIBE,
    );
    let start = op(
        realm_id,
        "000000000906",
        arkret_wire::EventKind::CallRecordingStart,
        json!({
            "sender": "ak:did_core:web:recorder.example",
            "call_id": "ak:call:ARUNG7uEIx_HZYhSqahMLGksSz4H88SpeRoxS9E5pnWO",
            "recording_id": "transcript-906",
            "recording_agent": "ak:did_core:web:recorder.example",
            "capture_kind": "transcript",
            "mode": "audio",
            "visible_notice": true,
            "result": {
                "retention": {"consent_confirmed": true}
            }
        }),
    );

    validate_operation_policy(&state, &[start])
        .await
        .expect("ak.call.transcribe should authorize transcript capture");
}

#[tokio::test]
async fn call_recording_start_rejects_missing_mode_and_noncanonical_recording_id() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AdoFjBodfOdOvxfSAV_E0X6ztrtRXo7FYSVsU9YRV4pE".to_owned(),
    )
    .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "ak:did_core:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_RECORD,
    );
    let payload = json!({
        "sender": "ak:did_core:web:recorder.example",
        "call_id": "ak:call:ATruBVw3F7e6GxSCTOAQ52Yh0RbzPwJS39bQb-Jz3JJt",
        "recording_id": "recording-907",
        "recording_agent": "ak:did_core:web:recorder.example",
        "capture_kind": "recording",
        "visible_notice": true,
        "result": {
            "recording_start_event_id": "ak:event:ATruBVw3F7e6GxSCTOAQ52Yh0RbzPwJS39bQb-Jz3JJt",
            "retention": {"consent_confirmed": true}
        }
    });
    let missing_mode = op(
        realm_id.clone(),
        "000000000907",
        arkret_wire::EventKind::CallRecordingStart,
        payload.clone(),
    );
    assert_eq!(
        validate_operation_policy(&state, &[missing_mode])
            .await
            .unwrap_err(),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION
    );

    let mut invalid_recording_id_payload = payload;
    invalid_recording_id_payload["recording_id"] = json!("recording id");
    invalid_recording_id_payload["mode"] = json!("audio_video");
    let invalid_recording_id = op(
        realm_id,
        "000000000908",
        arkret_wire::EventKind::CallRecordingStart,
        invalid_recording_id_payload,
    );
    assert_eq!(
        validate_operation_policy(&state, &[invalid_recording_id])
            .await
            .unwrap_err(),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION
    );
}

#[tokio::test]
async fn mls_prejoin_history_rejects_non_history_capable_content_scheme() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ASAnmWDtY3OTo77OiPg3GqeghKefJ_tQffOq_LTR6JRP".to_owned(),
    )
    .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c101",
        arkret_wire::EventKind::RealmCreate,
        json!({
            "object": {
                "id": realm_id.as_str(),
                "title": "Prejoin history",
                "history_visibility": "shared",
                "encryption_profile": "mls_rfc9420"
            }
        }),
    );
    let strict_scheme = op(
        realm_id,
        "00000000c102",
        arkret_wire::EventKind::RealmPolicyBundle,
        json!({
            "policy_revision": 1,
            "content_scheme": "mls_rfc9420"
        }),
    );

    let reason = validate_operation_policy(&state, &[create, strict_scheme])
        .await
        .unwrap_err();
    assert_eq!(
        reason,
        arkret_wire::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
    );
    assert_eq!(
        operation_policy_reason_code(reason),
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            "failed_precondition"
        )
    );
}

#[tokio::test]
async fn mls_prejoin_history_accepts_exporter_aead_content_scheme() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:Adn4myr04NNzApPCuwFYPkPb4gyi37eacqboukmzpWy_".to_owned(),
    )
    .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c201",
        arkret_wire::EventKind::RealmCreate,
        json!({
            "object": {
                "id": realm_id.as_str(),
                "title": "Prejoin history",
                "history_visibility": "shared",
                "encryption_profile": "mls_rfc9420"
            }
        }),
    );
    let exporter_scheme = op(
        realm_id,
        "00000000c202",
        arkret_wire::EventKind::RealmPolicyBundle,
        json!({
            "policy_revision": 1,
            "content_scheme": "mls_exporter_aead_v1"
        }),
    );

    validate_operation_policy(&state, &[create, exporter_scheme])
        .await
        .expect("pre-join history is valid when the MLS realm declares exporter-AEAD");
}

#[tokio::test]
async fn mls_prejoin_history_accepts_create_object_exporter_aead_content_scheme() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AW2U7U6ZnE5lEu9swBXj0abSIg2MUGft9XAX-S-ADm_6".to_owned(),
    )
    .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c211",
        arkret_wire::EventKind::RealmCreate,
        json!({
            "object": {
                "id": realm_id.as_str(),
                "title": "Prejoin history",
                "history_visibility": "shared",
                "encryption_profile": "mls_rfc9420",
                "content_scheme": "mls_exporter_aead_v1"
            }
        }),
    );

    validate_operation_policy(&state, &[create])
        .await
        .expect("pre-join history is valid when ak.realm.create declares exporter-AEAD");
}

#[tokio::test]
async fn mls_prejoin_history_rejects_create_object_strict_content_scheme() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AXL6DJpgz_9X_LYgOHyNrOeH-bhp9kH0i97n3OlavYdA".to_owned(),
    )
    .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c221",
        arkret_wire::EventKind::RealmCreate,
        json!({
            "object": {
                "id": realm_id.as_str(),
                "title": "Prejoin history",
                "history_visibility": "shared",
                "encryption_profile": "mls_rfc9420",
                "content_scheme": "mls_rfc9420"
            }
        }),
    );

    let reason = validate_operation_policy(&state, &[create])
        .await
        .unwrap_err();
    assert_eq!(
        reason,
        arkret_wire::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
    );
}

#[tokio::test]
async fn mls_strict_existing_realm_rejects_prejoin_history_update() {
    use arkret_state::lattice::CellState;

    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AURHN1jBw6BjkPcuVTL89ylRp2BLpjBYUaSMpx4hoZMO".to_owned(),
    )
    .unwrap();
    let now = chrono::Utc::now();
    state
        .realms()
        .store_realm_metadata(
            realm_id.as_str(),
            soland_services::events::RealmMetadata {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: std::collections::BTreeMap::new(),
                minimal_metadata_realm: false,
                aad_visibility_ceiling: Default::default(),
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("realm meta stored");
    {
        let mut projection = state.test_projection().lock();
        projection.realm_policy_bundle_cells.insert(
            realm_id.to_string(),
            CellState::Value(json!({
                "policy_revision": 1,
                "content_scheme": "mls_rfc9420"
            })),
        );
    }
    let history_visibility = op(
        realm_id,
        "00000000c301",
        arkret_wire::EventKind::RealmHistoryVisibility,
        json!({
            "value": "shared"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[history_visibility])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
    );
}

// encryption-and-audit.md §2.10.8 — an RRK-targeted `ak.realm_key.share` (to a
// declared recovery recipient) is accepted by the share-policy gate even though
// the recipient is NOT a member and the realm carries no history-sharing policy.
// The discriminator is structural: `recipient_principal_id` is a current
// `durability_policy.recovery_recipients[].principal_id`.
#[tokio::test]
async fn realm_key_share_rrk_targeted_is_accepted_for_recovery_recipient() {
    use arkret_state::lattice::CellState;

    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AZquEEE7ly4W-MA4shMoS_Jwvj_0MhqLDtIVHmnlPP4X".to_owned(),
    )
    .unwrap();
    let recovery_principal = "ak:did_core:webvh:z6mkfixturehr";
    let recovery_verification_method = "did:webvh:z6mkfixturehr:hr.example#rrk-1";

    // Seed the projected policy_bundle cell with an exporter-AEAD scheme +
    // org RRK durability policy naming `recovery_principal` as a recipient.
    {
        let mut projection = state.test_projection().lock();
        projection.realm_policy_bundle_cells.insert(
            realm_id.to_string(),
            CellState::Value(json!({
                "policy_revision": 1,
                "content_scheme": "mls_exporter_aead_v1",
                "durability_policy": {
                    "mode": "org_recovery_key",
                    "recovery_recipients": [{
                        "recipient_id": "rrk-1",
                        "principal_id": recovery_principal,
                        "verification_method": recovery_verification_method
                    }]
                }
            })),
        );
    }

    let share = op(
        realm_id.clone(),
        "00000000d100",
        arkret_wire::EventKind::RealmKeyShare,
        json!({
            "share_kind": "realm_recovery_key",
            "recipient_principal_id": recovery_principal,
            "recipient_verification_method": recovery_verification_method,
            "recovery_recipient_id": "rrk-1",
            "sender_device_id": "ak:device:01904100-0000-7000-8000-00000000d1d2",
            "source_authorization_ref": "ak:event:ASvPdNAOWXf8kk2Jd-FbnlIFnNiMFE5H2L2hHGSmQP4_",
            "sender_device_signature": {"signature_algorithm": "Ed25519", "kid": "k", "sig": "s"},
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id.as_str()},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "hpke-sealed-history-secret",
            "created_at": "2026-06-25T00:00:00.000Z"
        }),
    );

    validate_realm_key_share_policy(&state, &share)
        .await
        .expect("RRK-targeted share to a recovery recipient must be accepted");
}

#[tokio::test]
async fn realm_key_share_member_device_accepts_projection_metadata() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:Aa1JCF6pnQnSgl8DnT6vNtPcFGPCxLnEY130o2lmyDSh".to_owned(),
    )
    .unwrap();
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-05T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let bob = "ak:did_core:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-00000000d3d1";

    state
        .realms()
        .store_realm_metadata(
            realm_id.as_str(),
            soland_services::events::RealmMetadata {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "shared".to_owned(),
                history_sharing_policy: Some(json!({
                    "version": 1,
                    "default_key_share": "event_time_visibility",
                    "pre_join_history": "visibility_condition_allowed",
                    "allowed_key_sources": ["verified_member_device"],
                    "allowed_receiver_states": ["active_member"],
                    "audit": {
                        "share_audit_event_required": false,
                        "access_audit_required": false
                    }
                })),
                history_sharing_policy_digest: Some(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_owned(),
                ),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: std::collections::BTreeMap::new(),
                minimal_metadata_realm: false,
                aad_visibility_ceiling: Default::default(),
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("realm meta stored");
    state
        .identities()
        .save_device(soland_services::identity::SaveDeviceCommand {
            actor_id: bob.to_owned(),
            device_id: bob_device.to_owned(),
            display_name: None,
            device: soland_services::identity::DeviceIdentity {
                actor_id: bob.to_owned(),
                device_id: bob_device.to_owned(),
                display_name: None,
                verification_state: "verified".to_owned(),
                payload: json!({"algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1"]}),
                created_at: now,
                updated_at: now,
                revoked_at: None,
            },
        })
        .await
        .expect("device stored");
    {
        let mut projection = state.test_projection().lock();
        projection.members.insert(
            (realm_id.to_string(), bob.to_owned()),
            soland_domain::reducer::SolandMembershipState {
                member: bob.to_owned(),
                realm_id: realm_id.to_string(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                delivery_status: Some("routable".to_owned()),
                recipient_service_id: Some("ak:did_core:web:local.host".to_owned()),
                recipient_service_resolution: Some(json!({
                    "current_record_url": "https://local.host/_arkret/open/services/ak%3Adid_core%3Aweb%3Alocal.host/resolution"
                })),
                membership_event_ref: Some(
                    "ak:event:Aen872J0_GJsInIbyMOsXR2xbw27ZfJY2H6f96pYsgUC".to_owned(),
                ),
                delivery_binding_frontier: None,
                invited_at: Some(now),
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
    }

    let share = op(
        realm_id.clone(),
        "00000000d300",
        arkret_wire::EventKind::RealmKeyShare,
        json!({
            "share_kind": "member_device",
            "recipient_principal_id": bob,
            "recipient_device_id": bob_device,
            "sender_device_id": "ak:device:01904100-0000-7000-8000-00000000d3d2",
            "source_authorization_ref": "ak:event:AefFLnGCxWP_cx9pZCZR5OTqQnHHI1ubt8-iDlcMP-ZP",
            "sender_device_signature": {"signature_algorithm": "Ed25519", "kid": "k", "sig": "s"},
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id.as_str()},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "sealed-history-secret",
            "created_at": "2026-07-05T00:00:00.000Z",
            "event_id": "ak:event:AbmoMmPKDs6imtvD716Jo6SMuqoQBREkaSd3-lTFdVED",
            "sender": "ak:did_core:web:alice.example"
        }),
    );

    validate_realm_key_share_policy(&state, &share)
        .await
        .expect("projected member-device share metadata must not poison policy parsing");
}

// A non-recovery, non-member recipient with no history-sharing policy still
// fails closed — the RRK branch only applies to declared recovery recipients.
#[tokio::test]
async fn realm_key_share_non_recovery_recipient_without_policy_is_rejected() {
    use arkret_state::lattice::CellState;

    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AfjxQq9gX4KN0dq1wVuvCK-hy0kd5l2V1heQq4f3eqiB".to_owned(),
    )
    .unwrap();
    {
        let mut projection = state.test_projection().lock();
        projection.realm_policy_bundle_cells.insert(
            realm_id.to_string(),
            CellState::Value(json!({
                "policy_revision": 1,
                "content_scheme": "mls_exporter_aead_v1",
                "durability_policy": {
                    "mode": "org_recovery_key",
                    "recovery_recipients": [{
                        "recipient_id": "rrk-1",
                        "principal_id": "ak:did_core:webvh:z6mkfixturehr",
                        "verification_method": "did:webvh:z6mkfixturehr:hr.example#rrk-1"
                    }]
                }
            })),
        );
    }

    let share = op(
        realm_id.clone(),
        "00000000d200",
        arkret_wire::EventKind::RealmKeyShare,
        json!({
            "share_kind": "member_device",
            "recipient_principal_id": "ak:did_core:web:stranger.example",
            "recipient_device_id": "ak:device:01904100-0000-7000-8000-00000000d2d1",
            "sender_device_id": "ak:device:01904100-0000-7000-8000-00000000d2d2",
            "source_authorization_ref": "ak:event:ARj82v99exuqCarIqXhrBbP7-PnlaJkPBbkwanCUgGwc",
            "sender_device_signature": {"signature_algorithm": "Ed25519", "kid": "k", "sig": "s"},
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id.as_str()},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "sealed",
            "created_at": "2026-06-25T00:00:00.000Z"
        }),
    );

    let result = validate_realm_key_share_policy(&state, &share).await;
    assert_eq!(
        result,
        Err("history_sharing_policy_missing"),
        "a non-recovery recipient with no history-sharing policy must fail closed"
    );
}
