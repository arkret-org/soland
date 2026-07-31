use serde_json::{Value, json};

use super::*;

const REALM: &str = "ak:realm:0196419b-1000-7000-8000-000000000001";
const OTHER_REALM: &str = "ak:realm:0196419b-2000-7000-8000-000000000001";
const RECIPIENT: &str = "did:web:bob.example";
const RECIPIENT_DEVICE: &str = "ak:device:01904100-0000-7000-8000-0000000000b1";
const SENDER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";

fn realm_key_share_payload(effective_scope: Value) -> Value {
    json!({
        "share_kind": "member_device",
        "recipient_principal_id": RECIPIENT,
        "recipient_device_id": RECIPIENT_DEVICE,
        "sender_device_id": SENDER_DEVICE,
        "source_authorization_ref": "ak:event:01904100-0000-7000-8000-0000000000a1",
        "sender_device_signature": {
            "alg": "EdDSA",
            "kid": "did:web:alice.example#device-history",
            "sig": "signature-base64url-placeholder"
        },
        "key_scope": {
            "effective_scope": effective_scope,
            "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "membership_frontier_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "from_epoch": 1,
            "to_epoch": 3,
            "history_visibility": "shared"
        },
        "ciphertext": "sealed-history-key",
        "aad_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "created_at": "2026-06-22T00:00:00.000Z"
    })
}

fn realm_scope(realm_id: &str) -> Value {
    json!({
        "kind": "realm",
        "realm_id": realm_id
    })
}

#[test]
fn realm_key_share_dispatch_projects_effect() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("realm-key-share");

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::REALM_KEY_SHARE,
            REALM,
            realm_key_share_payload(realm_scope(REALM)),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::RealmKeyShareProjected {
            ref realm_id,
            ref recipient_principal_id,
            ref recipient_device_id,
        } if realm_id == REALM
            && recipient_principal_id == RECIPIENT
            && recipient_device_id.as_deref() == Some(RECIPIENT_DEVICE)
    ));
}

#[test]
fn realm_key_share_dispatch_accepts_projection_metadata() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("realm-key-share-projected-context");
    let mut payload = realm_key_share_payload(realm_scope(REALM));
    payload["event_id"] = json!("ak:event:01904100-0000-7000-8000-000000000701");
    payload["sender"] = json!("did:web:alice.example");
    payload["hlc"] = json!("2026-07-05T00:00:00.000Z/node/1");

    let effect = state.apply(
        &make_operation(arkret_wire::EventKind::REALM_KEY_SHARE, REALM, payload),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::RealmKeyShareProjected {
            ref realm_id,
            ref recipient_principal_id,
            ref recipient_device_id,
        } if realm_id == REALM
            && recipient_principal_id == RECIPIENT
            && recipient_device_id.as_deref() == Some(RECIPIENT_DEVICE)
    ));
}

/// Exactly-one material is now a wire invariant (schema `oneOf` plus the SDK
/// `RealmKeyShareMaterial` enum), so a share with neither material never
/// reaches the reducer's own checks — it fails at deserialization.
#[test]
fn realm_key_share_without_material_fails_typed_parsing() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("realm-key-share-material");
    let mut payload = realm_key_share_payload(realm_scope(REALM));
    let object = payload.as_object_mut().expect("payload object");
    object.remove("ciphertext");
    object.remove("encrypted_key_ref");

    let effect = state.apply(
        &make_operation(arkret_wire::EventKind::REALM_KEY_SHARE, REALM, payload),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "realm_key_share_payload_invalid"
    ));
}

/// `NonEmptyString` only rejects the empty string, so a whitespace-only
/// ciphertext still parses and must be caught by the reducer.
#[test]
fn realm_key_share_rejects_whitespace_only_ciphertext() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("realm-key-share-blank-material");
    let mut payload = realm_key_share_payload(realm_scope(REALM));
    let object = payload.as_object_mut().expect("payload object");
    object.remove("encrypted_key_ref");
    object.insert("ciphertext".to_owned(), serde_json::json!("   "));

    let effect = state.apply(
        &make_operation(arkret_wire::EventKind::REALM_KEY_SHARE, REALM, payload),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "realm_key_share_material_missing"
    ));
}

#[test]
fn realm_key_share_rejects_scope_mismatch() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("realm-key-share-scope");

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::REALM_KEY_SHARE,
            REALM,
            realm_key_share_payload(realm_scope(OTHER_REALM)),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "realm_key_share_scope_mismatch"
    ));
}

#[test]
fn realm_key_share_rejects_inverted_epoch_range() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("realm-key-share-epoch-range");
    let mut payload = realm_key_share_payload(realm_scope(REALM));
    payload["key_scope"]["from_epoch"] = json!(4);
    payload["key_scope"]["to_epoch"] = json!(3);

    let effect = state.apply(
        &make_operation(arkret_wire::EventKind::REALM_KEY_SHARE, REALM, payload),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "realm_key_share_epoch_range_invalid"
    ));
}

#[test]
fn realm_key_share_is_registered_in_default_apply_registry() {
    assert!(
        default_apply_registry().contains_key(arkret_wire::EventKind::REALM_KEY_SHARE),
        "ak.realm_key.share should dispatch through the reducer registry"
    );
}
