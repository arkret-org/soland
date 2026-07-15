use arkret_sdk::EncryptedEnvelopeAadVisibility;
use serde_json::json;

use super::*;

#[test]
fn aad_visibility_maps_known_wire_values() {
    // SEC-08 — wire discriminator → SDK enum, root and nested forms.
    assert!(matches!(
        minimal_metadata_aad_visibility(&json!({"aad_visibility_event_id": "hidden"})),
        Some(EncryptedEnvelopeAadVisibility::Hidden)
    ));
    assert!(matches!(
        minimal_metadata_aad_visibility(&json!({"aad_visibility_event_id": "routing_digest"})),
        Some(EncryptedEnvelopeAadVisibility::RoutingDigest)
    ));
    assert!(matches!(
        minimal_metadata_aad_visibility(&json!({"aad_visibility_event_id": "opaque_id"})),
        Some(EncryptedEnvelopeAadVisibility::OpaqueId)
    ));
    // Spec wire example nests the envelope under `envelope`.
    assert!(matches!(
        minimal_metadata_aad_visibility(
            &json!({"envelope": {"aad_visibility_event_id": "hidden"}})
        ),
        Some(EncryptedEnvelopeAadVisibility::Hidden)
    ));
}

#[test]
fn aad_visibility_missing_or_unknown_is_none() {
    // Absent or unrecognised discriminator → None, which the caller treats
    // as fail-closed for a minimal-metadata Realm.
    assert!(minimal_metadata_aad_visibility(&json!({})).is_none());
    assert!(
        minimal_metadata_aad_visibility(&json!({"aad_visibility_event_id": "bogus"})).is_none()
    );
}
