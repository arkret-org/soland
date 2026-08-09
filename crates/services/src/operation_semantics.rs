use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;

pub const AUDIT_COMPLIANCE_PROFILES: &[&str] = soland_domain::kinds::AUDIT_COMPLIANCE_PROFILES;
pub const REASON_KEYPACKAGE_NOT_FOUND: &str =
    soland_domain::reducer::mls::REASON_KEYPACKAGE_NOT_FOUND;
pub const REASON_KEYPACKAGE_ALREADY_CLAIMED: &str =
    soland_domain::reducer::mls::REASON_KEYPACKAGE_ALREADY_CLAIMED;
pub const REASON_KEYPACKAGE_REALM_MISMATCH: &str =
    soland_domain::reducer::mls::REASON_KEYPACKAGE_REALM_MISMATCH;
pub const CHILD_ORDER_CELL_FAMILY: &str = soland_domain::reducer::CHILD_ORDER_CELL_FAMILY;

pub fn canonical_kind_for_operation(operation: &Operation) -> Option<arkret_wire::EventKind> {
    soland_domain::kinds::canonical_kind_for_operation(operation)
}

pub fn canonical_kind(operation: &Operation) -> arkret_wire::EventKind {
    soland_domain::kinds::canonical_kind(operation)
}

pub fn operation_is_message_create(operation: &Operation) -> bool {
    soland_domain::kinds::operation_is_message_create(operation)
}

pub fn operation_is_redaction(operation: &Operation) -> bool {
    soland_domain::kinds::operation_is_redaction(operation)
}

pub fn operation_is_membership(operation: &Operation) -> bool {
    soland_domain::kinds::operation_is_membership(operation)
}

pub fn operation_is_invite(operation: &Operation) -> bool {
    soland_domain::kinds::operation_is_invite(operation)
}

pub fn operation_is_invite_create(operation: &Operation) -> bool {
    soland_domain::kinds::operation_is_invite_create(operation)
}

pub fn operation_is_invite_claim(operation: &Operation) -> bool {
    soland_domain::kinds::operation_is_invite_claim(operation)
}

pub fn operation_is_invite_third_party(operation: &Operation) -> bool {
    soland_domain::kinds::operation_is_invite_third_party(operation)
}

pub fn operation_is_realm_lifecycle(operation: &Operation) -> bool {
    soland_domain::kinds::operation_is_realm_lifecycle(operation)
}

pub fn payload_declares_minimal_metadata_realm(payload: &serde_json::Value) -> bool {
    soland_domain::kinds::payload_declares_minimal_metadata_realm(payload)
}

pub fn policy_bundle_aad_visibility_ceiling(
    payload: &serde_json::Value,
) -> Option<arkret_models_crypto::EncryptedEnvelopeAadVisibility> {
    soland_domain::kinds::policy_bundle_aad_visibility_ceiling(payload)
}

pub fn validate_join_policy_payload(join_policy: &Value) -> Result<(), &'static str> {
    soland_domain::reducer::validate_join_policy_payload(join_policy)
}

pub fn poll_id_from_content(content: &Value) -> Option<String> {
    soland_domain::reducer::poll_id_from_content(content)
}

pub fn inheritance_allowed_policies(payload: &Value) -> Vec<String> {
    soland_domain::reducer::inheritance_allowed_policies(payload)
}

pub fn message_redaction_target_ref(payload: &Value) -> Option<String> {
    soland_domain::reducer::message_redaction_target_ref(payload)
}

pub fn message_id_from_payload_or_event_id(payload: &Value, event_id: &str) -> String {
    soland_domain::reducer::message_id_from_payload_or_event_id(payload, event_id)
}
