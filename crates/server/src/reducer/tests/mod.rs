use super::*;

mod call_state;
mod cells_realm;
mod circle_encryption;
mod moderation;
mod pin_scope_safety;
mod redaction_message;
mod space_container;
mod strand_morph;

pub(super) fn make_operation(object_type: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        cokret_sdk::OperationId::new(format!("ck:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        cokret_sdk::RealmId::new(realm_id).unwrap(),
        object_type,
        payload,
    )
}
