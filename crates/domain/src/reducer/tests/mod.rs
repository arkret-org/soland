use super::*;

mod agent_lifecycle;
mod call_state;
mod cells_realm;
mod circle_encryption;
mod circle_history;
mod container_realm_control;
mod invite_claim;
mod key_backup_active_series;
mod moderation;
mod pending_replay;
mod pin_rsvp_encryption;
mod pin_scope_safety;
mod read_cursor;
mod realm_key_share;
mod redaction_message;
mod space_container;
mod strand_morph;

pub(super) fn make_operation(object_kind: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(realm_id).unwrap(),
        object_kind,
        payload,
    )
}

/// The registry-derived cell writes a v1 receiver projects for this
/// `kind + payload`.
///
/// The Event wire carries no producer `effects[]`, so a reducer test may not
/// hand-write the writes it wants applied: it has to go through the same
/// `arkret_schema::project_registered_cell_writes` contract evaluator the
/// server uses, over a real signed-shape Event. `event_id` matters because
/// or_set add tags are the canonical dot `ak:event:<event_id>:<write_index>`.
pub(super) fn projected_cell_writes(
    object_kind: &str,
    realm_id: &str,
    event_id: &str,
    payload: &Value,
) -> Vec<arkret_wire::cba::ProjectedCellWrite> {
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let event = arkret_wire::Event::new_with_id_at(
        arkret_identifiers::EventId::new(event_id.to_owned()).unwrap(),
        object_kind,
        arkret_wire::event_envelope::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id).unwrap(),
        },
        arkret_identifiers::Did::new("did:web:reducer-test.example").unwrap(),
        0,
        arkret_identifiers::Hlc::new("000000000000-0000-00000000").unwrap(),
        payload.clone(),
        created_at,
    )
    .expect("event envelope");
    arkret_schema::project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
        .expect("registered cell contract must be evaluable")
}
