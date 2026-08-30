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
mod poll;
mod read_cursor;
mod realm_authority;
mod redaction_message;
mod security_genesis;
mod space_container;
mod strand_morph;

pub(super) fn test_single_signer_notary(did: &str) -> arkret_wire::NotaryValue {
    let did = arkret_identifiers::Did::new(did.to_owned()).unwrap();
    let descriptor = arkret_wire::NotarySignerDescriptor {
        actor_id: arkret_wire::project_did_to_core_id(&did).unwrap(),
        verification_method: arkret_wire::DidUrl::new(format!("{did}#notary-key")).unwrap(),
        key_kind: arkret_wire::NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: arkret_wire::NotaryJoseAlgorithm::Ed25519,
        // RFC 8032 test-vector public key; the matching private fixture is
        // intentionally not needed by pure reducer tests.
        frozen_public_key_b64u: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_owned(),
        frozen_public_key_digest: arkret_identifiers::Hash::new(
            "sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9",
        )
        .unwrap(),
    };
    descriptor.validate().unwrap();
    arkret_wire::NotaryValue::single_signer(descriptor)
}

/// Materialize the registered genesis authority-root cell for a Realm.
///
/// `realm-and-space.md` section 2.5 makes this cell the sole source of Realm
/// owner authority, so a reducer test that needs an owner installs the cell
/// rather than a self-issued grant. The value is built through the SDK
/// projection type so a test can never seed a shape the create reducer would
/// not derive.
pub(super) fn install_realm_authority_root(
    state: &mut ProjectionState,
    realm_id: &str,
    controller_id: &str,
) {
    let value = arkret_policy::realm_bootstrap::RealmAuthorityRootValue::genesis(
        arkret_wire::ActorId::service(arkret_identifiers::DidCoreId::new(controller_id).unwrap()),
    );
    state.realm_null_subject_cells.insert(
        (
            realm_id.to_owned(),
            arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
        ),
        CellState::Value(serde_json::to_value(value).unwrap()),
    );
}

pub(super) fn make_operation(
    object_kind: impl AsRef<str>,
    realm_id: &str,
    mut payload: Value,
) -> Operation {
    // The production Event→Operation adapter injects the accepted event_id.
    // Unit tests commonly construct only the create object's typed id, so
    // mirror that adapter by retyping the same complete event token when the id-kind registry
    // declares the object Event-derived.
    let derived_event_id = payload
        .get("object")
        .and_then(Value::as_object)
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        .and_then(|object_id| object_id.rsplit_once(':'))
        .and_then(|(kind, event_token)| {
            let prefix = format!("{kind}:");
            arkret_identifiers::EVENT_DERIVED_ID_KIND_PREFIXES
                .contains(&prefix.as_str())
                .then(|| format!("ak:event:{event_token}"))
        });
    if payload.get("event_id").is_none()
        && let Some(event_id) = derived_event_id
    {
        payload
            .as_object_mut()
            .expect("operation payload object")
            .insert("event_id".to_owned(), Value::String(event_id));
    }
    arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(realm_id).unwrap(),
        object_kind.as_ref(),
        payload,
    )
}

/// The registry-derived cell writes a v1 receiver projects for this
/// `kind + payload`, plus the Event id they are bound to.
///
/// The Event wire carries no producer `effects[]`, so a reducer test may not
/// hand-write the writes it wants applied: it has to go through the same
/// `arkret_schema::project_registered_cell_writes` contract evaluator the
/// server uses, over a real signed-shape Event.
///
/// The id is an output, not an input. An Event id is the digest of the Event's
/// own content, so no caller can choose one; a test that pinned an id would be
/// asserting against an identity the content never produced. It is returned
/// because it is observable in the writes — or_set add tags are the canonical
/// dot `ak:event:<event_id>:<write_index>` — and because Event-derived object
/// ids retype this exact token.
///
/// `actor_seq` is the honest way to make two otherwise identical Events
/// distinct. Same kind, Realm, payload and seq is the *same* Event and
/// therefore the same id; a test that needs siblings varies the seq.
pub(super) fn projected_cell_writes_at_seq(
    object_kind: impl AsRef<str>,
    realm_id: &str,
    actor_seq: u64,
    payload: &Value,
) -> (
    arkret_identifiers::EventId,
    Vec<arkret_wire::cba::ProjectedCellWrite>,
) {
    let actor_id = arkret_wire::project_did_to_core_id(
        &arkret_identifiers::Did::new("did:web:reducer-test.example").unwrap(),
    )
    .unwrap();
    projected_cell_writes_for_actor(object_kind, realm_id, actor_seq, payload, actor_id)
}

pub(super) fn projected_cell_writes_for_actor(
    object_kind: impl AsRef<str>,
    realm_id: &str,
    actor_seq: u64,
    payload: &Value,
    actor_id: arkret_identifiers::DidCoreId,
) -> (
    arkret_identifiers::EventId,
    Vec<arkret_wire::cba::ProjectedCellWrite>,
) {
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let event = arkret_wire::test_support::raw_event_at(
        object_kind.as_ref(),
        arkret_wire::event_envelope::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id).unwrap(),
        },
        actor_id.clone(),
        actor_id,
        actor_seq,
        arkret_identifiers::Hlc::new("000000000000-0000-00000000").unwrap(),
        payload.clone(),
        created_at,
    )
    .expect("event envelope");
    let event_id = event.event_id.clone();
    let writes = arkret_schema::project_registered_cell_writes(
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("registered cell contract must be evaluable");
    (event_id, writes)
}

pub(super) fn projected_cell_writes(
    object_kind: impl AsRef<str>,
    realm_id: &str,
    payload: &Value,
) -> (
    arkret_identifiers::EventId,
    Vec<arkret_wire::cba::ProjectedCellWrite>,
) {
    projected_cell_writes_at_seq(object_kind, realm_id, 0, payload)
}
