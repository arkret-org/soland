use super::*;

/// Authentication result for a delivered private Invite notification.
/// It is not an Event admission or a Realm authority position.
pub(in crate::routing) struct PrivateInviteEnvelope {
    pub(in crate::routing) event_id: EventId,
    pub(in crate::routing) actor: arkret_wire::ActorId,
    pub(in crate::routing) realm_id: RealmId,
    pub(in crate::routing) canonical_digest: String,
}

/// A peer-delivered Invite cannot enter the holder-private projection until
/// its historical producer key is proven at the accepted Event/Commit cut.
pub(in crate::routing) async fn validate_private_invite_envelope(
    _state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
) -> Result<PrivateInviteEnvelope, EventValidationError> {
    let event: arkret_wire::Event = serde_json::from_value(envelope.clone()).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            error.to_string(),
        )
    })?;
    let object = envelope.as_object().expect("typed Event is an object");
    if event.kind != arkret_wire::EventKind::InviteCreate
        || event.actor_id.signing_principal_id().as_str() != session.actor
        || !invite_create_actor_is_inviter(object, &session.actor)
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            "invite producer binding mismatch",
        ));
    }
    arkret_schema::validate_event_for_submit(&event).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            format!("private Invite Event violates the submit schema: {error}"),
        )
    })?;
    Err(event_validation_error(
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
        "private Invite needs historical producer proof at an accepted Event/Commit cut",
    ))
}
