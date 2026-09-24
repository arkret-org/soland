use super::*;

/// Authentication result for a delivered private Invite notification.
/// It is not an Event admission or a Realm authority position.
pub(in crate::routing) struct PrivateInviteEnvelope {
    pub(in crate::routing) event_id: EventId,
    pub(in crate::routing) actor: arkret_wire::ActorId,
    pub(in crate::routing) realm_id: RealmId,
    pub(in crate::routing) canonical_digest: String,
}

/// Shape and inviter binding of a peer-delivered Invite (invite-addressing §7
/// step 4). The producer proof and the governance `invite_commit` are verified
/// by the caller under the non-governance receiver rule of federation §3.
pub(in crate::routing) async fn validate_private_invite_envelope(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
) -> Result<PrivateInviteEnvelope, EventValidationError> {
    let event: arkret_wire::Event = serde_json::from_value(envelope.clone()).map_err(|error| {
        event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
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
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            "invite producer binding mismatch",
        ));
    }
    arkret_schema::validate_event_for_submit(&event).map_err(|error| {
        event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            format!("private Invite Event violates the submit schema: {error}"),
        )
    })?;
    let digest_suite = state
        .projections()
        .realm_digest_suite(event.realm_id.as_str());
    let canonical_digest = event
        .event_digest_with_digest_suite(digest_suite)
        .map_err(|error| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                error.to_string(),
            )
        })?;
    Ok(PrivateInviteEnvelope {
        event_id: event.event_id,
        actor: event.actor_id,
        realm_id: event.realm_id,
        canonical_digest,
    })
}
