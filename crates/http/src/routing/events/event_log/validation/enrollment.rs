use arkret_event_draft::EventPayloadExt as _;

use super::super::*;

/// Enforce the closed device-authorization source model. Root-anchored
/// authorizations exist only inside the exact genesis/re-anchor unit passed by
/// the batch validator. Pairing requires a current, accepted authorizing
/// device; DID service/delegation state is never consulted.
pub(crate) async fn validate_device_authorization_binding(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<(), EventValidationError> {
    use arkret_models_collaboration::events_payloads::device_identity::{
        DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    };

    let event = serde_json::from_value::<arkret_wire::Event>(Value::Object(object.clone()))
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid typed ak.device.authorize Event: {error}"),
            )
        })?;
    let payload: DeviceAuthorizePayload = event
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid ak.device.authorize payload: {error}"),
            )
        })?;
    if payload.principal_id.as_str() != actor_id {
        return Err(device_authorization_invalid(
            "device authorization principal does not match actor_id",
        ));
    }
    match (&payload.authorization_binding_kind, &payload.authorized_by) {
        (
            DeviceAuthorizationBindingKind::RegistrationAnchor
            | DeviceAuthorizationBindingKind::PcrRecovery,
            DeviceOrPrincipalRef::Principal(root),
        ) => {
            let staged = realm_bootstrap_contexts.iter().any(|context| {
                context.actor_id == actor_id
                    && context.identity_anchor_event_id.is_some()
                    && context
                        .identity_anchor_candidate_device
                        .as_ref()
                        .is_some_and(|candidate| {
                            candidate.principal_id == payload.principal_id
                                && candidate.device_id == payload.device_id
                                && candidate.device_public_key_did == payload.device_public_key_did
                                && candidate.hpke_key == payload.hpke_key
                                && candidate.algorithms == payload.algorithms
                                && candidate.authorization_binding_kind
                                    == payload.authorization_binding_kind
                        })
            });
            if root.as_str() != actor_id || !staged {
                return Err(device_authorization_invalid(
                    "root_anchored authorization is outside a closed identity-anchor unit",
                ));
            }
        }
        (
            DeviceAuthorizationBindingKind::AcceptedDevice,
            DeviceOrPrincipalRef::DeviceId(authorizer),
        ) => {
            let proof_methods = event
                .proofs
                .iter()
                .filter_map(arkret_wire::EventProof::as_producer)
                .map(|proof| proof.verification_method.as_str())
                .collect::<Vec<_>>();
            if proof_methods.is_empty()
                || proof_methods.iter().any(|method| {
                    crate::jws_verify::validate_verification_method_controller(actor_id, method)
                        .is_err()
                        || method.rsplit_once('#').map(|(_, fragment)| fragment)
                            != Some(authorizer.as_str())
                })
            {
                return Err(device_authorization_invalid(
                    "accepted_device authorization must be Event-signed by the declared authorizing device",
                ));
            }
            let record = state
                .identities()
                .find_device(soland_services::identity::FindDeviceQuery {
                    actor_id: actor_id.to_owned(),
                    device_id: authorizer.to_string(),
                })
                .await
                .map_err(|error| {
                    event_validation_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "failed_precondition",
                        format!("authorizing device lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    device_authorization_invalid("authorizing device is not accepted")
                })?;
            let current = crate::routing::identity::device_generation::current_device_generation(
                state, actor_id,
            )
            .await
            .map_err(|error| {
                event_validation_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "failed_precondition",
                    format!("device generation state unavailable: {error}"),
                )
            })?
            .ok_or_else(|| device_authorization_invalid("device generation is unavailable"))?;
            if record.verification_state != "verified"
                || record.revoked_at.is_some()
                || record
                    .payload
                    .get("authorized_generation_ref")
                    .and_then(Value::as_u64)
                    != Some(current.current_ref)
            {
                return Err(device_authorization_invalid(
                    "authorizing device is not active at the current generation",
                ));
            }
        }
        _ => {
            return Err(device_authorization_invalid(
                "device authorization binding is not a closed v1 variant",
            ));
        }
    }
    crate::routing::identity::device_signing::validate_device_authorize_binding(state, &payload)
        .map_err(device_authorization_invalid)
}

fn device_authorization_invalid(message: impl Into<String>) -> EventValidationError {
    event_validation_error(StatusCode::FORBIDDEN, "failed_precondition", message)
}
