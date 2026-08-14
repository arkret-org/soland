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
                                && candidate.device_public_key == payload.device_public_key
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
                    .and_then(Value::as_str)
                    != Some(current.current_ref.as_str())
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

pub(super) async fn did_document_at(
    state: &AppState,
    did: &str,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, String> {
    let typed_did =
        arkret_identifiers::DidFullId::new(did.to_owned()).map_err(|error| error.to_string())?;
    if typed_did.method() == "key" {
        let document = crate::jws_verify::resolve_did_document_async(state, &typed_did).await?;
        return serde_json::to_value(document)
            .map_err(|error| format!("did:key document encode failed: {error}"));
    }
    let mut history = state
        .dids()
        .log_events(did)
        .await
        .map_err(|error| format!("DID history lookup failed: {error}"))?;
    history.sort_by_key(|entry| (entry.created_at, entry.seq));
    if let Some(document) = history.into_iter().rev().find_map(|entry| {
        (entry.created_at <= accepted_at)
            .then(|| entry.operation.get("state").cloned())
            .flatten()
    }) {
        return Ok(document);
    }
    let current = state
        .dids()
        .document(did)
        .await
        .map_err(|error| format!("DID document lookup failed: {error}"))?;
    if let Some(current) = current
        && current.updated_at <= accepted_at
    {
        return Ok(current.did_document);
    }
    if typed_did.method() == "webvh" {
        return resolve_remote_webvh_document_at(state, &typed_did, accepted_at).await;
    }
    Err("DID document history is unavailable at authorization accepted_at".to_owned())
}

async fn resolve_remote_webvh_document_at(
    state: &AppState,
    did: &arkret_identifiers::DidFullId,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, String> {
    let verified = resolve_remote_webvh_history(state, did).await?;
    webvh_document_at(&verified, accepted_at).ok_or_else(|| {
        "DID document history is unavailable at authorization accepted_at".to_owned()
    })
}

async fn resolve_remote_webvh_history(
    state: &AppState,
    did: &arkret_identifiers::DidFullId,
) -> Result<arkret_identity::VerifiedDidWebvhLog, String> {
    let raw_url = remote_webvh_history_url(state, did)?;
    let mut url = reqwest::Url::parse(&raw_url)
        .map_err(|error| format!("did:webvh history URL is invalid: {error}"))?;
    if state.config().development_mode
        && url
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback())
    {
        url.set_scheme("http")
            .map_err(|()| "did:webvh loopback history URL scheme is invalid".to_owned())?;
    }
    let request_timeout = std::time::Duration::from_secs(10);
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        url.as_str(),
        "did:webvh accepted-at history",
        state.config().development_mode,
        request_timeout,
    )?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("did:webvh history fetch failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "did:webvh history fetch returned HTTP {}",
            response.status()
        ));
    }
    let max_bytes = arkret_identity::DID_WEB_MAX_DOCUMENT_BYTES.saturating_mul(32);
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err("did:webvh history exceeds maximum size".to_owned());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("did:webvh history body read failed: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err("did:webvh history exceeds maximum size".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    arkret_identity::verify_did_webvh_v1_chain_bytes(did, &body)
        .map_err(|error| format!("did:webvh history verification failed: {error}"))
}

fn remote_webvh_history_url(
    state: &AppState,
    did: &arkret_identifiers::DidFullId,
) -> Result<String, String> {
    if let Ok(url) = arkret_identity::DidWebvhResolver::log_url(did) {
        return Ok(url);
    }
    if state.config().development_mode
        && let Some((_, host, port, path)) = arkret_identity::did_webvh_parts(did)
        && host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
    {
        let authority = port.map_or(host.clone(), |port| format!("{host}:{port}"));
        return if path.is_empty() {
            Ok(format!("https://{authority}/.well-known/did.jsonl"))
        } else {
            Ok(format!("https://{authority}/{}/did.jsonl", path.join("/")))
        };
    }
    Err("did:webvh history URL is unavailable".to_owned())
}

fn webvh_document_at(
    history: &arkret_identity::VerifiedDidWebvhLog,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Option<Value> {
    history
        .entries
        .iter()
        .rev()
        .find(|entry| entry.version_time <= accepted_at)
        .map(|entry| entry.state.clone())
}

#[cfg(test)]
mod tests {
    use arkret_identity::{DidWebvhLogEntry, VerifiedDidWebvhLog};
    use serde_json::json;

    use super::webvh_document_at;

    #[test]
    fn webvh_history_selects_latest_state_not_after_accepted_at() {
        let first_time = "2026-07-25T01:00:00Z".parse().unwrap();
        let second_time = "2026-07-25T02:00:00Z".parse().unwrap();
        let history = VerifiedDidWebvhLog {
            raw_entries: Vec::new(),
            entries: vec![
                DidWebvhLogEntry {
                    version_id: "1-first".to_owned(),
                    version_time: first_time,
                    parameters: json!({}),
                    state: json!({"id": "did:webvh:zExample:example.test", "marker": "first"}),
                    proof: Vec::new(),
                },
                DidWebvhLogEntry {
                    version_id: "2-second".to_owned(),
                    version_time: second_time,
                    parameters: json!({}),
                    state: json!({"id": "did:webvh:zExample:example.test", "marker": "second"}),
                    proof: Vec::new(),
                },
            ],
            head_version_id: "2-second".to_owned(),
            head_state: json!({}),
            active_update_keys: Vec::new(),
        };

        let between = "2026-07-25T01:30:00Z".parse().unwrap();
        assert_eq!(
            webvh_document_at(&history, between)
                .and_then(|document| document.get("marker").cloned()),
            Some(json!("first"))
        );
        assert!(webvh_document_at(&history, "2026-07-25T00:59:59Z".parse().unwrap()).is_none());
    }
}
