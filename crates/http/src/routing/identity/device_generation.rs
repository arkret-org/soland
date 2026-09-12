mod confirmed;

use std::hash::{Hash as _, Hasher};
use std::sync::{Arc, OnceLock};

use arkret_identifiers::{RealmId, SealId};
pub use arkret_models_crypto::keys::DeviceGenerationStatus;
pub(crate) use confirmed::load_confirmed_device_history;
use serde_json::Value;
use soland_services::ServiceError;

use crate::state::AppState;

const DEVICE_GENERATION_ADMISSION_LOCK_SHARDS: usize = 1024;

static DEVICE_GENERATION_ADMISSION_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> =
    OnceLock::new();

pub fn device_generation_admission_lock(scope_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let locks = DEVICE_GENERATION_ADMISSION_LOCKS.get_or_init(|| {
        (0..DEVICE_GENERATION_ADMISSION_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    scope_id.hash(&mut hasher);
    locks[(hasher.finish() as usize) % DEVICE_GENERATION_ADMISSION_LOCK_SHARDS].clone()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceGenerationView {
    pub current_ref: u64,
    pub status: DeviceGenerationStatus,
}

pub async fn current_device_generation(
    state: &AppState,
    principal_id: &str,
) -> Result<Option<DeviceGenerationView>, ServiceError> {
    let principal_id =
        arkret_identifiers::DidCoreId::new(principal_id.to_owned()).map_err(|error| {
            ServiceError::SchemaViolation(format!("principal id is invalid: {error}"))
        })?;
    let station_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| ServiceError::Internal(format!("local Station id is invalid: {error}")))?;
    let account = arkret_wire::AccountId::new(principal_id, station_id);
    let history = load_confirmed_device_history(state, &account)
        .await
        .map_err(|error| {
            ServiceError::Conflict(format!("confirmed device history unavailable: {error}"))
        })?;
    if let Some(history) = &history {
        state
            .persistence()
            .install_confirmed_device_history(history)
            .await
            .map_err(|error| {
                ServiceError::Conflict(format!("confirmed device mirror unavailable: {error}"))
            })?;
    }
    Ok(history.map(|history| DeviceGenerationView {
        current_ref: history.current_generation().number(),
        status: DeviceGenerationStatus::Active,
    }))
}

/// Recover the device mirror independently of generic timeline progress. No
/// individual member of a mixed unit is published by this source-only rebuild.
pub(crate) async fn recover_confirmed_device_projection(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<(), String> {
    let Some(events) = state
        .projections()
        .confirmed_genesis_unit(realm_id)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(());
    };
    let Some(genesis) = events.first() else {
        return Err("confirmed genesis is empty".into());
    };
    let create: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&genesis.payload).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if create.object.purpose
        != arkret_models_collaboration::events_payloads::RealmPurpose::PrincipalControl
    {
        return Ok(());
    }
    let account = genesis
        .actor_id
        .as_account_id()
        .ok_or_else(|| "PCR genesis has no Account".to_owned())?;
    if account.station_id != state.service_core_id() {
        return Ok(());
    }
    let history = load_confirmed_device_history(state, account)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "confirmed PCR has no authenticated device history".to_owned())?;
    state
        .persistence()
        .install_confirmed_device_history(&history)
        .await
        .map_err(|e| e.to_string())
}

/// Resolve the exact accepted device authorization tuple used by every
/// revocation-sensitive durable write. The returned selector is derived from
/// accepted local state; it is never accepted from an authoring payload.
pub async fn active_device_revocation_gate_selector(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
) -> Result<soland_storage::DeviceRevocationGateSelector, ServiceError> {
    let principal_id =
        arkret_identifiers::DidCoreId::new(principal_id.to_owned()).map_err(|error| {
            ServiceError::SchemaViolation(format!("principal id is invalid: {error}"))
        })?;
    let station_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| ServiceError::Internal(format!("local Station id is invalid: {error}")))?;
    let device_id = arkret_identifiers::DeviceId::new(device_id.to_owned())
        .map_err(|error| ServiceError::SchemaViolation(format!("device id is invalid: {error}")))?;
    let generation = current_device_generation(state, principal_id.as_str())
        .await?
        .filter(|generation| generation.status == DeviceGenerationStatus::Active)
        .ok_or_else(|| ServiceError::Conflict("device generation is not active".to_owned()))?;
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: principal_id.to_string(),
            device_id: device_id.to_string(),
        })
        .await?
        .ok_or_else(|| ServiceError::NotFound("device authorization is unavailable".to_owned()))?;
    let Some((target_device_authorize_event_id, authorized_generation_ref)) =
        verified_device_authorization_binding(&device)?
    else {
        return Err(ServiceError::NotFound(
            "device authorization is not active".to_owned(),
        ));
    };
    let authorize_event = state
        .event_queries()
        .canonical_event(target_device_authorize_event_id.as_str())
        .await
        .map_err(|error| ServiceError::Internal(error.to_string()))?
        .ok_or_else(|| {
            ServiceError::Conflict("accepted device authorization Event is unavailable".to_owned())
        })?;
    let event_device_id = authorize_event
        .envelope
        .pointer("/payload/device_id")
        .and_then(Value::as_str);
    if !accepted_authorization_binds_authority_tuple(
        authorize_event.actor_id.as_str(),
        authorize_event.kind.as_str(),
        event_device_id,
        principal_id.as_str(),
        station_id.as_str(),
        device_id.as_str(),
    ) {
        return Err(ServiceError::Conflict(
            "accepted device authorization Event does not bind the current authority tuple"
                .to_owned(),
        ));
    }
    let target_device_generation_ref = generation.current_ref;
    if authorized_generation_ref != target_device_generation_ref {
        return Err(ServiceError::Conflict(
            "device authorization is outside the current generation".to_owned(),
        ));
    }
    Ok(soland_storage::DeviceRevocationGateSelector {
        principal_id,
        station_id,
        device_id: device_id.to_string(),
        target_device_authorize_event_id: target_device_authorize_event_id.to_string(),
        target_device_generation_ref,
    })
}

/// `device-lifecycle.md` — the accepted `ak.device.authorize` Event a derived
/// selector points at MUST re-verify the whole local account-authority tuple
/// verbatim before the selector may be used: the same principal actor, the
/// `ak.device.authorize` kind, this exact Station, and the same
/// device. The same all-or-nothing re-check covers genesis, pairing and
/// re-anchor writers, because all three reach durable state only through this
/// selector. A selector is never partially trusted: one mismatched member is a
/// conflict, and the caller MUST NOT fall back to a placeholder Event id,
/// Station or device.
fn accepted_authorization_binds_authority_tuple(
    event_actor_id: &str,
    event_kind: &str,
    event_device_id: Option<&str>,
    principal_id: &str,
    station_id: &str,
    device_id: &str,
) -> bool {
    let expected_actor = arkret_identifiers::DidCoreId::new(principal_id.to_owned())
        .ok()
        .zip(arkret_identifiers::DidCoreId::new(station_id.to_owned()).ok())
        .map(|(principal_id, station_id)| {
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(principal_id, station_id))
        });
    expected_actor.is_some_and(|expected_actor| {
        serde_json::from_str::<arkret_wire::ActorId>(event_actor_id)
            .is_ok_and(|actor_id| actor_id == expected_actor)
    }) && event_kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
        && event_device_id == Some(device_id)
}

pub(crate) fn verified_device_authorization_binding(
    device: &soland_services::identity::DeviceIdentity,
) -> Result<Option<(arkret_identifiers::EventId, u64)>, ServiceError> {
    if device.verification_state != "verified" || device.revoked_at.is_some() {
        return Ok(None);
    }
    let target_device_authorize_event_id = device
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ServiceError::SchemaViolation(
                "device authorization omits its accepted Event id".to_owned(),
            )
        })?;
    let target_device_authorize_event_id = arkret_identifiers::EventId::new(
        target_device_authorize_event_id.to_owned(),
    )
    .map_err(|error| {
        ServiceError::SchemaViolation(format!("device authorization Event id is invalid: {error}"))
    })?;
    let authorized_generation_ref = device
        .payload
        .get("authorized_generation_ref")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ServiceError::SchemaViolation(
                "device authorization omits its generation binding".to_owned(),
            )
        })?;
    Ok(Some((
        target_device_authorize_event_id,
        authorized_generation_ref,
    )))
}

/// Return the unique confirmed head. Pending competing commands cannot erase
/// or rewind an already authenticated prefix.
pub async fn accepted_device_generation_seal_head(
    state: &AppState,
    principal_id: &str,
    realm_id: &RealmId,
) -> Result<Option<SealId>, ServiceError> {
    let principal = arkret_identifiers::DidCoreId::new(principal_id.to_owned())
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let account = arkret_wire::AccountId::new(principal, state.service_core_id().clone());
    let history = load_confirmed_device_history(state, &account)
        .await
        .map_err(|error| {
            ServiceError::Conflict(format!("confirmed device history unavailable: {error}"))
        })?;
    history
        .map(|history| {
            if history.realm_id() != realm_id {
                return Err(ServiceError::Conflict(
                    "device history belongs to another PCR".to_owned(),
                ));
            }
            Ok(history.confirmed_head().clone())
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    fn device(
        verification_state: &str,
        payload: Value,
    ) -> soland_services::identity::DeviceIdentity {
        soland_services::identity::DeviceIdentity {
            actor_id: "ak:did_core:webvh:z6mkfixture:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000030".to_owned(),
            display_name: None,
            verification_state: verification_state.to_owned(),
            payload,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn absent_authorization_and_malformed_verified_projection_are_distinct() {
        assert_eq!(
            verified_device_authorization_binding(&device("unverified", json!({}))).unwrap(),
            None
        );

        let malformed = verified_device_authorization_binding(&device(
            "verified",
            json!({"authorized_generation_ref": 1}),
        ));
        assert!(matches!(malformed, Err(ServiceError::SchemaViolation(_))));

        let malformed = verified_device_authorization_binding(&device(
            "verified",
            json!({
                "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
            }),
        ));
        assert!(matches!(malformed, Err(ServiceError::SchemaViolation(_))));
    }

    const TUPLE_PRINCIPAL: &str = "ak:did_core:webvh:z6mkfixture:alice.example";
    const TUPLE_STATION: &str = "ak:did_core:web:soland.example";
    const TUPLE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000030";

    fn binds_tuple(
        actor_id: &str,
        kind: &str,
        station_id: Option<&str>,
        device_id: Option<&str>,
    ) -> bool {
        let actor_id = station_id
            .and_then(|station_id| {
                arkret_identifiers::DidCoreId::new(actor_id.to_owned())
                    .ok()
                    .zip(arkret_identifiers::DidCoreId::new(station_id.to_owned()).ok())
            })
            .map(|(principal_id, station_id)| {
                arkret_wire::ActorId::account(arkret_wire::AccountId::new(principal_id, station_id))
                    .to_string()
            })
            .unwrap_or_default();
        accepted_authorization_binds_authority_tuple(
            &actor_id,
            kind,
            device_id,
            TUPLE_PRINCIPAL,
            TUPLE_STATION,
            TUPLE_DEVICE,
        )
    }

    /// The canonical positive: every member of the authority tuple matches.
    #[test]
    fn accepted_authorization_binds_the_exact_authority_tuple() {
        assert!(binds_tuple(
            TUPLE_PRINCIPAL,
            arkret_wire::EventKind::DeviceAuthorize.as_str(),
            Some(TUPLE_STATION),
            Some(TUPLE_DEVICE),
        ));
    }

    /// One mismatched member — actor, kind, Station or device — is
    /// enough to reject. Nothing is trusted partially, and a missing member is
    /// never treated as a wildcard.
    #[test]
    fn a_single_authority_tuple_mismatch_rejects_the_selector() {
        let authorize = arkret_wire::EventKind::DeviceAuthorize.as_str();
        assert!(!binds_tuple(
            "ak:did_core:webvh:z6mkfixture:mallory.example",
            authorize,
            Some(TUPLE_STATION),
            Some(TUPLE_DEVICE),
        ));
        assert!(!binds_tuple(
            TUPLE_PRINCIPAL,
            arkret_wire::event_kind_str::DEVICE_REANCHOR,
            Some(TUPLE_STATION),
            Some(TUPLE_DEVICE),
        ));
        assert!(!binds_tuple(
            TUPLE_PRINCIPAL,
            authorize,
            Some("ak:did_core:web:other-server.example"),
            Some(TUPLE_DEVICE),
        ));
        assert!(!binds_tuple(
            TUPLE_PRINCIPAL,
            authorize,
            None,
            Some(TUPLE_DEVICE)
        ));
        assert!(!binds_tuple(
            TUPLE_PRINCIPAL,
            authorize,
            Some(TUPLE_STATION),
            Some("ak:device:01904100-0000-7000-8000-000000000031"),
        ));
        assert!(!binds_tuple(
            TUPLE_PRINCIPAL,
            authorize,
            Some(TUPLE_STATION),
            None
        ));
    }

    /// The generation half of the same re-check: the projection's
    /// `authorized_generation_ref` is read back verbatim so the caller can
    /// compare it with the account's current active generation and reject an
    /// authorization that sits outside it.
    #[test]
    fn verified_projection_surfaces_the_authorized_generation_ref() {
        let binding = verified_device_authorization_binding(&device(
            "verified",
            json!({
                "device_authorize_event_id":
                    "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa",
                "authorized_generation_ref": 3
            }),
        ))
        .expect("well-formed verified projection")
        .expect("verified device carries a binding");
        assert_eq!(binding.1, 3);
    }
}
