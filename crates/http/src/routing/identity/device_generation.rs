mod confirmed;

use std::hash::{Hash as _, Hasher};
use std::sync::{Arc, OnceLock};

use arkret_identifiers::{DeviceId, EventId, RealmId, SealId};
pub use arkret_models_crypto::keys::DeviceGenerationStatus;
pub(crate) use confirmed::{candidate_device_control_projection, load_confirmed_device_history};
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct AcceptedBootstrapDeviceBinding {
    device_id: DeviceId,
    authorization_event_id: EventId,
}

/// Resolve the one pre-Seal device authority current-v1 permits.
///
/// Human PCR genesis is accepted as a closed two-Event unit and its canonical
/// receipt, Account/PCR slot and principal-resolution index are committed in
/// the same transaction. `account-lifecycle.md` §2.1.2 step 7 makes that exact
/// acceptance initialize device generation 1 as active so the Account
/// Authority can run the mandatory gate before issuing the first grant. No
/// re-anchor or ordinary unsealed Event is admitted by this path.
async fn accepted_bootstrap_device_binding(
    state: &AppState,
    account: &arkret_wire::AccountId,
) -> Result<Option<AcceptedBootstrapDeviceBinding>, ServiceError> {
    let Some(binding) = state
        .persistence()
        .principal_resolution_by_account_id(account)
        .await?
    else {
        return Ok(None);
    };
    let genesis = &binding.genesis_event;
    if binding.account_id != *account
        || genesis.actor_id != arkret_wire::ActorId::account(account.clone())
        || genesis.realm_id != binding.pcr_realm_id
        || genesis.kind != arkret_wire::EventKind::RealmCreate
    {
        return Err(ServiceError::Conflict(
            "accepted PCR bootstrap binding is internally inconsistent".to_owned(),
        ));
    }
    let actor = arkret_wire::ActorId::account(account.clone()).to_string();
    let candidates = state
        .event_queries()
        .accepted_events_for_actor(&actor)
        .await?
        .into_iter()
        .filter(|record| {
            record.kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
                && record.realm_id.as_deref() == Some(binding.pcr_realm_id.as_str())
                && record
                    .envelope
                    .get("prev_refs")
                    .and_then(Value::as_array)
                    .is_some_and(|refs| {
                        refs.len() == 1 && refs[0].as_str() == Some(genesis.event_id.as_str())
                    })
                && record
                    .envelope
                    .pointer("/payload/authorization_binding_kind")
                    .and_then(Value::as_str)
                    == Some("registration_anchor")
        })
        .collect::<Vec<_>>();
    let [authorize] = candidates.as_slice() else {
        return Err(ServiceError::Conflict(
            "accepted PCR bootstrap does not have one founding authorization".to_owned(),
        ));
    };
    let device_id = authorize
        .envelope
        .pointer("/payload/device_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ServiceError::Conflict(
                "accepted PCR founding authorization omits its device".to_owned(),
            )
        })?;
    let device_id = DeviceId::new(device_id.to_owned()).map_err(|error| {
        ServiceError::Conflict(format!(
            "accepted PCR founding authorization device is invalid: {error}"
        ))
    })?;
    let authorization_event_id = EventId::new(authorize.event_id.clone()).map_err(|error| {
        ServiceError::Conflict(format!(
            "accepted PCR founding authorization Event id is invalid: {error}"
        ))
    })?;
    let genesis_event_id = EventId::new(genesis.event_id.clone()).map_err(|error| {
        ServiceError::Conflict(format!("accepted PCR genesis Event id is invalid: {error}"))
    })?;
    let genesis_commit = state
        .persistence()
        .committed_event(&genesis_event_id)
        .await?;
    let authorization_commit = state
        .persistence()
        .committed_event(&authorization_event_id)
        .await?;
    let commit_pair_matches = genesis_commit.as_ref().is_some_and(|record| {
        record.commit.realm_id == binding.pcr_realm_id
            && record.commit.event_ref == genesis_event_id
            && record.event.kind == arkret_wire::EventKind::RealmCreate
    }) && authorization_commit.as_ref().is_some_and(|record| {
        record.commit.realm_id == binding.pcr_realm_id
            && record.commit.event_ref == authorization_event_id
            && record.event.kind == arkret_wire::EventKind::DeviceAuthorize
    });
    if !commit_pair_matches {
        return Err(ServiceError::Conflict(
            "accepted PCR founding authorization has no matching durable RealmCommit pair"
                .to_owned(),
        ));
    }
    Ok(Some(AcceptedBootstrapDeviceBinding {
        device_id,
        authorization_event_id,
    }))
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
    if let Some(history) = history {
        return Ok(Some(DeviceGenerationView {
            current_ref: history.current_generation().number(),
            status: DeviceGenerationStatus::Active,
        }));
    }
    Ok(accepted_bootstrap_device_binding(state, &account)
        .await?
        .map(|_| DeviceGenerationView {
            current_ref: 1,
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
    let _history = load_confirmed_device_history(state, account)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "confirmed PCR has no authenticated device history".to_owned())?;
    Ok(())
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
    let account = arkret_wire::AccountId::new(principal_id.clone(), station_id.clone());
    let history = load_confirmed_device_history(state, &account)
        .await
        .map_err(|error| {
            ServiceError::Conflict(format!("confirmed device history unavailable: {error}"))
        })?;
    if let Some(history) = history {
        let authorization = history
            .authorization(&target_device_authorize_event_id)
            .filter(|authorization| history.is_currently_active(authorization))
            .ok_or_else(|| {
                ServiceError::Conflict(
                    "device mirror does not name an active confirmed authorization instance".into(),
                )
            })?;
        if authorization.device_id() != &device_id
            || authorization.authorized_generation_ref() != authorized_generation_ref
        {
            return Err(ServiceError::Conflict(
                "device mirror differs from the confirmed authorization instance".into(),
            ));
        }
    } else {
        let bootstrap = accepted_bootstrap_device_binding(state, &account)
            .await?
            .ok_or_else(|| {
                ServiceError::Conflict(
                    "device authorization has neither bootstrap nor confirmed history".into(),
                )
            })?;
        if bootstrap.device_id != device_id
            || bootstrap.authorization_event_id != target_device_authorize_event_id
            || authorized_generation_ref != 1
        {
            return Err(ServiceError::Conflict(
                "device mirror differs from the accepted PCR founding authorization".into(),
            ));
        }
    }
    let target_device_generation_ref = generation.current_ref;
    if authorized_generation_ref != target_device_generation_ref {
        return Err(ServiceError::Conflict(
            "device authorization is outside the current generation".to_owned(),
        ));
    }
    let accepted = state
        .persistence()
        .committed_event(&target_device_authorize_event_id)
        .await?
        .ok_or_else(|| {
            ServiceError::Conflict("device authorization has no accepted RealmCommit".to_owned())
        })?;
    Ok(soland_storage::DeviceRevocationGateSelector {
        principal_id,
        station_id,
        device_id: device_id.to_string(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: target_device_authorize_event_id,
            commit_id: accepted.commit.commit_id,
            stream_ref: accepted.commit.stream_ref,
            stream_position: accepted.commit.stream_position,
        },
    })
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
