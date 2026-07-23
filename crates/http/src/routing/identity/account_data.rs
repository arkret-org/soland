//! Actor-private account data protocol handlers.
//!
//! Protocol writes use `ak.account_data.set` actor-private events and
//! `ak.self.account.stream.subscribe` for sync/read. This module is mounted under
//! `/_arkret/self/account_data*`.
//!
//! Spec: `discovery/client-preferences.md` §2 (storage model) plus the per-key
//! sections (§3.1 Space tags, §3.5 blocklist, §3.6 contact remarks, §3.7 Space
//! remarks, §3.8 read-receipt preferences). The server treats `payload` as an
//! opaque encrypted blob; clients own canonical encoding, schema validation,
//! and (where applicable) encryption.

use arkret_core::{
    AccountDataDeleteOutcome, AccountDataEntry, AccountDataList, AccountDataReplaceRequestBody,
    Did, Event, EventId, Hlc, RealmId,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_application::identity::{
    AccountDataState, FindAgentControllerQuery, IdentityApplicationService,
};
use soland_http::error::{AppError, ErrorCode};

use super::{AuthArgs, now};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

const MAX_DATA_TYPE_LEN: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// AKP-0008 / AKP-0009 (spec head 37ce729) — controller-private account-data
/// types. Writers MUST be the controller principal (not their own agent
/// runtime, not an applet-bound ghost).
struct AccountDataTypeSpec {
    data_type: &'static str,
    /// When `true`, only the controller principal may write the entry.
    /// Agents / applets / service principals are rejected with
    /// `capability_denied` even if they hold a controller-scoped session.
    controller_private: bool,
}

const REGISTERED_ACCOUNT_DATA_TYPES: &[AccountDataTypeSpec] = &[
    AccountDataTypeSpec {
        data_type: "ak.agent.draft.v1",
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_core::ACCOUNT_DATA_TYPE_AGENT_SIDECAR_PROJECTION,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_core::ACCOUNT_DATA_TYPE_AGENT_SIDECAR_VIEW_STATE,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_core::ACCOUNT_DATA_TYPE_REMINDER,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_core::ACCOUNT_DATA_TYPE_SCHEDULED_SEND,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_core::ACCOUNT_DATA_TYPE_SNOOZE,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_core::ACCOUNT_DATA_TYPE_SAVED,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_core::ACCOUNT_DATA_TYPE_DRAFT,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_core::ACCOUNT_DATA_TYPE_FILE_TRANSFER,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_core::ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: "ak.account.blocklist",
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: "ak.dnd_schedule",
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: "ak.presence.preference",
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: "ak.presence.visibility",
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: "ak.push_rules",
        controller_private: true,
    },
];

fn registered_account_data_type(data_type: &str) -> Option<&'static AccountDataTypeSpec> {
    let canonical_type =
        crate::routing::account_data_encryption::encrypted_account_data_prefix(data_type)
            .unwrap_or(data_type);
    REGISTERED_ACCOUNT_DATA_TYPES
        .iter()
        .find(|spec| spec.data_type == canonical_type)
}

fn validate_registered_account_data_key(data_type: &str) -> Result<(), AppError> {
    crate::routing::account_data_encryption::validate_encrypted_account_data_key(data_type)
        .map_err(|error| AppError::invalid_param(error.message()))
}

fn validate_private_account_data_content_for_actor(
    actor_id: &str,
    data_type: &str,
    content: &Value,
) -> Result<(), AppError> {
    crate::routing::account_data_encryption::validate_encrypted_account_data_value_for_actor(
        data_type,
        content,
        Some(actor_id),
    )
    .map_err(|error| AppError::invalid_param(error.message()))
}

#[cfg(test)]
fn validate_private_account_data_content(data_type: &str, content: &Value) -> Result<(), AppError> {
    crate::routing::account_data_encryption::validate_encrypted_account_data_value(
        data_type, content,
    )
    .map_err(|error| AppError::invalid_param(error.message()))
}

pub(super) fn router() -> Router {
    Router::with_path("account_data")
        .get(list_account_data)
        .push(
            Router::with_path("{data_type}")
                .get(get_account_data)
                .put(put_account_data)
                .delete(delete_account_data),
        )
}

fn validate_data_type(data_type: &str) -> Result<(), AppError> {
    if data_type.is_empty() {
        return Err(AppError::invalid_param("data_type must not be empty"));
    }
    if data_type.len() > MAX_DATA_TYPE_LEN {
        return Err(AppError::invalid_param("data_type too long"));
    }
    // Keys are dot-delimited namespaces (`ak.contacts.realm.<realm_id>` etc.).
    // Reject control chars / whitespace / path separators to keep them URL- and
    // log-safe; everything else (including the `:` in `ak:space:<uuid>`) is
    // permitted so the canonical wire keys round-trip.
    if data_type.chars().any(|c| {
        c.is_control() || c.is_whitespace() || c == '/' || c == '\\' || c == '?' || c == '#'
    }) {
        return Err(AppError::invalid_param(
            "data_type contains forbidden character",
        ));
    }
    Ok(())
}

fn entry_from(record: AccountDataState) -> AccountDataEntry {
    AccountDataEntry {
        data_type: record.data_type,
        content: record.payload,
        updated_at: record.updated_at,
    }
}

async fn session_actor_is_agent_runtime(
    identity: &IdentityApplicationService,
    actor: &str,
) -> Result<bool, AppError> {
    identity
        .find_agent_controller(FindAgentControllerQuery {
            agent_id: actor.to_owned(),
        })
        .await
        .map(|controller| controller.is_some())
        .map_err(|error| AppError::internal(format!("agent principal lookup failed: {error}")))
}

async fn persist_account_data_event(
    state: &AppState,
    session: &soland_application::identity::SessionIdentityState,
    data_type: &str,
    content: Option<Value>,
) -> Result<(), AppError> {
    let service_event_lock = crate::routing::events::event_log::service_event_authoring_lock();
    let _service_event_guard = service_event_lock.lock().await;
    let service_actor = state.service_id().as_str();
    let realm_id =
        RealmId::new(soland_application::identity::principal_control_realm_for_did(&session.actor))
            .map_err(|error| AppError::internal(format!("account_data realm invalid: {error}")))?;
    let records = state
        .event_query_application()
        .canonical_events_for_realm_actor(realm_id.as_str(), service_actor)
        .await
        .map_err(|error| {
            AppError::internal(format!("account_data frontier lookup failed: {error}"))
        })?;
    let max_actor_seq = records.iter().map(|record| record.actor_seq).max();
    let actor_seq = max_actor_seq
        .map(|value| {
            value.checked_add(1).ok_or_else(|| {
                AppError::new(
                    ErrorCode::FrontierSequenceExhausted,
                    "account_data actor sequence is exhausted",
                )
                .with_status(StatusCode::CONFLICT)
            })
        })
        .transpose()?
        .unwrap_or(0);
    let created_at = now();
    let mut payload = json!({
        "owner": session.actor,
        "key": data_type,
        "updated_at": arkret_canonical::format_timestamp_canonical(created_at),
    });
    if let Some(content) = content {
        payload["body"] = content;
    } else {
        payload["tombstone"] = Value::Bool(true);
    }
    let service_did = Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?;
    let mut event = Event::new_with_id_at(
        EventId::new(arkret_core::new_prefixed_uuid7("ak:event:")).map_err(|error| {
            AppError::internal(format!("account_data Event id invalid: {error}"))
        })?,
        arkret_wire::events::EventKind::ACCOUNT_DATA_SET,
        realm_id.clone(),
        service_did.clone(),
        actor_seq,
        Hlc::new(state.hlc().now())
            .map_err(|error| AppError::internal(format!("account_data HLC invalid: {error}")))?,
        payload,
        created_at,
    )
    .map_err(|error| AppError::internal(format!("account_data Event build failed: {error}")))?;
    if let Some(max_actor_seq) = max_actor_seq {
        event.prev_refs = records
            .iter()
            .filter(|record| record.actor_seq == max_actor_seq)
            .map(|record| {
                EventId::new(record.event_id.clone()).map_err(|error| {
                    AppError::internal(format!("account_data predecessor invalid: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        event
            .prev_refs
            .sort_by(|left, right| left.as_str().cmp(right.as_str()));
        event.prev_refs.dedup();
    }
    let verification_method = format!("{}#notary-key", state.service_id());
    let signer = arkret_signatures::Ed25519MoveSigner::new(
        state.notary_signing_key().as_ref().clone(),
        service_did,
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .map_err(|error| AppError::internal(format!("account_data Event signing failed: {error}")))?;
    let mut service_session = session.clone();
    service_session.actor = state.service_id().clone();
    let envelope = serde_json::to_value(event).map_err(|error| {
        AppError::internal(format!("account_data Event serialize failed: {error}"))
    })?;
    crate::routing::events::event_log::submit_account_data_event_value(
        state,
        &service_session,
        envelope,
        realm_id.as_str(),
        &session.actor,
        data_type,
    )
    .await
    .map_err(|error| {
        AppError::new(
            soland_http::error::ErrorCode::InvalidParam,
            format!("account_data Event admission failed: {}", error.message),
        )
        .with_status(error.status)
        .with_wire_code(error.code)
    })?;
    Ok(())
}

#[endpoint(
    operation_id = "ak.self.account_data.resource.replace",
    tags("account_data"),
    summary = "Upsert an actor-private account_data entry",
    status_codes(200, 201, 400, 401, 413, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.resource.replace"))]
async fn put_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    data_type: PathParam<String>,
    body: JsonBody<AccountDataReplaceRequestBody>,
) -> JsonResult<AccountDataEntry> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let data_type = data_type.into_inner();
    validate_data_type(&data_type)?;
    validate_registered_account_data_key(&data_type)?;

    // AKP-0008 / AKP-0009: registered personal-agent account-data types are
    // controller-private; native agent principals cannot write them directly.
    if let Some(spec) = registered_account_data_type(&data_type)
        && spec.controller_private
        && session_actor_is_agent_runtime(state.identity_application(), &session.actor).await?
    {
        return Err(AppError::capability_denied(format!(
            "{} is controller-private; agent runtimes cannot write it",
            spec.data_type
        )));
    }

    let body = body.into_inner();
    validate_private_account_data_content_for_actor(&session.actor, &data_type, &body.content)?;
    // Server-side guard against runaway payloads. Canonical serialisation is
    // the client's job; we just cap the wire size to keep one bad client from
    // filling the row with megabytes of base64.
    if serde_json::to_vec(&body.content)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
        > MAX_PAYLOAD_BYTES
    {
        return Err(AppError::new(
            soland_http::error::ErrorCode::PayloadTooLarge,
            "account_data payload exceeds 64 KiB",
        ));
    }

    let existed = state
        .account_data_application()
        .entry(&session.actor, &data_type)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some();

    persist_account_data_event(state, &session, &data_type, Some(body.content)).await?;
    let record = state
        .account_data_application()
        .entry(&session.actor, &data_type)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("account_data Event projection is missing"))?;

    super::append_audit_log(
        state,
        Some(&session.actor),
        "account_data.set",
        serde_json::json!({"data_type": data_type}),
        "accepted",
    )
    .await;
    if !existed {
        res.status_code(StatusCode::CREATED);
    }
    json_ok(entry_from(record))
}

#[endpoint(
    operation_id = "ak.self.account_data.resource.get",
    tags("account_data"),
    summary = "Fetch a single account_data entry by data_type"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.resource.get"))]
async fn get_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    data_type: PathParam<String>,
) -> JsonResult<AccountDataEntry> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let data_type = data_type.into_inner();
    validate_data_type(&data_type)?;
    validate_registered_account_data_key(&data_type)?;

    match state
        .account_data_application()
        .entry(&session.actor, &data_type)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(record) => json_ok(entry_from(record)),
        None => Err(AppError::not_found("not found")),
    }
}

#[endpoint(
    operation_id = "ak.self.account_data.query.list",
    tags("account_data"),
    summary = "List every account_data entry owned by the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.query.list"))]
async fn list_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountDataList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let entries = state
        .account_data_application()
        .entries_for_actor(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .into_iter()
        .map(entry_from)
        .collect();
    json_ok(AccountDataList { entries })
}

#[endpoint(
    operation_id = "ak.self.account_data.resource.delete",
    tags("account_data"),
    summary = "Delete an account_data entry"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.resource.delete"))]
async fn delete_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    data_type: PathParam<String>,
) -> JsonResult<AccountDataDeleteOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let data_type = data_type.into_inner();
    validate_data_type(&data_type)?;
    validate_registered_account_data_key(&data_type)?;

    persist_account_data_event(state, &session, &data_type, None).await?;

    super::append_audit_log(
        state,
        Some(&session.actor),
        "account_data.delete",
        serde_json::json!({"data_type": data_type}),
        "accepted",
    )
    .await;
    json_ok(AccountDataDeleteOutcome {
        ok: true,
        data_type,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use serde_json::{Value, json};
    use soland_application::ApplicationResult;
    use soland_application::identity::{
        AccountIdentity, AccountLifecycleState, AccountLocalpartState, AccountLookupPort,
        AccountProfileState, AgentController, AgentDirectoryPort, DeviceDirectoryPort,
        DeviceIdentity, SaveDeviceCommand,
    };

    use super::*;

    struct NoAccounts;
    struct NoDevices;
    struct AgentClassifier;

    #[async_trait]
    impl AccountLookupPort for NoAccounts {
        async fn find_account_by_actor(
            &self,
            _actor_id: &str,
        ) -> ApplicationResult<Option<AccountIdentity>> {
            Ok(None)
        }

        async fn register_account(
            &self,
            _command: soland_application::identity::RegisterAccountCommand,
        ) -> ApplicationResult<()> {
            Ok(())
        }

        async fn account(&self, _actor_id: &str) -> ApplicationResult<Option<AccountProfileState>> {
            Ok(None)
        }

        async fn accounts(&self) -> ApplicationResult<Vec<AccountProfileState>> {
            Ok(Vec::new())
        }

        async fn save_account(&self, _account: AccountProfileState) -> ApplicationResult<()> {
            Ok(())
        }

        async fn delete_account(&self, _actor_id: &str) -> ApplicationResult<()> {
            Ok(())
        }

        async fn account_localparts(
            &self,
            _actor_id: &str,
        ) -> ApplicationResult<Vec<AccountLocalpartState>> {
            Ok(Vec::new())
        }

        async fn localpart_owner(
            &self,
            _localpart: &str,
        ) -> ApplicationResult<Option<AccountLocalpartState>> {
            Ok(None)
        }

        async fn add_localpart(
            &self,
            _actor_id: &str,
            _localpart: &str,
            _primary: bool,
        ) -> ApplicationResult<AccountLocalpartState> {
            unreachable!("NoAccounts mock: add_localpart is not exercised by these tests")
        }

        async fn set_primary_localpart(
            &self,
            _actor_id: &str,
            _localpart: &str,
        ) -> ApplicationResult<AccountLocalpartState> {
            unreachable!("NoAccounts mock: set_primary_localpart is not exercised by these tests")
        }

        async fn remove_localpart(
            &self,
            _actor_id: &str,
            _localpart: &str,
        ) -> ApplicationResult<()> {
            Ok(())
        }

        async fn clear_localparts(&self, _actor_id: &str) -> ApplicationResult<()> {
            Ok(())
        }

        async fn record_handle_release(
            &self,
            _localpart: &str,
            _released_at: DateTime<Utc>,
        ) -> ApplicationResult<()> {
            Ok(())
        }

        async fn save_account_lifecycle(
            &self,
            _actor_id: &str,
            _lifecycle: AccountLifecycleState,
        ) -> ApplicationResult<()> {
            Ok(())
        }

        async fn delete_account_lifecycle(&self, _actor_id: &str) -> ApplicationResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl DeviceDirectoryPort for NoDevices {
        async fn list_active_device_actors(&self) -> ApplicationResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn devices(&self) -> ApplicationResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }

        async fn find_device(
            &self,
            _actor_id: &str,
            _device_id: &str,
        ) -> ApplicationResult<Option<DeviceIdentity>> {
            Ok(None)
        }

        async fn save_device(&self, _command: SaveDeviceCommand) -> ApplicationResult<()> {
            Ok(())
        }

        async fn save_device_if_absent(&self, _device: DeviceIdentity) -> ApplicationResult<bool> {
            Ok(true)
        }

        async fn devices_for_actor(
            &self,
            _actor_id: &str,
        ) -> ApplicationResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl AgentDirectoryPort for AgentClassifier {
        async fn find_agent_controller(
            &self,
            agent_id: &str,
        ) -> ApplicationResult<Option<AgentController>> {
            Ok(
                (agent_id == "did:web:agent.alice.example").then(|| AgentController {
                    controller_id: "did:web:alice.example".to_owned(),
                }),
            )
        }
    }

    fn encrypted_envelope(data_type: &str) -> Value {
        serde_json::to_value(
            arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
                &[7u8; 32],
                "did:web:alice.example",
                data_type,
                &json!({"private": true}),
                [9u8; 24],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn private_account_data_key_patterns_are_validated() {
        assert!(
            validate_registered_account_data_key(
                "ak.scheduled_send.v1:ak:message:01904100-0000-7000-8000-000000000001"
            )
            .is_ok()
        );
        assert!(
            validate_registered_account_data_key(
                "ak.file_transfer.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            )
            .is_ok()
        );
        let err = validate_registered_account_data_key(
            "ak.draft.v1:message:ak:message:01904100-0000-7000-8000-000000000001:main",
        )
        .unwrap_err();
        assert!(err.to_string().contains("registered private key pattern"));
    }

    #[test]
    fn private_account_data_requires_encrypted_content() {
        let key = "ak.saved.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        assert!(
            validate_private_account_data_content(
                key,
                &json!({"encrypted_payload": encrypted_envelope(key)}),
            )
            .is_ok()
        );
        assert!(
            validate_private_account_data_content(
                "ak.account.blocklist",
                &json!({"encrypted_payload": encrypted_envelope("ak.account.blocklist")}),
            )
            .is_ok()
        );
        assert!(
            validate_private_account_data_content(
                "ak.push_rules",
                &json!({"encrypted_payload": encrypted_envelope("ak.push_rules")}),
            )
            .is_ok()
        );
        assert!(
            validate_private_account_data_content(
                "ak.presence.preference",
                &json!({"encrypted_payload": encrypted_envelope("ak.presence.preference")}),
            )
            .is_ok()
        );
        assert!(validate_private_account_data_content(key, &json!({"tombstone": true})).is_ok());
        let err =
            validate_private_account_data_content("ak.dnd_schedule", &json!({"enabled": true}))
                .unwrap_err();
        assert!(err.to_string().contains("encrypted"));
        let err = validate_private_account_data_content(
            "ak.presence.preference",
            &json!({"manual_state": "dnd", "status_message": "In a meeting"}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("encrypted"));
        let err = validate_private_account_data_content(
            "ak.account.blocklist",
            &json!({"entries": [{"target": "did:web:bob.example"}]}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("encrypted"));
        let err = validate_private_account_data_content(
            key,
            &json!({"body": {"collection_title": "Leaks"}}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("plaintext"));

        let transfer_key = "ak.file_transfer.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = validate_private_account_data_content(
            transfer_key,
            &json!({"filename": "private.pdf", "encrypted_payload": encrypted_envelope(key)}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("plaintext"));
    }

    #[tokio::test]
    async fn controller_private_writer_classifier_uses_agent_principal_projection() {
        let identity = IdentityApplicationService::new(
            Arc::new(NoAccounts),
            Arc::new(NoDevices),
            Arc::new(AgentClassifier),
        );
        let agent_id = "did:web:agent.alice.example";

        assert!(
            session_actor_is_agent_runtime(&identity, agent_id)
                .await
                .unwrap()
        );
        assert!(
            !session_actor_is_agent_runtime(&identity, "did:web:alice.example")
                .await
                .unwrap()
        );
    }
}
