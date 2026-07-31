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

use arkret_identifiers::{Did, EventId, Hlc, RealmId};
use arkret_models_identity::account::{
    AccountDataDeleteOutcome, AccountDataList, AccountDataReplaceRequestBody, AccountDataRow,
};
use arkret_wire::Event;
use salvo::http::StatusCode;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_services::identity::{AccountDataState, FindAgentControllerQuery, IdentityService};

use super::{AuthArgs, now};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

const MAX_ACCOUNT_DATA_KEY_BYTES: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// AKP-0008 / AKP-0009 (spec head 37ce729) — controller-private account-data
/// types. Writers MUST be the controller principal (not their own agent
/// runtime, not an applet-bound ghost).
struct AccountDataKeySpec {
    account_data_key: &'static str,
    /// When `true`, only the controller principal may write the entry.
    /// Agents / applets / service principals are rejected with
    /// `capability_denied` even if they hold a controller-scoped session.
    controller_private: bool,
}

const REGISTERED_ACCOUNT_DATA_KEY_PATTERNS: &[AccountDataKeySpec] = &[
    AccountDataKeySpec {
        account_data_key: "ak.agent.draft.v1",
        controller_private: true,
    },
    // `ak.agent.sidecar_projection.v1` was removed from the account-data
    // registry on 2026-07-23: the exchange projection is a controller-device
    // local Event-fold cache and never an account-data surface
    // (zh/models/sidecar.md §7.2.4).
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::AGENT_SIDECAR_VIEW_STATE_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::REMINDERS_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::SCHEDULED_SEND_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::SNOOZE_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::SAVED_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::DRAFT_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::FILE_TRANSFER_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::SEARCH_INDEX_MANIFEST_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: "ak.account.blocklist",
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: "ak.dnd_schedule",
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: "ak.presence.preference",
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: "ak.presence.visibility",
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: "ak.push_rules",
        controller_private: true,
    },
];

fn registered_account_data_key_spec(account_data_key: &str) -> Option<&'static AccountDataKeySpec> {
    let canonical_type =
        crate::routing::account_data_encryption::encrypted_account_data_prefix(account_data_key)
            .unwrap_or(account_data_key);
    REGISTERED_ACCOUNT_DATA_KEY_PATTERNS
        .iter()
        .find(|spec| spec.account_data_key == canonical_type)
}

/// Controller-private account data never crosses to Agent runtime sessions:
/// neither over resource reads nor over the account stream, even when an
/// agent-granted session presents the controller as its actor
/// (zh/models/sidecar.md §7 / private-objects.md §4.2).
///
/// Retired prefixes (for example `ak.agent.sidecar_projection.v1`) also count
/// as controller-private: new writes are already hard-rejected by the key
/// validator, and treating legacy stored rows as controller-private keeps them
/// out of agent-session list results and the account stream (fail closed).
pub(crate) fn is_controller_private_account_data_key(account_data_key: &str) -> bool {
    crate::routing::account_data_encryption::is_retired_encrypted_account_data_key(account_data_key)
        || registered_account_data_key_spec(account_data_key)
            .is_some_and(|spec| spec.controller_private)
}

fn validate_registered_account_data_key(account_data_key: &str) -> Result<(), AppError> {
    crate::routing::account_data_encryption::validate_encrypted_account_data_key(account_data_key)
        .map_err(|error| AppError::invalid_param(error.message()))
}

fn validate_private_account_data_content_for_actor(
    actor_id: &str,
    account_data_key: &str,
    content: &Value,
) -> Result<(), AppError> {
    crate::routing::account_data_encryption::validate_encrypted_account_data_value_for_actor(
        account_data_key,
        content,
        Some(actor_id),
    )
    .map_err(|error| AppError::invalid_param(error.message()))
}

#[cfg(test)]
fn validate_private_account_data_content(
    account_data_key: &str,
    content: &Value,
) -> Result<(), AppError> {
    crate::routing::account_data_encryption::validate_encrypted_account_data_value(
        account_data_key,
        content,
    )
    .map_err(|error| AppError::invalid_param(error.message()))
}

pub(super) fn router() -> Router {
    Router::with_path("account_data")
        .get(list_account_data)
        .push(
            Router::with_path("{account_data_key}")
                .get(get_account_data)
                .put(put_account_data)
                .delete(delete_account_data),
        )
}

fn validate_account_data_key(account_data_key: &str) -> Result<(), AppError> {
    if account_data_key.is_empty() {
        return Err(AppError::invalid_param(
            "account_data_key must not be empty",
        ));
    }
    if account_data_key.len() > MAX_ACCOUNT_DATA_KEY_BYTES {
        return Err(AppError::invalid_param("account_data_key too long"));
    }
    // Keys are dot-delimited namespaces (`ak.contacts.realm.<realm_id>` etc.).
    // Reject control chars / whitespace / path separators to keep them URL- and
    // log-safe; everything else (including the `:` in `ak:space:<uuid>`) is
    // permitted so the canonical wire keys round-trip.
    if account_data_key.chars().any(|c| {
        c.is_control() || c.is_whitespace() || c == '/' || c == '\\' || c == '?' || c == '#'
    }) {
        return Err(AppError::invalid_param(
            "account_data_key contains forbidden character",
        ));
    }
    Ok(())
}

fn entry_from(record: AccountDataState) -> AccountDataRow {
    AccountDataRow {
        account_data_key: record.account_data_key,
        revision: record.revision,
        content: record.payload,
        updated_at: record.updated_at,
    }
}

fn account_data_conflict_details(
    account_data_key: &str,
    current: Option<&AccountDataState>,
) -> Value {
    let current_revision = current.map_or(0, |record| record.revision);
    let mut details = json!({
        "account_data_key": account_data_key,
        "current_revision": current_revision,
    });
    if let Some(record) = current.filter(|record| !record.tombstone) {
        details["current_entry"] = serde_json::to_value(entry_from(record.clone()))
            .expect("account data entry serialization cannot fail");
    }
    details
}

fn account_data_cas_conflict(
    account_data_key: &str,
    current: Option<&AccountDataState>,
) -> AppError {
    let details = account_data_conflict_details(account_data_key, current);
    let mut error = AppError::new(
        ErrorCode::CasConflict,
        "expected_revision does not match current account data revision",
    );
    for (key, value) in details.as_object().expect("details is an object") {
        error = error.with_wire_detail(key, value);
    }
    error
}

fn account_data_not_found(account_data_key: &str, current: Option<&AccountDataState>) -> AppError {
    let details = account_data_conflict_details(account_data_key, current);
    let mut error = AppError::not_found("not found");
    for (key, value) in details.as_object().expect("details is an object") {
        error = error.with_wire_detail(key, value);
    }
    error
}

async fn session_actor_is_agent_runtime(
    identity: &IdentityService,
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

/// Unified agent-context predicate for the controller-private gate. A session
/// is an agent context when it carries an agent grant marker OR when its actor
/// is itself a registered agent runtime principal — put/delete and get/list
/// MUST agree on this so a native agent principal cannot read what it is
/// forbidden to write (non-disclosure: get stays `not_found`, list filters).
async fn session_is_agent_context(
    state: &AppState,
    session: &soland_services::identity::SessionIdentityState,
) -> Result<bool, AppError> {
    if session.agent_session.is_some() {
        return Ok(true);
    }
    session_actor_is_agent_runtime(state.identities(), &session.actor).await
}

async fn persist_account_data_event(
    state: &AppState,
    session: &soland_services::identity::SessionIdentityState,
    account_data_key: &str,
    content: Option<Value>,
    expected_revision: u64,
) -> Result<u64, AppError> {
    let service_event_lock = crate::routing::events::event_log::service_event_authoring_lock();
    let _service_event_guard = service_event_lock.lock().await;
    let current = state
        .account_data()
        .entry(&session.actor, account_data_key)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let current_revision = current.as_ref().map_or(0, |record| record.revision);
    if current_revision != expected_revision {
        return Err(account_data_cas_conflict(
            account_data_key,
            current.as_ref(),
        ));
    }
    let revision = expected_revision.checked_add(1).ok_or_else(|| {
        AppError::new(
            ErrorCode::CasConflict,
            "account data revision high-water mark is exhausted",
        )
    })?;
    let service_actor = state.service_id().as_str();
    let realm_id = RealmId::new(soland_services::identity::principal_control_realm_for_did(
        &session.actor,
    ))
    .map_err(|error| AppError::internal(format!("account_data realm invalid: {error}")))?;
    let records = state
        .event_queries()
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
        "key": account_data_key,
        "expected_revision": expected_revision,
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
        EventId::new(arkret_identifiers::new_prefixed_uuid7("ak:event:")).map_err(|error| {
            AppError::internal(format!("account_data Event id invalid: {error}"))
        })?,
        arkret_wire::EventKind::ACCOUNT_DATA_SET,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
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
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#notary-key", state.service_id())).map_err(
            |error| {
                AppError::internal(format!(
                    "service notary verification method is invalid: {error}"
                ))
            },
        )?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
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
        account_data_key,
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
    Ok(revision)
}

#[endpoint(
    operation_id = "ak.self.account_data.resource.replace",
    summary = "Replace an account-data entry",
    tags("account_data")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.resource.replace"))]
async fn put_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    account_data_key: PathParam<String>,
    body: JsonBody<AccountDataReplaceRequestBody>,
) -> JsonResult<AccountDataRow> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account_data_key = account_data_key.into_inner();
    validate_account_data_key(&account_data_key)?;
    validate_registered_account_data_key(&account_data_key)?;

    // AKP-0008 / AKP-0009: registered personal-agent account-data types are
    // controller-private; native agent principals cannot write them directly,
    // and neither can an agent-granted session that presents the controller
    // as its actor.
    if let Some(spec) = registered_account_data_key_spec(&account_data_key)
        && spec.controller_private
        && session_is_agent_context(state, &session).await?
    {
        return Err(AppError::capability_denied(format!(
            "{} is controller-private; agent runtimes cannot write it",
            spec.account_data_key
        )));
    }

    let body = body.into_inner();
    let expected_revision = body.expected_revision;
    validate_private_account_data_content_for_actor(
        &session.actor,
        &account_data_key,
        &body.content,
    )?;
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
        .account_data()
        .entry(&session.actor, &account_data_key)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some_and(|record| !record.tombstone);

    persist_account_data_event(
        state,
        &session,
        &account_data_key,
        Some(body.content),
        expected_revision,
    )
    .await?;
    let record = state
        .account_data()
        .entry(&session.actor, &account_data_key)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("account_data Event projection is missing"))?;

    super::append_audit_log(
        state,
        Some(&session.actor),
        "account_data.set",
        serde_json::json!({"account_data_key": account_data_key}),
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
    summary = "Get an account-data entry",
    tags("account_data")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.resource.get"))]
async fn get_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_data_key: PathParam<String>,
) -> JsonResult<AccountDataRow> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account_data_key = account_data_key.into_inner();
    validate_account_data_key(&account_data_key)?;
    validate_registered_account_data_key(&account_data_key)?;

    // Controller-private entries are indistinguishable from absent ones for
    // Agent runtime sessions (fail closed, no existence disclosure). Same
    // predicate as put/delete: agent grant marker OR native agent principal.
    if is_controller_private_account_data_key(&account_data_key)
        && session_is_agent_context(state, &session).await?
    {
        return Err(AppError::not_found("not found"));
    }

    match state
        .account_data()
        .entry(&session.actor, &account_data_key)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(record) if !record.tombstone => json_ok(entry_from(record)),
        current => Err(account_data_not_found(&account_data_key, current.as_ref())),
    }
}

#[endpoint(
    operation_id = "ak.self.account_data.query.list",
    summary = "List account-data entries",
    tags("account_data")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.query.list"))]
async fn list_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountDataList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    // Same predicate as put/delete: agent grant marker OR native agent
    // principal (non-disclosure list filtering).
    let agent_context = session_is_agent_context(state, &session).await?;
    let entries = state
        .account_data()
        .entries_for_actor(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .into_iter()
        .filter(|record| {
            !(agent_context && is_controller_private_account_data_key(&record.account_data_key))
        })
        .map(entry_from)
        .collect();
    json_ok(AccountDataList { entries })
}

#[endpoint(
    operation_id = "ak.self.account_data.resource.delete",
    summary = "Delete an account-data entry",
    tags("account_data")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.resource.delete"))]
async fn delete_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_data_key: PathParam<String>,
) -> JsonResult<AccountDataDeleteOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account_data_key = account_data_key.into_inner();
    validate_account_data_key(&account_data_key)?;
    validate_registered_account_data_key(&account_data_key)?;
    let expected_revision = req.query::<u64>("expected_revision").ok_or_else(|| {
        AppError::new(
            ErrorCode::SchemaViolation,
            "expected_revision query parameter is required",
        )
    })?;

    if is_controller_private_account_data_key(&account_data_key)
        && session_is_agent_context(state, &session).await?
    {
        return Err(AppError::capability_denied(format!(
            "{account_data_key} is controller-private; agent runtimes cannot delete it"
        )));
    }
    if arkret_schema::account_data_pattern(&account_data_key)
        .is_some_and(|descriptor| descriptor.deletion_mode == "value_tombstone")
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "this account data type requires an in-value tombstone",
        )
        .with_reason_code("physical_delete_forbidden"));
    }

    let revision =
        persist_account_data_event(state, &session, &account_data_key, None, expected_revision)
            .await?;

    super::append_audit_log(
        state,
        Some(&session.actor),
        "account_data.delete",
        serde_json::json!({"account_data_key": account_data_key}),
        "accepted",
    )
    .await;
    json_ok(AccountDataDeleteOutcome {
        ok: true,
        account_data_key,
        revision,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use serde_json::{Value, json};
    use soland_services::ServiceResult;
    use soland_services::identity::{
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
        ) -> ServiceResult<Option<AccountIdentity>> {
            Ok(None)
        }

        async fn register_account(
            &self,
            _command: soland_services::identity::RegisterAccountCommand,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn account(&self, _actor_id: &str) -> ServiceResult<Option<AccountProfileState>> {
            Ok(None)
        }

        async fn accounts(&self) -> ServiceResult<Vec<AccountProfileState>> {
            Ok(Vec::new())
        }

        async fn save_account(&self, _account: AccountProfileState) -> ServiceResult<()> {
            Ok(())
        }

        async fn delete_account(&self, _actor_id: &str) -> ServiceResult<()> {
            Ok(())
        }

        async fn account_localparts(
            &self,
            _actor_id: &str,
        ) -> ServiceResult<Vec<AccountLocalpartState>> {
            Ok(Vec::new())
        }

        async fn localpart_owner(
            &self,
            _localpart: &str,
        ) -> ServiceResult<Option<AccountLocalpartState>> {
            Ok(None)
        }

        async fn add_localpart(
            &self,
            _actor_id: &str,
            _localpart: &str,
            _primary: bool,
        ) -> ServiceResult<AccountLocalpartState> {
            unreachable!("NoAccounts mock: add_localpart is not exercised by these tests")
        }

        async fn set_primary_localpart(
            &self,
            _actor_id: &str,
            _localpart: &str,
        ) -> ServiceResult<AccountLocalpartState> {
            unreachable!("NoAccounts mock: set_primary_localpart is not exercised by these tests")
        }

        async fn remove_localpart(&self, _actor_id: &str, _localpart: &str) -> ServiceResult<()> {
            Ok(())
        }

        async fn clear_localparts(&self, _actor_id: &str) -> ServiceResult<()> {
            Ok(())
        }

        async fn record_handle_release(
            &self,
            _localpart: &str,
            _released_at: DateTime<Utc>,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn save_account_lifecycle(
            &self,
            _actor_id: &str,
            _lifecycle: AccountLifecycleState,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn delete_account_lifecycle(&self, _actor_id: &str) -> ServiceResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl DeviceDirectoryPort for NoDevices {
        async fn list_active_device_actors(&self) -> ServiceResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn devices(&self) -> ServiceResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }

        async fn find_device(
            &self,
            _actor_id: &str,
            _device_id: &str,
        ) -> ServiceResult<Option<DeviceIdentity>> {
            Ok(None)
        }

        async fn save_device(&self, _command: SaveDeviceCommand) -> ServiceResult<()> {
            Ok(())
        }

        async fn save_device_if_absent(&self, _device: DeviceIdentity) -> ServiceResult<bool> {
            Ok(true)
        }

        async fn devices_for_actor(&self, _actor_id: &str) -> ServiceResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl AgentDirectoryPort for AgentClassifier {
        async fn find_agent_controller(
            &self,
            agent_id: &str,
        ) -> ServiceResult<Option<AgentController>> {
            Ok(
                (agent_id == "did:web:agent.alice.example").then(|| AgentController {
                    controller_id: "did:web:alice.example".to_owned(),
                }),
            )
        }
    }

    fn encrypted_envelope(account_data_key: &str) -> Value {
        serde_json::to_value(
            arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
                &[7u8; 32],
                "did:web:alice.example",
                account_data_key,
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

    /// S-1 (spec review): the retired `ak.agent.sidecar_projection.v1` prefix
    /// must be hard-rejected for put/get/delete regardless of session kind.
    /// All three handlers call `validate_registered_account_data_key` before
    /// any session/agent branching, so this validator-level rejection is the
    /// shared invalid_param outcome for agent sessions and plain sessions
    /// alike; and legacy stored rows stay controller-private so agent-session
    /// list filtering and the account-stream skip both keep applying.
    #[test]
    fn retired_sidecar_projection_prefix_is_rejected_and_stays_controller_private() {
        for key in [
            "ak.agent.sidecar_projection.v1",
            "ak.agent.sidecar_projection.v1:did:web:alice.example",
            "ak.agent.sidecar_projection.v1:did:web:alice.example:ak:realm:0196419b-0000-7000-8000-000000000000",
        ] {
            let err = validate_registered_account_data_key(key).unwrap_err();
            assert!(
                err.to_string().contains("registered private key pattern"),
                "retired key `{key}` must fail the shared key validator"
            );
            assert!(
                is_controller_private_account_data_key(key),
                "legacy rows under `{key}` must remain controller-private"
            );
        }
        // The active view-state surface is unaffected.
        assert!(
            validate_registered_account_data_key(
                "ak.agent.sidecar_view_state.v1:did:web:alice.example"
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn controller_private_writer_classifier_uses_agent_principal_projection() {
        let identity = IdentityService::new(
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
