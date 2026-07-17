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

use arkret_sdk::{
    AccountDataDeleteOutcome, AccountDataEntry, AccountDataList, AccountDataReplaceRequestBody,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_storage::{AccountDataRecord, AgentStore};

use super::device_messages::{
    ACCOUNT_DATA_UPDATE_TYPE, BLOCKLIST_UPDATE_TYPE, fanout_actor_private_update,
};
use super::{AuthArgs, now};
use crate::error::AppError;
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
        data_type: "ak.agent.sidecar_projection.v1",
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_sdk::ACCOUNT_DATA_TYPE_REMINDER,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_sdk::ACCOUNT_DATA_TYPE_SCHEDULED_SEND,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_sdk::ACCOUNT_DATA_TYPE_SNOOZE,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_sdk::ACCOUNT_DATA_TYPE_SAVED,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_sdk::ACCOUNT_DATA_TYPE_DRAFT,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_sdk::ACCOUNT_DATA_TYPE_FILE_TRANSFER,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: arkret_sdk::ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST,
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

fn entry_from(record: AccountDataRecord) -> AccountDataEntry {
    AccountDataEntry {
        data_type: record.data_type,
        content: record.payload,
        updated_at: record.updated_at,
    }
}

fn account_data_update_type(data_type: &str) -> &'static str {
    if data_type == "ak.account.blocklist" {
        BLOCKLIST_UPDATE_TYPE
    } else {
        ACCOUNT_DATA_UPDATE_TYPE
    }
}

async fn session_actor_is_agent_runtime(
    agent_store: &dyn AgentStore,
    actor: &str,
) -> Result<bool, AppError> {
    agent_store
        .get(actor)
        .await
        .map(|record| record.is_some())
        .map_err(|error| AppError::internal(format!("agent principal lookup failed: {error}")))
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
        && session_actor_is_agent_runtime(state.persistence.agents(), &session.actor).await?
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
            crate::error::ErrorCode::PayloadTooLarge,
            "account_data payload exceeds 64 KiB",
        ));
    }

    let existed = state
        .persistence
        .account_data()
        .get(&session.actor, &data_type)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some();

    let record = AccountDataRecord {
        actor: session.actor.clone(),
        data_type: data_type.clone(),
        payload: body.content,
        updated_at: now(),
    };
    state
        .persistence
        .account_data()
        .put(&record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    super::append_audit_log(
        state,
        Some(&session.actor),
        "account_data.set",
        serde_json::json!({"data_type": data_type}),
        "accepted",
    )
    .await;
    fanout_actor_private_update(
        state,
        &session.actor,
        &session.device_id,
        account_data_update_type(&data_type),
        json!({
            "operation": "put",
            "data_type": data_type,
            "content": record.payload.clone(),
            "updated_at": record.updated_at,
        }),
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
        .persistence
        .account_data()
        .get(&session.actor, &data_type)
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
        .persistence
        .account_data()
        .list_for_actor(&session.actor)
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

    state
        .persistence
        .account_data()
        .delete(&session.actor, &data_type)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    super::append_audit_log(
        state,
        Some(&session.actor),
        "account_data.delete",
        serde_json::json!({"data_type": data_type}),
        "accepted",
    )
    .await;
    fanout_actor_private_update(
        state,
        &session.actor,
        &session.device_id,
        account_data_update_type(&data_type),
        json!({
            "operation": "delete",
            "data_type": data_type,
            "deleted_at": now(),
        }),
    )
    .await;

    json_ok(AccountDataDeleteOutcome {
        ok: true,
        data_type,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use soland_storage::PersistenceStore;
    use soland_storage_memory::SolandMemoryPersistenceStore;

    use super::*;

    fn encrypted_envelope(data_type: &str) -> Value {
        serde_json::to_value(
            arkret_sdk::account_data_crypto::seal_account_data_value_with_nonce(
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
        let store = SolandMemoryPersistenceStore::new();
        let agent_id = "did:web:agent.alice.example";

        assert!(
            !session_actor_is_agent_runtime(store.agents(), agent_id)
                .await
                .unwrap()
        );

        let mut record = soland_storage::AgentPrincipalRecord::new(
            agent_id.to_owned(),
            "did:web:alice.example".to_owned(),
            "ak:realm:01964137-0000-7000-8000-000000000010".to_owned(),
            format!("{agent_id}#managed-controller"),
            "active".to_owned(),
            chrono::Utc::now(),
        );
        record.display_name = Some("Alice Assistant".to_owned());
        store.agents().put(record).await.unwrap();

        assert!(
            session_actor_is_agent_runtime(store.agents(), agent_id)
                .await
                .unwrap()
        );
        assert!(
            !session_actor_is_agent_runtime(store.agents(), "did:web:alice.example")
                .await
                .unwrap()
        );
    }
}
