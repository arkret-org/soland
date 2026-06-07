//! Legacy actor-private account data compatibility handlers.
//!
//! Protocol writes use `ck.account_data.set` actor-private events and
//! `ck.self.account.subscribe` for sync/read. This module is mounted only under
//! `/_soland/self/account_data*` for old local clients.
//!
//! Spec: `discovery/client-preferences.md` §2 (storage model) plus the per-key
//! sections (§3.1 Space tags, §3.5 blocklist, §3.6 contact remarks, §3.7 Space
//! remarks, §3.8 read-receipt preferences). The server treats `payload` as an
//! opaque encrypted blob; clients own canonical encoding, schema validation,
//! and (where applicable) encryption.

use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::device_messages::{
    ACCOUNT_DATA_UPDATE_TYPE, BLOCKLIST_UPDATE_TYPE, fanout_actor_private_update,
};
use super::{AuthArgs, now};
use crate::error::AppError;
use crate::state::{AccountDataRecord, AppState};
use crate::{JsonResult, json_ok};

const MAX_DATA_TYPE_LEN: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// CKP-0008 / CKP-0009 (spec head 37ce729) — controller-private account-data
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
        data_type: "ck.agent.draft.v1",
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: "ck.agent.sidecar_projection.v1",
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: cokret_sdk::ACCOUNT_DATA_TYPE_REMINDER,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: cokret_sdk::ACCOUNT_DATA_TYPE_SCHEDULED_SEND,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: cokret_sdk::ACCOUNT_DATA_TYPE_SNOOZE,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: cokret_sdk::ACCOUNT_DATA_TYPE_SAVED,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: cokret_sdk::ACCOUNT_DATA_TYPE_DRAFT,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: cokret_sdk::ACCOUNT_DATA_TYPE_FILE_TRANSFER,
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: cokret_sdk::ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST,
        controller_private: true,
    },
];

const PRIVATE_ACCOUNT_DATA_PREFIXES: &[&str] = &[
    cokret_sdk::ACCOUNT_DATA_TYPE_REMINDER,
    cokret_sdk::ACCOUNT_DATA_TYPE_SCHEDULED_SEND,
    cokret_sdk::ACCOUNT_DATA_TYPE_SNOOZE,
    cokret_sdk::ACCOUNT_DATA_TYPE_SAVED,
    cokret_sdk::ACCOUNT_DATA_TYPE_DRAFT,
    cokret_sdk::ACCOUNT_DATA_TYPE_FILE_TRANSFER,
    cokret_sdk::ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST,
];

fn registered_account_data_type(data_type: &str) -> Option<&'static AccountDataTypeSpec> {
    let canonical_type = private_account_data_prefix(data_type).unwrap_or(data_type);
    REGISTERED_ACCOUNT_DATA_TYPES
        .iter()
        .find(|spec| spec.data_type == canonical_type)
}

fn private_account_data_prefix(data_type: &str) -> Option<&'static str> {
    PRIVATE_ACCOUNT_DATA_PREFIXES
        .iter()
        .copied()
        .find(|prefix| {
            data_type
                .strip_prefix(*prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
        })
}

fn validate_registered_account_data_key(data_type: &str) -> Result<(), AppError> {
    if private_account_data_prefix(data_type).is_some() {
        cokret_sdk::validate_private_account_data_key(data_type)
            .map_err(|error| AppError::invalid_param(error.to_string()))?;
    }
    Ok(())
}

fn validate_private_account_data_content(data_type: &str, content: &Value) -> Result<(), AppError> {
    if private_account_data_prefix(data_type).is_none() {
        return Ok(());
    }
    let Some(object) = content.as_object() else {
        return Err(AppError::invalid_param(
            "private account_data content must be an encrypted envelope object",
        ));
    };
    if object.get("tombstone").is_some() {
        return Ok(());
    }
    for forbidden in [
        "body",
        "target_ref",
        "collection_title",
        "note",
        "message_payload",
        "content",
        "blind_tokens",
        "shard_key",
        "transfer_id",
        "blob_ref",
        "filename",
        "media_type",
        "plaintext_size_bytes",
        "content_digest",
        "recipient_device_ids",
        "content_key",
        "local_path",
    ] {
        if object.contains_key(forbidden) {
            return Err(AppError::invalid_param(format!(
                "private account_data content must not expose `{forbidden}` in plaintext",
            )));
        }
    }
    if object.contains_key("encrypted_payload")
        || object.contains_key("encrypted_content")
        || object.contains_key("ciphertext")
    {
        Ok(())
    } else {
        Err(AppError::invalid_param(
            "private account_data content requires encrypted_payload, encrypted_content, or ciphertext",
        ))
    }
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

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AccountDataSetRequest {
    /// Caller-supplied opaque payload. Server stores it verbatim; canonical
    /// encoding and (for sensitive keys like `ck.contacts.*` /
    /// `ck.account.blocklist`) client-side encryption are the client's
    /// responsibility.
    pub content: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AccountDataEntry {
    pub data_type: String,
    pub content: Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AccountDataListResponse {
    pub entries: Vec<AccountDataEntry>,
}

fn validate_data_type(data_type: &str) -> Result<(), AppError> {
    if data_type.is_empty() {
        return Err(AppError::invalid_param("data_type must not be empty"));
    }
    if data_type.len() > MAX_DATA_TYPE_LEN {
        return Err(AppError::invalid_param("data_type too long"));
    }
    // Keys are dot-delimited namespaces (`ck.contacts.realm.<realm_id>` etc.).
    // Reject control chars / whitespace / path separators to keep them URL- and
    // log-safe; everything else (including the `:` in `ck:space:<uuid>`) is
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
    if matches!(
        data_type,
        "ck.account.blocklist" | "ck.account.blocklist.v1"
    ) {
        BLOCKLIST_UPDATE_TYPE
    } else {
        ACCOUNT_DATA_UPDATE_TYPE
    }
}

#[endpoint(
    operation_id = "ck.extension.soland.account_data.set",
    tags("account_data"),
    summary = "Upsert an actor-private account_data entry",
    status_codes(200, 201, 400, 401, 413, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.account_data.set"))]
async fn put_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    data_type: PathParam<String>,
    body: JsonBody<AccountDataSetRequest>,
) -> JsonResult<AccountDataEntry> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let data_type = data_type.into_inner();
    validate_data_type(&data_type)?;
    validate_registered_account_data_key(&data_type)?;

    // CKP-0008 / CKP-0009 — enforce controller-only writes on the
    // registered personal-agent account-data types.
    // TODO(P2-impl): replace the `did:web:agent.` heuristic with a proper
    // controller-vs-agent classifier sourced from the agent_principal
    // projection (the bearer session record carries the actor DID; once
    // the projection lands we can ask the projection "is this session an
    // agent runtime acting on behalf of a controller?" instead).
    if let Some(spec) = registered_account_data_type(&data_type) {
        if spec.controller_private
            && (session.actor.starts_with("did:web:agent.")
                || session.actor.starts_with("did:agent:"))
        {
            return Err(AppError::capability_denied(format!(
                "{} is controller-private; agent runtimes cannot write it",
                spec.data_type
            )));
        }
    }

    let body = body.into_inner();
    validate_private_account_data_content(&data_type, &body.content)?;
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
    operation_id = "ck.extension.soland.account_data.get",
    tags("account_data"),
    summary = "Fetch a single account_data entry by data_type"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.account_data.get"))]
async fn get_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    data_type: PathParam<String>,
) -> JsonResult<AccountDataEntry> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    operation_id = "ck.extension.soland.account_data.list",
    tags("account_data"),
    summary = "List every account_data entry owned by the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.account_data.list"))]
async fn list_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountDataListResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    json_ok(AccountDataListResponse { entries })
}

#[endpoint(
    operation_id = "ck.extension.soland.account_data.delete",
    tags("account_data"),
    summary = "Delete an account_data entry"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.account_data.delete"))]
async fn delete_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    data_type: PathParam<String>,
) -> JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
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

    json_ok(serde_json::json!({"ok": true, "data_type": data_type}))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn private_account_data_key_patterns_are_validated() {
        assert!(
            validate_registered_account_data_key(
                "ck.scheduled_send.v1:ck:message:01904100-0000-7000-8000-000000000001"
            )
            .is_ok()
        );
        assert!(
            validate_registered_account_data_key(
                "ck.file_transfer.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            )
            .is_ok()
        );
        let err = validate_registered_account_data_key(
            "ck.draft.v1:message:ck:message:01904100-0000-7000-8000-000000000001:main",
        )
        .unwrap_err();
        assert!(err.to_string().contains("raw typed refs"));
    }

    #[test]
    fn private_account_data_requires_encrypted_content() {
        let key = "ck.saved.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        assert!(
            validate_private_account_data_content(
                key,
                &json!({"encrypted_payload": {"ciphertext": "opaque"}}),
            )
            .is_ok()
        );
        assert!(validate_private_account_data_content(key, &json!({"tombstone": true})).is_ok());
        let err = validate_private_account_data_content(
            key,
            &json!({"body": {"collection_title": "Leaks"}}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("body"));

        let transfer_key = "ck.file_transfer.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = validate_private_account_data_content(
            transfer_key,
            &json!({"filename": "private.pdf", "encrypted_payload": {"ciphertext": "opaque"}}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("filename"));
    }
}
