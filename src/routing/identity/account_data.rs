//! Actor-private account data CRUD.
//!
//! Surfaces:
//! - `PUT /api/v1/account_data/{type}` — upsert a per-actor account data entry
//! - `GET /api/v1/account_data/{type}` — fetch one entry
//! - `GET /api/v1/account_data` — list every entry the authenticated actor owns
//! - `DELETE /api/v1/account_data/{type}` — tombstone one entry
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

/// CXP-0008 / CXP-0009 (spec head 37ce729) — controller-private account-data
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
        data_type: "cx.agent.draft.v1",
        controller_private: true,
    },
    AccountDataTypeSpec {
        data_type: "cx.agent.sidecar_projection.v1",
        controller_private: true,
    },
];

fn registered_account_data_type(data_type: &str) -> Option<&'static AccountDataTypeSpec> {
    REGISTERED_ACCOUNT_DATA_TYPES
        .iter()
        .find(|spec| spec.data_type == data_type)
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
    /// encoding and (for sensitive keys like `cx.contacts.*` /
    /// `cx.account.blocklist`) client-side encryption are the client's
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
    // Keys are dot-delimited namespaces (`cx.contacts.space.<space_id>` etc.).
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
        "cx.account.blocklist" | "cx.account.blocklist.v1"
    ) {
        BLOCKLIST_UPDATE_TYPE
    } else {
        ACCOUNT_DATA_UPDATE_TYPE
    }
}

#[endpoint(
    operation_id = "cx.extension.soland.account_data.set",
    tags("account_data"),
    summary = "Upsert an actor-private account_data entry",
    status_codes(200, 201, 400, 401, 413, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account_data.set"))]
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

    // CXP-0008 / CXP-0009 — enforce controller-only writes on the
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
    let is_blocklist_update = matches!(
        data_type.as_str(),
        "cx.account.blocklist" | "cx.account.blocklist.v1"
    );
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
    if is_blocklist_update {
        crate::routing::federation::federation::fanout_blocklist_hints_to_peers(
            state,
            &session.actor,
            &record.payload,
        );
    }

    if !existed {
        res.status_code(StatusCode::CREATED);
    }
    json_ok(entry_from(record))
}

#[endpoint(
    operation_id = "cx.extension.soland.account_data.get",
    tags("account_data"),
    summary = "Fetch a single account_data entry by data_type"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account_data.get"))]
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
    operation_id = "cx.extension.soland.account_data.list",
    tags("account_data"),
    summary = "List every account_data entry owned by the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account_data.list"))]
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
    operation_id = "cx.extension.soland.account_data.delete",
    tags("account_data"),
    summary = "Delete an account_data entry"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account_data.delete"))]
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
