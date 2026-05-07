//! Account + contact handlers.
//!
//! Surfaces:
//! - `POST /api/v1/account/register` — create the account record
//! - `GET  /api/v1/account/me` — return the authenticated principal's account
//! - `POST /api/v1/contacts/request` — open a pending contact relationship
//! - `POST /api/v1/contacts/respond` — accept or reject a pending request
//! - `GET  /api/v1/contacts` — list contacts visible to the actor

use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;

use crate::{
    JsonResult,
    error::AppError,
    json_ok,
    state::{AccountRecord, AppState, ContactRecord, DeviceInventoryRecord},
    wire::{
        AccountResponse, ContactRequestRequest, ContactResponse, ContactRespondRequest,
        ContactsResponse, RegisterAccountRequest,
    },
};

use super::{
    AuthArgs, append_audit_log, is_valid_handle, normalize_handle, now,
    validate_device_id, validate_did,
};

#[endpoint(
    operation_id = "cx.account.register",
    tags("account"),
    summary = "Register a new account record",
    status_codes(201, 400, 401, 409, 500),
)]
pub async fn account_register(
    depot: &mut Depot,
    res: &mut Response,
    body: JsonBody<RegisterAccountRequest>,
) -> JsonResult<AccountResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if validate_did(&body.did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    if !is_valid_handle(&body.handle) {
        return Err(AppError::invalid_param("invalid handle"));
    }
    if let Some(device_id) = body.device_id.as_deref()
        && validate_device_id(device_id).is_err()
    {
        return Err(AppError::invalid_param("invalid device_id"));
    }

    let normalized_handle = normalize_handle(&body.handle);
    let accounts = state
        .persistence
        .accounts()
        .list()
        .map_err(|error| AppError::internal(error.to_string()))?;
    if accounts
        .iter()
        .any(|account| account.did == body.did || account.handle == normalized_handle)
    {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "account or handle already exists",
        ));
    }
    let account = AccountRecord {
        did: body.did.clone(),
        handle: normalized_handle,
        display_name: body.display_name,
        created_at: now(),
    };
    state
        .persistence
        .accounts()
        .put(&account)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(device_id) = body.device_id.as_deref() {
        let registered_at = now();
        let device = DeviceInventoryRecord {
            actor: body.did.clone(),
            device_id: device_id.to_owned(),
            display_name: account.display_name.clone(),
            verification_state: "unverified".to_owned(),
            payload: json!({
                "device_id": device_id,
                "display_name": account.display_name.clone(),
                "verification": "unverified",
                "registered_with_account": true,
            }),
            created_at: registered_at,
            updated_at: registered_at,
            revoked_at: None,
        };
        state
            .persistence
            .devices()
            .put(&device)
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    append_audit_log(
        state,
        Some(&body.did),
        "account.register",
        json!({"handle": account.handle.clone()}),
        "accepted",
    );
    res.status_code(StatusCode::CREATED);
    json_ok(account_response(account))
}

#[endpoint(
    operation_id = "cx.account.me",
    tags("account"),
    summary = "Get the authenticated principal's account record",
)]
pub async fn account_me(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    match state
        .persistence
        .accounts()
        .get(&session.actor)
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(account) => json_ok(account_response(account)),
        None => Err(AppError::not_found("not found")),
    }
}

#[endpoint(
    operation_id = "cx.contacts.request",
    tags("contacts"),
    summary = "Open a pending contact relationship",
    status_codes(200, 201, 400, 401, 404, 409, 500),
)]
pub async fn contact_request(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<ContactRequestRequest>,
) -> JsonResult<ContactResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if validate_did(&body.target).is_err() || body.target == session.actor {
        return Err(AppError::invalid_param("invalid contact target"));
    }
    let target_account = state
        .persistence
        .accounts()
        .get(&body.target)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if target_account.is_none() {
        return Err(AppError::not_found("not found"));
    }
    let store = state.persistence.contacts();
    if let Some(existing) = store
        .get(&session.actor, &body.target)
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        return json_ok(contact_response(existing));
    }
    if store
        .get(&body.target, &session.actor)
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some()
    {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "contact relationship already exists",
        ));
    }
    let contact = ContactRecord {
        requester: session.actor,
        target: body.target,
        status: "pending".to_owned(),
        created_at: now(),
        updated_at: now(),
    };
    store
        .put(&contact)
        .map_err(|error| AppError::internal(error.to_string()))?;
    res.status_code(StatusCode::CREATED);
    json_ok(contact_response(contact))
}

#[endpoint(
    operation_id = "cx.contacts.respond",
    tags("contacts"),
    summary = "Accept or reject a pending contact request",
)]
pub async fn contact_respond(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactRespondRequest>,
) -> JsonResult<ContactResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if !matches!(body.action.as_str(), "accept" | "reject") {
        return Err(AppError::invalid_param("action must be accept or reject"));
    }
    let store = state.persistence.contacts();
    let Some(mut contact) = store
        .get(&body.requester, &session.actor)
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(AppError::not_found("not found"));
    };
    if contact.status != "pending" {
        let requested_status = if body.action == "accept" {
            "accepted"
        } else {
            "rejected"
        };
        if contact.status == requested_status {
            return json_ok(contact_response(contact));
        }
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "contact request is no longer pending",
        ));
    }
    contact.status = if body.action == "accept" {
        "accepted".to_owned()
    } else {
        "rejected".to_owned()
    };
    contact.updated_at = now();
    store
        .put(&contact)
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(contact_response(contact))
}

#[endpoint(
    operation_id = "cx.contacts.list",
    tags("contacts"),
    summary = "List contacts visible to the authenticated actor",
)]
pub async fn list_contacts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ContactsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let result = state
        .persistence
        .contacts()
        .list_for_actor(&session.actor)
        .map_err(|error| AppError::internal(error.to_string()))?
        .into_iter()
        .map(contact_response)
        .collect();
    json_ok(ContactsResponse { contacts: result })
}

fn account_response(account: AccountRecord) -> AccountResponse {
    AccountResponse {
        did: account.did,
        handle: account.handle,
        display_name: account.display_name,
        created_at: account.created_at,
    }
}

fn contact_response(contact: ContactRecord) -> ContactResponse {
    ContactResponse {
        requester: contact.requester,
        target: contact.target,
        status: contact.status,
        created_at: contact.created_at,
        updated_at: contact.updated_at,
    }
}
