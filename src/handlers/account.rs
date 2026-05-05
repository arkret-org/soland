//! Account + contact handlers.
//!
//! Surfaces:
//! - `POST /api/v1/account/register` — create the account record
//! - `GET  /api/v1/account/me` — return the authenticated principal's account
//! - `POST /api/v1/contacts/request` — open a pending contact relationship
//! - `POST /api/v1/contacts/respond` — accept or reject a pending request
//! - `GET  /api/v1/contacts` — list contacts visible to the actor

use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    state::{AccountRecord, AppState, ContactRecord, DeviceInventoryRecord},
    wire::{
        AccountResponse, ContactRequestRequest, ContactResponse, ContactRespondRequest,
        ContactsResponse, RegisterAccountRequest,
    },
};

use super::{
    append_audit_log, auth_or_render, device_inventory_to_json, is_valid_handle, normalize_handle,
    now, render_error, validate_device_id, validate_did,
};

#[handler]
pub async fn account_register(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<RegisterAccountRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid account registration request",
            );
            return;
        }
    };
    if validate_did(&body.did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    if !is_valid_handle(&body.handle) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid handle",
        );
        return;
    }
    if let Some(device_id) = body.device_id.as_deref()
        && validate_device_id(device_id).is_err()
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid device_id",
        );
        return;
    }

    let normalized_handle = normalize_handle(&body.handle);
    let accounts = match state.persistence.accounts().list() {
        Ok(accounts) => accounts,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                &error.to_string(),
            );
            return;
        }
    };
    if accounts
        .iter()
        .any(|account| account.did == body.did || account.handle == normalized_handle)
    {
        render_error(
            res,
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "account or handle already exists",
        );
        return;
    }
    let account = AccountRecord {
        did: body.did.clone(),
        handle: normalized_handle,
        display_name: body.display_name,
        created_at: now(),
    };
    if let Err(error) = state.persistence.accounts().put(&account) {
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            &error.to_string(),
        );
        return;
    }
    state
        .accounts
        .lock()
        .expect("accounts lock")
        .insert(body.did.clone(), account.clone());
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
        if let Err(error) = state.persistence.devices().put(&device) {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                &error.to_string(),
            );
            return;
        }
        state
            .devices
            .lock()
            .expect("devices lock")
            .entry(body.did.clone())
            .or_default()
            .insert(device_id.to_owned(), device_inventory_to_json(&device));
    }
    append_audit_log(
        state,
        Some(&body.did),
        "account.register",
        json!({"handle": account.handle.clone()}),
        "accepted",
    );
    res.status_code(StatusCode::CREATED);
    res.render(Json(account_response(account)));
}

#[handler]
pub async fn account_me(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    match state.persistence.accounts().get(&session.actor) {
        Ok(Some(account)) => res.render(Json(account_response(account))),
        Ok(None) => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
        Err(error) => render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            &error.to_string(),
        ),
    }
}

#[handler]
pub async fn contact_request(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<ContactRequestRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid contact request",
            );
            return;
        }
    };
    if validate_did(&body.target).is_err() || body.target == session.actor {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid contact target",
        );
        return;
    }
    let target_account = match state.persistence.accounts().get(&body.target) {
        Ok(account) => account,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                &error.to_string(),
            );
            return;
        }
    };
    if target_account.is_none() {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let mut contacts = state.contacts.lock().expect("contacts lock");
    let key = (session.actor.clone(), body.target.clone());
    if let Some(existing) = contacts.get(&key).cloned() {
        res.render(Json(contact_response(existing)));
        return;
    }
    if contacts.contains_key(&(body.target.clone(), session.actor.clone())) {
        render_error(
            res,
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "contact relationship already exists",
        );
        return;
    }
    let contact = ContactRecord {
        requester: session.actor,
        target: body.target,
        status: "pending".to_owned(),
        created_at: now(),
        updated_at: now(),
    };
    contacts.insert(key, contact.clone());
    res.status_code(StatusCode::CREATED);
    res.render(Json(contact_response(contact)));
}

#[handler]
pub async fn contact_respond(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<ContactRespondRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid contact response",
            );
            return;
        }
    };
    if !matches!(body.action.as_str(), "accept" | "reject") {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "action must be accept or reject",
        );
        return;
    }
    let mut contacts = state.contacts.lock().expect("contacts lock");
    let key = (body.requester, session.actor);
    let Some(contact) = contacts.get_mut(&key) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    };
    if contact.status != "pending" {
        let requested_status = if body.action == "accept" {
            "accepted"
        } else {
            "rejected"
        };
        if contact.status == requested_status {
            res.render(Json(contact_response(contact.clone())));
            return;
        }
        render_error(
            res,
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "contact request is no longer pending",
        );
        return;
    }
    contact.status = if body.action == "accept" {
        "accepted".to_owned()
    } else {
        "rejected".to_owned()
    };
    contact.updated_at = now();
    res.render(Json(contact_response(contact.clone())));
}

#[handler]
pub async fn list_contacts(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let contacts = state.contacts.lock().expect("contacts lock");
    let result = contacts
        .values()
        .filter(|contact| contact.requester == session.actor || contact.target == session.actor)
        .cloned()
        .map(contact_response)
        .collect();
    res.render(Json(ContactsResponse { contacts: result }));
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
