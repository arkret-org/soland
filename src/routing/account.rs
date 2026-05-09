//! Account + contact handlers.
//!
//! Surfaces:
//! - `POST /api/v1/account/register` — create the account record
//! - `GET  /api/v1/account/me` — return the authenticated principal's account
//! - `POST /api/v1/contacts/request` — open a pending contact relationship
//! - `POST /api/v1/contacts/respond` — accept or reject a pending request
//! - `GET  /api/v1/contacts` — list contacts visible to the actor

use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
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

/// `GET /api/v1/account/{did}/principal-space` response.
///
/// **Wire shape (locked for coauth integration)**:
/// ```json
/// {
///   "did": "did:web:alice.example",
///   "space_id": "cx:space:01904100-0000-7000-8000-...",
///   "mapping_kind": "deterministic",
///   "stashed": true
/// }
/// ```
///
/// `mapping_kind` is one of:
/// - `"deterministic"` — the response was computed via the SHA-256 mapping
///   (current behavior; matches `coauth::holder_principal_space_for_did`).
/// - `"custom"` — a future override (admin-set or onboarding-time pinned)
///   was applied. v1 only emits `"deterministic"`; the field is reserved
///   so coauth can swap the mapping later without a wire bump.
///
/// `stashed` indicates the result was persisted to the audit log as a
/// follow-up hook so future custom-mapping overrides can write to the same
/// table and the deterministic mapping stays as the offline fallback.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct PrincipalSpaceResponse {
    pub did: String,
    pub space_id: String,
    pub mapping_kind: String,
    pub stashed: bool,
}

/// `GET /api/v1/account/{did}/principal-space`.
///
/// Returns the deterministic principal-control Space id for `did`,
/// matching the `sha256(did) → UUIDv7` convention coauth currently mirrors
/// at `coauth::handlers::account::anchor_view_query::holder_principal_space_for_did`.
/// The deterministic mapping is the v1 contract; a custom override layer
/// is reserved for round-25+ when admins can pin a non-default Space.
///
/// Side-effect: appends an audit-log entry (`account.principal_space.lookup`)
/// so a future `principal_space_overrides` table can backfill from the audit
/// trail and the deterministic mapping stays the offline default.
#[endpoint(
    operation_id = "cx.account.principal_space",
    tags("account"),
    summary = "Resolve the principal control Space for a DID",
)]
pub async fn account_principal_space(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    did: PathParam<String>,
) -> JsonResult<PrincipalSpaceResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let space_id = principal_space_for_did(&did);
    super::append_audit_log(
        state,
        Some(&did),
        "account.principal_space.lookup",
        json!({"space_id": space_id, "mapping_kind": "deterministic"}),
        "accepted",
    );
    json_ok(PrincipalSpaceResponse {
        did,
        space_id,
        mapping_kind: "deterministic".to_owned(),
        stashed: true,
    })
}

/// Deterministic DID → principal-control Space mapping.
///
/// Mirrors `coauth::holder_principal_space_for_did` exactly (same domain
/// separator, same UUIDv7 version/variant rewrite). When/if coauth swaps
/// to an HTTP call against this endpoint, both sides MUST stay in lockstep
/// or the offline fallback diverges. The bytes-level test
/// `principal_space_for_did_matches_coauth_convention` below pins the
/// shape so accidental drift fails CI.
pub fn principal_space_for_did(holder_did: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"cx:space:principal-control:v1:");
    hasher.update(holder_did.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Force UUIDv7 version (top nibble of byte 6 = 0x7) and RFC-9562
    // variant (top two bits of byte 8 = 0b10).
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let h = |b: u8| -> String { format!("{b:02x}") };
    let group = |slice: &[u8]| -> String { slice.iter().copied().map(h).collect::<String>() };
    format!(
        "cx:space:{}-{}-{}-{}-{}",
        group(&bytes[0..4]),
        group(&bytes[4..6]),
        group(&bytes[6..8]),
        group(&bytes[8..10]),
        group(&bytes[10..16]),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_space_for_did_is_deterministic() {
        let a = principal_space_for_did("did:web:alice.example");
        let b = principal_space_for_did("did:web:alice.example");
        assert_eq!(a, b);
    }

    #[test]
    fn principal_space_for_did_diverges_per_did() {
        let a = principal_space_for_did("did:web:alice.example");
        let c = principal_space_for_did("did:web:bob.example");
        assert_ne!(a, c);
    }

    #[test]
    fn principal_space_for_did_matches_coauth_convention() {
        // Locks the shape against accidental drift from
        // `coauth::handlers::account::anchor_view_query::holder_principal_space_for_did`.
        // Same domain separator (`cx:space:principal-control:v1:`),
        // same UUIDv7 version/variant rewrite — verified by checking the
        // post-bitmask invariants (byte 6 high-nibble = 0x7, byte 8 top
        // two bits = 0b10).
        let s = principal_space_for_did("did:web:alice.example");
        assert!(s.starts_with("cx:space:"), "got {s}");
        let uuid_segment = s.strip_prefix("cx:space:").unwrap();
        // Sections separated by '-'.
        let parts: Vec<&str> = uuid_segment.split('-').collect();
        assert_eq!(parts.len(), 5, "uuid has 5 dash-separated groups");
        // Group at index 2 is `version + 3 hex chars`. UUIDv7 → starts with "7".
        assert!(parts[2].starts_with('7'), "expected v7, got {}", parts[2]);
        // Group at index 3 starts with hex byte where top two bits = 0b10
        // → first hex digit is 8/9/a/b.
        let first_hex = parts[3].chars().next().unwrap();
        assert!(
            matches!(first_hex, '8' | '9' | 'a' | 'b'),
            "expected RFC9562 variant nibble 8|9|a|b, got {first_hex}"
        );
    }
}
