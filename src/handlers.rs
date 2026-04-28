use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contrix_sdk::{
    Commit, CommitId, CommitProofVerifier, DeviceId, Did, ErrorEnvelope, Hash, Operation,
    OperationId, Proof, SpaceId, SpaceSearchEntry,
};
use diesel::{
    QueryableByName, RunQueryDsl, sql_query,
    sql_types::{Jsonb, Nullable, Text, Timestamptz},
};
use salvo::{
    http::{Method, StatusCode},
    prelude::*,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::{
    ids,
    state::{
        AccountRecord, AppState, BlobRecord, ContactRecord, DeviceMessageRecord,
        IdentityDocumentRecord, IdentityLogRecord, MessageRecord, PresenceRecord,
        ProjectionEventRecord, SessionRecord, SpaceInviteRecord, SpaceMetaRecord,
    },
    wire::{
        AccountResponse, AddReactionRequest, AddSpaceMemberRequest, ApiError, AuthzCheckRequest,
        AuthzCheckResponse, BackfillResponse, ClientSyncRequest, ClientSyncResponse,
        ContactRequestRequest, ContactRespondRequest, ContactResponse, ContactsResponse,
        CreateEntityRequest, CreateGrantRequest, CreateRelationRequest, CreateSpaceRequest,
        CreateViewRequest, DevLoginRequest, DevLoginResponse, DeviceMessagesReceiveResponse,
        DeviceMessagesSendRequest, DeviceMessagesSendResponse, DirectoryDescribeResponse,
        DirectoryValueSearchResponse, EffectiveGrantsResponse, EntityResponse,
        GetOperationsRequest, GetOperationsResponse, HealthResponse, IdentityDescribeResponse,
        IdentityLogResponse, IdentityReceiptsResponse, IdentityResolveRequest,
        IdentityResolveResponse, IndexDescribeResponse, IndexEntityResponse, IndexInboxResponse,
        IndexNotificationsResponse, IndexQueryRequest, IndexQueryResponse, IndexSearchRequest,
        IndexSearchResponse, IndexSpaceHierarchyResponse, IndexThreadResponse, InvitesResponse,
        KeysClaimRequest, KeysClaimResponse, KeysQueryRequest, KeysQueryResponse,
        KeysUploadRequest, KeysUploadResponse, ListCommitsResponse, LogoutResponse,
        ModerationReportRequest, ModerationReportResponse, OkResponse, PolicyCheckRequest,
        PolicyCheckResponse, PushNotifyRequest, PushNotifyResponse, PushRegisterRequest,
        PushRegisterResponse, PushUnregisterRequest, ReactionResponse, ReadMarkerResponse,
        RedactMessageRequest, RedactMessageResponse, RegisterAccountRequest, RelationResponse,
        RemoveReactionRequest, RepoDescribeResponse, RepoSyncRequest, RepoSyncResponse,
        ResolveHandleRequest, ResolveHandleResponse, ResolveOrganizationRequest,
        ResolveOrganizationResponse, ResolveSpaceRequest, ResolveSpaceResponse,
        ReviseMessageRequest, ReviseMessageResponse, SearchActorsRequest,
        SearchOrganizationsRequest, SearchSpacesRequest, SearchSpacesResponse, SendMessageRequest,
        SendMessageResponse, SetReadMarkerRequest, SnapshotHeadResponse, SpaceLifecycleResponse,
        SubmitCommitRequest, SubmitCommitResponse, SubmitDidOperationRequest,
        SubmitDidOperationResponse, SyncDescribeResponse, UpdateEntityRequest, ViewResponse,
        describe, now, sync_token,
    },
};

#[handler]
pub async fn health(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(HealthResponse {
        ok: true,
        service: "soland",
        storage: state.db.mode(),
    }));
}

#[handler]
pub async fn server_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(describe(state.db.mode())));
}

#[handler]
pub async fn dev_login(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    // Only allow dev login in development mode
    if !state.config.development_mode {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "endpoint not available",
        );
        return;
    }
    let body = match req.parse_json::<DevLoginRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid login request",
            );
            return;
        }
    };
    if validate_did(&body.actor).is_err() || validate_device_id(&body.device_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "actor must be a DID and device_id is required",
        );
        return;
    }
    if !state
        .accounts
        .lock()
        .expect("accounts lock")
        .contains_key(&body.actor)
    {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "account is not registered",
        );
        return;
    }

    let expires_at = now() + chrono::Duration::hours(12);
    let token = token_for(&body.actor, &body.device_id, expires_at.timestamp_millis());
    state.sessions.lock().expect("sessions lock").insert(
        token.clone(),
        SessionRecord {
            token: token.clone(),
            actor: body.actor.clone(),
            device_id: body.device_id.clone(),
            expires_at,
        },
    );
    state
        .devices
        .lock()
        .expect("devices lock")
        .entry(body.actor.clone())
        .or_default()
        .insert(
            body.device_id.clone(),
            json!({
                "device_id": body.device_id.clone(),
                "display_name": body.display_name.clone(),
                "verification": "unverified",
                "last_seen_at": now()
            }),
        );
    append_audit_log(
        state,
        Some(&body.actor),
        "auth.dev_login",
        json!({"device_id": body.device_id.clone()}),
        "accepted",
    );

    res.render(Json(DevLoginResponse {
        access_token: token,
        token_type: "Bearer".to_owned(),
        actor: body.actor,
        device_id: body.device_id,
        expires_at,
    }));
}

#[handler]
pub async fn logout(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(token) = bearer_token(req).map(str::to_owned) else {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "missing bearer token",
        );
        return;
    };
    let removed = state.sessions.lock().expect("sessions lock").remove(&token);
    let revoked = removed.is_some();
    if let Some(session) = removed {
        append_audit_log(
            state,
            Some(&session.actor),
            "auth.logout",
            json!({"device_id": session.device_id}),
            "accepted",
        );
    }
    res.render(Json(LogoutResponse { ok: true, revoked }));
}

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
    let mut accounts = state.accounts.lock().expect("accounts lock");
    if accounts.contains_key(&body.did)
        || accounts
            .values()
            .any(|account| account.handle == normalized_handle)
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
    accounts.insert(body.did.clone(), account.clone());
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
    let accounts = state.accounts.lock().expect("accounts lock");
    match accounts.get(&session.actor) {
        Some(account) => res.render(Json(account_response(account.clone()))),
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
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
    if !state
        .accounts
        .lock()
        .expect("accounts lock")
        .contains_key(&body.target)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let mut contacts = state.contacts.lock().expect("contacts lock");
    let key = (session.actor.clone(), body.target.clone());
    if contacts.contains_key(&key)
        || contacts.contains_key(&(body.target.clone(), session.actor.clone()))
    {
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

#[handler]
pub async fn create_space(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateSpaceRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid create space request",
            );
            return;
        }
    };
    if body.title.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "title is required",
        );
        return;
    }
    for invitee in &body.invitees {
        if validate_did(invitee).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "invalid invitee did",
            );
            return;
        }
    }
    for service_did in &body.plaintext_visible_services {
        if validate_did(service_did).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "invalid plaintext_visible_services did",
            );
            return;
        }
    }
    let discoverability = body.discoverability.clone().unwrap_or_else(|| {
        if body.public {
            "public".to_owned()
        } else {
            "invite_only".to_owned()
        }
    });
    if !is_valid_discoverability(&discoverability) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid discoverability",
        );
        return;
    }
    let invitees = body.invitees.clone();
    let plaintext_visible_services = body.plaintext_visible_services.clone();
    let space_id = ids::generate_space_id();
    let mut entry = SpaceSearchEntry::new(
        SpaceId::new(space_id.clone()).expect("generated valid space id"),
        body.title.trim(),
    );
    entry.description = body.summary;
    entry.public = discoverability == "public";
    entry
        .members
        .insert(Did::new(session.actor.clone()).expect("session did is valid"));

    state.spaces.lock().expect("spaces lock").upsert(entry);
    state.space_meta.lock().expect("space meta lock").insert(
        space_id.clone(),
        SpaceMetaRecord {
            owner: session.actor.clone(),
            deleted: false,
            discoverability: discoverability.clone(),
            plaintext_visible_services: plaintext_visible_services.iter().cloned().collect(),
            created_at: now(),
            updated_at: now(),
        },
    );
    let invite_records: Vec<_> = invitees
        .iter()
        .map(|invitee| {
            let invite_id = ids::generate_invite_id();
            let invite_token = generate_invite_token(&invite_id, &space_id, invitee);
            SpaceInviteRecord {
                invite_id,
                space_id: space_id.clone(),
                inviter: session.actor.clone(),
                invitee: Some(invitee.clone()),
                invite_token,
                status: "pending".to_owned(),
                expires_at: Some(now() + chrono::Duration::days(7)),
                created_at: now(),
            }
        })
        .collect();
    if !invite_records.is_empty() {
        let mut invite_store = state.space_invites.lock().expect("space invites lock");
        for invite in &invite_records {
            invite_store.insert(invite.invite_id.clone(), invite.clone());
        }
    }
    if let Err(error) = record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "create",
            "owner": session.actor.clone(),
            "members": [],
            "invitees": invitees,
            "invite_ids": invite_records
                .iter()
                .map(|invite| invite.invite_id.clone())
                .collect::<Vec<_>>(),
            "public": discoverability == "public",
            "discoverability": discoverability,
            "plaintext_visible_services": plaintext_visible_services,
        }),
    ) {
        render_error(
            res,
            StatusCode::CONFLICT,
            "repo_conflict",
            &error.to_string(),
        );
        return;
    }

    res.status_code(StatusCode::CREATED);
    append_audit_log(
        state,
        Some(&session.actor),
        "space.create",
        json!({"space_id": space_id.clone()}),
        "accepted",
    );
    render_space_lifecycle(state, res, &space_id);
}

#[handler]
pub async fn add_space_member(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(space_id) = req.param::<String>("space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if !space_owner_matches(state, &space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "only the space owner can add members",
        );
        return;
    }
    let body = match req.parse_json::<AddSpaceMemberRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid add member request",
            );
            return;
        }
    };
    if validate_did(&body.member).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid member did",
        );
        return;
    }
    let Ok(space_id_value) = SpaceId::new(space_id.clone()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    };
    let mut spaces = state.spaces.lock().expect("spaces lock");
    let Some(mut entry) = spaces.get(&space_id_value).cloned() else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    };
    entry
        .members
        .insert(Did::new(body.member.clone()).expect("validated did"));
    spaces.upsert(entry);
    drop(spaces);
    touch_space(state, &space_id);
    if let Err(error) = record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "member.add",
            "member": body.member.clone(),
            "membership": "join",
        }),
    ) {
        render_error(
            res,
            StatusCode::CONFLICT,
            "repo_conflict",
            &error.to_string(),
        );
        return;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "space.member.add",
        json!({"space_id": space_id.clone(), "member": body.member}),
        "accepted",
    );
    render_space_lifecycle(state, res, &space_id);
}

#[handler]
pub async fn remove_space_member(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(space_id) = req.param::<String>("space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    let Some(member_did) = req.param::<String>("member_did") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "member_did is required",
        );
        return;
    };
    if !space_owner_matches(state, &space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "only the space owner can remove members",
        );
        return;
    }
    if member_did == session.actor {
        render_error(
            res,
            StatusCode::CONFLICT,
            "conflict",
            "owner cannot remove self",
        );
        return;
    }
    let Ok(space_id_value) = SpaceId::new(space_id.clone()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    };
    let Ok(member) = Did::new(member_did) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid member did",
        );
        return;
    };
    let mut spaces = state.spaces.lock().expect("spaces lock");
    let Some(mut entry) = spaces.get(&space_id_value).cloned() else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    };
    entry.members.remove(&member);
    spaces.upsert(entry);
    drop(spaces);
    touch_space(state, &space_id);
    if let Err(error) = record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "member.remove",
            "member": member.to_string(),
            "membership": "leave",
        }),
    ) {
        render_error(
            res,
            StatusCode::CONFLICT,
            "repo_conflict",
            &error.to_string(),
        );
        return;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "space.member.remove",
        json!({"space_id": space_id.clone(), "member": member.to_string()}),
        "accepted",
    );
    render_space_lifecycle(state, res, &space_id);
}

#[handler]
pub async fn delete_space(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(space_id) = req.param::<String>("space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if !space_owner_matches(state, &space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "only the space owner can delete the space",
        );
        return;
    }
    {
        let mut meta = state.space_meta.lock().expect("space meta lock");
        let Some(record) = meta.get_mut(&space_id) else {
            render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
            return;
        };
        record.deleted = true;
        record.updated_at = now();
    }
    if let Err(error) = record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "delete",
            "deleted": true,
        }),
    ) {
        render_error(
            res,
            StatusCode::CONFLICT,
            "repo_conflict",
            &error.to_string(),
        );
        return;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "space.delete",
        json!({"space_id": space_id.clone()}),
        "accepted",
    );
    render_space_lifecycle(state, res, &space_id);
}

#[handler]
pub async fn export_space(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(space_id) = req.param::<String>("space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if !space_id_accessible(state, &space_id, Some(&session)) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let operations = match state.repo.sync_space_operations(&space_id, None, 500) {
        Ok(page) => page.items,
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
            return;
        }
    };
    let events = state
        .projection_events
        .lock()
        .expect("projection events lock")
        .iter()
        .filter(|event| event.space_id == space_id)
        .map(|event| {
            json!({
                "event_id": event.event_id,
                "event_type": event.event_type,
                "operation_type": event.operation_type,
                "operation_id": event.operation_id,
                "sender": event.sender,
                "payload": event.payload,
                "created_at": event.created_at,
            })
        })
        .collect::<Vec<_>>();
    res.render(Json(json!({
        "schema": "cx.export.space.v1",
        "space_id": space_id,
        "generated_at": now(),
        "operations": operations,
        "events": events,
    })));
}

#[handler]
pub async fn send_message(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<SendMessageRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid send message request",
            );
            return;
        }
    };
    if validate_space_id(&body.space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if !space_has_member(state, &body.space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "sender is not a joined member of the space",
        );
        return;
    }
    if !body.content.is_object() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "content must be a JSON object",
        );
        return;
    }
    if let Err(message) = validate_canonical_json_value(&body.content) {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if !body.encrypted && !space_allows_plaintext_service(state, &body.space_id) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "policy_denied",
            "private plaintext messages require this service in plaintext_visible_services",
        );
        return;
    }
    if body.encrypted
        && let Err(message) = validate_encrypted_payload_envelope(&body.content)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if !body.encrypted
        && let Err(message) = validate_content_blocks(&body.content)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if !body.encrypted
        && let Err(message) = validate_mentions(&body.content)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }

    let event_id = ids::generate_event_id();
    let thread_id = body.thread_id.unwrap_or_else(|| body.space_id.clone());
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "event_id": event_id,
        "sender": session.actor.clone(),
        "thread_id": thread_id.clone(),
        "content": body.content,
        "encrypted": body.encrypted,
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).expect("generated valid operation id"),
        SpaceId::new(body.space_id.clone()).expect("validated space id"),
        "message",
        payload.clone(),
    );
    let operation_digest = match operation.operation_digest().and_then(Hash::new) {
        Ok(digest) => digest,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "repo_error",
                &error.to_string(),
            );
            return;
        }
    };
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).expect("generated valid commit id"),
        session.actor.clone(),
        Did::new(session.actor.clone()).expect("session actor is valid"),
        next_author_seq(state, &session.actor),
    );
    commit.prev_commit = match state.repo.head(&session.actor) {
        Ok(Some(head)) => match Hash::new(head) {
            Ok(head) => Some(head),
            Err(error) => {
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "repo_error",
                    &error.to_string(),
                );
                return;
            }
        },
        Ok(None) => None,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "repo_error",
                &error.to_string(),
            );
            return;
        }
    };
    commit.operations.push(operation_digest);
    commit.proofs.push(dev_proof(&session.actor));

    let projection_event = projection_event_from_operation(&operation, Some(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    let head_commit = match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &RequireProof,
    ) {
        Ok(head_commit) => head_commit,
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
            return;
        }
    };
    // Apply to deterministic reducer
    if let Ok(mut proj) = state.projection.lock() {
        proj.apply(&operation, &state.hlc);
    }
    append_projection_event(state, projection_event);

    state
        .messages
        .lock()
        .expect("messages lock")
        .push(MessageRecord {
            event_id: event_id.clone(),
            space_id: body.space_id,
            sender: session.actor,
            thread_id,
            content: payload["content"].clone(),
            encrypted: body.encrypted,
            created_at: now(),
        });

    res.status_code(StatusCode::CREATED);
    res.render(Json(SendMessageResponse {
        event_id,
        operation_id,
        commit_id,
        head_commit,
        sync_token: sync_token(),
    }));
}

#[handler]
pub async fn revise_message(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<ReviseMessageRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid revise request",
            );
            return;
        }
    };
    let Some(original) = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .find(|m| m.event_id == body.event_id)
        .cloned()
    else {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "original message not found",
        );
        return;
    };
    if original.sender != session.actor {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "only the sender can revise a message",
        );
        return;
    }
    let new_event_id = ids::generate_event_id();
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "target_event_id": body.event_id,
        "new_event_id": new_event_id,
        "sender": session.actor,
        "content": body.content,
        "thread_id": original.thread_id,
        "encrypted": original.encrypted
    });
    let operation = contrix_sdk::Operation::create(
        contrix_sdk::OperationId::new(operation_id.clone()).unwrap(),
        contrix_sdk::SpaceId::new(original.space_id.clone()).unwrap(),
        "message.revise",
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = contrix_sdk::Commit::new(
        contrix_sdk::CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        contrix_sdk::Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit
        .operations
        .push(contrix_sdk::Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = state.repo.head(&session.actor).ok().flatten();
    if let Some(head) = expected_head.as_ref()
        && let Ok(head) = contrix_sdk::Hash::new(head.clone())
    {
        commit.prev_commit = Some(head);
    }
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, std::slice::from_ref(&operation));
            // Update in-memory message store
            {
                let mut messages = state.messages.lock().expect("messages lock");
                messages.push(MessageRecord {
                    event_id: new_event_id.clone(),
                    space_id: original.space_id.clone(),
                    sender: session.actor.clone(),
                    thread_id: original.thread_id.clone(),
                    content: body.content,
                    encrypted: original.encrypted,
                    created_at: now(),
                });
            }
            res.render(Json(ReviseMessageResponse {
                event_id: new_event_id,
                revision_of: body.event_id,
                operation_id,
                commit_id,
            }));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn redact_message(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<RedactMessageRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid redact request",
            );
            return;
        }
    };
    // Verify message exists
    let found = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .any(|m| m.event_id == body.event_id);
    if !found {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "message not found");
        return;
    }
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "target_event_id": body.event_id
    });
    let space_id = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .find(|m| m.event_id == body.event_id)
        .map(|m| m.space_id.clone())
        .unwrap_or_default();
    let operation = contrix_sdk::Operation::create(
        contrix_sdk::OperationId::new(operation_id.clone()).unwrap(),
        contrix_sdk::SpaceId::new(space_id.clone()).unwrap(),
        "redaction",
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = contrix_sdk::Commit::new(
        contrix_sdk::CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        contrix_sdk::Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit
        .operations
        .push(contrix_sdk::Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = state.repo.head(&session.actor).ok().flatten();
    if let Some(head) = expected_head.as_ref()
        && let Ok(head) = contrix_sdk::Hash::new(head.clone())
    {
        commit.prev_commit = Some(head);
    }
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, &[operation]);
            res.render(Json(RedactMessageResponse {
                redacted: true,
                event_id: body.event_id,
            }));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn add_reaction(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<AddReactionRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid reaction request",
            );
            return;
        }
    };
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "event_id": body.event_id,
        "actor": session.actor,
        "key": body.key
    });
    let operation = contrix_sdk::Operation::create(
        contrix_sdk::OperationId::new(operation_id.clone()).unwrap(),
        contrix_sdk::SpaceId::new(body.space_id.clone()).unwrap(),
        "reaction.add",
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = contrix_sdk::Commit::new(
        contrix_sdk::CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        contrix_sdk::Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit
        .operations
        .push(contrix_sdk::Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, &[operation]);
            res.render(Json(ReactionResponse {
                event_id: body.event_id,
                actor: session.actor.clone(),
                key: body.key,
                active: true,
            }));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn remove_reaction(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<RemoveReactionRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid reaction request",
            );
            return;
        }
    };
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "event_id": body.event_id,
        "actor": session.actor,
        "key": body.key
    });
    let operation = contrix_sdk::Operation::create(
        contrix_sdk::OperationId::new(operation_id.clone()).unwrap(),
        contrix_sdk::SpaceId::new(body.space_id.clone()).unwrap(),
        "reaction.remove",
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = contrix_sdk::Commit::new(
        contrix_sdk::CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        contrix_sdk::Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit
        .operations
        .push(contrix_sdk::Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, &[operation]);
            res.render(Json(ReactionResponse {
                event_id: body.event_id,
                actor: session.actor.clone(),
                key: body.key,
                active: false,
            }));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn set_read_marker(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<SetReadMarkerRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid read marker request",
            );
            return;
        }
    };
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let scope_id = body
        .scope_id
        .clone()
        .unwrap_or_else(|| "_default".to_owned());
    let payload = json!({
        "event_id": body.event_id,
        "sender": session.actor,
        "scope_id": scope_id
    });
    let operation = contrix_sdk::Operation::create(
        contrix_sdk::OperationId::new(operation_id.clone()).unwrap(),
        contrix_sdk::SpaceId::new(body.space_id.clone()).unwrap(),
        "read_marker",
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = contrix_sdk::Commit::new(
        contrix_sdk::CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        contrix_sdk::Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit
        .operations
        .push(contrix_sdk::Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, &[operation]);
            res.render(Json(ReadMarkerResponse {
                space_id: body.space_id,
                actor: session.actor.clone(),
                scope_id,
                event_id: body.event_id,
                read_at: now().to_rfc3339(),
            }));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn get_read_markers(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let space_id = query_param(req, "space_id").unwrap_or_default();
    let markers = {
        let proj = state.projection.lock().expect("projection lock");
        proj.read_markers
            .values()
            .filter(|m| m.actor == session.actor && (space_id.is_empty() || m.space_id == space_id))
            .map(|m| ReadMarkerResponse {
                space_id: m.space_id.clone(),
                actor: m.actor.clone(),
                scope_id: m.scope_id.clone(),
                event_id: m.event_id.clone(),
                read_at: m.read_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    res.render(Json(json!({ "markers": markers })));
}

// ── Entity CRUD ──

#[handler]
pub async fn create_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateEntityRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid entity request",
            );
            return;
        }
    };
    if validate_space_id(&body.space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if !space_has_member(state, &body.space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a joined member of the space",
        );
        return;
    }
    if !is_valid_entity_type(&body.entity_type) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "entity_type must be cx.* or a reverse-domain name",
        );
        return;
    }
    if let Some(content) = &body.content
        && let Err(message) = validate_canonical_json_value(content)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    for value in body.fields.values() {
        if let Err(message) = validate_canonical_json_value(value) {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    }
    let entity_id = ids::generate_entity_id();
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "entity_id": entity_id,
        "entity_type": body.entity_type,
        "title": body.title,
        "content": body.content,
        "fields": body.fields
    });
    let operation = contrix_sdk::Operation::create(
        contrix_sdk::OperationId::new(operation_id.clone()).unwrap(),
        contrix_sdk::SpaceId::new(body.space_id.clone()).unwrap(),
        "entity.create",
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = contrix_sdk::Commit::new(
        contrix_sdk::CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        contrix_sdk::Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit
        .operations
        .push(contrix_sdk::Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = state.repo.head(&session.actor).ok().flatten();
    if let Some(head) = expected_head.as_ref()
        && let Ok(head) = contrix_sdk::Hash::new(head.clone())
    {
        commit.prev_commit = Some(head);
    }
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, std::slice::from_ref(&operation));
            // Read back from projection
            let entity = {
                let proj = state.projection.lock().expect("projection lock");
                proj.entities.get(&entity_id).cloned()
            };
            if let Some(e) = entity {
                res.render(Json(EntityResponse {
                    entity_id: e.entity_id,
                    space_id: e.space_id,
                    entity_type: e.entity_type,
                    title: e.title,
                    content: e.content,
                    fields: e.fields,
                    deleted: e.deleted,
                    created_at: e.created_at.to_rfc3339(),
                    updated_at: e.updated_at.to_rfc3339(),
                }));
            } else {
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "projection_error",
                    "entity not found after creation",
                );
            }
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn get_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(entity_id) = req.param::<String>("entity_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "entity_id is required",
        );
        return;
    };
    let entity = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities.get(&entity_id).cloned()
    };
    match entity {
        Some(e) if !e.deleted => {
            res.render(Json(EntityResponse {
                entity_id: e.entity_id,
                space_id: e.space_id,
                entity_type: e.entity_type,
                title: e.title,
                content: e.content,
                fields: e.fields,
                deleted: e.deleted,
                created_at: e.created_at.to_rfc3339(),
                updated_at: e.updated_at.to_rfc3339(),
            }));
        }
        _ => {
            render_error(res, StatusCode::NOT_FOUND, "not_found", "entity not found");
        }
    }
}

#[handler]
pub async fn update_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(entity_id) = req.param::<String>("entity_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "entity_id is required",
        );
        return;
    };
    let body = match req.parse_json::<UpdateEntityRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid update request",
            );
            return;
        }
    };
    // Find the entity to get its space_id
    let space_id = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities.get(&entity_id).map(|e| e.space_id.clone())
    };
    let Some(space_id) = space_id else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "entity not found");
        return;
    };
    if !space_has_member(state, &space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a joined member of the space",
        );
        return;
    }
    if let Some(content) = &body.content
        && let Err(message) = validate_canonical_json_value(content)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    for value in body.fields.values() {
        if let Err(message) = validate_canonical_json_value(value) {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    }
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let mut payload = json!({ "entity_id": entity_id });
    if let Some(title) = &body.title {
        payload["title"] = json!(title);
    }
    if let Some(content) = &body.content {
        payload["content"] = content.clone();
    }
    if !body.fields.is_empty() {
        payload["fields"] = json!(body.fields);
    }
    let operation = contrix_sdk::Operation::create(
        contrix_sdk::OperationId::new(operation_id.clone()).unwrap(),
        contrix_sdk::SpaceId::new(space_id.clone()).unwrap(),
        "entity.update",
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = contrix_sdk::Commit::new(
        contrix_sdk::CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        contrix_sdk::Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit
        .operations
        .push(contrix_sdk::Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, std::slice::from_ref(&operation));
            let entity = {
                let proj = state.projection.lock().expect("projection lock");
                proj.entities.get(&entity_id).cloned()
            };
            if let Some(e) = entity {
                res.render(Json(EntityResponse {
                    entity_id: e.entity_id,
                    space_id: e.space_id,
                    entity_type: e.entity_type,
                    title: e.title,
                    content: e.content,
                    fields: e.fields,
                    deleted: e.deleted,
                    created_at: e.created_at.to_rfc3339(),
                    updated_at: e.updated_at.to_rfc3339(),
                }));
            } else {
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "projection_error",
                    "entity not found after update",
                );
            }
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn delete_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(entity_id) = req.param::<String>("entity_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "entity_id is required",
        );
        return;
    };
    let space_id = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities.get(&entity_id).map(|e| e.space_id.clone())
    };
    let Some(space_id) = space_id else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "entity not found");
        return;
    };
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let operation = contrix_sdk::Operation::create(
        contrix_sdk::OperationId::new(operation_id.clone()).unwrap(),
        contrix_sdk::SpaceId::new(space_id).unwrap(),
        "entity.delete",
        json!({ "entity_id": entity_id }),
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = contrix_sdk::Commit::new(
        contrix_sdk::CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        contrix_sdk::Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit
        .operations
        .push(contrix_sdk::Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, std::slice::from_ref(&operation));
            res.render(Json(json!({ "deleted": true, "entity_id": entity_id })));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn list_entities(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let space_id = query_param(req, "space_id").unwrap_or_default();
    let entity_type = query_param(req, "entity_type");
    let entities = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities_for_space(&space_id, entity_type.as_deref())
            .into_iter()
            .map(|e| EntityResponse {
                entity_id: e.entity_id.clone(),
                space_id: e.space_id.clone(),
                entity_type: e.entity_type.clone(),
                title: e.title.clone(),
                content: e.content.clone(),
                fields: e.fields.clone(),
                deleted: e.deleted,
                created_at: e.created_at.to_rfc3339(),
                updated_at: e.updated_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    res.render(Json(json!({ "entities": entities })));
}

// ── Relation CRUD ──

#[handler]
pub async fn create_relation(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateRelationRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid relation request",
            );
            return;
        }
    };
    if validate_space_id(&body.space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let relation_id = ids::generate_relation_id();
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "relation_id": relation_id,
        "relation_kind": body.relation_kind,
        "from": body.from,
        "to": body.to,
        "fields": body.fields
    });
    let operation = contrix_sdk::Operation::create(
        contrix_sdk::OperationId::new(operation_id.clone()).unwrap(),
        contrix_sdk::SpaceId::new(body.space_id.clone()).unwrap(),
        "relation.create",
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = contrix_sdk::Commit::new(
        contrix_sdk::CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        contrix_sdk::Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit
        .operations
        .push(contrix_sdk::Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, std::slice::from_ref(&operation));
            let relation = {
                let proj = state.projection.lock().expect("projection lock");
                proj.relations.get(&relation_id).cloned()
            };
            if let Some(r) = relation {
                res.render(Json(RelationResponse {
                    relation_id: r.relation_id,
                    space_id: r.space_id,
                    relation_kind: r.relation_kind,
                    from: r.from_ref,
                    to: r.to_ref,
                    fields: r.fields,
                    deleted: r.deleted,
                    created_at: r.created_at.to_rfc3339(),
                }));
            } else {
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "projection_error",
                    "relation not found after creation",
                );
            }
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn delete_relation(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(relation_id) = req.param::<String>("relation_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "relation_id is required",
        );
        return;
    };
    let space_id = {
        let proj = state.projection.lock().expect("projection lock");
        proj.relations.get(&relation_id).map(|r| r.space_id.clone())
    };
    let Some(space_id) = space_id else {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "relation not found",
        );
        return;
    };
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let operation = contrix_sdk::Operation::create(
        contrix_sdk::OperationId::new(operation_id.clone()).unwrap(),
        contrix_sdk::SpaceId::new(space_id).unwrap(),
        "relation.delete",
        json!({ "relation_id": relation_id }),
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = contrix_sdk::Commit::new(
        contrix_sdk::CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        contrix_sdk::Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit
        .operations
        .push(contrix_sdk::Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, std::slice::from_ref(&operation));
            res.render(Json(json!({ "deleted": true, "relation_id": relation_id })));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn list_relations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let space_id = query_param(req, "space_id").unwrap_or_default();
    let kind = query_param(req, "kind");
    let relations = {
        let proj = state.projection.lock().expect("projection lock");
        proj.relations_for_space(&space_id, kind.as_deref())
            .into_iter()
            .map(|r| RelationResponse {
                relation_id: r.relation_id.clone(),
                space_id: r.space_id.clone(),
                relation_kind: r.relation_kind.clone(),
                from: r.from_ref.clone(),
                to: r.to_ref.clone(),
                fields: r.fields.clone(),
                deleted: r.deleted,
                created_at: r.created_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    res.render(Json(json!({ "relations": relations })));
}

// ── View endpoints ──

#[handler]
pub async fn create_view(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateViewRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid view request",
            );
            return;
        }
    };
    let view_id = ids::generate_view_id();
    let entities = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities_for_space(&body.space_id, body.entity_type.as_deref())
            .into_iter()
            .map(|e| EntityResponse {
                entity_id: e.entity_id.clone(),
                space_id: e.space_id.clone(),
                entity_type: e.entity_type.clone(),
                title: e.title.clone(),
                content: e.content.clone(),
                fields: e.fields.clone(),
                deleted: e.deleted,
                created_at: e.created_at.to_rfc3339(),
                updated_at: e.updated_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    res.render(Json(ViewResponse {
        view_id,
        space_id: body.space_id,
        kind: body.kind,
        title: body.title,
        entities,
        created_at: now().to_rfc3339(),
    }));
}

#[handler]
pub async fn get_view(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(view_id) = req.param::<String>("view_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "view_id is required",
        );
        return;
    };
    // Views are virtual — return current projection data
    let space_id = query_param(req, "space_id").unwrap_or_default();
    let entity_type = query_param(req, "entity_type");
    let entities = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities_for_space(&space_id, entity_type.as_deref())
            .into_iter()
            .map(|e| EntityResponse {
                entity_id: e.entity_id.clone(),
                space_id: e.space_id.clone(),
                entity_type: e.entity_type.clone(),
                title: e.title.clone(),
                content: e.content.clone(),
                fields: e.fields.clone(),
                deleted: e.deleted,
                created_at: e.created_at.to_rfc3339(),
                updated_at: e.updated_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    res.render(Json(ViewResponse {
        view_id,
        space_id,
        kind: "list".to_owned(),
        title: None,
        entities,
        created_at: now().to_rfc3339(),
    }));
}

struct DevProofVerifier;
impl contrix_sdk::CommitProofVerifier for DevProofVerifier {
    fn verify_commit(&self, commit: &contrix_sdk::Commit) -> contrix_sdk::Result<()> {
        if commit.proofs.is_empty() {
            return Err(contrix_sdk::Error::Protocol(
                "commit proofs must contain at least one proof".to_owned(),
            ));
        }
        Ok(())
    }
}

#[handler]
pub async fn identity_describe(res: &mut Response) {
    res.render(Json(IdentityDescribeResponse {
        service_did: "did:web:soland.local".to_owned(),
        registry_mode: "development_local".to_owned(),
        supported_receipts: vec!["local".to_owned()],
        protocol_version: "1.0".to_owned(),
        profiles: vec!["cx.identity.local-dev.v1".to_owned()],
    }));
}

#[handler]
pub async fn identity_resolve(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<IdentityResolveRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid identity resolve request",
            );
            return;
        }
    };
    if validate_did(&body.did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    let record = identity_document_record(state, &body.did);
    res.render(Json(IdentityResolveResponse {
        did_document: record.did_document,
        key_log_head: record.key_log_head,
        seq: record.seq,
        receipts: Vec::new(),
        method_evidence: record.method_evidence,
    }));
}

#[handler]
pub async fn identity_document(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(did) = query_param(req, "did") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "did is required",
        );
        return;
    };
    render_identity_document(state, res, did);
}

#[handler]
pub async fn identity_log(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(did) = query_param(req, "did") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "did is required",
        );
        return;
    };
    if validate_did(&did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    let events = state
        .identity_log_events
        .lock()
        .expect("identity log lock")
        .get(&did)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|event| {
            json!({
                "event_hash": event.event_hash,
                "did": event.did,
                "seq": event.seq,
                "operation": event.operation,
                "created_at": event.created_at,
            })
        })
        .collect();
    res.render(Json(IdentityLogResponse {
        events,
        next_cursor: None,
        has_more: false,
    }));
}

#[handler]
pub async fn submit_did_operation(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<SubmitDidOperationRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid DID operation request",
            );
            return;
        }
    };
    if validate_did(&body.did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    if body.proofs.is_empty() {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_signature",
            "DID operation requires proof material",
        );
        return;
    }
    let previous = state
        .identity_documents
        .lock()
        .expect("identity documents lock")
        .get(&body.did)
        .cloned();
    if let Some(previous) = &previous {
        if body.seq != previous.seq + 1 {
            render_error(
                res,
                StatusCode::CONFLICT,
                "cas_conflict",
                "DID operation seq must advance the current key log",
            );
            return;
        }
        if body.prev_event_hash.as_deref() != previous.key_log_head.as_deref() {
            render_error(
                res,
                StatusCode::CONFLICT,
                "cas_conflict",
                "prev_event_hash does not match current key log head",
            );
            return;
        }
    } else if body.seq != 1 {
        render_error(
            res,
            StatusCode::CONFLICT,
            "cas_conflict",
            "first DID operation seq must be 1",
        );
        return;
    }
    let head_event_hash = format!("sha256:{}", sha256_hex(body.patch.to_string().as_bytes()));
    let did_document = did_document_from_patch(&body.did, &body.patch)
        .unwrap_or_else(|| default_did_document(&body.did));
    let now = now();
    state
        .identity_documents
        .lock()
        .expect("identity documents lock")
        .insert(
            body.did.clone(),
            IdentityDocumentRecord {
                did: body.did.clone(),
                did_document,
                key_log_head: Some(head_event_hash.clone()),
                seq: body.seq,
                method_evidence: json!({"mode": "development_local", "source": "did_operation"}),
                updated_at: now,
            },
        );
    state
        .identity_log_events
        .lock()
        .expect("identity log lock")
        .entry(body.did.clone())
        .or_default()
        .push(IdentityLogRecord {
            event_hash: head_event_hash.clone(),
            did: body.did.clone(),
            seq: body.seq,
            operation: body.patch,
            created_at: now,
        });
    append_audit_log(
        state,
        Some(&body.did),
        "identity.did_operation",
        json!({"did": body.did, "seq": body.seq, "head_event_hash": head_event_hash.clone()}),
        "accepted",
    );
    res.render(Json(SubmitDidOperationResponse {
        status: "accepted".to_owned(),
        head_event_hash,
        seq: body.seq,
        receipts: vec![json!({"service_did": "did:web:soland.local", "issued_at": now})],
    }));
}

#[handler]
pub async fn identity_receipts(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(did) = query_param(req, "did") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "did is required",
        );
        return;
    };
    if validate_did(&did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    let record = state
        .identity_documents
        .lock()
        .expect("identity documents lock")
        .get(&did)
        .cloned();
    res.render(Json(IdentityReceiptsResponse {
        receipts: record
            .map(|record| {
                vec![json!({
                    "service_did": "did:web:soland.local",
                    "did": record.did,
                    "head_event_hash": record.key_log_head,
                    "seq": record.seq,
                    "issued_at": record.updated_at,
                })]
            })
            .unwrap_or_default(),
        threshold_met: true,
    }));
}

#[handler]
pub async fn sync_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(SyncDescribeResponse {
        service_did: "did:web:soland.local".to_owned(),
        supported_sync_profiles: vec![
            "initial".to_owned(),
            "incremental".to_owned(),
            "board".to_owned(),
            "chat".to_owned(),
            "topic".to_owned(),
        ],
        limits: json!({"max_spaces": 50, "max_timeline_events": 100}),
        frontier: json!({"storage": state.db.mode(), "generated_at": now()}),
    }));
}

#[handler]
pub async fn client_sync(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _body = match req.parse_json::<ClientSyncRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid sync request",
            );
            return;
        }
    };
    if let Some(presence) = _body.set_presence.as_deref()
        && !matches!(presence, "online" | "offline" | "unavailable")
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "set_presence must be online, offline, or unavailable",
        );
        return;
    }
    if let Some(profile) = _body.profile.as_deref()
        && !matches!(
            profile,
            "initial" | "incremental" | "board" | "chat" | "topic"
        )
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "profile must be initial, incremental, board, chat, or topic",
        );
        return;
    }

    let session = authenticated_session(state, req).ok();
    if let Some(presence) = _body.set_presence.as_deref() {
        let Some(session) = session.as_ref() else {
            render_error(
                res,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "set_presence requires authentication",
            );
            return;
        };
        state.presence.lock().expect("presence lock").insert(
            session.actor.clone(),
            PresenceRecord {
                actor: session.actor.clone(),
                status: presence.to_owned(),
                updated_at: chrono::Utc::now(),
            },
        );
    }
    let visible_spaces: Vec<_> = {
        let spaces = state.spaces.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .filter(|space| space_visible_to(state, space, session.as_ref()))
            .map(|space| {
                (
                    space.space_id.to_string(),
                    space.name.clone(),
                    space.description.clone(),
                    space.tags.clone(),
                    space.category.clone(),
                )
            })
            .collect()
    };
    let projection = state.projection.lock().expect("projection lock");
    let mut sync_spaces = std::collections::BTreeMap::new();
    for (space_id, title, summary, tags, category) in visible_spaces {
        let timeline_events: Vec<_> = projection
            .messages_for_space(&space_id)
            .into_iter()
            .map(|message| {
                json!({
                    "kind": "message",
                    "event_id": message.event_id,
                    "space_id": message.space_id,
                    "thread_id": message.thread_id,
                    "sender": message.sender,
                    "content": message.content,
                    "encrypted": message.encrypted,
                    "created_at": message.created_at,
                })
            })
            .collect();
        sync_spaces.insert(
            space_id,
            json!({
                "summary": {
                    "title": title,
                    "summary": summary,
                    "tags": tags,
                    "category": category,
                },
                "timeline": {"events": timeline_events, "limited": false},
                "state": [],
                "ephemeral": [],
                "unread": {"notification_count": 0, "highlight_count": 0}
            }),
        );
    }

    let to_device = session
        .map(|session| {
            let mut queue = state.device_messages.lock().expect("device message lock");
            let mut drained = Vec::new();
            queue.retain(|message| {
                let mine =
                    message.recipient == session.actor && message.device_id == session.device_id;
                if mine {
                    drained.push(json!({
                        "txn_id": message.txn_id,
                        "sender": message.sender,
                        "recipient": message.recipient,
                        "device_id": message.device_id,
                        "content": message.content,
                        "created_at": message.created_at
                    }));
                }
                !mine
            });
            drained
        })
        .unwrap_or_default();

    res.render(Json(ClientSyncResponse {
        next_batch: sync_token(),
        spaces: sync_spaces,
        to_device,
        account_data: Vec::new(),
        device_lists: json!({"changed": [], "left": []}),
    }));
}

#[handler]
pub async fn directory_describe(res: &mut Response) {
    res.render(Json(DirectoryDescribeResponse {
        service_did: "did:web:soland.local".to_owned(),
        resource_types: vec![
            "space".to_owned(),
            "organization".to_owned(),
            "actor".to_owned(),
        ],
        discovery_profiles: vec!["cx.profile.directory.v1".to_owned()],
        restricted_query_proof: false,
    }));
}

#[handler]
pub async fn search_spaces(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<SearchSpacesRequest>()
        .await
        .unwrap_or(SearchSpacesRequest {
            query: None,
            limit: Some(20),
        });
    let query = contrix_sdk::SpaceSearchQuery {
        text: body.query,
        public_only: false,
        limit: body.limit,
        ..Default::default()
    };
    let session = authenticated_session(state, req).ok();
    let spaces = state.spaces.lock().expect("spaces lock");
    let results = spaces
        .search(query)
        .into_iter()
        .filter(|space| space_search_visible_to(state, space, session.as_ref()))
        .cloned()
        .collect();
    res.render(Json(SearchSpacesResponse {
        results,
        next_cursor: None,
    }));
}

#[handler]
pub async fn resolve_space(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<ResolveSpaceRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid resolve space request",
            );
            return;
        }
    };
    if body.space_id.is_none()
        && body.alias.is_none()
        && body.invite_token.is_none()
        && body.signed_link.is_none()
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "one of space_id, alias, invite_token, or signed_link is required",
        );
        return;
    }

    let session = authenticated_session(state, req).ok();
    let invite_space_id = body
        .invite_token
        .as_deref()
        .and_then(|token| invite_token_space_id(state, token));
    let spaces = state.spaces.lock().expect("spaces lock");
    let space = spaces.search(Default::default()).into_iter().find(|entry| {
        space_resolvable_to(
            state,
            entry,
            session.as_ref(),
            body.invite_token.as_deref(),
            body.signed_link.as_deref(),
        ) && (body
            .space_id
            .as_deref()
            .is_some_and(|id| id == entry.space_id.as_str())
            || invite_space_id
                .as_deref()
                .is_some_and(|id| id == entry.space_id.as_str())
            || body
                .alias
                .as_deref()
                .is_some_and(|alias| alias.eq_ignore_ascii_case(&entry.name)))
    });
    match space {
        Some(space) => res.render(Json(ResolveSpaceResponse {
            space_preview: space.clone(),
            stripped_state: vec![json!({
                "type": "cx.space.discovery",
                "state_key": "",
                "content": {
                    "discoverability": space_discoverability(state, space.space_id.as_str()),
                    "directory_visibility": {
                        "searchable": space_search_discoverability(state, space.space_id.as_str())
                    }
                }
            })],
            join_rule: if space_discoverability(state, space.space_id.as_str()) == "public" {
                "public".to_owned()
            } else {
                "invite_or_request".to_owned()
            },
            via_services: vec!["did:web:soland.local".to_owned()],
        })),
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

#[handler]
pub async fn search_organizations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<SearchOrganizationsRequest>()
        .await
        .unwrap_or(SearchOrganizationsRequest {
            query: None,
            limit: Some(20),
        });
    let Some(limit) = checked_limit(res, body.limit) else {
        return;
    };
    let spaces = state.spaces.lock().expect("spaces lock");
    let space_entries: Vec<_> = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| !is_space_deleted(state, space.space_id.as_str()))
        .collect();
    let organization = demo_organization(&space_entries);
    let results = if query_matches(&organization, body.query.as_deref()) {
        vec![organization]
    } else {
        Vec::new()
    };
    res.render(Json(DirectoryValueSearchResponse {
        results: results.into_iter().take(limit).collect(),
        next_cursor: None,
    }));
}

#[handler]
pub async fn resolve_organization(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<ResolveOrganizationRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid resolve organization request",
            );
            return;
        }
    };
    if body.organization_id.is_none() && body.handle.is_none() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "organization_id or handle is required",
        );
        return;
    }

    let spaces = state.spaces.lock().expect("spaces lock");
    let space_entries: Vec<_> = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| !is_space_deleted(state, space.space_id.as_str()))
        .collect();
    let organization = demo_organization(&space_entries);
    let matches_id = body
        .organization_id
        .as_deref()
        .is_some_and(|id| id == organization["organization_id"].as_str().unwrap_or_default());
    let matches_handle = body
        .handle
        .as_deref()
        .is_some_and(|handle| handle.eq_ignore_ascii_case("@contrix-demo"));
    if !matches_id && !matches_handle {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }

    let spaces = space_entries
        .into_iter()
        .map(|space| {
            json!({
                "space_id": space.space_id,
                "name": space.name,
                "description": space.description,
                "category": space.category,
            })
        })
        .collect();
    res.render(Json(ResolveOrganizationResponse {
        organization,
        spaces,
    }));
}

#[handler]
pub async fn search_actors(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<SearchActorsRequest>()
        .await
        .unwrap_or(SearchActorsRequest {
            query: None,
            organization_id: None,
            limit: Some(20),
        });
    let Some(limit) = checked_limit(res, body.limit) else {
        return;
    };
    if let Some(organization_id) = body.organization_id.as_deref()
        && organization_id != "cx:org:demo"
    {
        res.render(Json(DirectoryValueSearchResponse {
            results: Vec::new(),
            next_cursor: None,
        }));
        return;
    }

    let session = authenticated_session(state, req).ok();
    let results: Vec<_> = demo_actors(state)
        .into_iter()
        .filter(|actor| actor_visible_to(state, actor, session.as_ref()))
        .filter(|actor| query_matches(actor, body.query.as_deref()))
        .take(limit)
        .collect();
    res.render(Json(DirectoryValueSearchResponse {
        results,
        next_cursor: None,
    }));
}

#[handler]
pub async fn search_users(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(limit) = query_limit(req, res) else {
        return;
    };
    let query = query_param(req, "query").or_else(|| query_param(req, "q"));
    let session = authenticated_session(state, req).ok();
    let results: Vec<_> = demo_actors(state)
        .into_iter()
        .filter(|actor| actor_visible_to(state, actor, session.as_ref()))
        .filter(|actor| query_matches(actor, query.as_deref()))
        .take(limit)
        .collect();
    res.render(Json(DirectoryValueSearchResponse {
        results,
        next_cursor: None,
    }));
}

#[handler]
pub async fn resolve_handle(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<ResolveHandleRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid resolve handle request",
            );
            return;
        }
    };
    if body.handle.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "handle is required",
        );
        return;
    }
    let normalized = normalize_handle(&body.handle);
    let session = authenticated_session(state, req).ok();
    let actor = demo_actors(state).into_iter().find(|actor| {
        actor_visible_to(state, actor, session.as_ref())
            && actor["handle"]
                .as_str()
                .is_some_and(|handle| handle == normalized)
    });
    match actor {
        Some(actor) => res.render(Json(ResolveHandleResponse {
            handle: normalized,
            did: actor["did"].as_str().unwrap_or_default().to_owned(),
            actor,
        })),
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

#[handler]
pub async fn index_describe(res: &mut Response) {
    res.render(Json(IndexDescribeResponse {
        service_did: "did:web:soland.local".to_owned(),
        reducer_profiles: vec!["cx.reducer.v1".to_owned()],
        schema_profiles: vec!["cx.schema.core.v1".to_owned()],
        query_features: vec![
            "space_preview".to_owned(),
            "entity_type_filter".to_owned(),
            "space_filter".to_owned(),
        ],
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[handler]
pub async fn index_query(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<IndexQueryRequest>()
        .await
        .unwrap_or(IndexQueryRequest {
            space_ids: Vec::new(),
            entity_types: Vec::new(),
            limit: Some(20),
        });
    let spaces = state.spaces.lock().expect("spaces lock");
    let session = authenticated_session(state, req).ok();
    let results = spaces
        .search(Default::default())
        .into_iter()
        .filter(|entry| {
            space_visible_to(state, entry, session.as_ref())
                && (body.space_ids.is_empty()
                    || body
                        .space_ids
                        .iter()
                        .any(|id| id == entry.space_id.as_str()))
        })
        .take(body.limit.unwrap_or(20))
        .map(|entry| {
            json!({
                "kind": "space_preview",
                "space_id": entry.space_id,
                "title": entry.name,
                "summary": entry.description,
                "entity_types": body.entity_types,
            })
        })
        .collect();
    res.render(Json(IndexQueryResponse {
        results,
        next_cursor: None,
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[handler]
pub async fn index_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let entity_id = query_param(req, "entity_id").or_else(|| query_param(req, "id"));
    let Some(entity_id) = entity_id else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "entity_id is required",
        );
        return;
    };
    if entity_id.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "entity_id must not be empty",
        );
        return;
    }

    let entity = find_demo_entity(state, &entity_id);
    match entity {
        Some(entity) => res.render(Json(IndexEntityResponse {
            entity,
            frontier: json!({"next_batch": sync_token()}),
        })),
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

#[handler]
pub async fn index_thread(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let thread_id = query_param(req, "thread_id").or_else(|| query_param(req, "id"));
    let Some(thread_id) = thread_id else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "thread_id is required",
        );
        return;
    };
    if thread_id.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "thread_id must not be empty",
        );
        return;
    }
    let session = authenticated_session(state, req).ok();
    // Use projection state for thread messages
    let projection = state.projection.lock().expect("projection lock");
    let events: Vec<_> = projection
        .messages_for_thread(&thread_id)
        .into_iter()
        .filter(|message| {
            message.redacted_at.is_none()
                && space_id_visible_to(state, &message.space_id, session.as_ref())
        })
        .map(|message| {
            json!({
                "event_id": message.event_id,
                "space_id": message.space_id,
                "sender": message.sender,
                "thread_id": message.thread_id,
                "content": message.content,
                "encrypted": message.encrypted,
                "created_at": message.created_at,
            })
        })
        .collect();
    let first_space_id = events
        .first()
        .and_then(|event| event["space_id"].as_str())
        .unwrap_or("cx:space:01js0sp0000000000000000000");
    res.render(Json(IndexThreadResponse {
        thread: json!({
            "thread_id": thread_id,
            "title": "Thread",
            "space_id": first_space_id,
            "reply_count": events.len(),
        }),
        events,
        next_cursor: None,
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[handler]
pub async fn index_notifications(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(limit) = query_limit(req, res) else {
        return;
    };
    let actor = query_param(req, "actor").unwrap_or_else(|| "did:web:alice.example".to_owned());
    if Did::new(actor.clone()).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid actor",
        );
        return;
    }
    // Use projection state for notifications
    let projection = state.projection.lock().expect("projection lock");
    let notifications: Vec<_> = projection
        .messages
        .values()
        .filter(|message| {
            message.sender != actor
                && message.redacted_at.is_none()
                && space_has_member(state, &message.space_id, &actor)
        })
        .map(|message| {
            json!({
                "notification_id": format!("cx:notification:{}", message.event_id.trim_start_matches("cx:event:")),
                "actor": actor,
                "space_id": message.space_id,
                "event_ref": message.event_id,
                "sender": message.sender,
                "encrypted": message.encrypted,
                "preview": (!message.encrypted).then(|| message.content.clone()),
                "created_at": message.created_at,
            })
        })
        .take(limit)
        .collect();
    let unread_count = notifications.len();
    res.render(Json(IndexNotificationsResponse {
        notifications,
        next_cursor: None,
        unread_count,
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[handler]
pub async fn index_inbox(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(limit) = query_limit(req, res) else {
        return;
    };
    let spaces = state.spaces.lock().expect("spaces lock");
    let session = authenticated_session(state, req).ok();
    // Use projection state for last message
    let projection = state.projection.lock().expect("projection lock");
    let rooms = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| space_visible_to(state, space, session.as_ref()))
        .take(limit)
        .map(|space| {
            let last_message = projection
                .messages_for_space(space.space_id.as_str())
                .into_iter()
                .next_back()
                .filter(|m| m.redacted_at.is_none())
                .map(|message| {
                    json!({
                        "event_id": message.event_id,
                        "space_id": message.space_id,
                        "sender": message.sender,
                        "content": message.content,
                        "encrypted": message.encrypted,
                        "created_at": message.created_at,
                    })
                });
            json!({
                "space_id": space.space_id,
                "name": space.name,
                "summary": space.description,
                "unread": {"notification_count": 0, "highlight_count": 0},
                "last_activity_at": now(),
                "last_message": last_message,
            })
        })
        .collect();
    res.render(Json(IndexInboxResponse {
        rooms,
        next_cursor: None,
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[handler]
pub async fn index_search(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<IndexSearchRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid index search request",
            );
            return;
        }
    };
    if body.query.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "query is required",
        );
        return;
    }
    let Some(limit) = checked_limit(res, body.limit) else {
        return;
    };

    let mut results = Vec::new();
    let spaces = state.spaces.lock().expect("spaces lock");
    let session = authenticated_session(state, req).ok();
    for space in spaces.search(Default::default()) {
        if !space_visible_to(state, space, session.as_ref()) {
            continue;
        }
        if !body.space_ids.is_empty()
            && !body
                .space_ids
                .iter()
                .any(|space_id| space_id == space.space_id.as_str())
        {
            continue;
        }
        let entity = json!({
            "kind": "space",
            "entity_id": space.space_id,
            "space_id": space.space_id,
            "title": space.name,
            "summary": space.description,
        });
        if (body.entity_types.is_empty() || body.entity_types.iter().any(|kind| kind == "space"))
            && query_matches(&entity, Some(&body.query))
        {
            results.push(entity);
        }
    }
    drop(spaces);

    // Use projection state for message search
    let projection = state.projection.lock().expect("projection lock");
    for message in projection.messages.values() {
        if message.encrypted
            || message.redacted_at.is_some()
            || !space_id_visible_to(state, &message.space_id, session.as_ref())
        {
            continue;
        }
        if !body.space_ids.is_empty()
            && !body
                .space_ids
                .iter()
                .any(|space_id| space_id == &message.space_id)
        {
            continue;
        }
        let entity = json!({
            "event_id": message.event_id,
            "space_id": message.space_id,
            "sender": message.sender,
            "content": message.content,
            "encrypted": message.encrypted,
            "created_at": message.created_at,
        });
        if (body.entity_types.is_empty() || body.entity_types.iter().any(|kind| kind == "message"))
            && query_matches(&entity, Some(&body.query))
        {
            results.push(entity);
        }
    }

    if body.entity_types.is_empty() || body.entity_types.iter().any(|kind| kind == "actor") {
        results.extend(
            demo_actors(state)
                .into_iter()
                .filter(|actor| query_matches(actor, Some(&body.query))),
        );
    }
    results.truncate(limit);
    res.render(Json(IndexSearchResponse {
        results,
        next_cursor: None,
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[handler]
pub async fn index_space_hierarchy(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let root_space_id = query_param(req, "root_space_id")
        .or_else(|| query_param(req, "space_id"))
        .unwrap_or_else(|| "cx:space:01js0sp0000000000000000000".to_owned());
    if SpaceId::new(root_space_id.clone()).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid root_space_id",
        );
        return;
    }
    let spaces = state.spaces.lock().expect("spaces lock");
    let session = authenticated_session(state, req).ok();
    let space_values: Vec<_> = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| space_visible_to(state, space, session.as_ref()))
        .map(|space| {
            json!({
                "space_id": space.space_id,
                "name": space.name,
                "description": space.description,
                "parent_space_id": null,
            })
        })
        .collect();
    if !space_values.iter().any(|space| {
        space["space_id"]
            .as_str()
            .is_some_and(|id| id == root_space_id)
    }) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    res.render(Json(IndexSpaceHierarchyResponse {
        root_space_id,
        spaces: space_values,
        edges: Vec::new(),
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[handler]
pub async fn sync_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let session = authenticated_session(state, req).ok();
    if !space_id_accessible(state, &space_id, session.as_ref()) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(100);
    let cursor = query_param(req, "cursor");
    match projected_event_page(state, &space_id, cursor.as_deref(), limit) {
        Ok(Some(page)) => {
            let frames: Vec<_> = page
                .items
                .into_iter()
                .enumerate()
                .map(|(index, event)| {
                    let cursor = event.event_id.clone();
                    json!({
                        "type": "event",
                        "seq": index + 1,
                        "cursor": cursor,
                        "payload": projection_event_json(&event)
                    })
                })
                .collect();
            res.render(Json(json!({
                "frames": frames,
                "next_cursor": page.next_cursor.or_else(|| Some(sync_token())),
                "has_more": page.has_more
            })));
        }
        Ok(None) => match state
            .repo
            .sync_space_operations(&space_id, cursor.as_deref(), limit)
        {
            Ok(page) => {
                let mut seq = 0usize;
                let frames: Vec<_> = page
                    .items
                    .into_iter()
                    .map(|operation| {
                        seq += 1;
                        let cursor = operation.operation_id.to_string();
                        json!({
                            "type": "operation",
                            "seq": seq,
                            "cursor": cursor,
                            "payload": operation
                        })
                    })
                    .collect();
                res.render(Json(json!({
                    "frames": frames,
                    "next_cursor": page.next_cursor.or_else(|| Some(sync_token())),
                    "has_more": page.has_more
                })));
            }
            Err(error) => render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "repo_error",
                &error.to_string(),
            ),
        },
        Err(error) => render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "projection_error",
            &error.to_string(),
        ),
    }
}

#[handler]
pub async fn sync_backfill(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let session = authenticated_session(state, req).ok();
    if !space_id_accessible(state, &space_id, session.as_ref()) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(100);
    let cursor = query_param(req, "cursor");
    match projected_event_page(state, &space_id, cursor.as_deref(), limit) {
        Ok(Some(page)) => {
            let events = page.items.iter().map(projection_event_json).collect();
            res.render(Json(BackfillResponse {
                events,
                prev_cursor: cursor,
                next_cursor: page.next_cursor.or_else(|| Some(sync_token())),
                limited: page.has_more,
            }));
            return;
        }
        Ok(None) => {}
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "projection_error",
                &error.to_string(),
            );
            return;
        }
    }
    let page = match state
        .repo
        .sync_space_operations(&space_id, cursor.as_deref(), limit)
    {
        Ok(page) => page,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "repo_error",
                &error.to_string(),
            );
            return;
        }
    };
    let redacted = redaction_targets_from_operations(&page.items);
    let events: Vec<_> = page
        .items
        .into_iter()
        .filter(|operation| operation_is_visible(operation, &redacted))
        .map(|operation| {
            let event_id = operation_event_id(&operation);
            json!({
                "event_id": event_id,
                "space_id": operation.space_id,
                "event_type": operation.object_type,
                "operation_type": operation.operation_type,
                "payload": operation.payload,
                "created_at": operation.created_at
            })
        })
        .collect();
    res.render(Json(BackfillResponse {
        events,
        prev_cursor: cursor,
        next_cursor: page.next_cursor.or_else(|| Some(sync_token())),
        limited: page.has_more,
    }));
}

#[handler]
pub async fn snapshot_head(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if is_space_deleted(state, &space_id) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let Ok(space_id_value) = SpaceId::new(space_id.clone()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    };
    let spaces = state.spaces.lock().expect("spaces lock");
    let Some(space) = spaces.get(&space_id_value) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    };
    let messages: Vec<_> = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .filter(|message| message.space_id == space_id)
        .map(message_event)
        .collect();
    let manifest = json!({
        "space_id": space_id,
        "title": space.name,
        "members": space.members.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "message_count": messages.len(),
        "messages": messages,
        "generated_at": now(),
    });
    let state_hash = format!("sha256:{}", sha256_hex(manifest.to_string().as_bytes()));
    let snapshot_ref = format!(
        "cx:snapshot:{}:{}",
        space_id,
        state_hash.trim_start_matches("sha256:")
    );
    let signature_payload = format!("{snapshot_ref}:{state_hash}:did:web:soland.local");
    res.render(Json(SnapshotHeadResponse {
        snapshot_ref,
        state_hash,
        frontier: json!({"space_id": space_id, "generated_at": now(), "message_count": manifest["message_count"]}),
        signature: json!({
            "kid": "did:web:soland.local#snapshot-dev",
            "alg": "sha256-dev",
            "sig": sha256_hex(signature_payload.as_bytes())
        }),
    }));
}

#[handler]
pub async fn repo_describe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let repo_id = query_param(req, "repo_id").unwrap_or_else(|| "did:web:soland.local".to_owned());
    let head_commit = match state.repo.head(&repo_id) {
        Ok(head) => head,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "repo_error",
                &error.to_string(),
            );
            return;
        }
    };
    res.render(Json(RepoDescribeResponse {
        repo_did: repo_id,
        head_commit,
        supported_signatures: vec![
            "detached_jws".to_owned(),
            "http_message_signature".to_owned(),
        ],
        limits: json!({"max_commits": 100, "max_operations": 500}),
    }));
}

#[handler]
pub async fn list_commits(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(100);
    let repo_id = query_param(req, "repo_id").unwrap_or_else(|| "did:web:soland.local".to_owned());
    match state
        .repo
        .list_commits(&repo_id, query_param(req, "cursor").as_deref(), limit)
    {
        Ok(page) => res.render(Json(ListCommitsResponse {
            commits: page.items,
            next_cursor: page.next_cursor,
            has_more: page.has_more,
        })),
        Err(error) => render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "repo_error",
            &error.to_string(),
        ),
    }
}

#[handler]
pub async fn get_commit(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(commit_id) = query_param(req, "commit_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "commit_id is required",
        );
        return;
    };
    let Ok(commit_id) = CommitId::new(commit_id.clone()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid commit_id",
        );
        return;
    };
    match state.repo.get_commit(&commit_id) {
        Ok(Some(commit)) => {
            let include_operations =
                query_flag(req, "include_operations") || query_flag(req, "expand_operations");
            let operations = if include_operations {
                match state.repo.get_operations_by_digests(
                    &commit
                        .operations
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                ) {
                    Ok(operations) => operations,
                    Err(error) => {
                        render_error(
                            res,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "repo_error",
                            &error.to_string(),
                        );
                        return;
                    }
                }
            } else {
                Vec::new()
            };
            let proofs = commit.proofs.clone();
            res.render(Json(
                json!({"commit": commit, "operations": operations, "proofs": proofs}),
            ))
        }
        Ok(None) => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
        Err(error) => render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "repo_error",
            &error.to_string(),
        ),
    }
}

#[handler]
pub async fn get_operations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<GetOperationsRequest>()
        .await
        .unwrap_or(GetOperationsRequest {
            operation_ids: Vec::new(),
            include_payload: true,
        });
    match state.repo.get_operations(&body.operation_ids, 500) {
        Ok((operations, missing)) => res.render(Json(GetOperationsResponse {
            operations,
            missing,
            unauthorized: Vec::new(),
        })),
        Err(error) => render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "repo_error",
            &error.to_string(),
        ),
    }
}

#[handler]
pub async fn repo_sync(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<RepoSyncRequest>()
        .await
        .unwrap_or(RepoSyncRequest {
            repo_id: "did:web:soland.local".to_owned(),
            since: None,
            limit: Some(100),
            filters: None,
        });
    let limit = body.limit.unwrap_or(100).min(500);
    match state
        .repo
        .sync_operations(&body.repo_id, body.since.as_deref(), limit)
    {
        Ok(page) => res.render(Json(RepoSyncResponse {
            operations: page.items,
            next_cursor: page.next_cursor.or_else(|| Some(sync_token())),
            has_more: page.has_more,
        })),
        Err(error) => render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "repo_error",
            &error.to_string(),
        ),
    }
}

#[handler]
pub async fn submit_commit(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<SubmitCommitRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid submit commit request",
            );
            return;
        }
    };

    struct RequireProof;
    impl CommitProofVerifier for RequireProof {
        fn verify_commit(&self, commit: &contrix_sdk::Commit) -> contrix_sdk::Result<()> {
            if commit.proofs.is_empty() {
                return Err(contrix_sdk::Error::Protocol(
                    "commit proofs must contain at least one proof".to_owned(),
                ));
            }
            Ok(())
        }
    }

    if let Err(message) = validate_operation_semantics(&body.operations) {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }

    let commit_id = body.commit.commit_id.to_string();
    let operations_for_projection = body.operations.clone();
    let repo_id = body.repo_id.clone();
    match state.repo.submit_commit(
        &body.repo_id,
        body.expected_head.as_deref(),
        body.operations,
        body.commit,
        &RequireProof,
    ) {
        Ok(head_commit) => {
            project_accepted_operations(state, &repo_id, &operations_for_projection);
            res.render(Json(SubmitCommitResponse {
                status: "accepted".to_owned(),
                commit_id,
                head_commit,
                sync_token: sync_token(),
            }));
        }
        Err(error) => {
            let code = if error.to_string().contains("expected_head mismatch") {
                "cas_conflict"
            } else {
                "duplicate_conflict"
            };
            render_error(res, StatusCode::CONFLICT, code, &error.to_string());
        }
    }
}

#[handler]
pub async fn authz_check(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<AuthzCheckRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid authz check request",
            );
            return;
        }
    };
    // Extract space_id from resource
    // Resource can be: a string "space:<id>" or an object {"kind":"space","space_id":"<id>"}
    let (resource_str, space_id) = if let Some(s) = body.resource.as_str() {
        let sid = s.strip_prefix("space:").unwrap_or(s);
        (s.to_owned(), sid.to_owned())
    } else if let Some(obj) = body.resource.as_object() {
        let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("space");
        let sid = obj
            .get("space_id")
            .and_then(|v| v.as_str())
            .or_else(|| obj.get("id").and_then(|v| v.as_str()))
            .unwrap_or("");
        (format!("{}:{}", kind, sid), sid.to_owned())
    } else {
        (String::new(), String::new())
    };
    // Look up space owner and members
    let (owner, members) = {
        let meta = state.space_meta.lock().expect("space meta lock");
        let spaces = state.spaces.lock().expect("spaces lock");
        let owner = meta.get(&space_id).map(|m| m.owner.clone());
        let members = spaces
            .get(
                &contrix_sdk::SpaceId::new(space_id.clone())
                    .unwrap_or_else(|_| contrix_sdk::SpaceId::new("cx:space:invalid").unwrap()),
            )
            .map(|s| s.members.iter().map(|m| m.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        (owner, members)
    };
    let result = state.authz.check(
        &body.actor,
        &body.action,
        &resource_str,
        &space_id,
        owner.as_deref(),
        &members,
    );
    res.render(Json(AuthzCheckResponse {
        allowed: result.allowed,
        reason_code: (!result.allowed).then(|| result.reason.clone()),
        grants: result
            .grants
            .iter()
            .map(|g| {
                json!({
                    "grant_id": g.grant_id,
                    "subject": g.subject,
                    "actions": g.actions,
                    "resource": g.resource
                })
            })
            .collect(),
        obligations: Vec::new(),
    }));
}

#[handler]
pub async fn effective_grants(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let subject = query_param(req, "subject").unwrap_or_else(|| "did:web:alice.example".to_owned());
    let space_id = query_param(req, "space_id").unwrap_or_else(|| "*".to_owned());
    let grants = if space_id == "*" {
        // Return grants across all spaces
        let meta = state.space_meta.lock().expect("space meta lock");
        meta.keys()
            .flat_map(|sid| state.authz.grants_for_subject(&subject, sid))
            .map(|g| {
                json!({
                    "grant_id": g.grant_id,
                    "subject": g.subject,
                    "actions": g.actions,
                    "resources": [{"kind": "space", "space_id": g.space_id}]
                })
            })
            .collect::<Vec<_>>()
    } else {
        state
            .authz
            .grants_for_subject(&subject, &space_id)
            .iter()
            .map(|g| {
                json!({
                    "grant_id": g.grant_id,
                    "subject": g.subject,
                    "actions": g.actions,
                    "resources": [{"kind": "space", "space_id": g.space_id}]
                })
            })
            .collect::<Vec<_>>()
    };
    // Include default member grants if the user is a member of any space
    let default_grants = if grants.is_empty() {
        vec![json!({
            "subject": subject,
            "actions": ["space.read", "directory.search", "repo.read"],
            "resources": [{"kind": "space", "space_id": "*"}]
        })]
    } else {
        Vec::new()
    };
    let all_grants = [grants, default_grants].concat();
    res.render(Json(EffectiveGrantsResponse {
        grants: all_grants,
        state_hash: Some(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ),
        evaluated_at: now(),
    }));
}

// ── Grant CRUD ──

#[handler]
pub async fn create_grant(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateGrantRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid grant request",
            );
            return;
        }
    };
    let constraints = body
        .constraints
        .into_iter()
        .map(|v| crate::authz::Constraint {
            constraint_type: v
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown")
                .to_owned(),
            value: v,
        })
        .collect();
    let grant = state.authz.create_grant(
        body.space_id,
        session.actor.clone(),
        body.subject,
        body.resource,
        body.actions,
        constraints,
    );
    append_audit_log(
        state,
        Some(&session.actor),
        "authz.grant.create",
        json!({"grant_id": grant.grant_id.clone(), "subject": grant.subject.clone()}),
        "accepted",
    );
    res.render(Json(json!({
        "grant_id": grant.grant_id,
        "subject": grant.subject,
        "actions": grant.actions,
        "resource": grant.resource,
        "created_at": grant.created_at.to_rfc3339()
    })));
}

#[handler]
pub async fn revoke_grant(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(grant_id) = req.param::<String>("grant_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "grant_id is required",
        );
        return;
    };
    if state.authz.revoke_grant(&grant_id) {
        append_audit_log(
            state,
            Some(&session.actor),
            "authz.grant.revoke",
            json!({"grant_id": grant_id.clone()}),
            "accepted",
        );
        res.render(Json(json!({ "revoked": true, "grant_id": grant_id })));
    } else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "grant not found");
    }
}

#[handler]
pub async fn invites(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let now = now();
    let invite_list = state
        .space_invites
        .lock()
        .expect("space invites lock")
        .values()
        .filter(|invite| {
            invite.status == "pending"
                && invite
                    .invitee
                    .as_deref()
                    .is_some_and(|invitee| invitee == session.actor)
                && invite.expires_at.is_none_or(|expires_at| expires_at > now)
        })
        .map(|invite| {
            json!({
                "invite_id": invite.invite_id,
                "space_id": invite.space_id,
                "inviter": invite.inviter,
                "invitee": invite.invitee,
                "invite_token": invite.invite_token,
                "status": invite.status,
                "expires_at": invite.expires_at,
                "created_at": invite.created_at,
            })
        })
        .collect();
    res.render(Json(InvitesResponse {
        invites: invite_list,
        next_cursor: None,
    }));
}

#[handler]
pub async fn audit_events(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let actor = query_param(req, "actor").unwrap_or_else(|| session.actor.clone());
    if actor != session.actor {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "audit queries are limited to the authenticated actor",
        );
        return;
    }
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(500);
    let events = state
        .audit_log
        .lock()
        .expect("audit log lock")
        .iter()
        .filter(|event| event["actor"].as_str() == Some(actor.as_str()))
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    res.render(Json(json!({
        "events": events,
        "next_cursor": null,
    })));
}

#[handler]
pub async fn profile_presence(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did = query_param(req, "did").unwrap_or_else(|| "did:web:alice.example".to_owned());
    if validate_did(&did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    let account = state
        .accounts
        .lock()
        .expect("accounts lock")
        .get(&did)
        .cloned();
    let presence = state
        .presence
        .lock()
        .expect("presence lock")
        .get(&did)
        .cloned();
    let presence_json = presence
        .map(|record| {
            json!({
                "status": record.status,
                "updated_at": record.updated_at,
            })
        })
        .unwrap_or_else(|| json!({"status": "offline", "updated_at": now()}));
    res.render(Json(json!({
        "actor": did,
        "display_name": account
            .and_then(|account| account.display_name)
            .unwrap_or_else(|| did.clone()),
        "avatar_url": null,
        "presence": presence_json
    })));
}

#[handler]
pub async fn push_register(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    if auth_or_render(state, req, res).is_none() {
        return;
    }
    let body = match req.parse_json::<PushRegisterRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid push register request",
            );
            return;
        }
    };
    if validate_device_id(&body.device_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid device_id",
        );
        return;
    }
    let registration_id = format!("cx:push:{}", body.device_id);
    state
        .push_devices
        .lock()
        .expect("push lock")
        .push(json!({"registration_id": registration_id, "device_id": body.device_id, "platform": body.platform}));
    res.render(Json(PushRegisterResponse {
        ok: true,
        registration_id: Some(registration_id),
        expires_at: None,
    }));
}

#[handler]
pub async fn push_unregister(_depot: &mut Depot, req: &mut Request, res: &mut Response) {
    if req.parse_json::<PushUnregisterRequest>().await.is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "bad_json",
            "invalid push unregister request",
        );
        return;
    }
    res.render(Json(OkResponse { ok: true }));
}

#[handler]
pub async fn push_notify(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<PushNotifyRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid push notify request",
            );
            return;
        }
    };
    if push_notification_leaks_plaintext(&body.notification) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "push notification must not include plaintext content",
        );
        return;
    }
    let devices = body
        .notification
        .get("devices")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let registered = state.push_devices.lock().expect("push lock");
    let rejected = devices
        .into_iter()
        .filter(|device| {
            let device_id = device
                .get("device_id")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            !registered
                .iter()
                .any(|registered| registered["device_id"].as_str() == Some(device_id))
        })
        .collect();
    res.render(Json(PushNotifyResponse { rejected }));
}

#[handler]
pub async fn policy_check(req: &mut Request, res: &mut Response) {
    let body = match req.parse_json::<PolicyCheckRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid policy check request",
            );
            return;
        }
    };
    if validate_did(&body.actor).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid actor",
        );
        return;
    }
    if let Some(space_id) = &body.space_id
        && validate_space_id(space_id).is_err()
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if !is_valid_sha256_digest(&body.request_canonical_hash) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "request_canonical_hash must be sha256:<64 lowercase hex>",
        );
        return;
    }
    let decision = if body.action.contains("delete") || body.action.contains("ban") {
        "require_review"
    } else {
        "allow"
    };
    res.render(Json(PolicyCheckResponse {
        decision: decision.to_owned(),
        reason_code: if decision == "allow" {
            "ok"
        } else {
            "review_required"
        }
        .to_owned(),
        expires_at: now() + chrono::Duration::minutes(5),
        obligations: Vec::new(),
        signature: json!({
            "kid": "did:web:soland.local#policy-dev",
            "alg": "none",
            "sig": sha256_hex(body.request_canonical_hash.as_bytes())
        }),
    }));
}

#[handler]
pub async fn ice_config(res: &mut Response) {
    res.render(Json(json!({
        "service_did": "did:web:soland.local",
        "ttl_seconds": 300,
        "ice_servers": [],
        "issued_at": now(),
    })));
}

#[handler]
pub async fn keys_upload(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<KeysUploadRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid keys upload request",
            );
            return;
        }
    };
    if validate_device_id(&body.device_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid device_id",
        );
        return;
    }
    if body.device_id != session.device_id {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "session device does not match upload device",
        );
        return;
    }
    state.device_keys.lock().expect("device keys lock").insert(
        (session.actor.clone(), body.device_id.clone()),
        json!({
            "device_id": body.device_id.clone(),
            "device_keys": body.device_keys.clone(),
            "principal_signing_keys": body.principal_signing_keys.clone(),
            "recovery_keys": body.recovery_keys.clone(),
            "session_keys": body.session_keys.clone(),
            "agent_keys": body.agent_keys.clone(),
            "fallback_keys": body.fallback_keys.clone(),
            "device_signature": body.device_signature.clone(),
            "mls_key_packages": body.mls_key_packages.clone(),
            "backup_restore_keys": body.backup_restore_keys.clone(),
            "updated_at": now()
        }),
    );
    state
        .one_time_keys
        .lock()
        .expect("one time keys lock")
        .insert((session.actor, body.device_id), body.one_time_keys.clone());
    res.render(Json(KeysUploadResponse {
        one_time_key_counts: json!({"signed_curve25519": body.one_time_keys.len()}),
        fallback_keys: body.fallback_keys,
    }));
}

#[handler]
pub async fn keys_query(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    if auth_or_render(state, req, res).is_none() {
        return;
    }
    let body = req
        .parse_json::<KeysQueryRequest>()
        .await
        .unwrap_or(KeysQueryRequest {
            device_keys: Default::default(),
            timeout_ms: None,
        });
    let keys = state.device_keys.lock().expect("device keys lock");
    let mut result = serde_json::Map::new();
    for (actor, devices) in body.device_keys {
        let mut actor_keys = serde_json::Map::new();
        for device_id in devices {
            if let Some(key) = keys.get(&(actor.clone(), device_id.clone())) {
                actor_keys.insert(device_id, key.clone());
            }
        }
        result.insert(actor, json!(actor_keys));
    }
    res.render(Json(KeysQueryResponse {
        device_keys: json!(result),
        failures: json!({}),
    }));
}

#[handler]
pub async fn keys_claim(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    if auth_or_render(state, req, res).is_none() {
        return;
    }
    let body = req
        .parse_json::<KeysClaimRequest>()
        .await
        .unwrap_or(KeysClaimRequest {
            one_time_keys: Default::default(),
        });
    let mut stored = state.one_time_keys.lock().expect("one time keys lock");
    let mut claimed = serde_json::Map::new();
    for (actor, devices) in body.one_time_keys {
        let mut device_map = serde_json::Map::new();
        for (device_id, _algorithm) in devices {
            if let Some(keys) = stored.get_mut(&(actor.clone(), device_id.clone()))
                && let Some(key) = keys.pop()
            {
                device_map.insert(device_id, key);
            }
        }
        claimed.insert(actor, json!(device_map));
    }
    res.render(Json(KeysClaimResponse {
        one_time_keys: json!(claimed),
        failures: json!({}),
    }));
}

#[handler]
pub async fn put_device_messages(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let txn_id = req.param::<String>("txn_id").unwrap_or_else(sync_token);
    let body = match req.parse_json::<DeviceMessagesSendRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid device messages request",
            );
            return;
        }
    };
    for (recipient, devices) in &body.messages {
        if validate_did(recipient).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "invalid device message recipient",
            );
            return;
        }
        for (device_id, content) in devices {
            if validate_device_id(device_id).is_err() {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "invalid device_id",
                );
                return;
            }
            if let Err(message) = validate_device_message_payload(content) {
                render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
                return;
            }
        }
    }
    {
        let mut txns = state
            .device_message_txns
            .lock()
            .expect("device message txn lock");
        if !txns.insert(format!("{}:{txn_id}", session.actor)) {
            res.render(Json(DeviceMessagesSendResponse {
                ok: true,
                delivered: json!({}),
                unknown_devices: json!({}),
            }));
            return;
        }
    }
    let mut delivered = serde_json::Map::new();
    let mut queue = state.device_messages.lock().expect("device message lock");
    for (recipient, devices) in body.messages {
        let mut delivered_devices = Vec::new();
        for (device_id, content) in devices {
            queue.push_back(DeviceMessageRecord {
                txn_id: txn_id.clone(),
                sender: session.actor.clone(),
                recipient: recipient.clone(),
                device_id: device_id.clone(),
                content,
                created_at: now(),
            });
            delivered_devices.push(device_id);
        }
        delivered.insert(recipient, json!(delivered_devices));
    }
    res.render(Json(DeviceMessagesSendResponse {
        ok: true,
        delivered: json!(delivered),
        unknown_devices: json!({}),
    }));
}

#[handler]
pub async fn get_device_messages(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let mut queue = state.device_messages.lock().expect("device message lock");
    let mut events = Vec::new();
    queue.retain(|message| {
        let mine = message.recipient == session.actor && message.device_id == session.device_id;
        if mine {
            events.push(json!({
                "txn_id": message.txn_id,
                "sender": message.sender,
                "recipient": message.recipient,
                "device_id": message.device_id,
                "content": message.content,
                "created_at": message.created_at
            }));
        }
        !mine
    });
    res.render(Json(DeviceMessagesReceiveResponse {
        events,
        next_batch: Some(sync_token()),
        limited: false,
    }));
}

/// Verify federation origin is a valid DID.
fn verify_federation_origin(origin: &str) -> bool {
    // Basic DID validation - must start with "did:" and contain method
    if !origin.starts_with("did:") {
        return false;
    }
    let rest = &origin[4..];
    // Must have method:name format
    if let Some(colon_pos) = rest.find(':') {
        let method = &rest[..colon_pos];
        let name = &rest[colon_pos + 1..];
        // Method must be non-empty and contain only lowercase letters
        !method.is_empty() && method.chars().all(|c| c.is_ascii_lowercase()) && !name.is_empty()
    } else {
        false
    }
}

#[handler]
pub async fn federation_transaction(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _txn_id = req.param::<String>("txn_id").unwrap_or_else(sync_token);
    let body = match req
        .parse_json::<contrix_sdk::FederationTransactionRequest>()
        .await
    {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid federation transaction request",
            );
            return;
        }
    };
    // Verify federation origin
    if !verify_federation_origin(body.origin.as_str()) {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_origin",
            "federation origin must be a valid DID",
        );
        return;
    }
    let ingest = ingest_federation_operations(state, body.origin.as_str(), body.operations);
    res.render(Json(contrix_sdk::FederationTransactionResponse {
        ok: true,
        accepted: ingest.accepted,
        rejected: ingest.rejected,
        next_retry_at: None,
    }));
}

#[handler]
pub async fn federation_push_operations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req
        .parse_json::<contrix_sdk::FederationPushOperationsRequest>()
        .await
    {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid federation push operations request",
            );
            return;
        }
    };
    // Verify federation origin
    if !verify_federation_origin(body.origin.as_str()) {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_origin",
            "federation origin must be a valid DID",
        );
        return;
    }
    let ingest = ingest_federation_operations(state, body.origin.as_str(), body.operations);
    res.render(Json(contrix_sdk::FederationPushOperationsResponse {
        accepted: ingest.accepted,
        rejected: ingest.rejected,
        quarantine: Vec::new(),
    }));
}

#[handler]
pub async fn federation_pull_operations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let after_cursor = query_param(req, "after_cursor");
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(100);
    let space_operations: Vec<_> = state
        .federation_operations
        .lock()
        .expect("federation lock")
        .iter()
        .filter(|operation| operation.space_id.as_str() == space_id)
        .cloned()
        .collect();
    let redacted = redaction_targets_from_operations(&space_operations);
    let snapshot_bootstrap = query_flag(req, "snapshot_bootstrap").then(|| {
        let manifest = json!({
            "type": "snapshot_bootstrap",
            "space_id": space_id,
            "snapshot_ref": ids::generate_snapshot_id(),
            "operation_count": space_operations.len(),
            "created_at": now(),
        });
        let state_hash = format!("sha256:{}", sha256_hex(manifest.to_string().as_bytes()));
        json!({
            "manifest": manifest,
            "state_hash": state_hash,
            "chunks": [],
            "via_services": ["did:web:soland.local"],
        })
    });
    let mut seen_cursor = after_cursor.is_none();
    let mut operations = Vec::new();
    for operation in space_operations {
        if !seen_cursor {
            seen_cursor = Some(operation.operation_id.as_str()) == after_cursor.as_deref();
            continue;
        }
        if !operation_is_visible(&operation, &redacted) {
            continue;
        }
        if operations.len() == limit + 1 {
            break;
        }
        operations.push(operation);
    }
    let has_more = operations.len() > limit;
    if has_more {
        operations.truncate(limit);
    }
    let next_cursor = operations
        .last()
        .map(|operation| operation.operation_id.to_string())
        .or_else(|| Some(sync_token()));
    res.render(Json(contrix_sdk::FederationPullOperationsResponse {
        operations,
        snapshot_bootstrap,
        next_cursor,
        has_more,
    }));
}

#[handler]
pub async fn federation_space_members(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    let Ok(space_id_value) = SpaceId::new(space_id.clone()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    };
    let members = state
        .spaces
        .lock()
        .expect("spaces lock")
        .get(&space_id_value)
        .map(|space| {
            space
                .members
                .iter()
                .map(|principal_id| contrix_sdk::MemberRef {
                    principal_id: principal_id.clone(),
                    membership: json!({"membership": "join"}),
                })
                .collect()
        })
        .unwrap_or_default();
    res.render(Json(contrix_sdk::FederationSpaceMembersResponse {
        members,
        membership_frontier: sync_token(),
        next_cursor: None,
    }));
}

#[handler]
pub async fn federation_verify_actor(req: &mut Request, res: &mut Response) {
    let body = match req
        .parse_json::<contrix_sdk::FederationVerifyActorRequest>()
        .await
    {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid federation verify actor request",
            );
            return;
        }
    };
    res.render(Json(contrix_sdk::FederationVerifyActorResponse {
        valid: true,
        actor_id: body.actor_id.clone(),
        verified_key_id: Some(format!("{}#dev", body.actor_id)),
        key_log_head: None,
        did_document_ref: Some(format!("{}#document", body.actor_id)),
        expires_at: Some(now() + chrono::Duration::minutes(5)),
        warnings: Vec::new(),
    }));
}

#[handler]
pub async fn blob_upload(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let bytes = match req.payload().await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid blob body",
            );
            return;
        }
    };
    let media_type = req
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let size = bytes.len();
    if size > 10 * 1024 * 1024 {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "blob exceeds maximum size",
        );
        return;
    }
    let encryption = match encrypted_attachment_metadata(req) {
        Ok(encryption) => encryption,
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    };
    let sha256 = sha256_hex(&bytes);
    match expected_blob_sha256(req) {
        Ok(Some(expected_sha256)) if expected_sha256 != sha256 => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "hash_mismatch",
                "provided sha256 does not match blob content",
            );
            return;
        }
        Ok(_) => {}
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    }
    let blob_ref = format!("cx:blob:sha256:{sha256}");
    let blob_dir = state.config.blob_root.join("sha256");
    if let Err(error) = std::fs::create_dir_all(&blob_dir) {
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "blob_store_error",
            &error.to_string(),
        );
        return;
    }
    let storage_path = blob_dir.join(&sha256);
    if let Err(error) = std::fs::write(&storage_path, &bytes) {
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "blob_store_error",
            &error.to_string(),
        );
        return;
    }
    state.blobs.lock().expect("blob lock").insert(
        blob_ref.clone(),
        BlobRecord {
            bytes,
            storage_path: Some(storage_path),
            media_type: media_type.clone(),
            filename: None,
            encryption: encryption.clone(),
            uploaded_by: session.actor,
            created_at: now(),
        },
    );
    res.render(Json(crate::wire::BlobUploadResponse {
        blob_ref,
        size,
        media_type,
        sha256,
        upload_receipt: json!({
            "service_did": "did:web:soland.local",
            "created_at": now(),
            "encrypted_attachment": encryption,
        }),
    }));
}

#[handler]
pub async fn blob_get(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(blob_ref) = query_param(req, "blob_ref") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "blob_ref is required",
        );
        return;
    };
    let blobs = state.blobs.lock().expect("blob lock");
    match blobs.get(&blob_ref) {
        Some(blob) => {
            let blob_bytes = blob
                .storage_path
                .as_ref()
                .and_then(|path| std::fs::read(path).ok())
                .unwrap_or_else(|| blob.bytes.clone());
            let total_len = blob_bytes.len();
            let (status, body, content_range) = match parse_range(req, total_len).transpose() {
                Ok(Some((start, end))) => {
                    let body = blob_bytes[start..=end].to_vec();
                    (
                        StatusCode::PARTIAL_CONTENT,
                        body,
                        Some(format!("bytes {start}-{end}/{total_len}")),
                    )
                }
                Ok(None) => (StatusCode::OK, blob_bytes, None),
                Err(message) => {
                    render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
                    return;
                }
            };
            res.status_code(status);
            res.headers_mut().insert(
                salvo::http::header::CONTENT_TYPE,
                blob.media_type.parse().unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::CONTENT_LENGTH,
                body.len().to_string().parse().unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("digest"),
                format!("sha-256={}", blob_ref.trim_start_matches("cx:blob:sha256:"))
                    .parse()
                    .unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("accept-ranges"),
                "bytes".parse().unwrap(),
            );
            // Set Content-Disposition: attachment for HTML/JS/SVG to prevent stored XSS
            let dangerous_types = ["text/html", "application/javascript", "image/svg+xml"];
            if dangerous_types.contains(&blob.media_type.as_str()) {
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_DISPOSITION,
                    "attachment".parse().unwrap(),
                );
            }
            if let Some(content_range) = content_range {
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_RANGE,
                    content_range.parse().unwrap(),
                );
            }
            append_audit_log(
                state,
                None,
                "blob.get",
                json!({"blob_ref": blob_ref.clone(), "status": status.as_u16()}),
                "accepted",
            );
            if req.method() != Method::HEAD {
                res.write_body(body).ok();
            }
        }
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

fn render_identity_document(state: &AppState, res: &mut Response, did: String) {
    if validate_did(&did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    let record = identity_document_record(state, &did);
    res.render(Json(IdentityResolveResponse {
        did_document: record.did_document,
        key_log_head: record.key_log_head,
        seq: record.seq,
        receipts: Vec::new(),
        method_evidence: record.method_evidence,
    }));
}

fn identity_document_record(state: &AppState, did: &str) -> IdentityDocumentRecord {
    state
        .identity_documents
        .lock()
        .expect("identity documents lock")
        .get(did)
        .cloned()
        .unwrap_or_else(|| IdentityDocumentRecord {
            did: did.to_owned(),
            did_document: default_did_document(did),
            key_log_head: None,
            seq: 0,
            method_evidence: json!({"mode": "development_local"}),
            updated_at: now(),
        })
}

fn default_did_document(did: &str) -> serde_json::Value {
    json!({
        "id": did,
        "verification_method": [],
        "authentication": [],
        "service": [{"id": "soland", "type": "ContrixPrincipalServer", "serviceEndpoint": "/api/v1"}]
    })
}

fn did_document_from_patch(did: &str, patch: &serde_json::Value) -> Option<serde_json::Value> {
    let document = patch
        .get("did_document")
        .or_else(|| patch.get("document"))
        .cloned()?;
    (document.get("id").and_then(|value| value.as_str()) == Some(did)).then_some(document)
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

fn message_event(message: &MessageRecord) -> serde_json::Value {
    json!({
        "kind": "message",
        "event_id": message.event_id,
        "space_id": message.space_id,
        "thread_id": message.thread_id,
        "sender": message.sender,
        "content": message.content,
        "encrypted": message.encrypted,
        "created_at": message.created_at,
    })
}

#[derive(Clone, Debug)]
struct ProjectedEventPage {
    items: Vec<ProjectionEventRecord>,
    next_cursor: Option<String>,
    has_more: bool,
}

#[derive(QueryableByName)]
struct ProjectionEventRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Text)]
    space_id: String,
    #[diesel(sql_type = Text)]
    event_type: String,
    #[diesel(sql_type = Text)]
    operation_type: String,
    #[diesel(sql_type = Nullable<Text>)]
    operation_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    sender: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

fn projection_event_json(event: &ProjectionEventRecord) -> serde_json::Value {
    json!({
        "event_id": event.event_id,
        "space_id": event.space_id,
        "event_type": event.event_type,
        "operation_type": event.operation_type,
        "operation_id": event.operation_id,
        "sender": event.sender,
        "payload": event.payload,
        "created_at": event.created_at,
    })
}

fn operation_event_id(operation: &Operation) -> String {
    operation
        .payload
        .get("event_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| operation.operation_id.to_string())
}

fn redaction_targets_from_operations(operations: &[Operation]) -> HashSet<String> {
    operations
        .iter()
        .filter(|operation| operation.object_type == "redaction")
        .filter_map(|operation| {
            operation
                .payload
                .get("target_event_id")
                .and_then(|value| value.as_str())
                .or_else(|| {
                    operation
                        .payload
                        .get("target")
                        .and_then(|value| value.as_str())
                })
                .or_else(|| {
                    operation
                        .payload
                        .get("redacts")
                        .and_then(|value| value.as_str())
                })
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn operation_is_visible(operation: &Operation, redacted_events: &HashSet<String>) -> bool {
    let event_id = operation_event_id(operation);
    operation.object_type != "redaction" && !redacted_events.contains(&event_id)
}

fn operation_type_string(operation: &Operation) -> String {
    serde_json::to_value(&operation.operation_type)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "create".to_owned())
}

fn projection_event_from_operation(
    operation: &Operation,
    sender_fallback: Option<&str>,
) -> ProjectionEventRecord {
    let event_id = operation_event_id(operation);
    ProjectionEventRecord {
        event_id,
        space_id: operation.space_id.to_string(),
        event_type: operation.object_type.clone(),
        operation_type: operation_type_string(operation),
        operation_id: Some(operation.operation_id.to_string()),
        sender: operation
            .payload
            .get("sender")
            .and_then(|value| value.as_str())
            .or(sender_fallback)
            .map(ToOwned::to_owned),
        payload: operation.payload.clone(),
        created_at: operation.created_at,
    }
}

fn redaction_targets_from_events(events: &[ProjectionEventRecord]) -> HashSet<String> {
    events
        .iter()
        .filter(|event| event.event_type == "redaction")
        .filter_map(|event| {
            event
                .payload
                .get("target_event_id")
                .and_then(|value| value.as_str())
                .or_else(|| event.payload.get("target").and_then(|value| value.as_str()))
                .or_else(|| {
                    event
                        .payload
                        .get("redacts")
                        .and_then(|value| value.as_str())
                })
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn event_is_visible(event: &ProjectionEventRecord, redacted: &HashSet<String>) -> bool {
    event.event_type != "redaction" && !redacted.contains(&event.event_id)
}

fn append_projection_event(state: &AppState, event: ProjectionEventRecord) {
    let mut events = state
        .projection_events
        .lock()
        .expect("projection event lock");
    if events.iter().any(|known| known.event_id == event.event_id) {
        return;
    }
    events.push(event);
}

fn projected_event_page(
    state: &AppState,
    space_id: &str,
    cursor: Option<&str>,
    limit: usize,
) -> anyhow::Result<Option<ProjectedEventPage>> {
    let mut events = state
        .projection_events
        .lock()
        .expect("projection event lock")
        .iter()
        .filter(|event| event.space_id == space_id)
        .cloned()
        .collect::<Vec<_>>();
    if events.is_empty() {
        events = load_projected_events_from_pg(state, space_id)?;
    }
    if events.is_empty() {
        return Ok(None);
    }
    events.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let redacted = redaction_targets_from_events(&events);
    let start = cursor
        .and_then(|cursor| {
            events
                .iter()
                .position(|event| event.event_id == cursor)
                .map(|index| index + 1)
        })
        .unwrap_or(0);
    let mut page_items = events
        .into_iter()
        .skip(start)
        .filter(|event| event_is_visible(event, &redacted))
        .collect::<Vec<_>>();
    let has_more = page_items.len() > limit;
    if has_more {
        page_items.truncate(limit);
    }
    let next_cursor = if has_more {
        page_items.last().map(|event| event.event_id.clone())
    } else {
        None
    };
    Ok(Some(ProjectedEventPage {
        items: page_items,
        next_cursor,
        has_more,
    }))
}

fn load_projected_events_from_pg(
    state: &AppState,
    space_id: &str,
) -> anyhow::Result<Vec<ProjectionEventRecord>> {
    let Some(pool) = state.db.pool.as_ref() else {
        return Ok(Vec::new());
    };
    let mut conn = pool.get()?;
    let rows = sql_query(
        "SELECT event_id, space_id, event_type, 'event' AS operation_type, operation_id, sender, payload, created_at \
         FROM events WHERE space_id = $1 \
         UNION ALL \
         SELECT event_id, space_id, event_type, 'state' AS operation_type, operation_id, sender, payload, created_at \
         FROM space_state_events WHERE space_id = $1 \
         ORDER BY created_at ASC, event_id ASC",
    )
    .bind::<Text, _>(space_id)
    .load::<ProjectionEventRow>(&mut conn)?;
    Ok(rows
        .into_iter()
        .map(|row| ProjectionEventRecord {
            event_id: row.event_id,
            space_id: row.space_id,
            event_type: row.event_type,
            operation_type: row.operation_type,
            operation_id: row.operation_id,
            sender: row.sender,
            payload: row.payload,
            created_at: row.created_at,
        })
        .collect())
}

struct FederationIngestResult {
    accepted: Vec<OperationId>,
    rejected: Vec<serde_json::Value>,
}

fn ingest_federation_operations(
    state: &AppState,
    origin: &str,
    operations: Vec<Operation>,
) -> FederationIngestResult {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for operation in operations {
        let operation_id = operation.operation_id.clone();
        if operation.validate_payload_object().is_err() {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "invalid_payload",
            }));
            continue;
        }
        if let Err(message) = validate_operation_semantics(std::slice::from_ref(&operation)) {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "invalid_semantics",
                "message": message,
            }));
            continue;
        }
        {
            let mut federation_operations =
                state.federation_operations.lock().expect("federation lock");
            if federation_operations
                .iter()
                .any(|known| known.operation_id == operation_id)
            {
                rejected.push(json!({
                    "operation_id": operation_id,
                    "reason": "replay",
                }));
                continue;
            }
            federation_operations.push(operation.clone());
        }
        project_federation_operation(state, origin, &operation);
        accepted.push(operation_id);
    }
    FederationIngestResult { accepted, rejected }
}

fn project_federation_operation(state: &AppState, origin: &str, operation: &Operation) {
    ensure_projected_space(state, origin, operation);
    match operation.object_type.as_str() {
        "message" => project_federated_message(state, origin, operation),
        "membership" | "space.lifecycle" => project_membership_operation(state, origin, operation),
        _ => {}
    }
    // Also apply to the deterministic reducer
    if let Ok(mut proj) = state.projection.lock() {
        proj.apply(operation, &state.hlc);
    }
    append_projection_event(
        state,
        projection_event_from_operation(operation, Some(origin)),
    );
}

fn project_accepted_operations(state: &AppState, repo_id: &str, operations: &[Operation]) {
    for operation in operations {
        ensure_projected_space(state, repo_id, operation);
        match operation.object_type.as_str() {
            "message" => project_federated_message(state, repo_id, operation),
            "membership" | "space.lifecycle" => {
                project_membership_operation(state, repo_id, operation)
            }
            _ => {}
        }
        // Also apply to the deterministic reducer
        if let Ok(mut proj) = state.projection.lock() {
            proj.apply(operation, &state.hlc);
        }
        append_projection_event(
            state,
            projection_event_from_operation(operation, Some(repo_id)),
        );
        if let Err(error) = persist_projected_operation(state, repo_id, operation) {
            tracing::warn!(
                error = %error,
                operation_id = %operation.operation_id,
                object_type = %operation.object_type,
                "failed to persist accepted operation projection"
            );
        }
    }
}

fn persist_projected_operation(
    state: &AppState,
    repo_id: &str,
    operation: &Operation,
) -> anyhow::Result<()> {
    let Some(pool) = state.db.pool.as_ref() else {
        return Ok(());
    };
    let mut conn = pool.get()?;
    match operation.object_type.as_str() {
        "message" => {
            let event_id = operation
                .payload
                .get("event_id")
                .and_then(|value| value.as_str())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| {
                    format!(
                        "cx:event:{}",
                        operation.operation_id.as_str().replace(':', "")
                    )
                });
            let sender = operation
                .payload
                .get("sender")
                .and_then(|value| value.as_str())
                .unwrap_or(repo_id);
            let thread_id = operation
                .payload
                .get("thread_id")
                .and_then(|value| value.as_str());
            sql_query(
                "INSERT INTO events (event_id, space_id, event_type, sender, thread_id, operation_id, payload, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (event_id) DO NOTHING",
            )
            .bind::<Text, _>(&event_id)
            .bind::<Text, _>(operation.space_id.as_str())
            .bind::<Text, _>(&operation.object_type)
            .bind::<Nullable<Text>, _>(Some(sender))
            .bind::<Nullable<Text>, _>(thread_id)
            .bind::<Nullable<Text>, _>(Some(operation.operation_id.as_str()))
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut conn)?;
        }
        "membership" | "space.lifecycle" => {
            let title = operation
                .payload
                .get("space_title")
                .or_else(|| operation.payload.get("title"))
                .and_then(|value| value.as_str())
                .unwrap_or_else(|| operation.space_id.as_str());
            let summary = operation
                .payload
                .get("space_summary")
                .or_else(|| operation.payload.get("summary"))
                .and_then(|value| value.as_str());
            let discoverability = operation
                .payload
                .get("discoverability")
                .and_then(|value| value.as_str())
                .unwrap_or_else(|| {
                    if operation
                        .payload
                        .get("public")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false)
                    {
                        "public"
                    } else {
                        "invite_only"
                    }
                });
            sql_query(
                "INSERT INTO spaces (space_id, title, summary, owner, discoverability, payload, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                 ON CONFLICT (space_id) DO UPDATE SET title = EXCLUDED.title, summary = EXCLUDED.summary, updated_at = EXCLUDED.updated_at",
            )
            .bind::<Text, _>(operation.space_id.as_str())
            .bind::<Text, _>(title)
            .bind::<Nullable<Text>, _>(summary)
            .bind::<Nullable<Text>, _>(Some(repo_id))
            .bind::<Text, _>(discoverability)
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut conn)?;

            if let Some(member) = operation
                .payload
                .get("member")
                .and_then(|value| value.as_str())
            {
                let membership = operation
                    .payload
                    .get("membership")
                    .and_then(|value| value.as_str())
                    .unwrap_or_else(|| {
                        if operation
                            .payload
                            .get("action")
                            .and_then(|value| value.as_str())
                            .is_some_and(|action| {
                                matches!(action, "member.remove" | "leave" | "ban")
                            })
                        {
                            "leave"
                        } else {
                            "join"
                        }
                    });
                sql_query(
                    "INSERT INTO space_members (space_id, actor, membership, payload, joined_at, left_at, updated_at) \
                     VALUES ($1, $2, $3, $4, CASE WHEN $3 = 'join' THEN $5 ELSE NULL END, CASE WHEN $3 <> 'join' THEN $5 ELSE NULL END, $5) \
                     ON CONFLICT (space_id, actor) DO UPDATE SET membership = EXCLUDED.membership, payload = EXCLUDED.payload, left_at = EXCLUDED.left_at, updated_at = EXCLUDED.updated_at",
                )
                .bind::<Text, _>(operation.space_id.as_str())
                .bind::<Text, _>(member)
                .bind::<Text, _>(membership)
                .bind::<Jsonb, _>(&operation.payload)
                .bind::<Timestamptz, _>(operation.created_at)
                .execute(&mut conn)?;
            }

            sql_query(
                "INSERT INTO space_state_events (event_id, space_id, event_type, state_key, sender, operation_id, payload, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $1, $6, $7) \
                 ON CONFLICT (event_id) DO NOTHING",
            )
            .bind::<Text, _>(operation.operation_id.as_str())
            .bind::<Text, _>(operation.space_id.as_str())
            .bind::<Text, _>(&operation.object_type)
            .bind::<Text, _>(
                operation
                    .payload
                    .get("member")
                    .and_then(|value| value.as_str())
                    .unwrap_or(""),
            )
            .bind::<Nullable<Text>, _>(Some(repo_id))
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut conn)?;
        }
        _ => {}
    }
    Ok(())
}

fn ensure_projected_space(state: &AppState, origin: &str, operation: &Operation) {
    let space_id = operation.space_id.clone();
    let mut spaces = state.spaces.lock().expect("spaces lock");
    if spaces.get(&space_id).is_none() {
        let title = operation
            .payload
            .get("space_title")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| space_id.as_str());
        let mut entry = SpaceSearchEntry::new(space_id.clone(), title);
        entry.description = operation
            .payload
            .get("space_summary")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned);
        let discoverability = operation
            .payload
            .get("discoverability")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| {
                if operation
                    .payload
                    .get("public")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                {
                    "public"
                } else {
                    "invite_only"
                }
            });
        entry.public = discoverability == "public";
        if let Ok(origin) = Did::new(origin.to_owned()) {
            entry.members.insert(origin);
        }
        spaces.upsert(entry);
    }
    drop(spaces);

    let now = now();
    state
        .space_meta
        .lock()
        .expect("space meta lock")
        .entry(space_id.to_string())
        .or_insert_with(|| SpaceMetaRecord {
            owner: origin.to_owned(),
            deleted: false,
            discoverability: operation
                .payload
                .get("discoverability")
                .and_then(|value| value.as_str())
                .filter(|value| is_valid_discoverability(value))
                .unwrap_or_else(|| {
                    if operation
                        .payload
                        .get("public")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false)
                    {
                        "public"
                    } else {
                        "invite_only"
                    }
                })
                .to_owned(),
            plaintext_visible_services: operation
                .payload
                .get("plaintext_visible_services")
                .and_then(|value| value.as_array())
                .map(|services| {
                    services
                        .iter()
                        .filter_map(|service| service.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            created_at: now,
            updated_at: now,
        });
    project_membership_operation(state, origin, operation);
}

fn project_membership_operation(state: &AppState, origin: &str, operation: &Operation) {
    let action = operation
        .payload
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or(operation.object_type.as_str());
    if matches!(action, "delete" | "space.delete") {
        if let Some(record) = state
            .space_meta
            .lock()
            .expect("space meta lock")
            .get_mut(operation.space_id.as_str())
        {
            record.deleted = true;
            record.updated_at = operation.created_at;
        }
        return;
    }

    let mut member_values = Vec::new();
    if let Some(member) = operation
        .payload
        .get("member")
        .and_then(|value| value.as_str())
    {
        member_values.push(member.to_owned());
    }
    if let Some(sender) = operation
        .payload
        .get("sender")
        .and_then(|value| value.as_str())
    {
        member_values.push(sender.to_owned());
    }
    if let Some(actor) = operation
        .payload
        .get("actor")
        .and_then(|value| value.as_str())
    {
        member_values.push(actor.to_owned());
    }
    if let Some(members) = operation
        .payload
        .get("members")
        .and_then(|value| value.as_array())
    {
        member_values.extend(
            members
                .iter()
                .filter_map(|member| member.as_str().map(ToOwned::to_owned)),
        );
    }
    member_values.push(origin.to_owned());

    let mut spaces = state.spaces.lock().expect("spaces lock");
    let Some(mut entry) = spaces.get(&operation.space_id).cloned() else {
        return;
    };
    for member in member_values {
        if let Ok(member) = Did::new(member) {
            if matches!(action, "member.remove" | "leave" | "ban") {
                entry.members.remove(&member);
            } else {
                entry.members.insert(member);
            }
        }
    }
    spaces.upsert(entry);
    drop(spaces);
    touch_space(state, operation.space_id.as_str());
}

fn project_federated_message(state: &AppState, origin: &str, operation: &Operation) {
    let event_id = operation
        .payload
        .get("event_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "cx:event:{}",
                operation.operation_id.as_str().replace(':', "")
            )
        });
    let mut messages = state.messages.lock().expect("messages lock");
    if messages.iter().any(|message| message.event_id == event_id) {
        return;
    }
    let content = operation
        .payload
        .get("content")
        .cloned()
        .or_else(|| {
            operation
                .payload
                .get("body")
                .map(|body| json!({"body": body}))
        })
        .unwrap_or_else(|| operation.payload.clone());
    let sender = operation
        .payload
        .get("sender")
        .and_then(|value| value.as_str())
        .unwrap_or(origin)
        .to_owned();
    let thread_id = operation
        .payload
        .get("thread_id")
        .and_then(|value| value.as_str())
        .unwrap_or(operation.space_id.as_str())
        .to_owned();
    let encrypted = operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    messages.push(MessageRecord {
        event_id,
        space_id: operation.space_id.to_string(),
        sender,
        thread_id,
        content,
        encrypted,
        created_at: operation.created_at,
    });
}

fn render_space_lifecycle(state: &AppState, res: &mut Response, space_id: &str) {
    let Ok(space_id_value) = SpaceId::new(space_id.to_owned()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    };
    let spaces = state.spaces.lock().expect("spaces lock");
    let meta = state.space_meta.lock().expect("space meta lock");
    let Some(record) = meta.get(space_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    };
    let members = spaces
        .get(&space_id_value)
        .map(|space| space.members.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    res.render(Json(SpaceLifecycleResponse {
        ok: true,
        space_id: space_id.to_owned(),
        owner: record.owner.clone(),
        members,
        deleted: record.deleted,
    }));
}

fn space_owner_matches(state: &AppState, space_id: &str, actor: &str) -> bool {
    state
        .space_meta
        .lock()
        .expect("space meta lock")
        .get(space_id)
        .is_some_and(|record| !record.deleted && record.owner == actor)
}

fn touch_space(state: &AppState, space_id: &str) {
    if let Some(record) = state
        .space_meta
        .lock()
        .expect("space meta lock")
        .get_mut(space_id)
    {
        record.updated_at = now();
    }
}

fn is_space_deleted(state: &AppState, space_id: &str) -> bool {
    state
        .space_meta
        .lock()
        .expect("space meta lock")
        .get(space_id)
        .is_some_and(|record| record.deleted)
}

fn is_valid_handle(handle: &str) -> bool {
    let normalized = normalize_handle(handle);
    normalized.len() > 1
        && normalized
            .trim_start_matches('@')
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_valid_entity_type(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix("cx.") {
        return !rest.is_empty()
            && rest.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'.'
                    || byte == b'_'
                    || byte == b'-'
            });
    }
    let labels: Vec<_> = value.split('.').collect();
    labels.len() >= 3
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn is_valid_discoverability(value: &str) -> bool {
    matches!(
        value,
        "public" | "listed" | "restricted" | "unlisted" | "invite_only" | "secret"
    )
}

fn space_discoverability(state: &AppState, space_id: &str) -> String {
    state
        .space_meta
        .lock()
        .expect("space meta lock")
        .get(space_id)
        .map(|record| record.discoverability.clone())
        .unwrap_or_else(|| "invite_only".to_owned())
}

fn space_has_member(state: &AppState, space_id: &str, actor: &str) -> bool {
    if is_space_deleted(state, space_id) {
        return false;
    }
    let Ok(space_id) = SpaceId::new(space_id.to_owned()) else {
        return false;
    };
    let Ok(actor) = Did::new(actor.to_owned()) else {
        return false;
    };
    state
        .spaces
        .lock()
        .expect("spaces lock")
        .get(&space_id)
        .is_some_and(|space| space.members.contains(&actor))
}

fn space_visible_to(
    state: &AppState,
    space: &contrix_sdk::SpaceSearchEntry,
    session: Option<&SessionRecord>,
) -> bool {
    if is_space_deleted(state, space.space_id.as_str()) {
        return false;
    }
    if space_discoverability(state, space.space_id.as_str()) == "public" {
        return true;
    }
    session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    })
}

fn space_search_visible_to(
    state: &AppState,
    space: &contrix_sdk::SpaceSearchEntry,
    session: Option<&SessionRecord>,
) -> bool {
    if is_space_deleted(state, space.space_id.as_str()) {
        return false;
    }
    if session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    }) {
        return true;
    }
    matches!(
        space_discoverability(state, space.space_id.as_str()).as_str(),
        "public" | "listed" | "restricted"
    )
}

fn space_resolvable_to(
    state: &AppState,
    space: &contrix_sdk::SpaceSearchEntry,
    session: Option<&SessionRecord>,
    invite_token: Option<&str>,
    signed_link: Option<&str>,
) -> bool {
    if is_space_deleted(state, space.space_id.as_str()) {
        return false;
    }
    if session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    }) {
        return true;
    }
    match space_discoverability(state, space.space_id.as_str()).as_str() {
        "public" | "listed" | "restricted" | "unlisted" => true,
        "invite_only" => invite_token
            .is_some_and(|token| invite_token_matches_space(state, space.space_id.as_str(), token)),
        "secret" => signed_link.is_some_and(|link| !link.trim().is_empty()),
        _ => false,
    }
}

fn invite_token_matches_space(state: &AppState, space_id: &str, token: &str) -> bool {
    invite_token_space_id(state, token)
        .is_some_and(|resolved_space_id| resolved_space_id == space_id)
}

fn invite_token_space_id(state: &AppState, token: &str) -> Option<String> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    let now = now();
    state
        .space_invites
        .lock()
        .expect("space invites lock")
        .values()
        .find(|invite| {
            invite.status == "pending"
                && invite.invite_token == token
                && invite.expires_at.is_none_or(|expires_at| expires_at > now)
        })
        .map(|invite| invite.space_id.clone())
}

fn space_search_discoverability(state: &AppState, space_id: &str) -> bool {
    matches!(
        space_discoverability(state, space_id).as_str(),
        "public" | "listed" | "restricted"
    )
}

fn space_id_visible_to(state: &AppState, space_id: &str, session: Option<&SessionRecord>) -> bool {
    if is_space_deleted(state, space_id) {
        return false;
    }
    let Ok(sid) = SpaceId::new(space_id.to_owned()) else {
        return false;
    };
    state
        .spaces
        .lock()
        .expect("spaces lock")
        .get(&sid)
        .is_some_and(|space| space_visible_to(state, space, session))
}

/// Check if a space is accessible for backfill/subscribe (allows deleted spaces for members).
fn space_id_accessible(state: &AppState, space_id: &str, session: Option<&SessionRecord>) -> bool {
    let Ok(sid) = SpaceId::new(space_id.to_owned()) else {
        return false;
    };
    let spaces = state.spaces.lock().expect("spaces lock");
    let Some(space) = spaces.get(&sid) else {
        return false;
    };
    if space_discoverability(state, space.space_id.as_str()) == "public" {
        return true;
    }
    session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    })
}

fn space_allows_plaintext_service(state: &AppState, space_id: &str) -> bool {
    let Ok(sid) = SpaceId::new(space_id.to_owned()) else {
        return false;
    };
    {
        let spaces = state.spaces.lock().expect("spaces lock");
        if spaces
            .get(&sid)
            .is_some_and(|space| space_discoverability(state, space.space_id.as_str()) == "public")
        {
            return true;
        }
    }
    state
        .space_meta
        .lock()
        .expect("space meta lock")
        .get(space_id)
        .is_some_and(|record| {
            record
                .plaintext_visible_services
                .contains(&state.config.service_did)
        })
}

struct RequireProof;

impl CommitProofVerifier for RequireProof {
    fn verify_commit(&self, commit: &Commit) -> contrix_sdk::Result<()> {
        commit.validate_for_submit()
    }
}

fn record_space_lifecycle_operation(
    state: &AppState,
    actor: &str,
    space_id: &str,
    payload: serde_json::Value,
) -> contrix_sdk::Result<Option<String>> {
    let operation = Operation::create(
        OperationId::new(ids::generate_operation_id()).expect("generated valid operation id"),
        SpaceId::new(space_id.to_owned()).expect("validated space id"),
        "space.lifecycle",
        payload,
    );
    let projection_event = projection_event_from_operation(&operation, Some(actor));
    let operation_digest = Hash::new(operation.operation_digest()?)?;
    let mut commit = Commit::new(
        CommitId::new(ids::generate_commit_id()).expect("generated valid commit id"),
        actor.to_owned(),
        Did::new(actor.to_owned()).expect("session actor is valid"),
        next_author_seq(state, actor),
    );
    commit.prev_commit = state.repo.head(actor)?.map(Hash::new).transpose()?;
    commit.operations.push(operation_digest);
    commit.proofs.push(dev_proof(actor));

    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    let head = state.repo.submit_commit(
        actor,
        expected_head.as_deref(),
        vec![operation],
        commit,
        &RequireProof,
    )?;
    append_projection_event(state, projection_event);
    Ok(head)
}

fn next_author_seq(state: &AppState, repo_id: &str) -> u64 {
    state
        .repo
        .list_commits(repo_id, None, 100)
        .map(|page| {
            page.items
                .iter()
                .map(|commit| commit.author_seq)
                .max()
                .unwrap_or(0)
                + 1
        })
        .unwrap_or(1)
}

fn dev_proof(actor: &str) -> Proof {
    Proof {
        kind: "detached_jws".to_owned(),
        alg: "none".to_owned(),
        verification_method: format!("{actor}#dev"),
        payload_hash: Hash::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("valid hash"),
        created_at: now(),
        domain: Some("soland-dev".to_owned()),
        audience: None,
        jws: "dev-proof".to_owned(),
    }
}

fn validate_operation_semantics(operations: &[Operation]) -> Result<(), &'static str> {
    for operation in operations {
        operation
            .validate_payload_object()
            .map_err(|_| "operation payload must be a JSON object")?;
        validate_canonical_json_value(&operation.payload)?;
        match operation.object_type.as_str() {
            "message" => {
                if !(operation.payload.get("body").is_some()
                    || operation.payload.get("content").is_some()
                    || operation.payload.get("event_id").is_some())
                {
                    return Err("message operation requires body, content, or event_id");
                }
                if operation
                    .payload
                    .get("encrypted")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                {
                    let Some(content) = operation.payload.get("content") else {
                        return Err("encrypted message operation requires content envelope");
                    };
                    validate_encrypted_payload_envelope(content)?;
                } else if let Some(content) = operation.payload.get("content") {
                    validate_content_blocks(content)?;
                    validate_mentions(content)?;
                }
            }
            "membership" => {
                if operation.payload.get("member").is_none()
                    || operation.payload.get("membership").is_none()
                {
                    return Err("membership operation requires member and membership");
                }
            }
            "space.lifecycle" => {
                if operation.payload.get("action").is_none() {
                    return Err("space lifecycle operation requires action");
                }
            }
            "redaction" => {
                if operation.payload.get("target_event_id").is_none()
                    && operation.payload.get("target").is_none()
                    && operation.payload.get("redacts").is_none()
                {
                    return Err("redaction operation requires target_event_id");
                }
            }
            "entity" | "entity.create" | "entity.update" | "entity.delete" | "relation"
            | "relation.create" | "relation.update" | "relation.delete" | "reaction"
            | "reaction.add" | "reaction.remove" | "read_marker" => {}
            _ => return Err("unknown operation family"),
        }
    }
    Ok(())
}

fn validate_device_message_payload(content: &serde_json::Value) -> Result<(), &'static str> {
    let Some(message) = content.as_object() else {
        return Err("device message must be a JSON object");
    };
    if !message
        .get("type")
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Err("device message requires type");
    }
    let Some(envelope) = message.get("content") else {
        return Err("device message requires encrypted content envelope");
    };
    validate_encrypted_payload_envelope(envelope)
}

fn validate_content_blocks(content: &serde_json::Value) -> Result<(), &'static str> {
    let Some(blocks) = content.get("blocks") else {
        return Ok(());
    };
    let Some(blocks) = blocks.as_array() else {
        return Err("content.blocks must be an array");
    };
    if blocks.is_empty() {
        return Err("content.blocks must not be empty");
    }
    for block in blocks {
        validate_content_block(block)?;
    }
    Ok(())
}

fn validate_mentions(content: &serde_json::Value) -> Result<(), &'static str> {
    let Some(mentions) = content.get("mentions") else {
        return Ok(());
    };
    let Some(mentions) = mentions.as_array() else {
        return Err("mentions must be an array");
    };
    for mention in mentions {
        if let Some(did) = mention.as_str() {
            validate_did(did).map_err(|_| "mention DID is invalid")?;
            continue;
        }
        let Some(mention) = mention.as_object() else {
            return Err("mention must be a DID string or reference object");
        };
        match mention.get("type").and_then(|value| value.as_str()) {
            Some("actor") => {
                let Some(did) = mention.get("did").and_then(|value| value.as_str()) else {
                    return Err("actor mention requires did");
                };
                validate_did(did).map_err(|_| "mention DID is invalid")?;
            }
            Some("entity") => {
                if !mention
                    .get("entity_id")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.starts_with("cx:entity:"))
                {
                    return Err("entity mention requires entity_id");
                }
            }
            _ => return Err("mention type must be actor or entity"),
        }
    }
    Ok(())
}

fn validate_canonical_json_value(value: &serde_json::Value) -> Result<(), &'static str> {
    match value {
        serde_json::Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err("canonical JSON does not allow floating point numbers");
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                validate_canonical_json_value(value)?;
            }
        }
        serde_json::Value::Object(object) => {
            for value in object.values() {
                validate_canonical_json_value(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_content_block(block: &serde_json::Value) -> Result<(), &'static str> {
    let Some(block) = block.as_object() else {
        return Err("content block must be a JSON object");
    };
    let Some(block_type) = block.get("type").and_then(|value| value.as_str()) else {
        return Err("content block requires type");
    };
    match block_type {
        "text" | "formatted_text" => {
            if !block
                .get("text")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err("text content block requires text");
            }
        }
        "code" => {
            if !block
                .get("text")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.is_empty())
            {
                return Err("code content block requires text");
            }
        }
        "image" | "video" | "audio" | "file" => {
            let has_blob_ref = block
                .get("blob_ref")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value.starts_with("cx:blob:sha256:"));
            let has_url = block
                .get("url")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty());
            if !has_blob_ref && !has_url {
                return Err("media content block requires blob_ref or url");
            }
        }
        "location" => {
            if !block.get("latitude").is_some_and(is_json_integer)
                || !block.get("longitude").is_some_and(is_json_integer)
            {
                return Err("location content block requires latitude and longitude");
            }
        }
        "poll" => {
            if !block
                .get("question")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
                || !block
                    .get("options")
                    .and_then(|value| value.as_array())
                    .is_some_and(|options| options.len() >= 2)
            {
                return Err("poll content block requires question and at least two options");
            }
        }
        _ => return Err("unsupported content block type"),
    }
    Ok(())
}

fn is_json_integer(value: &serde_json::Value) -> bool {
    value.as_i64().is_some() || value.as_u64().is_some()
}

fn validate_encrypted_payload_envelope(content: &serde_json::Value) -> Result<(), &'static str> {
    let Some(envelope) = content.as_object() else {
        return Err("encrypted content must be a JSON object");
    };
    for field in [
        "scheme",
        "group_id",
        "content_type",
        "ciphertext",
        "authentication_tag",
    ] {
        if !envelope
            .get(field)
            .and_then(|value| value.as_str())
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err("encrypted content envelope is missing required string fields");
        }
    }
    if !envelope
        .get("version")
        .is_some_and(|value| value.as_u64().is_some() || value.as_str().is_some())
    {
        return Err("encrypted content envelope requires version");
    }
    if !envelope
        .get("epoch")
        .is_some_and(|value| value.as_u64().is_some())
    {
        return Err("encrypted content envelope requires numeric epoch");
    }
    if !envelope.get("aad").is_some() {
        return Err("encrypted content envelope requires aad");
    }
    if !envelope
        .get("key_ref")
        .is_some_and(|value| value.is_object() || value.as_str().is_some())
    {
        return Err("encrypted content envelope requires key_ref");
    }
    let Some(digests) = envelope.get("digests").and_then(|value| value.as_object()) else {
        return Err("encrypted content envelope requires digests");
    };
    if digests.is_empty() {
        return Err("encrypted content envelope requires digests");
    }
    if !digests.values().all(|value| {
        value
            .as_str()
            .is_some_and(|digest| is_valid_sha256_digest(digest))
    }) {
        return Err("encrypted content envelope digests must be sha256:<64 lowercase hex>");
    }
    Ok(())
}

fn has_accepted_contact(state: &AppState, left: &str, right: &str) -> bool {
    state
        .contacts
        .lock()
        .expect("contacts lock")
        .values()
        .any(|contact| {
            contact.status == "accepted"
                && ((contact.requester == left && contact.target == right)
                    || (contact.requester == right && contact.target == left))
        })
}

fn actor_visible_to(
    state: &AppState,
    actor: &serde_json::Value,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(did) = actor["did"].as_str() else {
        return false;
    };
    if did == "did:web:alice.example" {
        return true;
    }
    session.is_some_and(|session| {
        session.actor == did || has_accepted_contact(state, &session.actor, did)
    })
}

fn demo_organization(spaces: &[&contrix_sdk::SpaceSearchEntry]) -> serde_json::Value {
    json!({
        "organization_id": "cx:org:demo",
        "handle": "@contrix-demo",
        "name": "Contrix Demo Organization",
        "description": "Demo organization projected by soland",
        "service_did": "did:web:soland.local",
        "space_count": spaces.len(),
        "actor_count": 1,
    })
}

fn demo_actors(state: &AppState) -> Vec<serde_json::Value> {
    let mut actors = vec![json!({
        "did": "did:web:alice.example",
        "handle": "@alice",
        "display_name": "Alice Example",
        "organization_id": "cx:org:demo",
        "avatar_url": null,
        "presence": {"status": "online", "updated_at": now()},
    })];

    let accounts = state.accounts.lock().expect("accounts lock");
    for account in accounts.values() {
        if actors
            .iter()
            .any(|actor| actor["did"].as_str() == Some(account.did.as_str()))
        {
            continue;
        }
        actors.push(json!({
            "did": account.did,
            "handle": account.handle,
            "display_name": account.display_name.as_deref().unwrap_or(account.did.as_str()),
            "organization_id": "cx:org:demo",
            "avatar_url": null,
            "presence": {"status": "offline", "updated_at": now()},
        }));
    }
    drop(accounts);

    let devices = state.devices.lock().expect("devices lock");
    for (did, actor_devices) in devices.iter() {
        if actors
            .iter()
            .any(|actor| actor["did"].as_str().is_some_and(|known| known == did))
        {
            continue;
        }
        let display_name = actor_devices
            .values()
            .find_map(|device| device["display_name"].as_str())
            .unwrap_or(did);
        actors.push(json!({
            "did": did,
            "handle": handle_for_did(did),
            "display_name": display_name,
            "organization_id": "cx:org:demo",
            "avatar_url": null,
            "presence": {"status": "offline", "updated_at": now()},
        }));
    }
    actors
}

fn find_demo_entity(state: &AppState, entity_id: &str) -> Option<serde_json::Value> {
    if entity_id == "cx:org:demo" {
        let spaces = state.spaces.lock().expect("spaces lock");
        return Some(demo_organization(&spaces.search(Default::default())));
    }
    if let Some(actor) = demo_actors(state)
        .into_iter()
        .find(|actor| actor["did"].as_str() == Some(entity_id))
    {
        return Some(actor);
    }
    let spaces = state.spaces.lock().expect("spaces lock");
    spaces
        .search(Default::default())
        .into_iter()
        .find(|space| {
            space.space_id.as_str() == entity_id
                && !is_space_deleted(state, space.space_id.as_str())
        })
        .map(|space| {
            json!({
                "kind": "space",
                "entity_id": space.space_id,
                "space_id": space.space_id,
                "title": space.name,
                "summary": space.description,
                "category": space.category,
                "tags": space.tags,
            })
        })
}

fn query_matches(value: &serde_json::Value, query: Option<&str>) -> bool {
    let Some(query) = query.map(str::trim).filter(|query| !query.is_empty()) else {
        return true;
    };
    value
        .to_string()
        .to_ascii_lowercase()
        .contains(&query.to_ascii_lowercase())
}

fn checked_limit(res: &mut Response, limit: Option<usize>) -> Option<usize> {
    let limit = limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "limit must be between 1 and 100",
        );
        return None;
    }
    Some(limit)
}

fn query_limit(req: &Request, res: &mut Response) -> Option<usize> {
    match query_param(req, "limit") {
        Some(raw) => match raw.parse::<usize>() {
            Ok(limit) => checked_limit(res, Some(limit)),
            Err(_) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "limit must be an integer",
                );
                None
            }
        },
        None => Some(20),
    }
}

fn normalize_handle(handle: &str) -> String {
    let trimmed = handle.trim().to_ascii_lowercase();
    if trimmed.starts_with('@') {
        trimmed
    } else {
        format!("@{trimmed}")
    }
}

fn handle_for_did(did: &str) -> String {
    did.rsplit(':')
        .next()
        .map(|tail| format!("@{}", tail.replace('.', "-")))
        .unwrap_or_else(|| "@user".to_owned())
}

#[handler]
pub async fn moderation_report(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<ModerationReportRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid moderation report request",
            );
            return;
        }
    };
    if validate_space_id(&body.space_id).is_err() || validate_did(&body.reporter).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id or reporter",
        );
        return;
    }
    if body.reporter != session.actor {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "reporter must match authenticated actor",
        );
        return;
    }
    if !space_has_member(state, &body.space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "reporter cannot see the target space",
        );
        return;
    }
    let report_id = ids::generate_report_id();
    state
        .moderation_reports
        .lock()
        .expect("moderation lock")
        .push(json!({"report_id": report_id, "space_id": body.space_id, "target_ref": body.target_ref, "reason": body.reason, "reporter": body.reporter}));
    state
        .moderation_actions
        .lock()
        .expect("moderation action lock")
        .push(json!({
            "action_id": ids::generate("moderation_action"),
            "report_id": report_id,
            "space_id": body.space_id,
            "target_ref": body.target_ref,
            "status": "open",
            "assigned_to": "did:web:soland.local#moderation",
            "created_at": now(),
        }));
    append_audit_log(
        state,
        Some(&session.actor),
        "moderation.report",
        json!({"report_id": report_id.clone()}),
        "queued",
    );
    res.render(Json(ModerationReportResponse {
        report_id,
        status: "queued".to_owned(),
        routed_to: vec!["did:web:soland.local#moderation".to_owned()],
    }));
}

#[handler]
pub async fn error_catcher(res: &mut Response, ctrl: &mut FlowCtrl) {
    let status = res.status_code.unwrap_or(StatusCode::NOT_FOUND);
    if !(status.is_client_error() || status.is_server_error()) {
        return;
    }
    if !(res.body_mut().is_none() || res.body_mut().is_error()) {
        return;
    }

    let (code, message) = match status {
        StatusCode::NOT_FOUND => ("not_found", "not found"),
        StatusCode::METHOD_NOT_ALLOWED => ("method_not_allowed", "method not allowed"),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ("unsupported_media_type", "unsupported media type"),
        StatusCode::PAYLOAD_TOO_LARGE => ("payload_too_large", "payload too large"),
        StatusCode::TOO_MANY_REQUESTS => ("rate_limited", "rate limited"),
        StatusCode::INTERNAL_SERVER_ERROR => ("internal_error", "internal server error"),
        _ if status.is_client_error() => ("bad_request", "bad request"),
        _ => ("internal_error", "internal server error"),
    };
    render_error(res, status, code, message);
    ctrl.skip_rest();
}

#[handler]
pub async fn wait_for_sync_token(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let header_name = salvo::http::header::HeaderName::from_static("x-contrix-wait-for");
    let Some(header_value) = req.headers().get(&header_name) else {
        ctrl.call_next(req, depot, res).await;
        return;
    };
    let Ok(header_value) = header_value.to_str() else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_header",
            "X-Contrix-Wait-For must be ASCII",
        );
        return;
    };
    let mut token_count = 0usize;
    for token in header_value.split(',').map(str::trim) {
        if token.is_empty() {
            continue;
        }
        token_count += 1;
        if !is_valid_sync_token(token) {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_header",
                "X-Contrix-Wait-For must contain sx:<timestamp_ms> sync tokens",
            );
            return;
        }
    }
    if token_count == 0 {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_header",
            "X-Contrix-Wait-For must contain at least one sync token",
        );
        return;
    }
    res.headers_mut().insert(
        salvo::http::header::HeaderName::from_static("x-contrix-wait-for-satisfied"),
        "true".parse().unwrap(),
    );
    ctrl.call_next(req, depot, res).await;
}

fn query_param(req: &Request, key: &str) -> Option<String> {
    req.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (name == key).then(|| value.replace('+', " "))
        })
    })
}

fn query_flag(req: &Request, key: &str) -> bool {
    query_param(req, key)
        .as_deref()
        .is_some_and(|value| matches!(value, "1" | "true" | "yes"))
}

fn is_valid_sync_token(token: &str) -> bool {
    if let Some(millis) = token.strip_prefix("sx:") {
        return millis.parse::<i64>().is_ok_and(|value| value > 0);
    }
    let Some(encoded) = token.strip_prefix("cx:cursor:") else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    value
        .get("schema")
        .and_then(|schema| schema.as_str())
        .is_some_and(|schema| schema == "cx.schema.cursor.v1")
        && value
            .get("version")
            .and_then(|version| version.as_u64())
            .is_some_and(|version| version == 1)
        && value
            .get("issued_at_ms")
            .and_then(|millis| millis.as_i64())
            .is_some_and(|millis| millis > 0)
        && value
            .get("positions")
            .is_some_and(|positions| positions.is_object())
}

fn expected_blob_sha256(req: &Request) -> Result<Option<String>, &'static str> {
    if let Some(value) = req
        .headers()
        .get("x-contrix-sha256")
        .and_then(|value| value.to_str().ok())
    {
        let digest = value.trim();
        if !is_valid_sha256_digest(digest) {
            return Err("x-contrix-sha256 must be sha256:<64 lowercase hex>");
        }
        return Ok(Some(digest.trim_start_matches("sha256:").to_owned()));
    }
    if let Some(value) = req
        .headers()
        .get(salvo::http::header::HeaderName::from_static("digest"))
        .and_then(|value| value.to_str().ok())
    {
        let Some(digest) = value.trim().strip_prefix("sha-256=") else {
            return Err("digest must be sha-256=<64 lowercase hex>");
        };
        if !is_valid_sha256_hex(digest) {
            return Err("digest must be sha-256=<64 lowercase hex>");
        }
        return Ok(Some(digest.to_owned()));
    }
    Ok(None)
}

fn is_valid_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(is_valid_sha256_hex)
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

fn generate_invite_token(invite_id: &str, space_id: &str, invitee: &str) -> String {
    format!(
        "cx:invite-token:{}",
        sha256_hex(format!("{invite_id}:{space_id}:{invitee}").as_bytes())
    )
}

fn encrypted_attachment_metadata(req: &Request) -> Result<Option<serde_json::Value>, &'static str> {
    let Some(value) = req
        .headers()
        .get(salvo::http::header::HeaderName::from_static(
            "x-contrix-attachment-envelope",
        ))
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let metadata: serde_json::Value =
        serde_json::from_str(value).map_err(|_| "attachment envelope must be JSON")?;
    validate_encrypted_attachment_metadata(&metadata)?;
    Ok(Some(metadata))
}

fn validate_encrypted_attachment_metadata(
    metadata: &serde_json::Value,
) -> Result<(), &'static str> {
    let Some(envelope) = metadata.as_object() else {
        return Err("attachment envelope must be a JSON object");
    };
    for field in ["algorithm", "nonce", "ciphertext_digest"] {
        if !envelope
            .get(field)
            .and_then(|value| value.as_str())
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err("attachment envelope is missing required string fields");
        }
    }
    if !envelope
        .get("key_ref")
        .is_some_and(|value| value.is_object() || value.as_str().is_some())
    {
        return Err("attachment envelope requires key_ref");
    }
    if !envelope
        .get("ciphertext_digest")
        .and_then(|value| value.as_str())
        .is_some_and(is_valid_sha256_digest)
    {
        return Err("attachment ciphertext_digest must be sha256:<64 lowercase hex>");
    }
    Ok(())
}

fn push_notification_leaks_plaintext(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "title" | "body" | "preview" | "content" | "plaintext" | "message"
            ) || push_notification_leaks_plaintext(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(push_notification_leaks_plaintext),
        _ => false,
    }
}

fn append_audit_log(
    state: &AppState,
    actor: Option<&str>,
    action: &str,
    target: serde_json::Value,
    outcome: &str,
) {
    state.audit_log.lock().expect("audit log lock").push(json!({
        "audit_id": ids::generate("audit"),
        "actor": actor,
        "action": action,
        "target": target,
        "outcome": outcome,
        "created_at": now(),
    }));
}

fn parse_range(req: &Request, total_len: usize) -> Option<Result<(usize, usize), &'static str>> {
    let header = req
        .headers()
        .get(salvo::http::header::RANGE)?
        .to_str()
        .ok()?;
    let Some(range) = header.strip_prefix("bytes=") else {
        return Some(Err("only bytes ranges are supported"));
    };
    let Some((start, end)) = range.split_once('-') else {
        return Some(Err("invalid range"));
    };
    let start = match start.parse::<usize>() {
        Ok(value) => value,
        Err(_) => return Some(Err("invalid range start")),
    };
    let end = if end.is_empty() {
        total_len.saturating_sub(1)
    } else {
        match end.parse::<usize>() {
            Ok(value) => value,
            Err(_) => return Some(Err("invalid range end")),
        }
    };
    if total_len == 0 || start > end || end >= total_len {
        return Some(Err("range is outside blob bounds"));
    }
    Some(Ok((start, end)))
}

fn validate_did(value: &str) -> Result<Did, ()> {
    Did::new(value.to_owned()).map_err(|_| ())
}

fn validate_device_id(value: &str) -> Result<DeviceId, ()> {
    DeviceId::new(value.to_owned()).map_err(|_| ())
}

fn validate_space_id(value: &str) -> Result<SpaceId, ()> {
    SpaceId::new(value.to_owned()).map_err(|_| ())
}

fn auth_or_render(state: &AppState, req: &Request, res: &mut Response) -> Option<SessionRecord> {
    match authenticated_session(state, req) {
        Ok(session) => Some(session),
        Err((status, code, message)) => {
            render_error(res, status, code, message);
            None
        }
    }
}

fn authenticated_session(
    state: &AppState,
    req: &Request,
) -> Result<SessionRecord, (StatusCode, &'static str, &'static str)> {
    if req.uri().query().is_some_and(|query| {
        query.contains("access_token=") || query.contains("auth=") || query.contains("token=")
    }) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "auth material in query strings is not allowed",
        ));
    }
    let token = bearer_token(req).ok_or((
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "missing bearer token",
    ))?;
    let session = state
        .sessions
        .lock()
        .expect("sessions lock")
        .get(token)
        .cloned()
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "invalid bearer token",
        ))?;
    if session.expires_at <= now() {
        return Err((StatusCode::UNAUTHORIZED, "auth_expired", "session expired"));
    }
    Ok(session)
}

fn bearer_token(req: &Request) -> Option<&str> {
    req.headers()
        .get(salvo::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn token_for(actor: &str, device_id: &str, expires_ms: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(actor.as_bytes());
    hasher.update(b":");
    hasher.update(device_id.as_bytes());
    hasher.update(b":");
    hasher.update(expires_ms.to_string().as_bytes());
    hasher.update(b":soland-dev-session");
    format!("sx_{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn render_error(res: &mut Response, status: StatusCode, code: &str, message: &str) {
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "request_id".to_owned(),
        serde_json::Value::String(ids::generate_request_id()),
    );
    res.status_code(status);
    res.render(Json(ApiError {
        ok: false,
        error: ErrorEnvelope {
            errcode: code.to_owned(),
            error: message.to_owned(),
            retry_after_ms: None,
            extra,
        },
    }));
}
