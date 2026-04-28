use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contrix_sdk::{
    Commit, CommitId, CommitProofVerifier, DeviceId, Did, ErrorEnvelope, Hash, Operation,
    OperationId, Proof, SpaceId, SpaceSearchEntry,
};
use std::collections::HashSet;
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

use crate::{
    ids,
    state::{
        AccountRecord, AppState, BlobRecord, ContactRecord, DeviceMessageRecord, MessageRecord,
        ProjectionEventRecord, SessionRecord, SpaceMetaRecord,
    },
    wire::{
        AccountResponse, AddSpaceMemberRequest, ApiError, AuthzCheckRequest, AuthzCheckResponse,
        BackfillResponse, ClientSyncRequest, ClientSyncResponse, ContactRequestRequest,
        ContactRespondRequest, ContactResponse, ContactsResponse, CreateSpaceRequest,
        DevLoginRequest, DevLoginResponse, DeviceMessagesReceiveResponse,
        DeviceMessagesSendRequest, DeviceMessagesSendResponse, DirectoryDescribeResponse,
        DirectoryValueSearchResponse, EffectiveGrantsResponse, GetOperationsRequest,
        GetOperationsResponse, HealthResponse, IdentityDescribeResponse, IdentityLogResponse,
        IdentityReceiptsResponse, IdentityResolveRequest, IdentityResolveResponse,
        IndexDescribeResponse, IndexEntityResponse, IndexInboxResponse, IndexNotificationsResponse,
        IndexQueryRequest, IndexQueryResponse, IndexSearchRequest, IndexSearchResponse,
        IndexSpaceHierarchyResponse, IndexThreadResponse, InvitesResponse, KeysClaimRequest,
        KeysClaimResponse, KeysQueryRequest, KeysQueryResponse, KeysUploadRequest,
        KeysUploadResponse, ListCommitsResponse, LogoutResponse, ModerationReportRequest,
        ModerationReportResponse, OkResponse, PolicyCheckRequest, PolicyCheckResponse,
        PushNotifyRequest, PushNotifyResponse, PushRegisterRequest, PushRegisterResponse,
        PushUnregisterRequest, RegisterAccountRequest, RepoDescribeResponse, RepoSyncRequest,
        RepoSyncResponse, ResolveHandleRequest, ResolveHandleResponse, ResolveOrganizationRequest,
        ResolveOrganizationResponse, ResolveSpaceRequest, ResolveSpaceResponse,
        SearchActorsRequest, SearchOrganizationsRequest, SearchSpacesRequest, SearchSpacesResponse,
        SendMessageRequest, SendMessageResponse, SnapshotHeadResponse, SpaceLifecycleResponse,
        SubmitCommitRequest, SubmitCommitResponse, SubmitDidOperationRequest,
        SubmitDidOperationResponse, SyncDescribeResponse, describe, now, sync_token,
    },
};

#[handler]
pub async fn health(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(HealthResponse {
        ok: true,
        service: "serverx",
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
                "device_id": body.device_id,
                "display_name": body.display_name,
                "verification": "unverified",
                "last_seen_at": now()
            }),
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
    let revoked = state
        .sessions
        .lock()
        .expect("sessions lock")
        .remove(&token)
        .is_some();
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
    accounts.insert(body.did, account.clone());
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
    let space_id = ids::generate_space_id();
    let mut entry = SpaceSearchEntry::new(
        SpaceId::new(space_id.clone()).expect("generated valid space id"),
        body.title.trim(),
    );
    entry.description = body.summary;
    entry.public = body.public;
    entry
        .members
        .insert(Did::new(session.actor.clone()).expect("session did is valid"));
    for invitee in &body.invitees {
        entry
            .members
            .insert(Did::new(invitee.clone()).expect("validated did"));
    }

    state.spaces.lock().expect("spaces lock").upsert(entry);
    state.space_meta.lock().expect("space meta lock").insert(
        space_id.clone(),
        SpaceMetaRecord {
            owner: session.actor.clone(),
            deleted: false,
            created_at: now(),
            updated_at: now(),
        },
    );
    if let Err(error) = record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "create",
            "owner": session.actor.clone(),
            "members": body.invitees,
            "public": body.public,
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
            "member": body.member,
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
    render_space_lifecycle(state, res, &space_id);
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
        vec![operation],
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
pub async fn identity_describe(res: &mut Response) {
    res.render(Json(IdentityDescribeResponse {
        service_did: "did:web:serverx.local".to_owned(),
        registry_mode: "development_local".to_owned(),
        supported_receipts: vec!["local".to_owned()],
        protocol_version: "1.0".to_owned(),
        profiles: vec!["cx.identity.local-dev.v1".to_owned()],
    }));
}

#[handler]
pub async fn identity_resolve(req: &mut Request, res: &mut Response) {
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
    res.render(Json(IdentityResolveResponse {
        did_document: json!({
            "id": body.did,
            "verification_method": [],
            "authentication": [],
            "service": [{"id": "serverx", "type": "ContrixPrincipalServer", "serviceEndpoint": "/api/v1"}]
        }),
        key_log_head: None,
        seq: 0,
        receipts: Vec::new(),
        method_evidence: json!({"mode": "development_local"}),
    }));
}

#[handler]
pub async fn identity_document(req: &mut Request, res: &mut Response) {
    let Some(did) = query_param(req, "did") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "did is required",
        );
        return;
    };
    render_identity_document(res, did, None, 0);
}

#[handler]
pub async fn identity_log(req: &mut Request, res: &mut Response) {
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
    res.render(Json(IdentityLogResponse {
        events: Vec::new(),
        next_cursor: None,
        has_more: false,
    }));
}

#[handler]
pub async fn submit_did_operation(req: &mut Request, res: &mut Response) {
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
    let head_event_hash = format!("sha256:{}", sha256_hex(body.patch.to_string().as_bytes()));
    res.render(Json(SubmitDidOperationResponse {
        status: "accepted".to_owned(),
        head_event_hash,
        seq: body.seq,
        receipts: vec![json!({"service_did": "did:web:serverx.local", "issued_at": now()})],
    }));
}

#[handler]
pub async fn identity_receipts(req: &mut Request, res: &mut Response) {
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
    res.render(Json(IdentityReceiptsResponse {
        receipts: vec![json!({"service_did": "did:web:serverx.local", "did": did})],
        threshold_met: true,
    }));
}

#[handler]
pub async fn sync_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(SyncDescribeResponse {
        service_did: "did:web:serverx.local".to_owned(),
        supported_sync_profiles: vec!["initial".to_owned(), "incremental".to_owned()],
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

    let spaces = state.spaces.lock().expect("spaces lock");
    let mut sync_spaces = std::collections::BTreeMap::new();
    let messages = state.messages.lock().expect("messages lock").clone();
    let session = authenticated_session(state, req).ok();
    for space in spaces.search(Default::default()) {
        if !space_visible_to(state, space, session.as_ref()) {
            continue;
        }
        let timeline_events: Vec<_> = messages
            .iter()
            .filter(|message| message.space_id == space.space_id.as_str())
            .map(message_event)
            .collect();
        sync_spaces.insert(
            space.space_id.to_string(),
            json!({
                "summary": {
                    "title": space.name,
                    "summary": space.description,
                    "tags": space.tags,
                    "category": space.category,
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
        service_did: "did:web:serverx.local".to_owned(),
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
        public_only: true,
        limit: body.limit,
        ..Default::default()
    };
    let spaces = state.spaces.lock().expect("spaces lock");
    let results = spaces
        .search(query)
        .into_iter()
        .filter(|space| !is_space_deleted(state, space.space_id.as_str()))
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

    let spaces = state.spaces.lock().expect("spaces lock");
    let session = authenticated_session(state, req).ok();
    let space = spaces.search(Default::default()).into_iter().find(|entry| {
        space_visible_to(state, entry, session.as_ref())
            && (body
                .space_id
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
                    "discoverability": "public",
                    "directory_visibility": {"public_directory": true}
                }
            })],
            join_rule: "public".to_owned(),
            via_services: vec!["did:web:serverx.local".to_owned()],
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
        service_did: "did:web:serverx.local".to_owned(),
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
    let events: Vec<_> = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .filter(|message| {
            (message.thread_id == thread_id || message.space_id == thread_id)
                && space_id_visible_to(state, &message.space_id, session.as_ref())
        })
        .map(message_event)
        .collect();
    res.render(Json(IndexThreadResponse {
        thread: json!({
            "thread_id": thread_id,
            "title": "Thread",
            "space_id": events.first().and_then(|event| event["space_id"].as_str()).unwrap_or("cx:space:01js0sp0000000000000000000"),
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
    let notifications: Vec<_> = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .filter(|message| message.sender != actor && space_has_member(state, &message.space_id, &actor))
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
    let messages = state.messages.lock().expect("messages lock").clone();
    let session = authenticated_session(state, req).ok();
    let rooms = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| space_visible_to(state, space, session.as_ref()))
        .take(limit)
        .map(|space| {
            let last_message = messages
                .iter()
                .rev()
                .find(|message| message.space_id == space.space_id.as_str())
                .map(message_event);
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

    for message in state.messages.lock().expect("messages lock").iter() {
        if message.encrypted || !space_id_visible_to(state, &message.space_id, session.as_ref()) {
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
        let entity = message_event(message);
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
        .filter(|operation| operation_is_visible(&operation, &redacted))
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
    let signature_payload = format!("{snapshot_ref}:{state_hash}:did:web:serverx.local");
    res.render(Json(SnapshotHeadResponse {
        snapshot_ref,
        state_hash,
        frontier: json!({"space_id": space_id, "generated_at": now(), "message_count": manifest["message_count"]}),
        signature: json!({
            "kid": "did:web:serverx.local#snapshot-dev",
            "alg": "sha256-dev",
            "sig": sha256_hex(signature_payload.as_bytes())
        }),
    }));
}

#[handler]
pub async fn repo_describe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let repo_id = query_param(req, "repo_id").unwrap_or_else(|| "did:web:serverx.local".to_owned());
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
    let repo_id = query_param(req, "repo_id").unwrap_or_else(|| "did:web:serverx.local".to_owned());
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
            repo_id: "did:web:serverx.local".to_owned(),
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
pub async fn authz_check(req: &mut Request, res: &mut Response) {
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
    let allowed = body.action.starts_with("space.read")
        || body.action.starts_with("directory.")
        || body.action == "repo.read";
    res.render(Json(AuthzCheckResponse {
        allowed,
        reason_code: (!allowed).then(|| "capability_denied".to_owned()),
        grants: if allowed {
            vec![json!({"actor": body.actor, "action": body.action, "resource": body.resource})]
        } else {
            Vec::new()
        },
        obligations: Vec::new(),
    }));
}

#[handler]
pub async fn effective_grants(req: &mut Request, res: &mut Response) {
    let subject = query_param(req, "subject").unwrap_or_else(|| "did:web:alice.example".to_owned());
    res.render(Json(EffectiveGrantsResponse {
        grants: vec![json!({
            "subject": subject,
            "actions": ["space.read", "directory.search", "repo.read"],
            "resources": [{"kind": "space", "space_id": "*"}]
        })],
        state_hash: Some(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ),
        evaluated_at: now(),
    }));
}

#[handler]
pub async fn invites(res: &mut Response) {
    res.render(Json(InvitesResponse {
        invites: Vec::new(),
        next_cursor: None,
    }));
}

#[handler]
pub async fn profile_presence(req: &mut Request, res: &mut Response) {
    let did = query_param(req, "did").unwrap_or_else(|| "did:web:alice.example".to_owned());
    res.render(Json(json!({
        "actor": did,
        "display_name": "Alice Example",
        "avatar_url": null,
        "presence": {"status": "online", "updated_at": now()}
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
            "kid": "did:web:serverx.local#policy-dev",
            "alg": "none",
            "sig": sha256_hex(body.request_canonical_hash.as_bytes())
        }),
    }));
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
            "device_id": body.device_id,
            "device_keys": body.device_keys,
            "fallback_keys": body.fallback_keys.clone(),
            "device_signature": body.device_signature,
            "mls_key_packages": body.mls_key_packages,
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
    let accepted = ingest_federation_operations(state, body.origin.as_str(), body.operations);
    res.render(Json(contrix_sdk::FederationTransactionResponse {
        ok: true,
        accepted,
        rejected: Vec::new(),
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
    let accepted = ingest_federation_operations(state, body.origin.as_str(), body.operations);
    res.render(Json(contrix_sdk::FederationPushOperationsResponse {
        accepted,
        rejected: Vec::new(),
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
    let mut seen_cursor = after_cursor.is_none();
    let mut operations = Vec::new();
    for operation in state
        .federation_operations
        .lock()
        .expect("federation lock")
        .iter()
    {
        if operation.space_id.as_str() != space_id {
            continue;
        }
        if !seen_cursor {
            seen_cursor = Some(operation.operation_id.as_str()) == after_cursor.as_deref();
            continue;
        }
        if operations.len() == limit + 1 {
            break;
        }
        operations.push(operation.clone());
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
        snapshot_bootstrap: None,
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
    let sha256 = sha256_hex(&bytes);
    if let Some(expected_sha256) = expected_blob_sha256(req)
        && expected_sha256 != sha256
    {
        render_error(
            res,
            StatusCode::CONFLICT,
            "hash_mismatch",
            "provided sha256 does not match blob content",
        );
        return;
    }
    let blob_ref = format!("cx:blob:sha256:{sha256}");
    state.blobs.lock().expect("blob lock").insert(
        blob_ref.clone(),
        BlobRecord {
            bytes,
            media_type: media_type.clone(),
            filename: None,
            uploaded_by: session.actor,
            created_at: now(),
        },
    );
    res.render(Json(crate::wire::BlobUploadResponse {
        blob_ref,
        size,
        media_type,
        sha256,
        upload_receipt: json!({"service_did": "did:web:serverx.local", "created_at": now()}),
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
            let total_len = blob.bytes.len();
            let (status, body, content_range) = match parse_range(req, total_len).transpose() {
                Ok(Some((start, end))) => {
                    let body = blob.bytes[start..=end].to_vec();
                    (
                        StatusCode::PARTIAL_CONTENT,
                        body,
                        Some(format!("bytes {start}-{end}/{total_len}")),
                    )
                }
                Ok(None) => (StatusCode::OK, blob.bytes.clone(), None),
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
            if let Some(content_range) = content_range {
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_RANGE,
                    content_range.parse().unwrap(),
                );
            }
            if req.method() != Method::HEAD {
                res.write_body(body).ok();
            }
        }
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

fn render_identity_document(
    res: &mut Response,
    did: String,
    key_log_head: Option<String>,
    seq: u64,
) {
    if validate_did(&did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    res.render(Json(IdentityResolveResponse {
        did_document: json!({
            "id": did,
            "verification_method": [],
            "authentication": [],
            "service": [{"id": "serverx", "type": "ContrixPrincipalServer", "serviceEndpoint": "/api/v1"}]
        }),
        key_log_head,
        seq,
        receipts: Vec::new(),
        method_evidence: json!({"mode": "development_local"}),
    }));
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
                .or_else(|| operation.payload.get("target").and_then(|value| value.as_str()))
                .or_else(|| operation.payload.get("redacts").and_then(|value| value.as_str()))
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
                .or_else(|| event.payload.get("redacts").and_then(|value| value.as_str()))
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

fn ingest_federation_operations(
    state: &AppState,
    origin: &str,
    operations: Vec<Operation>,
) -> Vec<OperationId> {
    let mut accepted = Vec::new();
    for operation in operations {
        if operation.validate_payload_object().is_err() {
            continue;
        }
        accepted.push(operation.operation_id.clone());
        project_federation_operation(state, origin, &operation);
        let mut federation_operations =
            state.federation_operations.lock().expect("federation lock");
        if !federation_operations
            .iter()
            .any(|known| known.operation_id == operation.operation_id)
        {
            federation_operations.push(operation);
        }
    }
    accepted
}

fn project_federation_operation(state: &AppState, origin: &str, operation: &Operation) {
    ensure_projected_space(state, origin, operation);
    match operation.object_type.as_str() {
        "message" => project_federated_message(state, origin, operation),
        "membership" | "space.lifecycle" => project_membership_operation(state, origin, operation),
        _ => {}
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
        entry.public = operation
            .payload
            .get("public")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
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
    if space.public {
        return true;
    }
    session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    })
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
    if space.public {
        return true;
    }
    session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
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
        OperationId::new(ids::generate_operation_id())
            .expect("generated valid operation id"),
        SpaceId::new(space_id.to_owned()).expect("validated space id"),
        "space.lifecycle",
        payload,
    );
    let projection_event = projection_event_from_operation(&operation, Some(actor));
    let operation_digest = Hash::new(operation.operation_digest()?)?;
    let mut commit = Commit::new(
        CommitId::new(ids::generate_commit_id())
            .expect("generated valid commit id"),
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
        domain: Some("serverx-dev".to_owned()),
        audience: None,
        jws: "dev-proof".to_owned(),
    }
}

fn validate_operation_semantics(operations: &[Operation]) -> Result<(), &'static str> {
    for operation in operations {
        operation
            .validate_payload_object()
            .map_err(|_| "operation payload must be a JSON object")?;
        match operation.object_type.as_str() {
            "message" => {
                if !(operation.payload.get("body").is_some()
                    || operation.payload.get("content").is_some()
                    || operation.payload.get("event_id").is_some())
                {
                    return Err("message operation requires body, content, or event_id");
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
        "description": "Demo organization projected by serverx",
        "service_did": "did:web:serverx.local",
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
    let report_id = format!("cx:report:{}", now().timestamp_millis());
    state
        .moderation_reports
        .lock()
        .expect("moderation lock")
        .push(json!({"report_id": report_id, "space_id": body.space_id, "target_ref": body.target_ref, "reason": body.reason, "reporter": body.reporter}));
    res.render(Json(ModerationReportResponse {
        report_id,
        status: "queued".to_owned(),
        routed_to: vec!["did:web:serverx.local#moderation".to_owned()],
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

fn expected_blob_sha256(req: &Request) -> Option<String> {
    req.headers()
        .get("x-contrix-sha256")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .trim()
                .trim_start_matches("sha256:")
                .to_ascii_lowercase()
        })
        .or_else(|| {
            req.headers()
                .get(salvo::http::header::HeaderName::from_static("digest"))
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("sha-256="))
                .map(|value| value.trim().to_ascii_lowercase())
        })
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
    hasher.update(b":serverx-dev-session");
    format!("sx_{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn render_error(res: &mut Response, status: StatusCode, code: &str, message: &str) {
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("request_id".to_owned(), serde_json::Value::String(ids::generate_request_id()));
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
