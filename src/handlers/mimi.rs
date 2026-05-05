//! MIMI (Messaging Layer Interop) provider-facade handlers.
//!
//! Surfaces under `/api/v1/mimi/*` plus the well-known
//! `mimi-protocol-directory`. All routes are scaffolds — receipts are
//! generated and audit-logged but mapping into the canonical Contrix event
//! reducer is not yet wired (tracked as Stream-C in `_todos.md`).

use chrono::Duration;
use contrix_sdk::SpaceId;
use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{ids, state::AppState};

use super::{append_audit_log, now, render_error, sha256_hex};

#[handler]
pub async fn mimi_protocol_directory(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(mimi_provider_directory_value(state)));
}

#[handler]
pub async fn mimi_provider_directory(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(mimi_provider_directory_value(state)));
}

#[handler]
pub async fn mimi_key_material(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match mimi_body(req, res).await {
        Some(body) => body,
        None => return,
    };
    if let Some(message) = unsupported_mimi_draft(&body) {
        render_error(res, StatusCode::BAD_REQUEST, "unsupported_draft", message);
        return;
    }
    let target = body
        .get("target_identifier")
        .or_else(|| body.get("target_did"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    res.render(Json(json!({
        "ok": true,
        "key_packages": [],
        "failures": {},
        "receipt": mimi_receipt(state, "cx.mimi.key_material", &body, json!({
            "target": target,
            "keypackage_claim_lifecycle": "single_use_required",
            "production_gap": "full_mls_keypackage_claim_not_implemented"
        }))
    })));
}

#[handler]
pub async fn mimi_room_update(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = req.param::<String>("room_id").unwrap_or_default();
    let body = match mimi_body(req, res).await {
        Some(body) => body,
        None => return,
    };
    if let Some(message) = unsupported_mimi_draft(&body) {
        render_error(res, StatusCode::BAD_REQUEST, "unsupported_draft", message);
        return;
    }
    if !valid_mimi_room_id(&room_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid MIMI room id",
        );
        return;
    }
    res.render(Json(json!({
        "ok": true,
        "room_id": room_id,
        "receipt": mimi_receipt(state, "cx.mimi.room_update", &body, json!({
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "truth_source": "contrix_signed_event_reducer",
            "status": "projected"
        }))
    })));
}

#[handler]
pub async fn mimi_room_notify(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = req.param::<String>("room_id").unwrap_or_default();
    let body = match mimi_body(req, res).await {
        Some(body) => body,
        None => return,
    };
    if let Some(message) = unsupported_mimi_draft(&body) {
        render_error(res, StatusCode::BAD_REQUEST, "unsupported_draft", message);
        return;
    }
    if !valid_mimi_room_id(&room_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid MIMI room id",
        );
        return;
    }
    res.status_code(StatusCode::ACCEPTED);
    res.render(Json(json!({
        "ok": true,
        "accepted": [room_id],
        "receipt": mimi_receipt(state, "cx.mimi.notify", &body, json!({
            "delivery": "queued",
            "mimi_room_uri": mimi_room_uri(state, &room_id)
        }))
    })));
}

#[handler]
pub async fn mimi_room_message(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = req.param::<String>("room_id").unwrap_or_default();
    let body = match mimi_body(req, res).await {
        Some(body) => body,
        None => return,
    };
    if let Some(message) = unsupported_mimi_draft(&body) {
        render_error(res, StatusCode::BAD_REQUEST, "unsupported_draft", message);
        return;
    }
    if !valid_mimi_room_id(&room_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid MIMI room id",
        );
        return;
    }
    let source_format = body
        .get("source_format")
        .or_else(|| body.get("content_type"))
        .and_then(|value| value.as_str())
        .unwrap_or("application/mimi-content");
    if !valid_mimi_content_type(source_format) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "unsupported MIMI content type",
        );
        return;
    }
    let operation_id = ids::generate_operation_id();
    let event_id = ids::generate_event_id();
    let mimi_message_id = body
        .get("mimi_message_id")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "mimi-msg-{}",
                operation_id.trim_start_matches("cx:operation:")
            )
        });
    let original_hash = body
        .get("original_envelope_hash")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("sha256:{}", sha256_hex(body.to_string().as_bytes())));
    let receipt = mimi_receipt(
        state,
        "cx.mimi.submit_message",
        &body,
        json!({
            "kind": "cx.mimi.mapping_receipt",
            "profile": "cx.profile.mimi_interop.v1",
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "source_format": source_format,
            "target_format": "cx.message.create",
            "original_envelope_hash": original_hash,
            "mapped_operation_id": operation_id,
            "contrix_event_id": event_id,
            "mimi_message_id": mimi_message_id,
            "truth_source": "contrix_signed_event_reducer"
        }),
    );
    append_audit_log(
        state,
        None,
        "mimi.submit_message",
        json!({
            "room_id": room_id,
            "operation_id": operation_id,
            "event_id": event_id,
            "source_format": source_format
        }),
        "mapped",
    );
    res.render(Json(json!({
        "ok": true,
        "mimi_message_id": mimi_message_id,
        "mapped_operation_id": operation_id,
        "contrix_event_id": event_id,
        "receipt": receipt
    })));
}

#[handler]
pub async fn mimi_group_info(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = req.param::<String>("room_id").unwrap_or_default();
    if !valid_mimi_room_id(&room_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid MIMI room id",
        );
        return;
    }
    let projection = mimi_room_projection(state, &room_id);
    res.render(Json(json!({
        "room_id": room_id,
        "mimi_room_uri": projection["mimi_room_uri"].clone(),
        "group_info": projection,
        "participants": mimi_demo_participants(state),
        "receipt": mimi_receipt(state, "cx.mimi.group_info", &json!({"room_id": room_id}), json!({
            "truth_source": "contrix_signed_event_reducer",
            "projection_only": true
        }))
    })));
}

#[handler]
pub async fn mimi_consent_request(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match mimi_body(req, res).await {
        Some(body) => body,
        None => return,
    };
    if let Some(message) = unsupported_mimi_draft(&body) {
        render_error(res, StatusCode::BAD_REQUEST, "unsupported_draft", message);
        return;
    }
    let consent_id = ids::generate("mimi_consent");
    res.status_code(StatusCode::ACCEPTED);
    res.render(Json(json!({
        "ok": true,
        "consent_id": consent_id,
        "state": "requested",
        "receipt": mimi_receipt(state, "cx.mimi.request_consent", &body, json!({
            "consent_grants_space_capability": false,
            "privacy_state": "holder_private"
        }))
    })));
}

#[handler]
pub async fn mimi_consent_update(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match mimi_body(req, res).await {
        Some(body) => body,
        None => return,
    };
    if let Some(message) = unsupported_mimi_draft(&body) {
        render_error(res, StatusCode::BAD_REQUEST, "unsupported_draft", message);
        return;
    }
    let consent_id = body
        .get("consent_id")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| ids::generate("mimi_consent"));
    let state_value = body
        .get("state")
        .and_then(|value| value.as_str())
        .unwrap_or("accepted");
    res.render(Json(json!({
        "ok": true,
        "consent_id": consent_id,
        "state": state_value,
        "receipt": mimi_receipt(state, "cx.mimi.update_consent", &body, json!({
            "consent_grants_space_capability": false,
            "membership_still_required": true
        }))
    })));
}

#[handler]
pub async fn mimi_identifiers_query(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match mimi_body(req, res).await {
        Some(body) => body,
        None => return,
    };
    if let Some(message) = unsupported_mimi_draft(&body) {
        render_error(res, StatusCode::BAD_REQUEST, "unsupported_draft", message);
        return;
    }
    let query = body
        .get("query")
        .or_else(|| body.get("target_identifier"))
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned();
    if query.is_empty() || !(query.starts_with("mimi://") || query.starts_with("did:")) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "identifier query must be a MIMI URI or DID",
        );
        return;
    }
    let mapped_did = query
        .contains("alice")
        .then(|| "did:web:alice.example".to_owned());
    res.render(Json(json!({
        "query": query,
        "reachable": mapped_did.is_some(),
        "mapped_did": mapped_did,
        "provider_id": mimi_provider_id(state),
        "proofs": [{
            "type": "time_bound_reachability",
            "privacy_mode": "private_contact_discovery",
            "expires_at": now() + Duration::minutes(5)
        }],
        "receipt": mimi_receipt(state, "cx.mimi.identifier_query", &body, json!({
            "contact_graph_exposed": false,
            "connection_identifier_separated": true
        }))
    })));
}

#[handler]
pub async fn mimi_report_abuse(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match mimi_body(req, res).await {
        Some(body) => body,
        None => return,
    };
    if let Some(message) = unsupported_mimi_draft(&body) {
        render_error(res, StatusCode::BAD_REQUEST, "unsupported_draft", message);
        return;
    }
    let report_id = ids::generate_report_id();
    state
        .moderation_reports
        .lock()
        .expect("moderation lock")
        .push(json!({
            "report_id": report_id,
            "kind": "mimi_abuse_report",
            "mimi_room_uri": body.get("mimi_room_uri").cloned(),
            "provider_id": body.get("provider_id").cloned(),
            "target_event_hash": body.get("target_event_hash").cloned(),
            "frank": body.get("frank").cloned(),
            "created_at": now()
        }));
    res.status_code(StatusCode::ACCEPTED);
    res.render(Json(json!({
        "ok": true,
        "report_id": report_id,
        "status": "queued",
        "receipt": mimi_receipt(state, "cx.mimi.report_abuse", &body, json!({
            "e2ee_evidence_plaintext_required": false,
            "routed_to": [format!("{}#moderation", state.config.service_did)]
        }))
    })));
}

#[handler]
pub async fn mimi_proxy_download(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match mimi_body(req, res).await {
        Some(body) => body,
        None => return,
    };
    if let Some(message) = unsupported_mimi_draft(&body) {
        render_error(res, StatusCode::BAD_REQUEST, "unsupported_draft", message);
        return;
    }
    let Some(blob_ref) = body.get("blob_ref").and_then(|value| value.as_str()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "blob_ref is required",
        );
        return;
    };
    let asset_policy = body
        .get("asset_privacy_policy")
        .and_then(|value| value.as_str())
        .unwrap_or("provider_proxy");
    let blob = state
        .blobs
        .lock()
        .expect("blob lock")
        .get(blob_ref)
        .cloned();
    let proxy_required = matches!(asset_policy, "provider_proxy" | "ohttp_relay");
    res.render(Json(json!({
        "ok": true,
        "blob_ref": blob_ref,
        "media_type": blob.as_ref().map(|blob| blob.media_type.clone()),
        "size": blob.as_ref().map(|blob| blob.bytes.len()),
        "proxy_url": if proxy_required {
            Some(format!("{}/proxy-download?blob_ref={}", mimi_base_url(state), blob_ref))
        } else {
            None
        },
        "receipt": mimi_receipt(state, "cx.mimi.proxy_download", &body, json!({
            "asset_privacy_policy": asset_policy,
            "direct_object_store_url_returned": false,
            "client_must_verify_content_hash": true
        }))
    })));
}

async fn mimi_body(req: &mut Request, res: &mut Response) -> Option<Value> {
    match req.parse_json::<Value>().await {
        Ok(body) => Some(body),
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid MIMI request",
            );
            None
        }
    }
}

fn mimi_provider_directory_value(state: &AppState) -> Value {
    json!({
        "schema": "cx.schema.mimi_interop.v1",
        "service_did": state.config.service_did.clone(),
        "service_type": "mimi_provider_facade",
        "supported_profiles": ["cx.profile.mimi_interop.v1"],
        "mimi": {
            "protocol_draft": "draft-ietf-mimi-protocol-06",
            "content_draft": "draft-ietf-mimi-content-08",
            "room_policy_draft": "draft-ietf-mimi-room-policy-03",
            "identifier_draft": "draft-kohbrok-mimi-identifiers-01",
            "base_url": mimi_base_url(state),
            "provider_id": mimi_provider_id(state),
            "features": [
                "key_material",
                "room_update",
                "notify",
                "submit_message",
                "group_info",
                "consent",
                "identifier_query",
                "report_abuse",
                "proxy_download"
            ],
            "mls_cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
            "content_profiles": [
                "application/mimi-content",
                "text/plain;charset=utf-8",
                "text/markdown;variant=GFM-MIMI",
                "application/vnd.contrix.content+json"
            ],
            "room_policy_components": [
                "roles",
                "membership",
                "history_visibility",
                "join_rule",
                "message_expiration",
                "asset_privacy"
            ]
        },
        "proof": {
            "type": "dev_service_digest",
            "kid": format!("{}#mimi-provider", state.config.service_did),
            "alg": "sha256-dev",
            "sig": sha256_hex(format!("{}:cx.profile.mimi_interop.v1", state.config.service_did).as_bytes())
        }
    })
}

fn mimi_base_url(state: &AppState) -> String {
    format!(
        "{}/api/v1/mimi",
        state.config.public_base_url.trim_end_matches('/')
    )
}

fn mimi_provider_id(state: &AppState) -> String {
    state
        .config
        .service_did
        .strip_prefix("did:web:")
        .map(|domain| format!("mimi://{}", domain.replace(':', "/")))
        .unwrap_or_else(|| format!("mimi://{}", state.config.service_did.replace(':', ".")))
}

fn mimi_room_uri(state: &AppState, room_id: &str) -> String {
    format!("{}/rooms/{room_id}", mimi_provider_id(state))
}

fn mimi_receipt(state: &AppState, operation_id: &str, body: &Value, extra: Value) -> Value {
    json!({
        "profile": "cx.profile.mimi_interop.v1",
        "operation_id": operation_id,
        "service_did": state.config.service_did,
        "provider_id": mimi_provider_id(state),
        "request_hash": format!("sha256:{}", sha256_hex(body.to_string().as_bytes())),
        "accepted_at": now(),
        "drafts": {
            "protocol": "draft-ietf-mimi-protocol-06",
            "content": "draft-ietf-mimi-content-08",
            "room_policy": "draft-ietf-mimi-room-policy-03",
            "identifiers": "draft-kohbrok-mimi-identifiers-01"
        },
        "extra": extra
    })
}

fn mimi_room_projection(state: &AppState, room_id: &str) -> Value {
    let space_id = "cx:space:01js0sp0000000000000000000";
    json!({
        "kind": "cx.mimi.room_binding",
        "profile": "cx.profile.mimi_interop.v1",
        "mimi_room_uri": mimi_room_uri(state, room_id),
        "binding_scope": {
            "space_id": space_id,
            "channel_id": Value::Null
        },
        "hub_provider": state.config.service_did.clone(),
        "local_provider_role": "hub",
        "mls_group_id": format!("mls:{}", room_id),
        "policy_root": format!("sha256:{}", sha256_hex(format!("{space_id}:{room_id}:policy").as_bytes())),
        "status": "accepted",
        "canonical_truth": "contrix_signed_event_reducer"
    })
}

fn mimi_demo_participants(state: &AppState) -> Vec<Value> {
    let space_id = SpaceId::new("cx:space:01js0sp0000000000000000000".to_owned())
        .expect("demo space id is valid");
    state
        .spaces
        .lock()
        .expect("spaces lock")
        .get(&space_id)
        .map(|space| {
            space
                .members
                .iter()
                .map(|did| {
                    json!({
                        "mimi_identifier": format!("{}/users/{}", mimi_provider_id(state), did.to_string().replace(':', ".")),
                        "did": did.to_string(),
                        "role": "member"
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn unsupported_mimi_draft(body: &Value) -> Option<&'static str> {
    for (field, expected, message) in [
        (
            "protocol_draft",
            "draft-ietf-mimi-protocol-06",
            "unsupported MIMI protocol draft",
        ),
        (
            "content_draft",
            "draft-ietf-mimi-content-08",
            "unsupported MIMI content draft",
        ),
        (
            "room_policy_draft",
            "draft-ietf-mimi-room-policy-03",
            "unsupported MIMI room policy draft",
        ),
        (
            "identifier_draft",
            "draft-kohbrok-mimi-identifiers-01",
            "unsupported MIMI identifier draft",
        ),
    ] {
        let value = body
            .get(field)
            .or_else(|| body.get("mimi").and_then(|mimi| mimi.get(field)))
            .and_then(|value| value.as_str());
        if value.is_some_and(|value| value != expected) {
            return Some(message);
        }
    }
    None
}

fn valid_mimi_room_id(room_id: &str) -> bool {
    !room_id.is_empty()
        && room_id.len() <= 256
        && room_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '~'))
}

fn valid_mimi_content_type(value: &str) -> bool {
    matches!(
        value,
        "application/mimi-content"
            | "text/plain;charset=utf-8"
            | "text/markdown;variant=GFM-MIMI"
            | "application/vnd.contrix.content+json"
    )
}
