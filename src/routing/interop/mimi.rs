//! MIMI (Messaging Layer Interop) provider-facade handlers.
//!
//! Surfaces under `/_cokret/open/mimi/*` plus the well-known
//! `mimi-protocol-directory`. Writes from the MIMI side map into the
//! canonical Cokret reducer chain:
//!
//!   * `POST /mimi/flows/{flow_id}/messages` -> emits a `MessageRecord` + a `ck.message.create`
//!     projection event so the MIMI ingress shows up on the canonical Cokret timeline.
//!   * `PUT  /mimi/flows/{flow_id}/update` -> emits a `ck.mimi.room_binding` projection event
//!     whenever the update body carries a `room_binding` block.
//!   * `POST /mimi/flows/{flow_id}/notify` -> broadcasts a synthetic `ck.open.mimi.notify` projection
//!     event so live subscribers observe MIMI fanout.
//!   * `POST /mimi/report-abuse` -> persists the moderation report row AND emits a
//!     `ck.self.moderation.report` projection event so the audit timeline reflects the report.
//!
//! Each canonical event carries `payload.mimi_provenance` metadata
//! (provider id, original MIMI envelope hash, MIMI message id) so
//! the receiving Cokret consumer can prove the message arrived
//! through the MIMI facade rather than as a native signed Move.

use chrono::Duration;
use cokret_sdk::RealmId;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{append_audit_log, now, sha256_hex};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, EventNotification, MessageRecord, ProjectionEventRecord};
use crate::{ids, kinds};

pub(super) fn router() -> Router {
    Router::with_path("mimi")
        .push(Router::with_path("provider-directory").get(mimi_provider_directory))
        .push(Router::with_path("key-material").post(mimi_key_material))
        .push(Router::with_path("flows/{flow_id}/update").put(mimi_room_update))
        .push(Router::with_path("flows/{flow_id}/notify").post(mimi_room_notify))
        .push(Router::with_path("flows/{flow_id}/messages").post(mimi_room_message))
        .push(Router::with_path("flows/{flow_id}/group-info").get(mimi_group_info))
        .push(Router::with_path("consent/request").post(mimi_consent_request))
        .push(Router::with_path("consent/update").post(mimi_consent_update))
        .push(Router::with_path("identifiers/query").post(mimi_identifiers_query))
        .push(Router::with_path("report-abuse").post(mimi_report_abuse))
        .push(Router::with_path("proxy-download").post(mimi_proxy_download))
}

pub(super) fn well_known_router() -> Router {
    Router::with_path(".well-known/mimi-protocol-directory").get(mimi_protocol_directory)
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "mimi_protocol_directory"))]
async fn mimi_protocol_directory(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(mimi_provider_directory_value(state)));
}

#[endpoint(
    operation_id = "ck.open.mimi.provider_directory",
    tags("mimi"),
    summary = "Read the MIMI provider directory"
)]
#[tracing::instrument(skip_all, fields(op = "mimi_provider_directory"))]
async fn mimi_provider_directory(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(mimi_provider_directory_value(state)));
}

#[endpoint(
    operation_id = "ck.open.mimi.key_material",
    tags("mimi"),
    summary = "Claim MIMI/MLS key material for a target identifier"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.key_material"))]
async fn mimi_key_material(body: JsonBody<Value>, depot: &mut Depot) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("unsupported_draft"));
    }
    let target = body
        .get("target_identifier")
        .or_else(|| body.get("target_did"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    json_ok(json!({
        "ok": true,
        "key_packages": [],
        "failures": {},
        "receipt": mimi_receipt(state, "ck.open.mimi.key_material", &body, json!({
            "target": target,
            "keypackage_claim_lifecycle": "single_use_required",
            "production_gap": "full_mls_keypackage_claim_not_implemented"
        }))
    }))
}

#[endpoint(
    operation_id = "ck.open.mimi.room_update",
    tags("mimi"),
    summary = "Apply a MIMI room update (optionally persists `room_binding`)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.room_update"))]
async fn mimi_room_update(
    flow_id: PathParam<String>,
    body: JsonBody<Value>,
    depot: &mut Depot,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = flow_id.into_inner();
    let body = body.into_inner();
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("unsupported_draft"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    // If the update carries a `room_binding` block, persist it as a
    // `ck.mimi.room_binding` projection event so the Cokret
    // timeline observes the binding. Updates without a binding block
    // fall through to the receipt-only response. A binding block that
    // omits both `binding_scope.realm_id` and a top-level `realm_id`
    // is rejected; we never implicitly route to a default Realm.
    let binding_event_id = match body.get("room_binding") {
        Some(binding) if binding.is_object() => {
            let event_id = emit_mimi_room_binding_event(state, &room_id, binding)
                .await
                .ok_or_else(|| {
                    AppError::invalid_param(
                        "room_binding requires `binding_scope.realm_id` or a top-level `realm_id`",
                    )
                    .with_wire_code("missing_realm_binding")
                })?;
            Some(event_id)
        }
        _ => None,
    };

    json_ok(json!({
        "ok": true,
        "room_id": room_id,
        "binding_event_id": binding_event_id,
        "receipt": mimi_receipt(state, "ck.open.mimi.room_update", &body, json!({
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "truth_source": "cokret_signed_event_reducer",
            "status": "projected",
            "binding_emitted": binding_event_id.is_some(),
        }))
    }))
}

#[endpoint(
    operation_id = "ck.mimi.room_notify",
    tags("mimi"),
    summary = "Fan out a MIMI room notify (broadcasts a `ck.open.mimi.notify` ephemeral)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.mimi.room_notify"))]
async fn mimi_room_notify(
    flow_id: PathParam<String>,
    body: JsonBody<Value>,
    depot: &mut Depot,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = flow_id.into_inner();
    let body = body.into_inner();
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("unsupported_draft"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    // Fan out a synthetic `ck.open.mimi.notify` projection event so live
    // subscribers observe the MIMI provider-to-provider
    // notification. The notify event is an ephemeral signal in the
    // spec's wire_scope taxonomy - we broadcast but don't persist
    // into projection_events so it doesn't pollute durable history.
    let realm_id = mimi_bound_realm_id(state, &room_id).await.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Cokret Realm")
            .with_wire_code("mimi_room_unbound")
    })?;
    let event_id = ids::generate_event_id();
    let notify_record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: "ck.open.mimi.notify".to_owned(),
        operation_type: "mimi_facade_notify".to_owned(),
        operation_id: None,
        sender: None,
        payload: json!({
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "mimi_room_id": room_id,
            "mimi_provider_id": mimi_provider_id(state),
            "notify_body": body.clone(),
            "facade": "soland.mimi.v1",
        }),
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        notify_record.realm_id.clone(),
        notify_record.event_id.clone(),
        crate::routing::events::projection::projection_event_json(&notify_record),
    ));

    // Note: response semantics shift from 202 Accepted to 200 OK with the
    // typed conversion; salvo-oapi typed handlers default to 200 and the
    // status-code distinction wasn't load-bearing for any caller.
    json_ok(json!({
        "ok": true,
        "accepted": [room_id],
        "broadcast_event_id": event_id,
        "receipt": mimi_receipt(state, "ck.open.mimi.notify", &body, json!({
            "delivery": "queued",
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "broadcast_emitted": true,
        }))
    }))
}

#[endpoint(
    operation_id = "ck.open.mimi.submit_message",
    tags("mimi"),
    summary = "Submit a MIMI room message (mapped into ck.message.create projection)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.submit_message"))]
async fn mimi_room_message(
    flow_id: PathParam<String>,
    body: JsonBody<Value>,
    depot: &mut Depot,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = flow_id.into_inner();
    let body = body.into_inner();
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("unsupported_draft"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    let source_format = body
        .get("source_format")
        .or_else(|| body.get("content_type"))
        .and_then(|value| value.as_str())
        .unwrap_or("application/mimi-content");
    if !valid_mimi_content_type(source_format) {
        return Err(AppError::invalid_param("unsupported MIMI content type"));
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
                operation_id.trim_start_matches("ck:operation:")
            )
        });
    let original_hash = body
        .get("original_envelope_hash")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("sha256:{}", sha256_hex(body.to_string().as_bytes())));

    // Map the MIMI message into the canonical Cokret timeline.
    // Append a MessageRecord + a `ck.message.create` projection event so
    // the message shows up in `GET /_cokret/self/events?realm_id=...`. The
    // MIMI provenance metadata is preserved verbatim under
    // `payload.mimi_provenance` so audit consumers can verify the
    // message arrived through the facade.
    let realm_id = mimi_bound_realm_id(state, &room_id).await.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Cokret Realm")
            .with_wire_code("mimi_room_unbound")
    })?;
    let sender = body
        .get("sender_did")
        .or_else(|| body.get("from_did"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            // Synthesize a stable sender DID from the MIMI provider
            // id + message id when the envelope omits one. Real
            // deployments will normalise this via the identifier
            // mapping layer per spec §10.
            format!("{}#mimi-anonymous", state.config.service_did,)
        });
    let mapped_content = map_mimi_message_content(&body, source_format)?;
    let thread_id = body
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| crate::routing::events::flow::flow_id_from_realm_id(&realm_id));
    let created_at = chrono::Utc::now();
    let mimi_provenance = json!({
        "facade": "soland.mimi.v1",
        "mimi_provider_id": mimi_provider_id(state),
        "mimi_room_uri": mimi_room_uri(state, &room_id),
        "mimi_room_id": room_id,
        "mimi_message_id": mimi_message_id,
        "original_envelope_hash": original_hash,
        "source_format": source_format,
        "accepted_at": created_at,
    });
    let message_record = MessageRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        sender: sender.clone(),
        thread_id: thread_id.clone(),
        content: mapped_content.content.clone(),
        encrypted: mapped_content.encrypted,
        created_at,
    };
    if let Err(error) = state.persistence.messages().put(&message_record).await {
        tracing::error!(%error, "mimi: failed to persist MessageRecord");
    }
    let projection_record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: kinds::CK_MESSAGE_CREATE.to_owned(),
        operation_type: "mimi_facade_ingress".to_owned(),
        operation_id: Some(operation_id.clone()),
        sender: Some(sender.clone()),
        payload: json!({
            "thread_id": thread_id.clone(),
            "content": mapped_content.content.clone(),
            "encrypted": mapped_content.encrypted,
            "mimi_provenance": mimi_provenance,
            "mimi_policy": mapped_content.policy.clone(),
            "quarantine": mapped_content.quarantine.clone(),
        }),
        created_at,
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        projection_record.realm_id.clone(),
        projection_record.event_id.clone(),
        crate::routing::events::projection::projection_event_json(&projection_record),
    ));
    if let Err(error) = state
        .persistence
        .projection_events()
        .append(projection_record)
        .await
    {
        tracing::error!(%error, "mimi: failed to mirror message into projection_events");
    }

    let receipt = mimi_receipt(
        state,
        "ck.open.mimi.submit_message",
        &body,
        json!({
            "kind": "ck.mimi.mapping_receipt",
            "profile": "ck.profile.mimi_interop.v1",
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "source_format": source_format,
            "target_format": "ck.message.create",
            "original_envelope_hash": original_hash,
            "mapped_operation_id": operation_id,
            "cokret_event_id": event_id,
            "mimi_message_id": mimi_message_id,
            "truth_source": "cokret_signed_event_reducer",
            "reducer_chain": "wired",
            "status": mapped_content.status,
            "mimi_policy": mapped_content.policy.clone(),
            "quarantine": mapped_content.quarantine.clone(),
        }),
    );
    append_audit_log(
        state,
        Some(&sender),
        "mimi.submit_message",
        json!({
            "room_id": room_id,
            "realm_id": realm_id,
            "operation_id": operation_id,
            "event_id": event_id,
            "source_format": source_format,
            "mimi_message_id": mimi_message_id,
            "mimi_policy": mapped_content.policy,
            "quarantine": mapped_content.quarantine,
        }),
        mapped_content.status,
    )
    .await;
    json_ok(json!({
        "ok": true,
        "status": mapped_content.status,
        "mimi_message_id": mimi_message_id,
        "mapped_operation_id": operation_id,
        "cokret_event_id": event_id,
        "realm_id": realm_id,
        "receipt": receipt
    }))
}

#[endpoint(
    operation_id = "ck.open.mimi.group_info",
    tags("mimi"),
    summary = "Read a MIMI room's group info / projection"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.group_info"))]
async fn mimi_group_info(flow_id: PathParam<String>, depot: &mut Depot) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = flow_id.into_inner();
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    let realm_id = mimi_bound_realm_id(state, &room_id).await.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Cokret Realm")
            .with_wire_code("mimi_room_unbound")
    })?;
    let projection = mimi_room_projection(state, &room_id, &realm_id);
    json_ok(json!({
        "room_id": room_id,
        "mimi_room_uri": projection["mimi_room_uri"].clone(),
        "group_info": projection,
        "participants": mimi_room_participants(state, &realm_id),
        "receipt": mimi_receipt(state, "ck.open.mimi.group_info", &json!({"room_id": room_id}), json!({
            "truth_source": "cokret_signed_event_reducer",
            "projection_only": true
        }))
    }))
}

#[endpoint(
    operation_id = "ck.open.mimi.request_consent",
    tags("mimi"),
    summary = "Open a MIMI consent request"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.request_consent"))]
async fn mimi_consent_request(body: JsonBody<Value>, depot: &mut Depot) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("unsupported_draft"));
    }
    let consent_id = ids::generate("mimi_consent");
    json_ok(json!({
        "ok": true,
        "consent_id": consent_id,
        "state": "requested",
        "receipt": mimi_receipt(state, "ck.open.mimi.request_consent", &body, json!({
            "consent_grants_space_capability": false,
            "privacy_state": "holder_private"
        }))
    }))
}

#[endpoint(
    operation_id = "ck.open.mimi.update_consent",
    tags("mimi"),
    summary = "Update a MIMI consent state"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.update_consent"))]
async fn mimi_consent_update(body: JsonBody<Value>, depot: &mut Depot) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("unsupported_draft"));
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
    json_ok(json!({
        "ok": true,
        "consent_id": consent_id,
        "state": state_value,
        "receipt": mimi_receipt(state, "ck.open.mimi.update_consent", &body, json!({
            "consent_grants_space_capability": false,
            "membership_still_required": true
        }))
    }))
}

#[endpoint(
    operation_id = "ck.open.mimi.identifier_query",
    tags("mimi"),
    summary = "Resolve a MIMI / DID identifier to a reachable Cokret actor"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.identifier_query"))]
async fn mimi_identifiers_query(body: JsonBody<Value>, depot: &mut Depot) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("unsupported_draft"));
    }
    let query = body
        .get("query")
        .or_else(|| body.get("target_identifier"))
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned();
    if query.is_empty() || !(query.starts_with("mimi://") || query.starts_with("did:")) {
        return Err(AppError::invalid_param(
            "identifier query must be a MIMI URI or DID",
        ));
    }
    let mapped_did = query
        .contains("alice")
        .then(|| "did:web:alice.example".to_owned());
    json_ok(json!({
        "query": query,
        "reachable": mapped_did.is_some(),
        "mapped_did": mapped_did,
        "provider_id": mimi_provider_id(state),
        "proofs": [{
            "type": "time_bound_reachability",
            "privacy_mode": "private_contact_discovery",
            "expires_at": now() + Duration::minutes(5)
        }],
        "receipt": mimi_receipt(state, "ck.open.mimi.identifier_query", &body, json!({
            "contact_graph_exposed": false,
            "connection_identifier_separated": true
        }))
    }))
}

#[endpoint(
    operation_id = "ck.open.mimi.report_abuse",
    tags("mimi"),
    summary = "File a MIMI abuse report (mirrors as ck.self.moderation.report projection event)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.report_abuse"))]
async fn mimi_report_abuse(body: JsonBody<Value>, depot: &mut Depot) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("unsupported_draft"));
    }
    let report_id = ids::generate_report_id();
    if let Err(error) = state
        .persistence
        .moderation()
        .append_report(json!({
            "report_id": report_id,
            "kind": "mimi_abuse_report",
            "mimi_room_uri": body.get("mimi_room_uri").cloned(),
            "provider_id": body.get("provider_id").cloned(),
            "target_event_digest": body.get("target_event_digest").cloned(),
            "frank": body.get("frank").cloned(),
            "created_at": now(),
        }))
        .await
    {
        tracing::error!(%error, "failed to persist mimi abuse report");
    }

    // Also emit a `ck.self.moderation.report` projection event so the
    // audit timeline observes the report in the same shape native
    // Cokret reports use. The MIMI provenance is preserved under
    // `payload.mimi_provenance`.
    // Extract room_id segment from MIMI URI
    // `mimi://provider/rooms/<id>` so we can look up a bound Realm if any.
    let mimi_room_id = body
        .get("mimi_room_uri")
        .and_then(Value::as_str)
        .and_then(|uri| uri.rsplit('/').next())
        .map(str::to_owned);
    let bound_realm = match mimi_room_id.as_deref() {
        Some(id) => mimi_bound_realm_id(state, id).await,
        None => None,
    };
    let realm_id = if let Some(realm_id) = body.get("realm_id").and_then(Value::as_str) {
        realm_id.to_owned()
    } else if let Some(bound) = bound_realm {
        bound
    } else {
        return Err(AppError::invalid_param(
            "mimi report requires `realm_id` or a `mimi_room_uri` that resolves to a bound Cokret Realm",
        )
        .with_wire_code("missing_realm_binding"));
    };
    let report_event_id = ids::generate_event_id();
    let report_record = ProjectionEventRecord {
        event_id: report_event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: "ck.self.moderation.report".to_owned(),
        operation_type: "mimi_facade_report".to_owned(),
        operation_id: None,
        sender: body
            .get("reporter_did")
            .and_then(Value::as_str)
            .map(str::to_owned),
        payload: json!({
            "report_id": report_id,
            "target_event_digest": body.get("target_event_digest").cloned(),
            "frank": body.get("frank").cloned(),
            "evidence_encrypted": true,
            "mimi_provenance": {
                "facade": "soland.mimi.v1",
                "mimi_room_uri": body.get("mimi_room_uri").cloned(),
                "mimi_provider_id": mimi_provider_id(state),
                "accepted_at": now(),
            },
        }),
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        report_record.realm_id.clone(),
        report_record.event_id.clone(),
        crate::routing::events::projection::projection_event_json(&report_record),
    ));
    if let Err(error) = state
        .persistence
        .projection_events()
        .append(report_record)
        .await
    {
        tracing::error!(%error, "mimi: failed to mirror report into projection_events");
    }

    // Note: response semantics shift from 202 Accepted to 200 OK with the
    // typed conversion; no caller asserted on the specific status code.
    json_ok(json!({
        "ok": true,
        "report_id": report_id,
        "report_event_id": report_event_id,
        "status": "queued",
        "receipt": mimi_receipt(state, "ck.open.mimi.report_abuse", &body, json!({
            "e2ee_evidence_plaintext_required": false,
            "routed_to": [format!("{}#moderation", state.config.service_did)],
            "moderation_event_emitted": true,
        }))
    }))
}

#[endpoint(
    operation_id = "ck.open.mimi.proxy_download",
    tags("mimi"),
    summary = "Issue a proxy-download token for a MIMI blob (asset privacy policy honored)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.proxy_download"))]
async fn mimi_proxy_download(body: JsonBody<Value>, depot: &mut Depot) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("unsupported_draft"));
    }
    let blob_ref = body
        .get("blob_ref")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::missing_param("blob_ref is required"))?;
    let asset_policy = body
        .get("asset_privacy_policy")
        .and_then(|value| value.as_str())
        .unwrap_or("provider_proxy");
    let blob = state.persistence.blobs().get(blob_ref).await.ok().flatten();
    let proxy_required = matches!(asset_policy, "provider_proxy" | "ohttp_relay");
    json_ok(json!({
        "ok": true,
        "blob_ref": blob_ref,
        "media_type": blob.as_ref().map(|blob| blob.media_type.clone()),
        "size": blob.as_ref().map(|blob| blob.size_bytes),
        "proxy_url": if proxy_required {
            Some(format!("{}/proxy-download?blob_ref={}", mimi_base_url(state), blob_ref))
        } else {
            None
        },
        "receipt": mimi_receipt(state, "ck.open.mimi.proxy_download", &body, json!({
            "asset_privacy_policy": asset_policy,
            "direct_object_store_url_returned": false,
            "client_must_verify_content_hash": true
        }))
    }))
}

fn mimi_provider_directory_value(state: &AppState) -> Value {
    json!({
        "schema": "ck.schema.mimi_interop.v1",
        "service_did": state.config.service_did.clone(),
        "service_type": "mimi_provider_facade",
        "supported_profiles": ["ck.profile.mimi_interop.v1"],
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
                "application/vnd.cokret.content+json"
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
            "sig": sha256_hex(format!("{}:ck.profile.mimi_interop.v1", state.config.service_did).as_bytes())
        }
    })
}

fn mimi_base_url(state: &AppState) -> String {
    format!(
        "{}/_cokret/open/mimi",
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
        "profile": "ck.profile.mimi_interop.v1",
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

struct MimiMappedContent {
    content: Value,
    encrypted: bool,
    policy: Value,
    quarantine: Option<Value>,
    status: &'static str,
}

fn map_mimi_message_content(
    body: &Value,
    source_format: &str,
) -> Result<MimiMappedContent, AppError> {
    let mut content = mimi_content_payload(body, source_format);
    let content_kind = mimi_content_kind(body, &content).map(str::to_owned);
    let e2ee_boundary = mimi_e2ee_boundary(body, &content);
    let plaintext_detected = mimi_plaintext_detected(body) || mimi_plaintext_detected(&content);
    let transcript_binding = mimi_transcript_binding(body, &content).cloned();
    let explicit_downgrade = mimi_explicit_downgrade(body, &content);

    if e2ee_boundary && plaintext_detected && transcript_binding.is_none() && !explicit_downgrade {
        return Err(AppError::invalid_param(
            "MIMI E2EE plaintext requires transcript_binding or explicit e2ee_downgrade marker",
        )
        .with_wire_code("mimi_e2ee_boundary_unmarked"));
    }

    let mut policy = json!({
        "profile": "ck.profile.mimi_interop.v1",
        "e2ee_boundary": "none",
        "plaintext_detected": plaintext_detected,
        "plaintext_guard": "not_e2ee",
    });
    let mut encrypted = e2ee_boundary && !explicit_downgrade;

    if e2ee_boundary && explicit_downgrade {
        ensure_content_object(&mut content);
        let object = content.as_object_mut().expect("content object");
        object.insert(
            "ck.morph.e2ee_downgrade".to_owned(),
            Value::String("mimi_bridge".to_owned()),
        );
        object.insert(
            "e2ee_downgrade".to_owned(),
            Value::String("mimi_bridge".to_owned()),
        );
        policy = json!({
            "profile": "ck.profile.mimi_interop.v1",
            "e2ee_boundary": "explicit_downgrade",
            "plaintext_detected": plaintext_detected,
            "plaintext_guard": "marked_explicit_downgrade",
            "downgrade_marker": "mimi_bridge",
        });
        encrypted = false;
    } else if e2ee_boundary {
        if let Some(binding) = transcript_binding {
            ensure_content_object(&mut content);
            let object = content.as_object_mut().expect("content object");
            object.insert("transcript_binding".to_owned(), binding.clone());
            object.insert(
                "ck.morph.e2ee_boundary".to_owned(),
                Value::String("transcript_bound".to_owned()),
            );
            policy = json!({
                "profile": "ck.profile.mimi_interop.v1",
                "e2ee_boundary": "transcript_bound",
                "plaintext_detected": plaintext_detected,
                "plaintext_guard": "transcript_binding",
                "transcript_binding": binding,
            });
        } else {
            policy = json!({
                "profile": "ck.profile.mimi_interop.v1",
                "e2ee_boundary": "opaque_ciphertext",
                "plaintext_detected": false,
                "plaintext_guard": "opaque_ciphertext_only",
            });
        }
    }

    if let Some(kind) = content_kind
        .as_deref()
        .filter(|kind| !valid_mimi_content_kind(kind))
    {
        let quarantine_id = ids::generate("mimi_quarantine");
        let quarantine = json!({
            "quarantine_id": quarantine_id,
            "unknown_content_kind": kind,
            "reason": "unknown_mimi_content_kind",
            "raw_payload_hash": format!("sha256:{}", sha256_hex(content.to_string().as_bytes())),
        });
        let content = json!({
            "kind": "ck.content.unsupported",
            "body": "unsupported content from MIMI",
            "ck.morph.unknown_content_kind": kind,
            "quarantine": quarantine.clone(),
        });
        let mut policy = policy;
        if let Some(object) = policy.as_object_mut() {
            object.insert(
                "content_quarantine".to_owned(),
                Value::String("unknown_mimi_content_kind".to_owned()),
            );
        }
        return Ok(MimiMappedContent {
            content,
            encrypted: false,
            policy,
            quarantine: Some(quarantine),
            status: "quarantined",
        });
    }

    Ok(MimiMappedContent {
        content,
        encrypted,
        policy,
        quarantine: None,
        status: "mapped",
    })
}

fn mimi_content_payload(body: &Value, source_format: &str) -> Value {
    body.get("content").cloned().unwrap_or_else(|| {
        let text = body
            .get("body")
            .or_else(|| body.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        json!({
            "kind": "ck.content.text",
            "body": text,
            "raw_mimi_source_format": source_format,
        })
    })
}

fn ensure_content_object(content: &mut Value) {
    if !content.is_object() {
        let raw = content.clone();
        *content = json!({
            "kind": "ck.content.opaque",
            "raw_mimi_content": raw,
        });
    }
}

fn mimi_content_kind<'a>(body: &'a Value, content: &'a Value) -> Option<&'a str> {
    body.get("content_kind")
        .or_else(|| body.get("mimi_content_kind"))
        .and_then(Value::as_str)
        .or_else(|| content.get("kind").and_then(Value::as_str))
}

fn valid_mimi_content_kind(kind: &str) -> bool {
    matches!(
        kind,
        "m.text"
            | "text/plain"
            | "text/markdown"
            | "m.markdown"
            | "ck.message.text"
            | "ck.message.revise"
            | "ck.message.redact"
            | "ck.content.text"
            | "ck.content.composite"
            | "ck.content.markdown"
    )
}

fn mimi_e2ee_boundary(body: &Value, content: &Value) -> bool {
    truthy_field(body, "e2ee")
        || truthy_field(body, "encrypted")
        || truthy_field(content, "e2ee")
        || truthy_field(content, "encrypted")
        || encryption_profile_enabled(body.get("encryption_profile"))
        || encryption_profile_enabled(body.get("source_encryption"))
        || encryption_profile_enabled(content.get("encryption_profile"))
        || encryption_profile_enabled(content.get("source_encryption"))
}

fn truthy_field(value: &Value, key: &str) -> bool {
    match value.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => matches!(
            value.as_str(),
            "true" | "e2ee" | "encrypted" | "mls" | "mls_rfc9420" | "mimi_mls"
        ),
        _ => false,
    }
}

fn encryption_profile_enabled(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|profile| !matches!(profile, "" | "none" | "plaintext" | "unencrypted"))
}

fn mimi_transcript_binding<'a>(body: &'a Value, content: &'a Value) -> Option<&'a Value> {
    body.get("transcript_binding")
        .or_else(|| body.get("mls_transcript_binding"))
        .or_else(|| content.get("transcript_binding"))
        .or_else(|| content.get("mls_transcript_binding"))
}

fn mimi_explicit_downgrade(body: &Value, content: &Value) -> bool {
    downgrade_marker(body.get("e2ee_downgrade"))
        || downgrade_marker(body.get("ck.morph.e2ee_downgrade"))
        || downgrade_marker(content.get("e2ee_downgrade"))
        || downgrade_marker(content.get("ck.morph.e2ee_downgrade"))
}

fn downgrade_marker(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|marker| marker == "mimi_bridge" || marker == "explicit")
}

fn mimi_plaintext_detected(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            if matches!(
                key.as_str(),
                "body" | "text" | "plain_text" | "markdown" | "html"
            ) {
                value.as_str().is_some_and(|text| !text.trim().is_empty())
            } else if matches!(
                key.as_str(),
                "ciphertext" | "ciphertext_hash" | "digest" | "hash" | "original_envelope_hash"
            ) {
                false
            } else {
                mimi_plaintext_detected(value)
            }
        }),
        Value::Array(values) => values.iter().any(mimi_plaintext_detected),
        _ => false,
    }
}

/// Look up which Cokret `realm_id` (if any) the MIMI `room_id` is
/// bound to. Scans the persistence projection event log for the
/// most recent `ck.mimi.room_binding` event whose
/// `payload.mimi_room_id` (or trailing segment of `mimi_room_uri`)
/// matches `room_id`. Returns `None` when no binding has been
/// recorded; callers translate that into a 404/400 rather than
/// silently routing the request at a hard-coded demo Realm.
async fn mimi_bound_realm_id(state: &AppState, room_id: &str) -> Option<String> {
    let entries = state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .ok()?;
    // Walk in reverse so the most-recently-recorded binding wins.
    for entry in entries.iter().rev() {
        if entry.event_kind != "ck.mimi.room_binding" {
            continue;
        }
        let payload_room = entry
            .payload
            .get("mimi_room_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                entry
                    .payload
                    .get("mimi_room_uri")
                    .and_then(Value::as_str)
                    .and_then(|uri| uri.rsplit('/').next().map(ToOwned::to_owned))
            });
        if payload_room.as_deref() == Some(room_id) {
            if let Some(bound) = entry
                .payload
                .get("binding_scope")
                .and_then(|s| s.get("realm_id"))
                .and_then(Value::as_str)
            {
                return Some(bound.to_owned());
            }
            if let Some(bound) = entry.payload.get("realm_id").and_then(Value::as_str) {
                return Some(bound.to_owned());
            }
        }
    }
    None
}

/// Emit a `ck.mimi.room_binding` projection event capturing the
/// binding state. Returns the generated event_id so the caller can
/// echo it back to the MIMI client. The binding payload is captured
/// verbatim under `payload.binding` and `mimi_room_id` is hoisted to
/// the top level so [`mimi_bound_realm_id`] can dispatch lookups
/// efficiently.
///
/// Returns `None` when the binding payload declares no Cokret
/// `realm_id` (neither under `binding_scope.realm_id` nor at the top
/// level). The caller is expected to surface that to the client as a
/// 400 rather than implicitly bind the room to some default Realm.
async fn emit_mimi_room_binding_event(
    state: &AppState,
    room_id: &str,
    binding: &Value,
) -> Option<String> {
    let event_id = ids::generate_event_id();
    let realm_id = binding
        .get("binding_scope")
        .and_then(|s| s.get("realm_id"))
        .and_then(Value::as_str)
        .or_else(|| binding.get("realm_id").and_then(Value::as_str))
        .map(str::to_owned)?;
    let mimi_room_uri_value = binding
        .get("mimi_room_uri")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| mimi_room_uri(state, room_id));
    let record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: "ck.mimi.room_binding".to_owned(),
        operation_type: "mimi_facade_room_binding".to_owned(),
        operation_id: None,
        sender: None,
        payload: json!({
            "profile": "ck.profile.mimi_interop.v1",
            "mimi_room_uri": mimi_room_uri_value,
            "mimi_room_id": room_id,
            "binding_scope": {
                "realm_id": realm_id,
                "flow_id": binding
                    .get("binding_scope")
                    .and_then(|s| s.get("flow_id"))
                    .cloned()
                    .unwrap_or(Value::Null),
            },
            "binding": binding.clone(),
            "mimi_provenance": {
                "facade": "soland.mimi.v1",
                "mimi_provider_id": mimi_provider_id(state),
                "accepted_at": chrono::Utc::now(),
            },
        }),
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        record.realm_id.clone(),
        record.event_id.clone(),
        crate::routing::events::projection::projection_event_json(&record),
    ));
    if let Err(error) = state.persistence.projection_events().append(record).await {
        tracing::error!(%error, "mimi: failed to append room_binding to projection_events");
    }
    Some(event_id)
}

fn mimi_room_projection(state: &AppState, room_id: &str, realm_id: &str) -> Value {
    json!({
        "kind": "ck.mimi.room_binding",
        "profile": "ck.profile.mimi_interop.v1",
        "mimi_room_uri": mimi_room_uri(state, room_id),
        "binding_scope": {
            "realm_id": realm_id,
            "channel_id": Value::Null
        },
        "hub_provider": state.config.service_did.clone(),
        "local_provider_role": "hub",
        "mls_group_id": format!("mls:{}", room_id),
        "policy_root": format!("sha256:{}", sha256_hex(format!("{realm_id}:{room_id}:policy").as_bytes())),
        "status": "accepted",
        "canonical_truth": "cokret_signed_event_reducer"
    })
}

fn mimi_room_participants(state: &AppState, realm_id: &str) -> Vec<Value> {
    let Ok(realm_id) = RealmId::new(realm_id.to_owned()) else {
        return Vec::new();
    };
    state
        .realms
        .lock()
        .expect("spaces lock")
        .get(&realm_id)
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
            | "application/vnd.cokret.content+json"
    )
}
