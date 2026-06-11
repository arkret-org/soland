//! Cross-Principal-Server contact fact delivery (spec
//! `contact-and-direct-conversation.md` §2 / §4.1).
//!
//! Contact facts (`ck.contact.requested` / `accepted` / `rejected` /
//! `tombstoned`) are principal-scoped and cross-Realm. When the issuer and the
//! target holder live on different Principal Servers, the issuer-side server
//! federates the signed fact to the target holder's server via
//! `ck.peer.contacts.submit` (`POST /_cokret/peer/contacts`); the recipient
//! projects the original signed envelope into the target holder's contact
//! projection without re-signing it.
//!
//! Surfaces:
//! - sender: [`federate_contact_fact`] — enqueue a durable outbound delivery when the addressed
//!   holder is hosted on a configured federation peer.
//! - receiver: [`peer_contacts_submit`] — accept a delivered fact and project it into the local
//!   target holder's contact projection.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::SecondsFormat;
use salvo::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::consent::{grant_contact_managed_consent, normalize_scope, persist_consent_cell};
use super::{now, sha256_hex};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, ContactRecord};

const HEADER_CONTENT_DIGEST: &str = "content-digest";
const HEADER_SOURCE_SERVICE_DID: &str = "source-service-did";

pub(crate) fn peer_router() -> Router {
    Router::new().push(Router::with_path("contacts").post(peer_contacts_submit))
}

/// Issuer-side: federate a signed contact fact to `subject_id`'s home
/// Principal Server (`recipient_service_did`). Returns `Ok(false)` (no-op)
/// when `recipient_service_did` is this service (same-server request handled
/// locally) or when the deployment does not list the peer; `Ok(true)` when a
/// durable outbound delivery was enqueued.
///
/// `fact_kind` is one of the `ck.contact.*` kinds. `fact_payload` carries the
/// projection fields the recipient needs (requester/target/scope/message/
/// granted_scopes/consent grant refs). The fact is wrapped in a dev-proof
/// EventEnvelope scoped to the issuer's Principal Control Realm so it is a
/// real signed contact fact the recipient can project as the original
/// envelope (spec §2).
pub(crate) async fn federate_contact_fact(
    state: &AppState,
    fact_kind: &str,
    issuer: &str,
    subject_id: &str,
    recipient_service_did: &str,
    fact_payload: Value,
) -> Result<bool, AppError> {
    let recipient_service_did = recipient_service_did.trim();
    if recipient_service_did.is_empty() || recipient_service_did == state.config.service_did {
        // Same Principal Server: nothing to federate, the local operation
        // already projected the fact for both holders.
        return Ok(false);
    }
    let Some(peer_url) = crate::routing::federation::federation::peer_url_for_service_did(
        state,
        recipient_service_did,
    ) else {
        tracing::warn!(
            recipient_service_did,
            issuer,
            fact_kind,
            "contact fact federation: recipient service DID is not a configured federation peer; \
             fact stays local"
        );
        return Ok(false);
    };

    let issuer_pcr = super::recovery::principal_control_realm_for_did(issuer);
    let contact_event = build_contact_envelope(state, fact_kind, issuer, &issuer_pcr, fact_payload);
    let delivery = json!({
        "schema": "ck.schema.peer_contact_delivery_request.v1",
        "contact_event": contact_event,
        "contact_address": {
            "subject_id": subject_id,
            "recipient_service_did": recipient_service_did,
            "recipient_service_type": "principal_server",
        },
        "fact_kind": fact_kind,
        "idempotency_key": contact_delivery_idempotency_key(
            &state.config.service_did,
            recipient_service_did,
            fact_kind,
            issuer,
            subject_id,
            &contact_event,
        ),
    });
    let payload_bytes = cokret_sdk::canonical::canonical_json_bytes(&delivery)
        .map_err(|error| AppError::internal(format!("contact delivery canonicalize: {error}")))?;
    let payload_json = String::from_utf8(payload_bytes)
        .map_err(|error| AppError::internal(format!("contact delivery utf8: {error}")))?;
    let idempotency_key = delivery
        .get("idempotency_key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    crate::routing::federation::outbox::enqueue_outbound(
        state,
        &peer_url,
        recipient_service_did,
        "/_cokret/peer/contacts",
        &idempotency_key,
        &payload_json,
    )
    .await
    .map_err(|error| AppError::internal(format!("contact delivery enqueue: {error}")))?;
    tracing::info!(
        fact_kind,
        issuer,
        subject_id,
        recipient_service_did,
        "enqueued cross-PS contact fact delivery"
    );
    Ok(true)
}

/// Build a dev-proof contact-fact EventEnvelope scoped to the issuer's
/// Principal Control Realm. The recipient validates + projects this as the
/// original signed envelope; it never re-signs it as a local fact (spec §2).
fn build_contact_envelope(
    state: &AppState,
    fact_kind: &str,
    issuer: &str,
    issuer_pcr: &str,
    fact_payload: Value,
) -> Value {
    let event_id = crate::ids::generate_event_id();
    let created_at = now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let payload_digest = format!(
        "sha256:{}",
        sha256_hex(
            &cokret_sdk::canonical::canonical_json_bytes(&fact_payload)
                .unwrap_or_else(|_| fact_payload.to_string().into_bytes())
        )
    );
    let _ = state;
    json!({
        "event_id": event_id,
        "kind": fact_kind,
        "schema_id": "ck.schema.event.v1",
        "realm_id": issuer_pcr,
        "actor_id": issuer,
        "actor_seq": 0,
        "created_at": created_at,
        "prev_refs": [],
        "refs": [],
        "payload": fact_payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{issuer}#device"),
            "payload_digest": payload_digest,
        }],
    })
}

fn contact_delivery_idempotency_key(
    origin_service_did: &str,
    recipient_service_did: &str,
    fact_kind: &str,
    issuer: &str,
    subject_id: &str,
    contact_event: &Value,
) -> String {
    let event_id = contact_event
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut hasher = Sha256::new();
    for part in [
        origin_service_did,
        recipient_service_did,
        fact_kind,
        issuer,
        subject_id,
        event_id,
    ] {
        hasher.update(part.as_bytes());
        hasher.update(b"|");
    }
    format!("ck:contact-outbox:{}", hex::encode(hasher.finalize()))
}

#[endpoint(
    operation_id = "ck.peer.contacts.submit",
    tags("peer"),
    summary = "Private Principal Server contact fact delivery"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.contacts.submit"))]
async fn peer_contacts_submit(depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<Value>()
        .await
        .map_err(|_| AppError::bad_json("invalid ck.peer.contacts.submit request body"))?;
    super::super::events::peer::validate_peer_request(state, req, Some(&body))?;
    validate_content_digest(req, &body)?;

    if body.get("schema").and_then(Value::as_str)
        != Some("ck.schema.peer_contact_delivery_request.v1")
    {
        return Err(super::super::events::peer::schema_violation(
            "schema must be ck.schema.peer_contact_delivery_request.v1",
        ));
    }
    let contact_event = body
        .get("contact_event")
        .ok_or_else(|| super::super::events::peer::schema_violation("contact_event is required"))?;
    let fact_kind = body
        .get("fact_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| super::super::events::peer::schema_violation("fact_kind is required"))?;
    if contact_event.get("kind").and_then(Value::as_str) != Some(fact_kind) {
        return Err(super::super::events::peer::schema_violation(
            "fact_kind must equal contact_event.kind",
        ));
    }
    let issuer = contact_event
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            super::super::events::peer::schema_violation("contact_event.actor_id is required")
        })?
        .to_owned();
    let subject_id = body
        .pointer("/contact_address/subject_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            super::super::events::peer::schema_violation("contact_address.subject_id is required")
        })?
        .to_owned();
    let recipient_service_did = body
        .pointer("/contact_address/recipient_service_did")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "contact_address.recipient_service_did is required",
            )
        })?;
    if recipient_service_did != state.config.service_did {
        return Err(super::super::events::peer::cross_domain_replay(
            "contact_address.recipient_service_did does not match this service",
        ));
    }
    let payload = contact_event.get("payload").cloned().unwrap_or(Value::Null);

    // Originating Principal Server of this delivery: the peer end of the
    // projected contact row (the issuer) is hosted there. `validate_peer_request`
    // above already verified this header is a present, well-formed DID, so we
    // record it on the projection as the contact's `peer_service_did` — that is
    // the requester's/accepter's home server, NOT this service. yougen reads it
    // off a pending_incoming row as the `requester_service_did` to address the
    // reverse `respond` delivery back to the originator.
    let source_service_did = req
        .headers()
        .get(HEADER_SOURCE_SERVICE_DID)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    // §2 hard boundary: project the issuer's original signed envelope into the
    // local target holder's contact projection. We do NOT re-sign it as a
    // local fact. soland's contact projection is the ContactRecord store +
    // contact-managed consent cells, so projection means upserting the
    // holder-scoped row (and, for accept, the target-controlled consent grant
    // refs the original issuer already wrote on its own PCR).
    let outcome = project_delivered_contact_fact(
        state,
        fact_kind,
        &issuer,
        &subject_id,
        &payload,
        source_service_did.as_deref(),
    )
    .await?;

    super::append_audit_log(
        state,
        Some(&subject_id),
        "peer.contacts.submit",
        json!({
            "fact_kind": fact_kind,
            "issuer": issuer,
            "subject_id": subject_id,
            "status": outcome,
        }),
        outcome,
    )
    .await;
    json_ok(json!({
        "status": outcome,
        "received_at": now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }))
}

/// Project a delivered contact fact into the local `subject_id`'s contact
/// projection. Returns the receive status (`accepted` / `duplicate`).
async fn project_delivered_contact_fact(
    state: &AppState,
    fact_kind: &str,
    issuer: &str,
    subject_id: &str,
    payload: &Value,
    source_service_did: Option<&str>,
) -> Result<&'static str, AppError> {
    let scope = normalize_scope(
        payload
            .get("requested_scopes")
            .and_then(Value::as_array)
            .and_then(|scopes| scopes.first())
            .and_then(Value::as_str)
            .or_else(|| {
                payload
                    .get("granted_scopes")
                    .and_then(Value::as_array)
                    .and_then(|scopes| scopes.first())
                    .and_then(Value::as_str)
            })
            .or_else(|| payload.get("scope").and_then(Value::as_str)),
    )?;
    let store = state.persistence.contacts();
    match fact_kind {
        "ck.contact.requested" => {
            // requester = issuer, target = subject_id (this holder). Form a
            // pending_incoming row on the target side.
            let message = payload
                .get("message")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            if let Some(existing) = store
                .get_scoped(issuer, subject_id, &scope)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            {
                if existing.status == "pending" {
                    return Ok("duplicate");
                }
            }
            let contact = ContactRecord {
                requester: issuer.to_owned(),
                target: subject_id.to_owned(),
                scope,
                status: "pending".to_owned(),
                message,
                // Peer end of this pending_incoming row is the remote requester
                // (`issuer`), hosted on the delivering source server. The local
                // holder later uses this as the reverse-delivery target when it
                // responds (yougen's `requester_service_did`).
                peer_service_did: source_service_did.map(ToOwned::to_owned),
                created_at: now(),
                updated_at: now(),
            };
            store
                .put(&contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            Ok("accepted")
        }
        "ck.contact.accepted" => {
            // Travelling back to the original requester (subject_id). The
            // target (issuer) accepted: flip the requester-side row to accepted
            // and materialize the issuer -> requester consent grant so the
            // requester's row surfaces invite_consent_grant_ref / bidirectional
            // scopes, mirroring the local accept path.
            for granted in granted_scopes(payload) {
                let (_grant_ref, grant_cell) =
                    grant_contact_managed_consent(state, issuer, subject_id, &granted, now());
                persist_consent_cell(state, &grant_cell).await;
            }
            let mut contact = store
                .get_scoped(subject_id, issuer, &scope)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .unwrap_or_else(|| ContactRecord {
                    requester: subject_id.to_owned(),
                    target: issuer.to_owned(),
                    scope: scope.clone(),
                    status: "accepted".to_owned(),
                    message: None,
                    peer_service_did: None,
                    created_at: now(),
                    updated_at: now(),
                });
            if contact.status == "accepted" {
                return Ok("duplicate");
            }
            contact.status = "accepted".to_owned();
            contact.updated_at = now();
            // Peer end is the remote accepter (`issuer`), hosted on the
            // delivering source server. Record/backfill it so the requester's
            // row can address future invites/responses to the peer's home PS.
            if let Some(source) = source_service_did {
                contact.peer_service_did = Some(source.to_owned());
            }
            store
                .put(&contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            Ok("accepted")
        }
        "ck.contact.rejected" => {
            let mut contact = store
                .get_scoped(subject_id, issuer, &scope)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .unwrap_or_else(|| ContactRecord {
                    requester: subject_id.to_owned(),
                    target: issuer.to_owned(),
                    scope: scope.clone(),
                    status: "rejected".to_owned(),
                    message: None,
                    peer_service_did: source_service_did.map(ToOwned::to_owned),
                    created_at: now(),
                    updated_at: now(),
                });
            if contact.status == "rejected" {
                return Ok("duplicate");
            }
            contact.status = "rejected".to_owned();
            contact.updated_at = now();
            store
                .put(&contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            Ok("accepted")
        }
        "ck.contact.tombstoned" => {
            // Downgrade every local row this holder shares with the issuer.
            let rows = store
                .list_for_actor(subject_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            for mut row in rows {
                let touches_issuer = (row.requester == subject_id && row.target == issuer)
                    || (row.requester == issuer && row.target == subject_id);
                if !touches_issuer || row.status == "tombstoned" {
                    continue;
                }
                row.status = "tombstoned".to_owned();
                row.updated_at = now();
                store
                    .put(&row)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?;
            }
            Ok("accepted")
        }
        other => Err(super::super::events::peer::schema_violation(format!(
            "unsupported contact fact_kind {other}"
        ))),
    }
}

fn granted_scopes(payload: &Value) -> Vec<String> {
    payload
        .get("granted_scopes")
        .and_then(Value::as_array)
        .map(|scopes| {
            scopes
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|scope| normalize_scope(Some(scope)).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// RFC 9530 `Content-Digest` check, matching `peer/invites` (the federation
/// outbox dispatcher emits `sha-256=:<base64(sha256(canonical_body))>:`).
fn validate_content_digest(req: &Request, body: &Value) -> Result<(), AppError> {
    let header = req
        .headers()
        .get(HEADER_CONTENT_DIGEST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            super::super::events::peer::schema_violation("required header content-digest missing")
        })?;
    let canonical_bytes = cokret_sdk::canonical::canonical_json_bytes(body).map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "request body is not canonical-hashable: {error}"
        ))
    })?;
    let expected = format!(
        "sha-256=:{}:",
        STANDARD.encode(Sha256::digest(&canonical_bytes))
    );
    if header != expected {
        crate::metrics::record_digest_mismatch("peer_contacts_content_digest");
        return Err(super::super::events::peer::cross_domain_replay(
            "Content-Digest does not match the canonical request body",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use super::*;
    use crate::config::{AppConfig, FederationPolicy, LogFormat, ObjectStorageConfig};
    use crate::db::Db;

    fn test_config() -> AppConfig {
        AppConfig {
            bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            metrics_bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            public_base_url: "http://test".to_owned(),
            service_did: "did:web:recipient.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: ObjectStorageConfig::local(std::env::temp_dir()),
            cors_allow_origin: None,
            auth_server_url: None,
            development_mode: true,
            oauth_introspection_url: None,
            oauth_introspection_bearer: None,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            anchorer_signing_key_seed: None,
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            federation_outbound_enabled: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            resumable_upload_dir: std::path::PathBuf::from("./soland-resumable-uploads"),
            resumable_upload_incomplete_ttl_seconds: 86_400,
            compaction_min_anchor_age_seconds: 0,
            compaction_min_witnesses: 0,
            compaction_preserve_genesis: false,
            compaction_prune_only_singleton_successors: false,
            compaction_prune_walk_interval_seconds: 0,
            compaction_prune_walk_per_realm_limit: 50,
            seed_demo_data: false,
            trust_domain: "ck:trust_domain:recipient.local".to_owned(),
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            erasure_propagation_window_ms: 604_800_000,
            log_format: LogFormat::Plain,
        }
    }

    /// Cross-PS `ck.contact.requested` delivery: the projected pending_incoming
    /// row on the recipient (target holder) MUST record the *originating*
    /// requester's home Principal Server as `peer_service_did` — the
    /// `source-service-did` of the delivery, NOT the recipient's own service
    /// DID. This is exactly the address yougen reads back as
    /// `requester_service_did` to federate the reverse `respond` delivery.
    #[tokio::test]
    async fn delivered_request_records_originating_peer_service_did() {
        let state = AppState::new(test_config(), Db { pool: None });
        let requester = "did:web:remote-alice.example"; // issuer, on source PS
        let target = "did:web:local-bob.example"; // subject_id, this holder
        let source_service_did = "did:web:remote.local"; // requester's home PS

        let payload = json!({
            "requested_scopes": ["message"],
            "message": "hi from across the federation",
        });

        let outcome = project_delivered_contact_fact(
            &state,
            "ck.contact.requested",
            requester,
            target,
            &payload,
            Some(source_service_did),
        )
        .await
        .expect("delivered request projects");
        assert_eq!(outcome, "accepted");

        let record = state
            .persistence
            .contacts()
            .get_scoped(requester, target, "message")
            .await
            .expect("contact store lookup")
            .expect("pending_incoming row was projected");

        assert_eq!(
            record.peer_service_did.as_deref(),
            Some(source_service_did),
            "peer_service_did must be the originating requester's PS, not the recipient's own \
             service_did ({})",
            state.config.service_did,
        );
        assert_ne!(
            record.peer_service_did.as_deref(),
            Some(state.config.service_did.as_str()),
            "peer_service_did must not point at this recipient service",
        );
    }
}
