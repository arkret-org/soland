use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hasher;
use std::sync::{Arc, OnceLock};

use cokret_sdk::EventsSubmitRejectedItem;

use super::*;
use crate::invite_claim_proofs::{
    invite_claim_proof_context_from_projection, verify_invite_claim_proofs_for_operation,
};

/// SOL-SEC-03 — per-actor submit serialization uses a fixed-size pool of locks
/// keyed by a hash of the actor DID, instead of an unbounded per-actor
/// `HashMap` entry that was never evicted. Federation inbound can carry
/// arbitrarily many distinct actor DIDs, so a per-actor map grows without bound
/// (memory DoS). A fixed pool bounds memory to `ACTOR_SUBMIT_LOCK_SHARDS`
/// entries; two actors hashing to the same shard merely serialize together,
/// which is a safe superset of the required per-actor exclusion.
const ACTOR_SUBMIT_LOCK_SHARDS: usize = 1024;

static ACTOR_SUBMIT_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();

fn actor_submit_lock(actor_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let locks = ACTOR_SUBMIT_LOCKS.get_or_init(|| {
        (0..ACTOR_SUBMIT_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(actor_id, &mut hasher);
    let shard = (hasher.finish() as usize) % ACTOR_SUBMIT_LOCK_SHARDS;
    locks[shard].clone()
}

fn stamp_projection_operation_received_at(
    operation: &mut cokret_sdk::Operation,
    received_at: chrono::DateTime<chrono::Utc>,
) {
    if !matches!(
        operation.object_type.as_str(),
        cokret_sdk::events::kinds::MEMBER_STATE | cokret_sdk::events::kinds::CIRCLE_MEMBER_STATE
    ) {
        return;
    }
    let Some(payload) = operation.payload.as_object_mut() else {
        return;
    };
    payload.insert(
        "event_received_at".to_owned(),
        Value::String(received_at.to_rfc3339()),
    );
}

#[derive(Debug)]
pub(in crate::routing) struct ValidatedEventEnvelope {
    pub(in crate::routing) event_id: String,
    pub(in crate::routing) actor_id: String,
    pub(in crate::routing) device_id: String,
    pub(in crate::routing) actor_seq: u64,
    pub(in crate::routing) realm_id: String,
    pub(in crate::routing) kind: String,
    pub(in crate::routing) schema_id: String,
    pub(in crate::routing) prev_refs: Vec<String>,
    pub(in crate::routing) authorized_refs: Vec<String>,
    pub(in crate::routing) canonical_digest: String,
    pub(in crate::routing) canonical_bytes: Vec<u8>,
}

#[derive(Debug)]
pub(in crate::routing) struct EventValidationError {
    pub(in crate::routing) status: StatusCode,
    pub(in crate::routing) code: &'static str,
    pub(in crate::routing) message: String,
}

#[derive(Debug)]
pub(in crate::routing) struct SubmitOneError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub quarantine_event_id: Option<String>,
}

#[derive(Debug)]
pub(in crate::routing) struct SubmittedEventOutcome {
    pub event_id: String,
    pub duplicate: bool,
    pub outcome: EventsSubmitOutcome,
}

#[derive(Debug, Clone)]
pub(in crate::routing) struct RealmBootstrapBatchContext {
    pub(in crate::routing) realm_id: String,
    pub(in crate::routing) actor_id: String,
}

const DELIVERY_BINDING_HANDOVER_GRACE_SECONDS: i64 = 86_400;

#[derive(Debug, Clone)]
struct DeliveryBindingMemberView {
    member: String,
    realm_id: String,
    recipient_service_did: String,
    membership_event_ref: Option<String>,
    delivery_binding_frontier_ref: String,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct DeliveryBindingHandoverEvidence {
    realm_id: String,
    actor_id: Did,
    new_recipient_service_did: Did,
    handover_frontier: Vec<EventId>,
    membership_event_ref: Option<String>,
    delivery_binding_frontier_ref: String,
    updated_at: DateTime<Utc>,
    witness: Value,
}

#[derive(Debug, Clone)]
enum FederationServiceBindingCheck {
    Current,
    Reject(&'static str),
    Stale(DeliveryBindingHandoverEvidence),
    HandedOver(DeliveryBindingHandoverEvidence),
}

impl SubmitOneError {
    pub(in crate::routing) fn new(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            quarantine_event_id: None,
        }
    }

    pub(in crate::routing) fn quarantine(
        event_id: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status: StatusCode::OK,
            code: code.into(),
            message: message.into(),
            quarantine_event_id: Some(event_id.into()),
        }
    }
}

fn realm_already_exists_error() -> SubmitOneError {
    SubmitOneError::new(
        StatusCode::CONFLICT,
        "realm_already_exists",
        "realm already exists",
    )
}

fn cba_bottom_reject(reason: &'static str) -> (&'static str, &'static str) {
    if reason == "cell_bottom_state" {
        ("failed_bottom", "cell_in_bottom_state")
    } else {
        (reason, reason)
    }
}

fn persistence_error_is_realm_already_exists(error: &crate::persistence::PersistenceError) -> bool {
    matches!(
        error,
        crate::persistence::PersistenceError::Conflict(message)
            if message.contains("realm_already_exists")
    )
}

impl From<EventValidationError> for SubmitOneError {
    fn from(error: EventValidationError) -> Self {
        Self::new(error.status, error.code, error.message)
    }
}

pub(super) fn event_validation_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> EventValidationError {
    EventValidationError {
        status,
        code,
        message: message.into(),
    }
}

pub(super) fn render_submit_one_error(res: &mut Response, error: SubmitOneError) {
    if let Some(event_id) = error.quarantine_event_id {
        res.render(Json(events_submit_outcome(
            EventsSubmitStatus::Partial,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![event_id],
            None,
        )));
        return;
    }
    if error.status == StatusCode::PRECONDITION_FAILED
        && error.code == "failed_precondition"
        && error.message != error.code
    {
        crate::routing::system::util::render_error_with_top_level_reason(
            res,
            error.status,
            &error.code,
            &error.message,
            &error.message,
            None,
        );
    } else {
        render_error(res, error.status, &error.code, &error.message);
    }
}

pub(super) async fn submit_event_batch(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Value>,
    res: &mut Response,
) {
    match submit_event_batch_outcome(state, session, envelopes).await {
        Ok(outcome) => res.render(Json(outcome)),
        Err(error) => render_submit_one_error(res, error),
    }
}

/// Run a multi-envelope batch and return its `EventsSubmitOutcome` without
/// rendering, so the caller can also feed the value through the generic
/// `Idempotency-Key` cache (api-conventions.md §6) before rendering. The batch
/// surface never produces a 409 on its own — per-envelope conflicts are folded
/// into `rejected[]` / `quarantine[]` and the aggregate status is `partial` —
/// so only the two early body-shape guards short-circuit as a `SubmitOneError`.
pub(super) async fn submit_event_batch_outcome(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Value>,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    if envelopes.is_empty() {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "events submit batch must contain at least one envelope",
        ));
    }
    if cokret_sdk::validate_event_submit_batch_count(envelopes.len()).is_err() {
        return Err(SubmitOneError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "events submit batch exceeds max batch size",
        ));
    }
    let mut accepted = Vec::new();
    let mut duplicate = Vec::new();
    let mut rejected = Vec::new();
    let mut quarantine = Vec::new();
    let mut realm_bootstrap_contexts: Vec<RealmBootstrapBatchContext> = Vec::new();

    for envelope in envelopes {
        let id = event_string_field_from_value(&envelope, "event_id")
            .unwrap_or_else(|| "unknown".to_owned());
        let kind = event_string_field_from_value(&envelope, "kind");
        let realm_id = event_string_field_from_value(&envelope, "realm_id");
        let actor_id = event_string_field_from_value(&envelope, "actor_id");
        match submit_event_value_with_context(state, session, envelope, &realm_bootstrap_contexts)
            .await
        {
            Ok(response) => {
                accepted.push(response.event_id.clone());
                if response.duplicate {
                    duplicate.push(response.event_id);
                }
                if !response.duplicate
                    && kind.as_deref() == Some(cokret_sdk::events::kinds::REALM_CREATE)
                    && let (Some(realm_id), Some(actor_id)) = (realm_id, actor_id)
                {
                    realm_bootstrap_contexts
                        .push(RealmBootstrapBatchContext { realm_id, actor_id });
                }
            }
            Err(error) => {
                if let Some(event_id) = error.quarantine_event_id {
                    quarantine.push(event_id);
                } else {
                    rejected.push(EventsSubmitRejectedItem {
                        id,
                        reason_code: error.code.to_owned(),
                        detail: Some(error.message),
                    });
                }
            }
        }
    }

    let status = if !rejected.is_empty() || !quarantine.is_empty() {
        EventsSubmitStatus::Partial
    } else if accepted.len() == duplicate.len() && !duplicate.is_empty() {
        EventsSubmitStatus::Duplicate
    } else {
        EventsSubmitStatus::Accepted
    };
    Ok(events_submit_outcome(
        status,
        accepted,
        duplicate,
        rejected,
        quarantine,
        Some(super::super::sync::sync_token_for_state(state).await),
    ))
}

pub(crate) async fn submit_federation_events(
    state: &AppState,
    req: &Request,
    body_value: Value,
    res: &mut Response,
) {
    let submit =
        match serde_json::from_value::<EventsSubmitFederationRequestBody>(body_value.clone()) {
            Ok(value) => value,
            Err(error) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "bad_json",
                    &format!("invalid ck.peer.events.command.submit request body: {error}"),
                );
                return;
            }
        };
    let EventsSubmitFederationRequestBody {
        service_binding_ref,
        events,
        idempotency_key: _,
    } = submit;

    let trust_headers =
        match crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(
            req,
        ) {
            Ok(headers) => headers,
            Err(violation) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    violation.error_code(),
                    &violation.message(),
                );
                return;
            }
        };
    let expected_destination = match TypedTrustDomainId::new(state.config.trust_domain.clone()) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "configured trust_domain failed typed validation");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "service trust_domain is invalid",
            );
            return;
        }
    };
    if trust_headers
        .verify_destination(&expected_destination)
        .is_err()
    {
        render_error(
            res,
            StatusCode::CONFLICT,
            "cross_domain_replay_rejected",
            "federation Destination-Trust-Domain header does not match this service",
        );
        return;
    }
    let request_hash = match canonical::canonical_sha256(&body_value) {
        Ok(value) => value,
        Err(error) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &format!("ck.peer.events.command.submit body is not canonical-hashable: {error}"),
            );
            return;
        }
    };
    if request_hash != trust_headers.request_canonical_digest.as_str() {
        crate::metrics::record_digest_mismatch("events_federation_request_binding");
        render_error(
            res,
            StatusCode::CONFLICT,
            "cross_domain_replay_rejected",
            "Request-Canonical-Digest does not match the canonical request body",
        );
        return;
    }

    if let Err((code, message)) =
        SolandEventsSubmitRequestBody::validate_federation_service_binding(&service_binding_ref)
    {
        render_error(res, StatusCode::BAD_REQUEST, code, &message);
        return;
    }
    if events.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "ck.peer.events.command.submit must contain at least one event",
        );
        return;
    }
    if cokret_sdk::validate_event_submit_batch_count(events.len()).is_err() {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "ck.peer.events.command.submit exceeds max batch size",
        );
        return;
    }
    let events = match events
        .into_iter()
        .map(typed_event_to_canonical_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(events) => events,
        Err(error) => {
            render_submit_one_error(res, error);
            return;
        }
    };

    let binding_realm = service_binding_ref.realm_id.as_str().to_owned();
    let source_service_did = req
        .headers()
        .get("source-service-did")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_owned();
    match crate::routing::federation::frontier_exchange::inbound_peer_is_stale(
        state,
        &binding_realm,
        &source_service_did,
    )
    .await
    {
        Ok(true) => {
            let quarantine = events
                .iter()
                .filter_map(|envelope| event_string_field_from_value(envelope, "event_id"))
                .collect::<Vec<_>>();
            append_audit_log(
                state,
                None,
                "peer.events.submit",
                json!({
                    "realm_id": binding_realm,
                    "source_service_did": source_service_did,
                    "reason": "stale_peer",
                    "quarantine_count": quarantine.len()
                }),
                "quarantine",
            )
            .await;
            res.render(Json(events_submit_outcome(
                EventsSubmitStatus::Partial,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                quarantine,
                Some(super::super::sync::sync_token_for_state(state).await),
            )));
            return;
        }
        Ok(false) => {}
        Err(error) => {
            append_audit_log(
                state,
                None,
                "peer.events.submit",
                json!({
                    "realm_id": binding_realm,
                    "source_service_did": source_service_did,
                    "reason": "stale_peer_state_unavailable",
                    "error": error
                }),
                "reject",
            )
            .await;
            render_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "stale_peer_state_unavailable",
                "federation stale_peer state is unavailable",
            );
            return;
        }
    }
    match federation_service_binding_current_for_destination(state, &service_binding_ref).await {
        FederationServiceBindingCheck::Current => {}
        FederationServiceBindingCheck::Reject(reason) => {
            render_error(res, StatusCode::CONFLICT, reason, reason);
            return;
        }
        FederationServiceBindingCheck::Stale(evidence) => {
            res.status_code(StatusCode::CONFLICT);
            res.render(Json(
                crate::routing::federation::federation::delivery_binding_stale_response(
                    &evidence.new_recipient_service_did,
                    &evidence.actor_id,
                    &evidence.handover_frontier,
                    evidence.witness,
                ),
            ));
            return;
        }
        FederationServiceBindingCheck::HandedOver(evidence) => {
            res.status_code(StatusCode::CONFLICT);
            res.render(Json(
                crate::routing::federation::federation::delivery_binding_handed_over_response(
                    &evidence.new_recipient_service_did,
                ),
            ));
            return;
        }
    }
    let mut accepted = Vec::new();
    let mut duplicate = Vec::new();
    let mut rejected = Vec::new();
    let mut quarantine = Vec::new();
    let created_at = now();
    let source_trust_domain = trust_headers.source_trust_domain.as_str().to_owned();
    let profile_gate =
        match crate::routing::federation::federation::federation_profile_intersection_for_peer(
            state,
            &source_service_did,
            Some(&source_trust_domain),
        )
        .await
        {
            Ok(gate) => gate,
            Err(rejection) => {
                let rejected = events
                    .iter()
                    .map(|envelope| EventsSubmitRejectedItem {
                        id: event_string_field_from_value(envelope, "event_id")
                            .unwrap_or_else(|| "unknown".to_owned()),
                        reason_code: rejection.code.to_owned(),
                        detail: Some(rejection.message.clone()),
                    })
                    .collect::<Vec<_>>();
                append_audit_log(
                    state,
                    None,
                    "peer.events.submit",
                    json!({
                        "realm_id": binding_realm,
                        "source_trust_domain": source_trust_domain,
                        "source_service_did": source_service_did,
                        "request_canonical_digest": request_hash,
                        "accepted": Vec::<String>::new(),
                        "duplicate": Vec::<String>::new(),
                        "rejected_count": rejected.len(),
                        "quarantine_count": 0,
                        "reason": rejection.code,
                    }),
                    "partial",
                )
                .await;
                res.render(Json(events_submit_outcome(
                    EventsSubmitStatus::Partial,
                    Vec::new(),
                    Vec::new(),
                    rejected,
                    Vec::new(),
                    Some(super::super::sync::sync_token_for_state(state).await),
                )));
                return;
            }
        };

    for envelope in events {
        let id = event_string_field_from_value(&envelope, "event_id")
            .unwrap_or_else(|| "unknown".to_owned());
        let event_realm = event_string_field_from_value(&envelope, "realm_id");
        if event_realm.as_deref() != Some(binding_realm.as_str()) {
            rejected.push(EventsSubmitRejectedItem {
                id,
                reason_code: "schema_violation".to_owned(),
                detail: Some("event realm_id must match service_binding_ref.realm_id".to_owned()),
            });
            continue;
        }
        let Some(actor) = event_string_field_from_value(&envelope, "actor_id") else {
            rejected.push(EventsSubmitRejectedItem {
                id,
                reason_code: "missing_param".to_owned(),
                detail: Some("actor_id is required".to_owned()),
            });
            continue;
        };
        if validate_did(&actor).is_err() {
            rejected.push(EventsSubmitRejectedItem {
                id,
                reason_code: "invalid_param".to_owned(),
                detail: Some("actor_id must be a DID".to_owned()),
            });
            continue;
        }
        // SOL-02-007 — bind the envelope actor to the asserted source trust
        // domain BEFORE constructing a session, instead of leaving author
        // identity entirely to the downstream proof chain. Two acceptance
        // paths:
        //   1. the actor's home trust domain (derived from its DID host, same derivation as the
        //      service-DID → trust-domain rule) equals the `source-trust-domain` header; or
        //   2. the actor is already a member of the binding Realm in the local membership index
        //      (the source domain is then relaying for a known member; identity is re-verified
        //      downstream by `validate_event_envelope`'s proof checks).
        if !crate::routing::federation::federation::federation_actor_origin_acceptable(
            state,
            &actor,
            &source_trust_domain,
            &binding_realm,
        )
        .await
        {
            rejected.push(EventsSubmitRejectedItem {
                id,
                reason_code: "capability_denied".to_owned(),
                detail: Some("actor_id home domain does not match source-trust-domain and the actor is not a known member of the binding realm".to_owned()),
            });
            continue;
        }
        if let Err(rejection) = profile_gate.enforce_event(&envelope) {
            rejected.push(EventsSubmitRejectedItem {
                id,
                reason_code: rejection.code.to_owned(),
                detail: Some(rejection.message),
            });
            continue;
        }
        let device_id = event_string_field_from_value(&envelope, "device_id")
            .unwrap_or_else(|| format!("federation:{source_trust_domain}"));
        let session = SessionRecord {
            token_hash: format!("federation:{source_trust_domain}:{}", request_hash),
            actor,
            device_id,
            audience: state.config.service_did.clone(),
            session_public_key: None,
            agent_session: None,
            expires_at: created_at + Duration::minutes(5),
            created_at,
            revoked_at: None,
        };
        match submit_event_value(state, &session, envelope).await {
            Ok(response) => {
                accepted.push(response.event_id.clone());
                if response.duplicate {
                    duplicate.push(response.event_id);
                }
            }
            Err(error) => {
                if let Some(event_id) = error.quarantine_event_id {
                    quarantine.push(event_id);
                } else {
                    rejected.push(EventsSubmitRejectedItem {
                        id,
                        reason_code: error.code.to_owned(),
                        detail: Some(error.message),
                    });
                }
            }
        }
    }

    let status = if !rejected.is_empty() || !quarantine.is_empty() {
        EventsSubmitStatus::Partial
    } else if accepted.len() == duplicate.len() && !duplicate.is_empty() {
        EventsSubmitStatus::Duplicate
    } else {
        EventsSubmitStatus::Accepted
    };
    let status_label = events_submit_status_label(status);
    append_audit_log(
        state,
        None,
        "peer.events.submit",
        json!({
            "realm_id": binding_realm,
            "source_trust_domain": source_trust_domain,
            "request_canonical_digest": request_hash,
            "accepted": accepted,
            "duplicate": duplicate,
            "rejected_count": rejected.len(),
            "quarantine_count": quarantine.len()
        }),
        status_label,
    )
    .await;
    res.render(Json(events_submit_outcome(
        status,
        accepted,
        duplicate,
        rejected,
        quarantine,
        Some(super::super::sync::sync_token_for_state(state).await),
    )));
}

pub(super) fn event_string_field_from_value(value: &Value, field: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|object| event_string_field(object, &[field]))
}

mod delivery_binding;
mod outcome;
mod post_commit;
mod preflight;
mod value;

use delivery_binding::*;
pub(super) use outcome::events_submit_outcome;
use outcome::*;
use post_commit::*;
use preflight::*;
pub(in crate::routing) use value::submit_event_value;
use value::*;

#[cfg(test)]
mod received_at_stamp_tests {
    use super::*;

    fn operation_for_kind(kind: &str, suffix: u32) -> Operation {
        Operation::create(
            OperationId::new(format!(
                "ck:operation:01904100-0000-7000-8000-{suffix:012x}"
            ))
            .unwrap(),
            RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001".to_owned()).unwrap(),
            kind,
            json!({ "actor_id": "did:web:alice.example" }),
        )
    }

    #[test]
    fn received_at_stamp_only_mutates_membership_projection_payloads() {
        let received_at = DateTime::parse_from_rfc3339("2026-07-07T05:20:58.398662Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut device_authorize = operation_for_kind("ck.device.authorize", 1);
        let mut member_state = operation_for_kind(cokret_sdk::events::kinds::MEMBER_STATE, 2);
        let mut circle_member_state =
            operation_for_kind(cokret_sdk::events::kinds::CIRCLE_MEMBER_STATE, 3);

        stamp_projection_operation_received_at(&mut device_authorize, received_at);
        stamp_projection_operation_received_at(&mut member_state, received_at);
        stamp_projection_operation_received_at(&mut circle_member_state, received_at);

        assert!(device_authorize.payload.get("event_received_at").is_none());
        assert_eq!(
            member_state
                .payload
                .get("event_received_at")
                .and_then(Value::as_str),
            Some("2026-07-07T05:20:58.398662+00:00")
        );
        assert_eq!(
            circle_member_state
                .payload
                .get("event_received_at")
                .and_then(Value::as_str),
            Some("2026-07-07T05:20:58.398662+00:00")
        );
    }
}

#[cfg(test)]
mod federation_delivery_binding_tests {
    use super::*;

    fn event_id(suffix: u32) -> EventId {
        EventId::new(format!("ck:event:01904100-0000-7000-8000-{suffix:012x}")).unwrap()
    }

    fn member_view(
        actor: &str,
        recipient_service_did: &str,
        frontier: &EventId,
        updated_at: DateTime<Utc>,
    ) -> DeliveryBindingMemberView {
        DeliveryBindingMemberView {
            member: actor.to_owned(),
            realm_id: "ck:realm:01904100-0000-7000-8000-000000000001".to_owned(),
            recipient_service_did: recipient_service_did.to_owned(),
            membership_event_ref: Some(frontier.as_str().to_owned()),
            delivery_binding_frontier_ref: frontier.as_str().to_owned(),
            updated_at,
        }
    }

    #[test]
    fn federation_service_binding_check_accepts_current_local_frontier() {
        let now = Utc::now();
        let frontier = event_id(1);
        let result = federation_service_binding_check_from_members(
            "did:web:local.example",
            now,
            std::slice::from_ref(&frontier),
            vec![member_view(
                "did:web:alice.example",
                "did:web:local.example",
                &frontier,
                now,
            )],
        );

        assert!(matches!(result, FederationServiceBindingCheck::Current));
    }

    #[test]
    fn federation_service_binding_check_rejects_empty_frontier_as_schema_violation() {
        let now = Utc::now();
        let result = federation_service_binding_check_from_members(
            "did:web:local.example",
            now,
            &[],
            vec![member_view(
                "did:web:alice.example",
                "did:web:local.example",
                &event_id(1),
                now,
            )],
        );

        assert!(matches!(
            result,
            FederationServiceBindingCheck::Reject("schema_violation")
        ));
    }

    #[test]
    fn federation_service_binding_check_emits_stale_handover_before_grace_expires() {
        let now = Utc::now();
        let old_frontier = event_id(1);
        let new_frontier = event_id(2);
        let result = federation_service_binding_check_from_members(
            "did:web:old.example",
            now,
            std::slice::from_ref(&old_frontier),
            vec![member_view(
                "did:web:alice.example",
                "did:web:new.example",
                &new_frontier,
                now - Duration::seconds(60),
            )],
        );

        match result {
            FederationServiceBindingCheck::Stale(evidence) => {
                assert_eq!(
                    evidence.new_recipient_service_did.as_str(),
                    "did:web:new.example"
                );
                assert_eq!(evidence.actor_id.as_str(), "did:web:alice.example");
                assert_eq!(evidence.handover_frontier, vec![new_frontier]);
            }
            other => panic!("expected stale handover evidence, got {other:?}"),
        }
    }

    #[test]
    fn federation_service_binding_check_emits_handed_over_after_grace_expires() {
        let now = Utc::now();
        let result = federation_service_binding_check_from_members(
            "did:web:old.example",
            now,
            &[event_id(1)],
            vec![member_view(
                "did:web:alice.example",
                "did:web:new.example",
                &event_id(2),
                now - Duration::seconds(DELIVERY_BINDING_HANDOVER_GRACE_SECONDS + 1),
            )],
        );

        assert!(matches!(
            result,
            FederationServiceBindingCheck::HandedOver(_)
        ));
    }

    #[test]
    fn federation_service_binding_check_rejects_ambiguous_handover_targets() {
        let now = Utc::now();
        let result = federation_service_binding_check_from_members(
            "did:web:old.example",
            now,
            &[event_id(1)],
            vec![
                member_view(
                    "did:web:alice.example",
                    "did:web:new.example",
                    &event_id(2),
                    now,
                ),
                member_view(
                    "did:web:bob.example",
                    "did:web:other.example",
                    &event_id(3),
                    now,
                ),
            ],
        );

        assert!(matches!(
            result,
            FederationServiceBindingCheck::Reject("delivery_binding_stale")
        ));
    }
}
