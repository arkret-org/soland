use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hasher;
use std::sync::{Arc, OnceLock};

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RawFederationEventsSubmitBody {
    service_binding_ref: FederationServiceBindingRef,
    events: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<String>,
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
    envelopes: Vec<Event>,
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
    envelopes: Vec<Event>,
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
        let envelope = match serde_json::to_value(envelope) {
            Ok(value) => value,
            Err(error) => {
                rejected.push(json!({
                    "id": "unknown",
                    "reason_code": "bad_json",
                    "detail": format!("event envelope re-encode failed: {error}"),
                }));
                continue;
            }
        };
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
                    rejected.push(json!({
                        "id": id,
                        "reason_code": error.code,
                        "detail": error.message,
                    }));
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
    let submit = match serde_json::from_value::<RawFederationEventsSubmitBody>(body_value.clone()) {
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

    if let Err((code, message)) = SolandEventsSubmitRequestBody::validate_federation_service_binding(
        &submit.service_binding_ref,
    ) {
        render_error(res, StatusCode::BAD_REQUEST, code, &message);
        return;
    }
    if submit.events.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "ck.peer.events.command.submit must contain at least one event",
        );
        return;
    }
    if cokret_sdk::validate_event_submit_batch_count(submit.events.len()).is_err() {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "ck.peer.events.command.submit exceeds max batch size",
        );
        return;
    }

    let binding_realm = submit.service_binding_ref.realm_id.as_str().to_owned();
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
            let quarantine = submit
                .events
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
    match federation_service_binding_current_for_destination(state, &submit.service_binding_ref)
        .await
    {
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
                let rejected = submit
                    .events
                    .iter()
                    .map(|envelope| {
                        json!({
                            "id": event_string_field_from_value(envelope, "event_id")
                                .unwrap_or_else(|| "unknown".to_owned()),
                            "reason_code": rejection.code,
                            "detail": rejection.message.clone(),
                        })
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

    for envelope in submit.events {
        let id = event_string_field_from_value(&envelope, "event_id")
            .unwrap_or_else(|| "unknown".to_owned());
        let event_realm = event_string_field_from_value(&envelope, "realm_id");
        if event_realm.as_deref() != Some(binding_realm.as_str()) {
            rejected.push(json!({
                "id": id,
                "reason_code": "schema_violation",
                "detail": "event realm_id must match service_binding_ref.realm_id",
            }));
            continue;
        }
        let Some(actor) = event_string_field_from_value(&envelope, "actor_id") else {
            rejected.push(json!({
                "id": id,
                "reason_code": "missing_param",
                "detail": "actor_id is required",
            }));
            continue;
        };
        if validate_did(&actor).is_err() {
            rejected.push(json!({
                "id": id,
                "reason_code": "invalid_param",
                "detail": "actor_id must be a DID",
            }));
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
            rejected.push(json!({
                "id": id,
                "reason_code": "capability_denied",
                "detail": "actor_id home domain does not match source-trust-domain and the actor is not a known member of the binding realm",
            }));
            continue;
        }
        if let Err(rejection) = profile_gate.enforce_event(&envelope) {
            rejected.push(json!({
                "id": id,
                "reason_code": rejection.code,
                "detail": rejection.message,
            }));
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
                    rejected.push(json!({
                        "id": id,
                        "reason_code": error.code,
                        "detail": error.message,
                    }));
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

async fn federation_service_binding_current_for_destination(
    state: &AppState,
    binding: &FederationServiceBindingRef,
) -> FederationServiceBindingCheck {
    // The delivery-binding gate validates an inbound push against the receiver's
    // existing local member bindings. A federation push that first establishes
    // the Realm on this receiver has no prior members to be stale against (and
    // the batch's own realm/member/binding events are validated by the normal
    // reducer admission path), so admit it instead of failing closed.
    if !crate::routing::events::event_log::realm_is_indexed(state, binding.realm_id.as_str()) {
        return FederationServiceBindingCheck::Current;
    }
    let members = {
        let projection = state.projection.lock().expect("projection lock");
        projection
            .members_of_realm(binding.realm_id.as_str())
            .into_iter()
            .filter_map(delivery_binding_member_view)
            .collect::<Vec<_>>()
    };
    // Federation replica / observer admission: when this server hosts the Realm
    // but is the effective `delivery_binding.recipient_service_did` for zero
    // local members, there is no local member binding the asserted frontier can
    // be stale against. A conservative deployment (default) still fails closed
    // below; a server explicitly configured as a replica / observer admits the
    // push as pure replication (config: `federation_replica_observer`).
    if state.settings().federation_replica_observer
        && !members
            .iter()
            .any(|member| member.recipient_service_did == state.config.service_did)
    {
        return FederationServiceBindingCheck::Current;
    }
    let result = federation_service_binding_check_from_members(
        state.config.service_did.as_str(),
        now(),
        &binding.delivery_binding_frontier,
        members,
    );
    match result {
        FederationServiceBindingCheck::Stale(mut evidence) => {
            evidence.witness = delivery_binding_handover_witness(state, &evidence).await;
            FederationServiceBindingCheck::Stale(evidence)
        }
        FederationServiceBindingCheck::HandedOver(mut evidence) => {
            evidence.witness = delivery_binding_handover_witness(state, &evidence).await;
            FederationServiceBindingCheck::HandedOver(evidence)
        }
        other => other,
    }
}

fn delivery_binding_member_view(
    member: &crate::reducer::SolandMembershipState,
) -> Option<DeliveryBindingMemberView> {
    if member.delivery_status.as_deref() != Some("routable") {
        return None;
    }
    let recipient_service_did = member.recipient_service_did.clone()?;
    let delivery_binding_frontier_ref = member
        .delivery_binding_frontier
        .clone()
        .or_else(|| member.membership_event_ref.clone())?;
    Some(DeliveryBindingMemberView {
        member: member.member.clone(),
        realm_id: member.realm_id.clone(),
        recipient_service_did,
        membership_event_ref: member.membership_event_ref.clone(),
        delivery_binding_frontier_ref,
        updated_at: member.updated_at,
    })
}

fn federation_service_binding_check_from_members(
    local_service_did: &str,
    now: DateTime<Utc>,
    request_frontier: &[EventId],
    members: Vec<DeliveryBindingMemberView>,
) -> FederationServiceBindingCheck {
    let current_local_frontiers = members
        .iter()
        .filter(|member| member.recipient_service_did == local_service_did)
        .map(|member| member.delivery_binding_frontier_ref.clone())
        .collect::<Vec<_>>();
    match federation_delivery_binding_frontier_is_current(request_frontier, current_local_frontiers)
    {
        Ok(()) => return FederationServiceBindingCheck::Current,
        Err("schema_violation") => {
            return FederationServiceBindingCheck::Reject("schema_violation");
        }
        Err(_) => {}
    }

    let request_set = request_frontier
        .iter()
        .map(|event_id| event_id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let candidates = members
        .into_iter()
        .filter(|member| !request_set.contains(member.delivery_binding_frontier_ref.as_str()))
        .filter_map(delivery_binding_handover_evidence_from_member)
        .map(|evidence| {
            (
                (
                    evidence.actor_id.as_str().to_owned(),
                    evidence.new_recipient_service_did.as_str().to_owned(),
                    evidence.delivery_binding_frontier_ref.clone(),
                ),
                evidence,
            )
        })
        .collect::<BTreeMap<_, _>>();
    if candidates.len() != 1 {
        return FederationServiceBindingCheck::Reject("delivery_binding_stale");
    }
    let evidence = candidates
        .into_values()
        .next()
        .expect("one handover evidence candidate");
    let grace_expired = evidence.new_recipient_service_did.as_str() != local_service_did
        && now.signed_duration_since(evidence.updated_at)
            > Duration::seconds(DELIVERY_BINDING_HANDOVER_GRACE_SECONDS);
    if grace_expired {
        FederationServiceBindingCheck::HandedOver(evidence)
    } else {
        FederationServiceBindingCheck::Stale(evidence)
    }
}

fn delivery_binding_handover_evidence_from_member(
    member: DeliveryBindingMemberView,
) -> Option<DeliveryBindingHandoverEvidence> {
    let actor_id = Did::new(member.member.clone()).ok()?;
    let new_recipient_service_did = Did::new(member.recipient_service_did.clone()).ok()?;
    let handover_frontier = vec![EventId::new(member.delivery_binding_frontier_ref.clone()).ok()?];
    Some(DeliveryBindingHandoverEvidence {
        realm_id: member.realm_id,
        actor_id,
        new_recipient_service_did,
        handover_frontier,
        membership_event_ref: member.membership_event_ref,
        delivery_binding_frontier_ref: member.delivery_binding_frontier_ref,
        updated_at: member.updated_at,
        witness: Value::Null,
    })
}

async fn delivery_binding_handover_witness(
    state: &AppState,
    evidence: &DeliveryBindingHandoverEvidence,
) -> Value {
    let frontier = evidence
        .handover_frontier
        .iter()
        .map(|event_id| event_id.as_str())
        .collect::<Vec<_>>();
    let mut witness = json!({
        "kind": "member_delivery_binding_projection",
        "realm_id": evidence.realm_id.as_str(),
        "actor_id": evidence.actor_id.as_str(),
        "recipient_service_did": evidence.new_recipient_service_did.as_str(),
        "delivery_binding_frontier": frontier,
        "membership_event_ref": evidence.membership_event_ref.as_deref(),
        "projection_updated_at": evidence.updated_at.to_rfc3339(),
    });

    if let Some(frontier_event_id) = evidence.handover_frontier.first() {
        match state
            .persistence
            .events()
            .get(frontier_event_id.as_str())
            .await
        {
            Ok(Some(record)) => {
                if let Some(object) = witness.as_object_mut() {
                    object.insert(
                        "event_id".to_owned(),
                        Value::String(record.event_id.clone()),
                    );
                    object.insert("event_kind".to_owned(), Value::String(record.kind.clone()));
                    object.insert(
                        "event_digest".to_owned(),
                        Value::String(record.canonical_digest.clone()),
                    );
                    object.insert(
                        "event_received_at".to_owned(),
                        Value::String(record.received_at.to_rfc3339()),
                    );
                }
            }
            Ok(None) => {
                if let Some(object) = witness.as_object_mut() {
                    object.insert(
                        "event_lookup".to_owned(),
                        Value::String("missing".to_owned()),
                    );
                }
            }
            Err(_) => {
                if let Some(object) = witness.as_object_mut() {
                    object.insert(
                        "event_lookup".to_owned(),
                        Value::String("unavailable".to_owned()),
                    );
                }
            }
        }
    }

    if let (Ok(realm_id), Ok(cell_ref)) = (
        RealmId::new(evidence.realm_id.clone()),
        cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.member.state.v1:{}",
            evidence.actor_id.as_str()
        )),
    ) {
        match state.cell_store.sealed_ops_for_cell(&realm_id, &cell_ref) {
            Ok(ops) => {
                let move_ids = ops.iter().map(|op| op.move_id.as_str()).collect::<Vec<_>>();
                if let Some(object) = witness.as_object_mut() {
                    object.insert("sealed_ops_count".to_owned(), json!(ops.len()));
                    object.insert("sealed_move_ids".to_owned(), json!(move_ids));
                    object.insert("seal_backed".to_owned(), json!(!ops.is_empty()));
                }
            }
            Err(_) => {
                if let Some(object) = witness.as_object_mut() {
                    object.insert(
                        "seal_lookup".to_owned(),
                        Value::String("unavailable".to_owned()),
                    );
                }
            }
        }
    }

    witness
}

fn events_submit_status_label(status: EventsSubmitStatus) -> &'static str {
    match status {
        EventsSubmitStatus::Accepted => "accepted",
        EventsSubmitStatus::Duplicate => "duplicate",
        EventsSubmitStatus::Partial => "partial",
        EventsSubmitStatus::HistoricalOnly => "historical_only",
    }
}

async fn preflight_mls_welcome_claim_signature_reject(
    state: &AppState,
    actor_id: &str,
    operation: &Operation,
) -> Option<String> {
    if kinds::canonical_kind_string(operation) != cokret_sdk::events::kinds::MLS_WELCOME {
        return None;
    }
    let envelope_value = match operation.payload.get("claim_envelope") {
        Some(value) => value.clone(),
        None => {
            return Some(crate::error::reasons::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
        }
    };
    let envelope =
        match serde_json::from_value::<cokret_sdk::MlsWelcomeClaimEnvelope>(envelope_value) {
            Ok(envelope) => envelope,
            Err(_) => {
                return Some(
                    crate::error::reasons::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned(),
                );
            }
        };
    if envelope.requester_did.as_str() != actor_id {
        return Some(crate::error::reasons::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
    }
    let sender_device_id = operation
        .payload
        .get("sender_device_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    crate::routing::identity::cross_signing::verify_mls_welcome_claim_envelope_signature(
        state,
        &envelope,
        sender_device_id,
    )
    .await
    .err()
    .map(str::to_owned)
}

pub(super) fn events_submit_outcome(
    status: EventsSubmitStatus,
    accepted: Vec<String>,
    duplicate: Vec<String>,
    rejected: Vec<Value>,
    quarantine: Vec<String>,
    cursor: Option<String>,
) -> EventsSubmitOutcome {
    EventsSubmitOutcome {
        status,
        accepted: accepted
            .into_iter()
            .filter_map(|event_id| EventId::new(event_id).ok())
            .collect(),
        duplicate: duplicate
            .into_iter()
            .filter_map(|event_id| EventId::new(event_id).ok())
            .collect(),
        rejected,
        quarantine: quarantine
            .into_iter()
            .filter_map(|event_id| EventId::new(event_id).ok())
            .collect(),
        actor_frontier: Value::Null,
        realm_frontier: Value::Null,
        cursor,
        original_outcome: None,
    }
}

async fn enforce_sibling_fork_limit(
    state: &AppState,
    session: &SessionRecord,
    parsed: &ValidatedEventEnvelope,
    existing_records: &[CanonicalEventRecord],
) -> Result<(), SubmitOneError> {
    let prev_frontier_digest = prev_frontier_digest(&parsed.prev_refs)?;
    let sibling_count = existing_records
        .iter()
        .filter(|record| record.actor_id == parsed.actor_id && record.actor_seq == parsed.actor_seq)
        .filter_map(|record| stored_prev_frontier_digest(record).ok())
        .filter(|digest| digest == &prev_frontier_digest)
        .count();
    if sibling_count < cokret_sdk::MAX_ACTOR_SEQ_SIBLINGS {
        return Ok(());
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "events.submit",
        json!({
            "event_id": parsed.event_id.clone(),
            "realm_id": parsed.realm_id.clone(),
            "actor_id": parsed.actor_id.clone(),
            "actor_seq": parsed.actor_seq,
            "prev_frontier_digest": prev_frontier_digest,
            "accepted_sibling_count": sibling_count,
            "max_actor_seq_siblings": cokret_sdk::MAX_ACTOR_SEQ_SIBLINGS,
        }),
        "fork_quarantine",
    )
    .await;
    Err(SubmitOneError::quarantine(
        parsed.event_id.clone(),
        "fork_quarantine",
        "actor_seq sibling fork limit exceeded; event is quarantined pending actor-chain repair",
    ))
}

fn stored_prev_frontier_digest(record: &CanonicalEventRecord) -> Result<String, SubmitOneError> {
    let prev_refs = record
        .envelope
        .get("prev_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    prev_frontier_digest(&prev_refs)
}

fn prev_frontier_digest(prev_refs: &[String]) -> Result<String, SubmitOneError> {
    cokret_sdk::prev_frontier_digest(prev_refs).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("prev_refs cannot be canonicalized: {error}"),
        )
    })
}

pub(in crate::routing) async fn submit_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    submit_event_value_with_context(state, session, envelope, &[]).await
}

async fn submit_event_value_with_context(
    state: &AppState,
    session: &SessionRecord,
    mut envelope: Value,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let raw_bytes = serde_json::to_vec(&envelope).map_err(|_| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "bad_json",
            "event envelope cannot be encoded",
        )
    })?;
    if cokret_sdk::validate_event_envelope_byte_len(raw_bytes.len()).is_err() {
        return Err(SubmitOneError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "event envelope exceeds max_event_bytes",
        ));
    }

    let parsed =
        validate_event_envelope_with_context(state, session, &envelope, realm_bootstrap_contexts)
            .await?;
    let actor_lock = actor_submit_lock(&parsed.actor_id);
    let _actor_submit_guard = actor_lock.lock().await;
    let received_at = now();
    let store = state.persistence.events();
    if let Ok(Some(existing)) = store.get(&parsed.event_id).await {
        if existing.canonical_bytes == parsed.canonical_bytes {
            return Ok(event_submit_response(
                state,
                EventsSubmitStatus::Duplicate,
                existing.event_id.clone(),
            )
            .await);
        }
        append_audit_log(
            state,
            Some(&session.actor),
            "events.submit",
            json!({
                "event_id": parsed.event_id,
                "reason": "duplicate_conflict",
                "canonical_digest": parsed.canonical_digest
            }),
            "duplicate_conflict",
        )
        .await;
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "event_id already exists with different canonical bytes",
        ));
    }
    let existing_records = store.snapshot_all().await.map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("events store unavailable: {error}"),
        )
    })?;
    if parsed.kind == cokret_sdk::events::kinds::REALM_CREATE
        && existing_records.iter().any(|record| {
            record.kind == cokret_sdk::events::kinds::REALM_CREATE
                && record.realm_id.as_deref() == Some(parsed.realm_id.as_str())
        })
    {
        return Err(realm_already_exists_error());
    }
    if let Some(max_seq) = existing_records
        .iter()
        .filter(|record| record.actor_id == parsed.actor_id)
        .map(|record| record.actor_seq)
        .max()
        && parsed.actor_seq < max_seq
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "cas_conflict",
            "actor_seq is older than the accepted actor frontier",
        ));
    }
    for prev_ref in &parsed.prev_refs {
        if !existing_records
            .iter()
            .any(|record| record.event_id == *prev_ref)
        {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "prev_refs must reference accepted events",
            ));
        }
    }
    for authorized_ref in &parsed.authorized_refs {
        if !existing_records
            .iter()
            .any(|record| record.event_id == *authorized_ref)
        {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "refs[role=authorized_by] must reference accepted authorization events",
            ));
        }
    }
    enforce_sibling_fork_limit(state, session, &parsed, &existing_records).await?;

    let projection_operation = projection_operation_from_event(&parsed, &envelope);
    tracing::debug!(
        event_id = %parsed.event_id,
        kind = %parsed.kind,
        realm_id = %parsed.realm_id,
        has_projection = projection_operation.is_some(),
        "submit_event"
    );
    let mut strand_status_audit_payload = None;
    if let Some(operation) = projection_operation.as_ref() {
        if let Err(message) = validate_operation_semantics(state, std::slice::from_ref(operation)) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                message,
            ));
        }
        if let Err(reason) =
            validate_content_encryption_floor(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        // CKP-0016 — reject agent_participation ceiling writes that widen
        // the parent scope's ceiling (tighten-only invariant).
        if let Err(reason) =
            validate_agent_participation_ceiling(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        // CKP-0016 §5.2 / architecture §7 — native personal agent writes
        // require an auditable agent_context plus the effective participation
        // bit for the write mode. Per 0016-agent-participation-policy.md §6,
        // missing materialised grants are preconditions, not auth-context
        // denials.
        let agent_policy_operation = operation_with_unsigned_agent_context(operation, &envelope);
        if let Err(reason) =
            validate_agent_reply_participation(state, std::slice::from_ref(&agent_policy_operation))
                .await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        if let Err(message) =
            validate_operation_policy(state, std::slice::from_ref(operation)).await
        {
            let (status, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            return Err(SubmitOneError::new(status, code, message));
        }
        if let Err(rejection) = policy_gate::enforce_operation_policy_server(
            state,
            &parsed.actor_id,
            operation,
            PolicyGateSurface::LocalSubmit,
        )
        .await
        {
            return Err(SubmitOneError::new(
                rejection.status,
                rejection.code,
                rejection.message,
            ));
        }
        if let Some(reason) =
            preflight_mls_welcome_claim_signature_reject(state, &parsed.actor_id, operation).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
        let (invite_preflight_reject, invite_proof_context) = {
            // Admission checks below are mandatory and MUST NOT be skipped
            // (fail-closed). The projection lock is the poison-free
            // `state::Mutex`, so acquiring it cannot fail and this block
            // always runs.
            let proj = state.projection.lock().expect("projection lock");
            if let Err(reason) = proj.check_space_container_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_status_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // event-and-patch.md §4.4 — a Control Move's generic
            // `preconditions[].head_eq` compare-and-swap MUST be evaluated
            // against the materialized head before any effect lands; a stale
            // head fails closed with `failed_precondition` and no partial
            // apply.
            if let Err(reason) = proj.check_move_preconditions(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            strand_status_audit_payload =
                proj.strand_status_transition_audit_payload(operation, &parsed.actor_id);
            if let Err(reason) = proj.check_morph_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // morph.md §4.1 S1/S3 — schema-migration profile gate, dialect
            // check, S1 version binding, and from_schema_refs[] CAS. Capability
            // (`capability_denied`) is enforced earlier in the operation policy
            // layer where the authz engine is available.
            if let Err(reason) = proj.check_morph_schema_migrate(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_redaction_target_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_tracks_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_bottom_cell_transition(operation) {
                let (code, message) = cba_bottom_reject(reason);
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    code,
                    message,
                ));
            }
            if let Err(reason) = proj.check_membership_join_admission(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // join-policy.md §3 / §7 / §12 — application-review workflow
            // anti-abuse limits (cooldown_after_reject, application_ttl,
            // max_open_applications_per_actor) and review-decision
            // preconditions for the candidate profile-private payloads.
            if let Err(reason) = proj.check_membership_application_admission(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // join-policy.md §7.5 — `ck.invite.create` with
            // `refs[role="join_authorised_by"]` MUST bind to a fresh,
            // unconsumed review accept whose reviewer still holds
            // `review_capability`.
            if let Err(reason) = proj.check_invite_join_authorisation(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_pin_scope_safety(operation) {
                let status = if reason == "not_found" {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::PRECONDITION_FAILED
                };
                return Err(SubmitOneError::new(status, reason, reason));
            }
            // relation.md §2/§4 — relation effective scope is reducer-managed,
            // and structural contains/belongs_to MUST stay within one Realm.
            if let Err(reason) = proj.check_relation_invariants(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_child_scope_policy_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // capabilities.md §10.2 — a ck.capability.delegate that closes a
            // delegation cycle MUST be rejected before it projects.
            if let Err(reason) = proj.check_delegation_cycle(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Some(reason) = preflight_calendar_projection_reject(&proj, operation, &state.hlc)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = preflight_mls_projection_reject(&proj, operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            // P2 — moderation §5.5.2 reducer constraints (separation of
            // duties, overturn↔lift, modify↔new-decision) fail-closed at
            // ingest. The clone sees cells already advanced by earlier
            // in-batch decision / lift submits, so the atomicity checks
            // resolve against the live moderation_state cell.
            if let Some(reason) =
                preflight_moderation_projection_reject(&proj, operation, &state.hlc)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            let invite_preflight_reject =
                preflight_invite_projection_reject(state, &proj, operation, &state.hlc);
            let invite_proof_context = if invite_preflight_reject.is_none() {
                invite_claim_proof_context_from_projection(&proj, operation).map_err(|reason| {
                    SubmitOneError::new(StatusCode::PRECONDITION_FAILED, reason, reason)
                })?
            } else {
                None
            };
            (invite_preflight_reject, invite_proof_context)
        };
        if let Some(reason) = invite_preflight_reject {
            record_rejected_invite_claim_effect(state, operation)
                .await
                .map_err(|message| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invite_claim_reject_effect_failed",
                        message,
                    )
                })?;
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
        if let Some(context) = invite_proof_context
            && let Err(reason) =
                verify_invite_claim_proofs_for_operation(state, operation, &context)
        {
            record_rejected_invite_claim_effect(state, operation)
                .await
                .map_err(|message| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invite_claim_reject_effect_failed",
                        message,
                    )
                })?;
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
    }

    // SEC-04 — receiver-side independent 24h inception-key online-window cap
    // (`identity/key-management.md` §5.0.1 step 5). When an inception-bootstrap
    // self-authorization (`ck.device.authorize` / `ck.session.grant` carrying a
    // `refs[role=did_inception]` evidence ref) is signed by the inception key,
    // the receiver MUST seal on the verifiable bootstrap timestamp
    // (`did:webvh` entry-0 `versionTime`) and reject the event when the
    // inception key age exceeds the 24h protocol hard cap — regardless of any
    // longer window the deployment self-reports. Runs against the full envelope
    // because the `did_inception` evidence ref lives on the envelope `refs[]`,
    // not on the projection operation payload.
    enforce_inception_key_online_window(state, &parsed, &envelope).await?;

    // SPEC-SOL-003 follow-through — an accepted durable `ck.device.revoke`
    // is the canonical revocation trigger (device-lifecycle.md §2.2).
    // Validate the revocation against the submitting session, then flip the
    // device record the auth gate reads BEFORE persisting the event: a
    // failed flip rejects the submission (no event-without-enforcement),
    // while a flipped record with a failed persist only over-revokes — the
    // safe direction, the peer device can resubmit.
    if parsed.kind == "ck.device.revoke" {
        let target_device_id = validate_device_revoke_submission(session, &parsed, &envelope)?;
        crate::routing::identity::auth::revoke_device_record(
            state,
            &parsed.actor_id,
            &target_device_id,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("device revocation enforcement failed: {error}"),
            )
        })?;
        // device-lifecycle.md §7 grace drop — a to-device message already queued
        // for the revoked device MUST be dropped on revocation: a lost or
        // compromised device that comes back online MUST NOT drain key-exchange
        // or verification bootstrap material queued before the revoke. Runs after
        // the record flip so `GET /_cokret/self/device_messages` for that device
        // returns nothing once the revoke is accepted.
        let purge_outcome = crate::routing::identity::auth::purge_device_delivery_state(
            state,
            &parsed.actor_id,
            &target_device_id,
        )
        .await;
        append_audit_log(
            state,
            Some(&parsed.actor_id),
            "device.revoke",
            json!({
                "revoked_device_id": target_device_id,
                "by_device_id": session.device_id.clone(),
                "via": "ck.device.revoke",
                "event_id": parsed.event_id.clone(),
                "to_device_messages_dropped": purge_outcome.to_device_messages_dropped,
                "push_registrations_removed": purge_outcome.push_registrations_removed,
            }),
            "accepted",
        )
        .await;
    }

    // morph.md §4.1 S3 — a breaking / transformation schema migration that
    // reached this point passed the profile gate + capability check + CAS, and
    // MUST emit a `schema_migration_breaking` audit record carrying issuer,
    // from/to schema sets, compatibility class, the capability action used, and
    // the opt-in profile ref. (additive migrations need no audit-grade record.)
    if parsed.kind == cokret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE {
        let migrate_payload = envelope.get("payload");
        let compatibility_class = migrate_payload
            .and_then(|payload| payload.get("compatibility_class"))
            .and_then(|value| value.as_str());
        if matches!(compatibility_class, Some("breaking" | "transformation")) {
            let payload_field =
                |field: &str| migrate_payload.and_then(|payload| payload.get(field));
            let capability_used = payload_field("capability_action")
                .or_else(|| payload_field("action"))
                .and_then(|value| value.as_str())
                .unwrap_or("ck.morph.schema_migrate");
            append_audit_log(
                state,
                Some(&parsed.actor_id),
                "schema_migration_breaking",
                json!({
                    "realm_id": parsed.realm_id.clone(),
                    "morph_id": payload_field("morph_id"),
                    "issuer": parsed.actor_id.clone(),
                    "from_schema_refs": payload_field("from_schema_refs"),
                    "to_schema_refs": payload_field("to_schema_refs"),
                    "compatibility_class": compatibility_class,
                    "capability_used": capability_used,
                    "profile_ref": "ck.profile.morph.schema_migration_transformations.v1",
                    "event_id": parsed.event_id.clone(),
                }),
                "accepted",
            )
            .await;
        }
    }

    // CKP-0007: stamp the authoritative top-level `effective_scope` onto the
    // stored envelope so read-path visibility gating
    // (`effective_scope_for_envelope` → `circle_event_visible_to_session`)
    // hides circle-scoped activity from realm members outside the Circle.
    //
    // Create events carry `scope_circle_id` in `payload.object` and the reader
    // extracts it directly, so they need no stamp. But events whose payload
    // does NOT carry the scope — a message (scope is a Strand field, never on
    // the message) and Strand update / lifecycle (scope is create-locked, not
    // re-sent) — would otherwise resolve to no scope and leak to non-members.
    // Resolve the authoritative Strand scope from the durable projection
    // (projection_strands.scope_circle_id survives restart) and stamp it.
    let scope_strand_id: Option<String> = envelope
        .get("payload")
        .and_then(|payload| match parsed.kind.as_str() {
            cokret_sdk::events::kinds::MESSAGE_CREATE
            | cokret_sdk::events::kinds::STRAND_MOVE
            | cokret_sdk::events::kinds::STRAND_REORDER => {
                payload.get("strand_id").and_then(Value::as_str)
            }
            cokret_sdk::events::kinds::STRAND_UPDATE
            | cokret_sdk::events::kinds::STRAND_ARCHIVE
            | cokret_sdk::events::kinds::STRAND_RESTORE => {
                payload.get("target_ref").and_then(Value::as_str)
            }
            _ => None,
        })
        .map(ToOwned::to_owned);
    if let Some(scope_strand_id) = scope_strand_id {
        let scope = state
            .projection
            .lock()
            .ok()
            .and_then(|proj| proj.strand_scope_circle_id(&scope_strand_id));
        if let Some(scope) = scope
            && let Some(object) = envelope.as_object_mut()
        {
            object.insert("effective_scope".to_owned(), Value::String(scope));
        }
    }

    let envelope_for_bootstrap = envelope.clone();
    if let Err(error) = store
        .put(CanonicalEventRecord {
            event_id: parsed.event_id.clone(),
            actor_id: parsed.actor_id.clone(),
            actor_seq: parsed.actor_seq,
            realm_id: Some(parsed.realm_id.clone()),
            kind: parsed.kind.clone(),
            schema_id: parsed.schema_id.clone(),
            canonical_digest: parsed.canonical_digest.clone(),
            canonical_bytes: parsed.canonical_bytes.clone(),
            envelope,
            received_at,
        })
        .await
    {
        if parsed.kind == cokret_sdk::events::kinds::REALM_CREATE
            && persistence_error_is_realm_already_exists(&error)
        {
            return Err(realm_already_exists_error());
        }
        tracing::error!(%error, "failed to persist canonical event");
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "events store unavailable",
        ));
    }
    if let Some(operation) = projection_operation {
        super::super::projection::project_accepted_operations_from_device(
            state,
            &parsed.actor_id,
            &parsed.device_id,
            &[operation],
        )
        .await;
    }
    if !session.token_hash.starts_with("federation:") {
        enqueue_peer_event_fanout(state, &parsed, &envelope_for_bootstrap).await;
    }
    if let Some(payload) = strand_status_audit_payload {
        append_audit_log(
            state,
            Some(&parsed.actor_id),
            "incident.status.transition",
            payload,
            "accepted",
        )
        .await;
    }
    if parsed.kind == "ck.realm.create"
        && let Some(envelope_object) = envelope_for_bootstrap.as_object()
    {
        bootstrap_realm_member_index(state, &parsed.realm_id, &parsed.actor_id, envelope_object)
            .await;
        organizations::record_realm_organizations_from_event(
            state,
            &parsed.realm_id,
            &envelope_for_bootstrap,
        )
        .await;
    }
    append_encrypted_message_franking(state, &parsed, &envelope_for_bootstrap).await;
    append_audit_log(
        state,
        Some(&session.actor),
        "events.submit",
        json!({
            "event_id": parsed.event_id.clone(),
            "realm_id": parsed.realm_id.clone(),
            "kind": parsed.kind.clone(),
            "canonical_digest": parsed.canonical_digest.clone()
        }),
        "accepted",
    )
    .await;
    Ok(event_submit_response(state, EventsSubmitStatus::Accepted, parsed.event_id).await)
}

fn operation_with_unsigned_agent_context(operation: &Operation, envelope: &Value) -> Operation {
    let mut operation = operation.clone();
    if let Some(object) = operation.payload.as_object_mut()
        && !object.contains_key("agent_context")
        && let Some(agent_context) = envelope
            .get("unsigned")
            .and_then(|unsigned| unsigned.get("agent_context"))
            .filter(|value| value.is_object())
    {
        object.insert("agent_context".to_owned(), agent_context.clone());
    }
    operation
}

async fn record_rejected_invite_claim_effect(
    state: &AppState,
    operation: &Operation,
) -> Result<(), String> {
    if !kinds::operation_is_invite_claim(operation) {
        return Ok(());
    }
    let Some(payload) = operation.payload.as_object() else {
        return Ok(());
    };
    let Some(invite_id) = rejected_invite_claim_string_field(payload, "invite_id") else {
        return Ok(());
    };
    let Some(claim_nonce) = rejected_invite_claim_string_field(payload, "claim_nonce") else {
        return Ok(());
    };

    let invites = state.persistence.realm_invites();
    let Some(mut record) = invites
        .get(&invite_id)
        .await
        .map_err(|error| format!("load invite {invite_id}: {error}"))?
    else {
        return Ok(());
    };

    let mut changed = false;
    match record.claim_nonces.get(&claim_nonce) {
        Some(existing_operation_id) if existing_operation_id != operation.operation_id.as_str() => {
            return Ok(());
        }
        Some(_) => {}
        None => {
            record
                .claim_nonces
                .insert(claim_nonce.clone(), operation.operation_id.to_string());
            changed = true;
        }
    }

    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= operation.created_at)
    {
        record.status = "expired".to_owned();
        record.invite_token.clear();
        remove_rejected_claim_active_material(&mut record.third_party_id, true);
        changed = true;
    }

    if !changed {
        return Ok(());
    }
    record.updated_at = Some(operation.created_at);
    invites
        .put(record)
        .await
        .map_err(|error| format!("store invite rejected claim effect: {error}"))
}

fn rejected_invite_claim_string_field(
    payload: &serde_json::Map<String, Value>,
    field: &str,
) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn remove_rejected_claim_active_material(
    third_party_id: &mut Option<Value>,
    remove_commitment: bool,
) {
    let Some(value) = third_party_id.as_mut() else {
        return;
    };
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for key in [
        "token_salt",
        "token_salt_id",
        "lookup_table_ref",
        "pepper",
        "pepper_id",
    ] {
        object.remove(key);
    }
    if remove_commitment {
        object.remove("token_commitment");
    }
}

async fn enqueue_peer_event_fanout(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) {
    let peers = dynamic_peer_event_targets(state, parsed);
    if peers.is_empty() {
        return;
    }
    let event_id = parsed.event_id.as_str();
    let binding_payload = json!({
        "domain": "ck.peer.events.command.submit.service_binding.v1",
        "realm_id": parsed.realm_id,
        "event_id": event_id,
        "canonical_digest": parsed.canonical_digest,
    });
    let event = match serde_json::from_value::<Event>(envelope.clone()) {
        Ok(event) => event,
        Err(error) => {
            tracing::warn!(
                %error,
                event_id,
                "failed to type checked peer fanout event envelope"
            );
            return;
        }
    };
    for peer in peers {
        let service_binding_ref = match service_binding_ref_for_target(
            parsed,
            &binding_payload,
            &peer,
        ) {
            Some(value) => value,
            None => {
                tracing::warn!(
                    event_id,
                    peer_did = %peer.service_did,
                    "failed to build typed dynamic ck.peer.events.command.submit service binding"
                );
                continue;
            }
        };
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(state.config.service_did.as_bytes());
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(peer.service_did.as_bytes());
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(event_id.as_bytes());
        hasher_input.extend_from_slice(b"|");
        hasher_input.extend_from_slice(parsed.canonical_digest.as_bytes());
        for frontier in &peer.delivery_binding_frontier {
            hasher_input.extend_from_slice(b"|");
            hasher_input.extend_from_slice(frontier.as_bytes());
        }
        let idempotency_key = format!("ck:outbox:event:{}", sha256_hex(&hasher_input));
        let body = EventsSubmitFederationRequestBody {
            service_binding_ref,
            events: vec![event.clone()],
            idempotency_key: Some(idempotency_key.clone()),
        };
        let payload = match canonical::canonical_json_bytes(&body)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
        {
            Some(payload) => payload,
            None => {
                tracing::warn!(
                    event_id,
                    peer_did = %peer.service_did,
                    "failed to encode dynamic ck.peer.events.command.submit body"
                );
                continue;
            }
        };
        if peer.service_did == state.config.service_did {
            continue;
        }
        if let Err(error) = crate::routing::federation::outbox::enqueue_outbound(
            state,
            peer.url.as_str(),
            peer.service_did.as_str(),
            "/_cokret/peer/events",
            &idempotency_key,
            &payload,
        )
        .await
        {
            tracing::warn!(
                %error,
                event_id,
                peer = %peer.url,
                peer_did = %peer.service_did,
                "failed to enqueue dynamic ck.peer.events.command.submit fanout"
            );
        }
    }
}

struct DynamicPeerEventTarget {
    url: String,
    service_did: String,
    membership_frontier: Vec<String>,
    delivery_binding_frontier: Vec<String>,
}

fn dynamic_peer_event_targets(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
) -> Vec<DynamicPeerEventTarget> {
    let service_frontiers = {
        let projection = state.projection.lock().expect("projection lock");
        // sync/federation.md §4.4 — peers whose federation service delegation
        // for this Realm has been revoked MUST NOT receive future outbound
        // pushes. Compute the revoked-peer set once under the projection lock.
        // The revoke / grant capability control events themselves still fan out
        // so the peer can invalidate its allow cache (§4.4: "推送 payload MUST
        // 包含原始 Event Envelope … 便于接收方立即失效 capability cache"); only
        // non-capability events are gated.
        let is_capability_control_event = matches!(
            parsed.kind.as_str(),
            "ck.capability.revoke" | "ck.capability.grant" | "ck.capability.delegate"
        );
        let revoked_peers = if is_capability_control_event {
            std::collections::BTreeSet::new()
        } else {
            projection.federation_delivery_revoked_peers(&parsed.realm_id)
        };
        let mut service_frontiers: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> =
            BTreeMap::new();
        for member in projection.members_of_realm(&parsed.realm_id) {
            if member.delivery_status.as_deref() != Some("routable") {
                continue;
            }
            let Some(service_did) = member.recipient_service_did.as_deref() else {
                continue;
            };
            if service_did == state.config.service_did {
                continue;
            }
            if revoked_peers.contains(service_did) {
                tracing::info!(
                    event_id = %parsed.event_id,
                    realm_id = %parsed.realm_id,
                    revoked_peer_service_did = %service_did,
                    "skipping outbound federation push to peer with revoked service delegation (federation.md §4.4)"
                );
                continue;
            }
            let entry = service_frontiers.entry(service_did.to_owned()).or_default();
            if let Some(frontier) = member.membership_event_ref.as_deref() {
                entry.0.insert(frontier.to_owned());
            }
            if let Some(frontier) = member
                .delivery_binding_frontier
                .as_deref()
                .or(member.membership_event_ref.as_deref())
            {
                entry.1.insert(frontier.to_owned());
            }
        }
        service_frontiers
    };

    service_frontiers
        .into_iter()
        .filter_map(
            |(service_did, (membership_frontier, delivery_binding_frontier))| {
                let url = match crate::routing::federation::federation::peer_url_for_service_did(
                    state,
                    &service_did,
                ) {
                    Some(url) => url,
                    None => {
                        tracing::warn!(
                            event_id = %parsed.event_id,
                            realm_id = %parsed.realm_id,
                            destination_service_did = %service_did,
                            "dynamic peer event fanout target has no configured service URL"
                        );
                        return None;
                    }
                };
                Some(DynamicPeerEventTarget {
                    url,
                    service_did,
                    membership_frontier: membership_frontier.into_iter().collect(),
                    delivery_binding_frontier: delivery_binding_frontier.into_iter().collect(),
                })
            },
        )
        .collect()
}

fn service_binding_ref_for_target(
    parsed: &ValidatedEventEnvelope,
    binding_payload: &Value,
    target: &DynamicPeerEventTarget,
) -> Option<cokret_sdk::FederationServiceBindingRef> {
    let membership_frontier =
        typed_frontier_or_fallback(&target.membership_frontier, &parsed.event_id)?;
    let delivery_binding_frontier =
        typed_frontier_or_fallback(&target.delivery_binding_frontier, &parsed.event_id)?;
    Some(cokret_sdk::FederationServiceBindingRef {
        realm_id: RealmId::new(parsed.realm_id.clone()).ok()?,
        realm_policy_digest: Hash::new(canonical_json_hash(binding_payload)).ok()?,
        membership_frontier,
        delivery_binding_frontier,
        destination_service_type: "principal_server".to_owned(),
        reducer_profile_digest: Hash::new(
            cokret_sdk::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST.to_owned(),
        )
        .ok()?,
    })
}

fn typed_frontier_or_fallback(
    frontier: &[String],
    fallback_event_id: &str,
) -> Option<Vec<EventId>> {
    let mut typed = frontier
        .iter()
        .filter_map(|event_id| EventId::new(event_id.to_owned()).ok())
        .collect::<Vec<_>>();
    if typed.is_empty() {
        typed.push(EventId::new(fallback_event_id.to_owned()).ok()?);
    }
    Some(typed)
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
