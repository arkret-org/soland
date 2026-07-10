//! AKP-0008 / AKP-0009 — Personal Agent provisioning + lifecycle surface.
//!
//! Implements the 11 personal-agent HTTP operations gap-reported as missing
//! in soland. The handlers below stand up the cross-project HTTP contract
//! (sodmin admin UI, inkson client, cotest journey vectors) ahead of the
//! deep reducer logic.
//!
//! Surfaces:
//! - `POST   /_arkret/gate/account/agent-key-pair`               —
//!   `ak.gate.account.command.pair_agent_key`
//! - `POST   /_arkret/self/agents`                             — `ak.self.agent.command.provision`
//! - `GET    /_arkret/self/agents`                             — `ak.self.agent.query.list`
//! - `GET    /_arkret/self/agents/{id}`                        — `ak.self.agent.resource.get`
//! - `POST   /_arkret/self/agents/{id}/pause`                  — `ak.self.agent.command.pause`
//! - `POST   /_arkret/self/agents/{id}/resume`                 — `ak.self.agent.command.resume`
//! - `POST   /_arkret/self/agents/{id}/deactivate`             — `ak.self.agent.command.deactivate`
//! - `POST   /_arkret/self/agents/{id}/rotate-key`             — `ak.self.agent.command.rotate_key`
//! - `POST   /_arkret/self/agents/{id}/grants`                 —
//!   `ak.self.agent.grant.command.attach`
//! - `DELETE /_arkret/self/agents/{id}/grants/{grant_id}`      —
//!   `ak.self.agent.grant.resource.delete`
//! - `POST   /_arkret/self/agent-sidecar-threads:ensure`       —
//!   `ak.self.agent.sidecar_thread.command.ensure`
//!
//! Controller operations enforce the persisted `agent_principals.controller_did`
//! binding before they mutate state or emit fan-out. Each handler appends an
//! audit-log row matching the canonical event-kind name so the existing admin /
//! federation projections stay in sync ahead of the reducer rewrite.

use std::collections::BTreeSet;

use arkret_sdk::models::{
    AgentDeactivateRequestBody, AgentGrantAttachOutcome, AgentGrantAttachRequestBody,
    AgentGrantDetachOutcome, AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentLifecycleOutcome,
    AgentLifecycleState, AgentList, AgentPairingBootstrap, AgentPairingResolveRequestBody,
    AgentParticipation, AgentParticipationEntry,
    AgentParticipationOutcome as AgentParticipationResBody, AgentParticipationScope,
    AgentParticipationSetRequestBody as AgentParticipationSetReqBody, AgentPauseRequestBody,
    AgentProjection, AgentProtocolDiscoverOutcome, AgentProtocolDiscoverRequestBody,
    AgentProvisionOutcome, AgentProvisionRequestBody, AgentResumeRequestBody,
    AgentRotateKeyOutcome, AgentRotateKeyRequestBody, AgentRuntimeApprovalOutcome,
    AgentRuntimeApprovalRequestBody, AgentSidecarContextRef, AgentSidecarExposureAck,
    AgentSidecarThreadEnsureOutcome, AgentSidecarThreadEnsureRequestBody, AgentStatus, AgentView,
    PublicKey, effective_participation, validate_agent_slug, validate_selection_within_ceiling,
};
use arkret_sdk::{
    CircleId, Did, EventId, GrantId, Hash, Operation, OperationId, RealmId, RelationId, StrandId,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::SecondsFormat;
use ed25519_dalek::Verifier as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, append_audit_log, now, validate_did};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::accept_local_operations;
use crate::routing::events::event_log::submit_event_value;
use crate::state::{AppState, SessionRecord};

mod dev_fanout;
use dev_fanout::{
    attach_agent_grant_event, ensure_self_realm, fanout_provision_subevents,
    materialize_capability_grant, revoke_capability_grant, submit_durable_agent_lifecycle,
    submit_durable_key_authorize, submit_revoke_agent_grants, submit_revoke_agent_keys,
};

mod common;
mod lifecycle;
mod pairing;
mod participation;
mod sidecar;

use common::*;
use lifecycle::*;
use pairing::*;
use participation::*;
use sidecar::*;

/// Mounted under `/_arkret/self`.
pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("agents")
                .post(provision_agent)
                .get(list_agents)
                .push(Router::with_path("discover").post(discover_agent_endpoint))
                .push(Router::with_path("{agent_principal_id}").get(get_agent))
                .push(Router::with_path("{agent_principal_id}/pause").post(pause_agent))
                .push(Router::with_path("{agent_principal_id}/resume").post(resume_agent))
                .push(Router::with_path("{agent_principal_id}/deactivate").post(deactivate_agent))
                .push(Router::with_path("{agent_principal_id}/rotate-key").post(rotate_agent_key))
                .push(
                    Router::with_path("{agent_principal_id}/grants")
                        .post(attach_agent_grant)
                        .push(Router::with_path("{grant_id}").delete(detach_agent_grant)),
                )
                .push(
                    Router::with_path("{agent_principal_id}/participation")
                        .get(get_agent_participation)
                        .put(set_agent_participation),
                ),
        )
        .push(
            Router::with_path("agent-sidecar-threads:ensure").post(ensure_sidecar_thread_canonical),
        )
}

/// `/_arkret/gate/account/agent-key-pair` lives under the auth router, not
/// `/_arkret/self/agents`. Registered separately in `routing::identity::auth`.
pub(crate) fn agent_key_pair_router() -> Router {
    Router::with_path("agent-key-pair").post(agent_key_pair)
}

/// Mounted under `/_arkret/open`.
pub(crate) fn open_router() -> Router {
    Router::with_path("agent-pairing")
        .push(Router::with_path("resolve").post(resolve_agent_pairing))
        .push(Router::with_path("runtime-key-requests").post(submit_agent_runtime_key_request))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(actor: &str) -> SessionRecord {
        SessionRecord {
            token_hash: format!("test-session:{actor}"),
            actor: actor.to_owned(),
            device_id: "test-device".to_owned(),
            audience: "did:web:soland.test".to_owned(),
            session_public_key: None,
            agent_session: None,
            expires_at: now() + chrono::Duration::minutes(5),
            created_at: now(),
            revoked_at: None,
        }
    }

    fn agent_record(agent_principal_id: &str, controller_did: &str) -> Value {
        json!({
            "agent_principal_id": agent_principal_id,
            "controller_did": controller_did,
            "agent_id": agent_principal_id,
            "display_name": "Test Agent",
            "state": "active",
        })
    }

    fn pending_pairing_record(
        agent_principal_id: &str,
        controller_did: &str,
        requested_scope: Value,
        pairing_code: &str,
        pairing_expires_at: &str,
    ) -> Value {
        json!({
            "agent_principal_id": agent_principal_id,
            "controller_did": controller_did,
            "agent_id": agent_principal_id,
            "display_name": "Test Agent",
            "state": "pending_runtime_key",
            "requested_scope": requested_scope,
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "pairing_code": pairing_code,
            "pairing_expires_at": pairing_expires_at,
        })
    }

    fn requested_agent_scope() -> Value {
        json!({
            "actions": [
                "ak.self.events.stream.subscribe",
                "ak.self.events.query.scan",
                "ak.self.events.command.submit",
                "ak.event.read",
                "ak.message.create"
            ],
            "resources": [{ "kind": "service", "service_did": "did:web:soland.local" }]
        })
    }

    fn key_authorize_envelope(
        record: &Value,
        controller: &str,
        agent_principal_id: &str,
        verification_method: &str,
        public_key_digest: &str,
        service_did: &str,
        scope: Value,
    ) -> Value {
        let request_canonical_digest = pairing_request_binding_digest(
            record,
            controller,
            agent_principal_id,
            verification_method,
            public_key_digest,
            service_did,
        )
        .expect("pairing binding digest");
        json!({
            "kind": "ak.agent.key.authorize",
            "actor_id": controller,
            "payload": {
                "agent_principal_id": agent_principal_id,
                "key_id": "ak:agent_key:01999999000070008000000000000001",
                "verification_method": verification_method,
                "public_key_digest": public_key_digest,
                "accountable_principal_id": controller,
                "agent_key_scope": scope,
                "audience": [service_did],
                "issued_at": "2026-07-06T00:00:00Z",
                "expires_at": "2999-01-01T00:00:00Z",
                "approval_evidence": {
                    "kind": "approval_event",
                    "ref": "ak:event:01999999-0000-7000-8000-000000000001",
                    "request_canonical_digest": request_canonical_digest,
                    "approved_by": controller,
                },
            },
        })
    }

    fn key_pair_request_body(
        agent: &str,
        verification_method: &str,
        service_did: &str,
    ) -> AgentKeyPairRequestBody {
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let public_key = json!({
            "kty": "OKP",
            "kid": verification_method,
            "alg": "Ed25519",
            "key": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing_key.verifying_key().as_bytes()),
        });
        let agent_id = Did::new(agent.to_owned()).expect("agent did");
        let pairing_request_id = "agent_pairing_request:01999999-0000-7000-8000-00000000feed";
        let request_digest = arkret_sdk::agent_key_pair_proof_request_binding_digest(
            pairing_request_id,
            &agent_id,
            verification_method,
            &public_key,
            None,
        )
        .expect("pop digest");
        let expires_at = chrono::DateTime::parse_from_rfc3339("2999-01-01T00:00:00.000Z")
            .expect("fixed future expiry")
            .with_timezone(&chrono::Utc);
        let signing_input = arkret_sdk::agent::agent_key_pair_proof_signing_input(
            verification_method.to_owned(),
            pairing_request_id,
            service_did.to_owned(),
            expires_at,
            request_digest.clone(),
        );
        let signature = signing_key.sign(
            &signing_input
                .canonical_bytes()
                .expect("pop signing canonical bytes"),
        );
        AgentKeyPairRequestBody {
            pairing_request_id: pairing_request_id.to_owned(),
            agent_principal_id: agent_id,
            verification_method: verification_method.to_owned(),
            public_key,
            proof_of_possession: json!({
                "challenge": pairing_request_id,
                "audience": service_did,
                "request_canonical_digest": request_digest.as_str(),
                "expires_at": expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "signature": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(signature.to_bytes()),
            }),
            runtime_attestation: None,
            authorize_event: Value::Null,
        }
    }

    #[test]
    fn agent_principal_id_is_did_not_typed_id() {
        validate_agent_principal_id("did:web:agent.example").expect("DID-as-id must be accepted");
        assert!(
            validate_agent_principal_id("ak:agent_principal:01999999-0000-7000-8000-00000000a001")
                .is_err()
        );
    }

    #[test]
    fn verification_method_principal_strips_query_and_fragment() {
        assert_eq!(
            verification_method_principal("did:web:agent.example?versionId=1#key-1"),
            "did:web:agent.example"
        );
    }

    #[test]
    fn detach_revoke_only_targets_capability_grants() {
        assert!(is_capability_grant_id(
            "ak:grant:01999999-0000-7000-8000-000000000001"
        ));
        assert!(!is_capability_grant_id(
            "ak:accountability_grant:01999999-0000-7000-8000-000000000001"
        ));
    }

    #[test]
    fn agent_view_projects_spec_shape_dropping_internal_columns() {
        let view = agent_view_from_record(&json!({
            "agent_principal_id": "did:webvh:z6mkfixture:agent.example",
            "controller_did": "did:webvh:example.com:users:alice",
            "agent_id": "did:webvh:z6mkfixture:agent.example",
            "display_name": "Summary Assistant",
            "agent_slug": "summary",
            "state": "active",
            "created_at": "2026-06-11T00:00:00.000Z",
            "updated_at": "2026-06-11T00:00:00.000Z"
        }));
        // spec `agent_view` = `{agent: <agent_projection>, status, ...}`.
        assert_eq!(view.status, "active");
        let agent = serde_json::to_value(&view).expect("view serializes");
        assert_eq!(agent["agent"]["agent_slug"], "summary");
        assert_eq!(agent["agent"]["status"], "active");
        assert_eq!(
            agent["agent"]["agent_principal_id"],
            "did:webvh:z6mkfixture:agent.example"
        );
        // soland-internal columns MUST NOT leak into the protocol projection.
        assert!(agent["agent"].get("controller_did").is_none());
        assert!(agent["agent"].get("agent_id").is_none());
    }

    #[test]
    fn selector_slug_reservation_ignores_expired_and_terminal_agents() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-07T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut active = agent_record("did:web:agent.example", "did:web:controller.example");
        active["state"] = json!("active");
        assert!(agent_record_reserves_selector_slug(&active, &now));

        let mut paused = active.clone();
        paused["state"] = json!("paused");
        assert!(agent_record_reserves_selector_slug(&paused, &now));

        let pending_future = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2026-07-08T00:00:00Z",
        );
        assert!(agent_record_reserves_selector_slug(&pending_future, &now));

        let pending_expired = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2026-07-06T00:00:00Z",
        );
        assert!(!agent_record_reserves_selector_slug(&pending_expired, &now));

        let mut pairing_expired = active.clone();
        pairing_expired["state"] = json!("pairing_expired");
        assert!(!agent_record_reserves_selector_slug(&pairing_expired, &now));

        let mut deactivated = active;
        deactivated["state"] = json!("deactivated");
        assert!(!agent_record_reserves_selector_slug(&deactivated, &now));
    }

    #[test]
    fn agent_pairing_token_decodes_compact_request_and_code() {
        let token = URL_SAFE_NO_PAD.encode(br#"{"r":"agent_pairing_request:0193","c":"12345678"}"#);

        assert!(is_agent_pairing_token_shape(&token));
        let decoded = decode_agent_pairing_token(&token).expect("decode token");

        assert_eq!(decoded["r"], json!("agent_pairing_request:0193"));
        assert_eq!(decoded["c"], json!("12345678"));
    }

    #[test]
    fn resume_sidecar_exposure_ack_is_validated_and_normalized() {
        let ack = normalize_sidecar_exposure_ack(
            Some(json!({
                "acknowledged_at": "2026-06-18T12:00:00Z",
                "acknowledged_by": "did:web:controller.example",
                "sidecar_refs": [
                    "ak:circle:01964137-0000-7000-8000-000000000020",
                    "ak:strand:01964137-0000-7000-8000-000000000021"
                ]
            })),
            "did:web:controller.example",
        )
        .expect("valid sidecar exposure ack should normalize")
        .expect("ack should be present");

        assert_eq!(ack["acknowledged_by"], "did:web:controller.example");
        assert_eq!(ack["sidecar_refs"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn resume_sidecar_exposure_ack_rejects_wrong_controller() {
        let err = normalize_sidecar_exposure_ack(
            Some(json!({
                "acknowledged_at": "2026-06-18T12:00:00Z",
                "acknowledged_by": "did:web:other.example",
                "sidecar_refs": ["ak:circle:01964137-0000-7000-8000-000000000020"]
            })),
            "did:web:controller.example",
        )
        .expect_err("ack by another controller must reject");

        assert_eq!(err.wire_code(), "capability_denied");
    }

    #[test]
    fn controller_binding_accepts_agent_controller() {
        let session = test_session("did:web:controller.example");
        let record = agent_record("did:web:agent.example", "did:web:controller.example");

        ensure_agent_record_controller(&record, "did:web:agent.example", &session)
            .expect("controller session must operate its agent");
    }

    #[test]
    fn controller_binding_rejects_non_controller() {
        let session = test_session("did:web:mallory.example");
        let record = agent_record("did:web:agent.example", "did:web:controller.example");

        let err = ensure_agent_record_controller(&record, "did:web:agent.example", &session)
            .expect_err("non-controller session must be rejected");

        assert_eq!(err.wire_code(), "capability_denied");
    }

    #[test]
    fn key_authorize_event_binds_pairing_transcript_and_scope() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00Z",
        );
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_did,
            scope,
        );

        ensure_pairing_request_open(&record).expect("pending pairing should be open");
        ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            public_key_digest,
            service_did,
        )
        .expect("matching authorize_event should pass");
    }

    #[test]
    fn key_pair_proof_of_possession_verifies_runtime_key() {
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let body = key_pair_request_body(agent, verification_method, service_did);

        verify_runtime_key_pair_proof_of_possession(&body, agent, service_did)
            .expect("runtime PoP must verify");
    }

    #[test]
    fn runtime_approval_request_for_controller_omits_pairing_code() {
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let key_pair = key_pair_request_body(agent, verification_method, service_did);
        let request = AgentRuntimeApprovalRequestBody {
            pairing_code: "12345678".to_owned(),
            pairing_request_id: key_pair.pairing_request_id.clone(),
            agent_principal_id: key_pair.agent_principal_id.clone(),
            verification_method: key_pair.verification_method.clone(),
            public_key: key_pair.public_key.clone(),
            proof_of_possession: key_pair.proof_of_possession.clone(),
            runtime_attestation: None,
        };

        let controller_request = runtime_key_request_for_controller(&request);

        assert!(controller_request.get("pairing_code").is_none());
        assert_eq!(
            controller_request["pairing_request_id"],
            key_pair.pairing_request_id
        );
        assert_eq!(
            controller_request["verification_method"],
            verification_method
        );
    }

    #[test]
    fn agent_key_state_projects_pending_runtime_approval() {
        let mut record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2999-01-01T00:00:00Z",
        );
        record["approval_request_id"] = json!("agent_runtime_approval:01999999");
        record["approval_requested_at"] = json!("2026-07-08T00:00:00.000Z");
        record["runtime_key_request"] = json!({
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "agent_principal_id": "did:web:agent.example",
            "verification_method": "did:web:agent.example#runtime-key-1",
            "public_key": {
                "kty": "OKP",
                "kid": "did:web:agent.example#runtime-key-1",
                "alg": "Ed25519",
                "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            },
            "proof_of_possession": { "challenge": "agent_pairing_request:01999999-0000-7000-8000-00000000feed" }
        });

        let key_state = agent_key_state_from_record(&record);

        assert_eq!(
            key_state["approval_request_id"],
            "agent_runtime_approval:01999999"
        );
        assert_eq!(
            key_state["pending_runtime_key_request"]["verification_method"],
            "did:web:agent.example#runtime-key-1"
        );
        assert_eq!(
            key_state["approval_requested_at"],
            "2026-07-08T00:00:00.000Z"
        );
    }

    #[test]
    fn key_pair_rejects_wrong_pairing_request_id() {
        let record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2999-01-01T00:00:00Z",
        );

        let err = ensure_pairing_request_id_matches(
            &record,
            "agent_pairing_request:01999999-0000-7000-8000-00000000bad1",
        )
        .expect_err("wrong pairing request must fail closed");

        assert_eq!(err.wire_code(), "failed_precondition");
    }

    #[test]
    fn key_authorize_event_rejects_wrong_pairing_code_digest() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00Z",
        );
        let mut mismatched_record = record.clone();
        mismatched_record["pairing_code"] = json!("87654321");
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_did,
            scope,
        );

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &mismatched_record,
            agent,
            verification_method,
            public_key_digest,
            service_did,
        )
        .expect_err("wrong pairing code must change the expected digest");

        assert_eq!(err.wire_code(), "invalid_param");
        assert!(err.message.contains("request_canonical_digest"));
    }

    #[test]
    fn key_authorize_event_rejects_wrong_controller_actor() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00Z",
        );
        let envelope = key_authorize_envelope(
            &record,
            "did:web:mallory.example",
            agent,
            verification_method,
            public_key_digest,
            service_did,
            scope,
        );

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            public_key_digest,
            service_did,
        )
        .expect_err("authorize_event actor must match authenticated controller");

        assert_eq!(err.wire_code(), "capability_denied");
        assert!(err.message.contains("actor_id"));
    }

    #[test]
    fn key_authorize_event_rejects_expired_pairing() {
        let record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2000-01-01T00:00:00Z",
        );

        let err = ensure_pairing_request_open(&record)
            .expect_err("expired pairing request must fail closed");

        assert_eq!(err.wire_code(), "failed_precondition");
        assert_eq!(
            err.reason_detail.as_deref(),
            Some("pairing request has expired")
        );
    }

    #[test]
    fn key_authorize_event_rejects_scope_mismatch() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let expected_scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            expected_scope,
            "12345678",
            "2999-01-01T00:00:00Z",
        );
        let weaker_scope = json!({
            "actions": ["ak.self.events.stream.subscribe"],
            "resources": [{ "kind": "service", "service_did": service_did }]
        });
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_did,
            weaker_scope,
        );

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            public_key_digest,
            service_did,
        )
        .expect_err("agent_key_scope must match provisioned requested_scope");

        assert_eq!(err.wire_code(), "invalid_param");
        assert!(err.message.contains("agent_key_scope"));
    }

    #[test]
    fn key_authorize_event_rejects_wrong_runtime_public_key_digest() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00Z",
        );
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_did,
            scope,
        );

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            service_did,
        )
        .expect_err("authorize_event public key digest must bind request public_key");

        assert_eq!(err.wire_code(), "invalid_param");
        assert!(err.message.contains("public_key_digest"));
    }

    #[test]
    fn sidecar_request_rejects_body_controller_mismatch() {
        let session = test_session("did:web:controller.example");
        let body = AgentSidecarThreadEnsureRequestBody {
            controller_principal_id: Did::new("did:web:mallory.example").expect("controller did"),
            addressed_agent_principal_ids: Vec::new(),
            context_ref: AgentSidecarContextRef::strand(
                RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000001").expect("realm id"),
                StrandId::new("ak:strand:0196419b-0000-7000-8000-000000000002").expect("strand id"),
            ),
        };

        let err = ensure_sidecar_controller_request(&body, &session)
            .expect_err("sidecar body controller must match session actor");

        assert_eq!(err.wire_code(), SIDECAR_CREATE_DENIED);
    }

    #[test]
    fn sidecar_context_ref_requires_strand_or_relation() {
        let context_ref = AgentSidecarContextRef {
            realm_id: RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030").unwrap(),
            strand_id: None,
            track_name: None,
            message_id: None,
            relation_id: None,
        };
        let err = normalize_sidecar_context_ref(&context_ref)
            .expect_err("context_ref without a target must reject");
        assert_eq!(err.wire_code(), "invalid_param");
    }

    #[test]
    fn sidecar_addressed_agents_rejects_controller() {
        let controller = Did::new("did:web:example.com:users:alice").unwrap();
        let body = AgentSidecarThreadEnsureRequestBody {
            controller_principal_id: controller.clone(),
            addressed_agent_principal_ids: vec![controller.clone()],
            context_ref: AgentSidecarContextRef::strand(
                RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030").unwrap(),
                StrandId::new("ak:strand:01964137-0000-7000-8000-000000000031").unwrap(),
            ),
        };
        let err = normalize_addressed_agents(controller.as_str(), &body)
            .expect_err("controller must not be addressable as an agent");
        assert_eq!(err.wire_code(), CONTROLLER_IN_ADDRESSED_AGENTS);
    }
}
