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
//! - `POST   /_arkret/self/agents/{id}/grants`                 —
//!   `ak.self.agent.grant.command.attach`
//! - `DELETE /_arkret/self/agents/{id}/grants/{grant_id}`      —
//!   `ak.self.agent.grant.resource.delete`
//! - `POST   /_arkret/self/agent-sidecars:ensure`              —
//!   `ak.self.agent.sidecar.command.ensure`
//! - `GET    /_arkret/self/agent-sidecars[/{sidecar_id}]`      — dedicated reads
//!
//! Controller operations enforce the persisted `agent_principals.controller_id`
//! binding before they mutate state or emit fan-out. Each handler appends an
//! audit-log row matching the canonical event-kind name so the existing admin /
//! federation projections stay in sync ahead of the reducer rewrite.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::Operation;
use arkret_identifiers::{
    BlobRef, CircleId, Did, EventId, GrantId, Hash, OperationId, RealmId, RelationId, StrandId,
};
use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentGrantAttachOutcome, AgentGrantAttachRequestBody,
    AgentGrantDetachOutcome, AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentLifecycleOutcome,
    AgentLifecycleState, AgentList, AgentPairingBootstrap, AgentPairingMode,
    AgentPairingResolveRequestBody, AgentPauseRequestBody, AgentProjection, AgentProvisionOutcome,
    AgentProvisionPcrRecovery, AgentProvisionRequestBody, AgentRenewPairingOutcome,
    AgentRenewPairingRequestBody, AgentResumeRequestBody, AgentRuntimeApprovalOutcome,
    AgentRuntimeApprovalRequestBody, AgentRuntimeApprovalStatusOutcome,
    AgentRuntimeApprovalStatusRequestBody, AgentRuntimeState, AgentView, KeyState,
};
#[cfg(test)]
use arkret_models_collaboration::agent_operations::{
    AgentSidecarContextRef, AgentSidecarEnsureRequestBody,
};
use arkret_models_collaboration::events_payloads::agent::{AgentKeyScope, AgentSidecarExposureAck};
use arkret_models_collaboration::governance::agent_artifacts::{GrantSnapshot, PublicKey};
use arkret_models_collaboration::governance::agent_participation::{
    AgentParticipation, AgentParticipationEntry, AgentParticipationOutcome,
    AgentParticipationReplaceRequestBody, AgentParticipationScope, effective_participation,
    validate_selection_within_ceiling,
};
use arkret_models_identity::validate_agent_slug;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Verifier as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_http::util::bearer_token;
use soland_services::identity::{
    AgentPairingState as AgentPrincipalRecord, SessionIdentityState as SessionRecord,
};
use subtle::ConstantTimeEq as _;

use super::{AuthArgs, append_audit_log, now, validate_did};
use crate::ids;
use crate::routing::accept_local_operations;
use crate::state::AppState;

mod dev_fanout;
use dev_fanout::{
    attach_agent_grant_event, fanout_provision_subevents,
    require_controller_principal_control_realm, revoke_capability_grant,
    submit_durable_agent_lifecycle, submit_signed_agent_event, validate_durable_agent_lifecycle,
};

mod common;
pub(crate) use common::agent_grant_within_requested_scope;
pub(crate) mod evidence;
mod lifecycle;
mod pairing;
mod participation;
pub(crate) mod sidecar;

use common::*;
use lifecycle::*;
use pairing::*;
use participation::*;
use sidecar::*;

fn agent_projection_service_authorized(state: &AppState, req: &Request) -> bool {
    let Some(expected) = state.config().session_grant_introspection_bearer.as_deref() else {
        return false;
    };
    let Some(presented) = bearer_token(req) else {
        return false;
    };
    expected.len() == presented.len() && bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
}

/// Mounted under `/_arkret/self`.
pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("agents")
                .post(provision_agent)
                .get(list_agents)
                .push(Router::with_path("{agent_id}").get(get_agent))
                .push(Router::with_path("{agent_id}/renew-pairing").post(renew_agent_pairing))
                .push(Router::with_path("{agent_id}/pause").post(pause_agent))
                .push(Router::with_path("{agent_id}/resume").post(resume_agent))
                .push(Router::with_path("{agent_id}/deactivate").post(deactivate_agent))
                .push(
                    Router::with_path("{agent_id}/grants")
                        .post(attach_agent_grant)
                        .push(Router::with_path("{grant_id}").delete(detach_agent_grant)),
                )
                .push(
                    Router::with_path("{agent_id}/participation")
                        .get(get_agent_participation)
                        .put(set_agent_participation),
                ),
        )
        .push(
            Router::with_path("agent-signer-evidence/query")
                .post(evidence::query_agent_signer_evidence),
        )
        .push(Router::with_path("agent-sidecars:ensure").post(ensure_sidecar))
        .push(
            Router::with_path("agent-sidecars")
                .get(list_sidecars)
                .push(Router::with_path("{sidecar_id}").get(get_sidecar)),
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
        .push(
            Router::with_path("runtime-key-requests/status").post(agent_runtime_key_request_status),
        )
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

    fn agent_record(agent_id: &str, controller_id: &str) -> AgentPrincipalRecord {
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-06-11T00:00:00.000Z")
            .expect("fixture timestamp")
            .with_timezone(&chrono::Utc);
        let mut record = AgentPrincipalRecord::new(
            agent_id.to_owned(),
            controller_id.to_owned(),
            "ak:realm:01999999-0000-7000-8000-00000000feed".to_owned(),
            arkret_wire::DidUrl::new(format!("{agent_id}#managed-controller")).unwrap(),
            AgentLifecycleState::Active,
            created_at,
        );
        record.display_name = Some("Test Agent".to_owned());
        record
    }

    fn pending_pairing_record(
        agent_id: &str,
        controller_id: &str,
        requested_scope: Value,
        pairing_code: &str,
        pairing_expires_at: &str,
    ) -> AgentPrincipalRecord {
        let mut record = agent_record(agent_id, controller_id);
        // Lifecycle intent is active from provisioning; the open bootstrap
        // handle drives runtime_state to pending_runtime_key (key-management.md
        // §3.6.1).
        record.state = AgentLifecycleState::Active;
        record.requested_scope = Some(requested_scope);
        record.pairing_request_id = Some(
            arkret_wire::OpaqueLocalId::new(
                "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            )
            .unwrap(),
        );
        record.pairing_code = Some(pairing_code.to_owned());
        record.pairing_expires_at = Some(
            chrono::DateTime::parse_from_rfc3339(pairing_expires_at)
                .expect("fixture pairing expiry")
                .with_timezone(&chrono::Utc),
        );
        record
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
            "resources": [
                {
                    "kind": "realm",
                    "realm_id": "ak:realm:01999999-0000-7000-8000-000000000099"
                },
                { "kind": "service", "service_id": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service" }
            ]
        })
    }

    fn initial_submission(event: arkret_wire::Event) -> arkret_wire::EventInitialSubmission {
        use arkret_wire::{
            AUTHORITY_SET_POLICY_SCHEMA, AuthoritySetAuthorizationRule, AuthoritySetIssuer,
            AuthoritySetIssuerRole, AuthoritySetPolicy, AuthoritySetPolicyKind,
            AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind, AuthorizationLease,
            AuthorizationLeaseId, DeviceId, DidUrl, LeaseBasisRef, RiskTier, SealId,
        };

        let policy = AuthoritySetPolicy {
            schema: AUTHORITY_SET_POLICY_SCHEMA.to_owned(),
            authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
            policy_kind: AuthoritySetPolicyKind::RealmAdmission,
            scope_ref: event.scope_ref.clone(),
            source: AuthoritySetPolicySource {
                source_kind: AuthoritySetSourceKind::RealmControl,
                source_ref: event.event_id.as_str().to_owned(),
                source_digest: arkret_wire::Hash::new(format!("sha256:{}", "e".repeat(64)))
                    .unwrap(),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: vec![AuthoritySetAuthorizationRule {
                rule_id: "realm_admission".to_owned(),
                issuer_role: AuthoritySetIssuerRole::RealmAdmission,
                allowed_actions: vec![event.kind.as_str().to_owned()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: DidUrl::new("did:web:controller.example#key-1").unwrap(),
                }],
                threshold: 1,
            }],
        };
        let issued_at = event.created_at;
        arkret_wire::EventInitialSubmission {
            authorization_lease: AuthorizationLease {
                authorization_lease_id: AuthorizationLeaseId::new(
                    "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
                )
                .unwrap(),
                basis_ref: LeaseBasisRef::Seal(
                    SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
                ),
                actor_id: event.actor_id.clone(),
                device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap(),
                scope_ref: event.scope_ref.clone(),
                action: event.kind.as_str().to_owned(),
                authorization_rule_id: "realm_admission".to_owned(),
                risk_tier: RiskTier::Low,
                issued_at,
                expires_at: issued_at + chrono::Duration::hours(1),
                authority_set_ref: AuthoritySetRef {
                    authority_set_id: policy.authority_set_id.clone(),
                    authority_set_digest: policy.digest().unwrap(),
                },
                authority_set_policy: policy,
                proofs: Vec::new(),
            },
            event,
            cba_proof_bundles: Vec::new(),
            control_proposal_receipt: None,
        }
    }

    fn key_authorize_envelope(
        record: &AgentPrincipalRecord,
        controller: &str,
        agent_id: &str,
        verification_method: &str,
        public_key_digest: &str,
        service_id: &str,
        scope: Value,
    ) -> Value {
        let request_canonical_digest = pairing_request_binding_digest(
            record,
            controller,
            agent_id,
            verification_method,
            public_key_digest,
            service_id,
        )
        .expect("pairing binding digest");
        json!({
            "event_id": "ak:event:01999999-0000-7000-8000-000000000001",
            "kind": "ak.agent.key.authorize",
            "actor_id": agent_id,
            "executed_by": controller,
            "authorization_ref": record.controller_authorization_ref.as_str(),
            "realm_id": record.principal_control_realm_id.as_str(),
            "payload": {
                "agent_id": agent_id,
                "key_id": "ak:agent_key:01999999000070008000000000000001",
                "verification_method": verification_method,
                "public_key_digest": public_key_digest,
                "accountable_principal_id": controller,
                "agent_key_scope": scope,
                "audience": [service_id],
                "issued_at": "2026-07-06T00:00:00.000Z",
                "expires_at": "2999-01-01T00:00:00.000Z",
                "approval_evidence": {
                    "kind": "pairing_request",
                    "request_canonical_digest": request_canonical_digest,
                    "pairing_request_id": record.pairing_request_id.as_deref(),
                    "approved_by": controller,
                },
            },
        })
    }

    fn key_pair_request_body(
        agent: &str,
        verification_method: &str,
        service_id: &str,
    ) -> AgentKeyPairRequestBody {
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let encoded_public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signing_key.verifying_key().as_bytes());
        let public_key_value = json!({
            "kty": "OKP",
            "kid": verification_method,
            "alg": "Ed25519",
            "key": encoded_public_key.clone(),
        });
        let public_key = PublicKey {
            kty: arkret_wire::NonEmptyString::new("OKP").unwrap(),
            kid: arkret_wire::NonEmptyString::new(verification_method).unwrap(),
            alg: arkret_wire::NonEmptyString::new("Ed25519").unwrap(),
            key: arkret_wire::Base64UrlString::new(encoded_public_key).unwrap(),
            key_digest: None,
        };
        let agent_id = Did::new(agent.to_owned()).expect("agent did");
        let pairing_request_id = "agent_pairing_request:01999999-0000-7000-8000-00000000feed";
        let request_digest = arkret_signatures::agent::agent_key_pair_proof_request_binding_digest(
            pairing_request_id,
            &agent_id,
            verification_method,
            &public_key_value,
            None,
        )
        .expect("pop digest");
        let expires_at = chrono::DateTime::parse_from_rfc3339("2999-01-01T00:00:00.000Z")
            .expect("fixed future expiry")
            .with_timezone(&chrono::Utc);
        let signing_input = arkret_signatures::agent::agent_key_pair_proof_signing_input(
            arkret_wire::DidUrl::new(verification_method).expect("fixture DID URL"),
            pairing_request_id,
            service_id.to_owned(),
            expires_at,
            request_digest.clone(),
        );
        let signature = signing_key.sign(
            &signing_input
                .canonical_bytes()
                .expect("pop signing canonical bytes"),
        );
        let controller_id = Did::new("did:web:controller.example".to_owned()).unwrap();
        let requested_scope: AgentKeyScope =
            serde_json::from_value(requested_agent_scope()).unwrap();
        let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
            &agent_id,
            &controller_id,
            &requested_scope,
        )
        .unwrap();
        let requested_scope_disclosure = serde_json::from_value(json!({
            "schema": "ak.schema.agent_requested_scope_disclosure.v1",
            "request_id": "ak:request:01999999-0000-7000-8000-000000000099",
            "agent_id": agent_id.as_str(),
            "controller_id": controller_id.as_str(),
            "requested_scope": requested_scope,
            "requested_scope_digest": requested_scope_digest.as_str(),
            "verifier_did": service_id,
            "audience": "ak.gate.account.command.pair_agent_key",
            "challenge": "pairing-challenge-0001",
            "issued_at": "2026-07-06T00:00:00.000Z",
            "expires_at": "2026-07-06T00:05:00.000Z",
            "proofs": [{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:web:controller.example#key-1",
                "event_digest": format!("sha256:{}", "0".repeat(64)),
                "created_at": "2026-07-06T00:00:00.000Z",
                "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
            }]
        }))
        .unwrap();
        let authorize_event = arkret_wire::Event::new(
            "ak.agent.key.authorize",
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_identifiers::RealmId::new(
                    "ak:realm:01999999-0000-7000-8000-00000000feed",
                )
                .unwrap(),
            },
            arkret_identifiers::Did::new("did:web:agent.example").unwrap(),
            1,
            arkret_identifiers::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({}),
        )
        .unwrap();
        let authorize_event_id = authorize_event.event_id.clone();
        let authorize_event = initial_submission(authorize_event);
        let public_key_digest =
            arkret_signatures::agent::agent_runtime_public_key_digest(&public_key_value).unwrap();
        let signing_key_binding = serde_json::from_value(json!({
            "schema": "ak.schema.agent_signing_key_binding.v1",
            "agent_id": agent_id,
            "agent_key_id": "ak:agent_key:01999999000070008000000000000001",
            "verification_method": verification_method,
            "public_key": {
                "kty": "OKP",
                "alg": "Ed25519",
                "key": public_key.key
            },
            "public_key_digest": public_key_digest,
            "agent_key_authorize_event_id": authorize_event_id,
            "issued_at": "2026-07-06T00:00:00.000Z",
            "controller_id": controller_id,
            "controller_proof": {
                "kind": "detached_jws",
                "verification_method": "did:web:controller.example#key-1",
                "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
            }
        }))
        .unwrap();
        AgentKeyPairRequestBody {
            pairing_request_id: arkret_wire::OpaqueLocalId::new(pairing_request_id).unwrap(),
            agent_id,
            verification_method: arkret_wire::DidUrl::new(verification_method).unwrap(),
            public_key,
            proof_of_possession: arkret_wire::wire_strings::NonEmptyJsonObject::new(
                std::collections::BTreeMap::from([
                    ("challenge".to_owned(), json!(pairing_request_id)),
                    ("audience".to_owned(), json!(service_id)),
                    (
                        "request_canonical_digest".to_owned(),
                        json!(request_digest.as_str()),
                    ),
                    (
                        "expires_at".to_owned(),
                        json!(arkret_canonical::format_timestamp_canonical(expires_at)),
                    ),
                    (
                        "signature".to_owned(),
                        json!(
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .encode(signature.to_bytes())
                        ),
                    ),
                ]),
            )
            .unwrap(),
            requested_scope_disclosure,
            runtime_attestation: None,
            authorize_event,
            signing_key_binding,
        }
    }

    #[test]
    fn agent_id_is_did_not_typed_id() {
        validate_agent_id("did:web:agent.example").expect("DID-as-id must be accepted");
        assert!(
            validate_agent_id("ak:agent_principal:01999999-0000-7000-8000-00000000a001").is_err()
        );
    }

    #[test]
    fn verification_method_principal_strips_query_and_fragment() {
        assert_eq!(
            verification_method_principal("did:web:agent.example?versionId=1#key-1"),
            "did:web:agent.example"
        );
    }

    fn bind_pairing_request_to_controller_device(
        body: &mut AgentKeyPairRequestBody,
        controller_id: &str,
    ) {
        let device_id = body.authorize_event.authorization_lease.device_id.as_str();
        let mut proof = body.requested_scope_disclosure.proofs[0].clone();
        proof.verification_method =
            arkret_wire::DidUrl::new(format!("{controller_id}#{device_id}")).unwrap();
        body.authorize_event.event.executed_by =
            Some(Did::new(controller_id.to_owned()).expect("controller DID"));
        body.authorize_event.event.proofs = vec![proof];
    }

    #[test]
    fn service_pairing_preserves_the_controller_device_bound_by_the_signed_submission() {
        let controller_id = "did:web:controller.example";
        let mut body = key_pair_request_body(
            "did:web:agent.example",
            "did:web:agent.example#runtime-key",
            "did:web:soland.example",
        );
        bind_pairing_request_to_controller_device(&mut body, controller_id);

        let device_id = service_pairing_controller_device_id(&body, controller_id)
            .expect("signed submission binds the service session device");

        assert_eq!(
            device_id,
            body.authorize_event.authorization_lease.device_id.as_str()
        );
    }

    #[test]
    fn service_pairing_rejects_a_proof_from_a_different_controller_device() {
        let controller_id = "did:web:controller.example";
        let mut body = key_pair_request_body(
            "did:web:agent.example",
            "did:web:agent.example#runtime-key",
            "did:web:soland.example",
        );
        bind_pairing_request_to_controller_device(&mut body, controller_id);
        body.authorize_event.event.proofs[0].verification_method = arkret_wire::DidUrl::new(
            format!("{controller_id}#ak:device:01904100-0000-7000-8000-000000000099"),
        )
        .unwrap();

        assert!(service_pairing_controller_device_id(&body, controller_id).is_err());
    }

    #[test]
    fn service_pairing_rejects_a_non_device_controller_proof() {
        let controller_id = "did:web:controller.example";
        let mut body = key_pair_request_body(
            "did:web:agent.example",
            "did:web:agent.example#runtime-key",
            "did:web:soland.example",
        );
        bind_pairing_request_to_controller_device(&mut body, controller_id);
        body.authorize_event.event.proofs[0].verification_method =
            arkret_wire::DidUrl::new(format!("{controller_id}#key-1")).unwrap();

        assert!(service_pairing_controller_device_id(&body, controller_id).is_err());
    }

    #[test]
    fn agent_view_projects_spec_shape_dropping_internal_columns() {
        let mut record = agent_record(
            "did:webvh:z6mkfixture:agent.example",
            "did:webvh:example.com:users:alice",
        );
        record.display_name = Some("Summary Assistant".to_owned());
        record.agent_slug = Some("summary".to_owned());
        let view = AgentView {
            agent: agent_projection_from_record(&record, AgentRuntimeState::Ready),
            status: AgentLifecycleState::Active,
            runtime_state: AgentRuntimeState::Ready,
            grants: Vec::new(),
            key_state: None,
        };
        // spec `agent_view` = `{agent: <agent_projection>, status, runtime_state, ...}`.
        assert_eq!(view.status, AgentLifecycleState::Active);
        assert_eq!(view.runtime_state, AgentRuntimeState::Ready);
        let agent = serde_json::to_value(&view).expect("view serializes");
        assert_eq!(agent["agent"]["slug"], "summary");
        assert_eq!(agent["agent"]["status"], "active");
        assert_eq!(agent["agent"]["runtime_state"], "ready");
        assert_eq!(
            agent["agent"]["agent_id"],
            "did:webvh:z6mkfixture:agent.example"
        );
        // soland-internal columns MUST NOT leak into the protocol projection.
        assert!(agent["agent"].get("controller_id").is_none());
    }

    #[test]
    fn selector_slug_reservation_ignores_expired_and_terminal_agents() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-07T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        // A keyed agent (authorized_event_ref set) reserves its slug for any
        // non-terminal lifecycle intent (key-management.md §3.6.1).
        let mut active = agent_record("did:web:agent.example", "did:web:controller.example");
        active.state = AgentLifecycleState::Active;
        active.authorized_event_ref =
            Some("ak:event:01964137-0000-7000-8000-000000000001".to_owned());
        assert!(agent_record_reserves_selector_slug(&active, &now));

        let mut paused = active.clone();
        paused.state = AgentLifecycleState::Paused;
        assert!(agent_record_reserves_selector_slug(&paused, &now));

        // A never-keyed agent reserves the slug only while its bootstrap handle
        // is still live.
        let pending_future = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2026-07-08T00:00:00.000Z",
        );
        assert!(agent_record_reserves_selector_slug(&pending_future, &now));

        let pending_expired = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2026-07-06T00:00:00.000Z",
        );
        assert!(!agent_record_reserves_selector_slug(&pending_expired, &now));

        // A never-keyed agent whose bootstrap window lapsed (active intent, no
        // key, no live handle) releases the slug for a fresh provision.
        let mut bootstrap_lapsed =
            agent_record("did:web:agent.example", "did:web:controller.example");
        bootstrap_lapsed.state = AgentLifecycleState::Active;
        assert!(!agent_record_reserves_selector_slug(
            &bootstrap_lapsed,
            &now
        ));

        // Deactivation is terminal.
        let mut deactivated = active;
        deactivated.state = AgentLifecycleState::Deactivated;
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
                "acknowledged_at": "2026-06-18T12:00:00.000Z",
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
                "acknowledged_at": "2026-06-18T12:00:00.000Z",
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
        let service_id =
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_id,
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
            service_id,
        )
        .expect("matching authorize_event should pass");
    }

    #[test]
    fn key_pair_proof_of_possession_verifies_runtime_key() {
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_id =
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
        let body = key_pair_request_body(agent, verification_method, service_id);

        verify_runtime_key_pair_proof_of_possession(&body, agent, service_id)
            .expect("runtime PoP must verify");
    }

    #[test]
    fn runtime_approval_request_for_controller_omits_pairing_code() {
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_id =
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
        let key_pair = key_pair_request_body(agent, verification_method, service_id);
        let request = AgentRuntimeApprovalRequestBody {
            pairing_code: arkret_wire::NonEmptyString::new("12345678").unwrap(),
            pairing_request_id: key_pair.pairing_request_id.clone(),
            agent_id: key_pair.agent_id.clone(),
            verification_method: key_pair.verification_method.clone(),
            public_key: key_pair.public_key.clone(),
            proof_of_possession: key_pair.proof_of_possession.clone(),
            runtime_attestation: None,
        };

        let controller_request = runtime_key_request_for_controller(&request);

        assert_eq!(
            controller_request.pairing_request_id,
            key_pair.pairing_request_id
        );
        assert_eq!(
            controller_request.verification_method.as_str(),
            verification_method,
        );
    }

    #[test]
    fn agent_key_state_projects_pending_runtime_approval() {
        let mut record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        record.approval_request_id =
            Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999").unwrap());
        record.approval_requested_at = Some(
            chrono::DateTime::parse_from_rfc3339("2026-07-08T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        record.runtime_key_request = Some(serde_json::from_value(json!({
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "agent_id": "did:web:agent.example",
            "verification_method": "did:web:agent.example#runtime-key-1",
            "public_key": {
                "kty": "OKP",
                "kid": "did:web:agent.example#runtime-key-1",
                "alg": "Ed25519",
                "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            },
            "proof_of_possession": { "challenge": "agent_pairing_request:01999999-0000-7000-8000-00000000feed" }
        }))
        .expect("valid controller runtime request"));

        let key_state = agent_key_state_from_record(
            &record,
            arkret_models_collaboration::agent_operations::AgentPcrRecoveryState::Pending,
            Vec::new(),
            AgentRuntimeState::PendingRuntimeKey,
        )
        .expect("key state projection");

        assert_eq!(
            key_state.approval_request_id.as_deref(),
            Some("agent_runtime_approval:01999999")
        );
        assert_eq!(
            key_state
                .pending_runtime_key_request
                .as_ref()
                .map(|request| request.verification_method.as_str()),
            Some("did:web:agent.example#runtime-key-1")
        );
        assert_eq!(
            key_state.approval_requested_at,
            record.approval_requested_at
        );
    }

    fn status_request_body(
        pairing_code: &str,
        agent_id: &str,
    ) -> AgentRuntimeApprovalStatusRequestBody {
        AgentRuntimeApprovalStatusRequestBody {
            pairing_request_id: arkret_wire::OpaqueLocalId::new(
                "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            )
            .unwrap(),
            pairing_code: pairing_code.to_owned(),
            agent_id: Did::new(agent_id.to_owned()).unwrap(),
        }
    }

    fn status_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-07-10T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn runtime_approval_status_reports_pending_request() {
        let mut record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        record.approval_request_id =
            Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999").unwrap());

        let outcome = agent_runtime_key_request_status_outcome(
            &record,
            &status_request_body("12345678", "did:web:agent.example"),
            status_now(),
        )
        .expect("pending status must resolve");

        assert_eq!(outcome.status, AgentLifecycleState::Active);
        assert_eq!(outcome.runtime_state, AgentRuntimeState::PendingRuntimeKey);
        assert_eq!(
            outcome.approval_request_id.as_deref(),
            Some("agent_runtime_approval:01999999")
        );
        assert!(outcome.authorized_event_ref.is_none());
        assert!(outcome.authorized_public_key_digest.is_none());
    }

    #[test]
    fn runtime_approval_status_reports_authorized_key_binding_after_approval() {
        let mut record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        record.state = AgentLifecycleState::Active;
        // Approval consumes the pairing handle (activation stamps
        // paired_pairing_request_id), so runtime_state derives to ready.
        record.paired_pairing_request_id = record.pairing_request_id.clone();
        let signing_key_binding = key_pair_request_body(
            "did:web:agent.example",
            "did:web:agent.example#runtime-1",
            "did:web:soland.example",
        )
        .signing_key_binding;
        record.authorized_event_ref =
            Some(signing_key_binding.agent_key_authorize_event_id.to_string());
        record.authorized_verification_method =
            Some(signing_key_binding.verification_method.to_string());
        record.authorized_public_key_digest =
            Some(signing_key_binding.public_key_digest.to_string());
        record.authorized_signing_key_binding = Some(signing_key_binding.clone());

        let outcome = agent_runtime_key_request_status_outcome(
            &record,
            &status_request_body("12345678", "did:web:agent.example"),
            status_now(),
        )
        .expect("approved status must resolve");

        assert_eq!(outcome.status, AgentLifecycleState::Active);
        assert_eq!(outcome.runtime_state, AgentRuntimeState::Ready);
        assert!(outcome.approval_request_id.is_none());
        assert_eq!(
            outcome.authorized_event_ref.as_ref().map(|id| id.as_str()),
            Some(signing_key_binding.agent_key_authorize_event_id.as_str())
        );
        assert_eq!(
            outcome.authorized_verification_method.as_deref(),
            Some("did:web:agent.example#runtime-1")
        );
        assert_eq!(
            outcome.authorized_public_key_digest.as_deref(),
            Some(signing_key_binding.public_key_digest.as_str())
        );
        assert_eq!(
            outcome.authorized_signing_key_binding,
            Some(signing_key_binding)
        );
    }

    #[test]
    fn runtime_approval_status_does_not_report_previous_binding_for_replacement() {
        let mut record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        record.state = AgentLifecycleState::Active;
        record.paired_pairing_request_id = Some(
            arkret_wire::OpaqueLocalId::new(
                "agent_pairing_request:01988888-0000-7000-8000-00000000feed",
            )
            .unwrap(),
        );
        let previous_binding = key_pair_request_body(
            "did:web:agent.example",
            "did:web:agent.example#runtime-1",
            "did:web:soland.example",
        )
        .signing_key_binding;
        record.authorized_event_ref =
            Some(previous_binding.agent_key_authorize_event_id.to_string());
        record.authorized_verification_method =
            Some(previous_binding.verification_method.to_string());
        record.authorized_public_key_digest = Some(previous_binding.public_key_digest.to_string());
        record.authorized_signing_key_binding = Some(previous_binding);

        let outcome = agent_runtime_key_request_status_outcome(
            &record,
            &status_request_body("12345678", "did:web:agent.example"),
            status_now(),
        )
        .expect("replacement status must resolve");

        assert_eq!(outcome.status, AgentLifecycleState::Active);
        assert_eq!(outcome.runtime_state, AgentRuntimeState::Replacing);
        assert!(outcome.authorized_event_ref.is_none());
        assert!(outcome.authorized_verification_method.is_none());
        assert!(outcome.authorized_public_key_digest.is_none());
        assert!(outcome.authorized_signing_key_binding.is_none());
    }

    #[test]
    fn runtime_approval_status_lazily_reports_expired_open_pairing() {
        let mut record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2026-07-09T00:00:00.000Z",
        );
        record.approval_request_id =
            Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999").unwrap());

        let outcome = agent_runtime_key_request_status_outcome(
            &record,
            &status_request_body("12345678", "did:web:agent.example"),
            status_now(),
        )
        .expect("expired status must resolve");

        assert_eq!(outcome.status, AgentLifecycleState::Active);
        assert_eq!(outcome.runtime_state, AgentRuntimeState::PairingExpired);
        assert!(outcome.approval_request_id.is_none());
        assert!(outcome.authorized_event_ref.is_none());
    }

    #[test]
    fn runtime_approval_status_mismatch_is_indistinguishable_from_missing_record() {
        let record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        let missing = agent_pairing_not_found();

        let wrong_code = agent_runtime_key_request_status_outcome(
            &record,
            &status_request_body("00000000", "did:web:agent.example"),
            status_now(),
        )
        .expect_err("wrong pairing code must fail closed");
        let wrong_principal = agent_runtime_key_request_status_outcome(
            &record,
            &status_request_body("12345678", "did:web:intruder.example"),
            status_now(),
        )
        .expect_err("wrong principal must fail closed");

        assert_eq!(wrong_code.wire_code(), missing.wire_code());
        assert_eq!(wrong_principal.wire_code(), missing.wire_code());
        assert_eq!(wrong_code.to_string(), missing.to_string());
        assert_eq!(wrong_principal.to_string(), missing.to_string());
    }

    #[test]
    fn key_pair_rejects_wrong_pairing_request_id() {
        let record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
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
        let service_id =
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        let mut mismatched_record = record.clone();
        mismatched_record.pairing_code = Some("87654321".to_owned());
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_id,
            scope,
        );

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &mismatched_record,
            agent,
            verification_method,
            public_key_digest,
            service_id,
        )
        .expect_err("wrong pairing code must change the expected digest");

        assert_eq!(err.wire_code(), "invalid_param");
        assert!(err.message.contains("request_canonical_digest"));
    }

    #[test]
    fn key_authorize_event_rejects_wrong_controller_executor() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_id =
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        let envelope = key_authorize_envelope(
            &record,
            "did:web:mallory.example",
            agent,
            verification_method,
            public_key_digest,
            service_id,
            scope,
        );

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            public_key_digest,
            service_id,
        )
        .expect_err("authorize_event executor must match authenticated controller");

        assert_eq!(err.wire_code(), "capability_denied");
        assert!(err.message.contains("executed_by"));
    }

    #[test]
    fn key_authorize_event_rejects_wrong_approval_principal() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_id =
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        let mut envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_id,
            scope,
        );
        envelope["payload"]["approval_evidence"]["approved_by"] = json!("did:web:mallory.example");

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            public_key_digest,
            service_id,
        )
        .expect_err("approval evidence must be issued by the authenticated controller");

        assert_eq!(err.wire_code(), "capability_denied");
        assert!(err.message.contains("approved_by"));
    }

    #[test]
    fn key_authorize_event_rejects_expired_pairing() {
        let record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2000-01-01T00:00:00.000Z",
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
    fn key_authorize_event_accepts_narrower_scope_and_rejects_widening() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_id =
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let expected_scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            expected_scope,
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        let weaker_scope = json!({
            "actions": ["ak.self.events.stream.subscribe"],
            "resources": [{ "kind": "service", "service_id": service_id }]
        });
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_id,
            weaker_scope,
        );

        ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            public_key_digest,
            service_id,
        )
        .expect("a narrower agent_key_scope must be accepted");

        let widened_scope = json!({
            "actions": ["ak.reaction.add"],
            "resources": [{ "kind": "service", "service_id": service_id }]
        });
        let widened_envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_id,
            widened_scope,
        );
        let err = ensure_key_authorize_event_matches_request(
            &widened_envelope,
            controller,
            &record,
            agent,
            verification_method,
            public_key_digest,
            service_id,
        )
        .expect_err("agent_key_scope must not exceed provisioned requested_scope");
        assert_eq!(err.wire_code(), "invalid_param");
        assert!(err.message.contains("agent_key_scope"));
    }

    #[test]
    fn key_authorize_event_rejects_wrong_runtime_public_key_digest() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_id =
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00.000Z",
        );
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_id,
            scope,
        );

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            service_id,
        )
        .expect_err("authorize_event public key digest must bind request public_key");

        assert_eq!(err.wire_code(), "invalid_param");
        assert!(err.message.contains("public_key_digest"));
    }

    #[test]
    fn sidecar_request_rejects_body_controller_mismatch() {
        let session = test_session("did:web:controller.example");
        let body = AgentSidecarEnsureRequestBody {
            controller_id: Did::new("did:web:mallory.example").expect("controller did"),
            addressed_agent_ids: Vec::new(),
            context_ref: AgentSidecarContextRef::strand(
                RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000001").expect("realm id"),
                StrandId::new("ak:strand:0196419b-0000-7000-8000-000000000002").expect("strand id"),
            ),
        };

        let err = ensure_sidecar_controller_request(&body, &session)
            .expect_err("sidecar body controller must match session actor");

        assert_eq!(
            err.wire_code(),
            arkret_wire::ReasonCode::SIDECAR_CREATE_DENIED
        );
    }

    #[test]
    fn sidecar_context_ref_requires_exactly_one_typed_target() {
        assert!(
            serde_json::from_value::<AgentSidecarContextRef>(serde_json::json!({
                "realm_id": "ak:realm:01964137-0000-7000-8000-000000000030"
            }))
            .is_err()
        );
    }

    #[test]
    fn sidecar_addressed_agents_rejects_controller() {
        let controller = Did::new("did:web:example.com:users:alice").unwrap();
        let body = AgentSidecarEnsureRequestBody {
            controller_id: controller.clone(),
            addressed_agent_ids: vec![controller.clone()],
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
