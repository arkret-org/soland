//! AKP-0008 / AKP-0009 — Personal Agent provisioning + lifecycle surface.
//!
//! Implements the 11 personal-agent HTTP operations gap-reported as missing
//! in soland. The handlers below stand up the cross-project HTTP contract
//! (sodmin admin UI, inkson client, cotest journey vectors) ahead of the
//! deep reducer logic.
//!
//! Surfaces:
//! - `POST   /_arkret/gate/account/agent-key-pair`               —
//!   `ak.gate.account.command.pair_agent_key.v1`
//! - `POST   /_arkret/self/agents`                             —
//!   `ak.self.agent.command.provision.v1`
//! - `GET    /_arkret/self/agents`                             — `ak.self.agent.read.list.v1`
//! - `GET    /_arkret/self/agents/{id}`                        — `ak.self.agent.resource.get.v1`
//! - `POST   /_arkret/self/agents/{id}/pause`                  — `ak.self.agent.command.pause.v1`
//! - `POST   /_arkret/self/agents/{id}/resume`                 — `ak.self.agent.command.resume.v1`
//! - `POST   /_arkret/self/agents/{id}/deactivate`             —
//!   `ak.self.agent.command.deactivate.v1`
//! - `POST   /_arkret/self/agent-sidecars:ensure`              —
//!   `ak.self.agent.sidecar.command.ensure.v1`
//! - `GET    /_arkret/self/agent-sidecars[/{sidecar_id}]`      — dedicated reads
//!
//! Controller operations enforce the persisted `agent_principals.controller_id`
//! binding before they mutate state or emit fan-out. Each handler appends an
//! audit-log row matching the canonical event-kind name so the existing admin /
//! federation projections stay in sync ahead of the reducer rewrite.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{BlobRef, Did, DidCoreId, EventId, GrantId, Hash, RealmId};
use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentKeyPairActivationState, AgentKeyPairOutcome,
    AgentKeyPairRequestBody, AgentLifecycleOutcome, AgentLifecycleState, AgentList,
    AgentPairingBootstrap, AgentPairingMode, AgentPairingResolveRequestBody, AgentPauseRequestBody,
    AgentPresence, AgentPresenceState, AgentProjection, AgentProvisionOutcome,
    AgentProvisionRequestBody, AgentReadiness, AgentReadinessBlocker, AgentReadinessState,
    AgentRenewPairingOutcome, AgentRenewPairingRequestBody, AgentResumeRequestBody,
    AgentRuntimeApprovalOutcome, AgentRuntimeApprovalRequestBody,
    AgentRuntimeApprovalStatusOutcome, AgentRuntimeApprovalStatusRequestBody, AgentRuntimeState,
    AgentView, KeyState,
};
use arkret_models_collaboration::events_payloads::agent::AgentKeyScope;
use arkret_models_collaboration::governance::agent_artifacts::{GrantSnapshot, PublicKey};
use arkret_models_collaboration::governance::agent_participation::{
    AgentParticipationEntry, AgentParticipationOutcome, MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION,
    ParticipationBits, ParticipationNextReplaceInput, ParticipationReplaceRequestBody,
    ParticipationScope,
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

use super::{AuthArgs, append_audit_log, now};
use crate::ids;
use crate::state::AppState;

mod dev_fanout;
use dev_fanout::{
    require_controller_principal_control_realm, submit_durable_agent_lifecycle,
    submit_provision_event, validate_durable_agent_lifecycle,
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
#[path = "agents/tests.rs"]
mod tests;
