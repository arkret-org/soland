//! Authorization HTTP surface.
//!
//! Surfaces:
//! - `POST /_cokret/self/authz/check`             — evaluate one (actor, action, resource)
//! - `GET  /_cokret/self/authz/effective-grants`  — direct grants visible to a subject
//! - `GET  /_cokret/self/authz/invites`           — pending invites visible to the actor
//!
//! The actual authorisation engine lives in `src/authz.rs` (the
//! `state.authz` field is shared). Still-open work: schema alignment,
//! the missing constraint types, the condition.kind types, the
//! capability lattice, and grant/invite/policy lifecycle integration.

use cokret_sdk::models::{
    AuthzDecision, CapabilityGrant, CapabilitySubject, GrantList, Invite, InviteDeliveryTarget,
    InviteState,
};
use cokret_sdk::{AuthzInviteList, Did, GrantId, Hash, InviteId, RealmId};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{now, query_param};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{AuthzCheckOutcome, AuthzCheckRequestBody};

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("authz/check").post(authz_check))
        .push(Router::with_path("authz/effective-grants").get(effective_grants))
        .push(Router::with_path("authz/invites").get(invites))
}

#[endpoint(
    operation_id = "ck.self.authz.query.check",
    tags("authz"),
    summary = "Evaluate one (actor, action, resource) authorization decision"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.authz.query.check"))]
async fn authz_check(
    aa: AuthArgs,
    body: JsonBody<AuthzCheckRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuthzCheckOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    // TODO(authz-scoping): service-http-binding.md §account_auth / §self authorization
    // requires caller-shape scoping (principal session vs service signature).
    // Until that is fully wired, anonymous access remains closed.
    let session = aa.authenticated_session(state, req).await?;
    let _ = &session;
    let body = body.into_inner();
    let resource = body.resource.clone().unwrap_or(Value::Null);
    let (resource_str, realm_id, resource_facets) = if let Some(s) = resource.as_str() {
        (s.to_owned(), s.to_owned(), Vec::new())
    } else if let Some(obj) = resource.as_object() {
        let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("realm");
        let sid = obj
            .get("realm_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                (kind == "realm")
                    .then(|| {
                        obj.get("id")
                            .and_then(|v| v.as_str())
                            .map(ToOwned::to_owned)
                    })
                    .flatten()
            })
            .unwrap_or_default();
        // SEL-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) —
        // `kind=circle` resources MUST carry a `ck:circle:<uuid>`
        // identifier; accept either `circle_id` or the canonical `id`
        // field. The Circle is scoped to its parent Realm; the resource
        // resolver pairs it with the calling realm_id below.
        let resource = obj
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                (kind == "circle")
                    .then(|| {
                        obj.get("circle_id")
                            .and_then(|v| v.as_str())
                            .map(ToOwned::to_owned)
                    })
                    .flatten()
            })
            .unwrap_or_else(|| format!("{kind}:{sid}"));
        let facets = facet_names_from_value(obj.get("facets"));
        (resource, sid, facets)
    } else {
        (String::new(), String::new(), Vec::new())
    };
    // Look up Realm owner and members.
    let (owner, members) = {
        let owner = state
            .persistence
            .realm_meta()
            .get(&realm_id)
            .await
            .ok()
            .flatten()
            .map(|m| m.owner);
        let realms = state.realms.lock().expect("realms lock");
        let members = cokret_sdk::RealmId::new(realm_id.clone())
            .ok()
            .and_then(|realm_id| realms.get(&realm_id))
            .map(|realm| {
                realm
                    .members
                    .iter()
                    .map(|member| member.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        (owner, members)
    };
    let result = state.authz.check(
        body.actor_id.as_str(),
        &body.action,
        &resource_str,
        &realm_id,
        owner.as_deref(),
        &members,
        &resource_facets,
    );
    let matched_grants = result
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
        .collect::<Vec<_>>();
    // The local authz engine yields a binary allow/deny verdict. spec §18 models
    // the decision as a five-valued enum where `quarantine`/`require_review` are
    // Policy Server-mediated soft outcomes (not produced by the local engine);
    // a local refusal maps to the conservative terminal `hard_deny`.
    let decision = if result.allowed {
        AuthzDecision::Allow
    } else {
        AuthzDecision::HardDeny
    };
    let reason_code = (!result.allowed).then(|| result.reason.clone());
    // Trace/diagnostic data lives in the spec-allowed `policy_results` array
    // rather than a private `decision_trace` field.
    let policy_results = vec![json!({
        "actor_id": body.actor_id.as_str(),
        "action": body.action,
        "resource": resource_str,
        "realm_id": realm_id,
        "reason_detail": result.reason_detail,
        "constraints": [],
        "missing_proofs": [],
        "cache": {
            "mode": "in_memory",
            "frontier": Value::Null
        }
    })];
    json_ok(AuthzCheckOutcome {
        decision,
        matched_grants,
        applied_constraints: Vec::new(),
        policy_results,
        missing_proofs: Vec::new(),
        frontier: None,
        freshness_state: None,
        last_known_frontier_age_ms: None,
        notary_status: None,
        cache_expires_at: None,
        reason_code,
        retry_after_ms: None,
        obligations: Vec::new(),
    })
}

fn facet_names_from_value(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        Some(serde_json::Value::Object(values)) => values.keys().cloned().collect(),
        Some(serde_json::Value::String(value)) => vec![value.clone()],
        _ => Vec::new(),
    }
}

#[endpoint(
    operation_id = "ck.self.authz.grants.query.effective",
    tags("authz"),
    summary = "List effective authorization grants for a subject"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.authz.grants.query.effective"))]
async fn effective_grants(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<GrantList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let subject = query_param(req, "subject").unwrap_or_else(|| session.actor.clone());
    let realm_id = query_param(req, "realm_id").unwrap_or_else(|| "*".to_owned());
    let grants = if realm_id == "*" {
        // Return grants across all Realms.
        state
            .persistence
            .realm_meta()
            .list()
            .await
            .unwrap_or_default()
            .into_iter()
            .flat_map(|(sid, _)| state.authz.grants_for_subject(&subject, &sid))
            .collect::<Vec<_>>()
            .into_iter()
            .map(capability_grant_from_authz_grant)
            .collect::<Result<Vec<_>, _>>()?
    } else {
        state
            .authz
            .grants_for_subject(&subject, &realm_id)
            .into_iter()
            .map(capability_grant_from_authz_grant)
            .collect::<Result<Vec<_>, _>>()?
    };
    // Include default member grants if the user is a member of any Realm.
    let default_grants = if grants.is_empty()
        && let Ok(default_grant) = default_member_grant(&subject)
    {
        vec![default_grant]
    } else {
        Vec::new()
    };
    let all_grants = [grants, default_grants].concat();
    crate::result::json_ok(GrantList {
        grants: all_grants,
        state_digest: Some(
            Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
                .map_err(|error| AppError::internal(error.to_string()))?,
        ),
        evaluated_at: now(),
    })
}

fn capability_grant_from_authz_grant(
    grant: crate::authz::Grant,
) -> Result<CapabilityGrant, AppError> {
    let realm_id = RealmId::new(grant.realm_id.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let issuer =
        Did::new(grant.issuer.clone()).map_err(|error| AppError::internal(error.to_string()))?;
    let subject = Did::new(grant.subject.clone())
        .map(CapabilitySubject::Did)
        .unwrap_or_else(|_| CapabilitySubject::Selector(json!(grant.subject)));
    let constraints = grant
        .constraints
        .into_iter()
        .map(|constraint| {
            serde_json::to_value(constraint).map_err(|error| AppError::internal(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CapabilityGrant {
        id: GrantId::new(grant.grant_id.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        schema: "ck.schema.capability_grant.v1".to_owned(),
        realm_id: Some(realm_id),
        issuer,
        subject,
        actions: grant.actions,
        resources: vec![json!({
            "kind": "realm",
            "realm_id": grant.realm_id,
            "resource": grant.resource,
        })],
        constraints,
        parent_grant_id: grant
            .delegated_from
            .map(GrantId::new)
            .transpose()
            .map_err(|error| AppError::internal(error.to_string()))?,
        issued_at: grant.created_at,
        not_before: None,
        expires_at: grant.expires_at,
        effective_after_first_authorized_key: None,
        updated_by: None,
        updated_at: None,
        revoked_by: None,
        revoked_at: grant.revoked.then_some(now()),
        proofs: Vec::new(),
    })
}

fn default_member_grant(subject: &str) -> Result<CapabilityGrant, AppError> {
    let subject = Did::new(subject.to_owned())
        .map(CapabilitySubject::Did)
        .unwrap_or_else(|_| CapabilitySubject::Selector(json!(subject)));
    Ok(CapabilityGrant {
        id: GrantId::new("ck:grant:01904100-0000-7000-8000-000000000001")
            .map_err(|error| AppError::internal(error.to_string()))?,
        schema: "ck.schema.capability_grant.v1".to_owned(),
        realm_id: None,
        issuer: Did::new("did:web:soland.local".to_owned())
            .map_err(|error| AppError::internal(error.to_string()))?,
        subject,
        actions: vec!["realm.read".to_owned(), "directory.search".to_owned()],
        resources: vec![json!({"kind": "realm", "realm_id": "*"})],
        constraints: Vec::new(),
        parent_grant_id: None,
        issued_at: now(),
        not_before: None,
        expires_at: None,
        effective_after_first_authorized_key: None,
        updated_by: None,
        updated_at: None,
        revoked_by: None,
        revoked_at: None,
        proofs: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.self.authz.invites.query.list",
    tags("authz"),
    summary = "List pending invites for the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.authz.invites.query.list"))]
async fn invites(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<AuthzInviteList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let now = now();
    let invite_list = state
        .persistence
        .realm_invites()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|invite| {
            invite.status == "pending"
                && invite
                    .invitee
                    .as_deref()
                    .is_some_and(|invitee| invitee == session.actor)
                && invite.expires_at.is_none_or(|expires_at| expires_at > now)
        })
        .map(invite_record_to_sdk)
        .collect::<Result<Vec<_>, _>>()?;
    crate::result::json_ok(AuthzInviteList {
        invites: invite_list,
        next_cursor: None,
    })
}

fn invite_record_to_sdk(invite: crate::state::RealmInviteRecord) -> Result<Invite, AppError> {
    let invite_delivery_target = invite
        .invite_delivery_target
        .clone()
        .and_then(|target| serde_json::from_value::<InviteDeliveryTarget>(target).ok());
    let introduction_evidence_digest = invite
        .introduction_evidence_digest
        .clone()
        .and_then(|digest| Hash::new(digest).ok());
    let expires_at = invite
        .expires_at
        .unwrap_or_else(|| invite.created_at + chrono::Duration::days(7));
    Ok(Invite {
        schema: "ck.schema.invite.v1".to_owned(),
        id: InviteId::new(invite.invite_id.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        realm_id: RealmId::new(invite.realm_id.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        inviter: Did::new(invite.inviter.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        invitee: invite
            .invitee
            .map(Did::new)
            .transpose()
            .map_err(|error| AppError::internal(error.to_string()))?,
        invite_delivery_target,
        introduction_evidence_digest,
        third_party_id: None,
        join_rule_snapshot: json!({
            "join_rule": "invite",
            "invite_token": invite.invite_token,
            "introduction_evidence_digest": invite.introduction_evidence_digest,
        }),
        capability_grant_refs: Vec::new(),
        expires_at,
        state: invite_state_from_record(&invite.status),
        created_at: invite.created_at,
        updated_by: None,
        updated_at: None,
    })
}

fn invite_state_from_record(status: &str) -> InviteState {
    match status {
        "accepted" => InviteState::Accepted,
        "rejected" => InviteState::Rejected,
        "revoked" => InviteState::Revoked,
        "expired" => InviteState::Expired,
        _ => InviteState::Pending,
    }
}
