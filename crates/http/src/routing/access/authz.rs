//! Authorization HTTP surface.
//!
//! Surfaces:
//! - `POST /_arkret/self/authz/check`             — evaluate one (actor, action, resource)
//! - `GET  /_arkret/self/authz/effective-grants`  — direct grants visible to a subject
//! - `GET  /_arkret/self/authz/invites`           — pending invites visible to the actor
//!
//! The actual authorisation engine lives in `src/authz.rs` (the
//! `state.authorization_application()` field is shared). This surface is a local preflight/read
//! projection. Dynamic, signed, or obligation-bearing decisions are served by
//! `/_arkret/self/policy/check`.

use std::collections::BTreeMap;

use arkret_core::models::{
    AuthzDecision, CapabilityGrant, CapabilitySubject, Facet,
    GrantConstraint as WireGrantConstraint, GrantConstraintEffect as WireGrantConstraintEffect,
    GrantConstraintExtensionKey, GrantConstraintSubtype as WireGrantConstraintSubtype,
    GrantConstraintType as WireGrantConstraintType, GrantList, Invite, InviteDeliveryTarget,
    InviteState,
};
use arkret_core::{AuthzInviteList, Did, GrantId, Hash, InviteId, RealmId};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::{now, query_param};
use crate::authz::{Constraint, GrantDecisionVerdict};
use crate::routing::spaces::space::realm_has_member_by_id;
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
    operation_id = "ak.self.authz.query.check",
    tags("authz"),
    summary = "Evaluate one (actor, action, resource) authorization decision"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.authz.query.check"))]
async fn authz_check(
    aa: AuthArgs,
    body: JsonBody<AuthzCheckRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuthzCheckOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.actor_id.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "authorization checks may only target the authenticated actor",
        ));
    }
    let resource = serde_json::to_value(&body.resource)
        .map_err(|error| AppError::internal(format!("resource encode failed: {error}")))?;
    let ParsedAuthzResource {
        resource: resource_str,
        realm_id,
        facets: resource_facets,
    } = parse_authz_resource(&resource);
    // Look up Realm owner and members.
    let (owner, members) = {
        let owner = state
            .realm_query_application()
            .realm_metadata(&realm_id)
            .await
            .ok()
            .flatten()
            .map(|m| m.owner);
        let realms = state.realm_directory_application().snapshot();
        let members = arkret_core::RealmId::new(realm_id.clone())
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
    let resource_expr = {
        let projection = state.projection_application().snapshot();
        Some(projection.authz_resource_expr(&realm_id, &resource_str))
    }
    .unwrap_or_else(|| resource_str.clone());
    let result = state.authorization_application().check(
        soland_application::authorization::AuthorizationCheck {
            actor: body.actor_id.as_str(),
            action: &body.action,
            resource: &resource_expr,
            realm_id: &realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &resource_facets,
        },
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
        "resource": resource_expr,
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

struct ParsedAuthzResource {
    resource: String,
    realm_id: String,
    facets: Vec<String>,
}

fn parse_authz_resource(resource: &Value) -> ParsedAuthzResource {
    if let Some(s) = resource.as_str() {
        return ParsedAuthzResource {
            resource: s.to_owned(),
            realm_id: s.to_owned(),
            facets: Vec::new(),
        };
    }
    let Some(obj) = resource.as_object() else {
        return ParsedAuthzResource {
            resource: String::new(),
            realm_id: String::new(),
            facets: Vec::new(),
        };
    };
    let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("realm");
    let realm_id = obj
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
    let resource = selector_resource_id(obj, kind, &realm_id);
    ParsedAuthzResource {
        resource,
        realm_id,
        facets: facet_names_from_value(obj.get("facets")),
    }
}

fn selector_resource_id(
    obj: &serde_json::Map<String, Value>,
    kind: &str,
    realm_id: &str,
) -> String {
    if kind == "realm" {
        return obj
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| obj.get("realm_id").and_then(Value::as_str))
            .unwrap_or(realm_id)
            .to_owned();
    }
    let kind_specific = match kind {
        "space" => "space_id",
        "circle" => "circle_id",
        "strand" => "strand_id",
        "message" => "message_id",
        "morph" => "morph_id",
        "relation" => "relation_id",
        "view" => "view_id",
        "event" => "event_id",
        "actor" => "actor_id",
        "schema" => "schema_ref",
        "policy" => "policy_id",
        "invite" => "invite_id",
        "blob" => "blob_ref",
        "object" => "object_ref",
        _ => "id",
    };
    obj.get("id")
        .and_then(Value::as_str)
        .or_else(|| obj.get(kind_specific).and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{kind}:{realm_id}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{capability_resource_selector, parse_authz_resource};

    #[test]
    fn realm_selector_uses_realm_id_as_resource() {
        let parsed = parse_authz_resource(&json!({
            "kind": "realm",
            "realm_id": "ak:realm:01970000-0000-7000-8000-000000000001"
        }));
        assert_eq!(
            parsed.realm_id,
            "ak:realm:01970000-0000-7000-8000-000000000001"
        );
        assert_eq!(
            parsed.resource,
            "ak:realm:01970000-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn object_selector_uses_kind_specific_typed_id() {
        let parsed = parse_authz_resource(&json!({
            "kind": "strand",
            "realm_id": "ak:realm:01970000-0000-7000-8000-000000000001",
            "strand_id": "ak:strand:01970000-0000-7000-8000-000000000002"
        }));
        assert_eq!(
            parsed.realm_id,
            "ak:realm:01970000-0000-7000-8000-000000000001"
        );
        assert_eq!(
            parsed.resource,
            "ak:strand:01970000-0000-7000-8000-000000000002"
        );
    }

    #[test]
    fn persisted_resource_is_reencoded_with_closed_selector_fields() {
        const REALM: &str = "ak:realm:01970000-0000-7000-8000-000000000001";
        const CIRCLE: &str = "ak:circle:01970000-0000-7000-8000-000000000002";
        const STRAND: &str = "ak:strand:01970000-0000-7000-8000-000000000003";

        let realm =
            serde_json::to_value(capability_resource_selector(REALM, REALM).unwrap()).unwrap();
        assert_eq!(realm, json!({"kind": "realm", "realm_id": REALM}));

        let circle =
            serde_json::to_value(capability_resource_selector(REALM, CIRCLE).unwrap()).unwrap();
        assert_eq!(
            circle,
            json!({"kind": "circle", "realm_id": REALM, "circle_id": CIRCLE})
        );

        let strand =
            serde_json::to_value(capability_resource_selector(REALM, STRAND).unwrap()).unwrap();
        assert_eq!(
            strand,
            json!({"kind": "strand", "realm_id": REALM, "strand_id": STRAND})
        );

        let object =
            serde_json::to_value(capability_resource_selector(REALM, "document:summary").unwrap())
                .unwrap();
        assert_eq!(
            object,
            json!({
                "kind": "object",
                "realm_id": REALM,
                "object_ref": "document:summary"
            })
        );
    }
}

#[endpoint(
    operation_id = "ak.self.authz.grants.query.effective",
    tags("authz"),
    summary = "List effective authorization grants for a subject"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.authz.grants.query.effective"))]
async fn effective_grants(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<GrantList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let subject = query_param(req, "subject").unwrap_or_else(|| session.actor.clone());
    let realm_id = query_param(req, "realm_id").unwrap_or_else(|| "*".to_owned());
    let subject_is_self = subject.as_str() == session.actor.as_str();
    let caller_can_query_subject = subject_is_self
        || (realm_id != "*" && session_owns_realm(state, session.actor.as_str(), &realm_id).await);
    if !caller_can_query_subject {
        return Err(AppError::capability_denied(
            "effective-grants subject requires self or realm owner scope",
        ));
    }
    let grants = if realm_id == "*" {
        // Return grants across all Realms.
        state
            .realm_query_application()
            .realm_metadata_list()
            .await
            .unwrap_or_default()
            .into_iter()
            .flat_map(|(sid, _)| {
                state
                    .authorization_application()
                    .grants_for_subject(&subject, &sid)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(capability_grant_from_authz_grant)
            .collect::<Result<Vec<_>, _>>()?
    } else {
        state
            .authorization_application()
            .grants_for_subject(&subject, &realm_id)
            .into_iter()
            .map(capability_grant_from_authz_grant)
            .collect::<Result<Vec<_>, _>>()?
    };
    soland_http::result::json_ok(GrantList {
        grants,
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
    let resource_selector = capability_resource_selector(&grant.realm_id, &grant.resource)?;
    let constraints = grant
        .constraints
        .into_iter()
        .map(wire_constraint_from_authz_constraint)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CapabilityGrant {
        id: GrantId::new(grant.grant_id.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        schema: "ak.schema.capability.v1".to_owned(),
        realm_id: Some(realm_id),
        issuer,
        subject,
        actions: grant.actions,
        resources: vec![resource_selector],
        capability_action_registry_digest: grant.capability_action_registry_digest,
        constraints,
        parent_grant_id: grant
            .delegated_from
            .map(GrantId::new)
            .transpose()
            .map_err(|error| AppError::internal(error.to_string()))?,
        issued_at: grant.created_at,
        not_before: None,
        expires_at: grant.expires_at,
        updated_by: None,
        updated_at: None,
        revoked_by: None,
        revoked_at: grant.revoked.then_some(now()),
        proofs: Vec::new(),
    })
}

fn wire_constraint_from_authz_constraint(
    constraint: Constraint,
) -> Result<WireGrantConstraint, AppError> {
    match constraint {
        Constraint::Decision { decision } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintType::ScopeLimitation,
                wire_effect_from_decision(decision),
            );
            insert_constraint_extension(
                &mut wire,
                "x_soland_decision",
                serde_json::to_value(decision)
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )?;
            Ok(wire)
        }
        Constraint::Temporal {
            expires_at,
            subtype,
            message_edit_window,
            message_redact_window,
            allow_redact_after_window,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintType::Temporal,
                WireGrantConstraintEffect::Allow,
            );
            wire.expires_at = expires_at;
            if let Some(subtype) = subtype {
                match subtype.as_str() {
                    "edit_window" => wire.subtype = Some(WireGrantConstraintSubtype::EditWindow),
                    "redact_window" => {
                        wire.subtype = Some(WireGrantConstraintSubtype::RedactWindow)
                    }
                    "window" => wire.subtype = Some(WireGrantConstraintSubtype::Window),
                    _ => insert_constraint_extension(
                        &mut wire,
                        "x_soland_temporal_subtype",
                        Value::String(subtype),
                    )?,
                }
            }
            wire.message_edit_window =
                message_edit_window.map(|duration| format!("{}{}", duration.value, duration.unit));
            wire.message_redact_window = message_redact_window
                .map(|duration| format!("{}{}", duration.value, duration.unit));
            wire.allow_redact_after_window = Some(allow_redact_after_window);
            Ok(wire)
        }
        Constraint::AllowedCircleIds { allowed_circle_ids } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintType::ScopeLimitation,
                WireGrantConstraintEffect::Allow,
            );
            wire.allowed_circle_ids = allowed_circle_ids.into_iter().collect();
            Ok(wire)
        }
        Constraint::AllowedSessionIds {
            allowed_session_ids,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintType::ScopeLimitation,
                WireGrantConstraintEffect::Allow,
            );
            wire.subtype = Some(WireGrantConstraintSubtype::Session);
            wire.allowed_session_ids = allowed_session_ids.into_iter().collect();
            Ok(wire)
        }
        Constraint::AllowedObjectFacets { facets } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintType::TypeRestriction,
                WireGrantConstraintEffect::Allow,
            );
            let mut unparsed = Vec::new();
            for facet in facets {
                match serde_json::from_value::<Facet>(Value::String(facet.clone())) {
                    Ok(facet) => wire.allowed_facets.push(facet),
                    Err(_) => unparsed.push(Value::String(facet)),
                }
            }
            if !unparsed.is_empty() {
                insert_constraint_extension(
                    &mut wire,
                    "x_soland_allowed_object_facets",
                    Value::Array(unparsed),
                )?;
            }
            Ok(wire)
        }
        Constraint::RateLimiting {
            max_operations,
            period,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintType::Quota,
                WireGrantConstraintEffect::Allow,
            );
            wire.subtype = Some(WireGrantConstraintSubtype::Rate);
            wire.max_operations = Some(max_operations);
            wire.period = Some(period);
            Ok(wire)
        }
        Constraint::DelegationControl {
            max_delegation_depth,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintType::DelegationControl,
                WireGrantConstraintEffect::Allow,
            );
            wire.max_delegation_depth = max_delegation_depth.map(u64::from);
            Ok(wire)
        }
        Constraint::AppletDelegationBinding {
            applet_id,
            executed_by,
            registration_epoch,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintType::DelegationControl,
                WireGrantConstraintEffect::Allow,
            );
            insert_constraint_extension(
                &mut wire,
                "x_soland_applet_delegation_binding",
                json!({
                    "applet_id": applet_id,
                    "executed_by": executed_by,
                    "registration_epoch": registration_epoch,
                }),
            )?;
            Ok(wire)
        }
    }
}

fn wire_effect_from_decision(decision: GrantDecisionVerdict) -> WireGrantConstraintEffect {
    match decision {
        GrantDecisionVerdict::Allow => WireGrantConstraintEffect::Allow,
        GrantDecisionVerdict::Deny => WireGrantConstraintEffect::Deny,
        GrantDecisionVerdict::Quarantine => WireGrantConstraintEffect::Quarantine,
        GrantDecisionVerdict::RequireReview => WireGrantConstraintEffect::RequireReview,
    }
}

fn insert_constraint_extension(
    constraint: &mut WireGrantConstraint,
    key: &'static str,
    value: Value,
) -> Result<(), AppError> {
    let key = GrantConstraintExtensionKey::new(key)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let _ = constraint.extensions.insert(key.into_string(), value);
    Ok(())
}

async fn session_owns_realm(state: &AppState, actor: &str, realm_id: &str) -> bool {
    state
        .realm_query_application()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|meta| meta.owner.as_str() == actor)
}

fn capability_resource_selector(
    realm_id: &str,
    resource: &str,
) -> Result<arkret_core::WireResourceSelector, AppError> {
    let value = if resource == "*" {
        json!({
            "kind": "realm",
            "realm_id": realm_id,
        })
    } else if resource == realm_id || resource.starts_with("ak:realm:") {
        json!({
            "kind": "realm",
            "realm_id": resource,
        })
    } else if resource.starts_with("ak:circle:") {
        json!({
            "kind": "circle",
            "realm_id": realm_id,
            "circle_id": resource,
        })
    } else if resource.starts_with("ak:strand:") {
        json!({
            "kind": "strand",
            "realm_id": realm_id,
            "strand_id": resource,
        })
    } else {
        json!({
            "kind": "object",
            "realm_id": realm_id,
            "object_ref": resource,
        })
    };
    serde_json::from_value(value)
        .map_err(|error| AppError::internal(format!("resource selector encode failed: {error}")))
}

#[endpoint(
    operation_id = "ak.self.authz.invites.query.list",
    tags("authz"),
    summary = "List pending invites for the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.authz.invites.query.list"))]
async fn invites(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<AuthzInviteList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let subject = query_param(req, "subject").unwrap_or_else(|| session.actor.clone());
    let realm_filter = query_param(req, "realm_id");
    let subject_is_self = subject.as_str() == session.actor.as_str();
    let caller_owns_realm = if subject_is_self {
        false
    } else if let Some(realm_id) = realm_filter.as_deref() {
        session_owns_realm(state, session.actor.as_str(), realm_id).await
    } else {
        false
    };
    let now = now();
    let mut invite_list = Vec::new();
    for invite in state
        .realm_invite_application()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
    {
        if !matches!(invite.status.as_str(), "pending" | "claimed")
            || realm_filter
                .as_deref()
                .is_some_and(|realm_id| invite.realm_id.as_str() != realm_id)
            || invite.invitee.as_deref() != Some(subject.as_str())
            || (!subject_is_self
                && invite.inviter.as_str() != session.actor.as_str()
                && !caller_owns_realm)
            || invite
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
        {
            continue;
        }
        if realm_has_member_by_id(state, &invite.realm_id, &subject).await {
            continue;
        }
        invite_list.push(invite_record_to_sdk(invite)?);
    }
    soland_http::result::json_ok(AuthzInviteList {
        invites: invite_list,
        next_cursor: None,
        has_more: false,
    })
}

fn invite_record_to_sdk(
    invite: soland_application::events::RealmInviteState,
) -> Result<Invite, AppError> {
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
        schema: "ak.schema.invite.v1".to_owned(),
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
        third_party_id: invite
            .third_party_id
            .and_then(|value| serde_json::from_value(value).ok()),
        join_rule_snapshot: invite
            .join_rule_snapshot
            .and_then(|value| {
                value.as_object().map(|object| {
                    object
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect()
                })
            })
            .unwrap_or_else(|| {
                BTreeMap::from([
                    ("join_rule".to_owned(), json!("invite")),
                    ("invite_token".to_owned(), json!(invite.invite_token)),
                    (
                        "introduction_evidence_digest".to_owned(),
                        json!(invite.introduction_evidence_digest),
                    ),
                ])
            }),
        capability_grant_refs: Vec::new(),
        expires_at,
        state: invite_state_from_record(&invite.status),
        created_at: invite.created_at,
        updated_by: None,
        updated_at: invite.updated_at,
    })
}

fn invite_state_from_record(status: &str) -> InviteState {
    match status {
        "accepted" => InviteState::Accepted,
        "claimed" => InviteState::Claimed,
        "rejected" => InviteState::Rejected,
        "revoked" => InviteState::Revoked,
        "expired" => InviteState::Expired,
        _ => InviteState::Pending,
    }
}
