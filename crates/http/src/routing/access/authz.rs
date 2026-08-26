//! Authorization HTTP surface.
//!
//! Surfaces:
//! - `POST /_arkret/self/authz/check`             — evaluate one (actor, action, resource)
//! - `GET  /_arkret/self/authz/effective-grants`  — direct grants visible to a subject
//! - `GET  /_arkret/self/authz/invites`           — pending invites visible to the actor
//!
//! The actual authorisation engine lives in `src/authz.rs` (the
//! `state.authorization()` field is shared). This surface is a local preflight/read
//! projection. Dynamic, signed, or obligation-bearing decisions are served by
//! `/_arkret/self/policy/check`.

use arkret_identifiers::{GrantId, Hash, InviteId, RealmId};
use arkret_models_collaboration::governance::authorization::{AuthzInviteList, GrantList};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, GrantConstraint as WireGrantConstraint,
    GrantConstraintEffect as WireGrantConstraintEffect, GrantConstraintExtensionKey,
    GrantConstraintKind as WireGrantConstraintKind,
    GrantConstraintSubkind as WireGrantConstraintSubkind,
};
use arkret_models_collaboration::governance::invite_addressing::{
    InviteDelivery, InviteDeliveryTarget,
};
use arkret_models_collaboration::governance::operation_wire::Invite;
use arkret_wire::{AccountDataKey, AuthzDecision, DidCoreId, Facet, InviteState};
use chrono::{DateTime, Utc};
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::{now, query_param};
use crate::authz::{GrantConstraint, GrantDecisionVerdict};
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
    operation_id = "ak.self.authz.read.check",
    summary = "Evaluate an authorization decision",
    tags("authz")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.authz.read.check"))]
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
            .realms()
            .realm_metadata(&realm_id)
            .await
            .ok()
            .flatten()
            .map(|m| m.owner);
        let realms = state.realm_directory().snapshot();
        let members = arkret_identifiers::RealmId::new(realm_id.clone())
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
        let projection = state.projections().snapshot();
        Some(projection.authz_resource_expr(&realm_id, &resource_str))
    }
    .unwrap_or_else(|| resource_str.clone());
    let result = state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor: body.actor_id.as_str(),
            actor_principal_server_id: Some(state.service_id()),
            action: &body.action,
            resource: &resource_expr,
            realm_id: &realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &resource_facets,
        });
    // The capability-engine map is an index over ordinary grant cells. Realm
    // genesis deliberately does not mint a synthetic self-grant: the current
    // controller instead holds effective `ak.realm.owner` through the
    // registered authority-root cell. Fold that independent operational
    // source into this local preflight, using the root's registry basis so an
    // old Realm is never reinterpreted under today's aggregate coverage.
    // Non-Event and root-control-only actions remain fail-closed.
    let owner_aggregate_allowed = state
        .projections()
        .snapshot()
        .realm_owner_operationally_covers_action(
            &realm_id,
            body.actor_id.as_str(),
            state.service_id(),
            &body.action,
            now(),
        );
    let allowed = result.allowed || owner_aggregate_allowed;
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
    let decision = if allowed {
        AuthzDecision::Allow
    } else {
        AuthzDecision::HardDeny
    };
    let reason_code = (!allowed).then(|| result.reason.clone());
    // Trace/diagnostic data lives in the spec-allowed `policy_results` array
    // rather than a private `decision_trace` field.
    let policy_results = vec![json!({
        "actor_id": body.actor_id.as_str(),
        "action": body.action,
        "resource": resource_expr,
        "realm_id": realm_id,
        "reason_detail": if owner_aggregate_allowed {
            Some("realm_owner_aggregate")
        } else {
            result.reason_detail.as_deref()
        },
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
        reason_code: reason_code.map(|code| arkret_wire::ReasonCode::from_wire(&code)),
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
            "realm_id": "ak:realm:ARib7U2kHFo1ErdwrDDP0057R6D3jtBM74RcEz4Pw4Jy"
        }));
        assert_eq!(
            parsed.realm_id,
            "ak:realm:ARib7U2kHFo1ErdwrDDP0057R6D3jtBM74RcEz4Pw4Jy"
        );
        assert_eq!(
            parsed.resource,
            "ak:realm:ARib7U2kHFo1ErdwrDDP0057R6D3jtBM74RcEz4Pw4Jy"
        );
    }

    #[test]
    fn object_selector_uses_kind_specific_typed_id() {
        let parsed = parse_authz_resource(&json!({
            "kind": "strand",
            "realm_id": "ak:realm:ARib7U2kHFo1ErdwrDDP0057R6D3jtBM74RcEz4Pw4Jy",
            "strand_id": "ak:strand:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M"
        }));
        assert_eq!(
            parsed.realm_id,
            "ak:realm:ARib7U2kHFo1ErdwrDDP0057R6D3jtBM74RcEz4Pw4Jy"
        );
        assert_eq!(
            parsed.resource,
            "ak:strand:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M"
        );
    }

    #[test]
    fn persisted_resource_is_reencoded_with_closed_selector_fields() {
        const REALM: &str = "ak:realm:ARib7U2kHFo1ErdwrDDP0057R6D3jtBM74RcEz4Pw4Jy";
        const CIRCLE: &str = "ak:circle:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M";
        const STRAND: &str = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";

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

#[salvo::oapi::endpoint(operation_id = "ak.self.authz.grants.read.effective", tags("access"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.authz.grants.read.effective"))]
async fn effective_grants(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<GrantList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let subject = query_param(req, "subject")
        .ok_or_else(|| AppError::param_invalid("subject is required"))
        .and_then(|value| {
            DidCoreId::new(value).map_err(|_| AppError::param_invalid("subject is invalid"))
        })?;
    let subject_principal_server_id = query_param(req, "subject_principal_server_id")
        .ok_or_else(|| AppError::param_invalid("subject_principal_server_id is required"))
        .and_then(|value| {
            DidCoreId::new(value)
                .map_err(|_| AppError::param_invalid("subject_principal_server_id is invalid"))
        })?;
    let realm_id = query_param(req, "realm_id")
        .ok_or_else(|| AppError::param_invalid("realm_id is required"))
        .and_then(|value| {
            RealmId::new(value).map_err(|_| AppError::param_invalid("realm_id is invalid"))
        })?;
    let evaluated_at = query_param(req, "at")
        .map(|value| {
            DateTime::parse_from_rfc3339(&value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|_| AppError::param_invalid("at is invalid"))
        })
        .transpose()?
        .unwrap_or_else(now);
    let subject_is_self = subject.as_str() == session.actor.as_str()
        && subject_principal_server_id.as_str() == session.audience.as_str();
    let caller_can_query_subject = subject_is_self
        || session_owns_realm(state, session.actor.as_str(), realm_id.as_str()).await;
    if !caller_can_query_subject {
        return Err(AppError::capability_denied(
            "effective-grants subject requires self or realm owner scope",
        ));
    }
    let grants = state
        .authorization()
        .grants_for_subject_at(
            subject.as_str(),
            Some(subject_principal_server_id.as_str()),
            realm_id.as_str(),
            evaluated_at,
        )
        .into_iter()
        .map(capability_grant_from_authz_grant)
        .collect::<Result<Vec<_>, _>>()?;
    soland_http::result::json_ok(GrantList {
        grants,
        state_digest: Some(
            Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
                .map_err(|error| AppError::internal(error.to_string()))?,
        ),
        evaluated_at,
    })
}

fn capability_grant_from_authz_grant(
    grant: crate::authz::Grant,
) -> Result<CapabilityGrant, AppError> {
    let realm_id = RealmId::new(grant.realm_id.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let issuer = arkret_wire::DidCoreId::new(grant.issuer.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let subject = arkret_wire::DidCoreId::new(grant.subject.clone())
        .map(CapabilitySubject::CoreDid)
        .map_err(|error| {
            AppError::internal(format!(
                "stored authorization grant subject is not a core DID: {error}"
            ))
        })?;
    let resource_selector = capability_resource_selector(&grant.realm_id, &grant.resource)?;
    let constraints = grant
        .constraints
        .into_iter()
        .map(wire_constraint_from_authz_constraint)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CapabilityGrant {
        id: GrantId::new(grant.grant_id.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
        realm_id: Some(realm_id),
        issuer,
        issuer_principal_server_id: arkret_wire::DidCoreId::new(
            grant.issuer_principal_server_id,
        )
        .map_err(|error| AppError::internal(error.to_string()))?,
        subject,
        subject_principal_server_id: grant
            .subject_principal_server_id
            .map(arkret_wire::DidCoreId::new)
            .transpose()
            .map_err(|error| AppError::internal(error.to_string()))?,
        actions: grant.actions,
        resources: vec![resource_selector],
        constraints,
        issuer_authority_refs: grant
            .issuer_authority_refs
            .iter()
            .filter_map(arkret_policy::authz::authority::IssuerAuthorityRef::grant_id)
            .map(|id| {
                GrantId::new(id).map(|grant_id| {
                    arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant { grant_id }
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| AppError::internal(error.to_string()))?,
        issued_at: grant.created_at,
        updated_by: None,
        updated_at: None,
        revoked_by: None,
        revoked_at: grant.revoked.then_some(now()),
    })
}

fn wire_constraint_from_authz_constraint(
    constraint: GrantConstraint,
) -> Result<WireGrantConstraint, AppError> {
    match constraint {
        GrantConstraint::Decision { decision } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintKind::ScopeLimitation,
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
        GrantConstraint::Temporal {
            expires_at,
            constraint_subkind,
            message_edit_window,
            message_redact_window,
            redact_after_window_allowed,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintKind::Temporal,
                WireGrantConstraintEffect::Allow,
            );
            wire.expires_at = expires_at;
            if let Some(constraint_subkind) = constraint_subkind {
                match constraint_subkind.as_str() {
                    "edit_window" => {
                        wire.constraint_subkind = Some(WireGrantConstraintSubkind::EditWindow)
                    }
                    "redact_window" => {
                        wire.constraint_subkind = Some(WireGrantConstraintSubkind::RedactWindow)
                    }
                    "window" => wire.constraint_subkind = Some(WireGrantConstraintSubkind::Window),
                    _ => insert_constraint_extension(
                        &mut wire,
                        "x_soland_temporal_subtype",
                        Value::String(constraint_subkind),
                    )?,
                }
            }
            wire.message_edit_window =
                message_edit_window.map(|duration| format!("{}{}", duration.value, duration.unit));
            wire.message_redact_window = message_redact_window
                .map(|duration| format!("{}{}", duration.value, duration.unit));
            wire.redact_after_window_allowed = Some(redact_after_window_allowed);
            Ok(wire)
        }
        GrantConstraint::AllowedCircleIds { allowed_circle_ids } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintKind::ScopeLimitation,
                WireGrantConstraintEffect::Allow,
            );
            wire.allowed_circle_ids = allowed_circle_ids.into_iter().collect();
            Ok(wire)
        }
        GrantConstraint::AllowedSessionIds {
            allowed_session_ids,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintKind::ScopeLimitation,
                WireGrantConstraintEffect::Allow,
            );
            wire.constraint_subkind = Some(WireGrantConstraintSubkind::Session);
            wire.allowed_session_ids = allowed_session_ids.into_iter().collect();
            Ok(wire)
        }
        GrantConstraint::AllowedObjectFacets { facets } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintKind::KindRestriction,
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
        GrantConstraint::RateLimiting {
            max_operations,
            period,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintKind::Quota,
                WireGrantConstraintEffect::Allow,
            );
            wire.constraint_subkind = Some(WireGrantConstraintSubkind::Rate);
            wire.max_operations = Some(max_operations);
            wire.period = Some(period);
            Ok(wire)
        }
        GrantConstraint::FieldAccess {
            effect,
            allowed_write_fields,
            denied_write_fields,
            allowed_read_fields,
            denied_read_fields,
            condition,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintKind::FieldAccess,
                wire_effect_from_decision(effect),
            );
            wire.allowed_write_fields = allowed_write_fields;
            wire.denied_write_fields = denied_write_fields;
            wire.allowed_read_fields = allowed_read_fields;
            wire.denied_read_fields = denied_read_fields;
            wire.condition = condition
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| AppError::internal(error.to_string()))?;
            Ok(wire)
        }
        GrantConstraint::ScopeLimitation {
            effect,
            allowed_strand_ids,
            denied_strand_ids,
            allowed_tracks,
            denied_tracks,
            allowed_circle_ids,
            allowed_session_ids,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintKind::ScopeLimitation,
                wire_effect_from_decision(effect),
            );
            wire.allowed_strand_ids = allowed_strand_ids;
            wire.denied_strand_ids = denied_strand_ids;
            wire.allowed_tracks = allowed_tracks;
            wire.denied_tracks = denied_tracks;
            wire.allowed_circle_ids = allowed_circle_ids.into_iter().collect();
            wire.allowed_session_ids = allowed_session_ids.into_iter().collect();
            Ok(wire)
        }
        GrantConstraint::AuthorityControl {
            max_authority_depth,
            authority_regrant_allowed,
            constraint_subkind,
            applet_id,
            executed_by,
            registration_epoch,
        } => {
            let mut wire = WireGrantConstraint::new(
                WireGrantConstraintKind::AuthorityControl,
                WireGrantConstraintEffect::Allow,
            );
            wire.max_authority_depth = max_authority_depth.map(u64::from);
            wire.authority_regrant_allowed = Some(authority_regrant_allowed);
            wire.constraint_subkind = constraint_subkind;
            wire.applet_id = applet_id;
            wire.executed_by = executed_by;
            wire.registration_epoch = registration_epoch;
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
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|meta| meta.owner.as_str() == actor)
}

fn capability_resource_selector(
    realm_id: &str,
    resource: &str,
) -> Result<arkret_wire::resource_selector::WireResourceSelector, AppError> {
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

#[salvo::oapi::endpoint(operation_id = "ak.self.authz.invites.read.list", tags("access"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.authz.invites.read.list"))]
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
    // invite-addressing.md §7: the accepted Realm Event establishes the
    // shared Invite lifecycle, but only the notify branch materializes the
    // holder-private invite delivery. Quarantined, dropped, and rejected
    // dispatches MUST therefore stay out of the holder's invite list even
    // though their shared `ak.invite.create` Event is already durable.
    let holder_delivery_ids = if subject_is_self {
        let delivery = state
            .account_data()
            .entry(subject.as_str(), AccountDataKey::ACCOUNT_INVITE_DELIVERY)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .map(|record| serde_json::from_value::<InviteDelivery>(record.payload))
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("invite delivery cell does not parse: {error}"))
            })?;
        Some(
            delivery
                .into_iter()
                .flat_map(|delivery| delivery.entries)
                .map(|entry| entry.invite_id.to_string())
                .collect::<std::collections::BTreeSet<_>>(),
        )
    } else {
        None
    };
    let now = now();
    let mut invite_list = Vec::new();
    for invite in state
        .realm_invites()
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
            || holder_delivery_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(&invite.invite_id))
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
    invite: soland_services::events::RealmInviteState,
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
        schema: arkret_wire::SchemaId::INVITE_V1.to_owned(),
        id: InviteId::new(invite.invite_id.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        realm_id: RealmId::new(invite.realm_id.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        inviter: arkret_wire::DidCoreId::new(invite.inviter.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        invitee: invite
            .invitee
            .map(arkret_wire::DidCoreId::new)
            .transpose()
            .map_err(|error| AppError::internal(error.to_string()))?,
        invite_delivery_target,
        introduction_evidence_digest,
        third_party_invite: invite.third_party_invite,
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
