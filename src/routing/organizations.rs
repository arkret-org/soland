//! Organization registry + moderation policy inheritance.
//!
//! This is the local P2 governance surface for organization-owned Realms:
//! org policies are stored once, Realm create links fan out through an index,
//! and Space-level overrides are accepted only when the organization has
//! explicitly approved the exception.

use std::collections::BTreeSet;

use chrono::Utc;
use salvo::http::StatusCode;
use salvo::oapi::ToSchema;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::AppError;
use crate::routing::system::extract::AuthArgs;
use crate::routing::system::util::validate_did;
use crate::state::{
    AppState, OrganizationPolicyRecord, OrganizationRecord, SpaceModerationPolicyRecord,
};
use crate::{JsonResult, json_ok};

#[derive(Debug, Deserialize, ToSchema)]
struct UpsertOrganizationRequest {
    #[serde(default)]
    organization_id: Option<String>,
    organization_did: String,
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    verified: Option<bool>,
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    member_count: Option<usize>,
}

#[derive(Debug, Deserialize, ToSchema)]
struct LinkOrganizationSpaceRequest {
    space_id: String,
}

pub(crate) fn router() -> Router {
    Router::with_path("organizations")
        .get(list_organizations)
        .post(upsert_organization)
        .push(
            Router::with_path("{organization_id}")
                .get(get_organization)
                .push(Router::with_path("policy").get(get_organization_policy))
                .push(Router::with_path("policy").post(upsert_organization_policy))
                .push(Router::with_path("spaces").post(link_organization_space)),
        )
}

#[endpoint(
    operation_id = "cx.extension.soland.organizations.list",
    tags("organizations"),
    summary = "List locally known organizations"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.organizations.list"))]
async fn list_organizations(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let mut rows = state
        .organizations
        .lock()
        .expect("organizations lock")
        .values()
        .map(|record| organization_record_json(state, record))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left["display_name"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["display_name"].as_str().unwrap_or_default())
    });
    let total = rows.len();
    json_ok(json!({
        "organizations": rows,
        "total": total,
    }))
}

#[endpoint(
    operation_id = "cx.extension.soland.organizations.upsert",
    tags("organizations"),
    summary = "Create or update a local organization registry row"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.organizations.upsert"))]
async fn upsert_organization(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<UpsertOrganizationRequest>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    validate_did(&body.organization_did)
        .map_err(|_| AppError::invalid_param("organization_did must be a DID"))?;
    let now = Utc::now();
    let organization_id = normalized_organization_id(
        body.organization_id
            .as_deref()
            .unwrap_or(body.organization_did.as_str()),
    )?;
    let display_name = body
        .display_name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| display_name_from_organization_id(&organization_id));
    let members = body
        .members
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect::<BTreeSet<_>>();
    let member_count = body.member_count.unwrap_or(members.len());
    let record = OrganizationRecord {
        organization_id: organization_id.clone(),
        organization_did: body.organization_did,
        handle: body.handle,
        display_name,
        verified: body.verified.unwrap_or(true),
        members,
        member_count,
        created_by: session.actor.clone(),
        created_at: now,
        updated_at: now,
    };
    state
        .organizations
        .lock()
        .expect("organizations lock")
        .insert(organization_id, record.clone());
    json_ok(organization_record_json(state, &record))
}

#[endpoint(
    operation_id = "cx.extension.soland.organizations.get",
    tags("organizations"),
    summary = "Read a local organization registry row"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.organizations.get"))]
async fn get_organization(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_id: PathParam<String>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let organization_id = normalized_organization_id(&organization_id.into_inner())?;
    let record = state
        .organizations
        .lock()
        .expect("organizations lock")
        .get(&organization_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("organization not found"))?;
    json_ok(organization_record_json(state, &record))
}

#[endpoint(
    operation_id = "cx.extension.soland.organizations.policy.get",
    tags("organizations", "policy"),
    summary = "Read the current organization moderation policy"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.organizations.policy.get"))]
async fn get_organization_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_id: PathParam<String>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let organization_id = normalized_organization_id(&organization_id.into_inner())?;
    let policy = state
        .organization_policies
        .lock()
        .expect("organization policies lock")
        .get(&organization_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("organization policy not found"))?;
    json_ok(organization_policy_record_json(state, &policy))
}

#[endpoint(
    operation_id = "cx.extension.soland.organizations.policy.upsert",
    tags("organizations", "policy"),
    summary = "Publish an organization moderation policy"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.organizations.policy.upsert")
)]
async fn upsert_organization_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let organization_id = normalized_organization_id(&organization_id.into_inner())?;
    ensure_organization_placeholder(state, &organization_id, &session.actor);
    let mut payload = body.into_inner();
    if !payload.is_object() {
        return Err(AppError::bad_json(
            "organization moderation policy must be a JSON object",
        ));
    }
    if payload.get("kind").and_then(Value::as_str).is_none() {
        payload.as_object_mut().expect("object checked").insert(
            "kind".to_owned(),
            json!("cx.organization.moderation_policy"),
        );
    }
    if payload
        .get("organization_did")
        .and_then(Value::as_str)
        .is_none()
    {
        payload.as_object_mut().expect("object checked").insert(
            "organization_did".to_owned(),
            json!(organization_id.clone()),
        );
    }
    let now = Utc::now();
    let version = state
        .organization_policies
        .lock()
        .expect("organization policies lock")
        .get(&organization_id)
        .map(|policy| policy.version.saturating_add(1))
        .unwrap_or(1);
    let policy_id = payload
        .get("policy_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "cx:org-policy:{}:{version}",
                safe_id_fragment(&organization_id)
            )
        });
    let record = OrganizationPolicyRecord {
        organization_id: organization_id.clone(),
        policy_id,
        payload,
        version,
        updated_by: session.actor.clone(),
        updated_at: now,
    };
    state
        .organization_policies
        .lock()
        .expect("organization policies lock")
        .insert(organization_id, record.clone());
    json_ok(organization_policy_record_json(state, &record))
}

#[endpoint(
    operation_id = "cx.extension.soland.organizations.spaces.link",
    tags("organizations", "spaces"),
    summary = "Link a Realm to an organization policy source"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.organizations.spaces.link"))]
async fn link_organization_space(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_id: PathParam<String>,
    body: JsonBody<LinkOrganizationSpaceRequest>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let organization_id = normalized_organization_id(&organization_id.into_inner())?;
    let body = body.into_inner();
    ensure_organization_placeholder(state, &organization_id, &session.actor);
    link_space_to_organization(state, &body.space_id, &organization_id);
    json_ok(json!({
        "organization_id": organization_id,
        "space_id": body.space_id,
        "linked": true,
    }))
}

pub(crate) fn record_realm_organizations_from_event(
    state: &AppState,
    realm_id: &str,
    envelope: &Value,
) {
    let Some(object) = envelope
        .pointer("/payload/object")
        .and_then(Value::as_object)
    else {
        return;
    };
    let mut orgs = Vec::new();
    if let Some(array) = object.get("owning_organizations").and_then(Value::as_array) {
        orgs.extend(
            array
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned),
        );
    }
    for key in ["organization_id", "organization_did", "organization_ref"] {
        if let Some(value) = object.get(key).and_then(Value::as_str) {
            orgs.push(value.to_owned());
        }
    }
    for org in orgs {
        let Ok(org_id) = normalized_organization_id(&org) else {
            continue;
        };
        ensure_organization_placeholder(state, &org_id, "realm_create");
        link_space_to_organization(state, realm_id, &org_id);
    }
}

pub(crate) fn link_space_to_organization(state: &AppState, space_id: &str, organization_id: &str) {
    state
        .space_organizations
        .lock()
        .expect("space organizations lock")
        .entry(space_id.to_owned())
        .or_default()
        .insert(organization_id.to_owned());
    state
        .organization_spaces
        .lock()
        .expect("organization spaces lock")
        .entry(organization_id.to_owned())
        .or_default()
        .insert(space_id.to_owned());
}

pub(crate) fn space_organization_ids(state: &AppState, space_id: &str) -> Vec<String> {
    state
        .space_organizations
        .lock()
        .expect("space organizations lock")
        .get(space_id)
        .map(|set| set.iter().cloned().collect())
        .unwrap_or_default()
}

pub(crate) fn effective_policy_for_space_json(state: &AppState, space_id: &str) -> Value {
    let org_ids = space_organization_ids(state, space_id);
    let policies = state
        .organization_policies
        .lock()
        .expect("organization policies lock");
    let links = state
        .organization_spaces
        .lock()
        .expect("organization spaces lock");
    let org_layers = org_ids
        .iter()
        .filter_map(|org_id| policies.get(org_id).map(|policy| (org_id, policy)))
        .map(|(org_id, policy)| {
            json!({
                "source": "organization",
                "organization_id": org_id,
                "policy_id": policy.policy_id,
                "version": policy.version,
                "policy": policy.payload,
                "applies_to_spaces": links
                    .get(org_id)
                    .map(|set| set.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    drop(links);
    drop(policies);

    let space_policy = state
        .space_moderation_policies
        .lock()
        .expect("space moderation policies lock")
        .get(space_id)
        .map(space_policy_record_json);
    json!({
        "space_id": space_id,
        "inheritance_mode": if org_ids.is_empty() { "none" } else { "organization" },
        "inheritance_chain": org_ids,
        "organization_policy_layers": org_layers,
        "space_policy": space_policy,
        "effective_rules": effective_rules(state, space_id),
        "override_requires_organization_approval": !space_organization_ids(state, space_id).is_empty(),
        "fanout": {
            "source": "organization_policy",
            "rewrites_space_policy": false,
        }
    })
}

pub(crate) fn organization_policy_blocks_join(
    state: &AppState,
    space_id: &str,
    actor: &str,
) -> bool {
    if accepted_space_override_allows_join(state, space_id, actor) {
        return false;
    }
    let org_ids = space_organization_ids(state, space_id);
    if org_ids.is_empty() {
        return false;
    }
    let policies = state
        .organization_policies
        .lock()
        .expect("organization policies lock");
    org_ids.iter().any(|org_id| {
        policies
            .get(org_id)
            .is_some_and(|policy| policy_denies_join_actor(&policy.payload, actor))
    })
}

pub(crate) fn space_policy_override_requires_approval(
    state: &AppState,
    space_id: &str,
    payload: &Value,
) -> bool {
    let targets = allow_join_override_targets(payload);
    if targets.is_empty() {
        return false;
    }
    let org_ids = space_organization_ids(state, space_id);
    if org_ids.is_empty() {
        return false;
    }
    let policies = state
        .organization_policies
        .lock()
        .expect("organization policies lock");
    targets.iter().any(|target| {
        org_ids.iter().any(|org_id| {
            policies
                .get(org_id)
                .is_some_and(|policy| policy_denies_join_actor(&policy.payload, target))
        })
    })
}

pub(crate) fn space_policy_override_has_approval(
    state: &AppState,
    space_id: &str,
    payload: &Value,
) -> bool {
    if !space_policy_override_requires_approval(state, space_id, payload) {
        return true;
    }
    let org_ids = space_organization_ids(state, space_id)
        .into_iter()
        .collect::<BTreeSet<_>>();
    approvals_from_payload(payload)
        .iter()
        .any(|approval| approval_matches(approval, &org_ids))
}

pub(crate) fn persist_space_moderation_policy(
    state: &AppState,
    space_id: &str,
    payload: Value,
    actor: &str,
) -> SpaceModerationPolicyRecord {
    let record = SpaceModerationPolicyRecord {
        space_id: space_id.to_owned(),
        payload,
        updated_by: actor.to_owned(),
        updated_at: Utc::now(),
    };
    state
        .space_moderation_policies
        .lock()
        .expect("space moderation policies lock")
        .insert(space_id.to_owned(), record.clone());
    record
}

pub(crate) fn organization_records_for_directory(state: &AppState) -> Vec<Value> {
    state
        .organizations
        .lock()
        .expect("organizations lock")
        .values()
        .map(|record| organization_record_json(state, record))
        .collect()
}

fn ensure_organization_placeholder(state: &AppState, organization_id: &str, actor: &str) {
    let mut guard = state.organizations.lock().expect("organizations lock");
    if guard.contains_key(organization_id) {
        return;
    }
    let now = Utc::now();
    guard.insert(
        organization_id.to_owned(),
        OrganizationRecord {
            organization_id: organization_id.to_owned(),
            organization_did: organization_id.to_owned(),
            handle: None,
            display_name: display_name_from_organization_id(organization_id),
            verified: true,
            members: BTreeSet::new(),
            member_count: 0,
            created_by: actor.to_owned(),
            created_at: now,
            updated_at: now,
        },
    );
}

fn organization_record_json(state: &AppState, record: &OrganizationRecord) -> Value {
    let spaces = state
        .organization_spaces
        .lock()
        .expect("organization spaces lock")
        .get(&record.organization_id)
        .map(|set| set.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let space_count = spaces.len();
    json!({
        "organization_id": record.organization_id.clone(),
        "organization_did": record.organization_did.clone(),
        "handle": record.handle.clone(),
        "display_name": record.display_name.clone(),
        "name": record.display_name.clone(),
        "verified": record.verified,
        "verified_badge": record.verified,
        "members": record.members.iter().cloned().collect::<Vec<_>>(),
        "member_count": record.member_count.max(record.members.len()),
        "spaces": spaces,
        "space_count": space_count,
        "created_by": record.created_by.clone(),
        "created_at": record.created_at.to_rfc3339(),
        "updated_at": record.updated_at.to_rfc3339(),
    })
}

fn organization_policy_record_json(state: &AppState, record: &OrganizationPolicyRecord) -> Value {
    let applies_to_spaces = state
        .organization_spaces
        .lock()
        .expect("organization spaces lock")
        .get(&record.organization_id)
        .map(|set| set.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    json!({
        "kind": "cx.organization.moderation_policy",
        "organization_id": record.organization_id.clone(),
        "policy_id": record.policy_id.clone(),
        "version": record.version,
        "policy": record.payload.clone(),
        "applies_to_spaces": applies_to_spaces,
        "updated_by": record.updated_by.clone(),
        "updated_at": record.updated_at.to_rfc3339(),
    })
}

fn space_policy_record_json(record: &SpaceModerationPolicyRecord) -> Value {
    json!({
        "kind": "cx.realm.moderation_policy",
        "space_id": record.space_id.clone(),
        "policy": record.payload.clone(),
        "updated_by": record.updated_by.clone(),
        "updated_at": record.updated_at.to_rfc3339(),
    })
}

fn effective_rules(state: &AppState, space_id: &str) -> Vec<Value> {
    let org_ids = space_organization_ids(state, space_id);
    let policies = state
        .organization_policies
        .lock()
        .expect("organization policies lock");
    let mut rules = Vec::new();
    for org_id in org_ids {
        if let Some(policy) = policies.get(&org_id) {
            rules.extend(policy_rules(&policy.payload));
        }
    }
    drop(policies);
    if let Some(space_policy) = state
        .space_moderation_policies
        .lock()
        .expect("space moderation policies lock")
        .get(space_id)
        .cloned()
    {
        rules.extend(
            allow_join_override_targets(&space_policy.payload)
                .into_iter()
                .map(|target| {
                    json!({
                        "source": "space_override",
                        "target": { "kind": "actor", "did": target },
                        "action": "allow_join",
                    })
                }),
        );
    }
    rules
}

fn policy_rules(policy: &Value) -> Vec<Value> {
    let mut rules = Vec::new();
    if let Some(array) = policy.get("rules").and_then(Value::as_array) {
        rules.extend(array.iter().cloned());
    }
    if let Some(array) = policy.get("targets").and_then(Value::as_array) {
        for entry in array {
            if let Some(object) = entry.as_object() {
                rules.push(json!({
                    "target": {
                        "kind": object.get("kind").and_then(Value::as_str).unwrap_or("actor"),
                        "did": object
                            .get("did")
                            .or_else(|| object.get("actor_id"))
                            .or_else(|| object.get("target"))
                            .cloned()
                            .unwrap_or(Value::Null),
                    },
                    "action": object.get("action").cloned().unwrap_or_else(|| json!("deny_join")),
                    "reason_code": object.get("reason_code").cloned().unwrap_or(Value::Null),
                }));
            }
        }
    }
    rules
}

fn policy_denies_join_actor(policy: &Value, actor: &str) -> bool {
    policy_rules(policy).iter().any(|rule| {
        let action = rule
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !matches!(action, "deny_join" | "deny_restricted_join") {
            return false;
        }
        target_did(rule).is_some_and(|did| did == actor)
    })
}

fn accepted_space_override_allows_join(state: &AppState, space_id: &str, actor: &str) -> bool {
    state
        .space_moderation_policies
        .lock()
        .expect("space moderation policies lock")
        .get(space_id)
        .is_some_and(|record| allow_join_override_targets(&record.payload).contains(actor))
}

fn allow_join_override_targets(payload: &Value) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    for key in ["allow_override", "allow_overrides", "overrides"] {
        let Some(array) = payload.get(key).and_then(Value::as_array) else {
            continue;
        };
        for item in array {
            let action = item
                .get("action")
                .or_else(|| item.get("override_action"))
                .and_then(Value::as_str)
                .unwrap_or("allow_join");
            if action != "allow_join" {
                continue;
            }
            if let Some(target) = target_did(item) {
                targets.insert(target.to_owned());
            }
        }
    }
    targets
}

fn approvals_from_payload(payload: &Value) -> Vec<Value> {
    let mut approvals = Vec::new();
    for key in [
        "organization_approval",
        "organization_approvals",
        "approval",
        "approvals",
    ] {
        match payload.get(key) {
            Some(Value::Array(array)) => approvals.extend(array.iter().cloned()),
            Some(Value::Object(_)) => approvals.push(payload[key].clone()),
            _ => {}
        }
    }
    approvals
}

fn approval_matches(approval: &Value, org_ids: &BTreeSet<String>) -> bool {
    if approval.get("approved").and_then(Value::as_bool) == Some(false) {
        return false;
    }
    let Some(org_id) = approval
        .get("organization_id")
        .or_else(|| approval.get("organization_did"))
        .or_else(|| approval.get("org"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    org_ids.contains(org_id)
}

fn target_did(value: &Value) -> Option<&str> {
    value
        .get("target")
        .and_then(|target| match target {
            Value::String(s) => Some(s.as_str()),
            Value::Object(object) => object
                .get("did")
                .or_else(|| object.get("actor_id"))
                .or_else(|| object.get("member"))
                .and_then(Value::as_str),
            _ => None,
        })
        .or_else(|| value.get("target_did").and_then(Value::as_str))
        .or_else(|| value.get("did").and_then(Value::as_str))
        .or_else(|| value.get("actor_id").and_then(Value::as_str))
        .or_else(|| value.get("member").and_then(Value::as_str))
}

fn normalized_organization_id(raw: &str) -> Result<String, AppError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(AppError::invalid_param("organization_id is required"));
    }
    if value.starts_with("did:") {
        validate_did(value)
            .map_err(|_| AppError::invalid_param("organization_id DID is invalid"))?;
    } else if !value.starts_with("cx:org:") {
        return Err(AppError::invalid_param(
            "organization_id must be a DID or cx:org: identifier",
        ));
    }
    Ok(value.to_owned())
}

fn display_name_from_organization_id(organization_id: &str) -> String {
    organization_id
        .trim_start_matches("did:web:")
        .trim_start_matches("cx:org:")
        .replace(['.', '-'], " ")
}

fn safe_id_fragment(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

pub(crate) fn requires_organization_approval_error() -> AppError {
    AppError::capability_denied("requires_organization_approval")
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("requires_organization_approval")
}
