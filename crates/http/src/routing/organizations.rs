//! Organization registry + moderation policy inheritance.
//!
//! This is the local P2 governance surface for organization-owned Realms:
//! org policies are stored once, Realm create links fan out through an index,
//! and linked Realm projections consume the effective organization policy.

use std::collections::BTreeSet;

use arkret_wire::DidCoreId;
use chrono::Utc;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_services::governance::{OrganizationPolicyRecord, OrganizationRecord};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct UpsertOrganizationRequestBody {
    #[serde(default)]
    organization_id: Option<String>,
    organization_principal_id: DidCoreId,
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

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct LinkOrganizationRealmRequestBody {
    realm_id: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub(crate) struct OrganizationView {
    organization_id: String,
    organization_principal_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
    display_name: String,
    #[serde(default)]
    source_refs: Vec<String>,
    policy_revision: String,
    verified: bool,
    verified_badge: bool,
    #[serde(default)]
    members: Vec<String>,
    member_count: usize,
    #[serde(default)]
    realms: Vec<String>,
    realm_count: usize,
    created_by: DidCoreId,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct OrganizationListOutcome {
    organizations: Vec<OrganizationView>,
    total: usize,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub(crate) struct OrganizationPolicyView {
    kind: String,
    organization_id: String,
    policy_id: String,
    version: u64,
    policy: Value,
    #[serde(default)]
    applies_to_realms: Vec<String>,
    updated_by: DidCoreId,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct OrganizationRealmLinkOutcome {
    organization_id: String,
    realm_id: String,
    linked: bool,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct OrganizationPolicyLayer {
    source: String,
    organization_id: String,
    policy_id: String,
    version: u64,
    policy: Value,
    #[serde(default)]
    applies_to_realms: Vec<String>,
}

#[derive(Debug, salvo::oapi::ToSchema)]
struct OrganizationModerationPolicyReplaceRequestBody(serde_json::Map<String, Value>);

impl<'de> Deserialize<'de> for OrganizationModerationPolicyReplaceRequestBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::Object(object) => Ok(Self(object)),
            _ => Err(serde::de::Error::custom(
                "organization moderation policy must be a JSON object",
            )),
        }
    }
}

impl From<OrganizationModerationPolicyReplaceRequestBody> for Value {
    fn from(body: OrganizationModerationPolicyReplaceRequestBody) -> Self {
        Value::Object(body.0)
    }
}

pub(crate) fn router() -> Router {
    Router::with_path("organizations")
        .get(list_organizations)
        .post(upsert_organization)
        .push(
            Router::with_path("{organization_principal_id}")
                .get(get_organization)
                .push(Router::with_path("policy").get(get_organization_policy))
                .push(Router::with_path("policy").post(upsert_organization_policy))
                .push(Router::with_path("realms").post(link_organization_realm)),
        )
}

fn ensure_organization_registry_admin(state: &AppState, actor: &str) -> Result<(), AppError> {
    if state.is_admin_principal(actor) {
        return Ok(());
    }
    Err(AppError::capability_denied(
        "organization registry write requires a server administrator",
    ))
}

pub(crate) async fn refresh_organization_projection(
    state: &AppState,
) -> soland_services::ServiceResult<()> {
    let organizations = state.governance().organizations().await?;
    let policies = state.governance().organization_policies().await?;
    let links = state.governance().realm_organization_links().await?;
    state
        .governance()
        .replace_organization_projection(organizations, policies, links);

    Ok(())
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.query.list",
    summary = "List organizations",
    tags("organizations")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.organization.query.list"))]
async fn list_organizations(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OrganizationListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut rows = state
        .governance()
        .cached_organizations()
        .iter()
        .map(|record| organization_record_view(state, record))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.display_name.cmp(&right.display_name));
    let total = rows.len();
    json_ok(OrganizationListOutcome {
        organizations: rows,
        total,
    })
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.command.upsert",
    summary = "Create or update an organization",
    tags("organizations")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.organization.command.upsert"))]
async fn upsert_organization(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<UpsertOrganizationRequestBody>,
) -> JsonResult<OrganizationView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    // Registering an organization (a verified, listable org-principal record) is
    // a deployment-governance act, gated to the server's configured admin
    // principals — not every authenticated user may mint organizations.
    ensure_organization_registry_admin(state, &session.actor)?;
    let body = body.into_inner();
    let now = Utc::now();
    let organization_id = normalized_organization_id(
        body.organization_id
            .as_deref()
            .unwrap_or(body.organization_principal_id.as_str()),
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
        organization_principal_id: body.organization_principal_id,
        handle: body.handle,
        display_name,
        // No source Event stands behind a locally registered organization.
        source_refs: Vec::new(),
        policy_revision: "local".to_owned(),
        verified: body.verified.unwrap_or(true),
        members,
        member_count,
        created_by: DidCoreId::new(session.actor.clone()).map_err(|error| {
            AppError::param_invalid(format!("authenticated principal_id: {error}"))
        })?,
        created_at: now,
        updated_at: now,
    };
    state
        .governance()
        .store_organization(&record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(organization_record_view(state, &record))
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.resource.get",
    summary = "Get an organization",
    tags("organizations")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.organization.resource.get"))]
async fn get_organization(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_principal_id: PathParam<DidCoreId>,
) -> JsonResult<OrganizationView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let organization_principal_id = organization_principal_id.into_inner();
    let organization_id = normalized_organization_id(organization_principal_id.as_str())?;
    let record = state
        .governance()
        .cached_organization(&organization_id)
        .ok_or_else(|| AppError::not_found("organization not found"))?;
    json_ok(organization_record_view(state, &record))
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.policy.resource.get",
    summary = "Get an organization moderation policy",
    tags("organizations")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.organization.policy.resource.get")
)]
async fn get_organization_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_principal_id: PathParam<DidCoreId>,
) -> JsonResult<OrganizationPolicyView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let organization_principal_id = organization_principal_id.into_inner();
    let organization_id = normalized_organization_id(organization_principal_id.as_str())?;
    let policy = state
        .governance()
        .cached_organization_policy(&organization_id)
        .ok_or_else(|| AppError::not_found("organization policy not found"))?;
    json_ok(organization_policy_record_view(state, &policy))
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.policy.resource.replace",
    summary = "Replace an organization moderation policy",
    tags("organizations")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.organization.policy.resource.replace")
)]
async fn upsert_organization_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_principal_id: PathParam<DidCoreId>,
    body: JsonBody<OrganizationModerationPolicyReplaceRequestBody>,
) -> JsonResult<OrganizationPolicyView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    ensure_organization_registry_admin(state, &session.actor)?;
    let organization_id =
        normalized_organization_id(organization_principal_id.into_inner().as_str())?;
    let actor_id = DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::param_invalid(format!("authenticated principal_id: {error}")))?;
    ensure_organization_placeholder(state, &organization_id, &actor_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut payload = Value::from(body.into_inner());
    if !payload.is_object() {
        return Err(AppError::json_invalid(
            "organization moderation policy must be a JSON object",
        ));
    }
    if payload.get("kind").and_then(Value::as_str).is_none() {
        payload.as_object_mut().expect("object checked").insert(
            "kind".to_owned(),
            json!(arkret_wire::event_kind_str::ORGANIZATION_MODERATION_POLICY),
        );
    }
    if payload
        .get("organization_principal_id")
        .and_then(Value::as_str)
        .is_none()
    {
        payload.as_object_mut().expect("object checked").insert(
            "organization_principal_id".to_owned(),
            json!(organization_id.clone()),
        );
    }
    let now = Utc::now();
    let version = state
        .governance()
        .organization_policy(&organization_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .map(|policy| policy.version.saturating_add(1))
        .unwrap_or(1);
    let policy_id = payload
        .get("policy_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "ak:org-policy:{}:{version}",
                safe_id_fragment(&organization_id)
            )
        });
    let record = OrganizationPolicyRecord {
        organization_id: organization_id.clone(),
        policy_id,
        payload,
        version,
        updated_by: DidCoreId::new(session.actor.clone()).map_err(|error| {
            AppError::param_invalid(format!("authenticated principal_id: {error}"))
        })?,
        updated_at: now,
    };
    state
        .governance()
        .store_organization_policy(&record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(organization_policy_record_view(state, &record))
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.realm.command.link",
    summary = "Link a realm to an organization",
    tags("organizations")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.organization.realm.command.link")
)]
async fn link_organization_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_principal_id: PathParam<DidCoreId>,
    body: JsonBody<LinkOrganizationRealmRequestBody>,
) -> JsonResult<OrganizationRealmLinkOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    ensure_organization_registry_admin(state, &session.actor)?;
    let organization_principal_id = organization_principal_id.into_inner();
    let organization_id = normalized_organization_id(organization_principal_id.as_str())?;
    let body = body.into_inner();
    let actor_id = DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::param_invalid(format!("authenticated principal_id: {error}")))?;
    ensure_organization_placeholder(state, &organization_id, &actor_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    link_realm_to_organization(state, &body.realm_id, &organization_principal_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(OrganizationRealmLinkOutcome {
        organization_id,
        realm_id: body.realm_id,
        linked: true,
    })
}

pub(crate) async fn record_realm_organizations_from_event(
    state: &AppState,
    realm_id: &str,
    envelope: &Value,
) {
    let Some(created_by) = envelope
        .get("actor_id")
        .and_then(Value::as_str)
        .and_then(|actor_id| DidCoreId::new(actor_id.to_owned()).ok())
    else {
        tracing::warn!(%realm_id, "Realm organization projection lacks a valid actor_id");
        return;
    };
    let Some(object) = envelope
        .pointer("/payload/object")
        .and_then(Value::as_object)
    else {
        return;
    };
    let organization_ids = match declared_organization_ids(object) {
        Ok(organization_ids) => organization_ids,
        Err(error) => {
            tracing::warn!(%realm_id, %error, "Realm organization projection contains invalid owning_organization_ids");
            return;
        }
    };
    for organization_principal_id in organization_ids {
        let org_id = organization_principal_id.to_string();
        if let Err(error) = ensure_organization_placeholder(state, &org_id, &created_by).await {
            tracing::warn!(%error, organization_id = %org_id, "failed to persist organization placeholder from Realm event");
            continue;
        }
        if let Err(error) =
            link_realm_to_organization(state, realm_id, &organization_principal_id).await
        {
            tracing::warn!(%error, %realm_id, organization_id = %org_id, "failed to persist Realm organization link");
        }
    }
}

fn declared_organization_ids(
    object: &serde_json::Map<String, Value>,
) -> Result<Vec<DidCoreId>, String> {
    let Some(value) = object.get("owning_organization_ids") else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| "owning_organization_ids must be an array".to_owned())?;
    array
        .iter()
        .map(|value| {
            let raw = value
                .as_str()
                .ok_or_else(|| "owning_organization_ids entries must be strings".to_owned())?;
            DidCoreId::new(raw).map_err(|_| {
                "owning_organization_ids entries must be DID core identifiers".to_owned()
            })
        })
        .collect()
}

pub(crate) async fn link_realm_to_organization(
    state: &AppState,
    realm_id: &str,
    organization_id: &DidCoreId,
) -> soland_services::ServiceResult<()> {
    state
        .governance()
        .link_realm_organization(realm_id, organization_id)
        .await?;
    Ok(())
}

/// SOL-ORG-05 — declared `owning_organization_ids` hints for a Realm. Display /
/// discovery surface ONLY; never use this to drive policy inheritance.
pub(crate) fn realm_organization_ids(state: &AppState, realm_id: &str) -> Vec<DidCoreId> {
    state.governance().cached_realm_organizations(realm_id)
}

/// SOL-ORG-05 — the stable organization ids whose active, in-window
/// `ak.realm.organization` statement endorses `realm_id` with a
/// `moderation_policy` control scope. This is the ONLY basis on which an
/// organization's moderation policy may flow into the Realm's effective policy;
/// `owning_organization_ids` declared hints no longer qualify. Returns a stable,
/// de-duplicated, sorted list.
pub(crate) fn verified_moderation_organization_ids(
    state: &AppState,
    realm_id: &str,
) -> Vec<DidCoreId> {
    let now = Utc::now();
    let proj = state.projections().snapshot();
    let mut ids = proj.verified_organizations_with_scope(
        realm_id,
        arkret_models_collaboration::RealmOrganizationControlScope::ModerationPolicy,
        now,
    );
    ids.sort();
    ids.dedup();
    ids
}

pub(crate) fn effective_policy_value_for_realm(state: &AppState, realm_id: &str) -> Value {
    // SOL-ORG-05 — only organizations with a verified, active, in-window
    // `ak.realm.organization` statement carrying the `moderation_policy`
    // control scope drive the effective moderation policy. Declared
    // `owning_organization_ids` hints no longer qualify.
    let org_ids = verified_moderation_organization_ids(state, realm_id);
    let directory_org_ids = org_ids.iter().map(ToString::to_string).collect::<Vec<_>>();
    let org_layers = state
        .governance()
        .cached_organization_policies(&directory_org_ids)
        .into_iter()
        .map(|(org_id, policy)| {
            let organization_principal_id = DidCoreId::new(org_id.clone())
                .expect("verified organization id remains a DID core id");
            OrganizationPolicyLayer {
                source: "organization".to_owned(),
                organization_id: org_id.clone(),
                policy_id: policy.policy_id.clone(),
                version: policy.version,
                policy: policy.payload.clone(),
                applies_to_realms: state
                    .governance()
                    .cached_organization_realms(&organization_principal_id),
            }
        })
        .collect::<Vec<_>>();

    json!({
        "organization_policy_layers": org_layers,
        "effective_rules": effective_rules(state, realm_id),
        "policy_merge_strategy": "most_restrictive",
    })
}

pub(crate) async fn organization_policy_blocks_join(
    state: &AppState,
    realm_id: &str,
    actor: &str,
) -> bool {
    if let Err(error) = refresh_organization_projection(state).await {
        tracing::warn!(%error, "failed to refresh organization projection for join policy");
    }
    // SOL-ORG-05 — only verified moderation-scoped organizations gate joins.
    let org_ids = verified_moderation_organization_ids(state, realm_id);
    if org_ids.is_empty() {
        return false;
    }
    org_ids.iter().any(|org_id| {
        state
            .governance()
            .cached_organization_policy(org_id.as_str())
            .is_some_and(|policy| policy_denies_join_actor(&policy.payload, actor))
    })
}

pub(crate) fn organization_records_for_directory(state: &AppState) -> Vec<Value> {
    state
        .governance()
        .cached_organizations()
        .iter()
        .map(|record| organization_record_json(state, record))
        .collect()
}

async fn ensure_organization_placeholder(
    state: &AppState,
    organization_id: &str,
    actor: &DidCoreId,
) -> soland_services::ServiceResult<()> {
    if state
        .governance()
        .organization(organization_id)
        .await?
        .is_some()
    {
        return Ok(());
    }
    let now = Utc::now();
    let record = OrganizationRecord {
        organization_id: organization_id.to_owned(),
        organization_principal_id: arkret_wire::DidCoreId::new(organization_id).map_err(
            |error| {
                soland_services::ServiceError::internal(format!(
                    "normalized organization principal is invalid: {error}"
                ))
            },
        )?,
        handle: None,
        display_name: display_name_from_organization_id(organization_id),
        // A placeholder record for an organization this server only knows locally:
        // there is no Event to point at, and `directory-operations.schema.json`
        // takes an omitted `source_refs` over a minted id for an Event nobody
        // authored. `policy_revision: "local"` is what marks the entry.
        source_refs: Vec::new(),
        policy_revision: "local".to_owned(),
        verified: false,
        members: BTreeSet::new(),
        member_count: 0,
        created_by: actor.clone(),
        created_at: now,
        updated_at: now,
    };
    state.governance().store_organization(&record).await?;
    Ok(())
}

fn organization_record_view(state: &AppState, record: &OrganizationRecord) -> OrganizationView {
    let realms = state
        .governance()
        .cached_organization_realms(&record.organization_principal_id);
    let realm_count = realms.len();
    OrganizationView {
        organization_id: record.organization_id.clone(),
        organization_principal_id: record.organization_principal_id.clone(),
        handle: record.handle.clone(),
        display_name: record.display_name.clone(),
        source_refs: record.source_refs.clone(),
        policy_revision: record.policy_revision.clone(),
        verified: record.verified,
        verified_badge: record.verified,
        members: record.members.iter().cloned().collect::<Vec<_>>(),
        member_count: record.member_count.max(record.members.len()),
        realms,
        realm_count,
        created_by: record.created_by.clone(),
        created_at: arkret_canonical::format_timestamp_canonical(record.created_at),
        updated_at: arkret_canonical::format_timestamp_canonical(record.updated_at),
    }
}

fn organization_record_json(state: &AppState, record: &OrganizationRecord) -> Value {
    serde_json::to_value(organization_record_view(state, record)).unwrap_or(Value::Null)
}

fn organization_policy_record_view(
    state: &AppState,
    record: &OrganizationPolicyRecord,
) -> OrganizationPolicyView {
    let applies_to_realms = state
        .governance()
        .cached_organization(&record.organization_id)
        .map(|organization| {
            state
                .governance()
                .cached_organization_realms(&organization.organization_principal_id)
        })
        .unwrap_or_default();
    OrganizationPolicyView {
        kind: arkret_wire::event_kind_str::ORGANIZATION_MODERATION_POLICY.to_owned(),
        organization_id: record.organization_id.clone(),
        policy_id: record.policy_id.clone(),
        version: record.version,
        policy: record.payload.clone(),
        applies_to_realms,
        updated_by: record.updated_by.clone(),
        updated_at: arkret_canonical::format_timestamp_canonical(record.updated_at),
    }
}

fn effective_rules(state: &AppState, realm_id: &str) -> Vec<Value> {
    // SOL-ORG-05 — effective rules are sourced only from verified
    // moderation-scoped organizations.
    let org_ids = verified_moderation_organization_ids(state, realm_id);
    let mut rules = Vec::new();
    for org_id in org_ids {
        if let Some(policy) = state
            .governance()
            .cached_organization_policy(org_id.as_str())
        {
            rules.extend(policy_rules(&policy.payload));
        }
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
                        "actor_id": object
                            .get("actor_id")
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
        target_actor_id(rule).is_some_and(|actor_id| actor_id == actor)
    })
}

fn target_actor_id(value: &Value) -> Option<&str> {
    value
        .get("target")
        .and_then(Value::as_object)
        .and_then(|target| target.get("actor_id"))
        .and_then(Value::as_str)
}

fn normalized_organization_id(raw: &str) -> Result<String, AppError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(AppError::param_invalid("organization_id is required"));
    }
    arkret_identifiers::DidCoreId::new(value.to_owned())
        .map(|id| id.to_string())
        .map_err(|_| AppError::param_invalid("organization_id must be a DID core identifier"))
}

fn display_name_from_organization_id(organization_id: &str) -> String {
    organization_id
        .trim_start_matches("ak:did_core:")
        .replace(['.', '-'], " ")
}

fn safe_id_fragment(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_organization_ids_accept_only_the_canonical_typed_array() {
        let object = serde_json::json!({
            "owning_organization_ids": [
                "ak:did_core:webvh:zOrganizationA",
                "ak:did_core:webvh:zOrganizationB"
            ]
        });
        let ids = declared_organization_ids(object.as_object().unwrap()).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].as_str(), "ak:did_core:webvh:zOrganizationA");
    }

    #[test]
    fn declared_organization_ids_fail_closed_on_any_invalid_entry() {
        let object = serde_json::json!({
            "owning_organization_ids": [
                "ak:did_core:webvh:zOrganizationA",
                "did:webvh:zOrganizationB:organization.example"
            ]
        });
        assert!(declared_organization_ids(object.as_object().unwrap()).is_err());
    }

    #[test]
    fn declared_organization_ids_do_not_read_legacy_single_value_fields() {
        let object = serde_json::json!({
            "organization_id": "ak:did_core:webvh:zOrganizationA",
            "organization_principal_id": "ak:did_core:webvh:zOrganizationB",
            "organization_ref": "ak:did_core:webvh:zOrganizationC"
        });
        assert!(
            declared_organization_ids(object.as_object().unwrap())
                .unwrap()
                .is_empty()
        );
    }
}
