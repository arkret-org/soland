//! Organization registry + moderation policy inheritance.
//!
//! This is the local P2 governance surface for organization-owned Realms:
//! org policies are stored once, Realm create links fan out through an index,
//! and linked Realm projections consume the effective organization policy.

use std::collections::BTreeSet;

use arkret_wire::{ActorId, DidCoreId};
use chrono::Utc;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soland_http::error::AppError;
use soland_services::governance::OrganizationRecord;

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct UpsertOrganizationRequestBody {
    organization_id: DidCoreId,
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

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub(crate) struct OrganizationView {
    organization_id: String,
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

pub(crate) fn router() -> Router {
    Router::with_path("organizations")
        .get(list_organizations)
        .post(upsert_organization)
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
    let links = state.governance().realm_organization_links().await?;
    state
        .governance()
        .replace_organization_projection(organizations, links);

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
    let organization_id = normalized_organization_id(body.organization_id.as_str())?;
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

pub(crate) async fn record_realm_organizations_from_event(
    state: &AppState,
    realm_id: &str,
    envelope: &Value,
) -> soland_services::ServiceResult<()> {
    let Some(actor) = envelope
        .get("actor_id")
        .and_then(|actor| serde_json::from_value::<ActorId>(actor.clone()).ok())
    else {
        tracing::warn!(%realm_id, "Realm organization projection lacks a valid actor_id");
        return Ok(());
    };
    // This placeholder's created_by is a display/discovery principal, not
    // policy authority. Decode the complete Event Actor before projecting it.
    let created_by = actor.signing_principal_id();
    let Some(object) = envelope
        .pointer("/payload/object")
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    let organization_ids = match declared_organization_ids(object) {
        Ok(organization_ids) => organization_ids,
        Err(error) => {
            tracing::warn!(%realm_id, %error, "Realm organization projection contains invalid owning_organization_ids");
            return Ok(());
        }
    };
    for organization_id in organization_ids {
        let org_id = organization_id.to_string();
        ensure_organization_placeholder(state, &org_id, created_by).await?;
        link_realm_to_organization(state, realm_id, &organization_id).await?;
    }
    Ok(())
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

pub(crate) async fn organization_policy_blocks_join(
    state: &AppState,
    realm_id: &str,
    actor: &ActorId,
) -> bool {
    let _ = actor;
    if let Err(error) = refresh_organization_projection(state).await {
        tracing::warn!(%error, "failed to refresh organization projection for join policy");
        return true;
    }
    unresolved_moderation_policy_authority(state, realm_id)
}

pub(crate) fn organization_policy_blocks_federation(
    state: &AppState,
    realm_id: &str,
    peer_service_id: &DidCoreId,
) -> bool {
    let _ = peer_service_id;
    unresolved_moderation_policy_authority(state, realm_id)
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
    let organization_id = DidCoreId::new(record.organization_id.clone())
        .expect("stored organization id remains a DID core id");
    let realms = state
        .governance()
        .cached_organization_realms(&organization_id);
    let realm_count = realms.len();
    OrganizationView {
        organization_id: record.organization_id.clone(),
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

/// The policy governance Realm is unique, but no accepted Event/Commit-backed
/// current-policy reader is wired yet. A verified moderation relationship
/// therefore blocks the sensitive action until that reader is available.
fn unresolved_moderation_policy_authority(state: &AppState, realm_id: &str) -> bool {
    state
        .projections()
        .snapshot()
        .verified_organization_relationships(realm_id, Utc::now())
        .into_iter()
        .any(|relationship| relationship.covers_scope("moderation_policy"))
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
