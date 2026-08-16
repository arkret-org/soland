//! Organization registry + moderation policy inheritance.
//!
//! This is the local P2 governance surface for organization-owned Realms:
//! org policies are stored once, Realm create links fan out through an index,
//! and Realm-level overrides are accepted only when the organization has
//! explicitly approved the exception.

use std::collections::BTreeSet;

use arkret_models_collaboration::governance::realm_governance::{
    REALM_MODERATION_POLICY_FANOUT_SOURCE_ORGANIZATION_POLICY,
    REALM_MODERATION_POLICY_MERGE_STRATEGY_MOST_RESTRICTIVE,
};
use arkret_state::lattice::CellState;
use chrono::Utc;
use salvo::http::StatusCode;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::util::validate_did;
use soland_services::governance::{OrganizationPolicyRecord, OrganizationRecord};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

const REALM_MODERATION_POLICY_CELL: &str = "ak:cell:ak.component.realm.moderation_policy.v1:null";

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct UpsertOrganizationRequestBody {
    #[serde(default)]
    organization_id: Option<String>,
    organization_principal_id: String,
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
    organization_principal_id: String,
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
    created_by: String,
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
    updated_by: String,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub(crate) struct RealmModerationPolicyOutcome {
    kind: String,
    realm_id: String,
    policy: Value,
    updated_by: String,
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

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct RealmModerationPolicyFanout {
    source: String,
    rewrites_realm_policy: bool,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub(crate) struct RealmEffectiveModerationPolicyOutcome {
    realm_id: String,
    inheritance_mode: String,
    #[serde(default)]
    inheritance_chain: Vec<String>,
    #[serde(default)]
    organization_policy_layers: Vec<OrganizationPolicyLayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    realm_policy: Option<RealmModerationPolicyOutcome>,
    #[serde(default)]
    effective_rules: Vec<Value>,
    override_organization_approval_required: bool,
    policy_merge_strategy: String,
    fanout: RealmModerationPolicyFanout,
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
    validate_did(&body.organization_principal_id)
        .map_err(|_| AppError::param_invalid("organization_principal_id must be a DID"))?;
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
        created_by: session.actor.clone(),
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
    organization_principal_id: PathParam<String>,
) -> JsonResult<OrganizationView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let organization_id = normalized_organization_id(&organization_principal_id.into_inner())?;
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
    organization_principal_id: PathParam<String>,
) -> JsonResult<OrganizationPolicyView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let organization_id = normalized_organization_id(&organization_principal_id.into_inner())?;
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
    organization_principal_id: PathParam<String>,
    body: JsonBody<OrganizationModerationPolicyReplaceRequestBody>,
) -> JsonResult<OrganizationPolicyView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    ensure_organization_registry_admin(state, &session.actor)?;
    let organization_id = normalized_organization_id(&organization_principal_id.into_inner())?;
    ensure_organization_placeholder(state, &organization_id, &session.actor)
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
        updated_by: session.actor.clone(),
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
    organization_principal_id: PathParam<String>,
    body: JsonBody<LinkOrganizationRealmRequestBody>,
) -> JsonResult<OrganizationRealmLinkOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    ensure_organization_registry_admin(state, &session.actor)?;
    let organization_id = normalized_organization_id(&organization_principal_id.into_inner())?;
    let body = body.into_inner();
    ensure_organization_placeholder(state, &organization_id, &session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    link_realm_to_organization(state, &body.realm_id, &organization_id)
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
    for key in [
        "organization_id",
        "organization_principal_id",
        "organization_ref",
    ] {
        if let Some(value) = object.get(key).and_then(Value::as_str) {
            orgs.push(value.to_owned());
        }
    }
    for org in orgs {
        let Ok(org_id) = normalized_organization_id(&org) else {
            continue;
        };
        if let Err(error) = ensure_organization_placeholder(state, &org_id, "realm_create").await {
            tracing::warn!(%error, organization_id = %org_id, "failed to persist organization placeholder from Realm event");
            continue;
        }
        if let Err(error) = link_realm_to_organization(state, realm_id, &org_id).await {
            tracing::warn!(%error, %realm_id, organization_id = %org_id, "failed to persist Realm organization link");
        }
    }
}

pub(crate) async fn link_realm_to_organization(
    state: &AppState,
    realm_id: &str,
    organization_id: &str,
) -> soland_services::ServiceResult<()> {
    state
        .governance()
        .link_realm_organization(realm_id, organization_id)
        .await?;
    Ok(())
}

/// SOL-ORG-05 — declared `owning_organizations` hint ids for a Realm. Display /
/// discovery surface ONLY; never use this to drive policy inheritance.
pub(crate) fn realm_organization_ids(state: &AppState, realm_id: &str) -> Vec<String> {
    state.governance().cached_realm_organizations(realm_id)
}

/// SOL-ORG-05 — the organization DIDs whose active, in-window
/// `ak.realm.organization` statement endorses `realm_id` with a
/// `moderation_policy` control scope. This is the ONLY basis on which an
/// organization's moderation policy may flow into the Realm's effective policy;
/// `owning_organizations` declared hints no longer qualify. Returns a stable,
/// de-duplicated, sorted list.
pub(crate) fn verified_moderation_organization_ids(
    state: &AppState,
    realm_id: &str,
) -> Vec<String> {
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

pub(crate) async fn effective_policy_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<RealmEffectiveModerationPolicyOutcome, AppError> {
    // SOL-ORG-05 — only organizations with a verified, active, in-window
    // `ak.realm.organization` statement carrying the `moderation_policy`
    // control scope drive the effective moderation policy. Declared
    // `owning_organizations` hints no longer qualify.
    let org_ids = verified_moderation_organization_ids(state, realm_id);
    let org_layers = state
        .governance()
        .cached_organization_policies(&org_ids)
        .into_iter()
        .map(|(org_id, policy)| OrganizationPolicyLayer {
            source: "organization".to_owned(),
            organization_id: org_id.clone(),
            policy_id: policy.policy_id.clone(),
            version: policy.version,
            policy: policy.payload.clone(),
            applies_to_realms: state.governance().cached_organization_realms(&org_id),
        })
        .collect::<Vec<_>>();

    let realm_policy = current_realm_policy_outcome(state, realm_id).await?;
    let has_organization_inheritance = !org_ids.is_empty();
    Ok(RealmEffectiveModerationPolicyOutcome {
        realm_id: realm_id.to_owned(),
        inheritance_mode: if has_organization_inheritance {
            "organization".to_owned()
        } else {
            "none".to_owned()
        },
        inheritance_chain: org_ids,
        organization_policy_layers: org_layers,
        realm_policy,
        effective_rules: effective_rules(state, realm_id),
        override_organization_approval_required: has_organization_inheritance,
        // content-moderation.md §7 — when a Realm names more than one owning
        // organization, the inherited layers combine most-restrictively: a join
        // / write is denied if ANY owning organization denies it (union of deny
        // rules). `organization_policy_blocks_join` already evaluates this union
        // across all linked organizations; this field surfaces the merge
        // semantics so a cross-organization Realm can be reasoned about.
        policy_merge_strategy: REALM_MODERATION_POLICY_MERGE_STRATEGY_MOST_RESTRICTIVE.to_owned(),
        fanout: RealmModerationPolicyFanout {
            source: REALM_MODERATION_POLICY_FANOUT_SOURCE_ORGANIZATION_POLICY.to_owned(),
            rewrites_realm_policy: false,
        },
    })
}

pub(crate) async fn effective_policy_value_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<Value, AppError> {
    serde_json::to_value(effective_policy_for_realm(state, realm_id).await?)
        .map_err(|error| AppError::internal(format!("serialize effective policy: {error}")))
}

pub(crate) async fn organization_policy_blocks_join(
    state: &AppState,
    realm_id: &str,
    actor: &str,
) -> bool {
    if let Err(error) = refresh_organization_projection(state).await {
        tracing::warn!(%error, "failed to refresh organization projection for join policy");
    }
    if accepted_realm_override_allows_join(state, realm_id, actor) {
        return false;
    }
    // SOL-ORG-05 — only verified moderation-scoped organizations gate joins.
    let org_ids = verified_moderation_organization_ids(state, realm_id);
    if org_ids.is_empty() {
        return false;
    }
    org_ids.iter().any(|org_id| {
        state
            .governance()
            .cached_organization_policy(org_id)
            .is_some_and(|policy| policy_denies_join_actor(&policy.payload, actor))
    })
}

pub(crate) async fn realm_policy_override_requires_approval(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> bool {
    if let Err(error) = refresh_organization_projection(state).await {
        tracing::warn!(%error, "failed to refresh organization projection for policy override");
    }
    realm_policy_override_requires_approval_cached(state, realm_id, payload)
}

fn realm_policy_override_requires_approval_cached(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> bool {
    let targets = allow_join_override_targets(payload);
    if targets.is_empty() {
        return false;
    }
    // SOL-ORG-05 — only verified moderation-scoped organizations' deny rules
    // require a Realm override to be approved.
    let org_ids = verified_moderation_organization_ids(state, realm_id);
    if org_ids.is_empty() {
        return false;
    }
    targets.iter().any(|target| {
        org_ids.iter().any(|org_id| {
            state
                .governance()
                .cached_organization_policy(org_id)
                .is_some_and(|policy| policy_denies_join_actor(&policy.payload, target))
        })
    })
}

pub(crate) async fn realm_policy_override_has_approval(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> bool {
    if let Err(error) = refresh_organization_projection(state).await {
        tracing::warn!(%error, "failed to refresh organization projection for policy approval");
    }
    if !realm_policy_override_requires_approval_cached(state, realm_id, payload) {
        return true;
    }
    // content-moderation.md §7 — most-restrictive cross-organization merge:
    // every owning organization that denies one of the override targets MUST
    // independently approve the override. An approval from an unrelated owning
    // organization (one that does not deny the target) does not satisfy the
    // denying organization's gate.
    let denying_org_ids = organizations_denying_override_targets(state, realm_id, payload);
    if denying_org_ids.is_empty() {
        return true;
    }
    let approvals = approvals_from_payload(payload);
    denying_org_ids.iter().all(|org_id| {
        let single = BTreeSet::from([org_id.clone()]);
        approvals
            .iter()
            .any(|approval| approval_matches(approval, &single))
    })
}

/// The verified moderation-scoped organizations of `realm_id` whose policy
/// denies at least one of the `allow_join` override targets carried in
/// `payload`. Drives the most-restrictive approval gate: each such organization
/// MUST approve. SOL-ORG-05 — declared `owning_organizations` hints do not
/// participate.
fn organizations_denying_override_targets(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> BTreeSet<String> {
    let targets = allow_join_override_targets(payload);
    if targets.is_empty() {
        return BTreeSet::new();
    }
    let org_ids = verified_moderation_organization_ids(state, realm_id);
    org_ids
        .into_iter()
        .filter(|org_id| {
            state
                .governance()
                .cached_organization_policy(org_id)
                .is_some_and(|policy| {
                    targets
                        .iter()
                        .any(|target| policy_denies_join_actor(&policy.payload, target))
                })
        })
        .collect()
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
    actor: &str,
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
        organization_principal_id: organization_id.to_owned(),
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
        created_by: actor.to_owned(),
        created_at: now,
        updated_at: now,
    };
    state.governance().store_organization(&record).await?;
    Ok(())
}

fn organization_record_view(state: &AppState, record: &OrganizationRecord) -> OrganizationView {
    let realms = state
        .governance()
        .cached_organization_realms(&record.organization_id);
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
        .cached_organization_realms(&record.organization_id);
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

pub(crate) fn realm_policy_event_outcome(
    realm_id: &str,
    policy: Value,
    updated_by: &str,
    updated_at: chrono::DateTime<Utc>,
) -> RealmModerationPolicyOutcome {
    RealmModerationPolicyOutcome {
        kind: arkret_wire::event_kind_str::REALM_MODERATION_POLICY.to_owned(),
        realm_id: realm_id.to_owned(),
        policy,
        updated_by: updated_by.to_owned(),
        updated_at: arkret_canonical::format_timestamp_canonical(updated_at),
    }
}

async fn current_realm_policy_outcome(
    state: &AppState,
    realm_id: &str,
) -> Result<Option<RealmModerationPolicyOutcome>, AppError> {
    let Some(policy) = current_realm_policy_value(state, realm_id)? else {
        return Ok(None);
    };
    let projected = state
        .event_queries()
        .projected_events_for_realm(realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let event = projected
        .into_iter()
        .filter(|event| {
            event.event_kind == arkret_wire::EventKind::RealmModerationPolicy
                && event.payload.get("value") == Some(&policy)
        })
        .max_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.event_id.cmp(&right.event_id))
        })
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "settled realm moderation policy has no accepted Event projection",
            )
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_wire_code("failed_precondition")
        })?;
    let sender = event.sender.ok_or_else(|| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "settled realm moderation policy Event has no actor projection",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("failed_precondition")
    })?;
    Ok(Some(realm_policy_event_outcome(
        realm_id,
        policy,
        &sender,
        event.created_at,
    )))
}

fn current_realm_policy_value(state: &AppState, realm_id: &str) -> Result<Option<Value>, AppError> {
    let snapshot = state.projections().snapshot();
    let key = (realm_id.to_owned(), REALM_MODERATION_POLICY_CELL.to_owned());
    let payload = match snapshot.realm_null_subject_cells.get(&key) {
        Some(CellState::Bottom(_)) => {
            return Err(AppError::new(
                ErrorCode::FailedPrecondition,
                "realm moderation policy cell is in Bottom",
            )
            .with_status(StatusCode::CONFLICT)
            .with_wire_code("failed_bottom"));
        }
        Some(CellState::Value(payload)) => payload,
        None => return Ok(None),
    };
    let Some(policy) = payload.get("value").filter(|value| value.is_object()) else {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "settled realm moderation policy cell has an invalid value",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("failed_precondition"));
    };
    Ok(Some(policy.clone()))
}

fn effective_rules(state: &AppState, realm_id: &str) -> Vec<Value> {
    // SOL-ORG-05 — effective rules are sourced only from verified
    // moderation-scoped organizations.
    let org_ids = verified_moderation_organization_ids(state, realm_id);
    let mut rules = Vec::new();
    for org_id in org_ids {
        if let Some(policy) = state.governance().cached_organization_policy(&org_id) {
            rules.extend(policy_rules(&policy.payload));
        }
    }
    if let Some(realm_policy) = current_realm_policy_value(state, realm_id).ok().flatten() {
        rules.extend(
            allow_join_override_targets(&realm_policy)
                .into_iter()
                .map(|target| {
                    json!({
                        "source": "realm_override",
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

fn accepted_realm_override_allows_join(state: &AppState, realm_id: &str, actor: &str) -> bool {
    current_realm_policy_value(state, realm_id)
        .ok()
        .flatten()
        .is_some_and(|policy| allow_join_override_targets(&policy).contains(actor))
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
        .or_else(|| approval.get("organization_principal_id"))
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
        return Err(AppError::param_invalid("organization_id is required"));
    }
    if value.starts_with("did:") {
        validate_did(value)
            .map_err(|_| AppError::param_invalid("organization_id DID is invalid"))?;
    } else if !value.starts_with("ak:org:") {
        return Err(AppError::param_invalid(
            "organization_id must be a DID or ak:org: identifier",
        ));
    }
    Ok(value.to_owned())
}

fn display_name_from_organization_id(organization_id: &str) -> String {
    organization_id
        .trim_start_matches("did:web:")
        .trim_start_matches("ak:org:")
        .replace(['.', '-'], " ")
}

fn safe_id_fragment(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

pub(crate) fn requires_organization_approval_error() -> AppError {
    AppError::new(
        ErrorCode::FailedPrecondition,
        "realm moderation policy override requires organization approval",
    )
    .with_status(StatusCode::CONFLICT)
    .with_reason_code(arkret_wire::ReasonCode::REQUIRES_ORGANIZATION_APPROVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_approval_rejection_uses_failed_precondition_layering() {
        let error = requires_organization_approval_error();

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(error.http_status(), StatusCode::CONFLICT);
        assert_eq!(error.wire_code(), "failed_precondition");
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::REQUIRES_ORGANIZATION_APPROVAL)
        );
    }
}
