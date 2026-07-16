//! Organization registry + moderation policy inheritance.
//!
//! This is the local P2 governance surface for organization-owned Realms:
//! org policies are stored once, Realm create links fan out through an index,
//! and Realm-level overrides are accepted only when the organization has
//! explicitly approved the exception.

use std::collections::BTreeSet;

use arkret_sdk::{
    REALM_MODERATION_POLICY_FANOUT_SOURCE_ORGANIZATION_POLICY,
    REALM_MODERATION_POLICY_MERGE_STRATEGY_MOST_RESTRICTIVE,
};
use chrono::Utc;
use salvo::http::StatusCode;
use salvo::oapi::ToSchema;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{AppError, ErrorCode};
use crate::routing::system::extract::AuthArgs;
use crate::routing::system::util::validate_did;
use crate::state::{
    AppState, OrganizationPolicyRecord, OrganizationRecord, RealmModerationPolicyRecord,
};
use crate::{JsonResult, ids, json_ok};

#[derive(Debug, Deserialize, ToSchema)]
struct UpsertOrganizationRequestBody {
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
struct LinkOrganizationRealmRequestBody {
    realm_id: String,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OrganizationView {
    organization_id: String,
    organization_did: String,
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

#[derive(Clone, Debug, Serialize, ToSchema)]
struct OrganizationListOutcome {
    organizations: Vec<OrganizationView>,
    total: usize,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
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

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct RealmModerationPolicyOutcome {
    kind: String,
    realm_id: String,
    policy: Value,
    updated_by: String,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
struct OrganizationRealmLinkOutcome {
    organization_id: String,
    realm_id: String,
    linked: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
struct OrganizationPolicyLayer {
    source: String,
    organization_id: String,
    policy_id: String,
    version: u64,
    policy: Value,
    #[serde(default)]
    applies_to_realms: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
struct RealmModerationPolicyFanout {
    source: String,
    rewrites_realm_policy: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
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
    override_requires_organization_approval: bool,
    policy_merge_strategy: String,
    fanout: RealmModerationPolicyFanout,
}

#[derive(Debug)]
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

impl ToSchema for OrganizationModerationPolicyReplaceRequestBody {
    fn to_schema(
        components: &mut salvo::oapi::Components,
    ) -> salvo::oapi::RefOr<salvo::oapi::schema::Schema> {
        serde_json::Map::<String, Value>::to_schema(components)
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
            Router::with_path("{organization_did}")
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
) -> Result<(), crate::persistence::PersistenceError> {
    let organizations = state.persistence.organizations().list().await?;
    {
        let mut map = state.organizations.lock();
        for record in organizations {
            map.insert(record.organization_id.clone(), record);
        }
    }

    let policies = state
        .persistence
        .organization_policies()
        .snapshot_all()
        .await?;
    {
        let mut map = state.organization_policies.lock();
        for record in policies {
            map.insert(record.organization_id.clone(), record);
        }
    }

    let links = state
        .persistence
        .realm_organizations()
        .snapshot_all()
        .await?;
    {
        let mut realm_map = state.realm_organizations.lock();
        let mut organization_map = state.organization_realms.lock();
        for (realm_id, organization_ids) in links {
            for organization_id in &organization_ids {
                organization_map
                    .entry(organization_id.clone())
                    .or_default()
                    .insert(realm_id.clone());
            }
            realm_map.insert(realm_id, organization_ids);
        }
    }

    let realm_policies = state
        .persistence
        .realm_moderation_policies()
        .snapshot_all()
        .await?;
    {
        let mut map = state.realm_moderation_policies.lock();
        for record in realm_policies {
            map.insert(record.realm_id.clone(), record);
        }
    }

    Ok(())
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.query.list",
    tags("organizations"),
    summary = "List locally known organizations"
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
        .organizations
        .lock()
        .values()
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
    tags("organizations"),
    summary = "Create or update a local organization registry row"
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
        source_refs: vec![ids::generate_event_id()],
        policy_revision: "local".to_owned(),
        verified: body.verified.unwrap_or(true),
        members,
        member_count,
        created_by: session.actor.clone(),
        created_at: now,
        updated_at: now,
    };
    state
        .persistence
        .organizations()
        .put(&record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    state
        .organizations
        .lock()
        .insert(organization_id, record.clone());
    json_ok(organization_record_view(state, &record))
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.resource.get",
    tags("organizations"),
    summary = "Read a local organization registry row"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.organization.resource.get"))]
async fn get_organization(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_did: PathParam<String>,
) -> JsonResult<OrganizationView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let organization_id = normalized_organization_id(&organization_did.into_inner())?;
    let record = state
        .organizations
        .lock()
        .get(&organization_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("organization not found"))?;
    json_ok(organization_record_view(state, &record))
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.policy.resource.get",
    tags("organizations", "policy"),
    summary = "Read the current organization moderation policy"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.organization.policy.resource.get")
)]
async fn get_organization_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_did: PathParam<String>,
) -> JsonResult<OrganizationPolicyView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let organization_id = normalized_organization_id(&organization_did.into_inner())?;
    let policy = state
        .organization_policies
        .lock()
        .get(&organization_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("organization policy not found"))?;
    json_ok(organization_policy_record_view(state, &policy))
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.policy.resource.replace",
    tags("organizations", "policy"),
    summary = "Publish an organization moderation policy"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.organization.policy.resource.replace")
)]
async fn upsert_organization_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_did: PathParam<String>,
    body: JsonBody<OrganizationModerationPolicyReplaceRequestBody>,
) -> JsonResult<OrganizationPolicyView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    ensure_organization_registry_admin(state, &session.actor)?;
    let organization_id = normalized_organization_id(&organization_did.into_inner())?;
    ensure_organization_placeholder(state, &organization_id, &session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut payload = Value::from(body.into_inner());
    if !payload.is_object() {
        return Err(AppError::bad_json(
            "organization moderation policy must be a JSON object",
        ));
    }
    if payload.get("kind").and_then(Value::as_str).is_none() {
        payload.as_object_mut().expect("object checked").insert(
            "kind".to_owned(),
            json!("ak.organization.moderation_policy"),
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
        .persistence
        .organization_policies()
        .get(&organization_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .or_else(|| {
            state
                .organization_policies
                .lock()
                .get(&organization_id)
                .cloned()
        })
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
        .persistence
        .organization_policies()
        .put(&record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    state
        .organization_policies
        .lock()
        .insert(organization_id, record.clone());
    json_ok(organization_policy_record_view(state, &record))
}

#[endpoint(
    operation_id = "org.arkret.soland.organization.realm.command.link",
    tags("organizations", "realms"),
    summary = "Link a Realm to an organization policy source"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.organization.realm.command.link")
)]
async fn link_organization_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_did: PathParam<String>,
    body: JsonBody<LinkOrganizationRealmRequestBody>,
) -> JsonResult<OrganizationRealmLinkOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    ensure_organization_registry_admin(state, &session.actor)?;
    let organization_id = normalized_organization_id(&organization_did.into_inner())?;
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
    for key in ["organization_id", "organization_did", "organization_ref"] {
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
) -> Result<(), crate::persistence::PersistenceError> {
    state
        .persistence
        .realm_organizations()
        .link(realm_id, organization_id)
        .await?;
    state
        .realm_organizations
        .lock()
        .entry(realm_id.to_owned())
        .or_default()
        .insert(organization_id.to_owned());
    state
        .organization_realms
        .lock()
        .entry(organization_id.to_owned())
        .or_default()
        .insert(realm_id.to_owned());
    Ok(())
}

/// SOL-ORG-05 — declared `owning_organizations` hint ids for a Realm. Display /
/// discovery surface ONLY; never use this to drive policy inheritance.
pub(crate) fn realm_organization_ids(state: &AppState, realm_id: &str) -> Vec<String> {
    state
        .realm_organizations
        .lock()
        .get(realm_id)
        .map(|set| set.iter().cloned().collect())
        .unwrap_or_default()
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
    let proj = state.projection.lock();
    let mut ids = proj.verified_organizations_with_scope(
        realm_id,
        arkret_sdk::models::RealmOrganizationControlScope::ModerationPolicy,
        now,
    );
    ids.sort();
    ids.dedup();
    ids
}

pub(crate) fn effective_policy_for_realm(
    state: &AppState,
    realm_id: &str,
) -> RealmEffectiveModerationPolicyOutcome {
    // SOL-ORG-05 — only organizations with a verified, active, in-window
    // `ak.realm.organization` statement carrying the `moderation_policy`
    // control scope drive the effective moderation policy. Declared
    // `owning_organizations` hints no longer qualify.
    let org_ids = verified_moderation_organization_ids(state, realm_id);
    let policies = state.organization_policies.lock();
    let links = state.organization_realms.lock();
    let org_layers = org_ids
        .iter()
        .filter_map(|org_id| policies.get(org_id).map(|policy| (org_id, policy)))
        .map(|(org_id, policy)| OrganizationPolicyLayer {
            source: "organization".to_owned(),
            organization_id: org_id.clone(),
            policy_id: policy.policy_id.clone(),
            version: policy.version,
            policy: policy.payload.clone(),
            applies_to_realms: links
                .get(org_id)
                .map(|set| set.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    drop(links);
    drop(policies);

    let realm_policy = state
        .realm_moderation_policies
        .lock()
        .get(realm_id)
        .map(realm_policy_record_outcome);
    let has_organization_inheritance = !org_ids.is_empty();
    RealmEffectiveModerationPolicyOutcome {
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
        override_requires_organization_approval: has_organization_inheritance,
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
    }
}

pub(crate) fn effective_policy_value_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<Value, serde_json::Error> {
    serde_json::to_value(effective_policy_for_realm(state, realm_id))
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
    let policies = state.organization_policies.lock();
    org_ids.iter().any(|org_id| {
        policies
            .get(org_id)
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
    let policies = state.organization_policies.lock();
    targets.iter().any(|target| {
        org_ids.iter().any(|org_id| {
            policies
                .get(org_id)
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
    let policies = state.organization_policies.lock();
    org_ids
        .into_iter()
        .filter(|org_id| {
            policies.get(org_id).is_some_and(|policy| {
                targets
                    .iter()
                    .any(|target| policy_denies_join_actor(&policy.payload, target))
            })
        })
        .collect()
}

pub(crate) async fn persist_realm_moderation_policy(
    state: &AppState,
    realm_id: &str,
    payload: Value,
    actor: &str,
) -> Result<RealmModerationPolicyRecord, crate::persistence::PersistenceError> {
    let record = RealmModerationPolicyRecord {
        realm_id: realm_id.to_owned(),
        payload,
        updated_by: actor.to_owned(),
        updated_at: Utc::now(),
    };
    state
        .persistence
        .realm_moderation_policies()
        .put(&record)
        .await?;
    state
        .realm_moderation_policies
        .lock()
        .insert(realm_id.to_owned(), record.clone());
    Ok(record)
}

pub(crate) fn organization_records_for_directory(state: &AppState) -> Vec<Value> {
    state
        .organizations
        .lock()
        .values()
        .map(|record| organization_record_json(state, record))
        .collect()
}

async fn ensure_organization_placeholder(
    state: &AppState,
    organization_id: &str,
    actor: &str,
) -> Result<(), crate::persistence::PersistenceError> {
    if state
        .persistence
        .organizations()
        .get(organization_id)
        .await?
        .is_some()
    {
        return Ok(());
    }
    let now = Utc::now();
    let record = OrganizationRecord {
        organization_id: organization_id.to_owned(),
        organization_did: organization_id.to_owned(),
        handle: None,
        display_name: display_name_from_organization_id(organization_id),
        source_refs: vec![ids::generate_event_id()],
        policy_revision: "local".to_owned(),
        verified: false,
        members: BTreeSet::new(),
        member_count: 0,
        created_by: actor.to_owned(),
        created_at: now,
        updated_at: now,
    };
    state.persistence.organizations().put(&record).await?;
    state
        .organizations
        .lock()
        .insert(organization_id.to_owned(), record);
    Ok(())
}

fn organization_record_view(state: &AppState, record: &OrganizationRecord) -> OrganizationView {
    let realms = state
        .organization_realms
        .lock()
        .get(&record.organization_id)
        .map(|set| set.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let realm_count = realms.len();
    OrganizationView {
        organization_id: record.organization_id.clone(),
        organization_did: record.organization_did.clone(),
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
        created_at: record.created_at.to_rfc3339(),
        updated_at: record.updated_at.to_rfc3339(),
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
        .organization_realms
        .lock()
        .get(&record.organization_id)
        .map(|set| set.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    OrganizationPolicyView {
        kind: "ak.organization.moderation_policy".to_owned(),
        organization_id: record.organization_id.clone(),
        policy_id: record.policy_id.clone(),
        version: record.version,
        policy: record.payload.clone(),
        applies_to_realms,
        updated_by: record.updated_by.clone(),
        updated_at: record.updated_at.to_rfc3339(),
    }
}

pub(crate) fn realm_policy_record_outcome(
    record: &RealmModerationPolicyRecord,
) -> RealmModerationPolicyOutcome {
    RealmModerationPolicyOutcome {
        kind: "ak.realm.moderation_policy".to_owned(),
        realm_id: record.realm_id.clone(),
        policy: record.payload.clone(),
        updated_by: record.updated_by.clone(),
        updated_at: record.updated_at.to_rfc3339(),
    }
}

fn effective_rules(state: &AppState, realm_id: &str) -> Vec<Value> {
    // SOL-ORG-05 — effective rules are sourced only from verified
    // moderation-scoped organizations.
    let org_ids = verified_moderation_organization_ids(state, realm_id);
    let policies = state.organization_policies.lock();
    let mut rules = Vec::new();
    for org_id in org_ids {
        if let Some(policy) = policies.get(&org_id) {
            rules.extend(policy_rules(&policy.payload));
        }
    }
    drop(policies);
    if let Some(realm_policy) = state
        .realm_moderation_policies
        .lock()
        .get(realm_id)
        .cloned()
    {
        rules.extend(
            allow_join_override_targets(&realm_policy.payload)
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
    state
        .realm_moderation_policies
        .lock()
        .get(realm_id)
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
    } else if !value.starts_with("ak:org:") {
        return Err(AppError::invalid_param(
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
    .with_reason_code(arkret_sdk::ReasonCode::REQUIRES_ORGANIZATION_APPROVAL)
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
            Some(arkret_sdk::ReasonCode::REQUIRES_ORGANIZATION_APPROVAL)
        );
    }
}
