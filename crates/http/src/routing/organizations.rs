//! Organization registry + moderation policy inheritance.
//!
//! This is the local P2 governance surface for organization-owned Realms:
//! org policies are stored once, Realm create links fan out through an index,
//! and linked Realm projections consume the effective organization policy.

use std::collections::BTreeSet;

use arkret_models_collaboration::events_payloads::{
    ModerationPolicyTarget, OrganizationModerationPolicyDocument,
    OrganizationModerationPolicyStatePayload,
};
use arkret_wire::{ActorId, CellFamilyId, CellRef, DidCoreId};
use chrono::Utc;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct OrganizationPolicyLayer {
    source: String,
    organization_id: String,
    policy_id: String,
    policy: Value,
    #[serde(default)]
    applies_to_realms: Vec<String>,
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

/// SOL-ORG-05 — the stable organization ids whose active, in-window
/// `ak.realm.organization` statement endorses `realm_id` with a
/// `moderation_policy` control scope. This is the ONLY basis on which an
/// organization's moderation policy may flow into the Realm's effective policy;
/// `owning_organization_ids` declared hints no longer qualify. Returns a stable,
/// de-duplicated, sorted list.
pub(crate) fn effective_policy_value_for_realm(state: &AppState, realm_id: &str) -> Value {
    // SOL-ORG-05 — only organizations with a verified, active, in-window
    // `ak.realm.organization` statement carrying the `moderation_policy`
    // control scope drive the effective moderation policy. Declared
    // `owning_organization_ids` hints no longer qualify.
    let org_layers = applicable_organization_policies(state, realm_id, None)
        .into_iter()
        .map(|(organization_id, policy)| OrganizationPolicyLayer {
            source: "organization".to_owned(),
            organization_id: organization_id.to_string(),
            policy_id: policy.policy_id.to_string(),
            policy: serde_json::to_value(&policy).unwrap_or(Value::Null),
            applies_to_realms: state
                .governance()
                .cached_organization_realms(&organization_id),
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
    actor: &ActorId,
) -> bool {
    if let Err(error) = refresh_organization_projection(state).await {
        tracing::warn!(%error, "failed to refresh organization projection for join policy");
    }
    // SOL-ORG-05 — only verified moderation-scoped organizations gate joins.
    applicable_organization_policies(state, realm_id, None)
        .iter()
        .any(|(_, policy)| policy_denies_join_actor(policy, actor))
}

pub(crate) fn organization_policy_blocks_federation(
    state: &AppState,
    realm_id: &str,
    peer_service_id: &DidCoreId,
) -> bool {
    let now = Utc::now();
    applicable_organization_policies(state, realm_id, Some(peer_service_id))
        .iter()
        .any(|(_, policy)| policy_denies_federation_service(policy, peer_service_id, now))
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

fn effective_rules(state: &AppState, realm_id: &str) -> Vec<Value> {
    // SOL-ORG-05 — effective rules are sourced only from verified
    // moderation-scoped organizations.
    let mut rules = Vec::new();
    for (_, policy) in applicable_organization_policies(state, realm_id, None) {
        rules.extend(policy_rules(&policy));
    }
    rules
}

fn policy_rules(policy: &OrganizationModerationPolicyDocument) -> Vec<Value> {
    policy
        .rules
        .iter()
        .filter_map(|rule| serde_json::to_value(rule).ok())
        .collect()
}

fn policy_denies_join_actor(
    policy: &OrganizationModerationPolicyDocument,
    actor: &ActorId,
) -> bool {
    use arkret_models_collaboration::events_payloads::OrganizationModerationAction;
    policy.rules.iter().any(|rule| {
        matches!(
            rule.action,
            OrganizationModerationAction::DenyJoin
                | OrganizationModerationAction::DenyRestrictedJoin
        ) && matches!(&rule.target, ModerationPolicyTarget::Actor { actor_id } if actor_id == actor)
    })
}

fn policy_denies_federation_service(
    policy: &OrganizationModerationPolicyDocument,
    service_id: &DidCoreId,
    now: chrono::DateTime<Utc>,
) -> bool {
    use arkret_models_collaboration::events_payloads::OrganizationModerationAction;
    policy.rules.iter().any(|rule| {
        rule.action == OrganizationModerationAction::DenyFederation
            && rule.created_at.is_none_or(|created_at| created_at <= now)
            && rule.expires_at.is_none_or(|expires_at| now < expires_at)
            && matches!(
                &rule.target,
                ModerationPolicyTarget::Service { service_id: target } if target == service_id
            )
    })
}

fn applicable_organization_policies(
    state: &AppState,
    realm_id: &str,
    service_id: Option<&DidCoreId>,
) -> Vec<(DidCoreId, OrganizationModerationPolicyDocument)> {
    let now = Utc::now();
    let projection = state.projections().snapshot();
    let mut policies = projection
        .verified_organization_relationships(realm_id, now)
        .into_iter()
        .filter(|relationship| relationship.covers_scope("moderation_policy"))
        .filter_map(|relationship| {
            let cell = CellRef::new(format!(
                "ak:cell:{}:{}",
                CellFamilyId::OrganizationModerationPolicyV1.as_str(),
                relationship.organization_id.as_str()
            ))
            .ok()?;
            let payload = serde_json::from_value::<OrganizationModerationPolicyStatePayload>(
                projection.cell_value(&cell)?.clone(),
            )
            .ok()?;
            if payload.organization_id != relationship.organization_id {
                return None;
            }
            let explicit_realm = payload
                .value
                .policy_scope
                .realm_ids
                .as_ref()
                .is_some_and(|ids| ids.iter().any(|id| id.as_str() == realm_id));
            let owned_realm = relationship.relationship == "owner"
                && payload
                    .value
                    .policy_scope
                    .applies_to_owned_realms
                    .unwrap_or(false);
            let explicit_service = service_id.is_some_and(|service_id| {
                payload
                    .value
                    .policy_scope
                    .service_ids
                    .as_ref()
                    .is_some_and(|ids| ids.iter().any(|id| id == service_id))
            });
            if !explicit_realm && !owned_realm && !explicit_service {
                return None;
            }
            if payload.value.not_before.is_some_and(|start| now < start)
                || payload.value.expires_at.is_some_and(|end| now >= end)
            {
                return None;
            }
            Some((payload.organization_id, payload.value))
        })
        .collect::<Vec<_>>();
    policies.sort_by(|left, right| left.0.cmp(&right.0));
    policies.dedup_by(|left, right| left.0 == right.0);
    policies
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

#[cfg(test)]
mod tests {
    use super::*;

    const REALM_ID: &str = "ak:realm:AabIzZyp4D-JzV77DNQ7bIKd7oGAuDD9keT1CyIv6SC6";
    const ORGANIZATION_ID: &str = "ak:did_core:web:organization.example";

    fn account_at(station: &str) -> ActorId {
        ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
        ))
    }

    fn join_policy(target: Value, action: &str) -> OrganizationModerationPolicyDocument {
        serde_json::from_value(json!({
            "policy_id": "ak:policy:0198f1a2-4c3d-7e56-8a90-1b2c3d4e5f60",
            "policy_scope": {"applies_to_owned_realms": true},
            "rules": [{"target": target, "action": action}]
        }))
        .unwrap()
    }

    fn install_federation_policy(state: &AppState, scope: Value, target_service_id: &DidCoreId) {
        let organization_id = DidCoreId::new(ORGANIZATION_ID).unwrap();
        let now = Utc::now();
        let relationship = soland_domain::reducer::RealmOrganizationStatementState {
            realm_id: REALM_ID.to_owned(),
            organization_id: organization_id.clone(),
            relationship: "governance".to_owned(),
            statement_id: "ak:organization_statement:0198f1a2-4c3d-7e56-8a90-1b2c3d4e5f60"
                .to_owned(),
            status: "active".to_owned(),
            control_scopes: vec!["moderation_policy".to_owned()],
            issued_at: now,
            not_before: None,
            expires_at: None,
            supersedes_statement_id: None,
            revokes_statement_id: None,
            realm_frontier_digest: None,
            proof_digest: None,
            delegation_ref: None,
            issuer_role: "organization".to_owned(),
            updated_at: now,
        };
        let cell = CellRef::new(format!(
            "ak:cell:{}:{}",
            CellFamilyId::OrganizationModerationPolicyV1.as_str(),
            organization_id
        ))
        .unwrap();
        let mut projection = state.test_projection().lock();
        projection.realm_organization_statements.insert(
            (
                REALM_ID.to_owned(),
                organization_id.clone(),
                "governance".to_owned(),
            ),
            relationship,
        );
        projection.cells.insert(
            cell,
            arkret_state::lattice::CellState::Value(json!({
                "organization_id": organization_id,
                "value": {
                    "policy_id": "ak:policy:0198f1a2-4c3d-7e56-8a90-1b2c3d4e5f60",
                    "policy_scope": scope,
                    "rules": [{
                        "target": {"kind": "service", "service_id": target_service_id},
                        "action": "deny_federation"
                    }]
                }
            })),
        );
    }

    #[test]
    fn organization_actor_deny_preserves_station_and_actor_id_variant() {
        let actor = account_at("station-a");
        let foreign = account_at("station-b");
        let service = ActorId::service(actor.signing_principal_id().clone());
        for action in ["deny_join", "deny_restricted_join"] {
            let policy = join_policy(json!({"kind": "actor", "actor_id": actor}), action);
            assert!(policy_denies_join_actor(&policy, &actor));
            assert!(!policy_denies_join_actor(&policy, &foreign));
            assert!(!policy_denies_join_actor(&policy, &service));
        }
    }

    #[test]
    fn organization_actor_deny_rejects_mistagged_targets() {
        let actor = account_at("station-a");
        for target in [
            json!({"kind": "actor", "actor_id": actor.to_string()}),
            json!({"kind": "service", "actor_id": actor}),
            json!({"actor_id": actor}),
        ] {
            assert!(
                serde_json::from_value::<OrganizationModerationPolicyDocument>(json!({
                    "policy_id": "ak:policy:0198f1a2-4c3d-7e56-8a90-1b2c3d4e5f60",
                    "policy_scope": {"applies_to_owned_realms": true},
                    "rules": [{"target": target, "action": "deny_join"}]
                }))
                .is_err()
            );
        }
    }

    #[test]
    fn federation_deny_requires_verified_relationship_scope_and_exact_service() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let denied = DidCoreId::new("ak:did_core:web:denied.example").unwrap();
        let allowed = DidCoreId::new("ak:did_core:web:allowed.example").unwrap();
        install_federation_policy(&state, json!({"realm_ids": [REALM_ID]}), &denied);
        assert!(organization_policy_blocks_federation(
            &state, REALM_ID, &denied
        ));
        assert!(!organization_policy_blocks_federation(
            &state, REALM_ID, &allowed
        ));
    }

    #[test]
    fn federation_deny_accepts_an_explicit_service_scope() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let denied = DidCoreId::new("ak:did_core:web:denied.example").unwrap();
        install_federation_policy(&state, json!({"service_ids": [denied.clone()]}), &denied);
        assert!(organization_policy_blocks_federation(
            &state, REALM_ID, &denied
        ));
    }

    #[tokio::test]
    async fn organization_display_projection_decodes_the_formal_event_actor() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let actor = account_at("station-a");
        let realm_id = "ak:realm:AabIzZyp4D-JzV77DNQ7bIKd7oGAuDD9keT1CyIv6SC6";
        let organization_id = "ak:did_core:web:organization.example";
        record_realm_organizations_from_event(
            &state,
            realm_id,
            &json!({
                "actor_id": actor,
                "payload": {"object": {"owning_organization_ids": [organization_id]}}
            }),
        )
        .await
        .unwrap();
        let record = state
            .governance()
            .organization(organization_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&record.created_by, actor.signing_principal_id());

        let rejected_id = "ak:did_core:web:rejected-organization.example";
        record_realm_organizations_from_event(
            &state,
            realm_id,
            &json!({
                "actor_id": actor.signing_principal_id(),
                "payload": {"object": {"owning_organization_ids": [rejected_id]}}
            }),
        )
        .await
        .unwrap();
        assert!(
            state
                .governance()
                .organization(rejected_id)
                .await
                .unwrap()
                .is_none()
        );
    }

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
    fn declared_organization_ids_do_not_treat_single_value_fields_as_verified_ownership() {
        let object = serde_json::json!({
            "organization_id": "ak:did_core:webvh:zOrganizationA",
            "organization_ref": "ak:did_core:webvh:zOrganizationC"
        });
        assert!(
            declared_organization_ids(object.as_object().unwrap())
                .unwrap()
                .is_empty()
        );
    }
}
