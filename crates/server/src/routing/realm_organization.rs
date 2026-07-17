//! SOL-ORG-06 — Realm organization-relationship read surface.
//!
//! `GET /_arkret/self/realms/{realm_id}/organizations`
//! (`ak.self.realm_organization.query.list`) projects the accepted
//! `ak.realm.organization` relationship statements (active / revoked / expired,
//! latest-per-`(organization_id, relationship)`) plus the declared
//! `owning_organizations` hints (SOL-ORG-05) that carry no verified statement.
//!
//! A relationship is only verified when `lifecycle_phase=verified_active`;
//! `declared_organization_hints` are unverified claims. This is the protocol
//! read path referenced by `realm-and-space.md` §2.3.0 — soland never invents a
//! private endpoint for it.
//!
//! Spec: `arkret-spec/spec/v1/zh/models/realm-and-space.md` §2.3.0; response
//! schema `realm-organization-operations.schema.json`.

use std::collections::BTreeSet;

use arkret_sdk::RealmId;
use arkret_sdk::models::{
    Did, Hash, RealmOrganizationLifecyclePhase, RealmOrganizationRelationshipList,
    RealmOrganizationRelationshipRow,
};
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::json;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::AuthArgs;
use crate::state::AppState;

pub(crate) fn router() -> Router {
    Router::with_path("realms")
        .push(Router::with_path("{realm_id}/organizations").get(list_realm_organizations))
}

/// Deserialize a validated projection string into a wire newtype / enum. The
/// projection only stores values the reducer already accepted, so a parse
/// failure is an internal invariant violation.
fn de_str<T: DeserializeOwned>(field: &str, value: &str) -> Result<T, AppError> {
    serde_json::from_value(json!(value))
        .map_err(|e| AppError::internal(format!("invalid projected {field} '{value}': {e}")))
}

#[endpoint(
    operation_id = "ak.self.realm_organization.query.list",
    tags("realms"),
    summary = "List projected ak.realm.organization relationships for a Realm (SOL-ORG-06)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_organization.query.list"))]
async fn list_realm_organizations(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmOrganizationRelationshipList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    if !crate::routing::realm_has_member(state, &realm_id, &session.actor).await {
        return Err(AppError::not_found("realm not found"));
    }
    let now = chrono::Utc::now();

    let mut relationships = Vec::new();
    // Organization DIDs with a currently-verified statement: these are excluded
    // from the declared-hint list so a hint never duplicates a verified row.
    let mut verified_org_ids: BTreeSet<String> = BTreeSet::new();
    {
        let projection = state.projection.lock();
        for row in projection.realm_organization_statements_for_realm(&realm_id) {
            let lifecycle_phase = if row.is_effective_active(now) {
                verified_org_ids.insert(row.organization_id.clone());
                RealmOrganizationLifecyclePhase::VerifiedActive
            } else {
                RealmOrganizationLifecyclePhase::RevokedOrExpired
            };
            let control_scopes = row
                .control_scopes
                .iter()
                .map(|s| de_str("control_scope", s))
                .collect::<Result<Vec<_>, _>>()?;
            let realm_frontier_digest = row
                .realm_frontier_digest
                .as_deref()
                .map(|s| de_str::<Hash>("realm_frontier_digest", s))
                .transpose()?;
            relationships.push(RealmOrganizationRelationshipRow {
                statement_id: row.statement_id.clone(),
                organization_id: de_str("organization_id", &row.organization_id)?,
                relationship: de_str("relationship", &row.relationship)?,
                status: de_str("status", &row.status)?,
                control_scopes,
                issued_at: row.issued_at,
                not_before: row.not_before,
                expires_at: row.expires_at,
                supersedes_statement_id: row.supersedes_statement_id.clone(),
                revokes_statement_id: row.revokes_statement_id.clone(),
                realm_frontier_digest,
                issuer_role: de_str("issuer_role", &row.issuer_role)?,
                delegation_ref: row.delegation_ref.clone(),
                lifecycle_phase,
                updated_at: Some(row.updated_at),
            });
        }
    }

    // SOL-ORG-05 declared `owning_organizations` hints (display surface only),
    // minus any organization that already has a currently-verified statement so
    // a hint never duplicates a verified row.
    let mut declared_organization_hints: Vec<Did> = Vec::new();
    for did in super::organizations::realm_organization_ids(state, &realm_id)
        .iter()
        .filter(|did| !verified_org_ids.contains(*did))
    {
        declared_organization_hints.push(de_str("declared_organization_hint", did)?);
    }

    json_ok(RealmOrganizationRelationshipList {
        realm_id: de_str::<RealmId>("realm_id", &realm_id)?,
        relationships,
        declared_organization_hints,
    })
}
