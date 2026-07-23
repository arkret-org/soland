//! Production admin query endpoints (D14).
//!
//! Typed, cursor-paginated, server-side-filtered reads for the four resources
//! sodmin manages:
//!
//! - `GET /_soland/admin/actors`        → [`AdminActorList`]
//! - `GET /_soland/admin/audit`         → [`AdminAuditList`]
//! - `GET /_soland/admin/capabilities`  → [`AdminCapabilityList`]
//! - `GET /_soland/admin/devices`       → [`AdminDeviceList`]
//!
//! These replace the dev-only `admin/{resource}` snapshot collection for
//! those resources (the collection keeps serving the surfaces that have not
//! been productionised yet). Wire contract lives in
//! `soland_contracts::admin` — see that module for the frozen rules.
//!
//! Pagination: rows are sorted by a stable key (actors: DID; capabilities:
//! grant id; devices: device id; audit: newest first, audit id as tiebreak).
//! `next_cursor` is the last row id of the page; resume looks the id up
//! again, so the cursor stays valid across inserts. A cursor that no longer
//! resolves is rejected with `cursor-expired` (410) so clients reset to the
//! first page instead of silently skipping rows.
//!
//! Authorization mirrors the rest of the operator surface: the admin tree's
//! `RequireAdmin` hoop enforces the `admin.read` session-grant scope, and
//! each handler additionally requires the caller DID to be an admin
//! principal (`require_admin_principal`). Every query appends an audit
//! record carrying the applied filters and returned row count.

use std::collections::BTreeMap;

use arkret_identifiers::Did;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_contracts::admin::{
    AdminActor, AdminActorList, AdminAuditEntry, AdminAuditList, AdminCapabilityList, AdminDevice,
    AdminDeviceList, CapabilityGrantState, CapabilitySummary,
};
use soland_http::error::{AppError, ErrorCode};
use util::query_param;

use super::{AuthArgs, append_audit_log, require_admin_principal, util};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

/// Clamp the caller-supplied page size to the configured admin window.
fn clamp_limit(state: &AppState, limit: Option<usize>) -> usize {
    limit
        .unwrap_or(state.config().admin_default_page_limit)
        .clamp(1, state.config().admin_max_page_limit)
}

/// Resume-by-id keyset pagination over an already-filtered, already-sorted
/// row set. Returns `(page, next_cursor, has_more)`. An unresolvable cursor
/// is a hard `cursor-expired` (410): the row the client saw last is gone, so
/// continuing would silently skip an unknown range.
fn paginate_by_id<T>(
    mut rows: Vec<T>,
    cursor: Option<&str>,
    limit: usize,
    id_of: impl Fn(&T) -> &str,
) -> Result<(Vec<T>, Option<String>, bool), AppError> {
    if let Some(cursor) = cursor {
        let position = rows
            .iter()
            .position(|row| id_of(row) == cursor)
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::CursorExpired,
                    "pagination cursor no longer resolves; restart from the first page".to_owned(),
                )
                .with_status(salvo::http::StatusCode::GONE)
            })?;
        rows.drain(..=position);
    }
    let has_more = rows.len() > limit;
    if has_more {
        rows.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| rows.last().map(|row| id_of(row).to_owned()))
        .flatten();
    Ok((rows, next_cursor, has_more))
}

/// Case-insensitive substring match helper for `filter[search]`-style
/// filters.
fn contains_ci(haystack: &str, needle_lower: &str) -> bool {
    haystack.to_lowercase().contains(needle_lower)
}

async fn query_audit_trail(
    state: &AppState,
    session: &soland_application::identity::SessionIdentityState,
    action: &str,
    filters: &BTreeMap<String, String>,
    count: usize,
) {
    append_audit_log(
        state,
        Some(&session.actor),
        action,
        json!({
            "device_id": session.device_id,
            "filters": filters,
            "count": count,
        }),
        "accepted",
    )
    .await;
}

// ---------------------------------------------------------------------------
// Actors
// ---------------------------------------------------------------------------

/// Build the production [`AdminActor`] projection for one account record.
/// `device_counts` / `realm_counts` are precomputed maps keyed by DID.
/// Returns `None` (with a warning) for rows whose stored DID fails the
/// canonical grammar — such rows cannot be represented in the typed contract.
pub(super) fn admin_actor_row(
    state: &AppState,
    account: &soland_application::identity::AccountProfileState,
    device_counts: &BTreeMap<String, u64>,
    realm_counts: &BTreeMap<String, u64>,
) -> Option<AdminActor> {
    let did = match Did::new(account.did.clone()) {
        Ok(did) => did,
        Err(error) => {
            tracing::warn!(did = %account.did, %error, "account row DID fails canonical grammar; skipped");
            return None;
        }
    };
    let status = state.account_lifecycle_status(&account.did);
    let deactivation_federation_incomplete = (status == AccountStatus::Deactivated).then(|| {
        !crate::routing::identity::account::deactivation_peer_service_targets_for_actor(
            state,
            &account.did,
        )
        .is_empty()
    });
    let handle = account.handle();
    Some(AdminActor {
        id: account.did.clone(),
        did,
        account_id: Some(account.id.clone()),
        handle: (!handle.is_empty()).then_some(handle),
        display_name: account.display_name.clone(),
        status: Some(status),
        is_admin: Some(state.is_admin_principal(&account.did)),
        deactivation_federation_incomplete,
        created_at: Some(account.created_at),
        // Not tracked by this deployment — reported as unknown, never a
        // fabricated timestamp.
        last_active_at: None,
        device_count: device_counts.get(&account.did).copied().or(Some(0)),
        realm_count: realm_counts.get(&account.did).copied().or(Some(0)),
    })
}

pub(super) async fn actor_count_maps(
    state: &AppState,
) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
    let mut device_counts: BTreeMap<String, u64> = BTreeMap::new();
    for actor in state
        .identity_application()
        .list_active_device_actors(soland_application::identity::ListActiveDeviceActorsQuery)
        .await
        .unwrap_or_default()
    {
        *device_counts.entry(actor).or_default() += 1;
    }
    let mut realm_counts: BTreeMap<String, u64> = BTreeMap::new();
    let realm_snapshot: Vec<_> = {
        let realms = state.realm_directory_application().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    for realm in realm_snapshot {
        for member in &realm.members {
            *realm_counts.entry(member.to_string()).or_default() += 1;
        }
    }
    (device_counts, realm_counts)
}

#[endpoint(
    operation_id = "org.arkret.soland.admin.actors.query",
    tags("soland-admin", "actors"),
    summary = "Production admin actors query (typed, cursor-paginated)",
    status_codes(200, 400, 401, 403, 410, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.actors.query"))]
pub(super) async fn admin_list_actors(
    aa: AuthArgs,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminActorList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let limit = clamp_limit(state, limit.into_inner());
    let cursor = cursor.into_inner();

    let mut filters = BTreeMap::new();
    let search = query_param(req, "filter[search]").filter(|value| !value.trim().is_empty());
    if let Some(search) = &search {
        filters.insert("search".to_owned(), search.clone());
    }
    let status_filter = match query_param(req, "filter[status]") {
        Some(raw) => {
            let status = AccountStatus::from_wire(&raw).ok_or_else(|| {
                AppError::invalid_param(format!("unknown account status filter: {raw}"))
            })?;
            filters.insert("status".to_owned(), raw);
            Some(status)
        }
        None => None,
    };

    let (device_counts, realm_counts) = actor_count_maps(state).await;
    let mut rows: Vec<AdminActor> = state
        .identity_application()
        .accounts()
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to list accounts");
            AppError::internal("account store unavailable")
        })?
        .iter()
        .filter_map(|account| admin_actor_row(state, account, &device_counts, &realm_counts))
        .collect();
    if let Some(search) = &search {
        let needle = search.to_lowercase();
        rows.retain(|actor| {
            contains_ci(&actor.id, &needle)
                || actor
                    .handle
                    .as_deref()
                    .is_some_and(|handle| contains_ci(handle, &needle))
                || actor
                    .display_name
                    .as_deref()
                    .is_some_and(|name| contains_ci(name, &needle))
        });
    }
    if let Some(status) = status_filter {
        rows.retain(|actor| actor.status == Some(status));
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let total = rows.len() as u64;
    let (actors, next_cursor, has_more) =
        paginate_by_id(rows, cursor.as_deref(), limit, |actor| actor.id.as_str())?;

    query_audit_trail(
        state,
        &session,
        "admin.actors.query",
        &filters,
        actors.len(),
    )
    .await;
    json_ok(AdminActorList {
        actors,
        total: Some(total),
        next_cursor,
        has_more,
        filters,
    })
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// Parse one durable audit record into the typed wire row. Records without
/// an `audit_id` are dropped (they cannot participate in cursor pagination).
fn audit_entry_from_record(record: &Value) -> Option<AdminAuditEntry> {
    let field = |key: &str| {
        record
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    Some(AdminAuditEntry {
        id: field("audit_id")?,
        request_id: field("request_id"),
        action: field("action").unwrap_or_default(),
        actor_id: field("actor"),
        device_id: field("device_id"),
        realm_id: field("realm_id"),
        operation_id: field("operation_id"),
        outcome: field("outcome"),
        payload: record.get("payload").filter(|p| !p.is_null()).cloned(),
        created_at: field("created_at")
            .and_then(|raw| chrono::DateTime::parse_from_rfc3339(&raw).ok())
            .map(|ts| ts.with_timezone(&chrono::Utc)),
    })
}

fn audit_matches_kind(entry: &AdminAuditEntry, kind: &str) -> bool {
    entry.action == kind
        || entry
            .payload
            .as_ref()
            .and_then(|payload| payload.get("kind").or_else(|| payload.get("type")))
            .and_then(Value::as_str)
            == Some(kind)
}

fn parse_time_bound(raw: &str, name: &str) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .map_err(|_| AppError::invalid_param(format!("{name} must be an RFC3339 timestamp")))
}

#[endpoint(
    operation_id = "org.arkret.soland.admin.audit.query",
    tags("soland-admin", "audit"),
    summary = "Production admin audit query (typed, newest first, cursor-paginated)",
    status_codes(200, 400, 401, 403, 410, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.audit.query"))]
pub(super) async fn admin_query_audit(
    aa: AuthArgs,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminAuditList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let limit = clamp_limit(state, limit.into_inner());
    let cursor = cursor.into_inner();

    let mut filters = BTreeMap::new();
    let mut simple_filter = |key: &str| {
        let value =
            query_param(req, &format!("filter[{key}]")).filter(|value| !value.trim().is_empty());
        if let Some(value) = &value {
            filters.insert(key.to_owned(), value.clone());
        }
        value
    };
    let action_filter = simple_filter("action");
    let actor_filter = simple_filter("actor_id");
    let realm_filter = simple_filter("realm_id");
    let kind_filter = simple_filter("kind");
    let since = match query_param(req, "since").filter(|value| !value.trim().is_empty()) {
        Some(raw) => {
            let bound = parse_time_bound(&raw, "since")?;
            filters.insert("since".to_owned(), raw);
            Some(bound)
        }
        None => None,
    };
    let until = match query_param(req, "until").filter(|value| !value.trim().is_empty()) {
        Some(raw) => {
            let bound = parse_time_bound(&raw, "until")?;
            filters.insert("until".to_owned(), raw);
            Some(bound)
        }
        None => None,
    };

    let mut entries: Vec<AdminAuditEntry> = state
        .governance_application()
        .audit_entries()
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to read audit log");
            AppError::internal("audit store unavailable")
        })?
        .iter()
        .filter_map(audit_entry_from_record)
        .collect();
    if let Some(action) = &action_filter {
        entries.retain(|entry| &entry.action == action);
    }
    if let Some(actor) = &actor_filter {
        entries.retain(|entry| entry.actor_id.as_deref() == Some(actor.as_str()));
    }
    if let Some(realm) = &realm_filter {
        entries.retain(|entry| {
            entry.realm_id.as_deref() == Some(realm.as_str())
                || entry
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.get("realm_id"))
                    .and_then(Value::as_str)
                    == Some(realm.as_str())
        });
    }
    if let Some(kind) = &kind_filter {
        entries.retain(|entry| audit_matches_kind(entry, kind));
    }
    if let Some(since) = since {
        entries.retain(|entry| entry.created_at.is_some_and(|ts| ts >= since));
    }
    if let Some(until) = until {
        entries.retain(|entry| entry.created_at.is_some_and(|ts| ts <= until));
    }
    // Newest first; audit id keeps the order total when timestamps collide.
    entries.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    let total = entries.len() as u64;
    let (entries, next_cursor, has_more) =
        paginate_by_id(entries, cursor.as_deref(), limit, |entry| entry.id.as_str())?;

    query_audit_trail(
        state,
        &session,
        "admin.audit.query",
        &filters,
        entries.len(),
    )
    .await;
    json_ok(AdminAuditList {
        entries,
        total: Some(total),
        next_cursor,
        has_more,
        filters,
    })
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

fn capability_summary(grant: &crate::authz::Grant) -> CapabilitySummary {
    CapabilitySummary {
        grant_id: grant.grant_id.clone(),
        realm_id: (!grant.realm_id.is_empty()).then(|| grant.realm_id.clone()),
        issuer: grant.issuer.clone(),
        subject: grant.subject.clone(),
        resource: (!grant.resource.is_empty()).then(|| grant.resource.clone()),
        actions: grant.actions.clone(),
        constraints: grant
            .constraints
            .iter()
            .filter_map(|constraint| {
                serde_json::to_value(constraint)
                    .ok()
                    .and_then(|value| serde_json::from_value(value).ok())
            })
            .collect(),
        revoked: grant.revoked,
        created_at: Some(grant.created_at),
        delegated_from: grant.delegated_from.clone(),
        expires_at: grant.expires_at,
    }
}

#[endpoint(
    operation_id = "org.arkret.soland.admin.capabilities.query",
    tags("soland-admin", "capabilities"),
    summary = "Production admin capability-grant query (typed, cursor-paginated)",
    status_codes(200, 400, 401, 403, 410, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.capabilities.query"))]
pub(super) async fn admin_list_capabilities(
    aa: AuthArgs,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminCapabilityList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let limit = clamp_limit(state, limit.into_inner());
    let cursor = cursor.into_inner();

    let mut filters = BTreeMap::new();
    let realm_filter =
        query_param(req, "filter[realm_id]").filter(|value| !value.trim().is_empty());
    if let Some(realm) = &realm_filter {
        filters.insert("realm_id".to_owned(), realm.clone());
    }
    let subject_filter =
        query_param(req, "filter[subject]").filter(|value| !value.trim().is_empty());
    if let Some(subject) = &subject_filter {
        filters.insert("subject".to_owned(), subject.clone());
    }
    let state_filter = match query_param(req, "filter[state]") {
        Some(raw) => {
            let parsed = CapabilityGrantState::from_wire(&raw).ok_or_else(|| {
                AppError::invalid_param(format!(
                    "unknown capability state filter: {raw} (expected active|revoked|all)"
                ))
            })?;
            filters.insert("state".to_owned(), raw);
            parsed
        }
        // Operators inspect grants for audit purposes, so revoked tombstones
        // are visible by default.
        None => CapabilityGrantState::All,
    };

    let mut rows: Vec<CapabilitySummary> = state
        .authorization_application()
        .grants_snapshot()
        .iter()
        .map(capability_summary)
        .collect();
    if let Some(realm) = &realm_filter {
        rows.retain(|summary| summary.realm_id.as_deref() == Some(realm.as_str()));
    }
    if let Some(subject) = &subject_filter {
        rows.retain(|summary| &summary.subject == subject);
    }
    match state_filter {
        CapabilityGrantState::Active => rows.retain(|summary| !summary.revoked),
        CapabilityGrantState::Revoked => rows.retain(|summary| summary.revoked),
        CapabilityGrantState::All => {}
        // `CapabilityGrantState` is #[non_exhaustive]; fail closed on any
        // future variant instead of silently widening visibility.
        _ => {
            return Err(AppError::invalid_param(
                "unsupported capability state filter",
            ));
        }
    }
    rows.sort_by(|left, right| left.grant_id.cmp(&right.grant_id));
    let total = rows.len() as u64;
    let (capabilities, next_cursor, has_more) =
        paginate_by_id(rows, cursor.as_deref(), limit, |summary| {
            summary.grant_id.as_str()
        })?;

    query_audit_trail(
        state,
        &session,
        "admin.capabilities.query",
        &filters,
        capabilities.len(),
    )
    .await;
    json_ok(AdminCapabilityList {
        capabilities,
        total: Some(total),
        next_cursor,
        has_more,
        filters,
    })
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

fn admin_device_row(device: &soland_application::identity::DeviceIdentity) -> AdminDevice {
    AdminDevice {
        id: device.device_id.clone(),
        actor_id: Some(device.actor_id.clone()),
        display_name: device.display_name.clone(),
        verification_state: Some(device.verification_state.clone()),
        payload: (!device.payload.is_null()).then(|| device.payload.clone()),
        created_at: Some(device.created_at),
        updated_at: Some(device.updated_at),
        revoked_at: device.revoked_at,
    }
}

#[endpoint(
    operation_id = "org.arkret.soland.admin.devices.query",
    tags("soland-admin", "devices"),
    summary = "Production admin devices query (typed, cursor-paginated)",
    status_codes(200, 400, 401, 403, 410, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.devices.query"))]
pub(super) async fn admin_list_devices(
    aa: AuthArgs,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminDeviceList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let limit = clamp_limit(state, limit.into_inner());
    let cursor = cursor.into_inner();

    let mut filters = BTreeMap::new();
    let name_or_id =
        query_param(req, "filter[name_or_id]").filter(|value| !value.trim().is_empty());
    if let Some(needle) = &name_or_id {
        filters.insert("name_or_id".to_owned(), needle.clone());
    }

    let mut rows: Vec<AdminDevice> = state
        .identity_application()
        .devices()
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to list devices");
            AppError::internal("device store unavailable")
        })?
        .iter()
        .map(admin_device_row)
        .collect();
    if let Some(needle) = &name_or_id {
        let needle = needle.to_lowercase();
        rows.retain(|device| {
            contains_ci(&device.id, &needle)
                || device
                    .actor_id
                    .as_deref()
                    .is_some_and(|actor| contains_ci(actor, &needle))
                || device
                    .display_name
                    .as_deref()
                    .is_some_and(|name| contains_ci(name, &needle))
        });
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let total = rows.len() as u64;
    let (devices, next_cursor, has_more) =
        paginate_by_id(rows, cursor.as_deref(), limit, |device| device.id.as_str())?;

    query_audit_trail(
        state,
        &session,
        "admin.devices.query",
        &filters,
        devices.len(),
    )
    .await;
    json_ok(AdminDeviceList {
        devices,
        total: Some(total),
        next_cursor,
        has_more,
        filters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paginate_by_id_walks_pages_and_flags_has_more() {
        let rows = vec!["a", "b", "c", "d", "e"];
        let (page, next, has_more) =
            paginate_by_id(rows.clone(), None, 2, |row| row).expect("first page");
        assert_eq!(page, vec!["a", "b"]);
        assert_eq!(next.as_deref(), Some("b"));
        assert!(has_more);

        let (page, next, has_more) =
            paginate_by_id(rows.clone(), Some("b"), 2, |row| row).expect("second page");
        assert_eq!(page, vec!["c", "d"]);
        assert_eq!(next.as_deref(), Some("d"));
        assert!(has_more);

        let (page, next, has_more) =
            paginate_by_id(rows, Some("d"), 2, |row| row).expect("last page");
        assert_eq!(page, vec!["e"]);
        assert_eq!(next, None);
        assert!(!has_more);
    }

    #[test]
    fn paginate_by_id_expired_cursor_is_gone() {
        let error = paginate_by_id(vec!["a", "b"], Some("zz"), 2, |row| row)
            .expect_err("unresolvable cursor must fail");
        assert_eq!(error.status, Some(salvo::http::StatusCode::GONE));
    }

    /// Production-mode admin-principal gate: a session whose actor is not
    /// listed in `SOLAND_ADMIN_PRINCIPAL_DIDS` is a hard 403; listing the
    /// DID admits it. (The HTTP-level 401 path is covered by the
    /// `admin_production_queries` contract tests; this locks the
    /// authorization decision itself, which dev-mode fixtures cannot reach.)
    #[test]
    fn require_admin_principal_is_fail_closed_in_production() {
        let session = |actor: &str| soland_application::identity::SessionIdentityState {
            token_hash: "hash".to_owned(),
            actor: actor.to_owned(),
            device_id: "ak:device:test".to_owned(),
            audience: "soland".to_owned(),
            session_public_key: None,
            agent_session: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        let state = AppState::new(
            crate::config::AppConfig {
                development_mode: false,
                admin_principal_dids: vec!["did:web:op.example".to_owned()],
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        );

        let denied = super::require_admin_principal(&state, session("did:web:nobody.example"))
            .expect_err("non-admin principal must be rejected in production");
        assert_eq!(denied.status, Some(salvo::http::StatusCode::FORBIDDEN));

        super::require_admin_principal(&state, session("did:web:op.example"))
            .expect("listed admin principal must be admitted");
    }
}
