//! G3.S2 — Realm policy server admin HTTP surface.
//!
//! Surfaces:
//! - `GET /_arkret/self/realms/{realm_id}/policy-server` — fetch the currently-projected
//!   `ak.realm.policy_server` config. Returns 404 if neither the realm nor its `governed_by`
//!   ancestor chain has declared one.
//! - `PUT /_arkret/self/realms/{realm_id}/policy-server` — submit the caller-signed
//!   `ak.realm.policy_server` declaration through ordinary Event admission, so the reducer's
//!   validators (URL scheme, on_timeout enum) and the `ak.policy.manage` capability run.
//! - `DELETE /_arkret/self/realms/{realm_id}/policy-server` — submit the caller-signed durable
//!   `{"tombstone":true}` value to the same CAS-register cell. It takes a request body, the way
//!   `ak.self.keys.backups.resource.delete` already does: the removal is a signed Event.
//!
//! Both writes used to be authored here and signed with the service notary key under the caller's
//! `actor_id`. That is the substitution `zh/security/key-management.md` section 411 forbids, and it
//! is why `head_eq` moved to the caller too: a precondition is inside the signed bytes.
//!
//! Spec: `arkret-spec/spec/v1/zh/authz/policy-server.md` §2.

use arkret_identifiers::{Did, RealmId};
use arkret_models_collaboration::governance::realm_governance::{
    RealmPolicyServerDeleteRequestBody, RealmPolicyServerOnTimeout, RealmPolicyServerPayload,
    RealmPolicyServerReplaceRequestBody, RealmPolicyServerView,
};
use arkret_state::lattice::CellState;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{EmptyResult, JsonResult, empty_ok, json_ok};
use soland_services::identity::SessionIdentityState as SessionRecord;

use super::AuthArgs;
use crate::state::AppState;

/// The one cell every `ak.realm.policy_server` write moves: a per-Realm
/// CAS register holding either the declaration or the value tombstone.
const POLICY_SERVER_CELL: &str = "ak:cell:ak.component.realm.policy_server.v1:null";

pub(crate) fn router() -> Router {
    Router::with_path("realms").push(
        Router::with_path("{realm_id}/policy-server")
            .get(get_realm_policy_server)
            .put(put_realm_policy_server)
            .delete(delete_realm_policy_server),
    )
}

#[endpoint(
    operation_id = "ak.self.realm_policy_server.resource.get",
    summary = "Get a realm's policy server config",
    tags("realm_policy_server")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_policy_server.resource.get"))]
async fn get_realm_policy_server(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmPolicyServerView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let view = state
        .projections()
        .realm_policy_server_config(&realm_id)
        .map_err(policy_server_resolution_error)?
        .ok_or_else(|| AppError::not_found("no ak.realm.policy_server declared for this realm"))?;
    json_ok(policy_server_view(view)?)
}

#[endpoint(
    operation_id = "ak.self.realm_policy_server.resource.replace",
    summary = "Replace a realm's policy server config",
    tags("realm_policy_server")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_policy_server.resource.replace"))]
async fn put_realm_policy_server(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    body: JsonBody<RealmPolicyServerReplaceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmPolicyServerView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let submission = body.into_inner().policy_server_event;

    let realm_scope = RealmId::new(realm_id.clone())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    require_policy_manage(state, &session.actor, realm_scope.as_str()).await?;
    let payload = caller_signed_policy_server_payload(
        "policy_server_event",
        &session.actor,
        &realm_id,
        &submission.event,
    )?;
    let RealmPolicyServerPayload::Declaration(declaration) = payload else {
        return Err(AppError::invalid_param(
            "policy_server_event payload must be a declaration; the value tombstone goes through \
             DELETE",
        ));
    };
    validate_https_policy_server_url(&declaration.policy_server_url)?;
    if declaration.timeout_ms == Some(0) {
        return Err(AppError::invalid_param(
            "policy server timeout_ms must be greater than zero",
        ));
    }
    let cell_key = policy_server_cell_key(&realm_id);
    if direct_policy_server_cell_value(state, &cell_key)?.is_some() {
        require_head_eq_precondition("policy_server_event", &submission.event)?;
    }
    submit_caller_signed_policy_server_event(state, &session, &realm_scope, submission).await?;

    let view = state
        .projections()
        .realm_policy_server_config(&realm_id)
        .map_err(policy_server_resolution_error)?
        .ok_or_else(|| {
            AppError::new(
                soland_http::error::ErrorCode::InternalError,
                "policy_server projection vanished after accept",
            )
        })?;
    json_ok(policy_server_view(view)?)
}

#[endpoint(
    operation_id = "ak.self.realm_policy_server.resource.delete",
    summary = "Delete a realm's policy server config",
    tags("realm_policy_server")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_policy_server.resource.delete"))]
async fn delete_realm_policy_server(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    body: JsonBody<RealmPolicyServerDeleteRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> EmptyResult {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let submission = body.into_inner().policy_server_event;
    let realm_scope = RealmId::new(realm_id.clone())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    require_policy_manage(state, &session.actor, realm_scope.as_str()).await?;

    let cell_key = policy_server_cell_key(&realm_id);
    match direct_policy_server_cell_value(state, &cell_key)? {
        // A settled tombstone is an idempotent empty success, and the submitted
        // Event is deliberately not admitted: writing it again would change the
        // cell's history for a request that promises not to.
        Some(value) if is_policy_server_tombstone(&value) => {
            return empty_ok();
        }
        Some(_) => {}
        None => {
            return Err(AppError::not_found(
                "no direct ak.realm.policy_server declaration to tombstone for this realm",
            ));
        }
    }

    let payload = caller_signed_policy_server_payload(
        "policy_server_event",
        &session.actor,
        &realm_id,
        &submission.event,
    )?;
    if !matches!(payload, RealmPolicyServerPayload::Tombstone(tombstone) if tombstone.validate().is_ok())
    {
        return Err(AppError::invalid_param(
            "policy_server_event payload must be exactly {\"tombstone\":true} on this operation",
        ));
    }
    require_head_eq_precondition("policy_server_event", &submission.event)?;
    submit_caller_signed_policy_server_event(state, &session, &realm_scope, submission).await?;

    match state
        .projections()
        .snapshot()
        .realm_null_subject_cells
        .get(&cell_key)
    {
        Some(CellState::Value(value)) if is_policy_server_tombstone(value) => empty_ok(),
        Some(CellState::Bottom(_)) => Err(policy_server_resolution_error("cell_bottom_state")),
        _ => Err(AppError::internal(
            "policy server tombstone projection vanished after accept",
        )),
    }
}

/// What a caller-signed `ak.realm.policy_server` Event says it is writing.
///
/// The signature, envelope shape and reducer admission are the ordinary Event
/// admission path's job; this covers only the bindings between the authenticated
/// session, the request path and the submitted Event. The Realm is
/// single-sourced by `event.realm_id`, so that is what the path is checked
/// against.
fn caller_signed_policy_server_payload(
    field: &str,
    actor: &str,
    realm_id: &str,
    event: &arkret_wire::Event,
) -> Result<RealmPolicyServerPayload, AppError> {
    if event.kind != arkret_wire::EventKind::REALM_POLICY_SERVER {
        return Err(AppError::invalid_param(format!(
            "{field}.event.kind must be ak.realm.policy_server"
        )));
    }
    if event.actor_id.as_str() != actor {
        return Err(AppError::invalid_param(format!(
            "{field}.event.actor_id must be the authenticated caller"
        )));
    }
    if event.realm_id.as_str() != realm_id {
        return Err(AppError::invalid_param(format!(
            "{field}.event.realm_id must equal the path realm_id"
        )));
    }
    serde_json::from_value(serde_json::Value::Object(
        event.payload.clone().into_iter().collect(),
    ))
    .map_err(|error| AppError::invalid_param(format!("{field} payload: {error}")))
}

/// Require the caller's own `head_eq` guard on the policy-server cell.
///
/// The service used to attach this precondition after reading the settled value.
/// It cannot any more: preconditions are inside the bytes the caller signs, so
/// attaching one would be rewriting the Event. What the service can still do is
/// refuse an unguarded write against a settled cell, which is what the operation
/// requires. Whether the guarded value actually matches is admission's check.
fn require_head_eq_precondition(field: &str, event: &arkret_wire::Event) -> Result<(), AppError> {
    let guarded = event.preconditions.iter().any(|precondition| {
        precondition.cell.as_str() == POLICY_SERVER_CELL
            && precondition.predicate.op == arkret_wire::PredicateOp::HeadEq
    });
    if guarded {
        return Ok(());
    }
    Err(AppError::new(
        soland_http::error::ErrorCode::FailedPrecondition,
        format!(
            "{field} MUST carry a head_eq precondition on {POLICY_SERVER_CELL} naming the settled              value it replaces"
        ),
    )
    .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
    .with_wire_code("failed_precondition"))
}

/// Submit the caller's exact Event bytes through ordinary Event admission.
///
/// No Event is built here and none is co-signed. This replaced a helper that
/// authored the Move under the caller's `actor_id` and signed it with the
/// service notary key -- the substitution `key-management.md` section 411
/// forbids outright. The local signing pass stays: sealing is the notary's own
/// job, and it is what lets this response observe the resulting Seal.
async fn submit_caller_signed_policy_server_event(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &RealmId,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<(), AppError> {
    crate::routing::events::event_log::submit_initial_event_submission(state, session, submission)
        .await
        .map(|_| ())
        .map_err(|error| {
            crate::routing::events::event_log::submit_one_error_to_app_error(
                "ak.realm.policy_server submit failed",
                error.status,
                error.code,
                &error.message,
            )
        })?;
    match crate::notary::run_one_signing_pass(state, realm_id, 1024).await {
        Ok(_) | Err(crate::notary::NotaryError::NotAuthorized(_)) => {}
        Err(error) => {
            tracing::warn!(
                %error,
                realm_id = %realm_id,
                "policy server Control Move remains pending after local signing pass"
            );
        }
    }
    Ok(())
}

fn policy_server_view(
    view: soland_services::authorization::RealmPolicyServerConfigView,
) -> Result<RealmPolicyServerView, AppError> {
    let cfg = view.config;
    Ok(RealmPolicyServerView {
        realm_id: RealmId::new(cfg.realm_id)
            .map_err(|error| AppError::internal(format!("stored realm_id is invalid: {error}")))?,
        policy_server_did: Did::new(cfg.policy_server_did).map_err(|error| {
            AppError::internal(format!("stored policy_server_did is invalid: {error}"))
        })?,
        policy_server_url: cfg.policy_server_url,
        cache_ttl_seconds: cfg.cache_ttl_seconds,
        timeout_ms: cfg.timeout_ms,
        on_timeout: match cfg.on_timeout.as_str() {
            "fail_closed" => RealmPolicyServerOnTimeout::FailClosed,
            "deny" => RealmPolicyServerOnTimeout::Deny,
            _ => {
                return Err(AppError::internal(
                    "stored policy server timeout mode is invalid",
                ));
            }
        },
        updated_at: cfg.updated_at,
        from_org_fallback: view.inherited_from_organization,
    })
}

fn validate_https_policy_server_url(raw_url: &str) -> Result<(), AppError> {
    let url = url::Url::parse(raw_url)
        .map_err(|error| AppError::invalid_param(format!("policy_server_url: {error}")))?;
    if url.scheme() != "https" {
        return Err(AppError::invalid_param("policy_server_url must use https"));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AppError::invalid_param(
            "policy_server_url must not contain credentials, query, or fragment",
        ));
    }
    if url.host_str().is_none() || url.path() != "/_arkret/self/policy/check" {
        return Err(AppError::invalid_param(
            "policy_server_url must target /_arkret/self/policy/check",
        ));
    }
    Ok(())
}

fn policy_server_cell_key(realm_id: &str) -> (String, String) {
    (realm_id.to_owned(), POLICY_SERVER_CELL.to_owned())
}

fn direct_policy_server_cell_value(
    state: &AppState,
    cell_key: &(String, String),
) -> Result<Option<serde_json::Value>, AppError> {
    let snapshot = state.projections().snapshot();
    match snapshot.realm_null_subject_cells.get(cell_key) {
        Some(CellState::Bottom(_)) => Err(policy_server_resolution_error("cell_bottom_state")),
        Some(CellState::Value(value)) if is_policy_server_tombstone(value) => {
            Ok(Some(value.clone()))
        }
        Some(CellState::Value(value))
            if matches!(
                serde_json::from_value::<RealmPolicyServerPayload>(value.clone()),
                Ok(RealmPolicyServerPayload::Declaration(_))
            ) && snapshot.realm_policy_servers.contains_key(&cell_key.0) =>
        {
            Ok(Some(value.clone()))
        }
        Some(CellState::Value(_)) => Err(policy_server_resolution_error(
            "realm_policy_server_projection_missing",
        )),
        None if snapshot.realm_policy_servers.contains_key(&cell_key.0) => Err(
            policy_server_resolution_error("realm_policy_server_projection_missing"),
        ),
        None => Ok(None),
    }
}

fn is_policy_server_tombstone(value: &serde_json::Value) -> bool {
    matches!(
        serde_json::from_value::<RealmPolicyServerPayload>(value.clone()),
        Ok(RealmPolicyServerPayload::Tombstone(tombstone)) if tombstone.validate().is_ok()
    )
}

async fn require_policy_manage(
    state: &AppState,
    actor: &str,
    realm_id: &str,
) -> Result<(), AppError> {
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(realm_id, actor, chrono::Utc::now())
    {
        return Ok(());
    }
    let (owner, members) =
        crate::routing::events::operations::realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            action: arkret_wire::CapabilityActionId::POLICY_MANAGE,
            resource: realm_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
    {
        Ok(())
    } else {
        Err(AppError::capability_denied("missing_capability"))
    }
}

fn policy_server_resolution_error(reason: &'static str) -> AppError {
    if reason == "cell_bottom_state" {
        return AppError::new(
            soland_http::error::ErrorCode::FailedPrecondition,
            "realm policy-server cell is in Bottom",
        )
        .with_status(salvo::http::StatusCode::CONFLICT)
        .with_wire_code("failed_bottom");
    }
    AppError::new(
        soland_http::error::ErrorCode::FailedPrecondition,
        format!("realm policy-server resolution failed closed: {reason}"),
    )
    .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
    .with_wire_code("failed_precondition")
}

#[cfg(test)]
mod caller_signed_policy_server_tests {
    use serde_json::{Value, json};

    use super::*;

    const ACTOR: &str = "did:web:alice.example";
    const REALM: &str = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";

    fn policy_server_event(actor: &str, realm_id: &str, payload: Value) -> arkret_wire::Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AUbhLbszCE22Bm-rjOxxh9NLjudxjc1Jm38OX5PZttdw",
            "kind": arkret_wire::EventKind::REALM_POLICY_SERVER,
            "realm_id": realm_id,
            "scope_ref": { "kind": "realm", "realm_id": realm_id },
            "actor_id": actor,
            "actor_seq": 0,
            "created_at": "2026-07-06T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": payload,
            "proofs": [],
        }))
        .expect("policy server envelope")
    }

    fn declaration() -> Value {
        json!({
            "policy_server_did": "did:web:policy.example",
            "policy_server_url": "https://policy.example/_arkret/self/policy/check",
        })
    }

    fn with_head_eq(mut event: arkret_wire::Event, value: Value) -> arkret_wire::Event {
        event.preconditions = serde_json::from_value(json!([{
            "cell": POLICY_SERVER_CELL,
            "predicate": { "op": "head_eq", "value": value },
        }]))
        .expect("head_eq precondition");
        event
    }

    #[test]
    fn the_declaration_is_read_off_the_signed_payload() {
        let payload = caller_signed_policy_server_payload(
            "policy_server_event",
            ACTOR,
            REALM,
            &policy_server_event(ACTOR, REALM, declaration()),
        )
        .unwrap();
        let RealmPolicyServerPayload::Declaration(declaration) = payload else {
            panic!("a declaration payload must not parse as the value tombstone");
        };
        assert_eq!(
            declaration.policy_server_did.as_str(),
            "did:web:policy.example"
        );
    }

    #[test]
    fn an_event_signed_by_someone_else_is_rejected() {
        caller_signed_policy_server_payload(
            "policy_server_event",
            "did:web:mallory.example",
            REALM,
            &policy_server_event(ACTOR, REALM, declaration()),
        )
        .expect_err("the submitted Event must be authored by the authenticated caller");
    }

    #[test]
    fn a_body_naming_another_realm_is_rejected() {
        caller_signed_policy_server_payload(
            "policy_server_event",
            ACTOR,
            "ak:realm:AW6ST0TiEb2kdaVDQ-YtsKW8ig0EM-l6_Y5YiT16u7b-",
            &policy_server_event(ACTOR, REALM, declaration()),
        )
        .expect_err("event.realm_id must equal the path realm_id");
    }

    #[test]
    fn an_unguarded_write_against_a_settled_cell_is_refused() {
        // The service used to attach `head_eq` itself after reading the settled
        // value. It cannot now — a precondition is inside the signed bytes — so
        // all it can do is refuse the unguarded write.
        let event = policy_server_event(ACTOR, REALM, declaration());
        let error = require_head_eq_precondition("policy_server_event", &event)
            .expect_err("a settled cell needs the caller's own head_eq");
        assert_eq!(
            error.code,
            soland_http::error::ErrorCode::FailedPrecondition
        );

        require_head_eq_precondition("policy_server_event", &with_head_eq(event, declaration()))
            .expect("a caller-attached head_eq satisfies the guard");
    }

    #[test]
    fn the_tombstone_payload_is_recognized_as_the_value_tombstone() {
        let payload = caller_signed_policy_server_payload(
            "policy_server_event",
            ACTOR,
            REALM,
            &policy_server_event(ACTOR, REALM, json!({ "tombstone": true })),
        )
        .unwrap();
        assert!(matches!(payload, RealmPolicyServerPayload::Tombstone(_)));
    }
}
