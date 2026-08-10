use salvo::prelude::*;

mod actors;
pub(crate) mod audit;
mod cells;
mod collection;
mod control;
mod delivery_binding;
mod handles;
mod introspect;
mod media;
mod moderation;
mod queries;
mod retention;
mod seal;
mod server_ops;
mod service_routes;
mod settings;

use audit::append_audit_log;
pub(super) use introspect::{introspect_admin_scopes, require_admin_scope};
use soland_http::error::{AppError, ErrorCode};
use soland_http::util;
use soland_services::identity::SessionIdentityState as SessionRecord;

use super::{
    AuthArgs, discussion_track_for_projection_event, now, policy_document_to_response,
    projection_event_from_operation, realm_has_member, strand_id_for_projection_event,
    strand_id_from_realm_id, strand_projection_for_realm,
};
use crate::state::AppState;

/// Salvo middleware that gates an admin route on an OAuth-style admin
/// scope. The middleware performs the bearer session lookup, introspects
/// the session grant through `require_admin_scope`, and only then lets
/// the endpoint handler run.
#[derive(Clone, Debug)]
pub(super) struct RequireAdmin {
    scope: &'static str,
}

impl RequireAdmin {
    pub(super) fn scope(scope: &'static str) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl Handler for RequireAdmin {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let result = match depot.get_typed::<AppState>() {
            Ok(state) => match AuthArgs.authenticated_session(state, req).await {
                Ok(session) => require_admin_scope(state, req, &session, self.scope)
                    .await
                    .map(|_| ()),
                Err(error) => Err(error),
            },
            Err(_) => Err(AppError::internal("state not injected")),
        };

        if let Err(error) = result {
            error.write(req, depot, res).await;
            return;
        }
        ctrl.call_next(req, depot, res).await;
    }
}

/// Gate a write-side admin handler on the caller's authorization.
///
/// In `development_mode` any authenticated session is allowed. In production
/// mode the session actor MUST appear in `AppConfig::admin_principal_dids`
/// (env `SOLAND_ADMIN_PRINCIPAL_DIDS`). Returns the original session on
/// success or an `AppError` with `capability_denied` on failure.
pub(super) fn require_admin_principal(
    state: &AppState,
    session: SessionRecord,
) -> Result<SessionRecord, AppError> {
    if state.config().development_mode || state.is_admin_principal(&session.actor) {
        Ok(session)
    } else {
        Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "admin API requires the caller DID to be listed in SOLAND_ADMIN_PRINCIPAL_DIDS"
                .to_owned(),
        )
        .with_status(salvo::http::StatusCode::FORBIDDEN))
    }
}

/// Client audit ingest (`/_soland/self/audit/*`): user-action telemetry and
/// franking-proof verification. Carries per-handler actor auth (plus the
/// `self` session-PoP hoop at the mount point); operator audit queries live
/// in the admin-gated branch below (see `admin_router`).
pub fn audit_ingest_router() -> Router {
    audit::ingest_router()
}

/// Deployment-local admin branch served at the bare `/admin/*`
/// namespace (collection snapshot, cell inspection, control-frame
/// triggers, retention), per arkret-spec `service-http-binding.md`
/// §2.1: `/admin/*` is deployment-local and MUST NOT carry the
/// `/_arkret/...` protocol prefix. Gated by the shared `RequireAdmin` hoop.
pub fn router() -> Router {
    Router::new()
        .hoop(RequireAdmin::scope(
            arkret_models_identity::admin_grant::admin_scopes::ADMIN_READ,
        ))
        .push(cells::router())
        .push(Router::with_path("admin/{resource}").get(collection::admin_collection))
        .push(control::router())
        .push(retention::router())
        .push(settings::router())
}

pub fn server_ops_router() -> Router {
    server_ops::router().hoop(RequireAdmin::scope(
        arkret_models_identity::admin_grant::admin_scopes::ADMIN_READ,
    ))
}

pub fn admin_router() -> Router {
    // Deployment-local operator surface served at the bare `/admin/*`
    // namespace (notary / seal-DAG / bottom repair / multisig /
    // gc-candidates / delivery-binding / moderation). Realm-scoped
    // operations use `/admin/realms/{realm_id}`; Space containers are
    // reserved for `/admin/spaces/*`. Per arkret-spec
    // `service-http-binding.md` §2.1 the `/admin/*` namespace is
    // deployment-local and MUST NOT carry the `/_arkret/...` protocol prefix.
    // Registered ahead of `router()` (the `{resource}` collection
    // wildcard) at the root so the concrete `bottom` segment wins.
    Router::with_path("admin")
        .hoop(RequireAdmin::scope(arkret_models_identity::admin_grant::admin_scopes::ADMIN_READ))
        .push(Router::with_path("realms").post(collection::admin_create_realm))
        .push(
            Router::with_path("realms/{realm_id}").get(collection::admin_get_realm),
        )
        .push(
            Router::with_path("realms/{realm_id}/members")
                .get(collection::admin_list_realm_members),
        )
        .push(
            Router::with_path("realms/{realm_id}/links")
                .get(crate::routing::realms::admin_list_realm_links),
        )
        .push(
            Router::with_path("realms/{realm_id}/organizations")
                .get(crate::routing::realm_organization::admin_list_realm_organizations),
        )
        .push(
            Router::with_path("viewer")
                .get(crate::routing::identity::account::admin_account_viewer),
        )
        .push(crate::routing::identity::key_backup::admin_router())
        .push(Router::with_path("realms/{realm_id}/notary").get(seal::admin_get_notary))
        .push(Router::with_path("realms/{realm_id}/bottom").get(seal::admin_list_realm_bottom))
        .push(Router::with_path("bottom").get(seal::admin_list_bottom_global))
        .push(
            Router::with_path("realms/{realm_id}/bottom/{cell_id}/repair")
                .post(seal::admin_repair_bottom),
        )
        .push(Router::with_path("realms/{realm_id}/seal-dag").get(seal::admin_get_seal_dag))
        .push(
            Router::with_path("realms/{realm_id}/seal-dag/prune").post(seal::admin_prune_seal_dag),
        )
        .push(
            Router::with_path("realms/{realm_id}/multisig/pending")
                .get(seal::admin_list_multisig_pending),
        )
        .push(
            Router::with_path("realms/{realm_id}/gc-candidates")
                .get(seal::admin_list_gc_candidates),
        )
        .push(
            Router::with_path("realms/{realm_id}/delivery-binding-policy")
                .get(delivery_binding::admin_get_realm_delivery_binding_policy),
        )
        // B3 — read-only member-routability view.
        .push(
            Router::with_path("realms/{realm_id}/member-routability")
                .get(delivery_binding::admin_list_member_routability),
        )
        // B4 — read-only delivery-binding handover audit view.
        .push(
            Router::with_path("realms/{realm_id}/delivery-binding/handovers")
                .get(delivery_binding::admin_list_delivery_binding_handovers),
        )
        // B2 — operator handle cluster (list / get / audit / revoke / reassign).
        .push(handles::router())
        .push(actors::router())
        // D14 — production typed queries replacing the dev snapshot
        // collection for capabilities / devices (actors and audit hang off
        // their own routers above/below).
        .push(Router::with_path("capabilities").get(queries::admin_list_capabilities))
        .push(Router::with_path("devices").get(queries::admin_list_devices))
        .push(media::router())
        .push(moderation::router())
        .push(service_routes::router())
        // Operator audit queries (`/_soland/admin/audit/events`,
        // `/_soland/admin/audit/erasure-receipts`) under the shared
        // `RequireAdmin` gate (SOL-NAME-02 — client ingest lives at
        // `/_soland/self/audit/*` instead of a second mount of this tree).
        .push(audit::ops_router())
}
