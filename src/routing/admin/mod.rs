use salvo::prelude::*;

mod anchor;
pub(crate) mod audit;
mod cells;
mod collection;
mod control;
mod delivery_binding;
mod introspect;
mod moderation;
mod retention;
mod spec;

use audit::append_audit_log;
pub(super) use introspect::{introspect_admin_scopes, require_admin_scope};

use super::system::util;
use super::{
    AuthArgs, demo_actors, device_inventory_to_json, discussion_track_for_projection_event,
    flow_id_for_projection_event, flow_id_from_space_id, flow_projection_for_space, now,
    policy_document_to_response, projection_event_from_operation, sha256_hex, space_has_member,
};
use crate::error::{AppError, ErrorCode};
use crate::state::{AppState, SessionRecord};

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
        let result = match depot.obtain::<AppState>() {
            Ok(state) => match AuthArgs::default().authenticated_session(state, req).await {
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
    if state.config.development_mode || state.config.is_admin_principal(&session.actor) {
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

/// Audit endpoints (`/_cokret/self/audit/*`). These live on the protocol
/// surface under the `self` trust segment, not the deployment-local
/// `/_soland/admin/*` namespace, and carry their own per-handler auth
/// rather than the shared `RequireAdmin` hoop — so they are mounted
/// separately from the admin branch below.
pub fn audit_router() -> Router {
    audit::router()
}

/// Deployment-local admin branch served at the bare `/admin/*`
/// namespace (collection snapshot, cell inspection, control-frame
/// triggers, retention), per cokret-spec `service-http-binding.md`
/// §2.1: `/admin/*` is deployment-local and MUST NOT carry the
/// `/_cokret/...` protocol prefix. Gated by the shared `RequireAdmin` hoop.
pub fn router() -> Router {
    Router::new()
        .hoop(RequireAdmin::scope(cokret_sdk::admin_scopes::ADMIN_READ))
        .push(cells::router())
        .push(Router::with_path("admin/{resource}").get(collection::admin_collection))
        .push(control::router())
        .push(retention::router())
}

pub fn spec_router() -> Router {
    spec::router().hoop(RequireAdmin::scope(cokret_sdk::admin_scopes::ADMIN_READ))
}

pub fn admin_router() -> Router {
    // Deployment-local operator surface served at the bare `/admin/*`
    // namespace (anchorer / anchor-DAG / bottom repair / multisig /
    // gc-candidates / delivery-binding / moderation). Per cokret-spec
    // `service-http-binding.md` §2.1 the `/admin/*` namespace is
    // deployment-local and MUST NOT carry the `/_cokret/...` protocol prefix.
    // Registered ahead of `router()` (the `{resource}` collection
    // wildcard) at the root so the concrete `bottom` segment wins.
    Router::with_path("admin")
        .oapi_tag("admin")
        .hoop(RequireAdmin::scope(cokret_sdk::admin_scopes::ADMIN_READ))
        .push(Router::with_path("spaces/{space_id}/anchorer").get(anchor::admin_get_anchorer))
        .push(
            Router::with_path("spaces/{space_id}/anchorer/reconfigure")
                .post(anchor::admin_reconfigure_anchorer),
        )
        .push(
            Router::with_path("spaces/{space_id}/anchorer/rotate-signing-key")
                .post(anchor::admin_rotate_signing_key),
        )
        .push(Router::with_path("spaces/{space_id}/bottom").get(anchor::admin_list_space_bottom))
        .push(Router::with_path("bottom").get(anchor::admin_list_bottom_global))
        .push(
            Router::with_path("spaces/{space_id}/bottom/{cell_id}/repair")
                .post(anchor::admin_repair_bottom),
        )
        .push(Router::with_path("spaces/{space_id}/anchor-dag").get(anchor::admin_get_anchor_dag))
        .push(
            Router::with_path("spaces/{space_id}/anchor-dag/compact")
                .post(anchor::admin_compact_anchor_dag),
        )
        .push(
            Router::with_path("spaces/{space_id}/anchor-dag/prune")
                .post(anchor::admin_prune_anchor_dag),
        )
        .push(
            Router::with_path("spaces/{space_id}/multisig/pending")
                .get(anchor::admin_list_multisig_pending),
        )
        .push(
            Router::with_path("spaces/{space_id}/multisig/{anchor_id}/partial")
                .post(anchor::admin_submit_multisig_partial),
        )
        .push(
            Router::with_path("spaces/{space_id}/gc-candidates")
                .get(anchor::admin_list_gc_candidates),
        )
        // R2.2 — Realm delivery-binding-policy admin surface (post
        // Realm/Space reversal). Aggressive-mode v1: the old
        // `/spaces/{id}/delivery-binding-policy` path returns 410 Gone
        // so callers fail loudly instead of silently reading a stale
        // shape.
        .push(
            Router::with_path("realms/{realm_id}/delivery-binding-policy")
                .get(delivery_binding::admin_get_realm_delivery_binding_policy),
        )
        .push(
            Router::with_path("spaces/{space_id}/delivery-binding-policy")
                .get(delivery_binding::admin_legacy_space_delivery_binding_policy_gone),
        )
        .push(moderation::router())
}
