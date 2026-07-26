use soland_http::error::AppError;

use crate::state::AppState;

pub(crate) fn ensure_private_inbound_read_rail_local(state: &AppState) -> Result<(), AppError> {
    if state.config().development_mode {
        return Ok(());
    }
    Err(AppError::unsupported_feature(
        "the /_soland/peer/federation/* read rail is a deployment-local debug affordance and is \
         disabled outside development mode. Use the protocol federation track \
         (/_arkret/peer/*) for cross-deployment reads",
    )
    .with_wire_code("federation_private_read_rail_local_only"))
}

pub(crate) async fn federation_actor_origin_acceptable(
    state: &AppState,
    actor: &str,
    source_service_id: &str,
    binding_realm: &str,
) -> bool {
    if did_deployment_authority(actor).is_some()
        && did_deployment_authority(actor) == did_deployment_authority(source_service_id)
    {
        return true;
    }
    crate::routing::spaces::space::realm_has_member(state, binding_realm, actor).await
}

fn did_deployment_authority(did: &str) -> Option<String> {
    let authority = if let Some(rest) = did.strip_prefix("did:web:") {
        rest.split(':').next()?
    } else {
        let rest = did.strip_prefix("did:webvh:")?;
        let mut parts = rest.split(':');
        let scid = parts.next()?;
        if scid.is_empty() {
            return None;
        }
        parts.next()?
    };
    let authority = authority.trim_end_matches('.');
    (!authority.is_empty()).then(|| authority.to_ascii_lowercase())
}
