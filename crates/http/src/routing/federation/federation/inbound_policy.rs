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
    source_id: &str,
    event_principal_server_id: Option<&str>,
    binding_realm: &str,
    event_kind: Option<&str>,
) -> bool {
    if let Some(principal_server_id) = event_principal_server_id {
        if !event_origin_matches_source(source_id, principal_server_id) {
            return false;
        }
        if did_deployment_authority(actor).is_some()
            && did_deployment_authority(actor) == did_deployment_authority(source_id)
        {
            return true;
        }
        let projection = state.projections().snapshot();
        return membership_authority_pair_acceptable(
            projection.member(binding_realm, actor),
            principal_server_id,
            event_kind,
        );
    }
    if did_deployment_authority(actor).is_some()
        && did_deployment_authority(actor) == did_deployment_authority(source_id)
    {
        return true;
    }
    if crate::routing::spaces::space::realm_has_member(state, binding_realm, actor).await {
        return true;
    }
    event_kind == Some(arkret_wire::EventKind::InviteAccept.as_str())
        && state
            .projections()
            .invite_member_is_invited(binding_realm, actor)
}

fn event_origin_matches_source(source_id: &str, principal_server_id: &str) -> bool {
    !source_id.is_empty() && source_id == principal_server_id
}

fn membership_authority_pair_acceptable(
    membership: Option<&soland_domain::reducer::SolandMembershipState>,
    principal_server_id: &str,
    event_kind: Option<&str>,
) -> bool {
    membership.is_some_and(|membership| {
        let acceptable_state = membership.state == "join"
            || (event_kind == Some(arkret_wire::EventKind::InviteAccept.as_str())
                && membership.state == "invite");
        acceptable_state && membership.recipient_id.as_deref() == Some(principal_server_id)
    })
}

fn did_deployment_authority(did: &str) -> Option<String> {
    let authority = if let Some(rest) = did
        .strip_prefix("ak:did_core:web:")
        .or_else(|| did.strip_prefix("did:web:"))
    {
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

#[cfg(test)]
mod tests {
    use super::{
        did_deployment_authority, event_origin_matches_source, membership_authority_pair_acceptable,
    };

    fn membership(
        state: &str,
        principal_server_id: &str,
    ) -> soland_domain::reducer::SolandMembershipState {
        let now = chrono::Utc::now();
        soland_domain::reducer::SolandMembershipState {
            member: "ak:did_core:web:alice.example".to_owned(),
            realm_id: "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
            state: state.to_owned(),
            role: "member".to_owned(),
            delivery_status: Some("routable".to_owned()),
            recipient_id: Some(principal_server_id.to_owned()),
            recipient_service_resolution: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
            delivery_binding_expires_at: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        }
    }

    #[test]
    fn did_deployment_authority_normalizes_did_and_core_web_ids() {
        assert_eq!(
            did_deployment_authority("did:web:Remote.Example"),
            Some("remote.example".to_owned())
        );
        assert_eq!(
            did_deployment_authority("ak:did_core:web:remote.example"),
            Some("remote.example".to_owned())
        );
    }

    #[test]
    fn event_origin_requires_the_exact_authenticated_source_service() {
        let source = "ak:did_core:web:remote.example";
        assert!(event_origin_matches_source(source, source));
        assert!(!event_origin_matches_source(
            source,
            "ak:did_core:web:other.example"
        ));
        assert!(!event_origin_matches_source("", ""));
    }

    #[test]
    fn membership_and_invite_authorization_are_bound_to_the_exact_principal_server() {
        let source = "ak:did_core:web:remote.example";
        let other = "ak:did_core:web:other.example";
        let joined = membership("join", source);
        assert!(membership_authority_pair_acceptable(
            Some(&joined),
            source,
            None
        ));
        assert!(!membership_authority_pair_acceptable(
            Some(&joined),
            other,
            None
        ));

        let invited = membership("invite", source);
        assert!(membership_authority_pair_acceptable(
            Some(&invited),
            source,
            Some(arkret_wire::EventKind::InviteAccept.as_str())
        ));
        assert!(!membership_authority_pair_acceptable(
            Some(&invited),
            source,
            Some(arkret_wire::EventKind::MessageCreate.as_str())
        ));
    }
}
