//! Realm-link state-machine helpers.
//!
//! Realm links are relationship metadata only. Current-v1 does not project
//! automatic policy, capability, membership, retention, notification, or
//! history state through a link.

use super::ProjectionState;

/// Projection-local facet coordinate of one directed Realm Link.
#[must_use]
pub fn realm_link_facet(target_realm_id: &str, link_kind: &str) -> super::FacetRef {
    super::FacetRef::composite(super::facet::REALM_LINK, &[target_realm_id, link_kind])
}

/// Preflight admission check for a proposed `ak.realm.link` write.
pub fn check_realm_link_admissible(
    state: &ProjectionState,
    source_realm_id: &str,
    target_realm_id: &str,
    link_kind: &str,
    status: &str,
) -> Result<(), &'static str> {
    if arkret_models_collaboration::governance::realm_governance::RealmLinkKind::parse(link_kind)
        .is_none()
    {
        return Err("realm_link_kind_invalid");
    }
    if source_realm_id == target_realm_id {
        return Err("realm_link_self_reference");
    }
    let Some(next_status) =
        arkret_models_collaboration::governance::realm_governance::RealmLinkStatus::parse(status)
    else {
        return Err("realm_link_status_invalid");
    };
    let current_status = state
        .realm_links
        .get(source_realm_id)
        .and_then(|links| {
            links
                .iter()
                .find(|link| link.target_realm_id == target_realm_id && link.link_kind == link_kind)
        })
        .and_then(|link| {
            arkret_models_collaboration::governance::realm_governance::RealmLinkStatus::parse(
                &link.status,
            )
        });
    if current_status.is_some_and(|current| !current.can_transition_to(next_status)) {
        return Err(arkret_wire::ReasonCode::REALM_LINK_INVALID_TRANSITION);
    }
    Ok(())
}
