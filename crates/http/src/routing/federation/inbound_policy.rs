use crate::state::AppState;

/// Resolve an endpoint principal only through an unambiguous accepted member
/// Actor whose routing Station is authenticated by the peer request.
pub(crate) fn joined_actor_for_principal_route(
    state: &AppState,
    realm_id: &str,
    principal_id: &arkret_wire::DidCoreId,
    station_id: &arkret_wire::DidCoreId,
) -> Option<arkret_wire::ActorId> {
    let projection = state.projections().snapshot();
    let mut actors = projection
        .members
        .iter()
        .filter_map(|((realm, key), member)| {
            if realm != realm_id || member.state != "join" {
                return None;
            }
            let actor = serde_json::from_str::<arkret_wire::ActorId>(key).ok()?;
            (actor.signing_principal_id() == principal_id && actor.route_service_id() == station_id)
                .then_some(actor)
        });
    let actor = actors.next()?;
    actors.next().is_none().then_some(actor)
}

pub(crate) async fn federation_mls_actor_route_acceptable(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    source_id: &str,
    event_station_id: Option<&str>,
    binding_realm: &str,
    event_kind: Option<&str>,
) -> bool {
    if actor.route_service_id().as_str() != source_id {
        return false;
    }
    let actor_key = actor.to_string();
    let principal = actor.signing_principal_id().as_str();
    if let Some(station_id) = event_station_id {
        if !mls_event_route_matches_source(source_id, station_id) {
            return false;
        }
        if did_deployment_authority(principal).is_some()
            && did_deployment_authority(principal) == did_deployment_authority(source_id)
        {
            return true;
        }
        let projection = state.projections().snapshot();
        if membership_authority_pair_acceptable(
            projection.member(binding_realm, &actor_key),
            station_id,
        ) {
            return true;
        }
        return event_kind == Some(arkret_wire::EventKind::InviteAccept.as_str())
            && actor_has_pending_invite(state, binding_realm, actor).await;
    }
    if did_deployment_authority(principal).is_some()
        && did_deployment_authority(principal) == did_deployment_authority(source_id)
    {
        return true;
    }
    if crate::routing::spaces::space::realm_has_member(state, binding_realm, &actor_key).await {
        return true;
    }
    event_kind == Some(arkret_wire::EventKind::InviteAccept.as_str())
        && actor_has_pending_invite(state, binding_realm, actor).await
}

fn mls_event_route_matches_source(source_id: &str, station_id: &str) -> bool {
    !source_id.is_empty() && source_id == station_id
}

fn membership_authority_pair_acceptable(
    membership: Option<&soland_domain::reducer::SolandMembershipState>,
    station_id: &str,
) -> bool {
    membership.is_some_and(|membership| {
        membership.state == "join"
            && serde_json::from_str::<arkret_wire::ActorId>(&membership.member)
                .is_ok_and(|actor| actor.route_service_id().as_str() == station_id)
    })
}

async fn actor_has_pending_invite(
    state: &AppState,
    realm_id: &str,
    actor: &arkret_wire::ActorId,
) -> bool {
    let Some(account_id) = actor.as_account_id() else {
        return false;
    };
    let account_id = account_id.to_string();
    state
        .realm_invites()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .any(|invite| {
            invite.realm_id == realm_id
                && invite.invitee_id.as_deref() == Some(account_id.as_str())
                && matches!(invite.status.as_str(), "pending" | "claimed")
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
        did_deployment_authority, membership_authority_pair_acceptable,
        mls_event_route_matches_source,
    };

    fn membership(state: &str, station_id: &str) -> soland_domain::reducer::SolandMembershipState {
        let now = chrono::Utc::now();
        soland_domain::reducer::SolandMembershipState {
            member: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
                arkret_wire::DidCoreId::new(station_id.to_owned()).unwrap(),
            ))
            .to_string(),
            realm_id: "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
            state: state.to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
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
    fn mls_event_route_requires_the_exact_authenticated_source_service() {
        let source = "ak:did_core:web:remote.example";
        assert!(mls_event_route_matches_source(source, source));
        assert!(!mls_event_route_matches_source(
            source,
            "ak:did_core:web:other.example"
        ));
        assert!(!mls_event_route_matches_source("", ""));
    }

    #[test]
    fn membership_authorization_is_bound_to_join_and_the_exact_station() {
        let source = "ak:did_core:web:remote.example";
        let other = "ak:did_core:web:other.example";
        let joined = membership("join", source);
        assert!(membership_authority_pair_acceptable(Some(&joined), source));
        assert!(!membership_authority_pair_acceptable(Some(&joined), other));

        let invited = membership("invite", source);
        assert!(!membership_authority_pair_acceptable(
            Some(&invited),
            source
        ));
    }

    #[tokio::test]
    async fn endpoint_principal_requires_an_exact_unambiguous_joined_station_actor() {
        let state = crate::state::AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let row = membership("join", "ak:did_core:web:station-a.example");
        let realm = row.realm_id.clone();
        let actor: arkret_wire::ActorId = serde_json::from_str(&row.member).unwrap();
        state
            .test_projection()
            .lock()
            .members
            .insert((realm.clone(), row.member.clone()), row.clone());
        let principal = actor.signing_principal_id();
        let station = actor.route_service_id();
        assert_eq!(
            super::joined_actor_for_principal_route(&state, &realm, principal, station),
            Some(actor.clone())
        );
        let foreign = arkret_wire::DidCoreId::new("ak:did_core:web:station-b.example").unwrap();
        assert!(
            super::joined_actor_for_principal_route(&state, &realm, principal, &foreign).is_none()
        );
        assert!(
            !super::federation_mls_actor_route_acceptable(
                &state,
                &actor,
                foreign.as_str(),
                Some(foreign.as_str()),
                &realm,
                None
            )
            .await
        );
        let same_account = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            station.clone(),
        ));
        let mut repeated_row = row;
        repeated_row.member = same_account.to_string();
        state
            .test_projection()
            .lock()
            .members
            .insert((realm.clone(), same_account.to_string()), repeated_row);
        assert!(
            super::joined_actor_for_principal_route(&state, &realm, principal, station)
                == Some(same_account)
        );
    }
}
