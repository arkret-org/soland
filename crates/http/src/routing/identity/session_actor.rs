//! Complete Actor identities derived from authenticated Station credentials.

use arkret_models_identity::session_credential::{
    SessionGrantCredentialClass, SessionGrantHolderBinding,
};
use arkret_wire::{AccountId, ActorId, DidCoreId};
use soland_http::error::AppError;
use soland_services::identity::SessionIdentityState;

use crate::state::AppState;

/// Pure projection for read models receiving an already authenticated session.
/// The HTTP boundary verifies its local account row separately below.
pub(crate) fn session_actor_from_credential(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<ActorId, AppError> {
    let principal = DidCoreId::new(session.actor.clone())
        .map_err(|_| AppError::unauthenticated("session principal is invalid"))?;
    let station = DidCoreId::new(session.audience.clone())
        .map_err(|_| AppError::unauthenticated("session Station is invalid"))?;
    if station != state.service_core_id() {
        return Err(AppError::unauthenticated(
            "session audience does not match this Station",
        ));
    }
    if let Some(grant) = session.session_grant.as_ref()
        && (grant.account_id.principal_id != principal || grant.account_id.station_id != station)
    {
        return Err(AppError::unauthenticated(
            "session must retain the signed grant's exact AccountId",
        ));
    }
    let hosted = match session
        .session_grant
        .as_ref()
        .map(|grant| &grant.holder_binding)
    {
        Some(SessionGrantHolderBinding::AgentRuntime {
            agent_id,
            device_id,
            ..
        }) => {
            if agent_id != &principal || device_id.as_str() != session.device_id {
                return Err(AppError::unauthenticated(
                    "AgentRuntime holder does not match the session",
                ));
            }
            true
        }
        Some(_) if session.agent_session.is_some() => {
            return Err(AppError::unauthenticated(
                "human credential cannot carry an Agent session",
            ));
        }
        Some(_) => false,
        None => session.agent_session.is_some(),
    };
    Ok(if hosted {
        ActorId::hosted_principal(principal, station)
    } else {
        ActorId::account(AccountId::new(principal, station))
    })
}

/// Verify the exact stored Account binding without a principal-only lookup.
pub(crate) async fn validated_session_actor(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<ActorId, AppError> {
    let actor = session_actor_from_credential(state, session)?;
    let Some(account_id) = actor.as_account_id() else {
        return Ok(actor);
    };
    let Some(account_pk) = session.account_pk else {
        // Recovery pre-proof credentials identify an Account but grant no
        // account-data access. The recovery operation allowlist remains in force.
        if session.session_grant.as_ref().is_some_and(|grant| {
            grant.credential_class == SessionGrantCredentialClass::RecoverySession
        }) {
            return Ok(actor);
        }
        return Err(AppError::unauthenticated(
            "session account binding is missing",
        ));
    };
    let account = state
        .identities()
        .account_by_id(account_pk)
        .await
        .map_err(|error| AppError::internal(format!("session account lookup failed: {error}")))?
        .ok_or_else(|| AppError::unauthenticated("session account no longer exists"))?;
    if account.pk != account_pk
        || &account.account_id != account_id
        || account.principal_id != account_id.principal_id
    {
        return Err(AppError::unauthenticated(
            "session does not bind the exact stored Account",
        ));
    }
    Ok(actor)
}

/// Resolve an introspected credential's already verified AccountId to its local
/// row, then apply the same binding check as a persisted bearer session.
pub(crate) async fn bind_authenticated_session_account(
    state: &AppState,
    session: &mut SessionIdentityState,
) -> Result<(), AppError> {
    let actor = session_actor_from_credential(state, session)?;
    if session.account_pk.is_none()
        && session.session_grant.is_some()
        && let Some(account_id) = actor.as_account_id()
    {
        session.account_pk = state
            .identities()
            .account(account_id)
            .await
            .map_err(|error| AppError::internal(format!("session account lookup failed: {error}")))?
            .map(|account| account.pk);
    }
    validated_session_actor(state, session).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AppState {
        AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        )
    }

    fn session(state: &AppState) -> SessionIdentityState {
        SessionIdentityState {
            token_hash: "test".into(),
            account_pk: None,
            actor: "ak:did_core:web:alice.example".into(),
            device_id: "device".into(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn same_principal_credential_at_another_station_is_rejected() {
        let state = state();
        let mut session = session(&state);
        session.audience = "ak:did_core:web:other-station.example".into();
        assert!(session_actor_from_credential(&state, &session).is_err());
    }

    #[tokio::test]
    async fn human_bearer_without_an_account_binding_is_rejected() {
        let state = state();
        assert!(
            validated_session_actor(&state, &session(&state))
                .await
                .is_err()
        );
    }

    #[test]
    fn verified_agent_session_is_a_hosted_principal_not_an_account() {
        let state = state();
        let mut session = session(&state);
        session.agent_session = Some(soland_services::identity::AgentSessionState {
            granted_scope: vec![],
            scope_details: serde_json::json!({}),
            freshness_state: arkret_wire::FreshnessState::Fresh,
        });
        assert!(matches!(
            session_actor_from_credential(&state, &session).unwrap(),
            ActorId::HostedPrincipal { .. }
        ));
    }
}
