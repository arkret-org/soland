use arkret_identifiers::{DidCoreId, DidFullId, project_full_id_to_core_id};
use arkret_models_identity::{
    OrganizationRegistrationChallenge, OrganizationRegistrationChallengeRequestBody,
    OrganizationRegistrationEnsureRequestBody, OrganizationRegistrationOutcome,
    OrganizationRegistrationRefreshRequestBody, OrganizationRegistrationRevokeRequestBody,
    OrganizationRegistrationScope,
};
use arkret_signatures::Ed25519DetachedJwsSigner;
use salvo::http::StatusCode;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::Value;
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::organization_registration::{
    OrganizationRegistrationError, OrganizationRegistrationErrorCode,
    OrganizationRegistrationReceiptSigner,
};

use super::AuthArgs;
use crate::state::AppState;

struct CurrentReceiptSigner {
    issuer_service_id: DidCoreId,
    verification_method: arkret_wire::DidUrl,
    signer: Ed25519DetachedJwsSigner,
}

impl CurrentReceiptSigner {
    fn from_state(state: &AppState) -> Result<Self, AppError> {
        let issuer_service_id = DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service core id is invalid: {error}")))?;
        let issuer_full_id = state.service_resolution_commitment().full_id.clone();
        let verification_method = arkret_wire::DidUrl::new(format!("{issuer_full_id}#notary-key"))
            .map_err(|error| {
                AppError::internal(format!(
                    "service notary verification method is invalid: {error}"
                ))
            })?;
        let signer = Ed25519DetachedJwsSigner::new(
            state.notary_signing_key().as_ref().clone(),
            verification_method.as_str().to_owned(),
        );
        Ok(Self {
            issuer_service_id,
            verification_method,
            signer,
        })
    }
}

impl OrganizationRegistrationReceiptSigner for CurrentReceiptSigner {
    fn issuer_service_id(&self) -> &DidCoreId {
        &self.issuer_service_id
    }

    fn verification_method(&self) -> &arkret_wire::DidUrl {
        &self.verification_method
    }

    fn sign_detached_jws(&self, signing_bytes: &[u8]) -> Result<String, String> {
        Ok(self.signer.sign_detached_jws(signing_bytes))
    }
}

#[endpoint(
    operation_id = "ak.root.identity.organization_registration.command.prepare",
    request_body = OrganizationRegistrationChallengeRequestBody,
    summary = "Prepare an external organization DID registration",
    tags("organization_registration")
)]
pub(crate) async fn prepare(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OrganizationRegistrationChallenge> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_registry_admin(state, &aa.authenticated_session(state, req).await?.actor)?;
    let body = parse_registration_body(req).await?;
    let issuer = DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service core id is invalid: {error}")))?;
    let origin = format!("{}/", state.config().public_base_url.trim_end_matches('/'));
    let challenge = state
        .organization_registrations()
        .prepare(
            body,
            &origin,
            state.config().trust_domain.as_str(),
            &issuer,
            chrono::Utc::now(),
        )
        .await
        .map_err(map_error)?;
    json_ok(challenge)
}

#[endpoint(
    operation_id = "ak.root.identity.organization_registration.command.ensure",
    request_body = OrganizationRegistrationEnsureRequestBody,
    summary = "Ensure an external organization DID registration",
    tags("organization_registration")
)]
pub(crate) async fn ensure(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OrganizationRegistrationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_registry_admin(state, &aa.authenticated_session(state, req).await?.actor)?;
    let body = parse_registration_body(req).await?;
    let signer = CurrentReceiptSigner::from_state(state)?;
    let outcome = state
        .organization_registrations()
        .ensure(body, &signer, chrono::Utc::now())
        .await
        .map_err(map_error)?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.root.identity.organization_registration.resource.get",
    summary = "Get an external organization DID registration",
    tags("organization_registration")
)]
pub(crate) async fn get(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_id: QueryParam<String, true>,
) -> JsonResult<OrganizationRegistrationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let actor = aa.authenticated_session(state, req).await?.actor;
    let organization_id = DidCoreId::new(organization_id.into_inner())
        .map_err(|error| AppError::param_invalid(format!("invalid organization_id: {error}")))?;
    let current = state
        .organization_registrations()
        .current(&organization_id)
        .await
        .map_err(map_error)?;
    let actor_core_id = authenticated_actor_core_id(&actor);
    let authorized = current.as_ref().is_some_and(|current| {
        state.is_admin_principal(&actor)
            || actor_core_id.as_ref() == Some(&current.generation.local_admin_subject)
    });
    if !authorized {
        return Err(indistinguishable_not_found());
    }
    let outcome = state
        .organization_registrations()
        .get(&organization_id)
        .await
        .map_err(|_| indistinguishable_not_found())?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.root.identity.organization_registration.command.refresh",
    summary = "Refresh an external organization DID registration",
    tags("organization_registration")
)]
pub(crate) async fn refresh(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<OrganizationRegistrationRefreshRequestBody>,
) -> JsonResult<OrganizationRegistrationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let request = body.into_inner();
    require_registration_manager(state, &aa, req, &request.organization_id).await?;
    let signer = CurrentReceiptSigner::from_state(state)?;
    let outcome = state
        .organization_registrations()
        .refresh(request, &signer, chrono::Utc::now())
        .await
        .map_err(map_error)?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.root.identity.organization_registration.command.revoke",
    summary = "Revoke an external organization DID registration",
    tags("organization_registration")
)]
pub(crate) async fn revoke(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<OrganizationRegistrationRevokeRequestBody>,
) -> JsonResult<OrganizationRegistrationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let request = body.into_inner();
    require_registration_manager(state, &aa, req, &request.organization_id).await?;
    let signer = CurrentReceiptSigner::from_state(state)?;
    let outcome = state
        .organization_registrations()
        .revoke(request, &signer, chrono::Utc::now())
        .await
        .map_err(map_error)?;
    json_ok(outcome)
}

async fn require_registration_manager(
    state: &AppState,
    aa: &AuthArgs,
    req: &mut Request,
    organization_id: &DidCoreId,
) -> Result<(), AppError> {
    let actor = aa.authenticated_session(state, req).await?.actor;
    let current = state
        .organization_registrations()
        .current(organization_id)
        .await
        .map_err(map_error)?;
    let actor_core_id = authenticated_actor_core_id(&actor);
    if current.as_ref().is_some_and(|current| {
        state.is_admin_principal(&actor)
            || actor_core_id.as_ref() == Some(&current.generation.local_admin_subject)
    }) {
        return Ok(());
    }
    Err(indistinguishable_not_found())
}

fn authenticated_actor_core_id(actor: &str) -> Option<DidCoreId> {
    let full_id = DidFullId::new(actor.to_owned()).ok()?;
    project_full_id_to_core_id(&full_id).ok()
}

fn require_registry_admin(state: &AppState, actor: &str) -> Result<(), AppError> {
    if state.is_admin_principal(actor) {
        return Ok(());
    }
    Err(AppError::capability_denied(
        "organization registration requires a trusted deployment administrator",
    ))
}

async fn parse_registration_body<T: DeserializeOwned>(req: &mut Request) -> Result<T, AppError> {
    let body = req
        .parse_json::<Value>()
        .await
        .map_err(|error| AppError::new(ErrorCode::SchemaViolation, error.to_string()))?;
    if let Some(scopes) = body.get("requested_scopes").and_then(Value::as_array) {
        for scope in scopes {
            if scope.is_string()
                && serde_json::from_value::<OrganizationRegistrationScope>(scope.clone()).is_err()
            {
                return Err(AppError::new(
                    ErrorCode::UnsupportedOrganizationRegistrationScope,
                    "organization registration scope is unsupported",
                ));
            }
        }
    }
    serde_json::from_value(body)
        .map_err(|error| AppError::new(ErrorCode::SchemaViolation, error.to_string()))
}

fn indistinguishable_not_found() -> AppError {
    AppError::new(
        ErrorCode::DidNotFound,
        "organization registration was not found",
    )
    .with_status(StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::authenticated_actor_core_id;

    #[test]
    fn authenticated_actor_is_projected_to_stable_core_id() {
        let core = authenticated_actor_core_id("did:webvh:z6mkactor:alice.example")
            .expect("active full DID projects to a core id");
        assert_eq!(core.as_str(), "ak:did_core:webvh:z6mkactor");
        assert!(authenticated_actor_core_id("ak:did_core:webvh:z6mkactor").is_none());
    }
}

fn map_error(error: OrganizationRegistrationError) -> AppError {
    let detail = error.detail;
    match error.code {
        OrganizationRegistrationErrorCode::SchemaViolation => {
            AppError::new(ErrorCode::SchemaViolation, detail)
        }
        OrganizationRegistrationErrorCode::DidNotFound => indistinguishable_not_found(),
        OrganizationRegistrationErrorCode::ChallengeInvalid => {
            AppError::new(ErrorCode::OrganizationRegistrationChallengeInvalid, detail)
        }
        OrganizationRegistrationErrorCode::ControlProofInvalid => AppError::new(
            ErrorCode::OrganizationRegistrationControlProofInvalid,
            detail,
        ),
        OrganizationRegistrationErrorCode::QuorumNotMet => {
            AppError::new(ErrorCode::OrganizationRegistrationQuorumNotMet, detail)
        }
        OrganizationRegistrationErrorCode::ScopeUnsupported => {
            AppError::new(ErrorCode::UnsupportedOrganizationRegistrationScope, detail)
        }
        OrganizationRegistrationErrorCode::Revoked => {
            AppError::new(ErrorCode::OrganizationRegistrationRevoked, detail)
        }
        OrganizationRegistrationErrorCode::Stale => {
            AppError::new(ErrorCode::OrganizationRegistrationStale, detail)
        }
        OrganizationRegistrationErrorCode::Internal => AppError::internal(detail),
    }
}
