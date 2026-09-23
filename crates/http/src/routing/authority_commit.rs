//! Canonical current-protocol routes.

use arkret_models_collaboration::authority_commit::{
    PeerAuthoritySubmitRequest, SelfAuthoritySubmitRequest,
};
use arkret_wire::{AuthorityBundleRequest, AuthorityHandoffRequest, StreamScanRequest};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;
use soland_services::{ServiceError, ServiceResult};

use crate::state::AppState;

pub fn router() -> Router {
    Router::with_path("_arkret")
        .push(
            Router::with_path("self")
                .push(Router::with_path("events").post(submit_self))
                .push(Router::with_path("streams/scan").post(scan_stream)),
        )
        .push(
            Router::with_path("peer")
                .push(Router::with_path("events").post(submit_peer))
                .push(Router::with_path("realm-authority/handoff").post(install_authority_handoff)),
        )
        .push(Router::with_path("open/realm-authority/bundle").post(authority_bundle))
}

async fn parse_current_json<T: serde::de::DeserializeOwned>(
    req: &mut Request,
) -> Result<T, String> {
    req.parse_json::<T>()
        .await
        .map_err(|error| format!("invalid canonical request body: {error}"))
}

fn state(depot: &Depot) -> Result<&AppState, String> {
    depot
        .get_typed::<AppState>()
        .map_err(|_| "authority service state is unavailable".to_owned())
}

fn validation_error(error: impl std::fmt::Display) -> String {
    format!("request does not match the current authority protocol: {error}")
}

fn invalid_application_output(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Internal(format!(
        "authority application returned an invalid current-protocol response: {error}"
    ))
}

fn render_result<T: Serialize + Send>(res: &mut Response, result: ServiceResult<T>) {
    match result {
        Ok(value) => res.render(Json(value)),
        Err(error) => render_service_error(res, error),
    }
}

fn render_bad_request(res: &mut Response, detail: String) {
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(serde_json::json!({
        "type": "https://arkret.org/problems/schema_violation",
        "status": 400,
        "code": "schema_violation",
        "detail": detail,
    })));
}

fn render_service_error(res: &mut Response, error: ServiceError) {
    let (status, code) = match &error {
        ServiceError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
        ServiceError::Conflict(_)
            if error.conflict_code()
                == Some(soland_storage::ConflictCode::MimiRoomBindingMigrationProofInvalid) =>
        {
            (
                StatusCode::CONFLICT,
                "mimi_room_binding_migration_proof_invalid",
            )
        }
        ServiceError::Conflict(_)
            if error.conflict_code()
                == Some(soland_storage::ConflictCode::RecipientQueueAtCapacity) =>
        {
            (StatusCode::FORBIDDEN, "quota_exceeded")
        }
        ServiceError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        ServiceError::SchemaViolation(_) => (StatusCode::BAD_REQUEST, "schema_violation"),
        ServiceError::Database(_) | ServiceError::Internal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    };
    let detail = if status == StatusCode::INTERNAL_SERVER_ERROR {
        "internal error".to_owned()
    } else {
        error.to_string()
    };
    res.status_code(status);
    res.render(Json(serde_json::json!({
        "type": format!("https://arkret.org/problems/{code}"),
        "status": status.as_u16(),
        "code": code,
        "detail": detail,
    })));
}

#[handler]
pub(crate) async fn submit_self(req: &mut Request, depot: &Depot, res: &mut Response) {
    let app_state = match state(depot) {
        Ok(state) => state,
        Err(error) => return render_bad_request(res, error),
    };
    let Some(session) = crate::routing::auth_or_render(app_state, req, res).await else {
        return;
    };
    if let Err(error) =
        crate::routing::identity::session_actor::validated_session_actor(app_state, &session).await
    {
        return crate::routing::render_error(
            res,
            error.http_status(),
            error.wire_code(),
            &error.message,
        );
    }
    if let Err(error) = crate::routing::events::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
    ) {
        return crate::routing::render_error(
            res,
            error.http_status(),
            error.wire_code(),
            &error.message,
        );
    }
    let request = match parse_current_json::<SelfAuthoritySubmitRequest>(req).await {
        Ok(request) => request,
        Err(error) => return render_bad_request(res, error),
    };
    if let Err(error) = request.validate() {
        return render_bad_request(res, validation_error(error));
    }
    let authority = app_state.authority();
    let result = authority
        .submit_self(&session, request.clone())
        .await
        .and_then(|outcome| {
            outcome
                .validate_for_request(&request)
                .map_err(invalid_application_output)?;
            Ok(outcome)
        });
    render_result(res, result);
}

#[handler]
async fn submit_peer(req: &mut Request, depot: &Depot, res: &mut Response) {
    let app_state = match state(depot) {
        Ok(state) => state,
        Err(error) => return render_bad_request(res, error),
    };
    let peer = match crate::routing::events::peer::authenticated_peer_context(app_state, req, true)
        .await
    {
        Ok(peer) => peer,
        Err(error) => {
            return crate::routing::render_error(
                res,
                error.http_status(),
                error.wire_code(),
                &error.message,
            );
        }
    };
    let request = match parse_current_json::<PeerAuthoritySubmitRequest>(req).await {
        Ok(request) => request,
        Err(error) => return render_bad_request(res, error),
    };
    if let Err(error) = request.validate() {
        return render_bad_request(res, validation_error(error));
    }
    let authority = app_state.authority();
    let result = authority
        .submit_peer(&peer, request.clone())
        .await
        .and_then(|outcome| {
            outcome
                .validate_for_request(&request)
                .map_err(invalid_application_output)?;
            Ok(outcome)
        });
    render_result(res, result);
}

#[handler]
async fn scan_stream(req: &mut Request, depot: &Depot, res: &mut Response) {
    let request = match parse_current_json::<StreamScanRequest>(req).await {
        Ok(request) => request,
        Err(error) => return render_bad_request(res, error),
    };
    if let Err(error) = request.validate() {
        return render_bad_request(res, validation_error(error));
    }
    let authority = match state(depot) {
        Ok(state) => state.authority(),
        Err(error) => return render_bad_request(res, error),
    };
    let result = authority
        .scan_stream(request.clone())
        .await
        .and_then(|outcome| {
            outcome
                .validate_for_request(&request)
                .map_err(invalid_application_output)?;
            Ok(outcome)
        });
    render_result(res, result);
}

#[handler]
async fn authority_bundle(req: &mut Request, depot: &Depot, res: &mut Response) {
    let request = match parse_current_json::<AuthorityBundleRequest>(req).await {
        Ok(request) => request,
        Err(error) => return render_bad_request(res, error),
    };
    if let Err(error) = request.validate() {
        return render_bad_request(res, validation_error(error));
    }
    let authority = match state(depot) {
        Ok(state) => state.authority(),
        Err(error) => return render_bad_request(res, error),
    };
    let result = authority
        .authority_bundle(request.clone())
        .await
        .and_then(|outcome| {
            outcome
                .validate_for_request(&request, chrono::Utc::now())
                .map_err(invalid_application_output)?;
            Ok(outcome)
        });
    render_result(res, result);
}

#[handler]
async fn install_authority_handoff(req: &mut Request, depot: &Depot, res: &mut Response) {
    let request = match parse_current_json::<AuthorityHandoffRequest>(req).await {
        Ok(request) => request,
        Err(error) => return render_bad_request(res, error),
    };
    if let Err(error) = request.validate_shape() {
        return render_bad_request(res, validation_error(error));
    }
    let authority = match state(depot) {
        Ok(state) => state.authority(),
        Err(error) => return render_bad_request(res, error),
    };
    let expected = request.handoff.clone();
    let result = authority
        .install_authority_handoff(request)
        .await
        .and_then(|outcome| {
            outcome
                .validate_shape()
                .map_err(invalid_application_output)?;
            if outcome != expected {
                return Err(ServiceError::Internal(
                    "authority application changed the installed handoff".to_owned(),
                ));
            }
            Ok(outcome)
        });
    render_result(res, result);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arkret_wire::{
        AuthoritySubmitOutcome, EventAdmissionSubmission, MlsCommitSubmission,
        RealmAuthorityBundle, RealmAuthorityHandoff, StreamScanOutcome,
    };
    use async_trait::async_trait;
    use salvo::test::TestClient;
    use soland_services::ServiceResult;
    use soland_services::authority_commit::AuthorityProtocolPort;

    use super::*;

    struct NeverCalled;

    #[async_trait]
    impl AuthorityProtocolPort for NeverCalled {
        async fn submit_self_event(
            &self,
            _session: &soland_services::identity::SessionIdentityState,
            _request: EventAdmissionSubmission,
        ) -> ServiceResult<AuthoritySubmitOutcome> {
            panic!("invalid input must not reach the application port")
        }

        async fn submit_self_mls(
            &self,
            _session: &soland_services::identity::SessionIdentityState,
            _request: MlsCommitSubmission,
        ) -> ServiceResult<AuthoritySubmitOutcome> {
            panic!("invalid input must not reach the application port")
        }

        async fn scan_stream(
            &self,
            _request: StreamScanRequest,
        ) -> ServiceResult<StreamScanOutcome> {
            panic!("invalid input must not reach the application port")
        }

        async fn authority_bundle(
            &self,
            _request: AuthorityBundleRequest,
        ) -> ServiceResult<RealmAuthorityBundle> {
            panic!("invalid input must not reach the application port")
        }

        async fn install_authority_handoff(
            &self,
            _request: AuthorityHandoffRequest,
        ) -> ServiceResult<RealmAuthorityHandoff> {
            panic!("invalid input must not reach the application port")
        }
    }

    #[test]
    fn current_routes_are_registered_without_a_legacy_recovery_surface() {
        let expected = [
            "/_arkret/self/events",
            "/_arkret/peer/events",
            "/_arkret/self/streams/scan",
            "/_arkret/open/realm-authority/bundle",
            "/_arkret/peer/realm-authority/handoff",
        ];
        for path in expected {
            assert!(
                arkret_wire::ServiceOperationId::ALL
                    .iter()
                    .any(|operation| operation.descriptor().http_path == path),
                "current operation registry is missing {path}"
            );
        }
    }

    #[tokio::test]
    async fn every_current_route_rejects_an_invalid_sdk_body_before_delegating() {
        let service = crate::service(AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        ));
        for path in [
            "/_arkret/self/events",
            "/_arkret/peer/events",
            "/_arkret/self/streams/scan",
            "/_arkret/open/realm-authority/bundle",
            "/_arkret/peer/realm-authority/handoff",
        ] {
            let response = TestClient::post(format!("http://server{path}"))
                .json(&serde_json::json!({}))
                .send(&service)
                .await;
            assert_eq!(
                response.status_code,
                Some(StatusCode::BAD_REQUEST),
                "{path}"
            );
        }

        let removed = TestClient::post("http://server/_arkret/peer/streams/resolve")
            .json(&serde_json::json!({}))
            .send(&service)
            .await;
        assert_eq!(removed.status_code, Some(StatusCode::NOT_FOUND));
    }
}
