//! Canonical current-protocol authority routes.
//!
//! `POST /_arkret/self/events` is mounted by the events router; this module
//! contributes the self stream scan and the open authority bundle. Peer
//! handoff has no authenticated, fenced implementation and stays unmounted.

use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
use arkret_wire::{AuthorityBundleRequest, ErrorCode, StreamScanRequest};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;
use soland_services::{ServiceError, ServiceResult};

use crate::state::AppState;

/// `ak.self.committed_event.read.scan.v1`, under the authenticated `self` tree.
pub(super) fn self_router() -> Router {
    Router::with_path("streams/scan").post(scan_stream)
}

/// `ak.open.realm_authority.read.bundle.v1`, under the unauthenticated `open` tree.
pub(super) fn open_router() -> Router {
    Router::with_path("realm-authority/bundle").post(authority_bundle)
}

/// Responses carrying authorization results, authority bundles, or Commits
/// are never cacheable (`service-http-binding.md` §6).
fn no_store(res: &mut Response) {
    res.headers_mut().insert(
        salvo::http::header::CACHE_CONTROL,
        salvo::http::HeaderValue::from_static("no-store"),
    );
}

/// Decode the exact body as the closed request type: malformed JSON is
/// `json_invalid`, a well-formed body outside the schema `schema_violation`.
async fn parse_closed_body<T: serde::de::DeserializeOwned>(
    req: &mut Request,
    res: &mut Response,
) -> Option<T> {
    let body = match req.payload().await {
        Ok(body) => body.clone(),
        Err(error) => {
            crate::error::render_error_code(
                ErrorCode::JsonInvalid,
                res,
                &format!("unable to read request body: {error}"),
            );
            return None;
        }
    };
    match serde_json::from_slice::<T>(&body) {
        Ok(value) => Some(value),
        Err(error) => {
            let code = if error.is_data() {
                ErrorCode::SchemaViolation
            } else {
                ErrorCode::JsonInvalid
            };
            crate::error::render_error_code(code, res, &format!("invalid request body: {error}"));
            None
        }
    }
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
    if error.conflict_code() == Some(soland_storage::ConflictCode::SnapshotCapacityExceeded) {
        return crate::error::render_error_with_reason_code(
            res,
            StatusCode::CONFLICT,
            "failed_precondition",
            &error.to_string(),
            soland_storage::ConflictCode::SnapshotCapacityExceeded.as_str(),
            None,
        );
    }
    if let ServiceError::Conflict(detail) = &error {
        let detail = detail.split_once(": ").map_or("", |(_, detail)| detail);
        match error.conflict_code() {
            Some(soland_storage::ConflictCode::EpochMismatch) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::EpochMismatch,
                    res,
                    detail,
                );
            }
            Some(soland_storage::ConflictCode::TemporarilyUnavailable) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::TemporarilyUnavailable,
                    res,
                    detail,
                );
            }
            Some(
                code @ (soland_storage::ConflictCode::EpochUpdateRequired
                | soland_storage::ConflictCode::MlsActivationRequired),
            ) => {
                return crate::error::render_error_with_reason_code(
                    res,
                    StatusCode::CONFLICT,
                    arkret_wire::ErrorCode::FAILED_PRECONDITION,
                    detail,
                    code.as_str(),
                    None,
                );
            }
            _ => {}
        }
    }
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
    let exact_request_body = match req.payload().await {
        Ok(body) => body.to_vec(),
        Err(error) => {
            return render_bad_request(
                res,
                format!("unable to read exact authority request body: {error}"),
            );
        }
    };
    let request = match parse_current_json::<SelfAuthoritySubmitRequest>(req).await {
        Ok(request) => request,
        Err(error) => return render_bad_request(res, error),
    };
    if serde_json::from_slice::<SelfAuthoritySubmitRequest>(&exact_request_body)
        .ok()
        .as_ref()
        != Some(&request)
    {
        return render_bad_request(
            res,
            "exact body differs from parsed authority request".to_owned(),
        );
    }
    if let Err(error) = request.validate() {
        return render_bad_request(res, validation_error(error));
    }
    let authority = app_state.authority();
    let result = authority
        .submit_self(&session, request.clone(), &exact_request_body)
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
    let app_state = match state(depot) {
        Ok(state) => state,
        Err(error) => {
            return crate::error::render_error_code(ErrorCode::InternalError, res, &error);
        }
    };
    let Some(session) = crate::routing::auth_or_render(app_state, req, res).await else {
        return;
    };
    let actor =
        match crate::routing::identity::session_actor::validated_session_actor(app_state, &session)
            .await
        {
            Ok(actor) => actor,
            Err(error) => {
                return crate::routing::render_error(
                    res,
                    error.http_status(),
                    error.wire_code(),
                    &error.message,
                );
            }
        };
    if let Err(error) = crate::routing::events::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
    ) {
        return crate::routing::render_error(
            res,
            error.http_status(),
            error.wire_code(),
            &error.message,
        );
    }
    let Some(request) = parse_closed_body::<StreamScanRequest>(req, res).await else {
        return;
    };
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            &validation_error(error),
        );
    }
    // Stream readability is decided for an Account member; an actor with no
    // Account has no readable interval on any Realm stream here.
    let Some(account) = actor.as_account_id() else {
        return crate::error::render_error_code(
            ErrorCode::CapabilityDenied,
            res,
            "the stream is not readable by this caller",
        );
    };
    let result = app_state
        .authority()
        .scan_stream_for_account(account, request.clone())
        .await;
    match result {
        Ok(soland_storage::AccountStreamScan::Page(outcome)) => {
            if let Err(error) = outcome.validate_for_request(&request) {
                return render_service_error(res, invalid_application_output(error));
            }
            no_store(res);
            res.render(Json(outcome));
        }
        Ok(soland_storage::AccountStreamScan::NotAuthorized) => {
            crate::error::render_error_code(
                ErrorCode::CapabilityDenied,
                res,
                "the stream is not readable by this caller",
            );
        }
        Ok(soland_storage::AccountStreamScan::Unproved(reason)) => {
            tracing::info!(realm_id = %request.realm_id, reason,
                "stream scan interval is not provable at this cut");
            crate::error::render_error_code(
                ErrorCode::TemporarilyUnavailable,
                res,
                "the caller's readable interval cannot be proved at this cut",
            );
        }
        Err(error) => render_service_error(res, error),
    }
}

#[handler]
async fn authority_bundle(req: &mut Request, depot: &Depot, res: &mut Response) {
    let Some(request) = parse_closed_body::<AuthorityBundleRequest>(req, res).await else {
        return;
    };
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            &validation_error(error),
        );
    }
    let authority = match state(depot) {
        Ok(state) => state.authority(),
        Err(error) => {
            return crate::error::render_error_code(ErrorCode::InternalError, res, &error);
        }
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
    match result {
        Ok(bundle) => {
            no_store(res);
            res.render(Json(bundle));
        }
        // A Realm this Station does not govern has no bundle here; the
        // operation registers no `not_found`, so this is the universal
        // non-enumerating refusal.
        Err(ServiceError::NotFound(_)) => crate::error::render_error_code(
            ErrorCode::CapabilityDenied,
            res,
            "no current authority bundle is available for this Realm here",
        ),
        Err(error) => render_service_error(res, error),
    }
}

#[cfg(test)]
mod tests {
    use salvo::test::{ResponseExt as _, TestClient};

    use super::*;

    #[test]
    fn mounted_authority_routes_are_the_registered_canonical_paths() {
        for (path, operation) in [
            (
                "/_arkret/self/streams/scan",
                arkret_wire::ServiceOperationId::SelfCommittedEventReadScanV1,
            ),
            (
                "/_arkret/open/realm-authority/bundle",
                arkret_wire::ServiceOperationId::OpenRealmAuthorityReadBundleV1,
            ),
        ] {
            let descriptor = operation.descriptor();
            assert_eq!(descriptor.http_path, path);
            assert_eq!(descriptor.http_method, "POST");
        }
    }

    #[tokio::test]
    async fn snapshot_capacity_overflow_renders_the_registered_precondition_reason() {
        let mut res = Response::new();
        render_service_error(
            &mut res,
            ServiceError::Conflict(
                "snapshot_capacity_exceeded: candidate Realm snapshot exceeds 8 MiB".to_owned(),
            ),
        );
        assert_eq!(res.status_code, Some(StatusCode::CONFLICT));
        let body: serde_json::Value = salvo::test::ResponseExt::take_json(&mut res)
            .await
            .expect("problem body");
        assert_eq!(body["status"], 409);
        assert_eq!(
            body["type"],
            "https://arkret.org/problems/failed_precondition"
        );
        assert_eq!(body["reason_code"], "snapshot_capacity_exceeded");
    }

    #[tokio::test]
    async fn mls_send_gate_refusals_render_their_registered_identities() {
        use soland_storage::ConflictCode;
        for (code, status, wire_code, reason_code) in [
            (
                ConflictCode::EpochMismatch,
                StatusCode::CONFLICT,
                "epoch_mismatch",
                None,
            ),
            (
                ConflictCode::EpochUpdateRequired,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("epoch_update_required"),
            ),
            (
                ConflictCode::MlsActivationRequired,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("mls_activation_required"),
            ),
            (
                ConflictCode::TemporarilyUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                None,
            ),
        ] {
            let mut res = Response::new();
            render_service_error(
                &mut res,
                ServiceError::Conflict(format!("{code}: gate refused")),
            );
            assert_eq!(res.status_code, Some(status), "{code}");
            let body: serde_json::Value = salvo::test::ResponseExt::take_json(&mut res)
                .await
                .expect("problem body");
            assert_eq!(body["status"], status.as_u16(), "{body}");
            assert_eq!(
                body["type"],
                format!("https://arkret.org/problems/{wire_code}"),
                "{body}"
            );
            assert_eq!(body["detail"], "gate refused", "{body}");
            match reason_code {
                Some(reason_code) => assert_eq!(body["reason_code"], reason_code, "{body}"),
                None => assert!(body.get("reason_code").is_none(), "{body}"),
            }
        }
    }

    #[tokio::test]
    async fn mounted_authority_reads_gate_before_delegating() {
        let service = crate::service(AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        ));
        let post = |path: &str, operation: &str| {
            TestClient::post(format!("http://server{path}")).add_header(
                "Arkret-Operation",
                operation,
                true,
            )
        };
        let bundle = arkret_wire::ServiceOperationId::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1;
        let scan = arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1;

        // The open bundle needs no session; a body outside the closed
        // request schema never reaches the application port.
        let mut response = post("/_arkret/open/realm-authority/bundle", bundle)
            .json(&serde_json::json!({}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
        let body: serde_json::Value = response.take_json().await.expect("problem body");
        assert_eq!(
            body["type"], "https://arkret.org/problems/schema_violation",
            "{body}"
        );
        let mut response = post("/_arkret/open/realm-authority/bundle", bundle)
            .raw_json("{")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        let body: serde_json::Value = response.take_json().await.expect("problem body");
        assert_eq!(
            body["type"], "https://arkret.org/problems/json_invalid",
            "{body}"
        );

        // The self scan authenticates before it reads the body.
        let mut response = post("/_arkret/self/streams/scan", scan)
            .json(&serde_json::json!({}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        let body: serde_json::Value = response.take_json().await.expect("problem body");
        assert_eq!(
            body["type"], "https://arkret.org/problems/unauthenticated",
            "{body}"
        );

        // No legacy resolver and no unauthenticated peer handoff are mounted.
        for path in [
            "/_arkret/peer/streams/resolve",
            "/_arkret/peer/realm-authority/handoff",
        ] {
            let response = TestClient::post(format!("http://server{path}"))
                .json(&serde_json::json!({}))
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND), "{path}");
        }
    }
}
