//! Soland error integration for canonical Arkret SDK error codes.
//!
//! Wire-form error codes are owned by `arkret_sdk::ErrorCode`; this module
//! only adds soland-specific Salvo rendering and typed endpoint plumbing.

/// Soland-local rejection reasons that are not registered protocol reason codes.
///
/// Registered reasons and top-level errors are consumed directly through
/// arkret_sdk::ReasonCode and arkret_sdk::ErrorCode.
pub(crate) mod reasons {
    pub(crate) const MEMBER_IDENTITY_HANDLE_FIELD_FORBIDDEN: &str =
        "member_identity_handle_field_forbidden";
    pub(crate) const CLAIM_TYPE_UNSUPPORTED: &str = "claim_type_unsupported";
    pub(crate) const HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID: &str =
        "handle_claim_subject_not_principal_did";
}
use salvo::async_trait;
use salvo::http::StatusCode;
use salvo::oapi::{self, Components, EndpointOutRegister, Operation, ToSchema};
use salvo::prelude::*;

use crate::routing::system::util::render_error;

/// Construct an [`AppError`] with a canonical [`ErrorCode`] variant.
///
/// Two forms:
///
/// ```ignore
/// // Plain (or captured-interpolation) message:
/// return Err(app_error!(InvalidParam, "bad space_id"));
/// return Err(app_error!(InvalidParam, "invalid space_id: {err}"));
///
/// // Explicit-args `format!` variant:
/// return Err(app_error!(InvalidParam, "invalid space_id: {}", err));
/// ```
///
/// The first argument is a bare variant identifier resolved against
/// [`crate::error::ErrorCode`] (i.e. `InvalidParam`, not
/// `ErrorCode::InvalidParam`). When the message argument is a string
/// literal it is forwarded through `format!` so captured-arg
/// interpolation (`{var}`) works in the single-arg form as well.
/// Non-literal `String`/`&str` expressions are passed through unchanged.
///
/// This replaces the boilerplate
/// `AppError::new(ErrorCode::X, format!("...", ...))` pattern that
/// otherwise litters every handler module. Prefer the macro over
/// `AppError::new(...)` in new code.
#[macro_export]
macro_rules! app_error {
    ($code:ident, $fmt:literal $(, $($arg:tt)*)?) => {
        $crate::error::AppError::new(
            $crate::error::ErrorCode::$code,
            format!($fmt $(, $($arg)*)?),
        )
    };
    ($code:ident, $msg:expr $(,)?) => {
        $crate::error::AppError::new($crate::error::ErrorCode::$code, $msg)
    };
}

pub use arkret_sdk::ErrorCode;

/// Convert the SDK registry status into Salvo's `StatusCode`.
pub fn error_http_status(code: ErrorCode) -> StatusCode {
    StatusCode::from_u16(code.http_status()).expect("registry status codes are valid HTTP statuses")
}

/// Render an SDK-owned error code through soland's standard error envelope.
pub fn render_error_code(code: ErrorCode, res: &mut Response, message: &str) {
    render_error(res, error_http_status(code), code.as_str(), message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_error_codes_are_soland_source_of_truth() {
        assert_eq!(
            ErrorCode::ALL.len(),
            arkret_sdk::error::KNOWN_ERROR_CODES.len(),
            "soland must use the SDK registry shape directly",
        );
        assert_eq!(ErrorCode::from_wire("bad_json"), Some(ErrorCode::BadJson));
        assert_eq!(
            ErrorCode::from_wire("directory_not_authorized"),
            Some(ErrorCode::DirectoryNotAuthorized),
        );
        assert_eq!(
            error_http_status(ErrorCode::BadJson),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            error_http_status(ErrorCode::DirectoryNotAuthorized),
            StatusCode::FORBIDDEN,
        );
    }
}

// ── AppError + typed-endpoint integration ────────────────────────────────
//
// `AppError` is the typed error returned by `#[endpoint]` handlers. It carries
// a canonical [`ErrorCode`] (registry-locked), a human-readable message, and
// an optional HTTP status override. Both `Writer` and `EndpointOutRegister`
// are implemented so the same value drives both runtime rendering and
// OpenAPI doc generation.

/// Typed error returned by `#[endpoint]` handlers.
#[derive(Debug, Clone)]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    /// When set, overrides the registry-derived HTTP status. Most call sites
    /// should leave this `None` and let the registry decide; lifecycle paths
    /// (`401` on missing token vs `403` on capability denial) sometimes need
    /// the override.
    pub status: Option<StatusCode>,
    /// When set, overrides the wire-form `error.code` string. Use sparingly -
    /// only for handlers that emit a non-canonical code downstream
    /// clients (or tests) depend on (e.g. `unknown_schema`,
    /// `<kind>_not_active`, `batch_not_supported`). New code should prefer
    /// a canonical `ErrorCode` variant.
    pub wire_code_override: Option<String>,
    /// Stable protocol reason code rendered as `error.details.reason_code`.
    pub reason_code: Option<String>,
    /// Free-form diagnostic explaining *why* this error fired.
    ///
    /// Round 2 — surfaced through the rendered envelope as
    /// `error.details.reason_detail` so on-call has something more
    /// specific than the canonical `code` to grep for. The shape is
    /// intentionally `Option<String>` (no enum, no schema) because the
    /// string is unstable across releases — see the [`EndpointOutRegister`]
    /// doc on the response: clients MUST NOT parse this value, only
    /// log/display it.
    pub reason_detail: Option<String>,
    /// When set, render a top-level `reason` field on the error envelope.
    ///
    /// Unlike [`Self::reason_detail`] (an opaque diagnostic at
    /// `error.details.reason_detail`), this is a **stable, normative**
    /// discriminator that the wire contract pins independently of the generic
    /// `error.code`. COT-03-001 / `applet-integration.md` §7.3.1 uses it for the
    /// inbound transaction-push signature failure codes
    /// (`http_signature_required` / `http_signature_invalid` /
    /// `signature_window_invalid`), where `error.code` stays the generic
    /// `unauthenticated` and the discriminator travels in `reason`.
    pub top_level_reason: Option<String>,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: None,
            wire_code_override: None,
            reason_code: None,
            reason_detail: None,
            top_level_reason: None,
        }
    }

    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    /// Override the on-wire `error.code` string. See `wire_code_override` for
    /// the rationale + caveats.
    pub fn with_wire_code(mut self, wire_code: impl Into<String>) -> Self {
        self.wire_code_override = Some(wire_code.into());
        self
    }

    /// Attach a stable protocol reason code without replacing `error.code`.
    pub fn with_reason_code(mut self, reason_code: impl Into<String>) -> Self {
        self.reason_code = Some(reason_code.into());
        self
    }

    /// Attach a free-form diagnostic. See [`AppError::reason_detail`].
    ///
    /// The value is rendered into the wire envelope at
    /// `error.details.reason_detail` and the OpenAPI schema annotates
    /// it as unstable / opaque.
    pub fn with_reason_detail(mut self, reason_detail: impl Into<String>) -> Self {
        self.reason_detail = Some(reason_detail.into());
        self
    }

    /// Attach a stable, normative top-level `reason` discriminator. See
    /// [`AppError::top_level_reason`]. Used by the COT-03-001 inbound
    /// transaction-push signature path so the `reason` carries the §7.3.1
    /// failure code while `error.code` stays generic.
    pub fn with_top_level_reason(mut self, reason: impl Into<String>) -> Self {
        self.top_level_reason = Some(reason.into());
        self
    }

    /// Resolve the HTTP status to use when rendering this error: explicit
    /// override first, then the registry binding.
    pub fn http_status(&self) -> StatusCode {
        self.status.unwrap_or_else(|| error_http_status(self.code))
    }

    /// Resolve the on-wire `error.code` string: explicit override first, then the
    /// canonical mapping from the registry.
    pub fn wire_code(&self) -> &str {
        self.wire_code_override
            .as_deref()
            .unwrap_or_else(|| self.code.as_str())
    }

    // ── Convenience constructors for the most-used codes. The full
    // `ErrorCode` set is always available via `AppError::new(code, msg)`.

    pub fn bad_json(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadJson, message)
    }
    pub fn missing_param(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::MissingParam, message)
    }
    pub fn invalid_param(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParam, message)
    }
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthenticated, message)
    }
    pub fn capability_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::CapabilityDenied, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalError, message)
    }
    pub fn unsupported_feature(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnsupportedFeature, message)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for AppError {}

impl From<ErrorCode> for AppError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code, "")
    }
}

#[async_trait]
impl Writer for AppError {
    async fn write(self, _req: &mut Request, depot: &mut Depot, res: &mut Response) {
        let status = self.http_status();
        let wire = self.wire_code().to_owned();
        let development_mode = depot
            .get_typed::<crate::state::AppState>()
            .map(|state| state.config.development_mode)
            .unwrap_or(false);
        let redact_internal = self.code == ErrorCode::InternalError && !development_mode;
        if redact_internal {
            tracing::error!(
                status = status.as_u16(),
                wire_code = %wire,
                internal_message = %self.message,
                "internal error response redacted"
            );
        }
        let public_message = if redact_internal {
            "internal error"
        } else {
            self.message.as_str()
        };
        if let Some(reason) = self.top_level_reason.as_deref() {
            crate::routing::system::util::render_error_with_top_level_reason(
                res,
                status,
                &wire,
                public_message,
                reason,
                self.reason_detail.as_deref(),
            );
        } else if let Some(reason_code) = self.reason_code.as_deref() {
            crate::routing::system::util::render_error_with_reason_code(
                res,
                status,
                &wire,
                public_message,
                reason_code,
                self.reason_detail.as_deref(),
            );
        } else if let Some(reason_detail) = self.reason_detail.as_deref() {
            crate::routing::system::util::render_error_with_detail(
                res,
                status,
                &wire,
                public_message,
                reason_detail,
            );
        } else {
            render_error(res, status, &wire, public_message);
        }
    }
}

impl EndpointOutRegister for AppError {
    fn register(components: &mut Components, operation: &mut Operation) {
        // Reuse `arkret_sdk::ErrorEnvelope` (already `ToSchema` under the
        // SDK's `salvo` feature) as the response body schema for every error
        // status. The wire representation is the spec-canonical
        // `{ ok: false, error: { code, message, ... }, request_id }`.
        //
        // Stable protocol rejections may carry `error.details.reason_code`;
        // opaque diagnostics may carry `error.details.reason_detail`.
        // The SDK schema already types `details` as `serde_json::Value`,
        // so the field is documentation-only — describe its shape and
        // stability contract in each response's `description` rather
        // than mutating the SDK-owned schema.
        let envelope_schema = <arkret_sdk::ErrorEnvelope as ToSchema>::to_schema(components);
        const ERROR_DETAILS_DOC: &str = " (envelope details may contain stable \
            `reason_code: string` and/or unstable `reason_detail: string`; do not parse \
            `reason_detail`)";
        let response = |description: &'static str| -> oapi::Response {
            let combined = format!("{description}{ERROR_DETAILS_DOC}");
            oapi::Response::new(combined).add_content(
                "application/json",
                oapi::Content::new(envelope_schema.clone()),
            )
        };

        operation.responses.insert("400", response("Bad request"));
        operation
            .responses
            .insert("401", response("Unauthenticated"));
        operation
            .responses
            .insert("403", response("Capability denied"));
        operation.responses.insert("404", response("Not found"));
        operation.responses.insert("409", response("Conflict"));
        operation.responses.insert("429", response("Rate limited"));
        operation
            .responses
            .insert("500", response("Internal server error"));
        operation
            .responses
            .insert("501", response("Unsupported feature or not implemented"));
    }
}
