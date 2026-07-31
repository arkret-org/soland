//! Soland error integration for canonical Arkret SDK error codes.
//!
//! Wire-form error codes are owned by `arkret_wire::ErrorCode`; this module
//! only adds soland-specific Salvo rendering and typed endpoint plumbing.

use salvo::async_trait;
use salvo::http::StatusCode;
use salvo::prelude::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct ErrorExposure {
    pub development_mode: bool,
}

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

pub use arkret_wire::ErrorCode;

/// Convert the SDK registry status into Salvo's `StatusCode`.
pub fn error_http_status(code: ErrorCode) -> StatusCode {
    StatusCode::from_u16(code.http_status()).expect("registry status codes are valid HTTP statuses")
}

fn request_id() -> String {
    arkret_identifiers::new_prefixed_uuid7("ak:request:")
}

pub fn render_error(res: &mut Response, status: StatusCode, code: &str, message: &str) {
    res.status_code(status);
    res.render(Json(
        arkret_wire::problem_details::ErrorEnvelope::new(code, message)
            .with_request_id(request_id()),
    ));
}

pub fn render_error_with_detail(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    message: &str,
    reason_detail: &str,
) {
    res.status_code(status);
    res.render(Json(
        arkret_wire::problem_details::ErrorEnvelope::new(code, message)
            .with_request_id(request_id())
            .with_detail(
                "reason_detail",
                serde_json::Value::String(reason_detail.to_owned()),
            ),
    ));
}

pub fn render_error_with_reason_code(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    message: &str,
    reason_code: &str,
    reason_detail: Option<&str>,
) {
    let mut envelope = arkret_wire::problem_details::ErrorEnvelope::new(code, message)
        .with_request_id(request_id())
        .with_detail(
            "reason_code",
            serde_json::Value::String(reason_code.to_owned()),
        );
    if let Some(reason_detail) = reason_detail {
        envelope = envelope.with_detail(
            "reason_detail",
            serde_json::Value::String(reason_detail.to_owned()),
        );
    }
    res.status_code(status);
    res.render(Json(envelope));
}

pub fn render_error_with_top_level_reason(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    message: &str,
    reason: &str,
    reason_detail: Option<&str>,
) {
    let mut envelope = arkret_wire::problem_details::ErrorEnvelope::new(code, message)
        .with_request_id(request_id());
    if let Some(reason_detail) = reason_detail {
        envelope = envelope.with_detail(
            "reason_detail",
            serde_json::Value::String(reason_detail.to_owned()),
        );
    }
    let mut body = serde_json::to_value(&envelope).unwrap_or_else(|_| {
        serde_json::json!({
            "ok": false,
            "error": { "code": code, "message": message },
        })
    });
    if let Some(object) = body.as_object_mut() {
        object.insert(
            "reason".to_owned(),
            serde_json::Value::String(reason.to_owned()),
        );
        if let Some(error) = object
            .get_mut("error")
            .and_then(serde_json::Value::as_object_mut)
        {
            error.insert(
                "reason".to_owned(),
                serde_json::Value::String(reason.to_owned()),
            );
        }
    }
    res.status_code(status);
    res.render(Json(body));
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
        assert!(
            !ErrorCode::ALL.is_empty()
                && ErrorCode::ALL
                    .iter()
                    .all(|code| ErrorCode::from_wire(code.as_str()) == Some(*code)),
            "every SDK registry entry must round-trip through its wire code",
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
// `AppError` is the typed error returned by handlers. It carries
// a canonical [`ErrorCode`] (registry-locked), a human-readable message, and
// an optional HTTP status override. `Writer` is implemented so the same value drives runtime
// rendering.

/// Typed error returned by handlers.
#[derive(Debug, Clone)]
pub struct AppError {
    pub code: ErrorCode,
    pub message: Box<str>,
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
    pub wire_code_override: Option<Box<str>>,
    /// Stable protocol reason code rendered as `error.details.reason_code`.
    pub reason_code: Option<Box<str>>,
    /// Free-form diagnostic explaining *why* this error fired.
    ///
    /// Round 2 — surfaced through the rendered envelope as
    /// `error.details.reason_detail` so on-call has something more
    /// specific than the canonical `code` to grep for. The shape is
    /// intentionally `Option<String>` (no enum, no schema) because the
    /// string is unstable across releases — clients MUST NOT parse this value and may only log or
    /// display it.
    pub reason_detail: Option<Box<str>>,
    /// Deployment-local diagnostic that is rendered only in development mode.
    ///
    /// Privacy-sensitive endpoints use this field to retain the concrete
    /// rejection cause while returning the same indistinguishable protocol
    /// error in production. When `SOLAND_DEVELOPMENT_MODE=true`, the writer
    /// exposes it as the unstable `error.details.reason_detail` diagnostic.
    pub private_detail: Option<Box<str>>,
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
    pub top_level_reason: Option<Box<str>>,
    /// Typed protocol details inserted into `error.details`.
    ///
    /// Boxed and optional because it is empty on the overwhelming majority of
    /// errors: inline, the map's three words push `AppError` past clippy's
    /// 128-byte `result_large_err` threshold and widen every `AppResult` in
    /// the crate. `None` costs one word and allocates nothing.
    pub wire_details: Option<Box<std::collections::BTreeMap<String, serde_json::Value>>>,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into().into_boxed_str(),
            status: None,
            wire_code_override: None,
            reason_code: None,
            reason_detail: None,
            private_detail: None,
            top_level_reason: None,
            wire_details: None,
        }
    }

    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    /// Override the on-wire `error.code` string. See `wire_code_override` for
    /// the rationale + caveats.
    pub fn with_wire_code(mut self, wire_code: impl Into<String>) -> Self {
        self.wire_code_override = Some(wire_code.into().into_boxed_str());
        self
    }

    /// Attach a stable protocol reason code without replacing `error.code`.
    pub fn with_reason_code(mut self, reason_code: impl Into<String>) -> Self {
        self.reason_code = Some(reason_code.into().into_boxed_str());
        self
    }

    /// Attach a free-form diagnostic. See [`AppError::reason_detail`].
    ///
    /// The value is rendered into the wire envelope at
    /// `error.details.reason_detail` and the OpenAPI schema annotates
    /// it as unstable / opaque.
    pub fn with_reason_detail(mut self, reason_detail: impl Into<String>) -> Self {
        self.reason_detail = Some(reason_detail.into().into_boxed_str());
        self
    }

    /// Attach a deployment-local diagnostic without changing the response.
    #[must_use]
    pub fn with_private_detail(mut self, private_detail: impl Into<String>) -> Self {
        self.private_detail = Some(private_detail.into().into_boxed_str());
        self
    }

    /// Attach a stable, normative top-level `reason` discriminator. See
    /// [`AppError::top_level_reason`]. Used by the COT-03-001 inbound
    /// transaction-push signature path so the `reason` carries the §7.3.1
    /// failure code while `error.code` stays generic.
    pub fn with_top_level_reason(mut self, reason: impl Into<String>) -> Self {
        self.top_level_reason = Some(reason.into().into_boxed_str());
        self
    }

    #[must_use]
    pub fn with_wire_detail(
        mut self,
        key: impl Into<String>,
        value: impl serde::Serialize,
    ) -> Self {
        if let Ok(value) = serde_json::to_value(value) {
            self.wire_details
                .get_or_insert_with(Box::default)
                .insert(key.into(), value);
        }
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
    /// HTTP 415 for a canonical non-streaming JSON operation that carried a
    /// `Content-Encoding` header. See `zh/conformance/scalability-constraints.md` §2.1.4.
    pub fn unsupported_content_encoding(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnsupportedContentEncoding, message)
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
            .get_typed::<ErrorExposure>()
            .map(|exposure| exposure.development_mode)
            .unwrap_or(false);
        let redact_internal = self.code == ErrorCode::InternalError && !development_mode;
        if development_mode {
            tracing::warn!(
                status = status.as_u16(),
                wire_code = %wire,
                error_code = %self.code.as_str(),
                message = %self.message,
                reason_code = self.reason_code.as_deref(),
                reason_detail = self.reason_detail.as_deref(),
                private_detail = self.private_detail.as_deref(),
                "detailed application error"
            );
        } else if redact_internal {
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
            self.message.as_ref()
        };
        // `private_detail` carries the useful cause for privacy-preserving
        // production errors such as Direct Conversation precondition failures.
        // Keep production responses indistinguishable, but make an explicitly
        // development-mode server actionable from the browser's response body.
        let wire_reason_detail = self.reason_detail.as_deref().or_else(|| {
            development_mode
                .then_some(self.private_detail.as_deref())
                .flatten()
        });
        if let Some(wire_details) = self.wire_details.filter(|details| !details.is_empty()) {
            let mut envelope =
                arkret_wire::problem_details::ErrorEnvelope::new(&wire, public_message)
                    .with_request_id(request_id());
            for (key, value) in *wire_details {
                envelope = envelope.with_detail(key, value);
            }
            if let Some(reason_code) = self.reason_code.as_deref() {
                envelope = envelope.with_detail(
                    "reason_code",
                    serde_json::Value::String(reason_code.to_owned()),
                );
            }
            if let Some(reason_detail) = wire_reason_detail {
                envelope = envelope.with_detail(
                    "reason_detail",
                    serde_json::Value::String(reason_detail.to_owned()),
                );
            }
            res.status_code(status);
            res.render(Json(envelope));
        } else if let Some(reason) = self.top_level_reason.as_deref() {
            render_error_with_top_level_reason(
                res,
                status,
                &wire,
                public_message,
                reason,
                wire_reason_detail,
            );
        } else if let Some(reason_code) = self.reason_code.as_deref() {
            render_error_with_reason_code(
                res,
                status,
                &wire,
                public_message,
                reason_code,
                wire_reason_detail,
            );
        } else if let Some(reason_detail) = wire_reason_detail {
            render_error_with_detail(res, status, &wire, public_message, reason_detail);
        } else {
            render_error(res, status, &wire, public_message);
        }
    }
}

// `#[endpoint]` handlers return `Result<Json<T>, AppError>`; salvo-oapi already
// registers the `Ok` arm through `Json<T>`, and calls `EndpointOutRegister` on
// the error arm so the generated document advertises the failure shape. Every
// handler renders the same canonical [`ErrorEnvelope`], so a single `default`
// response carrying that schema is the accurate contract regardless of which
// `ErrorCode` fired at runtime.
impl salvo::oapi::EndpointOutRegister for AppError {
    fn register(components: &mut salvo::oapi::Components, operation: &mut salvo::oapi::Operation) {
        let schema =
            <arkret_wire::problem_details::ErrorEnvelope as salvo::oapi::ToSchema>::to_schema(
                components,
            );
        operation.responses.insert(
            "default",
            salvo::oapi::Response::new("Arkret error envelope")
                .add_content("application/json", schema),
        );
    }
}
