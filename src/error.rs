//! Canonical Contrix error codes (spec error-code-registry.json v2026-05-03).
//!
//! Spec B-08 requires that every wire-form error code on `/api/v1/*` belongs
//! to the registry of 42 canonical codes; today the soland handlers pass raw
//! string literals to `util::render_error`, so it is easy to ship a typo or a
//! drifted spelling. This module gives the rest of the crate a typed
//! [`ErrorCode`] enum that:
//!
//! 1. enumerates exactly the 42 codes from the active registry,
//! 2. round-trips with `contrix_core::error::KNOWN_ERROR_CODES` (asserted in
//!    [`tests::variant_count_matches_registry`] / [`tests::wire_codes_round_trip`]),
//! 3. carries the canonical HTTP status binding so handlers can stop hand-picking it (a frequent
//!    source of B-08 drift), and
//! 4. exposes a [`ErrorCode::render`] convenience that funnels through the existing
//!    `crate::routing::util::render_error` so call-site rewrites are mechanical (`render_error(res,
//!    StatusCode::CONFLICT, "cas_conflict", "...")` → `ErrorCode::CasConflict.render(res, "...")`).
//!
//! Migrating every existing call site is tracked in `_todos.md` (F3
//! incremental rewrite); for now this module is the structured path that new
//! code MUST use, and the typed-vs-string parity is locked in by the registry
//! round-trip test below.

use contrix_sdk::error as core_error;
use salvo::async_trait;
use salvo::http::StatusCode;
use salvo::oapi::{self, Components, EndpointOutRegister, Operation, ToSchema};
use salvo::prelude::*;

use crate::routing::system::util::render_error;

/// Every canonical Contrix error code, in registry order.
///
/// Order matches `contrix-spec/spec/v1/artifacts/registry/error-code-registry.json`
/// (and `contrix_core::error::KNOWN_ERROR_CODES`). Adding a code requires
/// touching this enum **and** the registry; the round-trip test in this
/// module fails until both line up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    BadJson,
    BadQuery,
    SchemaViolation,
    MissingParam,
    InvalidParam,
    Unauthenticated,
    AuthExpired,
    SoftLoggedOut,
    InvalidSignature,
    CapabilityDenied,
    SpaceFrozen,
    ClaimRequired,
    NotFound,
    UnrecognizedEndpoint,
    MethodNotAllowed,
    Conflict,
    CasConflict,
    CausalConflict,
    DependencyMissing,
    DiscussionTrackDisabled,
    /// C14 / read-receipts §2.5: Sync Service drops `cx.receipt.read` when
    /// the effective Space `disclosure="disabled"` policy is in force.
    PolicyViolation,
    EpochMismatch,
    DuplicateConflict,
    RankExhausted,
    HlcLogicalOverflow,
    PayloadTooLarge,
    DigestMismatch,
    AadDigestMismatch,
    PayloadDigestMismatch,
    KeyUnavailable,
    StateMismatch,
    AuditReceiptInvalidated,
    UnknownDid,
    QuotaExceeded,
    RateLimited,
    Timeout,
    StaleFrontier,
    SyncTokenExpired,
    UnsupportedFeature,
    UnsupportedEventKind,
    ProjectionIncomplete,
    InternalError,
    TemporarilyUnavailable,
    PolicyCombinationInvalid,
    AnchorerRecoveryMissing,
    UnsupportedLatticeType,
}

impl ErrorCode {
    /// All variants in registry order. Length must equal
    /// `contrix_core::error::KNOWN_ERROR_CODES.len()`; the round-trip test
    /// catches mismatches.
    pub const ALL: &'static [Self] = &[
        Self::BadJson,
        Self::BadQuery,
        Self::SchemaViolation,
        Self::MissingParam,
        Self::InvalidParam,
        Self::Unauthenticated,
        Self::AuthExpired,
        Self::SoftLoggedOut,
        Self::InvalidSignature,
        Self::CapabilityDenied,
        Self::SpaceFrozen,
        Self::ClaimRequired,
        Self::NotFound,
        Self::UnrecognizedEndpoint,
        Self::MethodNotAllowed,
        Self::Conflict,
        Self::CasConflict,
        Self::CausalConflict,
        Self::DependencyMissing,
        Self::DiscussionTrackDisabled,
        Self::PolicyViolation,
        Self::EpochMismatch,
        Self::DuplicateConflict,
        Self::RankExhausted,
        Self::HlcLogicalOverflow,
        Self::PayloadTooLarge,
        Self::DigestMismatch,
        Self::AadDigestMismatch,
        Self::PayloadDigestMismatch,
        Self::KeyUnavailable,
        Self::StateMismatch,
        Self::AuditReceiptInvalidated,
        Self::UnknownDid,
        Self::QuotaExceeded,
        Self::RateLimited,
        Self::Timeout,
        Self::StaleFrontier,
        Self::SyncTokenExpired,
        Self::UnsupportedFeature,
        Self::UnsupportedEventKind,
        Self::ProjectionIncomplete,
        Self::InternalError,
        Self::TemporarilyUnavailable,
        Self::PolicyCombinationInvalid,
        Self::AnchorerRecoveryMissing,
        Self::UnsupportedLatticeType,
    ];

    /// Canonical wire-form code (snake_case string used in `ErrorEnvelope.errcode`).
    ///
    /// Returns the same `&'static str` as the matching `ERROR_CODE_*`
    /// constant in `contrix_core::error`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadJson => core_error::ERROR_CODE_BAD_JSON,
            Self::BadQuery => core_error::ERROR_CODE_BAD_QUERY,
            Self::SchemaViolation => core_error::ERROR_CODE_SCHEMA_VIOLATION,
            Self::MissingParam => core_error::ERROR_CODE_MISSING_PARAM,
            Self::InvalidParam => core_error::ERROR_CODE_INVALID_PARAM,
            Self::Unauthenticated => core_error::ERROR_CODE_UNAUTHENTICATED,
            Self::AuthExpired => core_error::ERROR_CODE_AUTH_EXPIRED,
            Self::SoftLoggedOut => core_error::ERROR_CODE_SOFT_LOGGED_OUT,
            Self::InvalidSignature => core_error::ERROR_CODE_INVALID_SIGNATURE,
            Self::CapabilityDenied => core_error::ERROR_CODE_CAPABILITY_DENIED,
            Self::SpaceFrozen => core_error::ERROR_CODE_SPACE_FROZEN,
            Self::ClaimRequired => core_error::ERROR_CODE_CLAIM_REQUIRED,
            Self::NotFound => core_error::ERROR_CODE_NOT_FOUND,
            Self::UnrecognizedEndpoint => core_error::ERROR_CODE_UNRECOGNIZED_ENDPOINT,
            Self::MethodNotAllowed => core_error::ERROR_CODE_METHOD_NOT_ALLOWED,
            Self::Conflict => core_error::ERROR_CODE_CONFLICT,
            Self::CasConflict => core_error::ERROR_CODE_CAS_CONFLICT,
            Self::CausalConflict => core_error::ERROR_CODE_CAUSAL_CONFLICT,
            Self::DependencyMissing => core_error::ERROR_CODE_DEPENDENCY_MISSING,
            Self::DiscussionTrackDisabled => core_error::ERROR_CODE_DISCUSSION_TRACK_DISABLED,
            Self::PolicyViolation => core_error::ERROR_CODE_POLICY_VIOLATION,
            Self::EpochMismatch => core_error::ERROR_CODE_EPOCH_MISMATCH,
            Self::DuplicateConflict => core_error::ERROR_CODE_DUPLICATE_CONFLICT,
            Self::RankExhausted => core_error::ERROR_CODE_RANK_EXHAUSTED,
            Self::HlcLogicalOverflow => core_error::ERROR_CODE_HLC_LOGICAL_OVERFLOW,
            Self::PayloadTooLarge => core_error::ERROR_CODE_PAYLOAD_TOO_LARGE,
            Self::DigestMismatch => core_error::ERROR_CODE_DIGEST_MISMATCH,
            Self::AadDigestMismatch => core_error::ERROR_CODE_AAD_DIGEST_MISMATCH,
            Self::PayloadDigestMismatch => core_error::ERROR_CODE_PAYLOAD_DIGEST_MISMATCH,
            Self::KeyUnavailable => core_error::ERROR_CODE_KEY_UNAVAILABLE,
            Self::StateMismatch => core_error::ERROR_CODE_STATE_MISMATCH,
            Self::AuditReceiptInvalidated => core_error::ERROR_CODE_AUDIT_RECEIPT_INVALIDATED,
            Self::UnknownDid => core_error::ERROR_CODE_UNKNOWN_DID,
            Self::QuotaExceeded => core_error::ERROR_CODE_QUOTA_EXCEEDED,
            Self::RateLimited => core_error::ERROR_CODE_RATE_LIMITED,
            Self::Timeout => core_error::ERROR_CODE_TIMEOUT,
            Self::StaleFrontier => core_error::ERROR_CODE_STALE_FRONTIER,
            Self::SyncTokenExpired => core_error::ERROR_CODE_SYNC_TOKEN_EXPIRED,
            Self::UnsupportedFeature => core_error::ERROR_CODE_UNSUPPORTED_FEATURE,
            Self::UnsupportedEventKind => core_error::ERROR_CODE_UNSUPPORTED_EVENT_KIND,
            Self::ProjectionIncomplete => core_error::ERROR_CODE_PROJECTION_INCOMPLETE,
            Self::InternalError => core_error::ERROR_CODE_INTERNAL_ERROR,
            Self::TemporarilyUnavailable => core_error::ERROR_CODE_TEMPORARILY_UNAVAILABLE,
            Self::PolicyCombinationInvalid => core_error::ERROR_CODE_POLICY_COMBINATION_INVALID,
            Self::AnchorerRecoveryMissing => core_error::ERROR_CODE_ANCHORER_RECOVERY_MISSING,
            Self::UnsupportedLatticeType => core_error::ERROR_CODE_UNSUPPORTED_LATTICE_TYPE,
        }
    }

    /// Canonical HTTP status binding from the registry.
    ///
    /// We re-use `contrix_core::error::error_code_http_status` to keep the
    /// soland binding in lock-step with the spec; the round-trip test
    /// guarantees that lookup will never miss for any [`ErrorCode`] variant.
    pub fn http_status(self) -> StatusCode {
        let raw = core_error::error_code_http_status(self.as_str())
            .expect("every ErrorCode variant has a registered HTTP status");
        StatusCode::from_u16(raw).expect("registry status codes are valid HTTP statuses")
    }

    /// Render this error through the standard `util::render_error` envelope.
    ///
    /// Equivalent to `render_error(res, code.http_status(), code.as_str(), message)`
    /// — call sites that don't need a custom HTTP status (i.e. nearly all of
    /// them) should prefer this so the registry mapping is the only source of
    /// truth.
    pub fn render(self, res: &mut Response, message: &str) {
        render_error(res, self.http_status(), self.as_str(), message);
    }

    /// Try to parse a wire-form code back into its typed variant.
    ///
    /// Useful for logs / tests where a string code arrives from the wire and
    /// we want to assert it's a registered code (rather than a typo). For
    /// any unknown code returns `None`.
    pub fn from_wire(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The enum and the registry MUST contain the same number of codes.
    /// Failing this means either a code was added to the registry without
    /// updating the enum or vice-versa — spec B-08 lock.
    #[test]
    fn variant_count_matches_registry() {
        assert_eq!(
            ErrorCode::ALL.len(),
            core_error::KNOWN_ERROR_CODES.len(),
            "ErrorCode::ALL drifted from contrix_core::error::KNOWN_ERROR_CODES",
        );
    }

    /// Every variant maps to a string in `KNOWN_ERROR_CODES`, and every
    /// string in `KNOWN_ERROR_CODES` has a parsing target. Both directions.
    #[test]
    fn wire_codes_round_trip() {
        for code in ErrorCode::ALL {
            let wire = code.as_str();
            assert!(
                core_error::is_known_error_code(wire),
                "ErrorCode::{:?} → {wire:?} is not in KNOWN_ERROR_CODES",
                code
            );
            assert_eq!(
                ErrorCode::from_wire(wire),
                Some(*code),
                "round trip failed for {:?}",
                code
            );
        }
        for wire in core_error::KNOWN_ERROR_CODES {
            assert!(
                ErrorCode::from_wire(wire).is_some(),
                "registry code {wire:?} has no matching ErrorCode variant",
            );
        }
    }

    /// Every variant has a registered HTTP status — so `http_status()` never
    /// hits its `expect` panic at runtime.
    #[test]
    fn http_status_lookup_never_misses() {
        for code in ErrorCode::ALL {
            let _ = code.http_status();
        }
    }

    /// Spot-check a couple of well-known status bindings so a refactor of
    /// the registry-mapper at least gets caught at the most common cases.
    #[test]
    fn http_status_spot_checks() {
        assert_eq!(ErrorCode::BadJson.http_status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            ErrorCode::Unauthenticated.http_status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ErrorCode::CapabilityDenied.http_status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(ErrorCode::NotFound.http_status(), StatusCode::NOT_FOUND);
        assert_eq!(ErrorCode::CasConflict.http_status(), StatusCode::CONFLICT);
        assert_eq!(ErrorCode::SyncTokenExpired.http_status(), StatusCode::GONE);
        assert_eq!(
            ErrorCode::PayloadTooLarge.http_status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            ErrorCode::SchemaViolation.http_status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            ErrorCode::RateLimited.http_status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ErrorCode::InternalError.http_status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ErrorCode::Timeout.http_status(),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            ErrorCode::TemporarilyUnavailable.http_status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ErrorCode::UnsupportedFeature.http_status(),
            StatusCode::NOT_IMPLEMENTED
        );
    }
}

// ── AppError + typed-endpoint integration ────────────────────────────────
//
// `AppError` is the typed error returned by `#[endpoint]` handlers. It carries
// a canonical [`ErrorCode`] (registry-locked, see spec B-08), a human-readable
// message, and an optional HTTP status override. Both `Writer` and
// `EndpointOutRegister` are implemented so the same value drives both runtime
// rendering and OpenAPI doc generation.
//
// Migration template (palpo-style): see `_oapi.md` for the per-handler shape.

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
    /// When set, overrides the wire-form `errcode` string. Use sparingly —
    /// only for handlers whose pre-typed `render_error` path emitted a
    /// non-canonical errcode that downstream clients (or tests) already
    /// depend on (e.g. `unknown_schema`, `<kind>_not_active`,
    /// `batch_not_supported`). New code should prefer a canonical
    /// `ErrorCode` variant.
    pub wire_code_override: Option<String>,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: None,
            wire_code_override: None,
        }
    }

    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    /// Override the on-wire `errcode` string. See `wire_code_override` for
    /// the rationale + caveats.
    pub fn with_wire_code(mut self, wire_code: impl Into<String>) -> Self {
        self.wire_code_override = Some(wire_code.into());
        self
    }

    /// Resolve the HTTP status to use when rendering this error: explicit
    /// override first, then the registry binding.
    pub fn http_status(&self) -> StatusCode {
        self.status.unwrap_or_else(|| self.code.http_status())
    }

    /// Resolve the on-wire errcode string: explicit override first, then the
    /// canonical mapping from the registry.
    pub fn wire_errcode(&self) -> &str {
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

impl AppError {
    /// Convenience: build an `AppError` with both an explicit HTTP status and
    /// a non-canonical wire `errcode` override, for lifecycle paths whose
    /// pre-typed `render_error` shape downstream clients already depend on.
    pub fn legacy(status: StatusCode, wire_code: impl Into<String>, message: impl Into<String>) -> Self {
        let wire_code = wire_code.into();
        Self::new(ErrorCode::InvalidParam, message)
            .with_status(status)
            .with_wire_code(wire_code)
    }
}

#[async_trait]
impl Writer for AppError {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        let status = self.http_status();
        let wire = self.wire_errcode().to_owned();
        render_error(res, status, &wire, &self.message);
    }
}

impl EndpointOutRegister for AppError {
    fn register(components: &mut Components, operation: &mut Operation) {
        // Reuse `contrix_sdk::ErrorEnvelope` (already `ToSchema` under the
        // SDK's `salvo` feature) as the response body schema for every error
        // status.  The wire representation is `{ errcode, error, retry_after_ms?, ... }`.
        let envelope_schema = <contrix_sdk::ErrorEnvelope as ToSchema>::to_schema(components);
        let response = |description: &'static str| {
            oapi::Response::new(description).add_content(
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
    }
}
