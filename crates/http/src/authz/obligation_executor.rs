//! G3.S2 — obligation executor.
//!
//! Executes the `obligations[]` array returned by a policy server
//! `/policy/check` response. The subset implemented here mirrors the
//! kinds explicitly listed in `arkret-spec/spec/v1/zh/authz/policy-server.md`
//! §4 `obligations`:
//!
//! - `require_mfa` — flag the [`RequestContext`] as needing MFA before the request may mutate
//!   state. If the caller has not already completed MFA, the executor returns
//!   [`ObligationError::MfaRequired`] which the integration layer maps to an authorization deny.
//! - `log_to_audit` — emit a tracing record on the structured `policy_audit_obligation` target
//!   carrying the full obligation payload.
//! - `rate_limit` — consult the realm's request_rate_counter in [`RequestContext`]; if the counter
//!   exceeds the obligation's declared `limit`, the executor returns
//!   [`ObligationError::RateLimited`] which the integration layer maps to HTTP 429.
//!
//! Unknown obligation `kind` values are logged at warn level and
//! produce [`ObligationError::UnknownKind`] — fail-closed per the
//! spec §6 conservative posture.

use serde_json::Value;

/// Per-request execution context the obligation executor needs to
/// consult or mutate.
#[derive(Clone, Debug, Default)]
pub struct RequestContext {
    /// Realm the request is bound to. Surfaces in audit emission and
    /// rate-limit bucket keying.
    pub realm_id: String,
    pub actor_id: String,
    pub action: String,
    /// Whether the caller's session has completed MFA. The executor
    /// reads this only — flipping it requires a fresh authentication
    /// pass on the upstream auth server.
    pub mfa_completed: bool,
    /// Marker the executor flips to `true` when a `require_mfa`
    /// obligation has been requested. The integration layer consults
    /// this to render the MFA challenge UI on the next response.
    pub mfa_requested: bool,
    /// Realm-scoped request counter consulted by `rate_limit`
    /// obligations. The counter is owned by the routing layer; the
    /// executor only compares it to the obligation's `limit`.
    pub request_rate_counter: u64,
}

/// Errors the obligation executor can surface to the caller. The
/// integration layer maps each variant to a canonical HTTP status:
///
/// - `MfaRequired` → 401 with `mfa_required` reason_code.
/// - `RateLimited` → 429 with `rate_limit_obligation` reason_code.
/// - `UnknownKind` → 500 with `obligation_unknown` reason_code.
/// - `BadPayload`  → 500 with `obligation_payload_invalid` reason_code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObligationError {
    MfaRequired,
    RateLimited { limit: u64, observed: u64 },
    UnknownKind(String),
    BadPayload(String),
}

impl std::fmt::Display for ObligationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MfaRequired => write!(f, "obligation: mfa_required"),
            Self::RateLimited { limit, observed } => {
                write!(
                    f,
                    "obligation: rate_limited (limit={limit}, observed={observed})"
                )
            }
            Self::UnknownKind(k) => write!(f, "obligation: unknown kind '{k}'"),
            Self::BadPayload(s) => write!(f, "obligation: payload invalid — {s}"),
        }
    }
}

impl std::error::Error for ObligationError {}

/// Execute every obligation in `obligations[]`. Returns the first
/// error encountered; the caller is responsible for deciding whether
/// to short-circuit (default) or continue. Successful obligations
/// before the failure ARE still applied — `require_mfa` flips the
/// `mfa_requested` flag immediately so a partial-execution failure
/// path still surfaces the MFA prompt on the response.
pub fn execute_obligations(
    obligations: &[Value],
    ctx: &mut RequestContext,
) -> Result<(), ObligationError> {
    for obligation in obligations {
        let kind = obligation
            .get("kind")
            .or_else(|| obligation.get("type"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ObligationError::BadPayload("obligation missing `kind` field".to_owned())
            })?;
        match kind {
            "require_mfa" => execute_require_mfa(ctx)?,
            "log_to_audit" => execute_log_to_audit(obligation, ctx),
            "rate_limit" => execute_rate_limit(obligation, ctx)?,
            other => {
                tracing::warn!(
                    target: "policy_audit_obligation",
                    kind = other,
                    realm_id = %ctx.realm_id,
                    actor = %ctx.actor_id,
                    "obligation: unknown kind, failing closed"
                );
                return Err(ObligationError::UnknownKind(other.to_owned()));
            }
        }
    }
    Ok(())
}

fn execute_require_mfa(ctx: &mut RequestContext) -> Result<(), ObligationError> {
    ctx.mfa_requested = true;
    if ctx.mfa_completed {
        Ok(())
    } else {
        Err(ObligationError::MfaRequired)
    }
}

fn execute_log_to_audit(obligation: &Value, ctx: &RequestContext) {
    let payload = obligation
        .get("fields")
        .cloned()
        .unwrap_or_else(|| obligation.clone());
    tracing::info!(
        target: "policy_audit_obligation",
        kind = "log_to_audit",
        realm_id = %ctx.realm_id,
        actor = %ctx.actor_id,
        action = %ctx.action,
        payload = %payload,
        "obligation: log_to_audit"
    );
}

fn execute_rate_limit(obligation: &Value, ctx: &RequestContext) -> Result<(), ObligationError> {
    let limit = obligation
        .get("limit")
        .or_else(|| obligation.get("remaining"))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ObligationError::BadPayload("rate_limit obligation missing numeric `limit`".to_owned())
        })?;
    if ctx.request_rate_counter > limit {
        return Err(ObligationError::RateLimited {
            limit,
            observed: ctx.request_rate_counter,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn ctx() -> RequestContext {
        RequestContext {
            realm_id: "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
            actor_id: "ak:did_core:web:alice.example".to_owned(),
            action: "ak.message.create".to_owned(),
            mfa_completed: false,
            mfa_requested: false,
            request_rate_counter: 0,
        }
    }

    #[test]
    fn require_mfa_denies_when_not_completed() {
        let mut c = ctx();
        let err = execute_obligations(&[json!({"kind": "require_mfa"})], &mut c).unwrap_err();
        assert_eq!(err, ObligationError::MfaRequired);
        assert!(c.mfa_requested, "mfa_requested must flip even on err");
    }

    #[test]
    fn require_mfa_passes_when_completed() {
        let mut c = ctx();
        c.mfa_completed = true;
        let res = execute_obligations(&[json!({"kind": "require_mfa"})], &mut c);
        assert!(res.is_ok());
        assert!(c.mfa_requested);
    }

    #[test]
    fn log_to_audit_succeeds() {
        let mut c = ctx();
        let res = execute_obligations(
            &[json!({"kind": "log_to_audit", "fields": {"category": "policy_block"}})],
            &mut c,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn rate_limit_denies_over_limit() {
        let mut c = ctx();
        c.request_rate_counter = 100;
        let err =
            execute_obligations(&[json!({"kind": "rate_limit", "limit": 10})], &mut c).unwrap_err();
        assert_eq!(
            err,
            ObligationError::RateLimited {
                limit: 10,
                observed: 100,
            }
        );
    }

    #[test]
    fn rate_limit_allows_under_limit() {
        let mut c = ctx();
        c.request_rate_counter = 5;
        let res = execute_obligations(&[json!({"kind": "rate_limit", "limit": 10})], &mut c);
        assert!(res.is_ok());
    }

    #[test]
    fn unknown_kind_fails_closed() {
        let mut c = ctx();
        let err = execute_obligations(&[json!({"kind": "summon_dragon"})], &mut c).unwrap_err();
        assert_eq!(
            err,
            ObligationError::UnknownKind("summon_dragon".to_owned())
        );
    }

    #[test]
    fn type_alias_for_kind_accepted() {
        // The spec example uses `type` (`{"type": "rate_limit", ...}`)
        // for the discriminator. We accept either to ease wire-shape
        // drift between implementations.
        let mut c = ctx();
        c.request_rate_counter = 5;
        let res = execute_obligations(&[json!({"type": "rate_limit", "limit": 10})], &mut c);
        assert!(res.is_ok());
    }

    #[test]
    fn missing_kind_field_rejected() {
        let mut c = ctx();
        let err = execute_obligations(&[json!({"foo": "bar"})], &mut c).unwrap_err();
        assert!(matches!(err, ObligationError::BadPayload(_)));
    }
}
