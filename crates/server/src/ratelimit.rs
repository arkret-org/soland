//! Simple in-memory rate limiter middleware.
//!
//! Spec: A.3 — buckets are keyed on `(remote_addr, endpoint_class)` rather
//! than the raw remote address so a single abusive endpoint cannot starve
//! a peer's quota across the rest of the API surface. We currently
//! recognize three endpoint classes:
//!
//! - `auth`   — the credential/bearer-issuing surface (strict, low ceiling): the spec-canonical
//!   `/_cokret/gate/account/session-grants` and `/_cokret/gate/account/agent-key-pair`, plus the
//!   `/_soland/gate/auth/*` auth routes. Must be hardened against credential-stuffing.
//! - `api`    — every other `/_cokret/*` request (moderate ceiling).
//! - `other`  — anything outside `/_cokret/*` (default ceiling).
//!
//! Each class can carry its own quota; absent overrides fall back to the
//! default (`max_requests` / `window`).
//!
//! Reverse-proxy deployments can opt into sanitized `X-Forwarded-For`
//! client extraction with `SOLAND_RATE_LIMIT_TRUST_X_FORWARDED_FOR=1`.
//! Directly exposed deployments keep the default fail-closed behaviour and
//! bucket on the TCP peer address.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use salvo::prelude::*;

/// Rate limiter configuration.
#[derive(Clone, Debug)]
pub struct RateLimiterConfig {
    /// Maximum requests per window per key. Used as the fallback for any
    /// endpoint class that does not have a class-specific override.
    pub max_requests: u32,
    /// Window duration.
    pub window: Duration,
    /// Strict ceiling for the credential/bearer-issuing endpoints (see the
    /// `Auth` class in [`EndpointClass::classify`]); defaults to a low value
    /// to harden against credential-stuffing.
    pub auth_max_requests: u32,
    /// Moderate ceiling for the rest of `/_cokret/*`.
    pub api_max_requests: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        // Match the `per_minute: 600` quota soland advertises in its
        // `ck.server.query.describe` response (`wire::describe`). Wire +
        // enforcement MUST agree, otherwise clients budget under the
        // advertised quota and trip 429 in normal long-poll loops.
        Self {
            max_requests: 600,
            window: Duration::from_secs(60),
            // Strict for /auth/*: 60/min ≈ 1/sec. Enough headroom for an
            // OAuth refresh cycle, but tight enough to stall a guessing
            // loop.
            auth_max_requests: 60,
            // Moderate for the rest of /_cokret/*. Lower than the
            // advertised `per_minute: 600` so a single endpoint cannot
            // burn the entire IP-wide budget on its own.
            api_max_requests: 300,
        }
    }
}

/// Endpoint class — derived from the request path. Each class participates
/// in a separate `(remote_addr, class)` bucket so a hot endpoint cannot
/// starve a peer's quota across the rest of the API surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum EndpointClass {
    Auth,
    Api,
    Other,
}

impl EndpointClass {
    fn classify(path: &str) -> Self {
        // Credential/bearer-issuing endpoints get the strict `Auth` bucket so the
        // anti-credential-stuffing quota actually covers them. These do NOT live
        // under a single `/_cokret/gate/auth/` prefix: the spec-canonical
        // session-grant exchange and agent-key-pair authorization sit under
        // `/_cokret/gate/account/*`, and the private auth surface lives under
        // `/_soland/gate/auth/*`. Match the real routes, not a dead prefix.
        if path == "/_cokret/gate/account/session-grants"
            || path == "/_cokret/gate/account/agent-key-pair"
            || path.starts_with("/_soland/gate/auth/")
        {
            Self::Auth
        } else if path.starts_with("/_cokret/") {
            Self::Api
        } else {
            Self::Other
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Api => "api",
            Self::Other => "other",
        }
    }
}

/// Rate limiter state.
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimiterConfig,
    state: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn ceiling_for(&self, class: EndpointClass) -> u32 {
        match class {
            EndpointClass::Auth => self.config.auth_max_requests,
            EndpointClass::Api => self.config.api_max_requests,
            EndpointClass::Other => self.config.max_requests,
        }
    }

    /// Check if a request is allowed for the given key.
    /// Returns true if allowed, false if rate limited.
    pub fn check(&self, key: &str) -> bool {
        self.check_with_ceiling(key, self.config.max_requests)
    }

    fn check_with_ceiling(&self, key: &str, ceiling: u32) -> bool {
        let mut state = self.state.lock().expect("rate limiter lock");
        let now = Instant::now();

        if let Some((count, window_start)) = state.get_mut(key)
            && now.duration_since(*window_start) < self.config.window
        {
            if *count >= ceiling {
                return false;
            }
            *count += 1;
            return true;
        }

        // New window or expired
        state.insert(key.to_owned(), (1, now));
        true
    }

    /// Remaining time in the current window for a key.
    pub fn retry_after(&self, key: &str) -> Duration {
        let state = self.state.lock().expect("rate limiter lock");
        let now = Instant::now();
        state
            .get(key)
            .and_then(|(_, window_start)| {
                self.config
                    .window
                    .checked_sub(now.duration_since(*window_start))
            })
            .unwrap_or(self.config.window)
    }

    /// Clean up expired entries.
    pub fn cleanup(&self) {
        let mut state = self.state.lock().expect("rate limiter lock");
        let now = Instant::now();
        state.retain(|_, (_, window_start)| now.duration_since(*window_start) < self.config.window);
    }
}

/// Rate limiter middleware for Salvo.
#[derive(Clone)]
pub struct RateLimiterMiddleware {
    limiter: RateLimiter,
}

impl RateLimiterMiddleware {
    pub fn new(limiter: RateLimiter) -> Self {
        Self { limiter }
    }
}

fn forwarded_for_trusted() -> bool {
    std::env::var("SOLAND_RATE_LIMIT_TRUST_X_FORWARDED_FOR")
        .or_else(|_| std::env::var("SOLAND_TRUST_X_FORWARDED_FOR"))
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "on" | "yes"
            )
        })
        .unwrap_or(false)
}

fn trusted_forwarded_client(req: &Request) -> Option<String> {
    if !forwarded_for_trusted() {
        return None;
    }
    let header = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())?;
    header
        .split(',')
        .map(str::trim)
        .find(|part| !part.is_empty())
        .map(ToOwned::to_owned)
}

fn rate_limit_peer_key(req: &Request) -> String {
    trusted_forwarded_client(req).unwrap_or_else(|| req.remote_addr().to_string())
}

#[async_trait]
impl Handler for RateLimiterMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        // Spec: A.3 — buckets are keyed on `(remote_addr, endpoint_class)`
        // so a hot endpoint (e.g. /auth) cannot starve the rest of the
        // surface for the same peer, and a low ceiling on /auth/* makes
        // credential-stuffing prohibitively slow.
        let class = EndpointClass::classify(req.uri().path());
        let key = format!("{}:{}", rate_limit_peer_key(req), class.label());
        let ceiling = self.limiter.ceiling_for(class);

        if !self.limiter.check_with_ceiling(&key, ceiling) {
            let retry_after = self.limiter.retry_after(&key);
            let retry_after_ms = retry_after.as_millis().try_into().unwrap_or(u64::MAX);
            let retry_after_seconds = retry_after_ms.div_ceil(1000).max(1);
            let request_id = crate::ids::generate_request_id();
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.headers_mut()
                .insert(salvo::http::header::RETRY_AFTER, retry_after_seconds.into());
            res.render(Json(
                cokret_sdk::ErrorEnvelope::new(
                    "rate_limited",
                    "Too many requests. Please try again later.",
                )
                .with_request_id(request_id)
                .with_retry_after_ms(Some(retry_after_ms)),
            ));
            return;
        }

        ctrl.call_next(req, depot, res).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_reports_active_window_remaining() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
            auth_max_requests: 1,
            api_max_requests: 1,
        });

        assert!(limiter.check("client"));
        assert!(!limiter.check("client"));

        let retry_after = limiter.retry_after("client");
        assert!(retry_after > Duration::from_secs(0));
        assert!(retry_after <= Duration::from_secs(60));
    }
}
