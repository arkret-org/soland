//! Simple in-memory rate limiter middleware.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use salvo::prelude::*;

use crate::wire::{ApiError, ApiErrorDetail};

/// Rate limiter configuration.
#[derive(Clone, Debug)]
pub struct RateLimiterConfig {
    /// Maximum requests per window per key.
    pub max_requests: u32,
    /// Window duration.
    pub window: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        // Match the `per_minute: 600` quota soland advertises in its
        // `cx.server.describe` response (`wire::describe`). Wire +
        // enforcement MUST agree, otherwise clients budget under the
        // advertised quota and trip 429 in normal long-poll loops.
        Self {
            max_requests: 600,
            window: Duration::from_secs(60),
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

    /// Check if a request is allowed for the given key.
    /// Returns true if allowed, false if rate limited.
    pub fn check(&self, key: &str) -> bool {
        let mut state = self.state.lock().expect("rate limiter lock");
        let now = Instant::now();

        if let Some((count, window_start)) = state.get_mut(key)
            && now.duration_since(*window_start) < self.config.window
        {
            if *count >= self.config.max_requests {
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

#[async_trait]
impl Handler for RateLimiterMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        // Use IP address as rate limit key
        let key = req.remote_addr().to_string();

        if !self.limiter.check(&key) {
            let retry_after = self.limiter.retry_after(&key);
            let retry_after_ms = retry_after.as_millis().try_into().unwrap_or(u64::MAX);
            let retry_after_seconds = retry_after_ms.div_ceil(1000).max(1);
            let request_id = crate::ids::generate_request_id();
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.headers_mut()
                .insert(salvo::http::header::RETRY_AFTER, retry_after_seconds.into());
            res.render(Json(ApiError {
                ok: false,
                error: ApiErrorDetail {
                    errcode: "rate_limited".to_owned(),
                    error: "Too many requests. Please try again later.".to_owned(),
                    request_id,
                    retry_after_ms: Some(retry_after_ms),
                    details: BTreeMap::new(),
                },
            }));
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
        });

        assert!(limiter.check("client"));
        assert!(!limiter.check("client"));

        let retry_after = limiter.retry_after("client");
        assert!(retry_after > Duration::from_secs(0));
        assert!(retry_after <= Duration::from_secs(60));
    }
}
