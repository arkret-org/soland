//! Simple in-memory rate limiter middleware.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use salvo::prelude::*;

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
        Self {
            max_requests: 100,
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
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.headers_mut().insert(
                salvo::http::header::RETRY_AFTER,
                "60".parse().unwrap(),
            );
            res.render(Json(serde_json::json!({
                "error": "rate_limited",
                "error_description": "Too many requests. Please try again later.",
                "request_id": crate::ids::generate_request_id()
            })));
            return;
        }

        ctrl.call_next(req, depot, res).await;
    }
}
