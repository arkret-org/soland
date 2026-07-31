//! Canonical JSON operation-body admission.
//!
//! The transport wire limit is 16 MiB, while every parsed non-streaming JSON
//! operation has a separate 8 MiB JCS-canonical body limit. Keeping this check
//! in middleware makes the bound uniform across the protocol and product
//! routers without changing the schema-error ordering for malformed JSON.

use arkret_wire::MAX_OPERATION_CANONICAL_BODY_BYTES;
use salvo::prelude::*;

use crate::content_encoding::is_canonical_json_request;
use crate::error::{AppError, ErrorCode};

fn canonical_body_size(raw: &[u8]) -> Option<usize> {
    let value: serde_json::Value = serde_json::from_slice(raw).ok()?;
    arkret_canonical::canonical_json_bytes(&value)
        .ok()
        .map(|bytes| bytes.len())
}

/// Reject a request whose wire body exceeds the transport limit.
///
/// `scalability-constraints.md` §2.1.8 step 4 is a `Content-Length` precheck
/// that answers `payload_too_large` (HTTP 413). Salvo's `SecureMaxSize` drops
/// the oversized body instead of answering, which leaves the handler parsing an
/// empty payload and reporting `schema_violation` — a byte-limit failure
/// surfacing as a schema failure. This runs the precheck the spec describes so
/// the size answer is the one that reaches the caller.
#[derive(Clone)]
pub struct RequestWireSizeLimitMiddleware {
    max_bytes: usize,
}

impl RequestWireSizeLimitMiddleware {
    #[must_use]
    pub fn new(max_bytes: usize) -> Self {
        Self { max_bytes }
    }
}

#[async_trait]
impl Handler for RequestWireSizeLimitMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let declared = req
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        // A caller that sends no `Content-Length` (chunked transfer) still owes
        // the same bound, so fall back to the bytes actually received. Only
        // canonical JSON bodies are buffered for this: reading a streaming or
        // multipart upload here would consume the very stream its handler needs.
        let observed = match declared {
            Some(length) => Some(length),
            None if is_canonical_json_request(req) => {
                req.payload().await.ok().map(|payload| payload.len())
            }
            None => None,
        };
        if observed.is_some_and(|length| length > self.max_bytes) {
            let error = AppError::new(
                ErrorCode::PayloadTooLarge,
                "request body exceeds the transport wire limit",
            )
            .with_wire_code("payload_too_large");
            error.write(req, depot, res).await;
            ctrl.skip_rest();
            return;
        }
        ctrl.call_next(req, depot, res).await;
    }
}

/// Reject a valid JSON body whose JCS form exceeds the operation-body limit.
///
/// Invalid JSON is deliberately passed through: operation handlers remain the
/// authority for `bad_json` and schema-validation errors.
#[derive(Clone)]
pub struct CanonicalJsonBodyLimitMiddleware;

#[async_trait]
impl Handler for CanonicalJsonBodyLimitMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if is_canonical_json_request(req) {
            if let Ok(payload) = req.payload().await {
                if canonical_body_size(payload)
                    .is_some_and(|size| size > MAX_OPERATION_CANONICAL_BODY_BYTES)
                {
                    let error = AppError::new(
                        ErrorCode::PayloadTooLarge,
                        "canonical JSON operation body exceeds 8 MiB",
                    )
                    .with_wire_code("payload_too_large");
                    error.write(req, depot, res).await;
                    ctrl.skip_rest();
                    return;
                }
            }
        }
        ctrl.call_next(req, depot, res).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_size_ignores_json_whitespace() {
        assert_eq!(canonical_body_size(br#"{ "b": 2, "a": 1 }"#), Some(13));
    }

    #[test]
    fn malformed_json_is_left_for_the_handler() {
        assert_eq!(canonical_body_size(b"{"), None);
    }
}
