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
