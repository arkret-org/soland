//! `Content-Encoding` admission for canonical non-streaming JSON operations.
//!
//! `zh/conformance/scalability-constraints.md` §2.1.4 bans `Content-Encoding` on every
//! `body_class=non_streaming_json` operation and requires the request to be rejected with HTTP 415
//! `unsupported_content_encoding` **before** the body is read or decompressed. Accepting a coding
//! would force three separate size layers (compressed wire, decompressed, canonical), open a
//! decompression-bomb surface, and undermine the deterministic byte semantics that producer proofs
//! and JCS depend on.
//!
//! The middleware keys on the request `Content-Type` rather than on the operation registry: every
//! `non_streaming_json` binding declares `application/json`, while the streaming and binary
//! bindings (NDJSON subscribe, multipart Blob upload, Blob/media download) use their own media
//! types and are excluded by §2.1.7. Requests without a body carry no coding to reject.

use salvo::prelude::*;

use crate::error::AppError;

const CANONICAL_JSON_CONTENT_TYPE: &str = "application/json";

pub(crate) fn is_canonical_json_request(req: &Request) -> bool {
    req.headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case(CANONICAL_JSON_CONTENT_TYPE)
        })
        .unwrap_or(false)
}

/// Reject `Content-Encoding` on canonical JSON operations before the body is touched.
#[derive(Clone)]
pub struct RejectContentEncodingMiddleware;

#[async_trait]
impl Handler for RejectContentEncodingMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if req.headers().contains_key("content-encoding") && is_canonical_json_request(req) {
            let error = AppError::unsupported_content_encoding(
                "canonical JSON operations must not use Content-Encoding",
            );
            error.write(req, depot, res).await;
            ctrl.skip_rest();
            return;
        }
        ctrl.call_next(req, depot, res).await;
    }
}
