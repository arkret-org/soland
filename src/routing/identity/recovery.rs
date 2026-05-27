//! CXP-0010 / R3 recovery policy + recovery receipt — STUB surface.
//!
//! Mounts the two new spec endpoints introduced in contrix-spec b47ff6ec:
//!
//! - `POST /api/v1/identity/recovery-policy`  — persist + advance a recovery policy.
//! - `POST /api/v1/identity/recovery-receipt` — record a recovery receipt for a witnessed session.
//!
//! Full validation (proof_kind enum, recovery_session binding, expires /
//! policy_version monotonicity, `recovery_witness_revoke_lagging` error path)
//! is intentionally deferred. These handlers return a canonical 501
//! `unimplemented` envelope so cross-project consumers (sodmin, cotest,
//! yougen) can discover the route shape now and the body shape later.
//!
//! TODO(R3.1): replace these stubs with real persistence + reducer wiring.

use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

pub(super) fn router() -> Router {
    Router::with_path("identity")
        .push(Router::with_path("recovery-policy").post(recovery_policy_stub))
        .push(Router::with_path("recovery-receipt").post(recovery_receipt_stub))
}

/// TODO(R3.1): implement `cx.identity.recovery_policy.put` per
/// `contrix-spec/spec/v1/artifacts/schemas/recovery-policy.schema.json`.
/// Full validation (proof_kind enum, recovery_session binding, expires /
/// policy_version monotonicity) is deferred. Today we return 501 so
/// cross-project consumers can discover the route shape.
#[handler]
async fn recovery_policy_stub(_body: JsonBody<Value>, res: &mut Response) {
    render_unimplemented(res, "cx.identity.recovery_policy.put");
}

/// TODO(R3.1): implement `cx.identity.recovery_receipt.put` per
/// `contrix-spec/spec/v1/artifacts/schemas/recovery-receipt.schema.json`.
/// `recovery_witness_revoke_lagging` error path also lands in R3.1.
#[handler]
async fn recovery_receipt_stub(_body: JsonBody<Value>, res: &mut Response) {
    render_unimplemented(res, "cx.identity.recovery_receipt.put");
}

fn render_unimplemented(res: &mut Response, operation: &str) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Json(json!({
        "error": "unimplemented",
        "operation": operation,
        "todo": "R3.1",
    })));
}
