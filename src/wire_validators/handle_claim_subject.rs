//! HC-SOL-1/2 handle-claim ingest hardening.
//!
//! - HC-SOL-1: the `claim_kind` enum lost `service_handle`; v1 only allows `handle_binding` /
//!   `organization_handle`. The retired `claim_type` and `class` field names MUST be rejected as
//!   forbidden wire fields.
//! - HC-SOL-2: the claim `subject` MUST be a holder / principal DID, not a Realm `actor_id`
//!   (`cx:actor:`), a server-local `account_id` (`cx:account:`), a service DID, or a generic
//!   resource id. We delegate to the SDK `validate_handle_claim_subject` so soland / coauth /
//!   cotest agree on the exact rejection surface, mapping its error to reason
//!   `handle_claim_subject_not_principal_did`.

use serde_json::Value;

use super::WireRejection;
use crate::error::reasons;

const REMOVED_SERVICE_HANDLE: &str = "service_handle";

/// Validate an ingested `cx.schema.handle_claim.v1` object's `claim_kind`
/// and `subject`.
pub fn validate_handle_claim_ingest(claim: &Value) -> Result<(), WireRejection> {
    validate_claim_kind(claim)?;
    validate_subject(claim)?;
    Ok(())
}

/// Reject `claim_kind=service_handle` and retired discriminator field names.
pub fn validate_claim_kind(claim: &Value) -> Result<(), WireRejection> {
    if claim.get("claim_type").is_some() || claim.get("class").is_some() {
        return Err(WireRejection::new(
            reasons::CLAIM_TYPE_UNSUPPORTED,
            "claim_type/class are forbidden on v1 handle claims; use claim_kind",
        ));
    }
    let claim_kind = claim.get("claim_kind").and_then(Value::as_str);
    if claim_kind == Some(REMOVED_SERVICE_HANDLE) {
        return Err(WireRejection::new(
            reasons::CLAIM_TYPE_UNSUPPORTED,
            "claim_kind=service_handle is removed in v1; use handle_binding or organization_handle",
        ));
    }
    Ok(())
}

/// Reject a non-principal-DID `subject`. Delegates to the SDK
/// `validate_handle_claim_subject` (the authoritative rejection rule).
pub fn validate_subject(claim: &Value) -> Result<(), WireRejection> {
    let Some(subject) = claim.get("subject").and_then(Value::as_str) else {
        // `subject` is optional on the carrier; absence is not a subject
        // violation (other schema layers enforce presence where required).
        return Ok(());
    };
    let did = contrix_sdk::Did::new(subject.to_owned()).map_err(|_| {
        WireRejection::new(
            reasons::HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID,
            format!("handle claim subject must be a holder/principal DID ({subject})"),
        )
    })?;
    contrix_sdk::validate_handle_claim_subject(&did).map_err(|err| {
        WireRejection::new(
            reasons::HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID,
            err.to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_principal_did_subject_and_handle_binding_claim() {
        let claim = json!({
            "claim_kind": "handle_binding",
            "subject": "did:web:alice-principal.example",
            "handle": "alice:acme.example"
        });
        assert!(validate_handle_claim_ingest(&claim).is_ok());
    }

    #[test]
    fn rejects_service_handle_claim_kind() {
        let claim = json!({"claim_kind": "service_handle", "subject": "did:web:svc.example"});
        let err = validate_handle_claim_ingest(&claim).unwrap_err();
        assert_eq!(err.reason, reasons::CLAIM_TYPE_UNSUPPORTED);
    }

    #[test]
    fn rejects_retired_class_field() {
        let claim = json!({"class": "service_handle", "subject": "did:web:svc.example"});
        let err = validate_claim_kind(&claim).unwrap_err();
        assert_eq!(err.reason, reasons::CLAIM_TYPE_UNSUPPORTED);
    }

    #[test]
    fn rejects_retired_claim_type_field_even_when_value_is_current() {
        let claim = json!({"claim_type": "handle_binding", "subject": "did:web:svc.example"});
        let err = validate_claim_kind(&claim).unwrap_err();
        assert_eq!(err.reason, reasons::CLAIM_TYPE_UNSUPPORTED);
    }

    #[test]
    fn rejects_actor_id_subject() {
        let claim = json!({
            "claim_kind": "handle_binding",
            "subject": "cx:actor:01904100-0000-7000-8000-000000000001"
        });
        let err = validate_handle_claim_ingest(&claim).unwrap_err();
        assert_eq!(err.reason, reasons::HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID);
    }

    #[test]
    fn rejects_account_id_subject() {
        let claim = json!({"subject": "cx:account:01904100-0000-7000-8000-000000000001"});
        let err = validate_handle_claim_ingest(&claim).unwrap_err();
        assert_eq!(err.reason, reasons::HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID);
    }

    #[test]
    fn rejects_non_did_subject() {
        let claim = json!({"subject": "alice:acme.example"});
        let err = validate_handle_claim_ingest(&claim).unwrap_err();
        assert_eq!(err.reason, reasons::HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID);
    }
}
