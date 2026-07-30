//! Handle-claim subject validation.
//!
//! The claim `subject` MUST be a holder / principal DID, not a Realm `actor_id`
//!   (`ak:actor:`), a server-local `account_id` (`ak:account:`), a service DID, or a generic
//!   resource id. We delegate to the SDK `validate_handle_claim_subject` so soland / coauth /
//!   cotest agree on the exact rejection surface.

use serde_json::Value;

use super::WireRejection;

/// Reject a non-principal-DID `subject`. Delegates to the SDK
/// `validate_handle_claim_subject` (the authoritative rejection rule).
pub fn validate_subject(claim: &Value) -> Result<(), WireRejection> {
    let Some(subject) = claim.get("subject").and_then(Value::as_str) else {
        // `subject` is optional on the carrier; absence is not a subject
        // violation (other schema layers enforce presence where required).
        return Ok(());
    };
    let did = arkret_identifiers::Did::new(subject.to_owned()).map_err(|_| {
        WireRejection::new(format!(
            "handle claim subject must be a holder/principal DID ({subject})"
        ))
    })?;
    arkret_models_identity::handle::validate_handle_claim_subject(&did)
        .map_err(|err| WireRejection::new(err.to_string()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_principal_did_subject() {
        let claim = json!({
            "subject": "did:web:alice-principal.example",
        });
        assert!(validate_subject(&claim).is_ok());
    }

    #[test]
    fn rejects_actor_id_subject() {
        let claim = json!({
            "claim_kind": "handle_binding",
            "subject": "ak:actor:01904100-0000-7000-8000-000000000001"
        });
        assert!(validate_subject(&claim).is_err());
    }

    #[test]
    fn rejects_account_id_subject() {
        let claim = json!({"subject": "ak:account:01904100-0000-7000-8000-000000000001"});
        assert!(validate_subject(&claim).is_err());
    }

    #[test]
    fn rejects_non_did_subject() {
        let claim = json!({"subject": "alice:acme.example"});
        assert!(validate_subject(&claim).is_err());
    }
}
