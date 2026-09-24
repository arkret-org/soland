//! Read-side PCR device lifecycle fold. The caller must supply a complete,
//! verified same-snapshot input set; this module never reads an empty cache as
//! evidence of no revocation or conflict.

use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use chrono::{DateTime, Utc};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RevokeCommandDecision {
    Pending,
    Rejected,
    Accepted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PcrDeviceLifecycle {
    Revoked,
    Conflicted,
    GenerationFenced,
    RevocationPending,
    Expired,
    Active,
    NotYetEffective,
}

/// This folds already confirmed inputs only. SQL provenance, authoritative
/// terminal binding and conflict-index completeness are verified before call.
pub(crate) fn fold_confirmed_device_status(
    authorization: &DeviceAuthorizePayload,
    current_generation: u64,
    proposals: &[RevokeCommandDecision],
    has_verified_device_conflict: bool,
    now: DateTime<Utc>,
) -> PcrDeviceLifecycle {
    if proposals.contains(&RevokeCommandDecision::Accepted) {
        return PcrDeviceLifecycle::Revoked;
    }
    if has_verified_device_conflict {
        return PcrDeviceLifecycle::Conflicted;
    }
    if authorization.authorized_generation_ref != current_generation {
        return PcrDeviceLifecycle::GenerationFenced;
    }
    if proposals.contains(&RevokeCommandDecision::Pending) {
        return PcrDeviceLifecycle::RevocationPending;
    }
    if authorization
        .expires_at
        .as_ref()
        .and_then(Option::as_ref)
        .is_some_and(|expiry| &now >= expiry)
    {
        return PcrDeviceLifecycle::Expired;
    }
    if now < authorization.not_before {
        return PcrDeviceLifecycle::NotYetEffective;
    }
    PcrDeviceLifecycle::Active
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn authorization() -> DeviceAuthorizePayload {
        serde_json::from_value(json!({
            "device_id":"ak:device:01964137-0000-7000-8000-000000000001",
            "device_public_key_did":"did:key:z6Mki3devicepublickey",
            "hpke_key":"z6LSdevicehpke",
            "algorithms":["Ed25519","HPKE-X25519-HKDF-SHA256-AES128GCM"],
            "device_key_algorithm":"Ed25519",
            "authorized_by":"ak:did_core:web:alice.example",
            "not_before":"2026-09-16T00:00:00.000Z",
            "authorization_binding_kind":"registration_anchor",
            "authorized_generation_ref":1,
            "device_signature":"c2lnbmF0dXJl"
        }))
        .unwrap()
    }

    #[test]
    fn accepted_revoke_wins_even_with_other_pending_or_conflict() {
        let now = "2026-09-24T00:00:00Z".parse().unwrap();
        assert_eq!(
            fold_confirmed_device_status(
                &authorization(),
                2,
                &[
                    RevokeCommandDecision::Rejected,
                    RevokeCommandDecision::Pending,
                    RevokeCommandDecision::Accepted,
                ],
                true,
                now,
            ),
            PcrDeviceLifecycle::Revoked
        );
    }

    #[test]
    fn rejected_dot_does_not_clear_another_pending_dot() {
        let now = "2026-09-24T00:00:00Z".parse().unwrap();
        let authorization = authorization();
        assert_eq!(
            fold_confirmed_device_status(
                &authorization,
                1,
                &[
                    RevokeCommandDecision::Rejected,
                    RevokeCommandDecision::Pending,
                ],
                false,
                now,
            ),
            PcrDeviceLifecycle::RevocationPending
        );
        assert_eq!(
            fold_confirmed_device_status(
                &authorization,
                1,
                &[RevokeCommandDecision::Rejected],
                false,
                now,
            ),
            PcrDeviceLifecycle::Active
        );
    }
}
