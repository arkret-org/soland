//! Shared `ak.media.participant_binding.v1` canonical-bytes + verification.
//!
//! `media-service-binding.md` §3 / §7 and `call-state.md` §4.1 require the
//! token issuer to sign, and the `ak.call.state` reducer / receiver to verify,
//! the **same** authoritative tuple over the **same** canonical bytes. To keep
//! the issue and verify sides byte-for-byte symmetric this module is the single
//! definition of:
//!
//! - the binding's signed canonical-JSON field set (`binding_canonical_value`, exactly the seven
//!   authoritative fields), and
//! - the label-prefixed Ed25519 signing input (`binding_signing_input`).
//!
//! The AKP-0010 token issuer ([`super::webrtc`]) builds the signing input here
//! and signs it with the notary key; the operation-admission path
//! ([`crate::routing::events::operations`]) rebuilds the identical bytes from
//! the wire binding and verifies the detached signature with the same notary
//! verifying key. Any drift between the two would surface as a verification
//! failure rather than a silent mismatch.
//!
//! `media-service-binding.md` §3 fixes the cross-implementation signing input:
//!
//! ```text
//! signing_input =
//!   "ak.media.participant_binding.v1" || 0x00 ||
//!   canonical_json({ actor_id, call_id, device_id, expires_at,
//!                    focus_id, participant_identity, realm_id })
//! ```
//!
//! The label is the fixed ASCII `scheme` value (verbatim bytes), followed by a
//! single `0x00`, followed by the canonical JSON of **only** the seven
//! authoritative fields. `scheme` / `issuer_kid` / `issued_at` are unsigned
//! metadata and MUST NOT enter the signing input. `service_signature.sig` signs
//! the identical bytes.

use std::collections::BTreeSet;

use arkret_sdk::{CellRef, Operation};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Value, json};

use crate::state::AppState;

/// Fixed ASCII domain-separation label prefixed (NUL-delimited) before the
/// canonical binding bytes. Equals the `scheme` value verbatim; MUST match the
/// issuer and verifier byte-for-byte (`media-service-binding.md` §3).
pub(crate) const BINDING_SIGNING_LABEL: &[u8] = arkret_sdk::PARTICIPANT_BINDING_SCHEMA.as_bytes();

/// Build the canonical-JSON value the issuer signs over: exactly the seven
/// authoritative fields `(actor_id, call_id, device_id, expires_at, focus_id,
/// participant_identity, realm_id)` (`media-service-binding.md` §3). Every value
/// is taken verbatim (no re-parsing of timestamps), so a verifier that reads the
/// same wire fields reconstructs identical canonical bytes after key sorting.
/// The unsigned metadata (`scheme` / `issuer_kid` / `issued_at`) MUST NOT appear
/// here.
pub(crate) fn binding_canonical_value(
    realm_id: &Value,
    call_id: &Value,
    focus_id: &Value,
    actor_id: &Value,
    device_id: &Value,
    participant_identity: &Value,
    expires_at: &Value,
) -> Value {
    json!({
        "realm_id": realm_id,
        "call_id": call_id,
        "focus_id": focus_id,
        "actor_id": actor_id,
        "device_id": device_id,
        "participant_identity": participant_identity,
        "expires_at": expires_at,
    })
}

/// Canonical bytes of a binding value (`binding_canonical_value` output).
pub(crate) fn binding_canonical_bytes(binding: &Value) -> Vec<u8> {
    arkret_sdk::canonical::canonical_json_bytes(binding)
        .unwrap_or_else(|_| binding.to_string().into_bytes())
}

/// Label-prefixed Ed25519 signing input: `LABEL \0 canonical_bytes`
/// (`media-service-binding.md` §3).
pub(crate) fn binding_signing_input(canonical_bytes: &[u8]) -> Vec<u8> {
    let mut signing_input =
        Vec::with_capacity(BINDING_SIGNING_LABEL.len() + canonical_bytes.len() + 1);
    signing_input.extend_from_slice(BINDING_SIGNING_LABEL);
    signing_input.push(0);
    signing_input.extend_from_slice(canonical_bytes);
    signing_input
}

/// Build the wire `sig` string for a binding given the notary signing key.
/// Used by the AKP-0010 issuer so the issued `sig` and the verifier share one
/// construction.
pub(crate) fn sign_binding(binding: &Value, signing_key: &ed25519_dalek::SigningKey) -> String {
    use ed25519_dalek::Signer as _;
    let canonical_bytes = binding_canonical_bytes(binding);
    let signing_input = binding_signing_input(&canonical_bytes);
    let signature = signing_key.sign(&signing_input);
    format!(
        "eddsa-ed25519:{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

/// Decode the wire `sig` (`eddsa-ed25519:<base64url>` or bare base64url) into a
/// raw Ed25519 [`Signature`].
pub(crate) fn decode_binding_signature(sig: &str) -> Option<Signature> {
    let encoded = sig.strip_prefix("eddsa-ed25519:").unwrap_or(sig);
    let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).ok()?;
    let array: [u8; 64] = bytes.try_into().ok()?;
    Some(Signature::from_bytes(&array))
}

/// Verify a detached binding signature against `verifying_key`. Returns `true`
/// iff the signature covers the canonical signing input for `binding`.
pub(crate) fn verify_binding_signature(
    binding: &Value,
    sig: &str,
    verifying_key: &VerifyingKey,
) -> bool {
    let Some(signature) = decode_binding_signature(sig) else {
        return false;
    };
    let canonical_bytes = binding_canonical_bytes(binding);
    let signing_input = binding_signing_input(&canonical_bytes);
    verifying_key.verify(&signing_input, &signature).is_ok()
}

/// `media_service_binding.md` §2 — the family of the per-realm media_service
/// epoch cell projected by `apply_realm_media_service`.
const REALM_MEDIA_SERVICE_CELL_FAMILY: &str = "ak.component.realm.media_service.v1";

/// The current-epoch issuer anchor set for one realm's media service.
struct MediaServiceAnchors {
    service_id: String,
    issuer_kids: BTreeSet<String>,
}

impl MediaServiceAnchors {
    /// `media-service-binding.md` §3 — an `issuer_kid` is anchored iff it is one
    /// of the focus issuer_kids OR resolves (via its `did#frag` prefix) to the
    /// authoritative `service_id`.
    fn anchors(&self, issuer_kid: &str) -> bool {
        self.issuer_kids.contains(issuer_kid)
            || issuer_kid_belongs_to_service(issuer_kid, &self.service_id)
    }
}

/// `did#frag` → `did` prefix match, matching the issuer-side anchoring rule in
/// `routing::interop::webrtc`.
fn issuer_kid_belongs_to_service(issuer_kid: &str, service_id: &str) -> bool {
    issuer_kid == service_id
        || issuer_kid
            .strip_prefix(service_id)
            .is_some_and(|rest| rest.starts_with('#'))
}

/// Read the current-epoch media_service anchor set for `realm_id` from the
/// projection. Returns `None` when no epoch is projected (fail-closed at the
/// call site with `token_issuer_unauthorised`).
fn media_service_anchors(state: &AppState, realm_id: &str) -> Option<MediaServiceAnchors> {
    let cell_id = CellRef::new(format!(
        "ak:cell:{REALM_MEDIA_SERVICE_CELL_FAMILY}:{realm_id}"
    ))
    .ok()?;
    let value = {
        let projection = state.projection.lock();
        projection.cell_value(&cell_id).cloned()?
    };
    // `apply_realm_media_service` stores either the wrapped
    // `{"media_service": {...}}` or a direct value; tolerate both.
    let config = value.get("media_service").unwrap_or(&value);
    let foci = config.get("foci").and_then(Value::as_array)?;
    let mut issuer_kids = BTreeSet::new();
    for focus in foci {
        if let Some(issuer_kid) = focus
            .get("issuer_kid")
            .or_else(|| config.get("issuer_kid"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|kid| !kid.is_empty())
        {
            issuer_kids.insert(issuer_kid.to_owned());
        }
    }
    let service_id = config
        .get("service_id")
        .or_else(|| config.get("service_did"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            issuer_kids
                .iter()
                .next()
                .and_then(|kid| kid.split_once('#').map(|(id, _)| id.to_owned()))
        })?;
    Some(MediaServiceAnchors {
        service_id,
        issuer_kids,
    })
}

/// Fetch a required string field from the wire binding object.
fn binding_str<'a>(binding: &'a Value, field: &str) -> Option<&'a str> {
    binding
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// `call-state.md` §4.1 / `media-service-binding.md` §3 / §7 — full
/// cryptographic verification of every `ak.call.state.participants[]`
/// `participant_binding`.
///
/// For each binding the receiver MUST:
/// 1. anchor `issuer_kid` to the **current epoch** `ak.realm.media_service` service DID / focus
///    issuer_kids set → else `token_issuer_unauthorised`;
/// 2. confirm the binding's authoritative tuple (`realm_id`, `call_id`, `focus_id`, `actor_id`,
///    `device_id`, `participant_identity`) matches the participant entry and the event envelope;
/// 3. reject an already-expired binding (`expires_at <= event.created_at`);
/// 4. verify the detached Ed25519 `sig` over the canonical signing input.
///
/// Steps 2–4 failing → `participant_binding_invalid`.
pub(crate) fn verify_call_state_participant_bindings(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let payload = &operation.payload;
    // The reducer keys the call cell off `payload.call_id`; some callers
    // wrap the state payload in `{"value": ...}` (Event Envelope shape).
    let call_payload = payload.get("value").unwrap_or(payload);
    let Some(participants) = call_payload.get("participants").and_then(Value::as_array) else {
        return Ok(());
    };
    if !participants
        .iter()
        .any(|participant| participant.get("participant_binding").is_some())
    {
        return Ok(());
    }

    let event_realm_id = operation.realm_id.as_str();
    let event_call_id = call_payload.get("call_id").and_then(Value::as_str);
    let event_created_at = operation.created_at;

    // The anchor set is required the moment any binding is present: a
    // `ak.call.state` carrying a `participant_binding` for a realm with no
    // projected media_service epoch has no authority to anchor the issuer.
    let anchors = media_service_anchors(state, event_realm_id).ok_or(
        "token_issuer_unauthorised: realm has no current-epoch ak.realm.media_service to anchor \
         participant_binding.issuer_kid",
    )?;
    let notary_key = state.notary_verifying_key();

    for participant in participants {
        let Some(binding) = participant.get("participant_binding") else {
            continue;
        };

        // (a) issuer anchoring — current epoch service_id / focus issuer_kids.
        let issuer_kid = binding_str(binding, "issuer_kid")
            .ok_or("participant_binding_invalid: participant_binding.issuer_kid is required")?;
        if !anchors.anchors(issuer_kid) {
            return Err(
                "token_issuer_unauthorised: participant_binding.issuer_kid is not anchored to the \
                 current epoch ak.realm.media_service.service_id",
            );
        }

        // (b) authoritative-tuple consistency with the participant entry +
        // event envelope. `media-service-binding.md` §4.1.2.
        let realm_id = binding_str(binding, "realm_id")
            .ok_or("participant_binding_invalid: participant_binding.realm_id is required")?;
        if realm_id != event_realm_id {
            return Err(
                "participant_binding_invalid: participant_binding.realm_id does not match the event",
            );
        }
        if let Some(call_id) = event_call_id {
            let binding_call_id = binding_str(binding, "call_id")
                .ok_or("participant_binding_invalid: participant_binding.call_id is required")?;
            if binding_call_id != call_id {
                return Err(
                    "participant_binding_invalid: participant_binding.call_id does not match the \
                     call",
                );
            }
        }
        // The participant entry mirrors actor_id / device_id /
        // participant_identity; the binding MUST cover the same tuple.
        for (field, label) in [
            ("actor_id", "actor_id"),
            ("device_id", "device_id"),
            ("participant_identity", "participant_identity"),
        ] {
            if let Some(entry_value) = participant.get(field).and_then(Value::as_str) {
                let binding_value = binding_str(binding, field).ok_or(
                    "participant_binding_invalid: participant_binding is missing a required tuple \
                     field",
                )?;
                if binding_value != entry_value {
                    return Err(field_mismatch_reason(label));
                }
            } else if binding_str(binding, field).is_none() {
                return Err(
                    "participant_binding_invalid: participant_binding is missing a required tuple \
                     field",
                );
            }
        }
        // focus_id is authoritative even when the participant entry omits it.
        if binding_str(binding, "focus_id").is_none() {
            return Err("participant_binding_invalid: participant_binding.focus_id is required");
        }

        // (c) freshness — reject an already-expired binding.
        let expires_at = binding_str(binding, "expires_at")
            .ok_or("participant_binding_invalid: participant_binding.expires_at is required")?;
        let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at).map_err(
            |_| "participant_binding_invalid: participant_binding.expires_at is not RFC3339",
        )?;
        if expires_at <= event_created_at {
            return Err(
                "participant_binding_invalid: participant_binding.expires_at is not after the event \
                 created_at",
            );
        }

        // (d) signature — reconstruct the canonical signing input verbatim from
        // the wire fields and verify the detached Ed25519 signature. The
        // arkret-native self-signed binding is minted with the notary key
        // (`routing::interop::webrtc`), so verify against the notary verifying
        // key; a federated issuer with a resolvable DID is accepted when its
        // resolved key validates the same bytes.
        let sig = binding_str(binding, "sig")
            .ok_or("participant_binding_invalid: participant_binding.sig is required")?;
        let canonical = canonical_value_from_wire(binding);
        if verify_binding_signature(&canonical, sig, &notary_key) {
            continue;
        }
        if let Ok(resolved) = crate::jws_verify::resolve_ed25519_pubkey(state, issuer_kid)
            && verify_binding_signature(&canonical, sig, &resolved)
        {
            continue;
        }
        return Err(
            "participant_binding_invalid: participant_binding.sig failed Ed25519 verification",
        );
    }
    Ok(())
}

/// Per-field mismatch reason (static strings to satisfy the `&'static str`
/// validator contract).
fn field_mismatch_reason(field: &str) -> &'static str {
    match field {
        "actor_id" => {
            "participant_binding_invalid: participant_binding.actor_id does not match the \
             participant entry"
        }
        "device_id" => {
            "participant_binding_invalid: participant_binding.device_id does not match the \
             participant entry"
        }
        _ => {
            "participant_binding_invalid: participant_binding.participant_identity does not match \
             the participant entry"
        }
    }
}

/// Rebuild the canonical binding value from the wire object, taking the seven
/// authoritative signed fields verbatim (`media-service-binding.md` §3). Key
/// sorting in `canonical_json_bytes` makes this byte-identical to the issuer's
/// `binding_canonical_value`. The unsigned metadata (`scheme` / `issuer_kid` /
/// `issued_at`) is deliberately excluded.
fn canonical_value_from_wire(binding: &Value) -> Value {
    let pick = |field: &str| binding.get(field).cloned().unwrap_or(Value::Null);
    binding_canonical_value(
        &pick("realm_id"),
        &pick("call_id"),
        &pick("focus_id"),
        &pick("actor_id"),
        &pick("device_id"),
        &pick("participant_identity"),
        &pick("expires_at"),
    )
}

#[cfg(test)]
mod cross_impl_tests {
    //! Cross-implementation byte lock for the `participant_binding` signing
    //! input. `media-service-binding.md` §3 fixes one normative `signing_input`
    //! that the issuer signs and the verifier reconstructs. soland issues the
    //! binding here (`binding_signing_input`) and the SDK
    //! ([`arkret_sdk::participant_binding_signing_input`]) reconstructs it on the
    //! verify side. Each side has its own self-consistent unit tests, but until
    //! this lock there was no test asserting the two produce **identical bytes**
    //! for the same logical seven-tuple — so a drift on either side could go
    //! unnoticed (unlike the `ak.call.signal` envelope proof, which has a real
    //! inkson round-trip). This test fails the moment either construction drifts.

    use arkret_sdk::{
        CallId, CallMediaParticipantBinding, DeviceId, Did, RealmId,
        participant_binding_signing_input,
    };
    use chrono::{DateTime, Utc};
    use serde_json::json;

    use super::{binding_canonical_bytes, binding_canonical_value, binding_signing_input};

    /// Fixed, realistic seven-tuple shared by both constructions.
    const REALM_ID: &str = "ak:realm:01904100-0000-7000-8000-9b64700c6ee8";
    const CALL_ID: &str = "ak:call:0196441c-0000-7000-8000-000000000000";
    const FOCUS_ID: &str = "fra-1";
    const ACTOR_ID: &str = "did:web:alice.example";
    const DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-000000000005";
    const PARTICIPANT_IDENTITY: &str = "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000";
    const EXPIRES_AT: &str = "2026-05-27T12:34:56Z";

    /// SDK-side signing input for the fixed tuple (`expires_at` overridable so
    /// the field-sensitivity assertion can perturb a single field).
    fn sdk_signing_input(expires_at: &str) -> Vec<u8> {
        let expires_at: DateTime<Utc> = expires_at.parse().unwrap();
        let binding = CallMediaParticipantBinding {
            // Unsigned metadata — MUST NOT enter the signing input.
            scheme: arkret_sdk::PARTICIPANT_BINDING_SCHEMA.to_owned(),
            sig: String::new(),
            issuer_kid: "did:web:media.example#media-token".to_owned(),
            issued_at: "2026-05-27T12:30:00Z".parse().unwrap(),
            // The seven authoritative fields.
            realm_id: RealmId::new(REALM_ID).unwrap(),
            call_id: CallId::new(CALL_ID).unwrap(),
            focus_id: FOCUS_ID.to_owned(),
            actor_id: Did::new(ACTOR_ID).unwrap(),
            device_id: DeviceId::new(DEVICE_ID).unwrap(),
            participant_identity: PARTICIPANT_IDENTITY.to_owned(),
            expires_at,
        };
        participant_binding_signing_input(&binding).unwrap()
    }

    /// soland-side signing input for the same logical tuple, built from the
    /// `&Value` wire form exactly as the issuer / verifier do.
    fn soland_signing_input(expires_at: &str) -> Vec<u8> {
        let canonical = binding_canonical_value(
            &json!(REALM_ID),
            &json!(CALL_ID),
            &json!(FOCUS_ID),
            &json!(ACTOR_ID),
            &json!(DEVICE_ID),
            &json!(PARTICIPANT_IDENTITY),
            &json!(expires_at),
        );
        binding_signing_input(&binding_canonical_bytes(&canonical))
    }

    #[test]
    fn soland_and_sdk_signing_input_are_byte_identical() {
        let soland = soland_signing_input(EXPIRES_AT);
        let sdk = sdk_signing_input(EXPIRES_AT);

        // The lock: the two implementations agree on every byte.
        assert_eq!(
            soland, sdk,
            "soland and SDK participant_binding signing_input diverged",
        );

        // Both carry the normative label + 0x00 prefix (`media-service-binding.md` §3).
        let prefix = b"ak.media.participant_binding.v1\x00";
        assert!(soland.starts_with(prefix), "soland missing label prefix");
        assert!(sdk.starts_with(prefix), "SDK missing label prefix");
    }

    #[test]
    fn signing_input_is_not_degenerate_when_a_field_changes() {
        // Perturbing a single authoritative field MUST change the bytes on both
        // sides (guards against a construction collapsing to a constant), and
        // the two sides MUST still agree on the perturbed bytes.
        let other_expires = "2026-05-27T12:34:57Z";

        let soland_base = soland_signing_input(EXPIRES_AT);
        let soland_other = soland_signing_input(other_expires);
        assert_ne!(
            soland_base, soland_other,
            "soland signing_input did not change when expires_at changed",
        );

        let sdk_base = sdk_signing_input(EXPIRES_AT);
        let sdk_other = sdk_signing_input(other_expires);
        assert_ne!(
            sdk_base, sdk_other,
            "SDK signing_input did not change when expires_at changed",
        );

        assert_eq!(
            soland_other, sdk_other,
            "soland and SDK diverged on the perturbed expires_at",
        );
    }
}
