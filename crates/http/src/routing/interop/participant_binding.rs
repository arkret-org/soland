//! Shared `ak.media.participant_binding.v1` verification.
//!
//! `media-service-binding.md` §3 / §7 and `call-state.md` §4.1 require the
//! token issuer to sign, and the `ak.call.state` reducer / receiver to verify,
//! the same authoritative tuple over the same canonical bytes. The SDK owns
//! that byte construction; Soland only resolves keys and performs admission.
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

use arkret_event_draft::Operation;
use arkret_identifiers::CellRef;
use arkret_models_collaboration::objects::media::CallMediaParticipantBinding;
use arkret_wire::REALM_MEDIA_SERVICE_CELL_FAMILY;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::Value;

use crate::state::AppState;

/// Decode the wire `sig` (unprefixed base64url, as fixed by the schema) into a
/// raw Ed25519 [`Signature`]. The algorithm belongs to the binding profile,
/// not to an ad-hoc prefix inside the signature bytes.
pub(crate) fn decode_binding_signature(sig: &str) -> Option<Signature> {
    let bytes = URL_SAFE_NO_PAD.decode(sig.as_bytes()).ok()?;
    let array: [u8; 64] = bytes.try_into().ok()?;
    Some(Signature::from_bytes(&array))
}

/// Verify a detached binding signature against `verifying_key`. Returns `true`
/// iff the signature covers the canonical signing input for `binding`.
pub(crate) fn verify_binding_signature(
    binding: &CallMediaParticipantBinding,
    sig: &str,
    verifying_key: &VerifyingKey,
) -> bool {
    let Some(signature) = decode_binding_signature(sig) else {
        return false;
    };
    let Ok(signing_input) = arkret_signatures::media::participant_binding_signing_input(binding)
    else {
        return false;
    };
    verifying_key.verify(&signing_input, &signature).is_ok()
}

/// `media_service_binding.md` §2 — the family of the per-realm media_service
/// epoch cell projected by `apply_realm_media_service`.

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
        arkret_wire::DidUrl::new(issuer_kid).is_ok()
            && (self.issuer_kids.contains(issuer_kid)
                || issuer_kid_belongs_to_service(issuer_kid, &self.service_id))
    }
}

/// `did#frag` → `did` prefix match, matching the issuer-side anchoring rule in
/// `routing::interop::webrtc`.
fn issuer_kid_belongs_to_service(issuer_kid: &str, service_id: &str) -> bool {
    issuer_kid
        .strip_prefix(service_id)
        .is_some_and(|rest| rest.starts_with('#'))
}

/// Read the current-epoch media_service anchor set for `realm_id` from the
/// projection. Returns `None` when no epoch is projected (fail-closed at the
/// call site with `token_issuer_unauthorised`).
fn media_service_anchors(state: &AppState, realm_id: &str) -> Option<MediaServiceAnchors> {
    let cell_id = CellRef::new(arkret_wire::null_subject_cell(
        REALM_MEDIA_SERVICE_CELL_FAMILY,
    ))
    .ok()?;
    let value = {
        let projection = state.projections().snapshot();
        projection.realm_cell_value(realm_id, &cell_id).cloned()?
    };
    let foci = value.get("foci").and_then(Value::as_array)?;
    let mut issuer_kids = BTreeSet::new();
    for focus in foci {
        if let Some(issuer_kid) = focus
            .get("issuer_kid")
            .or_else(|| value.get("issuer_kid"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|kid| !kid.is_empty())
        {
            issuer_kids.insert(issuer_kid.to_owned());
        }
    }
    let service_id = value
        .get("service_id")
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
/// cryptographic verification of an `ak.call.state.roster_delta` join
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
    let Some(participant) = call_payload
        .get("roster_delta")
        .filter(|delta| delta.get("op").and_then(Value::as_str) == Some("join"))
        .and_then(|delta| delta.get("participant"))
    else {
        return Ok(());
    };
    if participant.get("participant_binding").is_none() {
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

    {
        let binding = participant
            .get("participant_binding")
            .expect("presence checked above");

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
        let expires_at = arkret_canonical::parse_timestamp_canonical(expires_at).map_err(
            |_| "participant_binding_invalid: participant_binding.expires_at is not canonical",
        )?;
        if expires_at <= event_created_at {
            return Err(
                "participant_binding_invalid: participant_binding.expires_at is not after the event \
                 created_at",
            );
        }

        // (d) signature — reconstruct the canonical signing input verbatim from
        // the wire fields and verify the detached Ed25519 signature. The
        // arkret_native self-signed binding is minted with the notary key
        // (`routing::interop::webrtc`), so verify against the notary verifying
        // key; a federated issuer with a resolvable DID is accepted when its
        // resolved key validates the same bytes.
        let sig = binding_str(binding, "sig")
            .ok_or("participant_binding_invalid: participant_binding.sig is required")?;
        let typed_binding: CallMediaParticipantBinding = serde_json::from_value(binding.clone())
            .map_err(
                |_| "participant_binding_invalid: participant_binding is not the SDK wire type",
            )?;
        if verify_binding_signature(&typed_binding, sig, &notary_key) {
            return Ok(());
        }
        if let Ok(resolved) = crate::jws_verify::resolve_ed25519_pubkey(state, issuer_kid)
            && verify_binding_signature(&typed_binding, sig, &resolved)
        {
            return Ok(());
        }
        Err("participant_binding_invalid: participant_binding.sig failed Ed25519 verification")
    }
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
