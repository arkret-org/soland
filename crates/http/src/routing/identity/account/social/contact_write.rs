use arkret_models_collaboration::contact_operations::{
    ContactAcceptedOutcome, ContactBasis, ContactCommitRequestBody, ContactCurrentProof,
    ContactFailedOutcome, ContactLineage, ContactOperationRejectReason, ContactPreparedEventDraft,
    ContactPreparedOutcome, ContactResultKind, ContactScope, ContactScopeUpdatePayload,
    ContactScopeUpdateSchema, NormalResponseAcceptanceReceipt, RejectAcceptanceReceipt,
    RequestAcceptanceReceipt, RequestAcceptanceReceiptCore,
};
use arkret_models_collaboration::events_payloads::contact::{
    ContactAcceptedPayload, ContactRejectedPayload, ContactRequestedPayload,
    ContactTombstonedPayload,
};
use arkret_wire::{
    Base64UrlString, DidUrl, Event, IdempotencyKey, ProtocolOperationId, ProtocolSignature,
    ReservationHandle,
};
use ed25519_dalek::Signature;
use serde::de::DeserializeOwned;

use super::*;

const CONTACT_RESERVATION_TTL_MINUTES: i64 = 10;
const CONTACT_OUTCOME_TTL_HOURS: i64 = 24;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result_kind", rename_all = "snake_case", deny_unknown_fields)]
enum ContactReservationBranch {
    Request {
        peer: ContactPeer,
        granted_to_peer_scopes: Vec<ContactScope>,
        previous_terminal_basis_id: Option<Hash>,
    },
    Response {
        request_receipt: RequestAcceptanceReceipt,
        peer: ContactPeer,
        basis_id: Hash,
        granted_to_peer_scopes: Vec<ContactScope>,
    },
    Reject {
        request_receipt: RequestAcceptanceReceipt,
        peer: ContactPeer,
    },
    ScopeUpdate {
        peer: ContactPeer,
        basis_id: Hash,
        version: u64,
        predecessor_event_ref: EventId,
        granted_to_peer_scopes: Vec<ContactScope>,
    },
    Tombstone {
        peer: ContactPeer,
        basis_id: Hash,
        version: u64,
        predecessor_event_ref: EventId,
    },
}

impl ContactReservationBranch {
    fn peer(&self) -> &ContactPeer {
        match self {
            Self::Request { peer, .. }
            | Self::Response { peer, .. }
            | Self::Reject { peer, .. }
            | Self::ScopeUpdate { peer, .. }
            | Self::Tombstone { peer, .. } => peer,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactReservation {
    operation_id: ProtocolOperationId,
    idempotency_key: IdempotencyKey,
    reservation_handle: ReservationHandle,
    holder: ContactPeer,
    branch: ContactReservationBranch,
    event_draft: ContactPreparedEventDraft,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: chrono::DateTime<chrono::Utc>,
}

fn contact_reservation_key(handle: &ReservationHandle) -> String {
    format!("contact-reservation:{}", handle.as_str())
}

fn contact_phase_idempotency_key(phase: &str, key: &IdempotencyKey) -> String {
    format!("contact-{phase}:{}", key.as_str())
}

fn contact_hash<T: Serialize>(label: &str, value: &T) -> Result<Hash, AppError> {
    let canonical = arkret_canonical::canonical_json_bytes(value)
        .map_err(|error| AppError::internal(format!("Contact digest canonicalize: {error}")))?;
    let mut transcript = Vec::with_capacity(label.len() + 1 + canonical.len());
    transcript.extend_from_slice(label.as_bytes());
    transcript.push(b'\n');
    transcript.extend_from_slice(&canonical);
    Hash::new(arkret_canonical::sha256_digest(&transcript))
        .map_err(|error| AppError::internal(format!("Contact digest invalid: {error}")))
}

pub(crate) fn canonical_contact_digest<T: Serialize>(value: &T) -> Result<Hash, AppError> {
    Hash::new(
        arkret_canonical::canonical_sha256(value)
            .map_err(|error| AppError::internal(format!("Contact digest canonicalize: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact digest invalid: {error}")))
}

pub(crate) fn verify_contact_service_signature<T: Serialize>(
    state: &AppState,
    expected_service_id: &str,
    signature: &ProtocolSignature,
    signed_value: &T,
    evidence_field: &str,
) -> Result<(), AppError> {
    let signature_bytes = arkret_canonical::canonical_json_bytes(signed_value)
        .map_err(|error| AppError::internal(format!("Contact receipt canonicalize: {error}")))?;
    verify_contact_service_signature_bytes(
        state,
        expected_service_id,
        signature,
        &signature_bytes,
        evidence_field,
    )
}

pub(crate) fn verify_contact_service_signature_bytes(
    state: &AppState,
    expected_service_id: &str,
    signature: &ProtocolSignature,
    signature_bytes: &[u8],
    evidence_field: &str,
) -> Result<(), AppError> {
    let expected_method =
        crate::routing::federation::federation_service_signature_key_id(expected_service_id);
    if signature.verification_method.as_str() != expected_method {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            format!(
                "{evidence_field}.signature.verification_method is not the issuer's trusted service method"
            ),
        ));
    }
    let verifying_key = if expected_service_id == state.service_id() {
        state.notary_verifying_key()
    } else {
        state
            .federation_peer_verification_method_key(&expected_method)
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "{evidence_field}.signature historical verification key is unavailable"
                    ),
                )
            })?
    };
    let signature = URL_SAFE_NO_PAD
        .decode(signature.jws.as_str())
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "{evidence_field}.signature.jws must contain exactly 64 Ed25519 signature bytes"
                ),
            )
        })?;
    verifying_key
        .verify_strict(signature_bytes, &signature)
        .map_err(|_| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                format!("{evidence_field}.signature verification failed"),
            )
        })
}

pub(crate) fn validate_request_receipt_cryptography(
    state: &AppState,
    receipt: &RequestAcceptanceReceipt,
    evidence_field: &str,
) -> Result<(), AppError> {
    receipt.core.validate().map_err(|error| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            format!("{evidence_field}.core is invalid: {error}"),
        )
    })?;
    let recomputed = contact_hash("ak.contact.request-acceptance-core.v1", &receipt.core)?;
    if recomputed != receipt.receipt_digest {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            format!("{evidence_field}.receipt_digest does not match its canonical core"),
        ));
    }
    verify_contact_service_signature(
        state,
        receipt.core.issuer.as_str(),
        &receipt.signature,
        &json!({"core": receipt.core, "receipt_digest": receipt.receipt_digest}),
        evidence_field,
    )
}

fn service_signature<T: Serialize>(
    state: &AppState,
    value: &T,
) -> Result<ProtocolSignature, AppError> {
    let created_at = now();
    let bytes = arkret_canonical::canonical_json_bytes(value)
        .map_err(|error| AppError::internal(format!("Contact receipt canonicalize: {error}")))?;
    let signature = state.notary_signing_key().sign(&bytes);
    Ok(ProtocolSignature {
        verification_method: DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(state.service_id()),
        )
        .map_err(|error| AppError::internal(format!("service verification method: {error}")))?,
        created_at,
        jws: Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
            .map_err(|error| AppError::internal(format!("Contact signature encode: {error}")))?,
    })
}

async fn validate_request_acceptance_receipt(
    state: &AppState,
    record: &ContactRecord,
    responder: &ContactPeer,
    receipt: &RequestAcceptanceReceipt,
) -> Result<(), AppError> {
    receipt.core.validate().map_err(|error| {
        AppError::invalid_param(format!("invalid Contact request receipt: {error}"))
    })?;
    if &receipt.core.peer != responder {
        return Err(AppError::capability_denied(
            "Contact request receipt does not name the responder",
        ));
    }
    if record.status != "pending"
        || record.requester != receipt.core.holder.subject_id().as_str()
        || record.target != receipt.core.peer.subject_id().as_str()
        || record.request_event_ref.as_deref() != Some(receipt.core.request_event_ref.as_str())
    {
        return Err(AppError::conflict(
            "Contact request receipt differs from the durable pending slot",
        ));
    }

    validate_request_receipt_cryptography(state, receipt, "request_receipt")?;

    let expected_issuer = record
        .peer_service_id
        .as_deref()
        .unwrap_or_else(|| state.service_id());
    if receipt.core.issuer.as_str() != expected_issuer {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "request_receipt.core.issuer does not match the durable request source service",
        ));
    }
    let stored = state
        .event_queries()
        .accepted_event(receipt.core.request_event_ref.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Contact request Event lookup: {error}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "request_receipt.core.request_digest cannot be verified: the durable accepted source Event is unavailable",
            )
        })?;
    let request_event = serde_json::from_value::<Event>(stored.envelope)
        .map_err(|error| AppError::internal(format!("stored Contact request Event: {error}")))?;
    let request_digest = Hash::new(request_event.event_digest().map_err(|error| {
        AppError::internal(format!("stored Contact request Event digest: {error}"))
    })?)
    .map_err(|error| AppError::internal(format!("stored Contact request digest: {error}")))?;
    let requested_payload = serde_json::from_value::<ContactRequestedPayload>(
        serde_json::to_value(&request_event.payload)
            .map_err(|error| AppError::internal(format!("Contact request payload: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("stored Contact request payload: {error}")))?;
    let expected_checkpoint = contact_hash(
        "ak.contact.request-source-checkpoint.v1",
        &json!({
            "event_ref": request_event.event_id,
            "event_digest": request_digest,
        }),
    )?;
    if request_event.kind != arkret_wire::EventKind::ContactRequested
        || request_event.event_id != receipt.core.request_event_ref
        || request_event.actor_id != *receipt.core.holder.subject_id()
        || requested_payload.peer != receipt.core.peer
        || request_digest != receipt.core.request_digest
        || expected_checkpoint != receipt.core.source_checkpoint
        || receipt.core.accepted_at < request_event.created_at
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "request_receipt.core coordinates do not match the durable accepted Contact request",
        ));
    }
    Ok(())
}

async fn holder_peer(state: &AppState, holder: &str) -> Result<ContactPeer, AppError> {
    let holder_id = Did::new(holder.to_owned())
        .map_err(|error| AppError::internal(format!("holder DID invalid: {error}")))?;
    if let Some(agent) = state
        .agent_pairings()
        .agent(holder)
        .await
        .map_err(|error| AppError::internal(format!("holder Agent lookup: {error}")))?
    {
        return Ok(ContactPeer::Agent {
            agent_id: holder_id,
            controller_id: Did::new(agent.controller_id)
                .map_err(|error| AppError::internal(format!("Agent controller DID: {error}")))?,
        });
    }
    Ok(ContactPeer::Human {
        principal_id: holder_id,
    })
}

fn validate_distinct_peer(holder: &ContactPeer, peer: &ContactPeer) -> Result<(), AppError> {
    if holder.subject_id() == peer.subject_id() {
        return Err(AppError::invalid_param(
            "Contact peer must differ from holder",
        ));
    }
    Ok(())
}

fn contact_scope_strings(scopes: &[ContactScope]) -> Vec<String> {
    scopes
        .iter()
        .map(|scope| {
            serde_json::to_value(scope)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .expect("ContactScope serializes as a string")
        })
        .collect()
}

fn new_unsigned_contact_event<K: arkret_event_draft::EventSpec>(
    holder: &ContactPeer,
    realm_id: RealmId,
    actor_seq: u64,
    hlc: arkret_identifiers::Hlc,
    prev_refs: Vec<EventId>,
    seal_basis: arkret_wire::SealBasis,
    created_at: chrono::DateTime<chrono::Utc>,
    payload: K::Payload,
) -> Result<Event, AppError> {
    arkret_event_draft::TypedEventDraft::<K>::new(
        arkret_wire::ScopeRef::Realm { realm_id },
        holder.subject_id().clone(),
        payload,
    )
    .map(|draft| draft.with_prev_refs(prev_refs).with_seal_basis(seal_basis))
    .and_then(|draft| draft.author(actor_seq, hlc, created_at))
    .map_err(|error| AppError::internal(format!("Contact typed Event draft invalid: {error}")))
}

fn contact_event_draft(event: &Event) -> Result<ContactPreparedEventDraft, AppError> {
    let digest_payload = event
        .digest_payload()
        .map_err(|error| AppError::internal(format!("Contact Event draft: {error}")))?;
    let unsigned_bytes = arkret_canonical::canonical_json_bytes(&digest_payload)
        .map_err(|error| AppError::internal(format!("Contact Event draft bytes: {error}")))?;
    Ok(ContactPreparedEventDraft {
        event_id: event.event_id.clone(),
        kind: event.kind.clone(),
        unsigned_event_bytes: Base64UrlString::new(URL_SAFE_NO_PAD.encode(unsigned_bytes))
            .map_err(|error| AppError::internal(format!("Contact draft encode: {error}")))?,
        event_digest: Hash::new(
            event
                .event_digest()
                .map_err(|error| AppError::internal(format!("Contact Event digest: {error}")))?,
        )
        .map_err(|error| AppError::internal(format!("Contact Event digest invalid: {error}")))?,
    })
}

fn prepared_outcome(reservation: &ContactReservation) -> ContactOperationOutcome {
    let fields = (
        reservation.operation_id.clone(),
        reservation.reservation_handle.clone(),
        reservation.expires_at,
        reservation.event_draft.clone(),
    );
    let outcome = match reservation.branch {
        ContactReservationBranch::Request { .. } => ContactPreparedOutcome::Request {
            operation_id: fields.0,
            reservation_handle: fields.1,
            expires_at: fields.2,
            event_draft: fields.3,
        },
        ContactReservationBranch::Response { .. } => ContactPreparedOutcome::Response {
            operation_id: fields.0,
            reservation_handle: fields.1,
            expires_at: fields.2,
            event_draft: fields.3,
        },
        ContactReservationBranch::Reject { .. } => ContactPreparedOutcome::Reject {
            operation_id: fields.0,
            reservation_handle: fields.1,
            expires_at: fields.2,
            event_draft: fields.3,
        },
        ContactReservationBranch::ScopeUpdate { .. } => ContactPreparedOutcome::ScopeUpdate {
            operation_id: fields.0,
            reservation_handle: fields.1,
            expires_at: fields.2,
            event_draft: fields.3,
        },
        ContactReservationBranch::Tombstone { .. } => ContactPreparedOutcome::Tombstone {
            operation_id: fields.0,
            reservation_handle: fields.1,
            expires_at: fields.2,
            event_draft: fields.3,
        },
    };
    ContactOperationOutcome::Prepared { outcome }
}

async fn store_prepare(
    state: &AppState,
    principal: &str,
    idempotency_key: &IdempotencyKey,
    request_hash: &str,
    reservation: &ContactReservation,
) -> Result<(), AppError> {
    let created_at = now();
    let outcome = prepared_outcome(reservation);
    for (key, body) in [
        (
            contact_phase_idempotency_key("prepare", idempotency_key),
            serde_json::to_value(&outcome)
                .map_err(|error| AppError::internal(format!("Contact outcome encode: {error}")))?,
        ),
        (
            contact_reservation_key(&reservation.reservation_handle),
            serde_json::to_value(reservation).map_err(|error| {
                AppError::internal(format!("Contact reservation encode: {error}"))
            })?,
        ),
    ] {
        state
            .jobs()
            .store_idempotency_record(soland_services::jobs::IdempotencyState {
                principal_id: principal.to_owned(),
                idempotency_key: key,
                service_id: state.service_id().clone(),
                request_hash: request_hash.to_owned(),
                response_status: StatusCode::OK.as_u16().into(),
                response_body: body,
                created_at,
                expires_at: reservation.expires_at,
            })
            .await
            .map_err(|error| AppError::internal(format!("Contact reservation store: {error}")))?;
    }
    Ok(())
}

async fn replay<T: DeserializeOwned>(
    state: &AppState,
    principal: &str,
    key: &str,
    request_hash: &str,
) -> Result<Option<T>, AppError> {
    let Some(record) = state
        .jobs()
        .idempotency_record(principal, key)
        .await
        .map_err(|error| AppError::internal(format!("Contact idempotency lookup: {error}")))?
    else {
        return Ok(None);
    };
    if record.request_hash != request_hash {
        return Err(AppError::conflict(
            "Contact idempotency key was used for different canonical bytes",
        ));
    }
    serde_json::from_value(record.response_body)
        .map(Some)
        .map_err(|error| AppError::internal(format!("stored Contact outcome: {error}")))
}

async fn persist_final(
    state: &AppState,
    principal: &str,
    key: &str,
    request_hash: &str,
    outcome: &ContactOperationOutcome,
) -> Result<(), AppError> {
    let created_at = now();
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            principal_id: principal.to_owned(),
            idempotency_key: key.to_owned(),
            service_id: state.service_id().clone(),
            request_hash: request_hash.to_owned(),
            response_status: StatusCode::OK.as_u16().into(),
            response_body: serde_json::to_value(outcome)
                .map_err(|error| AppError::internal(format!("Contact outcome encode: {error}")))?,
            created_at,
            expires_at: created_at + chrono::Duration::hours(CONTACT_OUTCOME_TTL_HOURS),
        })
        .await
        .map_err(|error| AppError::internal(format!("Contact outcome store: {error}")))
}

async fn prepare<K: arkret_event_draft::EventSpec>(
    state: &AppState,
    session: &SessionRecord,
    operation_id: ProtocolOperationId,
    idempotency_key: IdempotencyKey,
    branch: ContactReservationBranch,
    payload: K::Payload,
) -> JsonResult<ContactOperationOutcome> {
    let holder = holder_peer(state, &session.actor).await?;
    validate_distinct_peer(&holder, branch.peer())?;
    let request_value = json!({
        "operation_id": operation_id,
        "idempotency_key": idempotency_key,
        "branch": branch,
        "payload": payload,
        "event_kind": K::KIND,
    });
    let request_hash = arkret_canonical::canonical_sha256(&request_value)
        .map_err(|error| AppError::internal(format!("Contact prepare digest: {error}")))?;
    if let Some(outcome) = replay::<ContactOperationOutcome>(
        state,
        &session.actor,
        &contact_phase_idempotency_key("prepare", &idempotency_key),
        &request_hash,
    )
    .await?
    {
        return json_ok(outcome);
    }
    let realm_id = RealmId::new(soland_services::identity::principal_control_realm_for_did(
        &session.actor,
    ))
    .map_err(|error| AppError::internal(format!("holder PCR id invalid: {error}")))?;
    let frontier = crate::routing::events::event_log::load_realm_actor_frontier(
        state,
        realm_id.clone(),
        holder.subject_id().clone(),
    )
    .await?;
    let accepted_seal = if state.projections().is_conformance_fixture_realm(&realm_id) {
        crate::notary::ensure_realm_seal_head(state, &realm_id)
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    format!("conformance fixture Seal head unavailable: {error}"),
                )
            })?
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    "conformance fixture Realm has no accepted Seal head",
                )
            })?
    } else {
        crate::routing::events::event_log::governance_proof::materialize_realm_event_seal(
            state, &realm_id,
        )
        .await?
        .accepted_seal
    };
    let seal_basis = arkret_wire::SealBasis {
        leaves: vec![accepted_seal.id],
    };
    let created_at = now();
    let event = new_unsigned_contact_event::<K>(
        &holder,
        realm_id,
        frontier.next_actor_seq,
        arkret_identifiers::Hlc::new(state.hlc().now())
            .map_err(|error| AppError::internal(format!("Contact Event HLC: {error}")))?,
        frontier.frontier_event_ids,
        seal_basis,
        created_at,
        payload,
    )?;
    let reservation = ContactReservation {
        operation_id,
        idempotency_key: idempotency_key.clone(),
        reservation_handle: ReservationHandle::new(crate::ids::generate("reservation"))
            .map_err(AppError::internal)?,
        holder,
        branch,
        event_draft: contact_event_draft(&event)?,
        expires_at: created_at + chrono::Duration::minutes(CONTACT_RESERVATION_TTL_MINUTES),
    };
    store_prepare(
        state,
        &session.actor,
        &idempotency_key,
        &request_hash,
        &reservation,
    )
    .await?;
    json_ok(prepared_outcome(&reservation))
}

fn validate_signed_event(event: &Event, draft: &ContactPreparedEventDraft) -> Result<(), AppError> {
    let actual = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|error| AppError::invalid_param(format!("signed Contact Event: {error}")))?,
    )
    .map_err(|error| AppError::invalid_param(format!("signed Contact Event bytes: {error}")))?;
    let expected = URL_SAFE_NO_PAD
        .decode(draft.unsigned_event_bytes.as_str())
        .map_err(|_| AppError::internal("stored Contact draft bytes are invalid"))?;
    let digest = Hash::new(
        event
            .event_digest()
            .map_err(|error| AppError::invalid_param(format!("signed Contact Event: {error}")))?,
    )
    .map_err(|error| AppError::invalid_param(format!("signed Contact digest: {error}")))?;
    if event.event_id != draft.event_id
        || event.kind != draft.kind
        || actual != expected
        || digest != draft.event_digest
        || event.proofs.is_empty()
        || event
            .proofs
            .iter()
            .any(|proof| proof.event_digest != draft.event_digest)
    {
        return Err(AppError::conflict(
            "signed Contact Event differs from its durable reservation draft",
        ));
    }
    Ok(())
}

async fn reservation_for_commit(
    state: &AppState,
    principal: &str,
    body: &ContactCommitRequestBody,
) -> Result<ContactReservation, AppError> {
    let record = state
        .jobs()
        .idempotency_record(
            principal,
            &contact_reservation_key(&body.reservation_handle),
        )
        .await
        .map_err(|error| AppError::internal(format!("Contact reservation lookup: {error}")))?
        .ok_or_else(|| AppError::conflict("Contact reservation is missing or expired"))?;
    if record.expires_at <= now() {
        return Err(AppError::conflict("Contact reservation expired"));
    }
    let reservation: ContactReservation = serde_json::from_value(record.response_body)
        .map_err(|error| AppError::internal(format!("stored Contact reservation: {error}")))?;
    if reservation.operation_id != body.operation_id
        || reservation.idempotency_key != body.idempotency_key
        || reservation.reservation_handle != body.reservation_handle
    {
        return Err(AppError::conflict("Contact reservation binding mismatch"));
    }
    validate_signed_event(&body.signed_event, &reservation.event_draft)?;
    Ok(reservation)
}

fn sorted_pair(left: &Did, right: &Did) -> [Did; 2] {
    if left.as_str().as_bytes() <= right.as_str().as_bytes() {
        [left.clone(), right.clone()]
    } else {
        [right.clone(), left.clone()]
    }
}

fn normal_basis(receipt: &RequestAcceptanceReceipt) -> Result<(ContactBasis, Hash), AppError> {
    let basis = ContactBasis::Normal {
        sorted_pair_members: sorted_pair(
            receipt.core.holder.subject_id(),
            receipt.core.peer.subject_id(),
        ),
        request_event_ref: receipt.core.request_event_ref.clone(),
        request_acceptance_receipt_digest: canonical_contact_digest(receipt)?,
    };
    let mut stable_semantics = serde_json::to_value(&basis)
        .map_err(|error| AppError::internal(format!("Contact basis serialize: {error}")))?;
    stable_semantics
        .as_object_mut()
        .ok_or_else(|| AppError::internal("Contact basis must serialize as an object"))?
        .insert("domain".to_owned(), json!("ak.contact.basis.v1"));
    let basis_id = canonical_contact_digest(&stable_semantics)?;
    Ok((basis, basis_id))
}

fn sign_request_receipt(
    state: &AppState,
    reservation: &ContactReservation,
    event: &Event,
) -> Result<RequestAcceptanceReceipt, AppError> {
    let request_digest = Hash::new(event.event_digest().map_err(|error| {
        AppError::internal(format!("accepted Contact request digest: {error}"))
    })?)
    .map_err(|error| AppError::internal(format!("accepted request digest invalid: {error}")))?;
    let core = RequestAcceptanceReceiptCore {
        holder: reservation.holder.clone(),
        peer: reservation.branch.peer().clone(),
        slot_version: 1,
        slot_predecessor: None,
        previous_terminal_basis_id: event
            .payload
            .get("previous_terminal_basis_id")
            .and_then(Value::as_str)
            .map(|value| Hash::new(value.to_owned()))
            .transpose()
            .map_err(|error| {
                AppError::invalid_param(format!("previous terminal basis: {error}"))
            })?,
        request_event_ref: event.event_id.clone(),
        request_digest: request_digest.clone(),
        source_checkpoint: contact_hash(
            "ak.contact.request-source-checkpoint.v1",
            &json!({"event_ref": event.event_id, "event_digest": request_digest}),
        )?,
        accepted_at: now(),
        issuer: Did::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?,
    };
    let receipt_digest = contact_hash("ak.contact.request-acceptance-core.v1", &core)?;
    let signature = service_signature(
        state,
        &json!({"core": core, "receipt_digest": receipt_digest}),
    )?;
    Ok(RequestAcceptanceReceipt {
        core,
        receipt_digest,
        signature,
    })
}

fn signed_lineage(
    state: &AppState,
    holder: ContactPeer,
    peer: ContactPeer,
    basis_id: Hash,
    version: u64,
    predecessor_event_ref: Option<EventId>,
    event_ref: EventId,
    scopes: Vec<ContactScope>,
    terminal: bool,
) -> Result<ContactLineage, AppError> {
    let unsigned = json!({
        "basis_id": basis_id,
        "issuer": holder,
        "peer": peer,
        "version": version,
        "predecessor_event_ref": predecessor_event_ref,
        "event_ref": event_ref,
        "granted_to_peer_scopes": scopes,
        "terminal": terminal.then_some(true),
    });
    Ok(ContactLineage {
        basis_id,
        issuer: holder,
        peer,
        version,
        predecessor_event_ref,
        event_ref,
        granted_to_peer_scopes: scopes,
        terminal: terminal.then_some(true),
        signature: service_signature(state, &unsigned)?,
    })
}

fn signed_current_proof(
    state: &AppState,
    basis_id: Hash,
    event: &Event,
) -> Result<ContactCurrentProof, AppError> {
    let terminal = event.kind == arkret_wire::EventKind::ContactTombstoned;
    let head_digest = Hash::new(
        event
            .event_digest()
            .map_err(|error| AppError::internal(format!("Contact head digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact head digest invalid: {error}")))?;
    let fresh_until = now() + chrono::Duration::minutes(10);
    let unsigned = json!({
        "basis_id": basis_id,
        "issuer": event.actor_id,
        "terminal": terminal,
        "head_event_ref": event.event_id,
        "head_digest": head_digest,
        "accepted_frontier": [event.event_id.clone()],
        "complete_through": event.actor_seq,
        "fresh_until": arkret_canonical::format_timestamp_canonical(fresh_until),
    });
    Ok(ContactCurrentProof {
        basis_id,
        issuer: event.actor_id.clone(),
        terminal,
        head_event_ref: event.event_id.clone(),
        head_digest,
        accepted_frontier: vec![event.event_id.clone()],
        complete_through: event.actor_seq,
        fresh_until,
        signature: service_signature(state, &unsigned)?,
    })
}

async fn commit(
    state: &AppState,
    session: &SessionRecord,
    body: ContactCommitRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    let request_hash = arkret_canonical::canonical_sha256(&body)
        .map_err(|error| AppError::internal(format!("Contact commit digest: {error}")))?;
    if let Some(outcome) = replay::<ContactOperationOutcome>(
        state,
        &session.actor,
        &contact_phase_idempotency_key("commit", &body.idempotency_key),
        &request_hash,
    )
    .await?
    {
        return json_ok(outcome);
    }
    let reservation = reservation_for_commit(state, &session.actor, &body).await?;
    if reservation.holder.subject_id().as_str() != session.actor {
        return Err(AppError::capability_denied(
            "Contact reservation belongs to another holder",
        ));
    }
    match &reservation.branch {
        ContactReservationBranch::Response {
            request_receipt,
            peer,
            ..
        }
        | ContactReservationBranch::Reject {
            request_receipt,
            peer,
        } => {
            let record = state
                .contacts()
                .contact_any(peer.subject_id().as_str(), &session.actor)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::not_found("pending Contact request not found"))?;
            validate_request_acceptance_receipt(
                state,
                &record,
                &reservation.holder,
                request_receipt,
            )
            .await?;
        }
        _ => {}
    }
    crate::routing::events::event_log::submit_initial_event_submission(
        state,
        session,
        arkret_wire::EventInitialSubmission {
            event: body.signed_event.clone(),
            authorization_lease: None,
            cba_proof_bundles: Vec::new(),
            control_proposal_ack: body.control_proposal_ack.clone(),
            membership_compensation_evidence: None,
        },
    )
    .await
    .map_err(|error| {
        AppError::new(ErrorCode::FailedPrecondition, error.message)
            .with_status(error.status)
            .with_wire_code(Box::leak(error.code.into_boxed_str()))
    })?;
    let outcome = project_contact_commit(state, &reservation, &body.signed_event).await?;
    persist_final(
        state,
        &session.actor,
        &contact_phase_idempotency_key("commit", &body.idempotency_key),
        &request_hash,
        &outcome,
    )
    .await?;
    json_ok(outcome)
}

async fn project_contact_commit(
    state: &AppState,
    reservation: &ContactReservation,
    event: &Event,
) -> Result<ContactOperationOutcome, AppError> {
    let holder = reservation.holder.subject_id().as_str().to_owned();
    let peer = reservation.branch.peer().subject_id().as_str().to_owned();
    let contacts = state.contacts();
    let outcome = match &reservation.branch {
        ContactReservationBranch::Request {
            granted_to_peer_scopes,
            ..
        } => {
            if contacts
                .contact_any(&holder, &peer)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .is_some()
                || contacts
                    .contact_any(&peer, &holder)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .is_some()
            {
                return Ok(ContactOperationOutcome::Failed {
                    outcome: ContactFailedOutcome {
                        result_kind: ContactResultKind::Request,
                        operation_id: reservation.operation_id.clone(),
                        reason: ContactOperationRejectReason::ContactBasisConflict,
                    },
                });
            }
            contacts
                .save_contact(ContactRecord {
                    requester: holder.clone(),
                    target: peer.clone(),
                    basis_id: None,
                    version: None,
                    granted_to_target_scopes: contact_scope_strings(granted_to_peer_scopes),
                    granted_to_requester_scopes: Vec::new(),
                    status: "pending".to_owned(),
                    request_event_ref: Some(event.event_id.to_string()),
                    response_event_ref: None,
                    tombstone_event_ref: None,
                    message: event
                        .payload
                        .get("message")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    peer_service_id: None,
                    created_at: event.created_at,
                    updated_at: event.created_at,
                })
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            ContactOperationOutcome::Accepted {
                outcome: ContactAcceptedOutcome::Request {
                    operation_id: reservation.operation_id.clone(),
                    request_acceptance_receipt: sign_request_receipt(state, reservation, event)?,
                },
            }
        }
        ContactReservationBranch::Response {
            request_receipt,
            basis_id,
            granted_to_peer_scopes,
            ..
        } => {
            let Some(mut record) = contacts
                .contact_any(&peer, &holder)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(AppError::not_found("pending Contact request not found"));
            };
            validate_request_acceptance_receipt(
                state,
                &record,
                &reservation.holder,
                request_receipt,
            )
            .await?;
            if record.status != "pending"
                || record.request_event_ref.as_deref()
                    != Some(request_receipt.core.request_event_ref.as_str())
            {
                return Err(AppError::conflict(
                    "Contact request slot is already consumed",
                ));
            }
            record.status = "accepted".to_owned();
            record.basis_id = Some(basis_id.to_string());
            record.version = Some(1);
            record.granted_to_requester_scopes = contact_scope_strings(granted_to_peer_scopes);
            record.response_event_ref = Some(event.event_id.to_string());
            record.updated_at = event.created_at;
            contacts
                .save_contact(record)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let response_digest = Hash::new(event.event_digest().map_err(|error| {
                AppError::internal(format!("Contact response digest: {error}"))
            })?)
            .map_err(|error| AppError::internal(format!("response digest invalid: {error}")))?;
            let no_outgoing_slot_proof = contact_hash(
                "ak.contact.no-outgoing-slot.v1",
                &json!({"holder": holder, "peer": peer, "observed_at": event.created_at}),
            )?;
            let accepted_at = now();
            let issuer = Did::new(holder.clone())
                .map_err(|error| AppError::internal(format!("holder DID invalid: {error}")))?;
            let unsigned_receipt = json!({
                "basis_id": basis_id,
                "request_receipt": request_receipt,
                "response_event_ref": event.event_id,
                "response_digest": response_digest,
                "no_outgoing_slot_proof": no_outgoing_slot_proof,
                "accepted_at": arkret_canonical::format_timestamp_canonical(accepted_at),
                "issuer": issuer,
            });
            let response_receipt = NormalResponseAcceptanceReceipt {
                basis_id: basis_id.clone(),
                request_receipt: request_receipt.clone(),
                response_event_ref: event.event_id.clone(),
                response_digest,
                no_outgoing_slot_proof,
                accepted_at,
                issuer,
                signature: service_signature(state, &unsigned_receipt)?,
            };
            let lineage = signed_lineage(
                state,
                reservation.holder.clone(),
                reservation.branch.peer().clone(),
                basis_id.clone(),
                1,
                None,
                event.event_id.clone(),
                granted_to_peer_scopes.clone(),
                false,
            )?;
            ContactOperationOutcome::Accepted {
                outcome: ContactAcceptedOutcome::Response {
                    operation_id: reservation.operation_id.clone(),
                    normal_response_acceptance_receipt: response_receipt,
                    lineage,
                    current_proof: signed_current_proof(state, basis_id.clone(), event)?,
                },
            }
        }
        ContactReservationBranch::Reject {
            request_receipt, ..
        } => {
            let Some(mut record) = contacts
                .contact_any(&peer, &holder)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(AppError::not_found("pending Contact request not found"));
            };
            validate_request_acceptance_receipt(
                state,
                &record,
                &reservation.holder,
                request_receipt,
            )
            .await?;
            if record.status != "pending" {
                return Err(AppError::conflict(
                    "Contact request slot is already consumed",
                ));
            }
            record.status = "rejected".to_owned();
            record.response_event_ref = Some(event.event_id.to_string());
            record.updated_at = event.created_at;
            contacts
                .save_contact(record)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let reject_digest =
                Hash::new(event.event_digest().map_err(|error| {
                    AppError::internal(format!("Contact reject digest: {error}"))
                })?)
                .map_err(|error| AppError::internal(format!("reject digest invalid: {error}")))?;
            let accepted_at = now();
            let issuer = Did::new(holder)
                .map_err(|error| AppError::internal(format!("holder DID invalid: {error}")))?;
            let unsigned = json!({
                "request_receipt": request_receipt,
                "reject_event_ref": event.event_id,
                "reject_digest": reject_digest,
                "accepted_at": arkret_canonical::format_timestamp_canonical(accepted_at),
                "issuer": issuer,
            });
            ContactOperationOutcome::Accepted {
                outcome: ContactAcceptedOutcome::Reject {
                    operation_id: reservation.operation_id.clone(),
                    reject_acceptance_receipt: RejectAcceptanceReceipt {
                        request_receipt: request_receipt.clone(),
                        reject_event_ref: event.event_id.clone(),
                        reject_digest,
                        accepted_at,
                        issuer,
                        signature: service_signature(state, &unsigned)?,
                    },
                },
            }
        }
        ContactReservationBranch::ScopeUpdate {
            basis_id,
            version,
            predecessor_event_ref,
            granted_to_peer_scopes,
            ..
        } => {
            let Some(mut record) = contact_record_for_lineage(state, &holder, &peer).await? else {
                return Err(AppError::not_found("accepted Contact basis not found"));
            };
            validate_lineage_head(&record, &holder, basis_id, *version, predecessor_event_ref)?;
            set_holder_scopes(
                &mut record,
                &holder,
                contact_scope_strings(granted_to_peer_scopes),
            );
            record.version = Some(*version);
            record.updated_at = event.created_at;
            // The accepted basis remains accepted even when its directional
            // intersection is empty. Authorization reads the exact full-set
            // heads, so an empty intersection grants nothing.
            record.status = "accepted".to_owned();
            set_holder_head(&mut record, &holder, event.event_id.to_string());
            contacts
                .save_contact(record)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let lineage = signed_lineage(
                state,
                reservation.holder.clone(),
                reservation.branch.peer().clone(),
                basis_id.clone(),
                *version,
                Some(predecessor_event_ref.clone()),
                event.event_id.clone(),
                granted_to_peer_scopes.clone(),
                false,
            )?;
            ContactOperationOutcome::Accepted {
                outcome: ContactAcceptedOutcome::ScopeUpdate {
                    operation_id: reservation.operation_id.clone(),
                    lineage,
                    current_proof: signed_current_proof(state, basis_id.clone(), event)?,
                },
            }
        }
        ContactReservationBranch::Tombstone {
            basis_id,
            version,
            predecessor_event_ref,
            ..
        } => {
            let Some(mut record) = contact_record_for_lineage(state, &holder, &peer).await? else {
                return Err(AppError::not_found("accepted Contact basis not found"));
            };
            validate_lineage_head(&record, &holder, basis_id, *version, predecessor_event_ref)?;
            record.version = Some(*version);
            record.status = "tombstoned".to_owned();
            record.tombstone_event_ref = Some(event.event_id.to_string());
            record.updated_at = event.created_at;
            contacts
                .save_contact(record)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let lineage = signed_lineage(
                state,
                reservation.holder.clone(),
                reservation.branch.peer().clone(),
                basis_id.clone(),
                *version,
                Some(predecessor_event_ref.clone()),
                event.event_id.clone(),
                Vec::new(),
                true,
            )?;
            ContactOperationOutcome::Accepted {
                outcome: ContactAcceptedOutcome::Tombstone {
                    operation_id: reservation.operation_id.clone(),
                    lineage,
                    current_proof: signed_current_proof(state, basis_id.clone(), event)?,
                },
            }
        }
    };
    Ok(outcome)
}

async fn contact_record_for_lineage(
    state: &AppState,
    holder: &str,
    peer: &str,
) -> Result<Option<ContactRecord>, AppError> {
    state
        .contacts()
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))
}

fn holder_head<'a>(record: &'a ContactRecord, holder: &str) -> Option<&'a str> {
    if record.requester == holder {
        record.request_event_ref.as_deref()
    } else {
        record.response_event_ref.as_deref()
    }
}

fn set_holder_head(record: &mut ContactRecord, holder: &str, event_ref: String) {
    if record.requester == holder {
        record.request_event_ref = Some(event_ref);
    } else {
        record.response_event_ref = Some(event_ref);
    }
}

fn set_holder_scopes(record: &mut ContactRecord, holder: &str, scopes: Vec<String>) {
    if record.requester == holder {
        record.granted_to_target_scopes = scopes;
    } else {
        record.granted_to_requester_scopes = scopes;
    }
}

fn validate_lineage_head(
    record: &ContactRecord,
    holder: &str,
    basis_id: &Hash,
    version: u64,
    predecessor: &EventId,
) -> Result<(), AppError> {
    if record.basis_id.as_deref() != Some(basis_id.as_str())
        || record.version.and_then(|current| current.checked_add(1)) != Some(version)
        || holder_head(record, holder) != Some(predecessor.as_str())
    {
        return Err(AppError::conflict("Contact lineage CAS mismatch"));
    }
    Ok(())
}

pub(super) async fn request(
    state: &AppState,
    session: &SessionRecord,
    body: ContactOperationRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactOperationRequestBody::Prepare(body) => {
            let prior = state
                .contacts()
                .contact_any(&session.actor, body.peer.subject_id().as_str())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let local_terminal_basis = prior.as_ref().and_then(|record| {
                (record.status == "tombstoned")
                    .then_some(record.basis_id.as_deref())
                    .flatten()
            });
            if local_terminal_basis != body.previous_terminal_basis_id.as_ref().map(Hash::as_str) {
                return Err(AppError::conflict(
                    "recontact request does not link the immediate local terminal Contact basis",
                )
                .with_wire_code("contact_lineage_conflict"));
            }
            let introduction_evidence_digest = contact_hash(
                "ak.contact.introduction-evidence.v1",
                &body.introduction_evidence,
            )?;
            let payload = ContactRequestedPayload {
                peer: body.peer.clone(),
                granted_to_peer_scopes: body.granted_to_peer_scopes.clone(),
                introduction_evidence_digest,
                previous_terminal_basis_id: body.previous_terminal_basis_id.clone(),
                message: normalize_contact_message(body.message.as_deref())?,
            };
            prepare::<arkret_wire::event_spec::ContactRequested>(
                state,
                session,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::Request {
                    peer: body.peer,
                    granted_to_peer_scopes: body.granted_to_peer_scopes,
                    previous_terminal_basis_id: body.previous_terminal_basis_id,
                },
                payload,
            )
            .await
        }
        ContactOperationRequestBody::Commit(body) => commit(state, session, body).await,
    }
}

pub(super) async fn respond(
    state: &AppState,
    session: &SessionRecord,
    body: ContactAcceptRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactAcceptRequestBody::Prepare(body) => {
            let holder = holder_peer(state, &session.actor).await?;
            let peer = body.request_receipt.core.holder.clone();
            let record = state
                .contacts()
                .contact_any(peer.subject_id().as_str(), &session.actor)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::not_found("pending Contact request not found"))?;
            validate_request_acceptance_receipt(state, &record, &holder, &body.request_receipt)
                .await?;
            let (_, basis_id) = normal_basis(&body.request_receipt)?;
            if state
                .contacts()
                .contact_any(&session.actor, peer.subject_id().as_str())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .is_some()
            {
                return Err(AppError::conflict(
                    "normal Contact response requires no outgoing request slot",
                ));
            }
            let payload = ContactAcceptedPayload {
                peer: peer.clone(),
                basis_id: basis_id.clone(),
                version: 1,
                request_event_ref: body.request_receipt.core.request_event_ref.clone(),
                request_acceptance_receipt_digest: canonical_contact_digest(&body.request_receipt)?,
                previous_terminal_basis_id: body
                    .request_receipt
                    .core
                    .previous_terminal_basis_id
                    .clone(),
                granted_to_peer_scopes: body.granted_to_peer_scopes.clone(),
            };
            prepare::<arkret_wire::event_spec::ContactAccepted>(
                state,
                session,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::Response {
                    request_receipt: body.request_receipt,
                    peer,
                    basis_id,
                    granted_to_peer_scopes: body.granted_to_peer_scopes,
                },
                payload,
            )
            .await
        }
        ContactAcceptRequestBody::Commit(body) => commit(state, session, body).await,
    }
}

pub(super) async fn reject(
    state: &AppState,
    session: &SessionRecord,
    body: ContactRejectRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactRejectRequestBody::Prepare(body) => {
            let holder = holder_peer(state, &session.actor).await?;
            let peer = body.request_receipt.core.holder.clone();
            let record = state
                .contacts()
                .contact_any(peer.subject_id().as_str(), &session.actor)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::not_found("pending Contact request not found"))?;
            validate_request_acceptance_receipt(state, &record, &holder, &body.request_receipt)
                .await?;
            let payload = ContactRejectedPayload {
                peer: peer.clone(),
                request_event_ref: body.request_receipt.core.request_event_ref.clone(),
                request_acceptance_receipt_digest: canonical_contact_digest(&body.request_receipt)?,
                reason: None,
            };
            prepare::<arkret_wire::event_spec::ContactRejected>(
                state,
                session,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::Reject {
                    request_receipt: body.request_receipt,
                    peer,
                },
                payload,
            )
            .await
        }
        ContactRejectRequestBody::Commit(body) => commit(state, session, body).await,
    }
}

pub(super) async fn scope_update(
    state: &AppState,
    session: &SessionRecord,
    body: ContactScopeUpdateRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactScopeUpdateRequestBody::Prepare(body) => {
            let payload = ContactScopeUpdatePayload {
                schema: ContactScopeUpdateSchema::V1,
                peer: body.peer.clone(),
                basis_id: body.basis_id.clone(),
                version: body.version,
                predecessor_event_ref: body.predecessor_event_ref.clone(),
                granted_to_peer_scopes: body.granted_to_peer_scopes.clone(),
            };
            prepare::<arkret_wire::event_spec::ContactScopeUpdate>(
                state,
                session,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::ScopeUpdate {
                    peer: body.peer,
                    basis_id: body.basis_id,
                    version: body.version,
                    predecessor_event_ref: body.predecessor_event_ref,
                    granted_to_peer_scopes: body.granted_to_peer_scopes,
                },
                payload,
            )
            .await
        }
        ContactScopeUpdateRequestBody::Commit(body) => commit(state, session, body).await,
    }
}

pub(super) async fn tombstone(
    state: &AppState,
    session: &SessionRecord,
    body: ContactTombstoneRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactTombstoneRequestBody::Prepare(body) => {
            let payload = ContactTombstonedPayload {
                peer: body.peer.clone(),
                basis_id: body.basis_id.clone(),
                version: body.version,
                predecessor_event_ref: body.predecessor_event_ref.clone(),
                reason: None,
            };
            prepare::<arkret_wire::event_spec::ContactTombstoned>(
                state,
                session,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::Tombstone {
                    peer: body.peer,
                    basis_id: body.basis_id,
                    version: body.version,
                    predecessor_event_ref: body.predecessor_event_ref,
                },
                payload,
            )
            .await
        }
        ContactTombstoneRequestBody::Commit(body) => commit(state, session, body).await,
    }
}

fn normalize_contact_message(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let normalized = arkret_canonical::to_nfc(trimmed);
    if normalized.chars().count() > 2_000 {
        return Err(AppError::invalid_param(
            "Contact request message must be at most 2000 characters",
        ));
    }
    Ok(Some(normalized))
}
