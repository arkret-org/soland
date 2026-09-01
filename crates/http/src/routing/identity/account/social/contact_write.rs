use arkret_models_collaboration::contact_operations::{
    ContactAcceptedOutcome, ContactCommitRequestBody, ContactContinuityEvidence,
    ContactCurrentProof, ContactFailedOutcome, ContactLineage, ContactOperationRejectReason,
    ContactPreparedOutcome, ContactResultKind, ContactRound, ContactRoundEvidenceBundle,
    ContactScope, ContactScopeUpdatePayload, ContactScopeUpdateSchema,
    NormalResponseAcceptanceReceipt, OutgoingRequestState, OutgoingSlotAbsenceTranscript,
    PeerContactSubmitRequestBody, RejectAcceptanceReceipt, RequestAcceptanceReceipt,
    RequestAcceptanceReceiptCore,
};
use arkret_models_collaboration::events_payloads::contact::{
    ContactAcceptedPayload, ContactRejectedPayload, ContactRequestedPayload,
    ContactTombstonedPayload,
};
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
use arkret_models_collaboration::prepared_event_draft::PreparedEventDraft;
use arkret_models_identity::ServiceResolutionCarrier;
use arkret_wire::{
    AuthoredEvent, Base64UrlString, DidUrl, Event, IdempotencyKey, ProtocolOperationId,
    ProtocolSignature, ReservationHandle,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as _};
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
        previous_terminal_contact_round_id: Option<Hash>,
        continuity_evidence: Option<ContactContinuityEvidence>,
        introduction_evidence: Box<ContactIntroductionEvidence>,
    },
    Response {
        request_receipt: RequestAcceptanceReceipt,
        peer: ContactPeer,
        contact_round_id: Hash,
        granted_to_peer_scopes: Vec<ContactScope>,
    },
    Reject {
        request_receipt: RequestAcceptanceReceipt,
        peer: ContactPeer,
    },
    ScopeUpdate {
        peer: ContactPeer,
        contact_round_id: Hash,
        version: u64,
        predecessor_event_ref: EventId,
        granted_to_peer_scopes: Vec<ContactScope>,
    },
    Tombstone {
        peer: ContactPeer,
        contact_round_id: Hash,
        version: u64,
        predecessor_event_ref: EventId,
        block_peer: bool,
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
    event_draft: PreparedEventDraft,
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
    let (controller, fragment) = signature
        .verification_method
        .as_str()
        .rsplit_once('#')
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                format!("{evidence_field}.signature.verification_method is not a DID URL"),
            )
        })?;
    let controller = arkret_wire::Did::new(controller.to_owned()).map_err(|_| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            format!("{evidence_field}.signature.verification_method controller is invalid"),
        )
    })?;
    let controller_core = arkret_wire::project_did_to_core_id(&controller).map_err(|_| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            format!("{evidence_field}.signature.verification_method controller is invalid"),
        )
    })?;
    if controller_core.as_str() != expected_service_id || fragment != "federation-fanout-key" {
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
            .federation_peer_verification_method_key(signature.verification_method.as_str())
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
    let recomputed = contact_hash(
        arkret_wire::DomainSeparationId::CONTACT_REQUEST_ACCEPTANCE_CORE_V1,
        &receipt.core,
    )?;
    if recomputed != receipt.receipt_digest {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            format!("{evidence_field}.receipt_digest does not match its canonical core"),
        ));
    }
    verify_contact_service_signature(
        state,
        receipt.core.issuer_id.as_str(),
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
            crate::routing::federation::federation_service_signature_key_id(
                state.service_did().as_str(),
            ),
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
        AppError::param_invalid(format!("invalid Contact request receipt: {error}"))
    })?;
    if &receipt.core.peer != responder {
        return Err(AppError::capability_denied(
            "Contact request receipt does not name the responder",
        ));
    }
    if record.status != "pending"
        || record.requester_id != receipt.core.holder.contact_actor_id()
        || record.target_id != receipt.core.peer.contact_actor_id()
        || record.request_event_ref.as_ref() != Some(&receipt.core.request_event_ref)
    {
        return Err(AppError::conflict(
            "Contact request receipt differs from the durable pending slot",
        ));
    }

    validate_request_receipt_cryptography(state, receipt, "request_receipt")?;

    let expected_issuer = record
        .peer_host_id
        .as_ref()
        .map(arkret_wire::DidCoreId::as_str)
        .unwrap_or_else(|| state.service_id());
    if receipt.core.issuer_id.as_str() != expected_issuer {
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
                "request_receipt.core.request_event_ref cannot be verified: the durable accepted source Event is unavailable",
            )
        })?;
    let request_event = serde_json::from_value::<Event>(stored.envelope)
        .map_err(|error| AppError::internal(format!("stored Contact request Event: {error}")))?;
    let request_digest = Hash::new(
        request_event
            .event_digest_with_digest_suite(stored.digest_suite)
            .map_err(|error| {
                AppError::internal(format!("stored Contact request Event digest: {error}"))
            })?,
    )
    .map_err(|error| AppError::internal(format!("stored Contact request digest: {error}")))?;
    let requested_payload = serde_json::from_value::<ContactRequestedPayload>(
        serde_json::to_value(&request_event.payload)
            .map_err(|error| AppError::internal(format!("Contact request payload: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("stored Contact request payload: {error}")))?;
    let expected_checkpoint = contact_hash(
        arkret_wire::DomainSeparationId::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,
        &json!({
            "event_ref": request_event.event_id,
            "event_digest": request_digest,
        }),
    )?;
    if request_event.kind != arkret_wire::EventKind::ContactRequested
        || request_event.event_id != receipt.core.request_event_ref
        || request_event.actor_id != receipt.core.holder.contact_actor_id()
        || requested_payload.peer != receipt.core.peer
        || request_digest != receipt.core.request_digest()
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

async fn holder_peer(state: &AppState, session: &SessionRecord) -> Result<ContactPeer, AppError> {
    let holder_id = arkret_identifiers::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("holder DID invalid: {error}")))?;
    if let Some(_agent) = state
        .agent_pairings()
        .agent(holder_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("holder Agent lookup: {error}")))?
    {
        let controller_account_pk = session
            .account_pk
            .ok_or_else(|| AppError::unauthenticated("Agent session has no controller account"))?;
        let controller_account = state
            .identities()
            .account_by_id(controller_account_pk)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::unauthenticated("controller account no longer exists"))?;
        let station_id = arkret_wire::DidCoreId::new(session.audience.clone())
            .map_err(|error| AppError::internal(format!("session audience invalid: {error}")))?;
        return Ok(ContactPeer::Agent {
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                holder_id, station_id,
            )),
            controller_account_id: controller_account.account_id,
        });
    }
    let account_pk = session
        .account_pk
        .ok_or_else(|| AppError::unauthenticated("session has no account binding"))?;
    let account = state
        .identities()
        .account_by_id(account_pk)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::unauthenticated("session account no longer exists"))?;
    Ok(ContactPeer::Human {
        account_id: account.account_id,
    })
}

fn validate_distinct_peer(holder: &ContactPeer, peer: &ContactPeer) -> Result<(), AppError> {
    if holder.contact_actor_id() == peer.contact_actor_id() {
        return Err(AppError::param_invalid(
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
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<AuthoredEvent, AppError> {
    arkret_event_draft::TypedEventDraft::<K>::new(
        arkret_wire::ScopeRef::Realm { realm_id },
        holder.contact_actor_id(),
        payload,
    )
    .map(|draft| draft.with_prev_refs(prev_refs).with_seal_basis(seal_basis))
    .and_then(|draft| draft.author_with_digest_suite(actor_seq, hlc, created_at, digest_suite))
    .map_err(|error| AppError::internal(format!("Contact typed Event draft invalid: {error}")))
}

fn contact_event_draft(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<PreparedEventDraft, AppError> {
    let digest_payload = event
        .digest_payload()
        .map_err(|error| AppError::internal(format!("Contact Event draft: {error}")))?;
    let unsigned_bytes = arkret_canonical::canonical_json_bytes(&digest_payload)
        .map_err(|error| AppError::internal(format!("Contact Event draft bytes: {error}")))?;
    Ok(PreparedEventDraft {
        unsigned_event_bytes: Base64UrlString::new(URL_SAFE_NO_PAD.encode(unsigned_bytes))
            .map_err(|error| AppError::internal(format!("Contact draft encode: {error}")))?,
        event_digest: Hash::new(
            event
                .event_digest_with_digest_suite(digest_suite)
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
    let principal_id = DidCoreId::new(principal.to_owned())
        .map_err(|error| AppError::internal(format!("Contact principal id invalid: {error}")))?;
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
                authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    principal_id.clone(),
                    state.service_core_id(),
                )),
                operation_id: "ak.self.contact.command.prepare".to_owned(),
                idempotency_key: key,
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
    operation_id: &str,
    key: &str,
    request_hash: &str,
) -> Result<Option<T>, AppError> {
    let principal_id = DidCoreId::new(principal.to_owned())
        .map_err(|error| AppError::internal(format!("Contact principal id invalid: {error}")))?;
    let Some(record) = state
        .jobs()
        .scoped_idempotency_record(
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id,
                state.service_core_id(),
            )),
            operation_id,
            key,
        )
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
    operation_id: &str,
    key: &str,
    request_hash: &str,
    outcome: &ContactOperationOutcome,
) -> Result<(), AppError> {
    let created_at = now();
    let principal_id = DidCoreId::new(principal.to_owned())
        .map_err(|error| AppError::internal(format!("Contact principal id invalid: {error}")))?;
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id,
                state.service_core_id(),
            )),
            operation_id: operation_id.to_owned(),
            idempotency_key: key.to_owned(),
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
    let holder = holder_peer(state, session).await?;
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
        "ak.self.contact.command.prepare",
        &contact_phase_idempotency_key("prepare", &idempotency_key),
        &request_hash,
    )
    .await?
    {
        return json_ok(outcome);
    }
    // A fresh prepare must reject a stale cursor before persisting a reservation.
    // Exact idempotent replays above retain their original outcome; commit also
    // rechecks the lineage to close the prepare/commit race.
    match &branch {
        ContactReservationBranch::ScopeUpdate {
            contact_round_id,
            version,
            predecessor_event_ref,
            ..
        }
        | ContactReservationBranch::Tombstone {
            contact_round_id,
            version,
            predecessor_event_ref,
            ..
        } => {
            let holder_actor = holder.contact_actor_id();
            let peer_actor = branch.peer().contact_actor_id();
            let record = contact_record_for_lineage(state, &holder_actor, &peer_actor)
                .await?
                .ok_or_else(|| {
                    AppError::conflict("Contact lineage is no longer current")
                        .with_wire_code("contact_lineage_conflict")
                })?;
            validate_lineage_head(
                &record,
                &holder_actor,
                contact_round_id,
                *version,
                predecessor_event_ref,
            )?;
        }
        _ => {}
    }
    // The authenticated device (or Agent allocation) selects one exact
    // `(principal_id, station_id)` pair and its local lifetime PCR
    // lineage. Never resolve account state from the principal core alone.
    let realm_id = contact_authority_realm(state, session, &holder).await?;
    let frontier = crate::routing::events::event_log::load_realm_actor_frontier(
        state,
        realm_id.clone(),
        holder.contact_actor_id(),
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
    let digest_suite = state.projections().realm_digest_suite(realm_id.as_str());
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
        digest_suite,
    )?;
    let reservation = ContactReservation {
        operation_id,
        idempotency_key: idempotency_key.clone(),
        reservation_handle: ReservationHandle::new(crate::ids::generate("reservation"))
            .map_err(AppError::internal)?,
        holder,
        branch,
        event_draft: contact_event_draft(&event, digest_suite)?,
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

fn device_authorization_matches_contact_account(
    authorize_actor: &str,
    account_id: &arkret_wire::AccountId,
) -> bool {
    arkret_wire::ActorId::account(account_id.clone())
        .canonical_key()
        .is_ok_and(|expected| authorize_actor == expected)
}

async fn contact_authority_realm(
    state: &AppState,
    session: &SessionRecord,
    holder: &ContactPeer,
) -> Result<RealmId, AppError> {
    let realm_id = match holder {
        ContactPeer::Human { account_id } => {
            if account_id.station_id.as_str() != state.service_id() {
                return Err(AppError::new(
                    ErrorCode::FailedPrecondition,
                    "Contact holder account does not belong to this Station",
                ));
            }
            let device = state
                .identities()
                .find_device(soland_services::identity::FindDeviceQuery {
                    actor_id: account_id.principal_id.to_string(),
                    device_id: session.device_id.clone(),
                })
                .await
                .map_err(|error| {
                    AppError::internal(format!("Contact holder device lookup: {error}"))
                })?
                .ok_or_else(|| {
                    AppError::new(
                        ErrorCode::FailedPrecondition,
                        "Contact holder device is unavailable",
                    )
                })?;
            if device.revoked_at.is_some() || device.verification_state != "verified" {
                return Err(AppError::new(
                    ErrorCode::FailedPrecondition,
                    "Contact holder device is not active",
                ));
            }
            let payload = serde_json::from_value::<
                crate::routing::identity::device_signing::ProjectedDevicePayload,
            >(device.payload)
            .map_err(|error| {
                AppError::internal(format!("Contact holder device evidence: {error}"))
            })?;
            let authorize_event_id = payload.device_authorize_event_id.ok_or_else(|| {
                AppError::new(
                    ErrorCode::FailedPrecondition,
                    "Contact holder device has no accepted authorization Event",
                )
            })?;
            let authorize_event = state
                .event_queries()
                .canonical_event(authorize_event_id.as_str())
                .await
                .map_err(|error| {
                    AppError::internal(format!("Contact device authorization lookup: {error}"))
                })?
                .ok_or_else(|| {
                    AppError::new(
                        ErrorCode::FailedPrecondition,
                        "Contact holder device authorization Event is unavailable",
                    )
                })?;
            if !device_authorization_matches_contact_account(&authorize_event.actor_id, account_id)
                || authorize_event.kind != arkret_wire::event_kind_str::DEVICE_AUTHORIZE
            {
                return Err(AppError::new(
                    ErrorCode::FailedPrecondition,
                    "Contact holder device authorization is invalid",
                ));
            }
            authorize_event.realm_id.ok_or_else(|| {
                AppError::new(
                    ErrorCode::FailedPrecondition,
                    "Contact holder device authorization has no PCR realm",
                )
            })?
        }
        ContactPeer::Agent { actor_id, .. } => {
            state
                .agent_pairings()
                .agent(actor_id.signing_principal_id().as_str())
                .await
                .map_err(|error| {
                    AppError::internal(format!("Contact holder Agent lookup: {error}"))
                })?
                .ok_or_else(|| {
                    AppError::new(
                        ErrorCode::FailedPrecondition,
                        "Contact holder Agent allocation is unavailable",
                    )
                })?
                .principal_control_realm_id
        }
    };
    let realm_id = RealmId::new(realm_id).map_err(|error| {
        AppError::internal(format!("Contact authority PCR id is invalid: {error}"))
    })?;
    let authority = state
        .persistence()
        .principal_resolution_for_realm(&realm_id)
        .await
        .map_err(|error| AppError::internal(format!("Contact authority lookup: {error}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "Contact account authority pair is unavailable",
            )
        })?;
    let holder_account_id = match holder {
        ContactPeer::Human { account_id } => account_id,
        ContactPeer::Agent {
            controller_account_id,
            ..
        } => controller_account_id,
    };
    if authority.account_id != *holder_account_id
        || authority.pcr_realm_id != realm_id
        || authority.account_id.station_id.as_str() != state.service_id()
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Contact account authority pair does not match the authenticated holder",
        ));
    }
    Ok(realm_id)
}

fn validate_signed_event(event: &Event, draft: &PreparedEventDraft) -> Result<(), AppError> {
    let actual = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|error| AppError::param_invalid(format!("signed Contact Event: {error}")))?,
    )
    .map_err(|error| AppError::param_invalid(format!("signed Contact Event bytes: {error}")))?;
    let expected = URL_SAFE_NO_PAD
        .decode(draft.unsigned_event_bytes.as_str())
        .map_err(|_| AppError::internal("stored Contact draft bytes are invalid"))?;
    let digest_suite = draft
        .event_digest
        .digest_suite()
        .map_err(|error| AppError::internal(format!("stored Contact digest suite: {error}")))?;
    let digest = Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| AppError::param_invalid(format!("signed Contact Event: {error}")))?,
    )
    .map_err(|error| AppError::param_invalid(format!("signed Contact digest: {error}")))?;
    if actual != expected
        || digest != draft.event_digest
        || event.proofs.is_empty()
        || event
            .proofs
            .iter()
            .filter_map(arkret_wire::EventProof::as_producer)
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
    let principal_id = DidCoreId::new(principal.to_owned())
        .map_err(|error| AppError::internal(format!("Contact principal id invalid: {error}")))?;
    let record = state
        .jobs()
        .scoped_idempotency_record(
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id,
                state.service_core_id(),
            )),
            "ak.self.contact.command.prepare",
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

fn sorted_pair(
    left: &arkret_wire::ActorId,
    right: &arkret_wire::ActorId,
) -> [arkret_wire::ActorId; 2] {
    if left <= right {
        [left.clone(), right.clone()]
    } else {
        [right.clone(), left.clone()]
    }
}

fn normal_basis(receipt: &RequestAcceptanceReceipt) -> Result<(ContactRound, Hash), AppError> {
    let contact_round = ContactRound::Normal {
        sorted_pair_member_ids: sorted_pair(
            &receipt.core.holder.contact_actor_id(),
            &receipt.core.peer.contact_actor_id(),
        ),
        request_event_ref: receipt.core.request_event_ref.clone(),
        request_acceptance_receipt_digest: canonical_contact_digest(receipt)?,
    };
    let contact_round_id = contact_hash("ak.contact.round.v1", &contact_round)?;
    Ok((contact_round, contact_round_id))
}

fn next_request_slot_coordinates(
    states: &[soland_services::identity::ContactRequestSlotState],
    owner_id: &arkret_wire::ActorId,
    peer_id: &arkret_wire::ActorId,
) -> Result<(u64, Option<Hash>), AppError> {
    let mut matches = states
        .iter()
        .filter(|state| &state.owner_id == owner_id && &state.peer_id == peer_id);
    let Some(current) = matches.next() else {
        return Ok((1, None));
    };
    if matches.next().is_some() || current.accepted_sequence == 0 {
        return Err(AppError::internal(
            "durable Contact request-slot state is invalid",
        ));
    }
    let next_sequence = current.accepted_sequence.checked_add(1).ok_or_else(|| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "Contact request-slot sequence is exhausted",
        )
    })?;
    Ok((next_sequence, Some(current.head_digest.clone())))
}

fn accept_request_slot_transition(
    states: &mut Vec<soland_services::identity::ContactRequestSlotState>,
    owner_id: &arkret_wire::ActorId,
    peer_id: &arkret_wire::ActorId,
    accepted_sequence: u64,
    slot_predecessor: Option<&Hash>,
    head_digest: Hash,
) -> Result<(), AppError> {
    let expected = next_request_slot_coordinates(states, owner_id, peer_id)?;
    if expected.0 != accepted_sequence || expected.1.as_ref() != slot_predecessor {
        return Err(AppError::internal(
            "Contact request-slot transition does not consume its durable predecessor",
        ));
    }
    if let Some(current) = states
        .iter_mut()
        .find(|state| &state.owner_id == owner_id && &state.peer_id == peer_id)
    {
        current.accepted_sequence = accepted_sequence;
        current.head_digest = head_digest;
    } else {
        states.push(soland_services::identity::ContactRequestSlotState {
            owner_id: owner_id.clone(),
            peer_id: peer_id.clone(),
            accepted_sequence,
            head_digest,
        });
        states.sort_by(|left, right| {
            (&left.owner_id, &left.peer_id).cmp(&(&right.owner_id, &right.peer_id))
        });
    }
    Ok(())
}

fn sign_request_receipt(
    state: &AppState,
    reservation: &ContactReservation,
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
    slot_version: u64,
    slot_predecessor: Option<Hash>,
) -> Result<RequestAcceptanceReceipt, AppError> {
    let request_digest = Hash::new(event.event_digest_with_digest_suite(digest_suite).map_err(
        |error| AppError::internal(format!("accepted Contact request digest: {error}")),
    )?)
    .map_err(|error| AppError::internal(format!("accepted request digest invalid: {error}")))?;
    let core = RequestAcceptanceReceiptCore {
        holder: reservation.holder.clone(),
        peer: reservation.branch.peer().clone(),
        slot_version,
        slot_predecessor,
        previous_terminal_contact_round_id: event
            .payload
            .get("previous_terminal_contact_round_id")
            .and_then(Value::as_str)
            .map(|value| Hash::new(value.to_owned()))
            .transpose()
            .map_err(|error| {
                AppError::param_invalid(format!("previous terminal contact_round: {error}"))
            })?,
        request_event_ref: event.event_id.clone(),
        source_checkpoint: contact_hash(
            arkret_wire::DomainSeparationId::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,
            &json!({"event_ref": event.event_id, "event_digest": request_digest}),
        )?,
        accepted_at: now(),
        issuer_id: arkret_identifiers::DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?,
    };
    let receipt_digest = contact_hash(
        arkret_wire::DomainSeparationId::CONTACT_REQUEST_ACCEPTANCE_CORE_V1,
        &core,
    )?;
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
    contact_round_id: Hash,
    version: u64,
    predecessor_event_ref: Option<EventId>,
    event_ref: EventId,
    scopes: Vec<ContactScope>,
    terminal: bool,
) -> Result<ContactLineage, AppError> {
    let unsigned = json!({
        "contact_round_id": contact_round_id,
        "issuer": holder,
        "peer": peer,
        "version": version,
        "predecessor_event_ref": predecessor_event_ref,
        "event_ref": event_ref,
        "granted_to_peer_scopes": scopes,
        "terminal": terminal.then_some(true),
    });
    Ok(ContactLineage {
        contact_round_id,
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
    contact_round_id: Hash,
    peer: ContactPeer,
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<ContactCurrentProof, AppError> {
    let _issuer_did = event
        .proofs
        .iter()
        .find_map(|proof| {
            let proof = proof.as_producer()?;
            let (controller, _) = proof.verification_method.rsplit_once('#')?;
            let did = arkret_wire::Did::new(controller.to_owned()).ok()?;
            (arkret_wire::project_did_to_core_id(&did).ok()
                == Some(event.actor_id.signing_principal_id().clone()))
            .then_some(did)
        })
        .ok_or_else(|| {
            AppError::param_invalid("Contact Event has no actor-bound proof controller")
        })?;
    let issuer = state.service_core_id();
    let terminal = event.kind == arkret_wire::EventKind::ContactTombstone;
    let head_digest = Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| AppError::internal(format!("Contact head digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact head digest invalid: {error}")))?;
    if head_digest != event.event_id.event_digest() {
        return Err(AppError::param_invalid(
            "Contact head EventId does not match its canonical digest",
        ));
    }
    let fresh_until = now() + chrono::Duration::minutes(10);
    let unsigned = json!({
        "contact_round_id": contact_round_id,
        "issuer_id": issuer,
        "peer": peer,
        "terminal": terminal,
        "head_event_ref": event.event_id,
        "accepted_frontier": [event.event_id.clone()],
        "complete_through": event.actor_seq,
        "fresh_until": arkret_canonical::format_timestamp_canonical(fresh_until),
    });
    Ok(ContactCurrentProof {
        contact_round_id,
        issuer_id: issuer,
        peer,
        terminal,
        head_event_ref: event.event_id.clone(),
        accepted_frontier: vec![event.event_id.clone()],
        complete_through: event.actor_seq,
        fresh_until,
        signature: service_signature(state, &unsigned)?,
    })
}

async fn local_requester_current_proof(
    state: &AppState,
    contact_round_id: &Hash,
    request_receipt: &RequestAcceptanceReceipt,
) -> Result<Option<ContactCurrentProof>, AppError> {
    let Some(record) = state
        .event_queries()
        .canonical_event(request_receipt.core.request_event_ref.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Contact request Event lookup: {error}")))?
    else {
        return Ok(None);
    };
    let request_event = serde_json::from_value::<Event>(record.envelope).map_err(|error| {
        AppError::internal(format!(
            "accepted Contact request Event is invalid: {error}"
        ))
    })?;
    let request_digest_suite = request_receipt
        .core
        .request_digest()
        .digest_suite()
        .map_err(|error| AppError::internal(format!("Contact request digest suite: {error}")))?;
    if request_event.kind != arkret_wire::EventKind::ContactRequested
        || request_event.actor_id != request_receipt.core.holder.contact_actor_id()
        || Hash::new(
            request_event
                .event_digest_with_digest_suite(request_digest_suite)
                .map_err(|error| {
                    AppError::internal(format!("accepted Contact request digest: {error}"))
                })?,
        )
        .map_err(|error| AppError::internal(format!("Contact request digest invalid: {error}")))?
            != request_receipt.core.request_digest()
    {
        return Err(AppError::internal(
            "accepted Contact request does not match its signed receipt",
        ));
    }
    let Some(resolution) = state
        .persistence()
        .principal_resolution_for_realm(&request_event.realm_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("Contact requester_id authority lookup: {error}"))
        })?
    else {
        return Ok(None);
    };
    if resolution.account_id.principal_id != *request_event.actor_id.signing_principal_id()
        || resolution.pcr_realm_id != request_event.realm_id
        || resolution.account_id.station_id.as_str() != state.service_id()
    {
        return Ok(None);
    }
    signed_current_proof(
        state,
        contact_round_id.clone(),
        request_receipt.core.peer.clone(),
        &request_event,
        request_digest_suite,
    )
    .map(Some)
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
        "ak.self.contact.command.commit",
        &contact_phase_idempotency_key("commit", &body.idempotency_key),
        &request_hash,
    )
    .await?
    {
        return json_ok(outcome);
    }
    let reservation = reservation_for_commit(state, &session.actor, &body).await?;
    let authenticated_holder = holder_peer(state, session).await?;
    if reservation.holder != authenticated_holder {
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
                .contact_any(
                    &peer.contact_actor_id(),
                    &reservation.holder.contact_actor_id(),
                )
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
    let (outcome, contact_projection) =
        plan_contact_commit(state, &reservation, &body.signed_event).await?;
    if matches!(outcome, ContactOperationOutcome::Failed { .. }) {
        persist_final(
            state,
            &session.actor,
            "ak.self.contact.command.commit",
            &contact_phase_idempotency_key("commit", &body.idempotency_key),
            &request_hash,
            &outcome,
        )
        .await?;
        return json_ok(outcome);
    }
    let delivery = prepare_contact_federation_delivery(
        state,
        &reservation,
        &body.signed_event,
        &outcome,
        contact_projection.as_ref().map(|commit| &commit.record),
    )
    .await?;
    let idempotency_created_at = now();
    let contact_idempotency = soland_services::events::IdempotentResponse {
        authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(session.actor.clone())
                .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?,
            state.service_core_id(),
        )),
        operation_id: "ak.self.contact.command.commit".to_owned(),
        key: contact_phase_idempotency_key("commit", &body.idempotency_key),
        request_hash: request_hash.clone(),
        status: StatusCode::OK.as_u16() as i32,
        body: serde_json::to_value(&outcome)
            .map_err(|error| AppError::internal(format!("Contact outcome encode: {error}")))?,
        created_at: idempotency_created_at,
        expires_at: idempotency_created_at + chrono::Duration::hours(CONTACT_OUTCOME_TTL_HOURS),
    };
    let committed_invite_policy = contact_projection
        .as_ref()
        .and_then(|projection| projection.invite_policy.clone());
    crate::routing::events::event_log::submit_initial_event_submission_with_contact_projection(
        state,
        session,
        arkret_wire::EventInitialSubmission {
            event: body.signed_event.clone(),
            authorization_lease: None,
            cba_proof_bundles: Vec::new(),
            control_proposal_ack: body.control_proposal_ack.clone(),
            membership_compensation_evidence: None,
        },
        contact_projection.ok_or_else(|| {
            AppError::internal("accepted Contact commit is missing its projection mutation")
        })?,
        delivery.into_iter().collect(),
        contact_idempotency,
    )
    .await
    .map_err(|error| {
        AppError::new(ErrorCode::FailedPrecondition, error.message)
            .with_status(error.status)
            .with_wire_code(Box::leak(error.code.into_boxed_str()))
    })?;
    if let Some((account_id, policy)) = committed_invite_policy {
        state
            .contacts()
            .apply_committed_invite_policy(account_id, policy);
    }
    json_ok(outcome)
}

async fn plan_contact_commit(
    state: &AppState,
    reservation: &ContactReservation,
    event: &Event,
) -> Result<
    (
        ContactOperationOutcome,
        Option<soland_services::events::CommitContactProjection>,
    ),
    AppError,
> {
    let holder = reservation.holder.contact_actor_id().clone();
    let peer = reservation.branch.peer().contact_actor_id().clone();
    let contacts = state.contacts();
    let digest_suite = reservation
        .event_draft
        .event_digest
        .digest_suite()
        .map_err(|error| AppError::internal(format!("stored Contact digest suite: {error}")))?;
    let projection;
    let outcome = match &reservation.branch {
        ContactReservationBranch::Request {
            granted_to_peer_scopes,
            previous_terminal_contact_round_id,
            continuity_evidence,
            introduction_evidence,
            ..
        } => {
            let same_service_target = if let Some(peer_account_id) = peer.as_account_id() {
                state
                    .identities()
                    .account(peer_account_id)
                    .await
                    .map_err(|error| {
                        AppError::internal(format!("Contact target account lookup: {error}"))
                    })?
                    .is_some()
            } else {
                false
            };
            let peer_id = if same_service_target
                || matches!(
                    introduction_evidence.as_ref(),
                    ContactIntroductionEvidence::SameStation
                ) {
                Some(
                    arkret_wire::DidCoreId::new(state.service_id().clone()).map_err(|error| {
                        AppError::internal(format!("invalid local service DID: {error}"))
                    })?,
                )
            } else {
                contact_request_delivery_address(
                    state,
                    &reservation.holder.contact_actor_id(),
                    &reservation.branch.peer().contact_actor_id(),
                    introduction_evidence,
                )
                .await?
                .map(|address| address.delivery_station_id().clone())
            };
            let existing = contacts
                .contact_any(&holder, &peer)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let (slot_version, slot_predecessor) = next_request_slot_coordinates(
                existing
                    .as_ref()
                    .map(|record| record.request_slot_states.as_slice())
                    .unwrap_or_default(),
                &holder,
                &peer,
            )?;
            let request_receipt = sign_request_receipt(
                state,
                reservation,
                event,
                digest_suite,
                slot_version,
                slot_predecessor.clone(),
            )?;
            let (mut history, expected_updated_at, created_at, mut request_slot_states) =
                match existing {
                    None if previous_terminal_contact_round_id.is_none() => {
                        (Vec::new(), None, event.created_at, Vec::new())
                    }
                    None => match continuity_evidence {
                        Some(evidence) => (
                            imported_contact_continuity_history(
                                state,
                                evidence,
                                previous_terminal_contact_round_id.as_ref(),
                            )?,
                            None,
                            event.created_at,
                            Vec::new(),
                        ),
                        None => {
                            return Err(AppError::new(
                                ErrorCode::ContinuityEvidenceUnavailable,
                                "Contact continuity evidence is unavailable",
                            )
                            .with_status(StatusCode::CONFLICT));
                        }
                    },
                    Some(existing) if existing.status == "tombstoned" => {
                        let terminal =
                            existing.contact_round_evidence.clone().ok_or_else(|| {
                                AppError::new(
                                    ErrorCode::FailedPrecondition,
                                    "terminal Contact round evidence is unavailable",
                                )
                            })?;
                        if previous_terminal_contact_round_id.as_ref()
                            != Some(&terminal.contact_round_id)
                            || terminal.current_proofs.len() != 2
                            || terminal.current_proofs.iter().any(|proof| {
                                !proof.terminal
                                    || proof.contact_round_id != terminal.contact_round_id
                            })
                        {
                            return Err(AppError::conflict(
                                "Contact request terminal predecessor is not the durable terminal head",
                            ));
                        }
                        arkret_models_collaboration::contact_operations::validate_recontact_continuity(
                        &terminal,
                        &existing.contact_round_evidence_history,
                    )
                    .map_err(|error| {
                        AppError::new(
                            ErrorCode::ContinuityInvalid,
                            format!("terminal Contact continuity is invalid: {error}"),
                        )
                        .with_status(StatusCode::CONFLICT)
                    })?;
                        let mut history = Vec::with_capacity(
                            existing
                                .contact_round_evidence_history
                                .len()
                                .saturating_add(1),
                        );
                        history.push(terminal);
                        history.extend(existing.contact_round_evidence_history.iter().cloned());
                        if history.len() > 64 {
                            history = continuity_evidence
                                .as_ref()
                                .map(|evidence| {
                                    imported_contact_continuity_history(
                                        state,
                                        evidence,
                                        previous_terminal_contact_round_id.as_ref(),
                                    )
                                })
                                .transpose()?
                                .ok_or_else(|| {
                                    AppError::new(
                                        ErrorCode::ContinuityEvidenceUnavailable,
                                        "Contact continuity checkpoint is required",
                                    )
                                    .with_status(StatusCode::CONFLICT)
                                })?;
                        }
                        (
                            history,
                            Some(existing.updated_at),
                            existing.created_at,
                            existing.request_slot_states,
                        )
                    }
                    Some(existing) if existing.status == "rejected" => {
                        let expected = existing
                            .contact_round_evidence_history
                            .first()
                            .map(|bundle| &bundle.contact_round_id);
                        if previous_terminal_contact_round_id.as_ref() != expected {
                            return Err(AppError::conflict(
                                "Contact request does not preserve the last terminal predecessor",
                            ));
                        }
                        (
                            existing.contact_round_evidence_history,
                            Some(existing.updated_at),
                            existing.created_at,
                            existing.request_slot_states,
                        )
                    }
                    Some(_) => {
                        return Ok((
                            ContactOperationOutcome::Failed {
                                outcome: ContactFailedOutcome {
                                    result_kind: ContactResultKind::Request,
                                    operation_id: reservation.operation_id.clone(),
                                    reason: ContactOperationRejectReason::ContactRoundConflict,
                                },
                            },
                            None,
                        ));
                    }
                };
            accept_request_slot_transition(
                &mut request_slot_states,
                &holder,
                &peer,
                slot_version,
                slot_predecessor.as_ref(),
                request_receipt.receipt_digest.clone(),
            )?;
            // Same-service delivery is a fact about the target account's
            // current host, not about the requester_id's introduction-evidence
            // trust tier. A DID without URL components legitimately uses `explicit_address`,
            // but its local recipient still needs the exact privately
            // resolvable request Event required to author a response.
            let verified_mirror = same_service_target
                .then(|| {
                    Ok::<_, AppError>(soland_storage::ContactVerifiedMirrorRecord {
                        target_holder_id: peer.to_string(),
                        request_event_id: event.event_id.to_string(),
                        request_digest: request_receipt.core.request_digest().to_string(),
                        canonical_event_bytes: arkret_canonical::canonical_json_bytes(event)
                            .map_err(|error| {
                                AppError::internal(format!(
                                    "same-service Contact mirror canonical Event: {error}"
                                ))
                            })?,
                        source_receipt: request_receipt.clone(),
                        issuer_id: state.service_id().clone(),
                        verified_at: now(),
                    })
                })
                .transpose()?;
            projection = Some(soland_services::events::CommitContactProjection {
                record: ContactRecord {
                    requester_id: holder.clone(),
                    target_id: peer.clone(),
                    contact_round_id: None,
                    version: None,
                    granted_to_target_scopes: contact_scope_strings(granted_to_peer_scopes),
                    granted_to_requester_scopes: Vec::new(),
                    status: "pending".to_owned(),
                    request_event_ref: Some(event.event_id.clone()),
                    request_slot_states,
                    request_receipts: vec![request_receipt.clone()],
                    request_mirror_receipts: Vec::new(),
                    contact_round_evidence: None,
                    contact_round_evidence_history: std::mem::take(&mut history),
                    control_outcomes: Vec::new(),
                    response_event_ref: None,
                    tombstone_event_ref: None,
                    message: event
                        .payload
                        .get("message")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    peer_host_id: peer_id,
                    peer_service_resolution: contact_service_resolution(state, &reservation.branch)
                        .await?,
                    created_at,
                    updated_at: expected_updated_at
                        .map(|expected| contact_revision_after(expected, event.created_at))
                        .unwrap_or(event.created_at),
                },
                expected_updated_at,
                conflict_code: "contact_round_conflict".to_owned(),
                verified_mirror,
                invite_policy: None,
            });
            ContactOperationOutcome::Accepted {
                outcome: ContactAcceptedOutcome::Request {
                    operation_id: reservation.operation_id.clone(),
                    request_acceptance_receipt: request_receipt,
                },
            }
        }
        ContactReservationBranch::Response {
            request_receipt,
            contact_round_id,
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
                || record.request_event_ref.as_ref()
                    != Some(&request_receipt.core.request_event_ref)
            {
                return Err(AppError::conflict(
                    "Contact request slot is already consumed",
                ));
            }
            let (contact_round, expected_contact_round_id) = normal_basis(request_receipt)?;
            if &expected_contact_round_id != contact_round_id {
                return Err(AppError::conflict(
                    "Contact response contact_round does not match the accepted request receipt",
                ));
            }
            let accepted_at = now();
            let expected_updated_at = record.updated_at;
            let sorted_pair_member_ids = match &contact_round {
                ContactRound::Normal {
                    sorted_pair_member_ids,
                    ..
                } => sorted_pair_member_ids.clone(),
                ContactRound::Glare { .. } => unreachable!("normal basis returned glare"),
            };
            let mut cas_frontier = event.prev_refs.clone();
            cas_frontier.push(event.event_id.clone());
            cas_frontier.sort();
            cas_frontier.dedup();
            let (cas_sequence, slot_predecessor) =
                next_request_slot_coordinates(&record.request_slot_states, &holder, &peer)?;
            let absence = OutgoingSlotAbsenceTranscript {
                sorted_pair_member_ids,
                request_slot_owner: holder.clone(),
                contact_round_id: contact_round_id.clone(),
                slot_predecessor: slot_predecessor.clone(),
                cas_sequence,
                cas_frontier,
                observed_at: accepted_at,
                outgoing_request_state: OutgoingRequestState::Absent,
            };
            let outgoing_slot_absence_digest = absence
                .digest()
                .map_err(|error| AppError::internal(error.to_string()))?;
            accept_request_slot_transition(
                &mut record.request_slot_states,
                &holder,
                &peer,
                cas_sequence,
                slot_predecessor.as_ref(),
                outgoing_slot_absence_digest.clone(),
            )?;
            let issuer = state.service_core_id();
            let unsigned_receipt = json!({
                "contact_round_id": contact_round_id,
                "request_receipt": request_receipt,
                "response_event_ref": event.event_id,
                "outgoing_slot_absence_digest": outgoing_slot_absence_digest,
                "accepted_at": arkret_canonical::format_timestamp_canonical(accepted_at),
                "issuer_id": issuer,
            });
            let response_receipt = NormalResponseAcceptanceReceipt {
                contact_round_id: contact_round_id.clone(),
                request_receipt: request_receipt.clone(),
                response_event_ref: event.event_id.clone(),
                outgoing_slot_absence_digest,
                accepted_at,
                issuer_id: issuer,
                signature: service_signature(state, &unsigned_receipt)?,
            };
            let current_proof = signed_current_proof(
                state,
                contact_round_id.clone(),
                reservation.branch.peer().clone(),
                event,
                digest_suite,
            )?;
            let requester_current_proof =
                local_requester_current_proof(state, contact_round_id, request_receipt).await?;
            record.status = "accepted".to_owned();
            record.request_receipts.clear();
            record.request_mirror_receipts.clear();
            record.contact_round_id = Some(contact_round_id.clone());
            record.version = Some(1);
            record.granted_to_requester_scopes = contact_scope_strings(granted_to_peer_scopes);
            record.response_event_ref = Some(event.event_id.clone());
            record.contact_round_evidence = Some(ContactRoundEvidenceBundle {
                contact_round_id: contact_round_id.clone(),
                previous_terminal_contact_round_id: request_receipt
                    .core
                    .previous_terminal_contact_round_id
                    .clone(),
                contact_round,
                request_receipts: vec![request_receipt.clone()],
                normal_response_receipt: Some(response_receipt.clone()),
                glare_concurrency_attestations: None,
                // A same-service pair already has the requester_id's accepted
                // PCR Event and exact local principal authority pair, so its source
                // can issue both holder checkpoints without a transport
                // round-trip. Cross-service pairs still merge the requester_id
                // proof returned by the peer carrier.
                current_proofs: requester_current_proof
                    .into_iter()
                    .chain(std::iter::once(current_proof.clone()))
                    .collect(),
                continuity_checkpoint: record
                    .contact_round_evidence_history
                    .iter()
                    .find_map(|bundle| bundle.continuity_checkpoint.clone()),
            });
            record.updated_at = contact_revision_after(expected_updated_at, event.created_at);
            projection = Some(soland_services::events::CommitContactProjection {
                record,
                expected_updated_at: Some(expected_updated_at),
                conflict_code: "contact_lineage_conflict".to_owned(),
                verified_mirror: None,
                invite_policy: None,
            });
            let lineage = signed_lineage(
                state,
                reservation.holder.clone(),
                reservation.branch.peer().clone(),
                contact_round_id.clone(),
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
                    current_proof,
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
            let expected_updated_at = record.updated_at;
            record.status = "rejected".to_owned();
            record.request_receipts.clear();
            record.request_mirror_receipts.clear();
            record.response_event_ref = Some(event.event_id.clone());
            record.updated_at = contact_revision_after(expected_updated_at, event.created_at);
            projection = Some(soland_services::events::CommitContactProjection {
                record,
                expected_updated_at: Some(expected_updated_at),
                conflict_code: "contact_lineage_conflict".to_owned(),
                verified_mirror: None,
                invite_policy: None,
            });
            let accepted_at = now();
            let issuer = state.service_core_id();
            let unsigned = json!({
                "request_receipt": request_receipt,
                "reject_event_ref": event.event_id,
                "accepted_at": arkret_canonical::format_timestamp_canonical(accepted_at),
                "issuer_id": issuer,
            });
            ContactOperationOutcome::Accepted {
                outcome: ContactAcceptedOutcome::Reject {
                    operation_id: reservation.operation_id.clone(),
                    reject_acceptance_receipt: RejectAcceptanceReceipt {
                        request_receipt: request_receipt.clone(),
                        reject_event_ref: event.event_id.clone(),
                        accepted_at,
                        issuer_id: issuer,
                        signature: service_signature(state, &unsigned)?,
                    },
                },
            }
        }
        ContactReservationBranch::ScopeUpdate {
            contact_round_id,
            version,
            predecessor_event_ref,
            granted_to_peer_scopes,
            ..
        } => {
            let Some(mut record) = contact_record_for_lineage(state, &holder, &peer).await? else {
                return Err(AppError::not_found("accepted Contact round not found"));
            };
            validate_lineage_head(
                &record,
                &holder,
                contact_round_id,
                *version,
                predecessor_event_ref,
            )?;
            let expected_updated_at = record.updated_at;
            set_holder_scopes(
                &mut record,
                &holder,
                contact_scope_strings(granted_to_peer_scopes),
            );
            record.version = Some(*version);
            record.updated_at = contact_revision_after(expected_updated_at, event.created_at);
            // The accepted contact_round remains accepted even when its directional
            // intersection is empty. Authorization reads the exact full-set
            // heads, so an empty intersection grants nothing.
            record.status = "accepted".to_owned();
            set_holder_head(&mut record, &holder, event.event_id.clone());
            let current_proof = signed_current_proof(
                state,
                contact_round_id.clone(),
                reservation.branch.peer().clone(),
                event,
                digest_suite,
            )?;
            if let Some(bundle) = record.contact_round_evidence.as_mut() {
                bundle
                    .current_proofs
                    .retain(|proof| proof.peer != current_proof.peer);
                bundle.current_proofs.push(current_proof.clone());
                bundle.current_proofs.sort_by(|left, right| {
                    left.peer
                        .contact_actor_id()
                        .cmp(&right.peer.contact_actor_id())
                });
            }
            projection = Some(soland_services::events::CommitContactProjection {
                record,
                expected_updated_at: Some(expected_updated_at),
                conflict_code: "contact_lineage_conflict".to_owned(),
                verified_mirror: None,
                invite_policy: None,
            });
            let lineage = signed_lineage(
                state,
                reservation.holder.clone(),
                reservation.branch.peer().clone(),
                contact_round_id.clone(),
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
                    current_proof,
                },
            }
        }
        ContactReservationBranch::Tombstone {
            contact_round_id,
            version,
            predecessor_event_ref,
            block_peer,
            ..
        } => {
            let Some(mut record) = contact_record_for_lineage(state, &holder, &peer).await? else {
                return Err(AppError::not_found("accepted Contact round not found"));
            };
            validate_lineage_head(
                &record,
                &holder,
                contact_round_id,
                *version,
                predecessor_event_ref,
            )?;
            let expected_updated_at = record.updated_at;
            record.version = Some(*version);
            record.status = "tombstoned".to_owned();
            record.request_receipts.clear();
            record.request_mirror_receipts.clear();
            record.tombstone_event_ref = Some(event.event_id.clone());
            record.updated_at = contact_revision_after(expected_updated_at, event.created_at);
            let current_proof = signed_current_proof(
                state,
                contact_round_id.clone(),
                reservation.branch.peer().clone(),
                event,
                digest_suite,
            )?;
            if let Some(bundle) = record.contact_round_evidence.as_mut() {
                bundle
                    .current_proofs
                    .retain(|proof| proof.peer != current_proof.peer);
                bundle.current_proofs.push(current_proof.clone());
                bundle.current_proofs.sort_by(|left, right| {
                    left.peer
                        .contact_actor_id()
                        .cmp(&right.peer.contact_actor_id())
                });
            }
            let invite_policy = if *block_peer {
                let holder_account_id = match &reservation.holder {
                    ContactPeer::Human { account_id } => account_id.clone(),
                    ContactPeer::Agent {
                        controller_account_id,
                        ..
                    } => controller_account_id.clone(),
                };
                let mut policy = state
                    .contacts()
                    .invite_policy(&holder_account_id)
                    .unwrap_or_else(|| {
                        InviteReceivePolicy::spec_default(holder_account_id.clone())
                    });
                if !policy.denied_actor_ids.contains(&peer) {
                    policy.denied_actor_ids.push(peer.clone());
                    policy
                        .denied_actor_ids
                        .sort_by_key(arkret_wire::ActorId::to_string);
                }
                Some((holder_account_id, policy))
            } else {
                None
            };
            projection = Some(soland_services::events::CommitContactProjection {
                record,
                expected_updated_at: Some(expected_updated_at),
                conflict_code: "contact_lineage_conflict".to_owned(),
                verified_mirror: None,
                invite_policy,
            });
            let lineage = signed_lineage(
                state,
                reservation.holder.clone(),
                reservation.branch.peer().clone(),
                contact_round_id.clone(),
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
                    current_proof,
                },
            }
        }
    };
    Ok((outcome, projection))
}

fn imported_contact_continuity_history(
    state: &AppState,
    evidence: &ContactContinuityEvidence,
    previous_terminal_contact_round_id: Option<&Hash>,
) -> Result<Vec<ContactRoundEvidenceBundle>, AppError> {
    if evidence.uncompressed_tail_entries.is_empty()
        || evidence.uncompressed_tail_entries.len() > 64
    {
        return Err(AppError::new(
            ErrorCode::ContinuityEvidenceUnavailable,
            "portable Contact continuity tail is unavailable",
        )
        .with_status(StatusCode::CONFLICT));
    }
    evidence.checkpoint.validate_contact_shape().map_err(|_| {
        AppError::new(
            ErrorCode::ContinuityInvalid,
            "portable Contact continuity is invalid",
        )
        .with_status(StatusCode::CONFLICT)
    })?;
    let signing_bytes = evidence.checkpoint.signing_bytes().map_err(|_| {
        AppError::new(
            ErrorCode::ContinuityInvalid,
            "portable Contact continuity is invalid",
        )
        .with_status(StatusCode::CONFLICT)
    })?;
    for checkpoint_signature in &evidence.checkpoint.signatures {
        verify_contact_service_signature_bytes(
            state,
            checkpoint_signature.signer.station_id.as_str(),
            &checkpoint_signature.signature,
            &signing_bytes,
            "continuity_evidence.checkpoint",
        )
        .map_err(|_| {
            AppError::new(
                ErrorCode::ContinuityInvalid,
                "portable Contact continuity is invalid",
            )
            .with_status(StatusCode::CONFLICT)
        })?;
    }
    let mut tail = evidence.uncompressed_tail_entries.clone();
    if previous_terminal_contact_round_id != Some(&tail[0].contact_round_id) {
        return Err(AppError::new(
            ErrorCode::ContinuityInvalid,
            "portable Contact continuity is invalid",
        )
        .with_status(StatusCode::CONFLICT));
    }
    tail[0].continuity_checkpoint = Some(evidence.checkpoint.clone());
    arkret_models_collaboration::contact_operations::validate_recontact_continuity(
        &tail[0],
        &tail[1..],
    )
    .map_err(|_| {
        AppError::new(
            ErrorCode::ContinuityInvalid,
            "portable Contact continuity is invalid",
        )
        .with_status(StatusCode::CONFLICT)
    })?;
    Ok(tail)
}

async fn prepare_contact_federation_delivery(
    state: &AppState,
    reservation: &ContactReservation,
    event: &Event,
    outcome: &ContactOperationOutcome,
    _planned_record: Option<&ContactRecord>,
) -> Result<Option<soland_services::federation::FederationDeliveryRecord>, AppError> {
    let ContactOperationOutcome::Accepted { outcome } = outcome else {
        return Ok(None);
    };
    let holder = reservation.holder.contact_actor_id();
    let peer = reservation.branch.peer().contact_actor_id();
    let address = match &reservation.branch {
        ContactReservationBranch::Request {
            introduction_evidence,
            ..
        } => contact_request_delivery_address(state, &holder, &peer, introduction_evidence).await?,
        // Stored delivery coordinates do not retain the exact authority
        // instance and therefore cannot authorize a later human-PCR route.
        _ => None,
    };
    let Some(contact_address) = address else {
        // Some introduction profiles intentionally carry no routable service
        // coordinate. The accepted local request remains pending_outgoing and
        // cannot be upgraded to accepted authority until a verified delivery
        // binding becomes available.
        return Ok(None);
    };
    let key = IdempotencyKey::new(format!("peer-contact:{}", event.event_id))
        .map_err(|error| AppError::internal(format!("Contact peer key invalid: {error}")))?;
    let delivery = match outcome {
        ContactAcceptedOutcome::Request {
            request_acceptance_receipt,
            ..
        } => {
            let ContactReservationBranch::Request {
                introduction_evidence,
                ..
            } = &reservation.branch
            else {
                return Err(AppError::internal(
                    "Contact request outcome/branch mismatch",
                ));
            };
            PeerContactSubmitRequestBody::Request {
                idempotency_key: key,
                signed_event: event.clone(),
                request_receipt: request_acceptance_receipt.clone(),
                contact_address,
                introduction_evidence: (**introduction_evidence).clone(),
                current_proof: None,
            }
        }
        ContactAcceptedOutcome::Response {
            normal_response_acceptance_receipt,
            current_proof,
            ..
        } => PeerContactSubmitRequestBody::Response {
            idempotency_key: key,
            signed_event: event.clone(),
            response_receipt: normal_response_acceptance_receipt.clone(),
            contact_address,
            current_proof: Some(current_proof.clone()),
        },
        ContactAcceptedOutcome::Reject {
            reject_acceptance_receipt,
            ..
        } => PeerContactSubmitRequestBody::Reject {
            idempotency_key: key,
            signed_event: event.clone(),
            reject_receipt: reject_acceptance_receipt.clone(),
            contact_address,
        },
        ContactAcceptedOutcome::ScopeUpdate {
            lineage,
            current_proof,
            ..
        } => PeerContactSubmitRequestBody::ScopeUpdate {
            idempotency_key: key,
            signed_event: event.clone(),
            lineage: lineage.clone(),
            current_proof: current_proof.clone(),
            contact_address,
        },
        ContactAcceptedOutcome::Tombstone {
            lineage,
            current_proof,
            ..
        } => PeerContactSubmitRequestBody::Tombstone {
            idempotency_key: key,
            signed_event: event.clone(),
            lineage: lineage.clone(),
            current_proof: current_proof.clone(),
            contact_address,
        },
    };
    let recipient_id = match &delivery {
        PeerContactSubmitRequestBody::Request {
            contact_address, ..
        }
        | PeerContactSubmitRequestBody::Response {
            contact_address, ..
        }
        | PeerContactSubmitRequestBody::Reject {
            contact_address, ..
        }
        | PeerContactSubmitRequestBody::ScopeUpdate {
            contact_address, ..
        }
        | PeerContactSubmitRequestBody::Tombstone {
            contact_address, ..
        } => contact_address.delivery_station_id().as_str(),
        PeerContactSubmitRequestBody::ProofRefresh { .. }
        | PeerContactSubmitRequestBody::GlareFinalize { .. }
        | PeerContactSubmitRequestBody::ContinuityCheckpoint { .. } => {
            unreachable!("Contact commit only emits Event carriers")
        }
    };
    crate::routing::identity::contact_federation::prepare_peer_contact_carrier(
        state,
        recipient_id,
        &delivery,
    )
    .await
}

async fn contact_request_delivery_address(
    _state: &AppState,
    _holder: &arkret_wire::ActorId,
    _peer: &arkret_wire::ActorId,
    _evidence: &ContactIntroductionEvidence,
) -> Result<Option<PeerContactAddress>, AppError> {
    // Contact introduction evidence does not carry enough authority to derive
    // a delivery target. In particular, Realm membership is social context,
    // not an account-to-Station routing binding.
    Ok(None)
}

async fn contact_introduction_service_resolution(
    state: &AppState,
    introduction_evidence: &ContactIntroductionEvidence,
) -> Result<Option<ServiceResolutionCarrier>, AppError> {
    let carrier = match introduction_evidence {
        ContactIntroductionEvidence::LocatorRef { principal_locator } => {
            Some(principal_locator.service_resolution.clone())
        }
        // Realm membership proves social context, not transport routing. The
        // removed membership delivery binding must not be resurrected here.
        ContactIntroductionEvidence::SharedRealm { .. } => None,
        ContactIntroductionEvidence::SameStation => state
            .current_signed_service_resolution()
            .await
            .map_err(|error| {
                AppError::internal(format!("current service resolution unavailable: {error}"))
            })?
            .map(|inline| ServiceResolutionCarrier::Inline { inline }),
        ContactIntroductionEvidence::HandleClaim { .. }
        | ContactIntroductionEvidence::ExplicitAddress => None,
    };
    Ok(carrier)
}

async fn contact_service_resolution(
    state: &AppState,
    branch: &ContactReservationBranch,
) -> Result<Option<Value>, AppError> {
    let ContactReservationBranch::Request {
        introduction_evidence,
        ..
    } = branch
    else {
        return Ok(None);
    };
    contact_introduction_service_resolution(state, introduction_evidence)
        .await?
        .map(|carrier| {
            serde_json::to_value(carrier).map_err(|error| {
                AppError::internal(format!("Contact service resolution encode failed: {error}"))
            })
        })
        .transpose()
}

async fn contact_record_for_lineage(
    state: &AppState,
    holder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
) -> Result<Option<ContactRecord>, AppError> {
    let forward = state
        .contacts()
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if forward.is_some() {
        return Ok(forward);
    }
    // A Contact round has one durable row, oriented by the original
    // requester. Scope/tombstone lineage commands are holder-symmetric, so a
    // holder who was the original target must resolve the reverse key before
    // validating its local lineage head.
    state
        .contacts()
        .contact_any(peer, holder)
        .await
        .map_err(|error| AppError::internal(error.to_string()))
}

fn holder_head<'a>(
    record: &'a ContactRecord,
    holder: &arkret_wire::ActorId,
) -> Option<&'a EventId> {
    if &record.requester_id == holder {
        record.request_event_ref.as_ref()
    } else {
        record.response_event_ref.as_ref()
    }
}

fn set_holder_head(record: &mut ContactRecord, holder: &arkret_wire::ActorId, event_ref: EventId) {
    if &record.requester_id == holder {
        record.request_event_ref = Some(event_ref);
    } else {
        record.response_event_ref = Some(event_ref);
    }
}

fn set_holder_scopes(
    record: &mut ContactRecord,
    holder: &arkret_wire::ActorId,
    scopes: Vec<String>,
) {
    if &record.requester_id == holder {
        record.granted_to_target_scopes = scopes;
    } else {
        record.granted_to_requester_scopes = scopes;
    }
}

fn validate_lineage_head(
    record: &ContactRecord,
    holder: &arkret_wire::ActorId,
    contact_round_id: &Hash,
    version: u64,
    predecessor: &EventId,
) -> Result<(), AppError> {
    if record.contact_round_id.as_ref() != Some(contact_round_id)
        || record.version.and_then(|current| current.checked_add(1)) != Some(version)
        || holder_head(record, holder) != Some(predecessor)
    {
        return Err(AppError::conflict("Contact lineage CAS mismatch")
            .with_wire_code("contact_lineage_conflict"));
    }
    let bundle = record.contact_round_evidence.as_ref().ok_or_else(|| {
        AppError::conflict("Contact round evidence is not yet authoritative")
            .with_wire_code("contact_scope_stale")
    })?;
    let directional_proofs_valid = bundle.current_proofs.iter().all(|proof| {
        let peer = proof.peer.contact_actor_id();
        let subject = if peer == record.requester_id {
            &record.target_id
        } else if peer == record.target_id {
            &record.requester_id
        } else {
            return false;
        };
        subject
            .as_account_id()
            .is_some_and(|account| account.station_id == proof.issuer_id)
    });
    let proof_peers = bundle
        .current_proofs
        .iter()
        .map(|proof| proof.peer.contact_actor_id())
        .collect::<std::collections::BTreeSet<_>>();
    let participants = [record.requester_id.clone(), record.target_id.clone()]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if bundle.contact_round_id != *contact_round_id
        || bundle.current_proofs.len() != 2
        || proof_peers != participants
        || !directional_proofs_valid
        || bundle.current_proofs.iter().any(|proof| {
            proof.contact_round_id != bundle.contact_round_id
                || proof.terminal
                || proof.complete_through == 0
                || !proof.accepted_frontier.contains(&proof.head_event_ref)
        })
        || arkret_models_collaboration::contact_operations::validate_recontact_continuity(
            bundle,
            &record.contact_round_evidence_history,
        )
        .is_err()
    {
        return Err(
            AppError::conflict("Contact round evidence is not authoritative")
                .with_wire_code("contact_scope_stale"),
        );
    }
    Ok(())
}

fn contact_revision_after(
    expected_updated_at: chrono::DateTime<chrono::Utc>,
    preferred: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    preferred.max(expected_updated_at + chrono::Duration::microseconds(1))
}

pub(super) async fn request(
    state: &AppState,
    session: &SessionRecord,
    body: ContactOperationRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactOperationRequestBody::Prepare(body) => {
            let session_actor_id = holder_peer(state, session).await?.contact_actor_id();
            let prior = state
                .contacts()
                .contact_any(&session_actor_id, &body.peer.contact_actor_id())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let local_terminal_basis = prior.as_ref().and_then(|record| {
                (record.status == "tombstoned")
                    .then_some(record.contact_round_id.as_ref().map(|value| value.as_str()))
                    .flatten()
            });
            if local_terminal_basis
                != body
                    .previous_terminal_contact_round_id
                    .as_ref()
                    .map(Hash::as_str)
            {
                return Err(AppError::conflict(
                    "recontact request does not link the immediate local terminal Contact round",
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
                previous_terminal_contact_round_id: body.previous_terminal_contact_round_id.clone(),
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
                    previous_terminal_contact_round_id: body.previous_terminal_contact_round_id,
                    continuity_evidence: body.continuity_evidence,
                    introduction_evidence: Box::new(body.introduction_evidence),
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
            let holder = holder_peer(state, session).await?;
            let peer = body.request_receipt.core.holder.clone();
            let record = state
                .contacts()
                .contact_any(&peer.contact_actor_id(), &holder.contact_actor_id())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::not_found("pending Contact request not found"))?;
            validate_request_acceptance_receipt(state, &record, &holder, &body.request_receipt)
                .await?;
            let (_, contact_round_id) = normal_basis(&body.request_receipt)?;
            if state
                .contacts()
                .contact_any(&holder.contact_actor_id(), &peer.contact_actor_id())
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
                contact_round_id: contact_round_id.clone(),
                version: 1,
                request_event_ref: body.request_receipt.core.request_event_ref.clone(),
                request_acceptance_receipt_digest: canonical_contact_digest(&body.request_receipt)?,
                previous_terminal_contact_round_id: body
                    .request_receipt
                    .core
                    .previous_terminal_contact_round_id
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
                    contact_round_id,
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
            let holder = holder_peer(state, session).await?;
            let peer = body.request_receipt.core.holder.clone();
            let record = state
                .contacts()
                .contact_any(&peer.contact_actor_id(), &holder.contact_actor_id())
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
                contact_round_id: body.contact_round_id.clone(),
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
                    contact_round_id: body.contact_round_id,
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
                contact_round_id: body.contact_round_id.clone(),
                version: body.version,
                predecessor_event_ref: body.predecessor_event_ref.clone(),
                reason: None,
            };
            prepare::<arkret_wire::event_spec::ContactTombstone>(
                state,
                session,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::Tombstone {
                    peer: body.peer,
                    contact_round_id: body.contact_round_id,
                    version: body.version,
                    predecessor_event_ref: body.predecessor_event_ref,
                    block_peer: body.block_peer,
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
        return Err(AppError::param_invalid(
            "Contact request message must be at most 2000 characters",
        ));
    }
    Ok(Some(normalized))
}

#[cfg(test)]
mod device_authorization_account_tests {
    use arkret_wire::{AccountId, ActorId, DidCoreId, Hash};

    use super::{
        accept_request_slot_transition, device_authorization_matches_contact_account,
        next_request_slot_coordinates,
    };

    fn account(principal: &str, station: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new(station).unwrap(),
        ))
    }

    fn hash(marker: char) -> Hash {
        Hash::new(format!("sha256:{}", marker.to_string().repeat(64))).unwrap()
    }

    #[test]
    fn contact_device_authorization_preserves_the_exact_account_and_actor_branch() {
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = DidCoreId::new("ak:did_core:web:station-a.example").unwrap();
        let account = AccountId::new(principal.clone(), station.clone());
        assert!(device_authorization_matches_contact_account(
            &ActorId::account(account.clone()).canonical_key().unwrap(),
            &account,
        ));
        let foreign = AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
        );
        for actor in [
            ActorId::account(foreign),
            ActorId::service(principal.clone()),
        ] {
            assert!(!device_authorization_matches_contact_account(
                &actor.canonical_key().unwrap(),
                &account,
            ));
        }
        assert!(!device_authorization_matches_contact_account(
            principal.as_str(),
            &account,
        ));
    }

    #[test]
    fn request_slot_coordinates_come_from_the_exact_durable_direction() {
        let alice = account(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
        );
        let bob = account(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:station.example",
        );
        let alice_head = hash('a');
        let bob_head = hash('b');
        let mut states = vec![
            soland_services::identity::ContactRequestSlotState {
                owner_id: alice.clone(),
                peer_id: bob.clone(),
                accepted_sequence: 7,
                head_digest: alice_head.clone(),
            },
            soland_services::identity::ContactRequestSlotState {
                owner_id: bob.clone(),
                peer_id: alice.clone(),
                accepted_sequence: 3,
                head_digest: bob_head.clone(),
            },
        ];

        assert_eq!(
            next_request_slot_coordinates(&states, &alice, &bob).unwrap(),
            (8, Some(alice_head.clone()))
        );
        assert_eq!(
            next_request_slot_coordinates(&states, &bob, &alice).unwrap(),
            (4, Some(bob_head.clone()))
        );

        let accepted_head = hash('c');
        accept_request_slot_transition(
            &mut states,
            &alice,
            &bob,
            8,
            Some(&alice_head),
            accepted_head.clone(),
        )
        .unwrap();
        assert_eq!(
            next_request_slot_coordinates(&states, &alice, &bob).unwrap(),
            (9, Some(accepted_head))
        );
        assert_eq!(
            next_request_slot_coordinates(&states, &bob, &alice).unwrap(),
            (4, Some(bob_head))
        );
    }

    #[test]
    fn request_slot_genesis_is_sequence_one_with_no_predecessor() {
        let alice = account(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
        );
        let bob = account(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:station.example",
        );
        assert_eq!(
            next_request_slot_coordinates(&[], &alice, &bob).unwrap(),
            (1, None)
        );
    }

    #[test]
    fn request_slot_rejects_stale_or_wrong_predecessor_without_mutation() {
        let alice = account(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
        );
        let bob = account(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:station.example",
        );
        let durable_head = hash('a');
        let original = vec![soland_services::identity::ContactRequestSlotState {
            owner_id: alice.clone(),
            peer_id: bob.clone(),
            accepted_sequence: 7,
            head_digest: durable_head.clone(),
        }];

        for (sequence, predecessor) in [(7, Some(durable_head.clone())), (8, Some(hash('b')))] {
            let mut states = original.clone();
            assert!(
                accept_request_slot_transition(
                    &mut states,
                    &alice,
                    &bob,
                    sequence,
                    predecessor.as_ref(),
                    hash('c'),
                )
                .is_err()
            );
            assert_eq!(states.len(), 1);
            assert_eq!(states[0].owner_id, original[0].owner_id);
            assert_eq!(states[0].peer_id, original[0].peer_id);
            assert_eq!(states[0].accepted_sequence, original[0].accepted_sequence);
            assert_eq!(states[0].head_digest, original[0].head_digest);
        }
    }
}
