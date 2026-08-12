use arkret_models_collaboration::events_payloads::audit::{
    AuditAccessedKind, AuditAccessedPayload,
};
use arkret_models_collaboration::events_payloads::strand::{
    StrandWatchLevel, StrandWatchSetPayload,
};

use super::super::*;
use super::envelope::{event_digest_for_suite, event_digest_suite};

/// `strand-and-message.md` §8.4 — the one `refs` role that carries the
/// `.others` audit pairing edge.
const AUDIT_PAIR_ROLE: &str = "audit_pair";

pub(crate) async fn append_encrypted_message_franking(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) {
    let Some(proof) = encrypted_message_franking_proof(state.service_id(), parsed, envelope) else {
        return;
    };
    append_audit_log(
        state,
        Some(&parsed.actor_id),
        arkret_wire::EventKind::ModerationFrankingProof.as_str(),
        proof,
        "accepted",
    )
    .await;
}

fn encrypted_message_franking_proof(
    service_id: &str,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) -> Option<Value> {
    if parsed.kind != arkret_wire::EventKind::MessageCreate.as_str() {
        return None;
    }
    let ciphertext_digest = encrypted_message_ciphertext_digest(envelope)?;
    let mut proof = json!({
        "kind": arkret_wire::EventKind::ModerationFrankingProof,
        "realm_id": parsed.realm_id,
        "target_event_id": parsed.event_id,
        "sender_did": parsed.actor_id,
        "receiving_service_id": service_id,
        "ciphertext_digest": ciphertext_digest,
        "event_canonical_digest": parsed.canonical_digest,
        "timestamp": now(),
    });
    let proof_digest = franking_proof_digest(&proof);
    proof["proof_digest"] = json!(proof_digest);
    Some(proof)
}

fn encrypted_message_ciphertext_digest(envelope: &Value) -> Option<String> {
    if let Some(digest) = envelope
        .pointer("/payload/encrypted_content/payload_digest")
        .and_then(Value::as_str)
        && is_valid_hash_digest(digest)
    {
        return Some(digest.to_owned());
    }
    None
}

fn franking_proof_digest(proof: &Value) -> String {
    let material = json!({
        "kind": proof
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or(arkret_wire::EventKind::ModerationFrankingProof.as_str()),
        "target_event_id": proof.get("target_event_id").and_then(Value::as_str).unwrap_or_default(),
        "sender_did": proof.get("sender_did").and_then(Value::as_str).unwrap_or_default(),
        "receiving_service_id": proof.get("receiving_service_id").and_then(Value::as_str).unwrap_or_default(),
        "ciphertext_digest": proof.get("ciphertext_digest").and_then(Value::as_str).unwrap_or_default(),
        "event_canonical_digest": proof.get("event_canonical_digest").and_then(Value::as_str).unwrap_or_default(),
    });
    let bytes = serde_json::to_vec(&material).unwrap_or_default();
    arkret_canonical::sha256_digest(&bytes)
}

/// The one `ak.audit.accessed` rule that is not stateable in the payload
/// schema: the declared writer is this Event's own actor.
///
/// Everything else about the payload — the closed field set, the `access_kind`
/// enum, DID / object-ref / cell-ref / hash / timestamp shapes, and the
/// per-`access_kind` conditional required sets (`watch_set_others` pulls in
/// `target_actor_id`, `target_cell_id`, `paired_event_id`,
/// `paired_event_digest` and both cell heads) — is already enforced against
/// `event-payload.schema.json#/$defs/audit_accessed_payload` by the SDK
/// payload validator catalog in `validate_event_schema_and_payload`, which runs
/// earlier in this same admission pass. A hand-written second copy of those
/// rules used to live here, and it is exactly how a `writer_did` field name
/// survived after the schema settled on `writer_actor_id`: the duplicate was
/// the only thing rejecting conformant payloads. Parse through the SDK type
/// instead, so a schema change breaks the build rather than the wire.
pub(super) fn validate_audit_accessed_payload(
    kind: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if kind != arkret_wire::event_kind_str::AUDIT_ACCESSED {
        return Ok(());
    }
    let payload = audit_accessed_payload(object)?;
    if object.get("actor_id").and_then(Value::as_str) != Some(payload.writer_actor_id.as_str()) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "ak.audit.accessed writer_actor_id must match actor_id",
        ));
    }
    Ok(())
}

fn audit_accessed_payload(
    object: &serde_json::Map<String, Value>,
) -> Result<AuditAccessedPayload, EventValidationError> {
    typed_payload(object, "ak.audit.accessed")
}

fn strand_watch_set_payload(
    object: &serde_json::Map<String, Value>,
) -> Result<StrandWatchSetPayload, EventValidationError> {
    typed_payload(object, "ak.strand.watch.set")
}

fn typed_payload<T: serde::de::DeserializeOwned>(
    object: &serde_json::Map<String, Value>,
    kind: &str,
) -> Result<T, EventValidationError> {
    let payload = object.get("payload").cloned().unwrap_or(Value::Null);
    serde_json::from_value(payload).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("{kind} payload does not match its registered wire type: {error}"),
        )
    })
}

/// Per-event half of the `.others` watch rules: the level constraints, which need
/// nothing but this envelope.
///
/// The audit pairing itself is **not** checked here. Under content-bound ids the audit
/// Event is authored after the write it records (encoding.md 6.0.1 forbids the two from
/// naming each other), so the pairing is only decidable once the whole submit batch is in
/// hand — see [`validate_watch_set_others_audit_pairs`].
pub(super) fn validate_strand_watch_manage_others_levels(
    kind: &str,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
) -> Result<(), EventValidationError> {
    if kind != arkret_wire::event_kind_str::STRAND_WATCH_SET {
        return Ok(());
    }
    let payload = strand_watch_set_payload(object)?;
    if payload.watcher_actor_id.as_str() == actor_id {
        return Ok(());
    }
    // `muted` suppresses mention / moderation routing and `level_public` is a
    // personal publication opt-in, so neither may be written on someone's
    // behalf. Each carries its own reason code (strand-and-message.md 8.4);
    // both used to report `watch_set_others_audit_missing`, which blamed the
    // audit pair for a level the audit pair would not have fixed.
    if matches!(payload.level, Some(StrandWatchLevel::Muted)) {
        return Err(event_validation_error(
            StatusCode::PRECONDITION_FAILED,
            arkret_wire::ReasonCode::WATCH_MUTED_MUST_BE_SELF,
            "manage_others strand watch writes cannot set level=muted",
        ));
    }
    if payload.level_public == Some(true) {
        return Err(event_validation_error(
            StatusCode::PRECONDITION_FAILED,
            arkret_wire::ReasonCode::WATCH_LEVEL_PUBLIC_MUST_BE_SELF,
            "manage_others strand watch writes cannot set level_public=true",
        ));
    }
    // The write is the first Event of the pair to form, so it cannot name the
    // audit that names it. Rejecting the pre-migration shape here means a
    // producer still authoring the old mutual edge fails on the edge itself
    // rather than on an `event_id` that cannot be computed.
    if !event_refs_with_role(object, AUDIT_PAIR_ROLE)?.is_empty() {
        return Err(manage_others_audit_error(
            "a cross-actor strand watch write MUST NOT reference its audit event; \
             the audit_pair edge runs audit -> write",
        ));
    }
    Ok(())
}

/// Batch half: every cross-actor `.others` watch write MUST be paired with exactly one
/// `ak.audit.accessed` Event **in the same submit batch**, and the pairing edge runs
/// audit -> write (strand-and-message.md 8.4).
///
/// The direction is forced: `refs` is inside the `event_digest` preimage and `event_id`
/// derives from that digest, so a write naming its audit while the audit commits to the
/// write's id and digest would make the two Events preimages of each other, with no fixed
/// point (encoding.md 6.0.1). The write is therefore formed first and the audit second,
/// which is also why this cannot be decided one envelope at a time.
pub(in crate::routing) fn validate_watch_set_others_audit_pairs(
    state: &AppState,
    envelopes: &[Value],
) -> Result<(), EventValidationError> {
    validate_watch_set_others_audit_pairs_with_digest(envelopes, |envelope, object, realm_id| {
        let suite = event_digest_suite(
            state,
            arkret_wire::EventKind::StrandWatchSet.as_str(),
            realm_id,
            object,
            &[],
        )?;
        let canonical_bytes = event_canonical_bytes(envelope)?;
        event_digest_for_suite(&canonical_bytes, &suite)
    })
}

/// Digest resolution is injected so the pairing rule itself is testable without an
/// `AppState`; the only thing the state supplies is the Realm's live digest suite.
fn validate_watch_set_others_audit_pairs_with_digest<F>(
    envelopes: &[Value],
    write_digest: F,
) -> Result<(), EventValidationError>
where
    F: Fn(&Value, &serde_json::Map<String, Value>, &str) -> Result<String, EventValidationError>,
{
    // Audits whose payload does not parse are not collected: they cannot pair,
    // and the envelope pass that runs after this one reports the real reason.
    let audits: Vec<(&serde_json::Map<String, Value>, AuditAccessedPayload)> = envelopes
        .iter()
        .filter_map(Value::as_object)
        .filter(|object| {
            object.get("kind").and_then(Value::as_str)
                == Some(arkret_wire::EventKind::AuditAccessed.as_str())
        })
        .filter_map(|object| Some((object, audit_accessed_payload(object).ok()?)))
        .collect();

    for envelope in envelopes {
        let Some(object) = envelope.as_object() else {
            continue;
        };
        if object.get("kind").and_then(Value::as_str)
            != Some(arkret_wire::EventKind::StrandWatchSet.as_str())
        {
            continue;
        }
        let (Some(actor_id), Some(event_id)) = (
            object.get("actor_id").and_then(Value::as_str),
            object.get("event_id").and_then(Value::as_str),
        ) else {
            continue;
        };
        let payload = strand_watch_set_payload(object)?;
        if payload.watcher_actor_id.as_str() == actor_id {
            continue;
        }
        // The cell the audit has to name comes from the SDK payload type, which
        // is pinned to the registered `cell_writes` contract — not re-derived
        // here, where it could drift from what the reducer actually writes.
        let target_cell_id = payload.cell_ref().map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("strand watch payload does not resolve a watch cell: {error}"),
            )
        })?;
        let realm_id = object
            .get("realm_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let canonical_digest = write_digest(envelope, object, realm_id)?;

        let matches = audits
            .iter()
            .filter(|(audit, audit_payload)| {
                matches!(audit_payload.access_kind, AuditAccessedKind::WatchSetOthers)
                    && audit_payload.writer_actor_id.as_str() == actor_id
                    && audit_payload.target_actor_id.as_ref()
                        == Some(&payload.watcher_actor_id)
                    && audit_payload.target_ref == payload.strand_id.as_str()
                    && audit_payload.target_cell_id.as_ref() == Some(&target_cell_id)
                    && audit_payload
                        .paired_event_id
                        .as_ref()
                        .is_some_and(|paired| paired.as_str() == event_id)
                    && audit_payload
                        .paired_event_digest
                        .as_ref()
                        .is_some_and(|digest| digest.as_str() == canonical_digest)
                    // The payload binding is what the write's own digest
                    // covers; the `refs` edge is what makes the audit a causal
                    // dependent of it. Requiring both keeps the surviving
                    // direction complete rather than half-authored.
                    && event_refs_with_role(audit, AUDIT_PAIR_ROLE).is_ok_and(|refs| {
                        refs.iter()
                            .any(|edge| edge.id == event_id && edge.critical)
                    })
            })
            .count();
        match matches {
            1 => {}
            0 => {
                return Err(manage_others_audit_error(
                    "cross-actor strand watch writes require a same-batch ak.audit.accessed event \
                     whose refs[role=audit_pair], paired_event_id and paired_event_digest name \
                     this write",
                ));
            }
            _ => {
                return Err(manage_others_audit_error(
                    "cross-actor strand watch writes require exactly one paired \
                     ak.audit.accessed event in the batch",
                ));
            }
        }
    }
    Ok(())
}

/// One `refs[]` entry carrying the requested role.
///
/// `critical` travels with the id because the audit pairing edge is specified
/// as `critical: true`: a non-critical edge is a weaker claim and MUST NOT
/// satisfy the pairing, while on the write side *any* `audit_pair` entry is
/// already the wrong direction.
struct RoleRef {
    id: String,
    critical: bool,
}

fn event_refs_with_role(
    object: &serde_json::Map<String, Value>,
    role: &str,
) -> Result<Vec<RoleRef>, EventValidationError> {
    let Some(values) = object.get("refs").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut refs = Vec::new();
    for value in values {
        let Some(reference) = value.as_object() else {
            continue;
        };
        if reference.get("role").and_then(Value::as_str) == Some(role) {
            let id = reference.get("id").and_then(Value::as_str).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "refs entries require id",
                )
            })?;
            if !is_valid_event_id(id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "audit_pair refs must use ak:event: typed ids",
                ));
            }
            refs.push(RoleRef {
                id: id.to_owned(),
                critical: reference.get("critical").and_then(Value::as_bool) == Some(true),
            });
        }
    }
    Ok(refs)
}

fn manage_others_audit_error(message: impl Into<String>) -> EventValidationError {
    event_validation_error(
        StatusCode::PRECONDITION_FAILED,
        arkret_wire::ReasonCode::WATCH_SET_OTHERS_AUDIT_MISSING,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(kind: &str) -> ValidatedEventEnvelope {
        ValidatedEventEnvelope {
            event_id: "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000002".to_owned(),
            actor_seq: 1,
            realm_id: "ak:realm:AdA2LFMgPUC2EAmzvOPY69_DX8_NLEXKyCwX9zR989nv".to_owned(),
            kind: kind.to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            prev_refs: Vec::new(),
            canonical_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            canonical_bytes: Vec::new(),
        }
    }

    const WRITE_ID: &str = "ak:event:AcLYVbj_1rgVJeGiPPDHp4GUgpcNGjkVCg8NW-2p21m6";
    const WRITE_DIGEST: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const WRITER: &str = "did:web:alice.example";
    const TARGET: &str = "did:web:bob.example";
    const STRAND: &str = "ak:strand:AU6JCWNYlBGUETxX5NBB9hy8YgtevzngI2Yj3vKnYDWb";

    fn others_watch_write() -> Value {
        json!({
            "event_id": WRITE_ID,
            "kind": arkret_wire::EventKind::StrandWatchSet,
            "actor_id": WRITER,
            "realm_id": "ak:realm:AdA2LFMgPUC2EAmzvOPY69_DX8_NLEXKyCwX9zR989nv",
            "payload": {
                "strand_id": STRAND,
                "watcher_actor_id": TARGET,
                "level": "participating"
            }
        })
    }

    fn watch_cell_id() -> String {
        strand_watch_set_payload(others_watch_write().as_object().unwrap())
            .expect("the fixture write carries a valid strand_watch_set payload")
            .cell_ref()
            .expect("the watch payload resolves its cas_register cell")
            .as_str()
            .to_owned()
    }

    fn paired_audit() -> Value {
        json!({
            "event_id": "ak:event:ARYFDQjhXHE479tnu9g71RR9SxducTw_bWQIMigD_pYL",
            "kind": arkret_wire::EventKind::AuditAccessed,
            "actor_id": WRITER,
            "refs": [{"id": WRITE_ID, "role": "audit_pair", "critical": true}],
            "payload": {
                "access_kind": "watch_set_others",
                "writer_actor_id": WRITER,
                "target_actor_id": TARGET,
                "target_ref": STRAND,
                "target_cell_id": watch_cell_id(),
                "paired_event_id": WRITE_ID,
                "paired_event_digest": WRITE_DIGEST,
                "cell_head_before": null,
                "cell_head_after": WRITE_DIGEST,
                "purpose": "seed strand watchers on create",
                "accessed_at": "2026-08-06T00:00:00.000Z"
            }
        })
    }

    fn check(envelopes: &[Value]) -> Result<(), EventValidationError> {
        validate_watch_set_others_audit_pairs_with_digest(envelopes, |_, _, _| {
            Ok(WRITE_DIGEST.to_owned())
        })
    }

    #[test]
    fn others_watch_write_needs_a_same_batch_audit_naming_it() {
        check(&[others_watch_write(), paired_audit()]).expect("the paired batch is admissible");

        let alone = check(&[others_watch_write()]).expect_err("a lone .others write is rejected");
        assert_eq!(
            alone.code,
            arkret_wire::ReasonCode::WATCH_SET_OTHERS_AUDIT_MISSING
        );
        assert_eq!(alone.status, StatusCode::PRECONDITION_FAILED);

        // The write does not name the audit, so a stale digest is the only thing that can
        // point the audit at a different write.
        let mut wrong_digest = paired_audit();
        wrong_digest["payload"]["paired_event_digest"] =
            json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        check(&[others_watch_write(), wrong_digest])
            .expect_err("an audit that names another write does not pair");

        let mut wrong_target = paired_audit();
        wrong_target["payload"]["target_actor_id"] = json!("did:web:carol.example");
        check(&[others_watch_write(), wrong_target])
            .expect_err("an audit for another target does not pair");
    }

    #[test]
    fn duplicate_audits_for_one_write_are_rejected() {
        check(&[others_watch_write(), paired_audit(), paired_audit()])
            .expect_err("two audits naming the same write are ambiguous");
    }

    #[test]
    fn self_watch_writes_need_no_audit() {
        let mut own = others_watch_write();
        own["payload"]["watcher_actor_id"] = json!(WRITER);
        check(&[own]).expect("writing your own watch state needs no audit pair");
    }

    /// The pre-migration audit shape carried `writer_did`. It has to stop
    /// pairing, or the rename would be cosmetic: an old producer would keep
    /// getting `.others` writes admitted against a field the schema no longer
    /// knows.
    #[test]
    fn the_pre_migration_writer_field_no_longer_pairs() {
        let mut legacy = paired_audit();
        let payload = legacy["payload"].as_object_mut().unwrap();
        let writer = payload.remove("writer_actor_id").unwrap();
        payload.insert("writer_did".to_owned(), writer);

        check(&[others_watch_write(), legacy])
            .expect_err("an audit using the removed writer_did field does not pair");
    }

    #[test]
    fn the_audit_pair_edge_must_be_present_and_critical() {
        let mut no_edge = paired_audit();
        no_edge["refs"] = json!([]);
        check(&[others_watch_write(), no_edge])
            .expect_err("an audit without refs[role=audit_pair] does not pair");

        let mut not_critical = paired_audit();
        not_critical["refs"] = json!([{"id": WRITE_ID, "role": "audit_pair", "critical": false}]);
        check(&[others_watch_write(), not_critical])
            .expect_err("a non-critical audit_pair edge does not pair");
    }

    #[test]
    fn the_audit_must_name_the_cell_the_write_targets() {
        let mut wrong_cell = paired_audit();
        wrong_cell["payload"]["target_cell_id"] =
            json!("ak:cell:ak.component.strand.watch.v1:not-the-subject");
        check(&[others_watch_write(), wrong_cell])
            .expect_err("an audit naming another watch cell does not pair");
    }

    /// The write forms first, so naming the audit is the cycle the migration
    /// removed. Rejecting it is what stops a pre-migration producer from
    /// getting a confusing digest failure instead of the real reason.
    #[test]
    fn a_cross_actor_write_must_not_reference_its_audit() {
        let mut old_direction = others_watch_write();
        old_direction["refs"] = json!([{
            "id": "ak:event:ARYFDQjhXHE479tnu9g71RR9SxducTw_bWQIMigD_pYL",
            "role": "audit_pair",
            "critical": true
        }]);
        let error = validate_strand_watch_manage_others_levels(
            arkret_wire::EventKind::StrandWatchSet.as_str(),
            old_direction.as_object().unwrap(),
            WRITER,
        )
        .expect_err("the write must not carry the audit_pair edge");
        assert_eq!(
            error.code,
            arkret_wire::ReasonCode::WATCH_SET_OTHERS_AUDIT_MISSING
        );

        validate_strand_watch_manage_others_levels(
            arkret_wire::EventKind::StrandWatchSet.as_str(),
            others_watch_write().as_object().unwrap(),
            WRITER,
        )
        .expect("the one-way shape is admissible");
    }

    #[test]
    fn muted_and_public_levels_report_their_own_reason_codes() {
        let mut muted = others_watch_write();
        muted["payload"]["level"] = json!("muted");
        assert_eq!(
            validate_strand_watch_manage_others_levels(
                arkret_wire::EventKind::StrandWatchSet.as_str(),
                muted.as_object().unwrap(),
                WRITER,
            )
            .expect_err("muted cannot be written for someone else")
            .code,
            arkret_wire::ReasonCode::WATCH_MUTED_MUST_BE_SELF
        );

        let mut public = others_watch_write();
        public["payload"]["level_public"] = json!(true);
        assert_eq!(
            validate_strand_watch_manage_others_levels(
                arkret_wire::EventKind::StrandWatchSet.as_str(),
                public.as_object().unwrap(),
                WRITER,
            )
            .expect_err("level_public is a personal opt-in")
            .code,
            arkret_wire::ReasonCode::WATCH_LEVEL_PUBLIC_MUST_BE_SELF
        );
    }

    #[test]
    fn the_audit_writer_must_be_the_audit_events_own_actor() {
        let mut impersonating = paired_audit();
        impersonating["actor_id"] = json!(TARGET);
        let error = validate_audit_accessed_payload(
            arkret_wire::EventKind::AuditAccessed.as_str(),
            impersonating.as_object().unwrap(),
        )
        .expect_err("an audit cannot record a write as someone else");
        assert_eq!(error.code, "actor_session_mismatch");

        validate_audit_accessed_payload(
            arkret_wire::EventKind::AuditAccessed.as_str(),
            paired_audit().as_object().unwrap(),
        )
        .expect("the paired audit fixture is well formed");
    }

    #[test]
    fn encrypted_message_franking_is_not_gated_by_audit_applet_policy() {
        let proof = encrypted_message_franking_proof(
            "did:web:soland.example",
            &parsed(arkret_wire::EventKind::MessageCreate.as_str()),
            &json!({
                "payload": {
                    "encrypted_content": {
                        "payload_digest":
                            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    }
                }
            }),
        )
        .expect("encrypted messages get a local moderation franking proof");

        assert_eq!(
            proof.get("kind").and_then(Value::as_str),
            Some(arkret_wire::EventKind::ModerationFrankingProof.as_str())
        );
        assert_eq!(
            proof.get("receiving_service_id").and_then(Value::as_str),
            Some("did:web:soland.example")
        );
        assert!(proof.get("audit_disclosure_policy").is_none());
        assert!(proof.get("proof_digest").is_some());
    }

    #[test]
    fn plaintext_messages_do_not_get_a_franking_proof() {
        assert!(
            encrypted_message_franking_proof(
                "did:web:soland.example",
                &parsed(arkret_wire::EventKind::MessageCreate.as_str()),
                &json!({"payload": {"content": {"body": "hello"}}}),
            )
            .is_none()
        );
    }
}
