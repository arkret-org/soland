//! Immutable publication dependencies retained before Agent approval finality.

use diesel::sql_types::{BigInt, Binary, Jsonb, SmallInt};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{EventCommitRequest, PersistenceError, PersistenceResult, ids};

#[derive(QueryableByName)]
struct PublicationRow {
    #[diesel(sql_type = Binary)]
    publication_event_id: Vec<u8>,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    approval: serde_json::Value,
    #[diesel(sql_type = SmallInt)]
    digest_suite: i16,
}

fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(error.to_string())
}

pub(super) async fn load(
    conn: &mut AsyncPgConnection,
    approval_event_id: &arkret_wire::EventId,
) -> PersistenceResult<Option<arkret_wire::Event>> {
    let id = ids::parse_event_id(approval_event_id.as_str())
        .ok_or_else(|| invalid("invalid approval EventId"))?;
    let row = sql_query("SELECT publication.publication_event_id, publication.canonical_bytes, approval.envelope AS approval, approval.digest_suite FROM agent_approval_publications publication JOIN canonical_events approval ON approval.pk = publication.approval_event_pk WHERE approval.id = $1 AND approval.state <> 'quarantined'")
        .bind::<Binary, _>(id.to_vec())
        .get_result::<PublicationRow>(conn).await.optional().map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let publication: arkret_wire::Event =
        serde_json::from_slice(&row.canonical_bytes).map_err(invalid)?;
    let canonical = arkret_canonical::canonical_json_bytes(&publication).map_err(invalid)?;
    let approval: arkret_wire::Event = serde_json::from_value(row.approval).map_err(invalid)?;
    let suite = match row.digest_suite {
        1 => arkret_canonical::DigestSuite::Sha256,
        2 => arkret_canonical::DigestSuite::Blake3,
        _ => return Err(invalid("invalid stored approval digest suite")),
    };
    if canonical != row.canonical_bytes
        || approval.event_id != *approval_event_id
        || ids::parse_event_id(publication.event_id.as_str()).map(|id| id.to_vec())
            != Some(row.publication_event_id)
    {
        return Err(invalid(
            "stored approval publication identity or bytes disagree",
        ));
    }
    arkret_wire::event_submission::validate_approval_publication_event(
        &approval,
        Some(&publication),
        suite,
    )
    .map_err(invalid)?;
    Ok(Some(publication))
}

pub(crate) async fn commit(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    request: &EventCommitRequest,
    existing: bool,
) -> PersistenceResult<()> {
    let approval: arkret_wire::Event =
        serde_json::from_value(request.event.envelope.clone()).map_err(invalid)?;
    arkret_wire::event_submission::validate_approval_publication_event(
        &approval,
        request.publication_event.as_ref(),
        request.event.digest_suite,
    )
    .map_err(invalid)?;
    let Some(publication) = &request.publication_event else {
        return Ok(());
    };
    let canonical = arkret_canonical::canonical_json_bytes(publication).map_err(invalid)?;
    if existing {
        let retained = load(conn, &approval.event_id).await?.ok_or_else(|| {
            invalid("pending approval is missing its immutable publication dependency")
        })?;
        if arkret_canonical::canonical_json_bytes(&retained).map_err(invalid)? != canonical {
            return Err(PersistenceError::Conflict(
                "approval publication bytes differ on exact retry".to_owned(),
            ));
        }
        return Ok(());
    }
    let publication_id = ids::parse_event_id(publication.event_id.as_str())
        .ok_or_else(|| invalid("invalid publication EventId"))?;
    sql_query("INSERT INTO agent_approval_publications (approval_event_pk, publication_event_id, canonical_bytes) VALUES ($1, $2, $3)")
        .bind::<BigInt, _>(event_pk).bind::<Binary, _>(publication_id.to_vec()).bind::<Binary, _>(&canonical)
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_wire::{AccountId, ActorId, Event, EventId, Hash, ScopeRef};
    use diesel::sql_types::Text;
    use serde_json::json;
    use soland_storage::{EventBatchCommitRequest, EventCommitUnitOfWork, EventStore};

    use super::*;

    const SUITE: DigestSuite = DigestSuite::Sha256;

    fn request(marker: u8) -> EventCommitRequest {
        let timestamp = "2026-09-12T00:00:00.000Z".parse().unwrap();
        let realm = arkret_wire::RealmId::from_event_id(&EventId::from_digest(SUITE, [42; 32]));
        let actor = ActorId::account(AccountId::new(
            format!("ak:did_core:web:controller-{marker}.example")
                .parse()
                .unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ));
        let mut publication = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.message.create",
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            actor.clone(),
            0,
            "000000000000-0000-00000000".parse().unwrap(),
            json!({"body": "the exact pre-signed publication"}),
            timestamp,
        )
        .unwrap();
        publication.auth_context = Some(arkret_wire::AuthContext {
            key_id: arkret_wire::OpaqueLocalId::new("device-1").unwrap(),
            key_epoch: 1,
            credential_epoch: None,
            authority_refs: vec![
                format!("ak:seal:sha256:{}", "a".repeat(64))
                    .parse()
                    .unwrap(),
            ],
        });
        publication
            .refresh_content_bound_identity_with_digest_suite(SUITE)
            .unwrap();
        publication.proofs = vec![arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "did:web:controller-{marker}.example#device-1"
            ))
            .unwrap(),
            event_digest: Hash::new(publication.event_digest_with_digest_suite(SUITE).unwrap())
                .unwrap(),
            signer_resolution_evidence_ref: Some(
                arkret_wire::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "22".repeat(32)
                ))
                .unwrap(),
            ),
            created_at: timestamp,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "e30..c2ln".to_owned(),
        }];
        // These fixtures enter below producer authorization. Retention checks
        // structure and exact bytes; it cannot confer approval finality.
        let mut approval = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.agent.action_approve",
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            actor.clone(),
            0,
            "000000000000-0000-00000000".parse().unwrap(),
            json!({
                "approval_id": "approval-fixture",
                "agent_id": "ak:did_core:web:agent.example",
                "proposed_action": "ak.message.create",
                "target": {"kind": "realm", "realm_id": realm},
                "approved_event_id": publication.event_id,
                "approval_nonce": "AAAAAAAAAAAAAAAAAAAAAA",
                "approved_at": timestamp,
                "expires_at": "2026-09-12T00:05:00.000Z"
            }),
            timestamp,
        )
        .unwrap();
        approval.seal_basis = Some(arkret_wire::SealBasis {
            leaves: publication
                .auth_context
                .as_ref()
                .unwrap()
                .authority_refs
                .clone(),
        });
        approval
            .refresh_content_bound_identity_with_digest_suite(SUITE)
            .unwrap();
        let digest = approval.event_digest_with_digest_suite(SUITE).unwrap();
        let mut ack = arkret_wire::ControlProposalAck {
            kind: arkret_wire::ControlProposalAckKind::SignedAck,
            defer_count: 0,
            realm_id: realm.clone(),
            proposal_digest: digest.parse().unwrap(),
            received_at: timestamp,
            decision_due_at: timestamp + chrono::Duration::seconds(30),
            absolute_due_at: timestamp + chrono::Duration::seconds(90),
            authority_set_ref: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            signature: arkret_wire::PayloadSignature {
                verification_method: arkret_wire::DidUrl::new("did:web:station.example#key")
                    .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: timestamp,
                jws: "e30..c2ln".to_owned(),
            },
        };
        ack.signature.payload_digest = ack.ack_body_digest().unwrap();
        EventCommitRequest {
            publication_event: Some(publication),
            mls_public_producer: None,
            mls_public_genesis: None,
            mls_frontier_leaves: None,
            replicated: false,
            event: soland_storage::CanonicalEventRecord {
                event_id: approval.event_id.to_string(),
                actor_id: actor.canonical_key().unwrap(),
                actor_seq: 0,
                realm_id: Some(realm.to_string()),
                kind: approval.kind.as_str().to_owned(),
                schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
                digest_suite: SUITE,
                canonical_digest: digest,
                canonical_bytes: arkret_canonical::canonical_json_bytes(
                    &approval.digest_payload().unwrap(),
                )
                .unwrap(),
                envelope: serde_json::to_value(approval).unwrap(),
                received_at: timestamp,
            },
            membership_compensation_evidence: None,
            governance_dependencies: vec![],
            device_pairing_authorization: None,
            contact_projection: None,
            consent_projection: None,
            control_proposal_ingress: Some(
                arkret_state::state::store::ControlProposalIngress::AckRequired(ack),
            ),
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: vec![],
            idempotency: None,
            outbox: vec![],
        }
    }

    fn batch(events: Vec<EventCommitRequest>) -> EventBatchCommitRequest {
        EventBatchCommitRequest {
            events,
            franking_replay_nonce: None,
            applet_record: None,
            applet_authoring_preview: None,
            agent_membership_cascade: None,
        }
    }

    async fn retained(pool: &crate::PgPool, request: &EventCommitRequest) -> Option<Event> {
        // Recreate the public read adapter to exercise recovery from durable
        // bytes, rather than relying on any admission-process cache.
        crate::events::PgEventStore { pool: pool.clone() }
            .publication_event_for_approval(&request.event.event_id.parse().unwrap())
            .await
            .unwrap()
    }

    #[derive(QueryableByName, Debug)]
    struct Counts {
        #[diesel(sql_type = BigInt)]
        canonical: i64,
        #[diesel(sql_type = BigInt)]
        attachments: i64,
        #[diesel(sql_type = BigInt)]
        pending: i64,
        #[diesel(sql_type = BigInt)]
        decisions: i64,
        #[diesel(sql_type = BigInt)]
        effects: i64,
        #[diesel(sql_type = BigInt)]
        sources: i64,
        #[diesel(sql_type = BigInt)]
        timeline: i64,
    }

    async fn assert_pending_only(pool: &crate::PgPool, expected: i64) {
        let mut conn = crate::pg_conn(pool).await.unwrap();
        let counts = sql_query("SELECT (SELECT count(*) FROM canonical_events) AS canonical, (SELECT count(*) FROM agent_approval_publications) AS attachments, (SELECT count(*) FROM state_control_events) AS pending, (SELECT count(*) FROM state_seal_control_events) AS decisions, (SELECT count(*) FROM state_cell_ops) AS effects, (SELECT count(*) FROM current_data_sources) AS sources, (SELECT count(*) FROM projection_events) AS timeline")
            .get_result::<Counts>(&mut conn).await.unwrap();
        assert_eq!(counts.canonical, expected, "{counts:?}");
        assert_eq!(counts.attachments, expected, "{counts:?}");
        assert_eq!(counts.pending, expected, "{counts:?}");
        assert_eq!(
            (
                counts.decisions,
                counts.effects,
                counts.sources,
                counts.timeline
            ),
            (0, 0, 0, 0),
            "{counts:?}"
        );
    }

    #[tokio::test]
    async fn approval_publication_exact_retry_restores_pending_bytes_without_business_publication()
    {
        let db = crate::test_database::TestDatabase::lease().await;
        let pool = db.pool();
        let uow = crate::unit_of_work::PgEventCommitUnitOfWork::new(pool.clone());
        let request = request(1);
        assert!(
            uow.commit_event(request.clone())
                .await
                .unwrap()
                .event_inserted
        );
        assert!(
            !uow.commit_event(request.clone())
                .await
                .unwrap()
                .event_inserted
        );
        assert_eq!(retained(&pool, &request).await, request.publication_event);
        assert_pending_only(&pool, 1).await;
        let mut conn = crate::pg_conn(&pool).await.unwrap();
        let ordinary_id = request
            .publication_event
            .as_ref()
            .unwrap()
            .event_id
            .token_bytes();
        let absent =
            sql_query("SELECT NOT EXISTS(SELECT 1 FROM canonical_events WHERE id=$1) AS present")
                .bind::<Binary, _>(ordinary_id.to_vec())
                .get_result::<crate::ExistsRow>(&mut conn)
                .await
                .unwrap();
        assert!(absent.present);
    }

    #[tokio::test]
    async fn approval_publication_retry_rejects_changed_proofs_replacement_and_missing_attachment()
    {
        let db = crate::test_database::TestDatabase::lease().await;
        let pool = db.pool();
        let uow = crate::unit_of_work::PgEventCommitUnitOfWork::new(pool.clone());
        let request = request(2);
        uow.commit_event(request.clone()).await.unwrap();
        let mut proof_variant = request.clone();
        proof_variant.publication_event.as_mut().unwrap().proofs[0].jws = "e30..b3RoZXI".to_owned();
        assert_eq!(
            proof_variant.publication_event.as_ref().unwrap().event_id,
            request.publication_event.as_ref().unwrap().event_id
        );
        arkret_wire::event_submission::validate_approval_publication_event(
            &serde_json::from_value(request.event.envelope.clone()).unwrap(),
            proof_variant.publication_event.as_ref(),
            SUITE,
        )
        .unwrap();
        let error = uow.commit_event(proof_variant).await.unwrap_err();
        assert!(matches!(error, PersistenceError::Conflict(_)), "{error}");
        assert!(
            error.to_string().contains("publication bytes differ"),
            "{error}"
        );
        let mut replacement = request.clone();
        let publication = replacement.publication_event.as_mut().unwrap();
        publication
            .payload
            .insert("body".to_owned(), json!("replacement"));
        publication
            .refresh_content_bound_identity_with_digest_suite(SUITE)
            .unwrap();
        publication.proofs[0].event_digest =
            Hash::new(publication.event_digest_with_digest_suite(SUITE).unwrap()).unwrap();
        assert!(uow.commit_event(replacement).await.is_err());
        let mut missing = request.clone();
        missing.publication_event = None;
        assert!(uow.commit_event(missing).await.is_err());
        assert_eq!(retained(&pool, &request).await, request.publication_event);
        assert_pending_only(&pool, 1).await;
    }

    #[tokio::test]
    async fn approval_publication_batch_replay_conflict_rolls_back_first_dependency_and_ingress() {
        let db = crate::test_database::TestDatabase::lease().await;
        let pool = db.pool();
        let uow = crate::unit_of_work::PgEventCommitUnitOfWork::new(pool.clone());
        let first = request(3);
        let mut same_id_different_proof = first.clone();
        same_id_different_proof
            .publication_event
            .as_mut()
            .unwrap()
            .proofs[0]
            .jws = "e30..b3RoZXI".to_owned();
        let error = uow
            .commit_event_batch(batch(vec![first.clone(), same_id_different_proof]))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("publication bytes differ"),
            "{error}"
        );
        assert!(retained(&pool, &first).await.is_none());
        assert_pending_only(&pool, 0).await;
        let mut second_missing_dependency = request(4);
        second_missing_dependency.publication_event = None;
        let error = uow
            .commit_event_batch(batch(vec![first.clone(), second_missing_dependency]))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("publication_event is required exactly"),
            "{error}"
        );
        assert!(retained(&pool, &first).await.is_none());
        assert_pending_only(&pool, 0).await;
        assert!(
            uow.commit_event_batch(batch(vec![first.clone(), first.clone()]))
                .await
                .unwrap()
                .event_inserted
        );
        assert_eq!(retained(&pool, &first).await, first.publication_event);
        assert_pending_only(&pool, 1).await;
    }

    #[tokio::test]
    async fn approval_publication_quarantined_approval_cannot_supply_dependency() {
        let db = crate::test_database::TestDatabase::lease().await;
        let pool = db.pool();
        let request = request(5);
        crate::unit_of_work::PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(request.clone())
            .await
            .unwrap();
        let mut conn = crate::pg_conn(&pool).await.unwrap();
        sql_query("UPDATE canonical_events SET state='quarantined' WHERE envelope->>'event_id'=$1")
            .bind::<Text, _>(&request.event.event_id)
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(retained(&pool, &request).await.is_none());
        assert_pending_only(&pool, 1).await;
    }
}
