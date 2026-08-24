use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_models_collaboration::governance::join_policy::JoinApplicationAuditAction;
use arkret_wire::{DidCoreId, Hash};
use parking_lot::Mutex;
use soland_storage::{
    JoinApplicationCommand, JoinApplicationCommandOutcome, JoinApplicationIdempotencyRecord,
    JoinApplicationRecord, JoinApplicationStore, PersistenceError, PersistenceResult,
    apply_join_application_mutation, join_application_mutation_receipt_ref,
    join_application_response_body,
};

#[derive(Default)]
struct MemoryJoinApplicationState {
    records: BTreeMap<(String, String), JoinApplicationRecord>,
    idempotency: BTreeMap<(String, String), JoinApplicationIdempotencyRecord>,
}

pub(crate) struct MemoryJoinApplicationStore {
    state: Arc<Mutex<MemoryJoinApplicationState>>,
}

impl MemoryJoinApplicationStore {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryJoinApplicationState::default())),
        }
    }
}

#[async_trait::async_trait]
impl JoinApplicationStore for MemoryJoinApplicationStore {
    async fn execute(
        &self,
        command: JoinApplicationCommand,
    ) -> PersistenceResult<JoinApplicationCommandOutcome> {
        let mut state = self.state.lock();
        state
            .idempotency
            .retain(|_, record| record.expires_at > chrono::Utc::now());
        let idempotency_key = (
            command.principal_id.clone(),
            command.idempotency_key.clone(),
        );
        if let Some(existing) = state.idempotency.get(&idempotency_key) {
            if existing.request_hash != command.request_hash {
                return Ok(JoinApplicationCommandOutcome::IdempotencyConflict);
            }
            let record = state
                .records
                .values()
                .find(|record| record.application_ref == existing.application_ref)
                .cloned()
                .ok_or_else(|| {
                    PersistenceError::Internal(
                        "join application idempotency row points to a missing record".to_owned(),
                    )
                })?;
            return Ok(JoinApplicationCommandOutcome::Replay {
                response_body: existing.response_body.clone(),
                record,
            });
        }

        let receipt_ref = join_application_mutation_receipt_ref(&command.mutation);
        let record = apply_join_application_mutation(&mut state.records, command.mutation)?;
        let response_body = join_application_response_body(&record, &receipt_ref);
        state.idempotency.insert(
            idempotency_key,
            JoinApplicationIdempotencyRecord {
                principal_id: command.principal_id,
                idempotency_key: command.idempotency_key,
                request_hash: command.request_hash,
                response_body: response_body.clone(),
                application_ref: record.application_ref.clone(),
                expires_at: command.idempotency_expires_at,
            },
        );
        Ok(JoinApplicationCommandOutcome::Applied {
            response_body,
            record,
        })
    }

    async fn get(
        &self,
        realm_id: &str,
        application_ref: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<JoinApplicationRecord>> {
        let mut state = self.state.lock();
        let Some(record) = state
            .records
            .get_mut(&(realm_id.to_owned(), application_ref.to_owned()))
        else {
            return Ok(None);
        };
        record.refresh_expiry(now);
        Ok(Some(record.clone()))
    }

    async fn list(
        &self,
        realm_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<JoinApplicationRecord>> {
        let mut state = self.state.lock();
        let mut records = state
            .records
            .iter_mut()
            .filter(|((record_realm, _), _)| record_realm == realm_id)
            .map(|(_, record)| {
                record.refresh_expiry(now);
                record.clone()
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| {
            (
                record.receipt.submitted_at,
                record.application_ref.as_str().to_owned(),
            )
        });
        Ok(records)
    }

    async fn append_read_audit(
        &self,
        realm_id: &str,
        application_ref: &str,
        actor_id: &str,
        occurred_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let mut state = self.state.lock();
        let record = state
            .records
            .get_mut(&(realm_id.to_owned(), application_ref.to_owned()))
            .ok_or_else(|| PersistenceError::NotFound("join application".to_owned()))?;
        let actor_id = DidCoreId::new(actor_id.to_owned())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let receipt_ref = Hash::new(application_ref.to_owned())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        record.append_audit(
            JoinApplicationAuditAction::Read,
            actor_id,
            occurred_at,
            receipt_ref,
        );
        Ok(())
    }

    async fn consume_review_authorisations(
        &self,
        realm_id: &str,
        review_receipt_digests: &[String],
        actor_id: &str,
        occurred_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        if review_receipt_digests.is_empty() {
            return Ok(false);
        }
        let mut state = self.state.lock();
        let Some(record) = state.records.values_mut().find(|record| {
            record.receipt.realm_id.as_str() == realm_id
                && record
                    .required_accept_refs
                    .iter()
                    .map(arkret_wire::Hash::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
                    == review_receipt_digests
                        .iter()
                        .map(String::as_str)
                        .collect::<std::collections::BTreeSet<_>>()
                && record.required_accept_refs.len() == review_receipt_digests.len()
        }) else {
            return Ok(false);
        };
        record.refresh_expiry(occurred_at);
        if record.invite_consumed
            && record.status
                == arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::Consumed
        {
            return Ok(true);
        }
        if record.status
            != arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::Accepted
            || record.invite_consumed
        {
            return Ok(false);
        }
        let actor_id = DidCoreId::new(actor_id.to_owned())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        record.invite_consumed = true;
        record.status =
            arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::Consumed;
        for digest in review_receipt_digests {
            let receipt_ref = Hash::new(digest.clone())
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            record.append_audit(
                JoinApplicationAuditAction::InviteConsumed,
                actor_id.clone(),
                occurred_at,
                receipt_ref,
            );
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::governance::join_policy::JoinApplicationReviewReceipt;
    use chrono::{DateTime, Duration, Utc};
    use serde_json::json;
    use soland_storage::{
        JoinApplicationCommand, JoinApplicationCommandOutcome, JoinApplicationMutation,
        JoinApplicationRecord, JoinApplicationStore,
    };

    use super::MemoryJoinApplicationStore;

    const REALM: &str = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";
    const APPLICANT: &str = "ak:did_core:web:alice.example";
    const KNOCK: &str = "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";

    fn at(second: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("2026-07-24T00:00:{second:02}.000Z"))
            .unwrap()
            .with_timezone(&Utc)
    }

    fn hash(fill: char) -> String {
        format!("sha256:{}", fill.to_string().repeat(64))
    }

    fn application_record() -> JoinApplicationRecord {
        serde_json::from_value(json!({
            "application_ref": hash('a'),
            "receipt": {
                "candidate_kind": "member.application",
                "realm_id": REALM,
                "applicant_actor_id": APPLICANT,
                "knock_ref": KNOCK,
                "policy_version_digest": hash('b'),
                "application_revision_digest": hash('c'),
                "private_body_digest": hash('d'),
                "submitted_at": "2026-07-24T00:00:00.000Z",
                "application_receipt_digest": hash('a'),
                "proof": {
                    "kind": "detached_jws",
                    "verification_method": "did:web:alice.example#device",
                    "payload_digest": hash('a'),
                    "created_at": "2026-07-24T00:00:00.000Z",
                    "jws": "eyJhbGciOiJFZDI1NTE5In0..AQ"
                }
            },
            "private_body": {
                "mode": "server_protected",
                "answers": [],
                "gate_proofs": []
            },
            "status": "awaiting_review",
            "applicant_visibility": "reviewer_only",
            "expires_at": "2026-07-25T00:00:00.000Z",
            "reviews": [],
            "required_accept_refs": [],
            "invite_consumed": false,
            "audit_entries": [],
            "updated_at": "2026-07-24T00:00:00.000Z"
        }))
        .unwrap()
    }

    fn accept_review(
        reviewer: &str,
        grant: &str,
        digest_fill: char,
        second: u32,
    ) -> JoinApplicationReviewReceipt {
        accept_review_at_authority(
            reviewer,
            "ak:did_core:web:principal.example",
            grant,
            digest_fill,
            second,
        )
    }

    fn accept_review_at_authority(
        reviewer: &str,
        reviewer_principal_server_id: &str,
        grant: &str,
        digest_fill: char,
        second: u32,
    ) -> JoinApplicationReviewReceipt {
        let digest = hash(digest_fill);
        let reviewer_verification_method = format!(
            "did:{}#device",
            reviewer
                .strip_prefix("ak:did_core:")
                .expect("reviewer fixture is a core DID")
        );
        serde_json::from_value(json!({
            "candidate_kind": "member.application.review",
            "realm_id": REALM,
            "application_ref": hash('a'),
            "application_revision_digest": hash('c'),
            "reviewer_actor_id": reviewer,
            "reviewer_principal_server_id": reviewer_principal_server_id,
            "decision": "accept",
            "evidence_refs": [],
            "reviewer_capability_proof": {
                "grant_id": grant,
                "frontier_digest": hash('f')
            },
            "reviewed_at": format!("2026-07-24T00:00:{second:02}.000Z"),
            "review_receipt_digest": digest,
            "proof": {
                "kind": "detached_jws",
                "verification_method": reviewer_verification_method,
                "payload_digest": digest,
                "created_at": format!("2026-07-24T00:00:{second:02}.000Z"),
                "jws": "eyJhbGciOiJFZDI1NTE5In0..AQ"
            }
        }))
        .unwrap()
    }

    fn command(
        key: &str,
        request_hash: &str,
        mutation: JoinApplicationMutation,
    ) -> JoinApplicationCommand {
        JoinApplicationCommand {
            principal_id: APPLICANT.to_owned(),
            idempotency_key: key.to_owned(),
            request_hash: request_hash.to_owned(),
            idempotency_expires_at: Utc::now() + Duration::days(30),
            mutation,
        }
    }

    #[tokio::test]
    async fn idempotency_quorum_and_atomic_multi_ref_consumption() {
        let store = MemoryJoinApplicationStore::new();
        let submit = command(
            "submit-1",
            "request-submit",
            JoinApplicationMutation::Submit {
                record: Box::new(application_record()),
                max_open_applications: 1,
                cooldown_after_reject_seconds: 60,
            },
        );
        assert!(matches!(
            store.execute(submit.clone()).await.unwrap(),
            JoinApplicationCommandOutcome::Applied { .. }
        ));
        assert!(matches!(
            store.execute(submit.clone()).await.unwrap(),
            JoinApplicationCommandOutcome::Replay { .. }
        ));
        let mut conflicting = submit;
        conflicting.request_hash = "different-request".to_owned();
        assert_eq!(
            store.execute(conflicting).await.unwrap(),
            JoinApplicationCommandOutcome::IdempotencyConflict
        );

        let first = accept_review(
            "ak:did_core:web:reviewer-one.example",
            "ak:grant:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            '1',
            1,
        );
        let first_ref = first.review_receipt_digest.to_string();
        let first_outcome = store
            .execute(command(
                "review-1",
                "request-review-1",
                JoinApplicationMutation::Review {
                    realm_id: REALM.to_owned(),
                    application_ref: arkret_wire::Hash::new(hash('a')).unwrap(),
                    receipt: first,
                    accept_threshold: 2,
                },
            ))
            .await
            .unwrap();
        let JoinApplicationCommandOutcome::Applied { record, .. } = first_outcome else {
            panic!("first review should apply");
        };
        assert_eq!(
            record.status,
            arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::AwaitingReview
        );
        assert!(record.required_accept_refs.is_empty());

        let second = accept_review(
            "ak:did_core:web:reviewer-two.example",
            "ak:grant:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg",
            '2',
            2,
        );
        let second_ref = second.review_receipt_digest.to_string();
        let second_outcome = store
            .execute(command(
                "review-2",
                "request-review-2",
                JoinApplicationMutation::Review {
                    realm_id: REALM.to_owned(),
                    application_ref: arkret_wire::Hash::new(hash('a')).unwrap(),
                    receipt: second,
                    accept_threshold: 2,
                },
            ))
            .await
            .unwrap();
        let JoinApplicationCommandOutcome::Applied { record, .. } = second_outcome else {
            panic!("second review should apply");
        };
        assert_eq!(
            record.status,
            arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::Accepted
        );
        assert_eq!(record.required_accept_refs.len(), 2);

        assert!(
            !store
                .consume_review_authorisations(
                    REALM,
                    std::slice::from_ref(&first_ref),
                    APPLICANT,
                    at(3)
                )
                .await
                .unwrap()
        );
        let complete = vec![first_ref, second_ref];
        assert!(
            store
                .consume_review_authorisations(REALM, &complete, APPLICANT, at(3))
                .await
                .unwrap()
        );
        assert!(
            store
                .consume_review_authorisations(REALM, &complete, APPLICANT, at(3))
                .await
                .unwrap(),
            "reconciliation replay must be idempotent"
        );
        let consumed = store.get(REALM, &hash('a'), at(4)).await.unwrap().unwrap();
        assert!(consumed.invite_consumed);
        assert_eq!(
            consumed.status,
            arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::Consumed
        );
        assert_eq!(
            consumed
                .audit_entries
                .iter()
                .filter(|entry| entry.action
                    == arkret_models_collaboration::governance::join_policy::JoinApplicationAuditAction::InviteConsumed)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn request_changes_can_be_revised_without_exceeding_open_limit() {
        let store = MemoryJoinApplicationStore::new();
        store
            .execute(command(
                "submit-original",
                "request-original",
                JoinApplicationMutation::Submit {
                    record: Box::new(application_record()),
                    max_open_applications: 1,
                    cooldown_after_reject_seconds: 60,
                },
            ))
            .await
            .unwrap();
        let mut review_value = serde_json::to_value(accept_review(
            "ak:did_core:web:reviewer.example",
            "ak:grant:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            '3',
            1,
        ))
        .unwrap();
        review_value["decision"] = json!("request_changes");
        review_value["reason_code"] = json!("other");
        let request_changes = serde_json::from_value(review_value).unwrap();
        store
            .execute(command(
                "request-changes",
                "request-review",
                JoinApplicationMutation::Review {
                    realm_id: REALM.to_owned(),
                    application_ref: arkret_wire::Hash::new(hash('a')).unwrap(),
                    receipt: request_changes,
                    accept_threshold: 1,
                },
            ))
            .await
            .unwrap();

        let mut revision = application_record();
        revision.application_ref = arkret_wire::Hash::new(hash('e')).unwrap();
        revision.receipt.application_receipt_digest = arkret_wire::Hash::new(hash('e')).unwrap();
        revision.receipt.application_revision_digest = arkret_wire::Hash::new(hash('9')).unwrap();
        revision.receipt.proof.payload_digest = arkret_wire::Hash::new(hash('e')).unwrap();
        revision.receipt.submitted_at = at(2);
        revision.receipt.proof.created_at = at(2);
        revision.updated_at = at(2);
        let outcome = store
            .execute(command(
                "submit-revision",
                "request-revision",
                JoinApplicationMutation::Submit {
                    record: Box::new(revision),
                    max_open_applications: 1,
                    cooldown_after_reject_seconds: 60,
                },
            ))
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            JoinApplicationCommandOutcome::Applied { .. }
        ));
        let original = store.get(REALM, &hash('a'), at(3)).await.unwrap().unwrap();
        assert_eq!(
            original.superseded_by.as_ref().map(ToString::to_string),
            Some(hash('e'))
        );
        let applications = store.list(REALM, at(3)).await.unwrap();
        assert_eq!(
            applications
                .iter()
                .filter(|record| record.is_open())
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn quorum_deduplicates_actor_and_uses_digest_winner_independent_of_arrival() {
        async fn run(digest_order: [char; 2]) -> Vec<String> {
            let store = MemoryJoinApplicationStore::new();
            store
                .execute(command(
                    "submit-quorum",
                    "request-submit-quorum",
                    JoinApplicationMutation::Submit {
                        record: Box::new(application_record()),
                        max_open_applications: 1,
                        cooldown_after_reject_seconds: 60,
                    },
                ))
                .await
                .unwrap();

            for (index, digest_fill) in digest_order.into_iter().enumerate() {
                let receipt = accept_review_at_authority(
                    "ak:did_core:web:reviewer-one.example",
                    if index == 0 {
                        "ak:did_core:web:principal-one.example"
                    } else {
                        "ak:did_core:web:principal-two.example"
                    },
                    "ak:grant:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
                    digest_fill,
                    index as u32 + 1,
                );
                let outcome = store
                    .execute(command(
                        &format!("review-same-{index}"),
                        &format!("request-review-same-{index}"),
                        JoinApplicationMutation::Review {
                            realm_id: REALM.to_owned(),
                            application_ref: arkret_wire::Hash::new(hash('a')).unwrap(),
                            receipt,
                            accept_threshold: 2,
                        },
                    ))
                    .await
                    .unwrap();
                let JoinApplicationCommandOutcome::Applied { record, .. } = outcome else {
                    panic!("same-actor review should apply");
                };
                assert_eq!(
                    record.status,
                    arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::AwaitingReview,
                    "multiple Principal Server accounts must still count as one reviewer"
                );
            }

            let second_actor = accept_review(
                "ak:did_core:web:reviewer-two.example",
                "ak:grant:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg",
                '2',
                3,
            );
            let outcome = store
                .execute(command(
                    "review-distinct",
                    "request-review-distinct",
                    JoinApplicationMutation::Review {
                        realm_id: REALM.to_owned(),
                        application_ref: arkret_wire::Hash::new(hash('a')).unwrap(),
                        receipt: second_actor,
                        accept_threshold: 2,
                    },
                ))
                .await
                .unwrap();
            let JoinApplicationCommandOutcome::Applied { record, .. } = outcome else {
                panic!("distinct reviewer should complete quorum");
            };
            assert_eq!(
                record.status,
                arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::Accepted
            );
            record
                .required_accept_refs
                .into_iter()
                .map(|digest| digest.to_string())
                .collect()
        }

        let forward = run(['1', '9']).await;
        let reverse = run(['9', '1']).await;
        assert_eq!(forward, reverse);
        assert!(forward.contains(&hash('9')));
        assert!(!forward.contains(&hash('1')));
        assert_eq!(forward.len(), 2);
    }
}
