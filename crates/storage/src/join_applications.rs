use arkret_models_collaboration::governance::join_policy::{
    JoinApplicationAuditAction, JoinApplicationAuditEntry, JoinApplicationCancelReceipt,
    JoinApplicationDecision, JoinApplicationPrivateBody, JoinApplicationReceipt,
    JoinApplicationReviewReceipt, JoinApplicationStatus,
};
use arkret_wire::Hash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{PersistenceResult, async_trait};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JoinApplicationRecord {
    pub application_ref: Hash,
    pub receipt: JoinApplicationReceipt,
    pub private_body: JoinApplicationPrivateBody,
    pub status: JoinApplicationStatus,
    pub applicant_visibility: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub reviews: Vec<JoinApplicationReviewReceipt>,
    /// Exact accept-receipt set that first satisfied the reviewer quorum.
    /// Invite creation must cite this complete set.
    #[serde(default)]
    pub required_accept_refs: Vec<Hash>,
    /// A request-changes revision remains auditable but stops counting as an
    /// open application once the applicant submits its successor receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_receipt: Option<JoinApplicationCancelReceipt>,
    #[serde(default)]
    pub invite_consumed: bool,
    #[serde(default)]
    pub audit_entries: Vec<JoinApplicationAuditEntry>,
    pub updated_at: DateTime<Utc>,
}

impl JoinApplicationRecord {
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.superseded_by.is_none()
            && matches!(
                self.status,
                JoinApplicationStatus::AwaitingReview | JoinApplicationStatus::ChangesRequested
            )
    }

    pub fn refresh_expiry(&mut self, now: DateTime<Utc>) {
        if self.is_open() && now >= self.expires_at {
            self.status = JoinApplicationStatus::Expired;
            self.updated_at = now;
        }
    }

    pub fn append_audit(
        &mut self,
        action: JoinApplicationAuditAction,
        actor_id: arkret_wire::DidCoreId,
        occurred_at: DateTime<Utc>,
        receipt_ref: Hash,
    ) {
        self.audit_entries.push(JoinApplicationAuditEntry {
            action,
            actor_id,
            occurred_at,
            receipt_ref,
        });
        self.updated_at = occurred_at;
    }
}

#[derive(Clone, Debug)]
pub enum JoinApplicationMutation {
    Submit {
        record: Box<JoinApplicationRecord>,
        max_open_applications: usize,
        cooldown_after_reject_seconds: i64,
    },
    Review {
        realm_id: String,
        application_ref: Hash,
        receipt: JoinApplicationReviewReceipt,
        accept_threshold: usize,
    },
    Cancel {
        realm_id: String,
        application_ref: Hash,
        receipt: JoinApplicationCancelReceipt,
    },
}

#[derive(Clone, Debug)]
pub struct JoinApplicationCommand {
    pub principal_id: String,
    pub idempotency_key: String,
    pub request_hash: String,
    pub idempotency_expires_at: DateTime<Utc>,
    pub mutation: JoinApplicationMutation,
}

#[doc(hidden)]
pub fn join_application_mutation_receipt_ref(mutation: &JoinApplicationMutation) -> Hash {
    match mutation {
        JoinApplicationMutation::Submit { record, .. } => record.application_ref.clone(),
        JoinApplicationMutation::Review { receipt, .. } => receipt.review_receipt_digest.clone(),
        JoinApplicationMutation::Cancel { receipt, .. } => receipt.cancel_receipt_digest.clone(),
    }
}

#[doc(hidden)]
pub fn join_application_response_body(record: &JoinApplicationRecord, receipt_ref: &Hash) -> Value {
    serde_json::json!({
        "realm_id": record.receipt.realm_id,
        "application_ref": record.application_ref,
        "receipt_ref": receipt_ref,
        "status": record.status,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub enum JoinApplicationCommandOutcome {
    Applied {
        response_body: Value,
        record: JoinApplicationRecord,
    },
    Replay {
        response_body: Value,
        record: JoinApplicationRecord,
    },
    IdempotencyConflict,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JoinApplicationIdempotencyRecord {
    pub principal_id: String,
    pub idempotency_key: String,
    pub request_hash: String,
    pub response_body: Value,
    pub application_ref: Hash,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait JoinApplicationStore: Send + Sync {
    async fn execute(
        &self,
        command: JoinApplicationCommand,
    ) -> PersistenceResult<JoinApplicationCommandOutcome>;

    async fn get(
        &self,
        realm_id: &str,
        application_ref: &str,
        now: DateTime<Utc>,
    ) -> PersistenceResult<Option<JoinApplicationRecord>>;

    async fn list(
        &self,
        realm_id: &str,
        now: DateTime<Utc>,
    ) -> PersistenceResult<Vec<JoinApplicationRecord>>;

    async fn append_read_audit(
        &self,
        realm_id: &str,
        application_ref: &str,
        actor_id: &str,
        occurred_at: DateTime<Utc>,
    ) -> PersistenceResult<()>;

    async fn consume_review_authorisations(
        &self,
        realm_id: &str,
        review_receipt_digests: &[String],
        actor_id: &str,
        occurred_at: DateTime<Utc>,
    ) -> PersistenceResult<bool>;
}

#[doc(hidden)]
pub fn apply_join_application_mutation(
    records: &mut std::collections::BTreeMap<(String, String), JoinApplicationRecord>,
    mutation: JoinApplicationMutation,
) -> PersistenceResult<JoinApplicationRecord> {
    match mutation {
        JoinApplicationMutation::Submit {
            record,
            max_open_applications,
            cooldown_after_reject_seconds,
        } => {
            let mut record = *record;
            let realm_id = record.receipt.realm_id.as_str().to_owned();
            let applicant = record.receipt.applicant_actor_id.as_str();
            let now = record.receipt.submitted_at;
            let key = (realm_id.clone(), record.application_ref.as_str().to_owned());
            if records.contains_key(&key) {
                return Err(super::PersistenceError::Conflict(
                    "duplicate_conflict: application_ref already exists".to_owned(),
                ));
            }
            let revision_predecessor = records
                .iter()
                .find(|(_, existing)| {
                    existing.receipt.realm_id.as_str() == realm_id
                        && existing.receipt.applicant_actor_id.as_str() == applicant
                        && existing.receipt.knock_ref == record.receipt.knock_ref
                        && existing.status == JoinApplicationStatus::ChangesRequested
                        && existing.superseded_by.is_none()
                })
                .map(|(key, _)| key.clone());
            let mut open = 0usize;
            for existing in records.values_mut().filter(|existing| {
                existing.receipt.realm_id.as_str() == realm_id
                    && existing.receipt.applicant_actor_id.as_str() == applicant
            }) {
                existing.refresh_expiry(now);
                if existing.is_open() {
                    open += 1;
                }
                if existing.status == JoinApplicationStatus::Rejected
                    && existing.reviews.last().is_some_and(|review| {
                        now.signed_duration_since(review.reviewed_at).num_seconds()
                            < cooldown_after_reject_seconds
                    })
                {
                    return Err(super::PersistenceError::Conflict(
                        "failed_precondition: cooldown_after_reject".to_owned(),
                    ));
                }
            }
            if revision_predecessor.is_some() {
                open = open.saturating_sub(1);
            }
            if open >= max_open_applications {
                return Err(super::PersistenceError::Conflict(
                    "failed_precondition: max_open_applications_per_actor".to_owned(),
                ));
            }
            if let Some(predecessor) = revision_predecessor {
                let previous = records
                    .get_mut(&predecessor)
                    .expect("revision predecessor was selected from this map");
                previous.superseded_by = Some(record.application_ref.clone());
                previous.updated_at = now;
            }
            record.append_audit(
                JoinApplicationAuditAction::Submitted,
                record.receipt.applicant_actor_id.clone(),
                record.receipt.submitted_at,
                record.application_ref.clone(),
            );
            records.insert(key, record.clone());
            Ok(record)
        }
        JoinApplicationMutation::Review {
            realm_id,
            application_ref,
            receipt,
            accept_threshold,
        } => {
            let key = (realm_id, application_ref.as_str().to_owned());
            let record = records
                .get_mut(&key)
                .ok_or_else(|| super::PersistenceError::NotFound("join application".to_owned()))?;
            record.refresh_expiry(receipt.reviewed_at);
            if record
                .reviews
                .iter()
                .any(|review| review.review_receipt_digest == receipt.review_receipt_digest)
            {
                return Err(super::PersistenceError::Conflict(
                    "duplicate_conflict: review receipt already exists".to_owned(),
                ));
            }
            if record.status != JoinApplicationStatus::AwaitingReview
                || record.superseded_by.is_some()
            {
                let reason = if record.status == JoinApplicationStatus::Expired {
                    "ttl_expired"
                } else {
                    "failed_precondition"
                };
                return Err(super::PersistenceError::Conflict(reason.to_owned()));
            }
            if receipt.application_revision_digest != record.receipt.application_revision_digest {
                return Err(super::PersistenceError::Conflict(
                    "failed_precondition: application revision mismatch".to_owned(),
                ));
            }
            record.reviews.push(receipt.clone());
            record.status = match receipt.decision {
                JoinApplicationDecision::Reject => JoinApplicationStatus::Rejected,
                JoinApplicationDecision::RequestChanges => JoinApplicationStatus::ChangesRequested,
                JoinApplicationDecision::Accept => {
                    let accepted = effective_accept_receipts(
                        &record.reviews,
                        &record.receipt.application_revision_digest,
                    );
                    if accepted.len() >= accept_threshold.max(1) {
                        record.required_accept_refs = accepted
                            .into_iter()
                            .map(|review| review.review_receipt_digest.clone())
                            .collect();
                        JoinApplicationStatus::Accepted
                    } else {
                        JoinApplicationStatus::AwaitingReview
                    }
                }
            };
            record.append_audit(
                JoinApplicationAuditAction::Reviewed,
                receipt.reviewer_actor_id.clone(),
                receipt.reviewed_at,
                receipt.review_receipt_digest.clone(),
            );
            Ok(record.clone())
        }
        JoinApplicationMutation::Cancel {
            realm_id,
            application_ref,
            receipt,
        } => {
            let key = (realm_id, application_ref.as_str().to_owned());
            let record = records
                .get_mut(&key)
                .ok_or_else(|| super::PersistenceError::NotFound("join application".to_owned()))?;
            record.refresh_expiry(receipt.cancelled_at);
            if !record.is_open() || receipt.cancelled_by != record.receipt.applicant_actor_id {
                return Err(super::PersistenceError::Conflict(
                    "failed_precondition".to_owned(),
                ));
            }
            record.status = JoinApplicationStatus::Canceled;
            record.cancel_receipt = Some(receipt.clone());
            record.append_audit(
                JoinApplicationAuditAction::Canceled,
                receipt.cancelled_by.clone(),
                receipt.cancelled_at,
                receipt.cancel_receipt_digest.clone(),
            );
            Ok(record.clone())
        }
    }
}

fn effective_accept_receipts<'a>(
    reviews: &'a [JoinApplicationReviewReceipt],
    revision: &Hash,
) -> Vec<&'a JoinApplicationReviewReceipt> {
    let mut latest =
        std::collections::BTreeMap::<String, (&JoinApplicationReviewReceipt, bool)>::new();
    for review in reviews
        .iter()
        .filter(|review| &review.application_revision_digest == revision)
    {
        let key = review.reviewer_actor_id.as_str().to_owned();
        match latest.get_mut(&key) {
            None => {
                latest.insert(key, (review, false));
            }
            Some((current, conflict)) if review.reviewed_at > current.reviewed_at => {
                *current = review;
                *conflict = false;
            }
            Some((current, conflict))
                if review.reviewed_at == current.reviewed_at
                    && review.decision != current.decision =>
            {
                *conflict = true;
            }
            Some(_) => {}
        }
    }
    let mut accepted = latest
        .values()
        .filter_map(|(review, conflict)| {
            (!*conflict && review.decision == JoinApplicationDecision::Accept).then_some(*review)
        })
        .collect::<Vec<_>>();
    accepted.sort_by(|left, right| {
        left.reviewer_actor_id
            .cmp(&right.reviewer_actor_id)
            .then_with(|| left.review_receipt_digest.cmp(&right.review_receipt_digest))
    });
    accepted
}
