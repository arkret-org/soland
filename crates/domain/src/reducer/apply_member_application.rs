//! Profile-private join-application projection.
//!
//! `member.application`, `member.application.review`, and
//! `member.application.cancel` are signed private receipts. They never enter
//! shared Realm Event history and are never represented as extension fields
//! on `ak.member.state`. The public membership reducer only establishes the
//! stage-1 `knock`; this module mirrors the durable private store into a
//! rebuildable cache so `ak.invite.create.refs[role="join_authorised_by"]`
//! can be checked synchronously during Event admission.

use arkret_models_collaboration::governance::join_policy::{
    JoinApplicationDecision, JoinApplicationPrivateBody, JoinApplicationReceipt,
    JoinApplicationReviewReceipt, JoinApplicationStatus,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use super::*;

const DEFAULT_APPLICATION_TTL: &str = "PT168H";
const DEFAULT_COOLDOWN_AFTER_REJECT: &str = "PT72H";
const DEFAULT_REVIEW_CAPABILITY: &str = "ak.realm.join.review";

#[derive(Clone, Debug)]
pub struct MemberApplicationView {
    pub applicant_did: String,
    pub application_receipt_digest: String,
    pub status: String,
    pub submitted_at: String,
    pub private_body: Option<Value>,
    pub application_pending: Option<bool>,
    pub latest_review_ref: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MemberApplicationState {
    pub realm_id: String,
    pub applicant: String,
    pub receipt_digest: String,
    pub knock_ref: String,
    pub policy_version_digest: String,
    pub application_revision_digest: String,
    pub private_body: Value,
    pub status: String,
    pub accepted_by: Option<String>,
    pub accepted_grant_id: Option<String>,
    pub review_receipt_digests: Vec<String>,
    pub required_accept_refs: Vec<String>,
    pub invite_consumed: bool,
    pub superseded: bool,
    pub applicant_visibility: String,
    pub submitted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl MemberApplicationState {
    fn is_open(&self) -> bool {
        !self.superseded
            && matches!(
                self.status.as_str(),
                "awaiting_review" | "changes_requested"
            )
    }
}

#[derive(Clone, Debug)]
pub struct JoinApplicationAdmission {
    pub application_ttl: Duration,
    pub cooldown_after_reject: Duration,
    pub max_open_applications: usize,
    pub applicant_visibility: String,
}

fn join_policy_duration_or(join_policy: &Value, field: &str, default: &str) -> Duration {
    join_policy
        .get(field)
        .and_then(Value::as_str)
        .and_then(parse_iso8601_duration)
        .or_else(|| parse_iso8601_duration(default))
        .unwrap_or_else(|| Duration::hours(168))
}

fn join_policy_review_capability(join_policy: &Value) -> String {
    join_policy
        .get("review_capability")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(DEFAULT_REVIEW_CAPABILITY)
        .to_owned()
}

fn status_name(status: &JoinApplicationStatus) -> &'static str {
    match status {
        JoinApplicationStatus::AwaitingReview => "awaiting_review",
        JoinApplicationStatus::ChangesRequested => "changes_requested",
        JoinApplicationStatus::Accepted => "accepted",
        JoinApplicationStatus::Rejected => "rejected",
        JoinApplicationStatus::Canceled => "canceled",
        JoinApplicationStatus::Expired => "expired",
        JoinApplicationStatus::Consumed => "consumed",
    }
}

impl ProjectionState {
    pub fn check_private_join_application(
        &self,
        receipt: &JoinApplicationReceipt,
        private_body: &JoinApplicationPrivateBody,
    ) -> Result<JoinApplicationAdmission, &'static str> {
        let realm_id = receipt.realm_id.as_str();
        let applicant = receipt.applicant_did.as_str();
        let member = self
            .member(realm_id, applicant)
            .ok_or("failed_precondition")?;
        if member.state != "knock"
            || member.membership_event_ref.as_deref() != Some(receipt.knock_ref.as_str())
        {
            return Err("failed_precondition");
        }
        let join_policy = self
            .realm_join_policy_cell_value(realm_id)
            .ok_or("gate_check_failed")?;
        validate_join_policy_payload(join_policy).map_err(|_| "gate_check_failed")?;
        let policy_digest =
            arkret_canonical::canonical_sha256(join_policy).map_err(|_| "gate_check_failed")?;
        if policy_digest != receipt.policy_version_digest.as_str() {
            return Err("failed_precondition");
        }
        validate_application_private_body_against_policy(private_body, join_policy)?;
        if self
            .realm_encryption_profile(realm_id)
            .as_deref()
            .is_some_and(|profile| profile == "mls_rfc9420")
            && !matches!(
                private_body,
                JoinApplicationPrivateBody::ReviewerEnvelope { .. }
            )
        {
            return Err("gate_check_failed");
        }

        let cooldown_after_reject = join_policy_duration_or(
            join_policy,
            "cooldown_after_reject",
            DEFAULT_COOLDOWN_AFTER_REJECT,
        );
        if let Some(rejected_at) = self
            .member_application_reject_at
            .get(&(realm_id.to_owned(), applicant.to_owned()))
            && receipt.submitted_at.signed_duration_since(*rejected_at) < cooldown_after_reject
        {
            return Err("failed_precondition");
        }
        let max_open_applications = join_policy
            .get("max_open_applications_per_actor")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .clamp(1, 5) as usize;
        let open_count = self
            .member_applications
            .values()
            .filter(|state| {
                state.realm_id == realm_id
                    && state.applicant == applicant
                    && state.is_open()
                    && !(state.status == "changes_requested"
                        && state.knock_ref == receipt.knock_ref.as_str())
            })
            .count();
        if open_count >= max_open_applications {
            return Err("failed_precondition");
        }
        Ok(JoinApplicationAdmission {
            application_ttl: join_policy_duration_or(
                join_policy,
                "application_ttl",
                DEFAULT_APPLICATION_TTL,
            ),
            cooldown_after_reject,
            max_open_applications,
            applicant_visibility: join_policy
                .get("applicant_visibility")
                .and_then(Value::as_str)
                .unwrap_or("reviewer_only")
                .to_owned(),
        })
    }

    pub fn check_private_join_application_review(
        &self,
        receipt: &JoinApplicationReviewReceipt,
    ) -> Result<usize, &'static str> {
        let realm_id = receipt.realm_id.as_str();
        let application = self
            .member_application_by_receipt(realm_id, receipt.application_ref.as_str())
            .ok_or("failed_precondition")?;
        if application.status != "awaiting_review" || application.superseded {
            return Err("failed_precondition");
        }
        if receipt.reviewed_at >= application.expires_at {
            return Err("ttl_expired");
        }
        if receipt.application_revision_digest.as_str() != application.application_revision_digest {
            return Err("failed_precondition");
        }
        let join_policy = self
            .realm_join_policy_cell_value(realm_id)
            .ok_or("gate_check_failed")?;
        let policy_digest =
            arkret_canonical::canonical_sha256(join_policy).map_err(|_| "gate_check_failed")?;
        if policy_digest != application.policy_version_digest {
            return Err("failed_precondition");
        }
        let action = join_policy_review_capability(join_policy);
        if !self.projected_capability_grant_matches(
            receipt.reviewer_capability_proof.grant_id.as_str(),
            receipt.reviewer_did.as_str(),
            realm_id,
            &action,
            realm_id,
        ) {
            return Err("capability_denied");
        }
        join_policy_review_threshold(
            self,
            realm_id,
            join_policy,
            receipt.reviewer_did.as_str(),
            &action,
        )
    }

    pub fn install_private_join_application(
        &mut self,
        receipt: &JoinApplicationReceipt,
        private_body: &JoinApplicationPrivateBody,
        status: &JoinApplicationStatus,
        reviews: &[JoinApplicationReviewReceipt],
        required_accept_refs: &[arkret_wire::Hash],
        superseded_by: Option<&arkret_wire::Hash>,
        invite_consumed: bool,
        applicant_visibility: String,
        expires_at: DateTime<Utc>,
    ) {
        if superseded_by.is_none() {
            for previous in self.member_applications.values_mut().filter(|state| {
                state.receipt_digest != receipt.application_receipt_digest.as_str()
                    && state.realm_id == receipt.realm_id.as_str()
                    && state.applicant == receipt.applicant_did.as_str()
                    && state.knock_ref == receipt.knock_ref.as_str()
                    && state.status == "changes_requested"
                    && !state.superseded
            }) {
                previous.superseded = true;
            }
        }
        let latest_accept = reviews.iter().rev().find(|review| {
            review.decision == JoinApplicationDecision::Accept
                && review.application_revision_digest == receipt.application_revision_digest
        });
        let state = MemberApplicationState {
            realm_id: receipt.realm_id.as_str().to_owned(),
            applicant: receipt.applicant_did.as_str().to_owned(),
            receipt_digest: receipt.application_receipt_digest.as_str().to_owned(),
            knock_ref: receipt.knock_ref.as_str().to_owned(),
            policy_version_digest: receipt.policy_version_digest.as_str().to_owned(),
            application_revision_digest: receipt.application_revision_digest.as_str().to_owned(),
            private_body: serde_json::to_value(private_body).unwrap_or(Value::Null),
            status: status_name(status).to_owned(),
            accepted_by: latest_accept.map(|review| review.reviewer_did.as_str().to_owned()),
            accepted_grant_id: latest_accept.map(|review| {
                review
                    .reviewer_capability_proof
                    .grant_id
                    .as_str()
                    .to_owned()
            }),
            review_receipt_digests: reviews
                .iter()
                .filter(|review| review.decision == JoinApplicationDecision::Accept)
                .map(|review| review.review_receipt_digest.as_str().to_owned())
                .collect(),
            required_accept_refs: required_accept_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
            invite_consumed,
            superseded: superseded_by.is_some(),
            applicant_visibility,
            submitted_at: receipt.submitted_at,
            expires_at,
        };
        if *status == JoinApplicationStatus::Rejected
            && let Some(rejected_at) = reviews.last().map(|review| review.reviewed_at)
        {
            self.member_application_reject_at.insert(
                (
                    receipt.realm_id.as_str().to_owned(),
                    receipt.applicant_did.as_str().to_owned(),
                ),
                rejected_at,
            );
        }
        self.member_applications.insert(
            (
                receipt.realm_id.as_str().to_owned(),
                receipt.application_receipt_digest.as_str().to_owned(),
            ),
            state,
        );
    }

    /// Invite authorization is anchored at each accepted receipt's own review
    /// basis. Later capability revocation does not retroactively invalidate a
    /// counted accept.
    pub fn check_invite_join_authorisation(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::events::EventKind::INVITE_CREATE)
        {
            return Ok(());
        }
        let review_refs = join_authorised_by_refs(operation);
        if review_refs.is_empty() {
            return Ok(());
        }
        let supplied = review_refs.iter().cloned().collect::<BTreeSet<_>>();
        if supplied.len() != review_refs.len() {
            return Err("join_authorisation_invalid");
        }
        let state = self
            .member_application_by_review(operation.realm_id.as_str(), &review_refs[0])
            .ok_or("join_authorisation_invalid")?;
        let required = state
            .required_accept_refs
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if state.status != "accepted"
            || state.invite_consumed
            || operation.created_at >= state.expires_at
            || required.is_empty()
            || supplied != required
        {
            return Err("join_authorisation_invalid");
        }
        Ok(())
    }

    pub(crate) fn consume_join_authorisation(&mut self, operation: &Operation) {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::events::EventKind::INVITE_CREATE)
        {
            return;
        }
        let realm_id = operation.realm_id.as_str();
        for review_ref in join_authorised_by_refs(operation) {
            if let Some(state) = self.member_applications.values_mut().find(|state| {
                state.realm_id == realm_id
                    && state
                        .review_receipt_digests
                        .iter()
                        .any(|digest| digest == &review_ref)
            }) {
                state.invite_consumed = true;
                state.status = "consumed".to_owned();
            }
        }
    }

    pub fn realm_join_policy_review_capability(&self, realm_id: &str) -> Option<String> {
        self.realm_join_policy_cell_value(realm_id)
            .map(join_policy_review_capability)
    }

    fn member_application_by_receipt(
        &self,
        realm_id: &str,
        receipt_digest: &str,
    ) -> Option<&MemberApplicationState> {
        self.member_applications
            .get(&(realm_id.to_owned(), receipt_digest.to_owned()))
    }

    fn member_application_by_review(
        &self,
        realm_id: &str,
        review_receipt_digest: &str,
    ) -> Option<&MemberApplicationState> {
        self.member_applications.values().find(|state| {
            state.realm_id == realm_id
                && state
                    .review_receipt_digests
                    .iter()
                    .any(|digest| digest == review_receipt_digest)
        })
    }
}

fn validate_application_private_body_against_policy(
    private_body: &JoinApplicationPrivateBody,
    join_policy: &Value,
) -> Result<(), &'static str> {
    let JoinApplicationPrivateBody::ServerProtected {
        answers,
        gate_proofs: _,
        applicant_note: _,
    } = private_body
    else {
        return Ok(());
    };
    let supplied = answers
        .iter()
        .map(|answer| answer.question_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let required = join_policy
        .get("gates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|gate| gate.get("kind").and_then(Value::as_str) == Some("application_form"))
        .flat_map(|gate| {
            gate.get("questions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|question| {
            question
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|question| question.get("question_id").and_then(Value::as_str));
    if required
        .into_iter()
        .any(|question| !supplied.contains(question))
    {
        return Err("gate_check_failed");
    }
    Ok(())
}

fn join_policy_review_threshold(
    state: &ProjectionState,
    realm_id: &str,
    join_policy: &Value,
    reviewer: &str,
    action: &str,
) -> Result<usize, &'static str> {
    match join_policy.get("reviewer_quorum") {
        None => Ok(1),
        Some(Value::String(value)) if value == "any" => Ok(1),
        Some(Value::String(value)) if value == "majority" || value == "all" => {
            let eligible = state
                .projected_capability_holder_count(realm_id, action)
                .max(1);
            Ok(if value == "all" {
                eligible
            } else {
                eligible / 2 + 1
            })
        }
        Some(Value::Object(quorum)) => {
            let reviewers = quorum
                .get("reviewers")
                .and_then(Value::as_array)
                .ok_or("gate_check_failed")?;
            if !reviewers.iter().any(|candidate| {
                candidate
                    .as_str()
                    .is_some_and(|candidate| candidate == reviewer)
            }) {
                return Err("capability_denied");
            }
            quorum
                .get("threshold")
                .and_then(Value::as_u64)
                .map(|threshold| threshold as usize)
                .filter(|threshold| *threshold > 0)
                .ok_or("gate_check_failed")
        }
        _ => Err("gate_check_failed"),
    }
}

fn join_authorised_by_refs(operation: &Operation) -> Vec<String> {
    let direct = operation
        .refs
        .iter()
        .filter(|reference| reference.role == "join_authorised_by")
        .filter_map(|reference| {
            let value = reference.id.trim();
            (!value.is_empty()).then(|| value.to_owned())
        })
        .collect::<Vec<_>>();
    if !direct.is_empty() {
        return direct;
    }
    operation
        .payload
        .get("refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reference| {
            if reference.get("role").and_then(Value::as_str) != Some("join_authorised_by") {
                return None;
            }
            reference
                .get("id")
                .or_else(|| reference.get("digest"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{OperationId, RealmId};
    use arkret_wire::EventRef;
    use chrono::{Duration, Utc};
    use serde_json::json;

    use super::{MemberApplicationState, ProjectionState};

    const REALM: &str = "ak:realm:0196419b-0000-7000-8000-000000000000";
    const APPLICATION: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REVIEW_ONE: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const REVIEW_TWO: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn state() -> ProjectionState {
        let mut state = ProjectionState::new();
        let now = Utc::now();
        state.member_applications.insert(
            (REALM.to_owned(), APPLICATION.to_owned()),
            MemberApplicationState {
                realm_id: REALM.to_owned(),
                applicant: "did:web:applicant.example".to_owned(),
                receipt_digest: APPLICATION.to_owned(),
                knock_ref: "ak:event:0196419b-0000-7000-8000-000000000001".to_owned(),
                policy_version_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_owned(),
                application_revision_digest:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_owned(),
                private_body: json!({"mode": "server_protected", "answers": []}),
                status: "accepted".to_owned(),
                accepted_by: Some("did:web:reviewer.example".to_owned()),
                accepted_grant_id: Some("ak:grant:0196419b-0000-7000-8000-000000000010".to_owned()),
                review_receipt_digests: vec![REVIEW_ONE.to_owned(), REVIEW_TWO.to_owned()],
                required_accept_refs: vec![REVIEW_ONE.to_owned(), REVIEW_TWO.to_owned()],
                invite_consumed: false,
                superseded: false,
                applicant_visibility: "reviewer_only".to_owned(),
                submitted_at: now,
                expires_at: now + Duration::hours(1),
            },
        );
        state
    }

    fn invite(refs: &[&str]) -> arkret_event_draft::Operation {
        let mut operation = arkret_event_draft::Operation::create(
            OperationId::new("ak:operation:0196419b-0000-7000-8000-000000000020".to_owned())
                .unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            arkret_wire::events::EventKind::INVITE_CREATE,
            json!({}),
        );
        operation.refs = refs
            .iter()
            .map(|reference| EventRef::new(*reference, "join_authorised_by"))
            .collect();
        operation
    }

    #[test]
    fn invite_requires_the_complete_unique_quorum_receipt_set() {
        let mut state = state();
        assert!(
            state
                .check_invite_join_authorisation(&invite(&[REVIEW_ONE]))
                .is_err()
        );
        assert!(
            state
                .check_invite_join_authorisation(&invite(&[REVIEW_ONE, REVIEW_ONE]))
                .is_err()
        );
        let complete = invite(&[REVIEW_TWO, REVIEW_ONE]);
        assert!(state.check_invite_join_authorisation(&complete).is_ok());
        state.consume_join_authorisation(&complete);
        assert!(state.check_invite_join_authorisation(&complete).is_err());
    }
}
