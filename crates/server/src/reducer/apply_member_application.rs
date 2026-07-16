//! Join-policy application-review workflow reducer (spec
//! `governance/join-policy.md` §7). The `member.application` /
//! `member.application.review` / `member.application.cancel` records are
//! candidate profile-private payloads (§1, §7.2, §7.3): they are NOT
//! standalone `ak.*` Event kinds and MUST NOT be written to shared Realm
//! history under a bare name. soland carries them as profile-private
//! sub-objects on the active `ak.member.state` event:
//!
//!   - stage 1 knock: `ak.member.state{membership=knock}` with an `application` object → opens an
//!     application record.
//!   - stage 2 review: `ak.member.state{membership=knock|leave}` with an `application_review`
//!     object → records reviewer accept / reject / request_changes. `reject` drives the member to
//!     `leave` and stamps a `cooldown_after_reject` anchor (§3, §12).
//!   - cancel: `ak.member.state{membership=leave}` with an `application_cancel` object → applicant
//!     withdraws; no cooldown (§7.4).
//!
//! The reducer enforces the §3 / §12 anti-abuse limits
//! (`max_open_applications_per_actor`, `application_ttl`,
//! `cooldown_after_reject`) at submit time and binds the §7.5
//! `refs[role="join_authorised_by"]` invite reference to a fresh, unconsumed
//! review accept whose reviewer still holds `review_capability`.

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use super::*;

const DEFAULT_APPLICATION_TTL: &str = "PT168H";
const DEFAULT_COOLDOWN_AFTER_REJECT: &str = "PT72H";
const DEFAULT_REVIEW_CAPABILITY: &str = "ak.realm.join.review";

/// Open-application projection state for one `(realm_id, applicant)` pair.
#[derive(Clone, Debug)]
pub struct MemberApplicationState {
    pub realm_id: String,
    pub applicant: String,
    /// Stable receipt digest the review / invite reference. Derived from the
    /// opening knock event's canonical digest (or its `event_id`).
    pub receipt_digest: String,
    pub knock_ref: Option<String>,
    pub policy_version_digest: Option<String>,
    pub answers: Value,
    /// `pending` / `awaiting_review` / `changes_requested` / `accepted` /
    /// `rejected` / `canceled` / `expired`.
    pub status: String,
    /// Reviewer DID on the accepted review (set once accepted).
    pub accepted_by: Option<String>,
    /// `reviewer_capability_proof.grant_id` on the accepted review; used to
    /// re-check reviewer capability when the invite is written (§7.5 #3).
    pub accepted_grant_id: Option<String>,
    /// Digest of the accepted review record, the `join_authorised_by` target.
    pub review_receipt_digest: Option<String>,
    /// True once a `ak.invite.create` consumed the accept (anti-replay §7.5).
    pub invite_consumed: bool,
    /// `applicant_visibility` floor copied from the policy at open time.
    pub applicant_visibility: String,
    pub submitted_at: DateTime<Utc>,
    /// Submit-time + TTL; reducer rejects accepts past this instant.
    pub expires_at: DateTime<Utc>,
}

impl MemberApplicationState {
    fn is_open(&self) -> bool {
        matches!(
            self.status.as_str(),
            "pending" | "awaiting_review" | "changes_requested"
        )
    }
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

fn application_receipt_digest(operation: &Operation) -> String {
    if let Some(digest) = operation
        .canonical_event_digest
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        return digest.to_owned();
    }
    if let Some(event_id) = operation
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return event_id.to_owned();
    }
    operation.operation_id.as_str().to_owned()
}

fn member_from_payload(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("actor_id")
        .or_else(|| operation.payload.get("member"))
        .or_else(|| operation.payload.get("member_id"))
        .or_else(|| operation.payload.get("subject"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

impl ProjectionState {
    /// Submit-time gate for the application-review workflow. Runs before the
    /// `ak.member.state` projection commits. Enforces the §3 / §12 limits and
    /// the review-decision preconditions; returns the canonical `reason_code`
    /// on rejection.
    pub fn check_membership_application_admission(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_sdk::events::EventKind::MEMBER_STATE)
        {
            return Ok(());
        }
        let realm_id = operation.realm_id.as_str();
        let Some(member) = member_from_payload(operation) else {
            return Ok(());
        };

        if operation.payload.get("application").is_some() {
            return self.check_application_open(operation, realm_id, member);
        }
        if let Some(review) = operation.payload.get("application_review") {
            return self.check_application_review(review, realm_id);
        }
        Ok(())
    }

    fn check_application_open(
        &self,
        operation: &Operation,
        realm_id: &str,
        member: &str,
    ) -> Result<(), &'static str> {
        let Some(join_policy) = self.realm_join_policy_cell_value(realm_id) else {
            return Ok(());
        };
        if validate_join_policy_payload(join_policy).is_err() {
            return Err("gate_check_failed");
        }
        let now = operation.created_at;
        let cooldown = join_policy_duration_or(
            join_policy,
            "cooldown_after_reject",
            DEFAULT_COOLDOWN_AFTER_REJECT,
        );
        if let Some(rejected_at) = self
            .member_application_reject_at
            .get(&(realm_id.to_owned(), member.to_owned()))
            && now.signed_duration_since(*rejected_at) < cooldown
        {
            return Err("failed_precondition");
        }
        let max_open = join_policy
            .get("max_open_applications_per_actor")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .max(1);
        let open_count = self
            .member_applications
            .get(&(realm_id.to_owned(), member.to_owned()))
            .filter(|state| state.is_open())
            .map(|_| 1u64)
            .unwrap_or(0);
        if open_count >= max_open {
            return Err("failed_precondition");
        }
        Ok(())
    }

    fn check_application_review(&self, review: &Value, realm_id: &str) -> Result<(), &'static str> {
        let decision = review.get("decision").and_then(Value::as_str).unwrap_or("");
        if !matches!(decision, "accept" | "reject" | "request_changes") {
            return Err("failed_precondition");
        }
        let application_ref = review
            .get("application_ref")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("failed_precondition")?;
        let Some(state) = self.member_application_by_receipt(realm_id, application_ref) else {
            return Err("failed_precondition");
        };
        if !state.is_open() {
            return Err("failed_precondition");
        }
        if review.created_at_past_ttl(state) {
            return Err("ttl_expired");
        }
        Ok(())
    }

    /// Submit-time gate for `ak.invite.create` carrying
    /// `refs[role="join_authorised_by"]` (§7.5). The cited review accept MUST
    /// still point at an open, unconsumed, unexpired application whose
    /// reviewer still holds `review_capability` at the current frontier.
    pub fn check_invite_join_authorisation(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_sdk::events::EventKind::INVITE_CREATE)
        {
            return Ok(());
        }
        let refs = join_authorised_by_refs(operation);
        if refs.is_empty() {
            return Ok(());
        }
        let realm_id = operation.realm_id.as_str();
        let review_capability = self
            .realm_join_policy_cell_value(realm_id)
            .map(join_policy_review_capability)
            .unwrap_or_else(|| DEFAULT_REVIEW_CAPABILITY.to_owned());
        for review_ref in refs {
            let Some(state) = self.member_application_by_review(realm_id, &review_ref) else {
                return Err("join_authorisation_invalid");
            };
            if state.status != "accepted" || state.invite_consumed {
                return Err("join_authorisation_invalid");
            }
            if operation.created_at >= state.expires_at {
                return Err("join_authorisation_invalid");
            }
            let Some(reviewer) = state.accepted_by.as_deref() else {
                return Err("join_authorisation_invalid");
            };
            if !self.issuer_has_projected_capability(
                reviewer,
                realm_id,
                &review_capability,
                realm_id,
            ) {
                return Err("join_authorisation_invalid");
            }
        }
        Ok(())
    }

    /// Resolve the policy `review_capability` action token for a Realm
    /// (defaults to `ak.realm.join.review` when no policy is projected).
    pub fn realm_join_policy_review_capability(&self, realm_id: &str) -> Option<String> {
        self.realm_join_policy_cell_value(realm_id)
            .map(join_policy_review_capability)
    }

    /// Receipt digests of every projected application for a Realm. Used by the
    /// read endpoint to emit one `ak.audit.accessed` per reviewer body read.
    pub fn member_application_receipts(&self, realm_id: &str) -> Vec<String> {
        self.member_applications
            .values()
            .filter(|state| state.realm_id == realm_id)
            .map(|state| state.receipt_digest.clone())
            .collect()
    }

    fn member_application_by_receipt(
        &self,
        realm_id: &str,
        receipt_digest: &str,
    ) -> Option<&MemberApplicationState> {
        self.member_applications
            .values()
            .find(|state| state.realm_id == realm_id && state.receipt_digest == receipt_digest)
    }

    fn member_application_by_review(
        &self,
        realm_id: &str,
        review_receipt_digest: &str,
    ) -> Option<&MemberApplicationState> {
        self.member_applications.values().find(|state| {
            state.realm_id == realm_id
                && state.review_receipt_digest.as_deref() == Some(review_receipt_digest)
        })
    }

    /// Reducer-side projection step for the application-review sub-payloads on
    /// an accepted `ak.member.state` event. Called from `apply_membership`
    /// after the FSM transition is committed.
    pub(crate) fn project_member_application(&mut self, operation: &Operation) {
        let realm_id = operation.realm_id.as_str().to_owned();
        let Some(member) = member_from_payload(operation).map(ToOwned::to_owned) else {
            return;
        };
        if operation.payload.get("application").is_some() {
            self.open_member_application(operation, &realm_id, &member);
            return;
        }
        if let Some(review) = operation.payload.get("application_review").cloned() {
            self.apply_member_application_review(operation, &realm_id, &review);
            return;
        }
        if operation.payload.get("application_cancel").is_some() {
            if let Some(state) = self
                .member_applications
                .get_mut(&(realm_id.clone(), member.clone()))
            {
                state.status = "canceled".to_owned();
            }
        }
    }

    fn open_member_application(&mut self, operation: &Operation, realm_id: &str, member: &str) {
        let application = operation
            .payload
            .get("application")
            .cloned()
            .unwrap_or(Value::Null);
        let join_policy = self.realm_join_policy_cell_value(realm_id).cloned();
        let ttl = join_policy
            .as_ref()
            .map(|policy| {
                join_policy_duration_or(policy, "application_ttl", DEFAULT_APPLICATION_TTL)
            })
            .unwrap_or_else(|| Duration::hours(168));
        let applicant_visibility = join_policy
            .as_ref()
            .and_then(|policy| policy.get("applicant_visibility").and_then(Value::as_str))
            .unwrap_or("reviewer_only")
            .to_owned();
        let receipt_digest = application
            .get("application_receipt_digest")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| application_receipt_digest(operation));
        let submitted_at = operation.created_at;
        let state = MemberApplicationState {
            realm_id: realm_id.to_owned(),
            applicant: member.to_owned(),
            receipt_digest,
            knock_ref: application
                .get("knock_ref")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            policy_version_digest: application
                .get("policy_version_digest")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            answers: application.get("answers").cloned().unwrap_or(Value::Null),
            status: "awaiting_review".to_owned(),
            accepted_by: None,
            accepted_grant_id: None,
            review_receipt_digest: None,
            invite_consumed: false,
            applicant_visibility,
            submitted_at,
            expires_at: submitted_at + ttl,
        };
        self.member_applications
            .insert((realm_id.to_owned(), member.to_owned()), state);
    }

    fn apply_member_application_review(
        &mut self,
        operation: &Operation,
        realm_id: &str,
        review: &Value,
    ) {
        let Some(application_ref) = review
            .get("application_ref")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return;
        };
        let decision = review
            .get("decision")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let reviewer = review
            .get("reviewer_did")
            .and_then(Value::as_str)
            .or_else(|| operation.payload.get("sender").and_then(Value::as_str))
            .map(ToOwned::to_owned);
        let grant_id = review
            .get("reviewer_capability_proof")
            .and_then(|proof| proof.get("grant_id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let review_receipt_digest = review
            .get("review_receipt_digest")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| application_receipt_digest(operation));
        let now = operation.created_at;

        let Some((key, applicant)) = self
            .member_applications
            .iter()
            .find(|(_, state)| {
                state.realm_id == realm_id && state.receipt_digest == application_ref
            })
            .map(|(key, state)| (key.clone(), state.applicant.clone()))
        else {
            return;
        };
        if let Some(state) = self.member_applications.get_mut(&key) {
            match decision.as_str() {
                "accept" => {
                    state.status = "accepted".to_owned();
                    state.accepted_by = reviewer;
                    state.accepted_grant_id = grant_id;
                    state.review_receipt_digest = Some(review_receipt_digest);
                }
                "reject" => {
                    state.status = "rejected".to_owned();
                }
                "request_changes" => {
                    state.status = "changes_requested".to_owned();
                }
                _ => {}
            }
        }
        if decision == "reject" {
            self.member_application_reject_at
                .insert((realm_id.to_owned(), applicant), now);
        }
    }

    /// Mark the review accept cited by a `ak.invite.create` as consumed, so a
    /// second invite cannot replay the same authorisation (§7.5 #3).
    pub(crate) fn consume_join_authorisation(&mut self, operation: &Operation) {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_sdk::events::EventKind::INVITE_CREATE)
        {
            return;
        }
        let realm_id = operation.realm_id.as_str().to_owned();
        for review_ref in join_authorised_by_refs(operation) {
            if let Some(key) = self
                .member_applications
                .iter()
                .find(|(_, state)| {
                    state.realm_id == realm_id
                        && state.review_receipt_digest.as_deref() == Some(review_ref.as_str())
                })
                .map(|(key, _)| key.clone())
            {
                if let Some(state) = self.member_applications.get_mut(&key) {
                    state.invite_consumed = true;
                }
            }
        }
    }

    /// Read-side listing of applications for a Realm, scoped by viewer. When
    /// the viewer does not hold `review_capability` (and is not the applicant)
    /// the answers are redacted to honour `applicant_visibility=reviewer_only`
    /// (§3 #2, §8.1).
    pub fn member_applications_for_viewer(
        &self,
        realm_id: &str,
        viewer: &str,
        viewer_is_reviewer: bool,
    ) -> Vec<crate::routing::realms::MemberApplicationEntry> {
        let now = Utc::now();
        self.member_applications
            .values()
            .filter(|state| state.realm_id == realm_id)
            .map(|state| {
                let effective_status = if state.is_open() && now >= state.expires_at {
                    "expired"
                } else {
                    state.status.as_str()
                };
                let can_see_body = viewer_is_reviewer
                    || state.applicant == viewer
                    || state.applicant_visibility == "public"
                    || (state.applicant_visibility == "members_after_join"
                        && state.status == "accepted");
                crate::routing::realms::MemberApplicationEntry {
                    applicant_did: state.applicant.clone(),
                    application_receipt_digest: state.receipt_digest.clone(),
                    status: effective_status.to_owned(),
                    submitted_at: state.submitted_at.to_rfc3339(),
                    answers: can_see_body.then(|| state.answers.clone()),
                    application_pending: (!can_see_body).then_some(true),
                }
            })
            .collect()
    }
}

fn join_authorised_by_refs(operation: &Operation) -> Vec<String> {
    let refs = join_authorised_by_refs_from_event_refs(&operation.refs);
    if !refs.is_empty() {
        return refs;
    }
    join_authorised_by_refs_from_payload(&operation.payload)
}

fn join_authorised_by_refs_from_event_refs(refs: &[arkret_sdk::EventRef]) -> Vec<String> {
    refs.iter()
        .filter(|reference| reference.role == "join_authorised_by")
        .filter_map(|reference| {
            let value = reference.id.trim();
            (!value.is_empty()).then(|| value.to_owned())
        })
        .collect()
}

fn join_authorised_by_refs_from_payload(payload: &Value) -> Vec<String> {
    payload
        .get("refs")
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(|reference| {
                    let object = reference.as_object()?;
                    if object.get("role").and_then(Value::as_str) != Some("join_authorised_by") {
                        return None;
                    }
                    object
                        .get("id")
                        .or_else(|| object.get("digest"))
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .map(ToOwned::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

trait ReviewTtlCheck {
    fn created_at_past_ttl(&self, state: &MemberApplicationState) -> bool;
}

impl ReviewTtlCheck for Value {
    fn created_at_past_ttl(&self, state: &MemberApplicationState) -> bool {
        let now = self
            .get("reviewed_at")
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        now >= state.expires_at
    }
}
