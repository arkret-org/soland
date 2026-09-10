//! Authenticated Realm join preparation.
//!
//! This boundary turns holder-Station state into the exact governance facts
//! and complete unsigned Event a not-yet-member device may sign. It never accepts a
//! Directory candidate, endpoint, or caller-supplied governance basis.

use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, JoinGateProof, MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    RealmJoinGovernanceFacts, RealmJoinIntent, RealmJoinPrepareOutcome,
    RealmJoinPrepareRequestBody, RealmJoinTransition, RealmJoinUnsignedEvent,
};
use arkret_schema::InviteLiveTargetSlot;
use arkret_wire::{
    ActorId, EncryptionProfile, ErrorCode, JoinRule, Precondition, Predicate, PredicateOp,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

const PREPARE_TTL_MINUTES: i64 = 5;

pub(super) fn self_router() -> Router {
    Router::new().push(Router::with_path("realm-joins/prepare").post(prepare))
}

async fn require_prepare_device_active(
    state: &AppState,
    selector: &soland_storage::DeviceRevocationGateSelector,
) -> Result<(), AppError> {
    let status = state
        .persistence()
        .device_revocation_gate_status(selector)
        .await
        .map_err(|e| AppError::internal(format!("join authoring device gate failed: {e}")))?;
    status.ensure_allowed().map_err(|e| {
        AppError::capability_denied(format!("join authoring device is no longer active: {e}"))
    })
}

fn validation(error: arkret_wire::WireError) -> AppError {
    AppError::new(
        error.error_code().unwrap_or(ErrorCode::SchemaViolation),
        error.to_string(),
    )
}

fn join_rule(value: &str) -> JoinRule {
    match value {
        "public" => JoinRule::Public,
        "knock" => JoinRule::Knock,
        "restricted" => JoinRule::Restricted,
        "knock_restricted" => JoinRule::KnockRestricted,
        "closed" => JoinRule::Closed,
        _ => JoinRule::Invite,
    }
}

fn rule_allows_intent(rule: &str, intent: &RealmJoinIntent) -> bool {
    match intent {
        RealmJoinIntent::InviteAccept { .. } => true,
        RealmJoinIntent::MemberJoin { .. } => {
            matches!(rule, "public" | "restricted" | "knock_restricted")
        }
        RealmJoinIntent::Knock {} => matches!(rule, "knock" | "knock_restricted"),
    }
}

fn invite_accept_core(
    invite_id: arkret_wire::InviteId,
    account_id: arkret_wire::AccountId,
) -> Result<RealmJoinTransition, AppError> {
    let precondition = InviteLiveTargetSlot::held_by_invite(&invite_id)
        .precondition(&account_id)
        .map_err(|error| AppError::internal(format!("invite live-target cell: {error}")))?;
    Ok(RealmJoinTransition::InviteAccept {
        payload: InviteAcceptPayload::directed(invite_id, account_id),
        preconditions: vec![precondition],
    })
}

async fn member_state_core(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    seal_basis: &arkret_wire::SealBasis,
    member_id: ActorId,
    membership: MembershipPayloadState,
    gate_proofs: Vec<JoinGateProof>,
) -> Result<RealmJoinTransition, AppError> {
    let subject = arkret_wire::composite_subject(&[member_id
        .canonical_key()
        .map_err(|error| AppError::param_invalid(error.to_string()))?])
    .map_err(validation)?;
    let cell_id =
        arkret_wire::CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}"))
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let expected = state
        .projections()
        .effective_state_at(&seal_basis.leaves, realm_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("verified member state is unavailable: {error}"),
            )
        })?
        .get(&cell_id)
        .cloned()
        .and_then(arkret_state::lattice::CellState::into_value)
        .unwrap_or(serde_json::Value::Null);
    let payload = MembershipPayload {
        strand_id: None,
        realm_id: Some(realm_id.clone()),
        member_id,
        membership,
        gate_proofs,
        reason: None,
        membership_cause: None,
        agent_controller_binding: None,
        invite_ref: None,
    };
    Ok(RealmJoinTransition::MemberState {
        payload,
        preconditions: vec![Precondition {
            cell_id,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(expected),
                values: None,
                predicate_id: None,
            },
        }],
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.realm_join.command.prepare",
    tags("realm_join")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_join.command.prepare.v1"))]
async fn prepare(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<RealmJoinPrepareRequestBody>,
) -> JsonResult<RealmJoinPrepareOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let authenticated_account =
        crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
            state, &session,
        )
        .await?;
    let body = body.into_inner();
    body.validate().map_err(validation)?;
    if body.account_id != authenticated_account
        || body.account_id.station_id.as_str() != state.service_id()
    {
        return Err(AppError::not_found("Realm join preparation not found"));
    }

    let generation =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            authenticated_account.principal_id.as_str(),
            &session.device_id,
        )
        .await
        .map_err(|error| {
            AppError::conflict(format!("join authoring device unavailable: {error}"))
        })?;
    let authenticated_actor = ActorId::account(authenticated_account.clone());
    let request_hash = arkret_canonical::canonical_sha256(&body).map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("Realm join preparation request cannot be canonicalized: {error}"),
        )
    })?;
    let scoped_request_id = format!(
        "{}:{}:{}",
        session.device_id, generation.target_device_generation_ref, body.request_id
    );
    let idempotency_key = scoped_request_id.as_str();
    let operation_id = arkret_wire::ServiceOperationId::SELF_REALM_JOIN_COMMAND_PREPARE_V1;
    match state
        .jobs()
        .scoped_idempotency_record(&authenticated_actor, operation_id, idempotency_key)
        .await
        .map_err(|error| AppError::internal(format!("Realm join preparation lookup: {error}")))?
    {
        Some(record) if record.request_hash == request_hash => {
            let outcome = serde_json::from_value(record.response_body).map_err(|error| {
                AppError::internal(format!("stored Realm join preparation is invalid: {error}"))
            })?;
            require_prepare_device_active(state, &generation).await?;
            return json_ok(outcome);
        }
        Some(_) => {
            return Err(crate::app_error!(
                DuplicateConflict,
                "request_id is already bound to another Realm join preparation",
            ));
        }
        None => {}
    }

    let observed_at = crate::wire::now();
    let rule = crate::routing::spaces::directory::realm_resolution::realm_join_rule(
        state,
        body.realm_id.as_str(),
    );
    let mut intent_expiry = None;
    match &body.intent {
        RealmJoinIntent::InviteAccept {
            invite_id,
            invite_token,
        } => {
            let expected_invitee = authenticated_account.to_string();
            let invite = state
                .realm_invites()
                .get(invite_id.as_str())
                .await
                .map_err(|error| AppError::internal(format!("Realm invite lookup: {error}")))?
                .filter(|invite| {
                    invite.realm_id == body.realm_id.as_str()
                        && invite.status == "pending"
                        && invite.invitee_id.as_deref() == Some(expected_invitee.as_str())
                        && invite.invite_token == invite_token.as_str()
                        && invite
                            .expires_at
                            .is_none_or(|expires_at| expires_at > observed_at)
                })
                .ok_or_else(|| AppError::not_found("Realm join preparation not found"))?;
            intent_expiry = invite.expires_at;
        }
        RealmJoinIntent::MemberJoin { .. } if rule_allows_intent(rule.as_str(), &body.intent) => {}
        RealmJoinIntent::Knock {} if rule_allows_intent(rule.as_str(), &body.intent) => {
            // The closed knock intent carries no user-authored content.
        }
        RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => {
            return Err(AppError::not_found("Realm join preparation not found"));
        }
    }
    let mut leaves = state
        .projections()
        .realm_seal_leaves(&body.realm_id)
        .await
        .map_err(|_| {
            crate::app_error!(
                FrontierUnavailable,
                "verified Realm join frontier is unavailable",
            )
        })?;
    leaves.sort();
    leaves.dedup();
    let seal_basis = arkret_wire::SealBasis { leaves };
    if seal_basis.leaves.is_empty() || seal_basis.validate_protocol_bounds().is_err() {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "verified Realm join frontier is unavailable",
        ));
    }
    if let RealmJoinIntent::InviteAccept { invite_token, .. } = &body.intent {
        match crate::routing::spaces::space::invite_token_realm_resolution(state, invite_token)
            .await
        {
            crate::routing::spaces::space::InviteTokenRealmResolution::Ready {
                realm_id,
                seal_basis: invite_basis,
            } if realm_id == body.realm_id.as_str() && invite_basis == seal_basis => {}
            crate::routing::spaces::space::InviteTokenRealmResolution::FrontierUnavailable => {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "verified Realm join frontier is unavailable",
                ));
            }
            _ => return Err(AppError::not_found("Realm join preparation not found")),
        }
    }
    let transition = match &body.intent {
        RealmJoinIntent::InviteAccept { invite_id, .. } => {
            invite_accept_core(invite_id.clone(), authenticated_account.clone())?
        }
        RealmJoinIntent::MemberJoin { gate_proofs } => {
            member_state_core(
                state,
                &body.realm_id,
                &seal_basis,
                authenticated_actor.clone(),
                MembershipPayloadState::Join,
                gate_proofs.clone(),
            )
            .await?
        }
        RealmJoinIntent::Knock {} => {
            member_state_core(
                state,
                &body.realm_id,
                &seal_basis,
                authenticated_actor.clone(),
                MembershipPayloadState::Knock,
                Vec::new(),
            )
            .await?
        }
    };
    let digest_algorithm = state
        .projections()
        .predecessor_digest_suite(&body.realm_id, &seal_basis.leaves)
        .await
        .map_err(|_| {
            crate::app_error!(
                FrontierUnavailable,
                "verified Realm join digest suite is unavailable",
            )
        })?;
    let projection = state.projections().snapshot();
    let encryption_profile: EncryptionProfile = projection
        .realm_encryption_profile(body.realm_id.as_str())
        .and_then(|value| serde_json::from_value(serde_json::Value::String(value)).ok())
        .ok_or_else(|| {
            crate::app_error!(
                FrontierUnavailable,
                "verified Realm encryption profile is unavailable",
            )
        })?;
    let expires_at = intent_expiry
        .map(|expiry| expiry.min(observed_at + chrono::Duration::minutes(PREPARE_TTL_MINUTES)))
        .unwrap_or_else(|| observed_at + chrono::Duration::minutes(PREPARE_TTL_MINUTES));
    let accepted_actor_frontier = crate::routing::events::event_log::load_realm_actor_frontier(
        state,
        body.realm_id.clone(),
        authenticated_actor.clone(),
    )
    .await?;
    let unsigned_event = RealmJoinUnsignedEvent::prepare(
        &body,
        &accepted_actor_frontier,
        seal_basis.clone(),
        transition,
        digest_algorithm,
    )
    .map_err(validation)?;
    let outcome = RealmJoinPrepareOutcome {
        request_id: body.request_id.clone(),
        account_id: authenticated_account,
        realm_id: body.realm_id.clone(),
        request_digest: body.request_digest().map_err(validation)?,
        governance_facts: RealmJoinGovernanceFacts {
            join_rule: join_rule(&rule),
            seal_basis,
            digest_algorithm,
            encryption_profile,
        },
        unsigned_event,
        accepted_actor_frontier,
        authoring_device_generation_ref: generation.target_device_generation_ref,
        observed_at,
        expires_at,
    };
    outcome.validate_for_request(&body).map_err(validation)?;
    require_prepare_device_active(state, &generation).await?;
    let response_body = serde_json::to_value(&outcome)
        .map_err(|error| AppError::internal(format!("Realm join preparation encode: {error}")))?;
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            authenticated_actor: authenticated_actor.clone(),
            operation_id: operation_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            request_hash: request_hash.clone(),
            response_status: StatusCode::OK.as_u16() as i32,
            response_body,
            created_at: observed_at,
            expires_at,
        })
        .await
        .map_err(|error| AppError::internal(format!("Realm join preparation persist: {error}")))?;
    let landed = state
        .jobs()
        .scoped_idempotency_record(&authenticated_actor, operation_id, idempotency_key)
        .await
        .map_err(|error| AppError::internal(format!("Realm join preparation replay: {error}")))?
        .ok_or_else(|| AppError::internal("Realm join preparation was not persisted"))?;
    if landed.request_hash != request_hash {
        return Err(crate::app_error!(
            DuplicateConflict,
            "request_id lost a concurrent Realm join preparation race",
        ));
    }
    let landed_outcome = serde_json::from_value(landed.response_body).map_err(|error| {
        AppError::internal(format!(
            "persisted Realm join preparation is invalid: {error}"
        ))
    })?;
    require_prepare_device_active(state, &generation).await?;
    json_ok(landed_outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directed_invite_core_freezes_live_target_precondition() {
        let invite_id = arkret_wire::InviteId::new(
            "ak:invite:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N".to_owned(),
        )
        .unwrap();
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
        );
        let core = invite_accept_core(invite_id.clone(), account_id.clone()).unwrap();
        let RealmJoinTransition::InviteAccept {
            payload,
            preconditions,
        } = core
        else {
            panic!("wrong authoring branch")
        };
        assert_eq!(payload.invite_id, invite_id);
        assert_eq!(payload.invitee_account_id.as_ref(), Some(&account_id));
        assert_eq!(preconditions.len(), 1);
        assert_eq!(
            preconditions[0].cell_id,
            arkret_schema::invite_live_target_cell(&account_id).unwrap()
        );
    }

    #[test]
    fn join_rules_select_only_the_registered_intents() {
        let join = RealmJoinIntent::MemberJoin {
            gate_proofs: Vec::new(),
        };
        let knock = RealmJoinIntent::Knock {};
        assert!(rule_allows_intent("public", &join));
        assert!(rule_allows_intent("restricted", &join));
        assert!(rule_allows_intent("knock_restricted", &join));
        assert!(!rule_allows_intent("invite", &join));
        assert!(rule_allows_intent("knock", &knock));
        assert!(rule_allows_intent("knock_restricted", &knock));
        assert!(!rule_allows_intent("public", &knock));
        assert!(!rule_allows_intent("closed", &knock));
    }
}
