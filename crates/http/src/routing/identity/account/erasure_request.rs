//! Self-initiated account erasure entry (`account-lifecycle.md` §8.1).
//!
//! `ak.self.account.command.request_erasure` is the only client operation that
//! starts a holder-initiated account erasure. It does exactly three things:
//! authenticate the holder as a high-risk action, durably record the erasure
//! intent, and leave the `erasure_pending` `AccountStatusRecord` issuance to
//! the Account Authority. It never signs a record, never performs a physical
//! erasure, and never creates a second erasure semantics: §8's accepted-record
//! rail stays the only erasure command.

use arkret_models_identity::account::{
    AccountRequestErasureOutcome, AccountRequestErasureRequestBody, AccountRequestErasureStatus,
};

use super::*;

/// Durable intent key. There is exactly one live self-erasure intent per
/// account, so the pointer is keyed by the principal alone and carries the
/// recorded acceptance outcome verbatim: exact replay returns it, a second
/// distinct `request_id` is refused against it.
const LIVE_INTENT_KEY: &str = "self-account-erasure-intent";

/// Retention of the durable intent. The intent outlives the request that
/// created it by design — §8.1 makes acceptance permanent until the Account
/// Authority signs the record, and the signed record is terminal — so the
/// record is kept for the same effectively unbounded window the erasure
/// execution ledger uses rather than expiring into a repeatable request.
const INTENT_RETENTION_DAYS: i64 = 36_500;

#[salvo::oapi::endpoint(
    operation_id = "ak.self.account.command.request_erasure",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.command.request_erasure"))]
pub(super) async fn request_erasure(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountRequestErasureRequestBody>,
) -> JsonResult<AccountRequestErasureOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    json_ok(record_erasure_request(state, &session, body.into_inner()).await?)
}

/// Transport-free core of the operation, so the §8.1 acceptance rules are
/// exercised directly instead of only through a mounted route.
async fn record_erasure_request(
    state: &AppState,
    session: &SessionRecord,
    body: AccountRequestErasureRequestBody,
) -> Result<AccountRequestErasureOutcome, AppError> {
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let principal_id = session_actor_core_id(&session.actor)?;

    require_erasure_request_entry_status(state, principal_id.as_str())?;
    require_fresh_high_risk_authentication(state, session)?;

    let request_digest = arkret_canonical::canonical_sha256(&body).map_err(|error| {
        AppError::param_invalid(format!("erasure request is not canonical: {error}"))
    })?;

    if let Some(recorded) = recorded_intent(state, principal_id.as_str()).await? {
        if recorded.outcome.request_id != body.request_id {
            return Err(erasure_request_already_pending());
        }
        if recorded.request_digest != request_digest {
            return Err(AppError::conflict(
                "erasure request_id was reused with different canonical content",
            )
            .with_wire_code(ErrorCode::DUPLICATE_CONFLICT));
        }
        return Ok(recorded.outcome);
    }

    let recorded_at = now();
    let outcome = AccountRequestErasureOutcome {
        request_id: body.request_id.clone(),
        status: AccountRequestErasureStatus::Accepted,
        principal_id: principal_id.clone(),
        recorded_at,
        withdrawal_window_ends_at: withdrawal_window_ends_at(state, recorded_at)?,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(format!("erasure acceptance is invalid: {error}")))?;
    store_intent(state, principal_id.as_str(), &request_digest, &outcome).await?;

    // Re-read the durable intent so the response is the stored acceptance and
    // never a value that only exists in this request. A racing request that
    // won the store returns its recorded outcome here, which is also how the
    // §8.1 single-live-intent rule holds under concurrency.
    let recorded = recorded_intent(state, principal_id.as_str())
        .await?
        .ok_or_else(|| AppError::internal("erasure intent was not durably stored"))?;
    if recorded.outcome.request_id != body.request_id {
        return Err(erasure_request_already_pending());
    }

    append_audit_log(
        state,
        Some(principal_id.as_str()),
        "self.account.request_erasure",
        json!({
            "operation_id": arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_REQUEST_ERASURE,
            "device_id": session.device_id,
            "request_id": recorded.outcome.request_id,
            "recorded_at": arkret_canonical::format_timestamp_canonical(recorded.outcome.recorded_at),
            "withdrawal_window_ends_at": recorded
                .outcome
                .withdrawal_window_ends_at
                .map(arkret_canonical::format_timestamp_canonical),
        }),
        "accepted",
    )
    .await;

    Ok(recorded.outcome)
}

/// §8.1 entry condition. `locked` / `deactivated` / `erasure_pending` already
/// fail at authentication with their §3 code, so reaching this function with
/// one of them means the session gate drifted; the closed match keeps the
/// operation's own entry rule verifiable instead of implied.
fn require_erasure_request_entry_status(
    state: &AppState,
    principal_id: &str,
) -> Result<(), AppError> {
    match state.account_lifecycle_status(principal_id) {
        AccountStatus::Active | AccountStatus::SoftLoggedOut | AccountStatus::Suspended => Ok(()),
        AccountStatus::Locked => Err(AppError::unauthenticated("account is locked")
            .with_wire_code(ErrorCode::AccountLocked.as_str())),
        AccountStatus::Deactivated => {
            Err(AppError::unauthenticated("account has been deactivated")
                .with_wire_code(ErrorCode::AccountDeactivated.as_str()))
        }
        AccountStatus::ErasurePending => {
            Err(AppError::unauthenticated("account erasure is pending")
                .with_wire_code(ErrorCode::AccountErased.as_str()))
        }
    }
}

/// §8.1 high-risk action authentication. The deployment names the session-grant
/// scope its Account Authority only issues after a fresh high-risk
/// authentication; a deployment that names none cannot establish freshness at
/// all and therefore refuses every request with zero writes.
fn require_fresh_high_risk_authentication(
    state: &AppState,
    session: &SessionRecord,
) -> Result<(), AppError> {
    let Some(required_scope) = state
        .config()
        .account_erasure_request_required_session_scope
        .as_deref()
    else {
        return Err(reauthentication_required(
            "this deployment configures no fresh high-risk action authentication for account erasure requests",
        ));
    };
    let Some(grant) = session.session_grant.as_ref() else {
        return Err(reauthentication_required(
            "account erasure requires a session grant carrying fresh high-risk action authentication",
        ));
    };
    if !grant.scopes.iter().any(|scope| scope == required_scope) {
        return Err(reauthentication_required(
            "the presented session grant does not carry fresh high-risk action authentication",
        ));
    }
    Ok(())
}

/// §8.1: a distinct `request_id` while a live intent exists whose
/// `erasure_pending` AccountStatusRecord is still unsigned.
fn erasure_request_already_pending() -> AppError {
    AppError::new(
        ErrorCode::FailedPrecondition,
        "an erasure request is already recorded for this account",
    )
    .with_reason_code(arkret_wire::ReasonCode::ERASURE_REQUEST_ALREADY_PENDING)
}

fn reauthentication_required(message: &'static str) -> AppError {
    AppError::new(ErrorCode::ReauthenticationRequired, message)
}

fn withdrawal_window_ends_at(
    state: &AppState,
    recorded_at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AppError> {
    let Some(seconds) = state
        .config()
        .account_erasure_request_withdrawal_window_seconds
    else {
        return Ok(None);
    };
    let seconds = i64::try_from(seconds).map_err(|_| {
        AppError::internal("configured erasure withdrawal window exceeds the representable range")
    })?;
    let ends_at = recorded_at
        .checked_add_signed(chrono::Duration::seconds(seconds))
        .ok_or_else(|| {
            AppError::internal(
                "configured erasure withdrawal window exceeds the representable range",
            )
        })?;
    Ok(Some(ends_at))
}

struct RecordedIntent {
    request_digest: String,
    outcome: AccountRequestErasureOutcome,
}

async fn recorded_intent(
    state: &AppState,
    principal_id: &str,
) -> Result<Option<RecordedIntent>, AppError> {
    let Some(record) = state
        .jobs()
        .idempotency_record(principal_id, LIVE_INTENT_KEY)
        .await
        .map_err(|error| AppError::internal(format!("erasure intent lookup failed: {error}")))?
    else {
        return Ok(None);
    };
    let outcome = serde_json::from_value::<AccountRequestErasureOutcome>(record.response_body)
        .map_err(|error| {
            AppError::internal(format!("stored erasure intent is invalid: {error}"))
        })?;
    Ok(Some(RecordedIntent {
        request_digest: record.request_hash,
        outcome,
    }))
}

async fn store_intent(
    state: &AppState,
    principal_id: &str,
    request_digest: &str,
    outcome: &AccountRequestErasureOutcome,
) -> Result<(), AppError> {
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            principal_id: principal_id.to_owned(),
            idempotency_key: LIVE_INTENT_KEY.to_owned(),
            service_id: state.service_id().clone(),
            request_hash: request_digest.to_owned(),
            response_status: StatusCode::OK.as_u16().into(),
            response_body: serde_json::to_value(outcome).map_err(|error| {
                AppError::internal(format!("erasure acceptance encode failed: {error}"))
            })?,
            created_at: outcome.recorded_at,
            expires_at: outcome.recorded_at + chrono::Duration::days(INTENT_RETENTION_DAYS),
        })
        .await
        .map_err(|error| AppError::internal(format!("erasure intent store failed: {error}")))
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{RequestId, SessionGrantId};
    use arkret_models_identity::session_credential::{
        SessionGrantCredentialClass, SessionGrantHolderBinding,
    };
    use soland_services::identity::{AccountLifecycleState, SessionGrantAuthorizationState};
    use soland_storage_postgres::Db;

    use super::*;

    const ACTOR: &str = "ak:did_core:web:alice.example";
    const DEVICE: &str = "ak:device:0196419b-0000-7000-8000-000000000001";
    const FRESH_SCOPE: &str = "ak.account.erasure.request";

    fn state_with(
        required_scope: Option<&str>,
        withdrawal_window_seconds: Option<u64>,
    ) -> AppState {
        let config = crate::config::AppConfig {
            account_erasure_request_required_session_scope: required_scope.map(ToOwned::to_owned),
            account_erasure_request_withdrawal_window_seconds: withdrawal_window_seconds,
            ..crate::config::AppConfig::test_default()
        };
        AppState::new(config, Db { pool: None })
    }

    fn bearer_session() -> SessionRecord {
        SessionRecord {
            token_hash: "sha256:fixture".to_owned(),
            actor: ACTOR.to_owned(),
            device_id: DEVICE.to_owned(),
            audience: "ak:did_core:web:soland.example".to_owned(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: now() + chrono::Duration::hours(1),
            created_at: now(),
            revoked_at: None,
        }
    }

    fn session_with_scopes(scopes: &[&str]) -> SessionRecord {
        SessionRecord {
            session_grant: Some(SessionGrantAuthorizationState {
                grant_id: SessionGrantId::new(
                    "ak:session_grant:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                )
                .expect("fixture grant id"),
                issuer: "did:web:coauth.local".to_owned(),
                scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                credential_class: SessionGrantCredentialClass::Standard,
                holder_binding: SessionGrantHolderBinding::HumanDevice {
                    device_binding: DEVICE.to_owned(),
                },
                device_binding: None,
                cnf_jkt: "fixture-jkt".to_owned(),
            }),
            ..bearer_session()
        }
    }

    fn request(request_id: &str) -> AccountRequestErasureRequestBody {
        AccountRequestErasureRequestBody {
            request_id: RequestId::new(request_id.to_owned()).expect("fixture request id"),
        }
    }

    async fn set_lifecycle(state: &AppState, wire_state: &str) {
        state
            .identities()
            .save_account_lifecycle(
                ACTOR,
                AccountLifecycleState {
                    state: wire_state.to_owned(),
                    reason: None,
                    changed_by: None,
                    changed_at: now(),
                },
            )
            .await
            .expect("lifecycle record is writable");
    }

    #[tokio::test]
    async fn unconfigured_deployment_refuses_with_reauthentication_required() {
        let state = state_with(None, None);
        let error = record_erasure_request(
            &state,
            &session_with_scopes(&[FRESH_SCOPE]),
            request("ak:request:0196419b-0000-7000-8000-000000000001"),
        )
        .await
        .expect_err("an unconfigured high-risk gate must fail closed");
        assert_eq!(error.wire_code(), ErrorCode::REAUTHENTICATION_REQUIRED);
        assert_eq!(error.http_status().as_u16(), 401);
        assert!(
            recorded_intent(&state, ACTOR)
                .await
                .expect("intent lookup")
                .is_none(),
            "a refused request must not record an intent"
        );
    }

    #[tokio::test]
    async fn session_without_the_configured_step_up_scope_is_refused() {
        let state = state_with(Some(FRESH_SCOPE), None);
        for session in [bearer_session(), session_with_scopes(&["ak.events.write"])] {
            let error = record_erasure_request(
                &state,
                &session,
                request("ak:request:0196419b-0000-7000-8000-000000000002"),
            )
            .await
            .expect_err("a session without fresh high-risk authentication must fail closed");
            assert_eq!(error.wire_code(), ErrorCode::REAUTHENTICATION_REQUIRED);
        }
        assert!(
            recorded_intent(&state, ACTOR)
                .await
                .expect("intent lookup")
                .is_none()
        );
    }

    #[tokio::test]
    async fn acceptance_records_the_intent_and_replays_verbatim() {
        let state = state_with(Some(FRESH_SCOPE), None);
        let session = session_with_scopes(&[FRESH_SCOPE]);
        let body = request("ak:request:0196419b-0000-7000-8000-000000000003");
        let accepted = record_erasure_request(&state, &session, body.clone())
            .await
            .expect("a fresh session accepts the erasure request");
        assert_eq!(accepted.status, AccountRequestErasureStatus::Accepted);
        assert_eq!(accepted.principal_id.as_str(), ACTOR);
        assert_eq!(accepted.request_id, body.request_id);
        assert!(accepted.withdrawal_window_ends_at.is_none());

        let replayed = record_erasure_request(&state, &session, body)
            .await
            .expect("exact replay returns the recorded acceptance");
        assert_eq!(replayed, accepted);

        // Acceptance records intent only. It never advances the account status:
        // that stays the Account Authority decision, carried by a signed
        // `erasure_pending` AccountStatusRecord.
        assert_eq!(state.account_lifecycle_status(ACTOR), AccountStatus::Active);
    }

    #[tokio::test]
    async fn configured_withdrawal_window_is_echoed() {
        let state = state_with(Some(FRESH_SCOPE), Some(3_600));
        let accepted = record_erasure_request(
            &state,
            &session_with_scopes(&[FRESH_SCOPE]),
            request("ak:request:0196419b-0000-7000-8000-000000000004"),
        )
        .await
        .expect("a fresh session accepts the erasure request");
        let ends_at = accepted
            .withdrawal_window_ends_at
            .expect("a configured window is echoed");
        assert_eq!(ends_at - accepted.recorded_at, chrono::Duration::hours(1));
    }

    #[tokio::test]
    async fn second_request_id_while_an_intent_is_live_fails_precondition() {
        let state = state_with(Some(FRESH_SCOPE), None);
        let session = session_with_scopes(&[FRESH_SCOPE]);
        let accepted = record_erasure_request(
            &state,
            &session,
            request("ak:request:0196419b-0000-7000-8000-000000000005"),
        )
        .await
        .expect("first request is accepted");

        let error = record_erasure_request(
            &state,
            &session,
            request("ak:request:0196419b-0000-7000-8000-000000000006"),
        )
        .await
        .expect_err("a second distinct request_id must be refused");
        assert_eq!(error.wire_code(), ErrorCode::FAILED_PRECONDITION);
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::ERASURE_REQUEST_ALREADY_PENDING)
        );
        let recorded = recorded_intent(&state, ACTOR)
            .await
            .expect("intent lookup")
            .expect("the first intent stays live");
        assert_eq!(recorded.outcome, accepted);
    }

    #[tokio::test]
    async fn same_request_id_with_different_canonical_bytes_is_duplicate_conflict() {
        let state = state_with(Some(FRESH_SCOPE), None);
        let session = session_with_scopes(&[FRESH_SCOPE]);
        let body = request("ak:request:0196419b-0000-7000-8000-000000000007");

        // Stand in for a first request whose canonical bytes differ from this
        // one: seed the durable intent under the same request_id but a foreign
        // digest. The closed one-field body cannot express that difference on
        // the wire today, so the guard is proved here instead of staying
        // untested until the body grows.
        let recorded_at = now();
        store_intent(
            &state,
            ACTOR,
            "sha256:other-canonical-bytes",
            &AccountRequestErasureOutcome {
                request_id: body.request_id.clone(),
                status: AccountRequestErasureStatus::Accepted,
                principal_id: session_actor_core_id(ACTOR).expect("fixture principal"),
                recorded_at,
                withdrawal_window_ends_at: None,
            },
        )
        .await
        .expect("the seeded intent is the first write");

        let error = record_erasure_request(&state, &session, body)
            .await
            .expect_err("a reused request_id with other bytes must be refused");
        assert_eq!(error.wire_code(), ErrorCode::DUPLICATE_CONFLICT);
    }

    #[tokio::test]
    async fn erasure_pending_account_cannot_open_a_second_request() {
        let state = state_with(Some(FRESH_SCOPE), None);
        set_lifecycle(&state, AccountStatus::ErasurePending.as_str()).await;
        let error = record_erasure_request(
            &state,
            &session_with_scopes(&[FRESH_SCOPE]),
            request("ak:request:0196419b-0000-7000-8000-000000000008"),
        )
        .await
        .expect_err("a terminal account must not record another intent");
        assert_eq!(error.wire_code(), ErrorCode::AccountErased.as_str());
        assert!(
            recorded_intent(&state, ACTOR)
                .await
                .expect("intent lookup")
                .is_none()
        );
    }

    #[tokio::test]
    async fn suspended_and_soft_logged_out_accounts_may_request_erasure() {
        for wire_state in [
            AccountStatus::Suspended.as_str(),
            AccountStatus::SoftLoggedOut.as_str(),
        ] {
            let state = state_with(Some(FRESH_SCOPE), None);
            set_lifecycle(&state, wire_state).await;
            record_erasure_request(
                &state,
                &session_with_scopes(&[FRESH_SCOPE]),
                request("ak:request:0196419b-0000-7000-8000-000000000009"),
            )
            .await
            .unwrap_or_else(|error| panic!("{wire_state} must be admitted: {error:?}"));
        }
    }
}
