//! Read-only preparation of one caller-signed ordinary message.
use arkret_models_collaboration::message_authoring::{
    MessageAuthoringContent, MessagePrepareOutcome, MessagePrepareRequestBody,
};
use arkret_models_collaboration::prepared_event_draft::PreparedEventDraft;
use arkret_wire::{ActorId, Base64UrlString, EncryptedPayloadScheme, Event, Hash, ScopeRef};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::with_path("messages/prepare").post(prepare)
}
fn invalid(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(SchemaViolation, error.to_string())
}

fn prepared_event_draft(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<PreparedEventDraft, AppError> {
    let digest_payload = event
        .digest_payload()
        .map_err(|error| AppError::internal(format!("message Event draft: {error}")))?;
    let unsigned_bytes = arkret_canonical::canonical_json_bytes(&digest_payload)
        .map_err(|error| AppError::internal(format!("message Event draft bytes: {error}")))?;
    Ok(PreparedEventDraft {
        unsigned_event_bytes: Base64UrlString::new(arkret_canonical::base64url_encode(
            &unsigned_bytes,
        ))
        .map_err(|error| AppError::internal(format!("message draft encode: {error}")))?,
        event_digest: Hash::new(
            event
                .event_digest_with_digest_suite(digest_suite)
                .map_err(|error| AppError::internal(format!("message Event digest: {error}")))?,
        )
        .map_err(|error| AppError::internal(format!("message Event digest invalid: {error}")))?,
    })
}

async fn device_active(
    state: &AppState,
    selector: &soland_storage::DeviceRevocationGateSelector,
) -> Result<(), AppError> {
    state
        .persistence()
        .device_revocation_gate_status(selector)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ensure_allowed()
        .map_err(|e| AppError::capability_denied(e.to_string()))
}

/// Check a message intent against the target scope's accepted MLS state.
///
/// Each branch keeps its registered identity so a client can choose between
/// retrying as-is, waiting for a covering Commit and re-encrypting:
/// plaintext into an activated scope is `failed_precondition` /
/// `mls_activation_required`; a non-RFC 9420 frozen context is
/// `schema_violation`; a frozen scope other than the Strand's is
/// `failed_precondition` / `scope_ref_mismatch`; a sender domain other than the
/// authenticated device is `capability_denied`; absent accepted MLS state is
/// `revision_unavailable`; an uncovered key-access revision is
/// `failed_precondition` / `epoch_update_required`; and a frozen epoch or group
/// state the scope has moved past is `failed_precondition` /
/// `mls_governance_binding_stale`.
async fn validate_encryption_context(
    state: &AppState,
    content: &MessageAuthoringContent,
    scope: &ScopeRef,
    device: &str,
) -> Result<(), AppError> {
    let group = scope.canonical_mls_group_id().map_err(invalid)?;
    let current = state
        .mls_commits()
        .commit(scope, &group)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let MessageAuthoringContent::Mls {
        encrypted_content,
        encrypted_metadata,
        encryption_context: frozen,
    } = content
    else {
        if current.is_some() {
            return Err(crate::app_error!(
                FailedPrecondition,
                "plaintext is not allowed after MLS activation",
            )
            .with_reason_code(arkret_wire::ReasonCode::MLS_ACTIVATION_REQUIRED));
        }
        return Ok(());
    };
    if frozen.scheme != EncryptedPayloadScheme::MlsRfc9420 {
        return Err(invalid(
            "message encryption_context.scheme must be mls_rfc9420",
        ));
    }
    let envelopes = || std::iter::once(encrypted_content).chain(encrypted_metadata);
    for envelope in envelopes() {
        envelope.validate().map_err(invalid)?;
        if envelope.encryption_context.counter().is_some()
            || envelope.encryption_context.routing_context().is_some()
        {
            return Err(invalid(
                "message envelopes carry only the standard RFC 9420 epoch and group_state_ref",
            ));
        }
    }
    if &frozen.effective_scope != scope {
        return Err(crate::app_error!(
            FailedPrecondition,
            "message encryption scope does not match the target Strand scope",
        )
        .with_reason_code(arkret_wire::ReasonCode::SCOPE_REF_MISMATCH));
    }
    if frozen.sender_domain != device {
        return Err(AppError::capability_denied(
            "message sender domain does not match the authenticated device",
        ));
    }
    let current = current.ok_or_else(|| {
        crate::app_error!(
            RevisionUnavailable,
            "accepted MLS group state is unavailable",
        )
    })?;
    if state
        .projections()
        .snapshot()
        .pending_mls_removals
        .iter()
        .any(|removal| {
            removal.realm_id == scope.realm_id().as_str()
                && removal.circle_id.as_deref() == scope.circle_id().map(|id| id.as_str())
        })
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "the scope key-access revision is not yet covered by an accepted MLS Commit",
        )
        .with_reason_code(arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED));
    }
    let current_ref = current
        .accepted_commit_ref
        .as_deref()
        .unwrap_or(&current.genesis_event_ref);
    if current.effective_scope != *scope
        || current.governance_binding.effective_scope() != scope
        || envelopes().any(|envelope| {
            envelope.encryption_context.epoch() != current.epoch
                || envelope.encryption_context.group_state_ref().as_str() != current_ref
        })
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "frozen message encryption context is no longer applicable",
        )
        .with_reason_code(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE));
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.self.messages.command.prepare", tags("messages"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.messages.command.prepare.v1"))]
async fn prepare(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<MessagePrepareRequestBody>,
) -> JsonResult<MessagePrepareOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    let body = body.into_inner();
    body.validate().map_err(invalid)?;
    if body.account_id != account || body.account_id.station_id.as_str() != state.service_id() {
        return Err(AppError::not_found("message preparation not found"));
    }
    let observed_at = crate::wire::now();
    let expires_at = body
        .created_at
        .checked_add_signed(chrono::Duration::seconds(300))
        .ok_or_else(|| {
            crate::app_error!(
                AuthoringRequestExpired,
                "message preparation timestamp overflows expiry",
            )
        })?;
    if body.created_at > observed_at || expires_at <= observed_at {
        return Err(crate::app_error!(
            AuthoringRequestExpired,
            "message preparation has expired or has a future creation time",
        ));
    }
    let request_digest = body.canonical_request_digest().map_err(invalid)?;
    let request_hash = request_digest.as_str().to_owned();
    let generation =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            account.principal_id.as_str(),
            &session.device_id,
        )
        .await
        .map_err(|e| AppError::capability_denied(e.to_string()))?;
    device_active(state, &generation).await?;
    let actor = ActorId::account(account);
    let operation_id = "ak.self.messages.command.prepare.v1";
    let key = format!(
        "{}:{}:{}",
        session.device_id, generation.authorization_ref.event_id, body.request_id
    );
    if let Some(record) = state
        .jobs()
        .scoped_idempotency_record(&actor, operation_id, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    {
        if record.request_hash != request_hash {
            return Err(crate::app_error!(
                DuplicateConflict,
                "message request_id already has another intent",
            ));
        }
        if record.expires_at <= observed_at {
            return Err(crate::app_error!(
                AuthoringRequestExpired,
                "message preparation expired",
            ));
        }
        let result: MessagePrepareOutcome =
            serde_json::from_value(record.response_body).map_err(invalid)?;
        result.validate_against_request(&body).map_err(invalid)?;
        return json_ok(result);
    }
    let scope = {
        let projection = state.projections().snapshot();
        let strand = projection
            .strands
            .get(body.intent.strand_id.as_str())
            .filter(|strand| strand.realm_id == body.realm_id.as_str())
            .ok_or_else(|| AppError::not_found("message target not found"))?;
        let _ = strand;
        match projection.strand_scope_circle_id(body.intent.strand_id.as_str()) {
            Some(circle) => ScopeRef::Circle {
                realm_id: body.realm_id.clone(),
                circle_id: arkret_wire::CircleId::new(circle).map_err(invalid)?,
            },
            None => ScopeRef::Realm {
                realm_id: body.realm_id.clone(),
            },
        }
    };
    validate_encryption_context(state, &body.intent.content, &scope, &session.device_id).await?;
    let digest_suite = state
        .projections()
        .realm_digest_suite(body.realm_id.as_str());
    let authored =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
            scope,
            actor.clone(),
            body.intent.payload(),
        )
        .and_then(|draft| draft.author_with_digest_suite(body.created_at, digest_suite))
        .map_err(invalid)?;
    let outcome = MessagePrepareOutcome {
        request_digest,
        draft: prepared_event_draft(authored.event(), digest_suite)?,
        observed_at,
        expires_at,
    };
    outcome.validate_against_request(&body).map_err(invalid)?;
    device_active(state, &generation).await?;
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            authenticated_actor: actor.clone(),
            operation_id: operation_id.to_owned(),
            idempotency_key: key.clone(),
            request_hash: request_hash.clone(),
            response_status: 200,
            response_body: serde_json::to_value(&outcome).map_err(invalid)?,
            created_at: observed_at,
            expires_at: outcome.expires_at,
        })
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let landed = state
        .jobs()
        .scoped_idempotency_record(&actor, operation_id, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(AuthoringRequestExpired, "preparation record is unavailable",)
        })?;
    if landed.request_hash != request_hash {
        return Err(crate::app_error!(
            DuplicateConflict,
            "message request identity conflicts with concurrent request",
        ));
    }
    let result: MessagePrepareOutcome =
        serde_json::from_value(landed.response_body).map_err(invalid)?;
    result.validate_against_request(&body).map_err(invalid)?;
    device_active(state, &generation).await?;
    json_ok(result)
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_models_collaboration::events_payloads::message::ContentBlock;
    use arkret_models_collaboration::message_authoring::MessageEncryptionContext;
    use arkret_models_crypto::{
        EncryptedEnvelope, EncryptedEnvelopeEncryptionContext, EncryptedEnvelopeRoutingContext,
        MlsGovernanceBindingPayload,
    };
    use arkret_wire::{EventId, RealmId};
    use soland_services::events::{AdvanceMlsEpochCommand, InitializeMlsGroupCommand};

    use super::*;

    const REALM: &str = "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT";
    const OTHER_REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000006";
    const LEADER: &str = "ak:did_core:web:alice.example";

    fn test_state() -> AppState {
        AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        )
    }

    fn realm_scope(realm: &str) -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new(realm).unwrap(),
        }
    }

    fn event_ref(seed: u8) -> EventId {
        EventId::from_digest(DigestSuite::Sha256, [seed; 32])
    }

    fn envelope(context: EncryptedEnvelopeEncryptionContext) -> EncryptedEnvelope {
        EncryptedEnvelope {
            version: "1.0".to_owned(),
            content_type: "application/vnd.arkret.message+json".to_owned(),
            encryption_context: context,
            ciphertext: "Y2lwaGVydGV4dA".to_owned(),
        }
    }

    fn standard(epoch: u64, group_state_ref: EventId) -> EncryptedEnvelope {
        envelope(EncryptedEnvelopeEncryptionContext::standard(
            epoch,
            group_state_ref,
        ))
    }

    fn mls_content(
        content: EncryptedEnvelope,
        metadata: Option<EncryptedEnvelope>,
        effective_scope: ScopeRef,
        sender_domain: &str,
    ) -> MessageAuthoringContent {
        MessageAuthoringContent::Mls {
            encrypted_content: content,
            encrypted_metadata: metadata,
            encryption_context: MessageEncryptionContext {
                scheme: EncryptedPayloadScheme::MlsRfc9420,
                effective_scope,
                sender_domain: sender_domain.to_owned(),
            },
        }
    }

    fn plaintext() -> MessageAuthoringContent {
        MessageAuthoringContent::Plaintext {
            content: ContentBlock::text("hello"),
            metadata: None,
        }
    }

    /// Accept the scope's `ak.mls.genesis` through the durable MLS commit port.
    async fn accept_genesis(state: &AppState, scope: &ScopeRef, genesis: &EventId) {
        state
            .mls_commits()
            .initialize_group(InitializeMlsGroupCommand {
                effective_scope: scope.clone(),
                group_id: scope.canonical_mls_group_id().unwrap().to_string(),
                leader_actor_id: LEADER.to_owned(),
                creator_device_id: DEVICE.to_owned(),
                genesis_event_ref: genesis.as_str().to_owned(),
                governance_binding: MlsGovernanceBindingPayload::realm(
                    scope.realm_id().clone(),
                    None,
                    0,
                    0,
                    0,
                )
                .unwrap(),
                committed_at: 1_788_000_000,
            })
            .await
            .unwrap()
            .expect("the scope had no accepted MLS genesis");
    }

    /// Accept the epoch 0 -> 1 Commit through the durable MLS commit port.
    async fn accept_commit(
        state: &AppState,
        scope: &ScopeRef,
        genesis: &EventId,
        commit: &EventId,
    ) {
        state
            .mls_commits()
            .advance_epoch(AdvanceMlsEpochCommand {
                expected_previous_epoch: 0,
                effective_scope: scope.clone(),
                group_id: scope.canonical_mls_group_id().unwrap().to_string(),
                leader_actor_id: LEADER.to_owned(),
                governance_binding: MlsGovernanceBindingPayload::realm(
                    scope.realm_id().clone(),
                    Some(genesis.clone()),
                    0,
                    1,
                    0,
                )
                .unwrap(),
                accepted_commit_ref: commit.as_str().to_owned(),
                committed_at: 1_788_000_060,
            })
            .await
            .unwrap()
            .expect("the epoch 0 Commit wins its CAS");
    }

    async fn problem(error: AppError) -> (StatusCode, serde_json::Value) {
        let mut res = Response::new();
        error
            .write(&mut Request::new(), &mut Depot::new(), &mut res)
            .await;
        let status = res.status_code.expect("problem status");
        let body = salvo::test::ResponseExt::take_json(&mut res)
            .await
            .expect("problem body");
        (status, body)
    }

    async fn assert_problem(
        result: Result<(), AppError>,
        status: StatusCode,
        code: &str,
        reason_code: Option<&str>,
    ) {
        let (actual_status, body) = problem(result.expect_err("the branch must reject")).await;
        assert_eq!(actual_status, status, "{body}");
        assert_eq!(body["status"], status.as_u16(), "{body}");
        assert_eq!(
            body["type"],
            format!("https://arkret.org/problems/{code}"),
            "{body}"
        );
        match reason_code {
            Some(reason_code) => assert_eq!(body["reason_code"], reason_code, "{body}"),
            None => assert!(body.get("reason_code").is_none(), "{body}"),
        }
    }

    #[tokio::test]
    async fn message_authoring_plaintext_is_prepared_before_mls_activation() {
        let state = test_state();
        let scope = realm_scope(REALM);
        validate_encryption_context(&state, &plaintext(), &scope, DEVICE)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn message_authoring_plaintext_after_activation_is_mls_activation_required() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        assert_problem(
            validate_encryption_context(&state, &plaintext(), &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("mls_activation_required"),
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_non_rfc9420_scheme_is_schema_violation() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        let mut content = mls_content(standard(0, event_ref(1)), None, scope.clone(), DEVICE);
        let MessageAuthoringContent::Mls {
            encryption_context, ..
        } = &mut content
        else {
            unreachable!()
        };
        encryption_context.scheme = EncryptedPayloadScheme::MlsExporterAeadV1;
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_exporter_counter_is_schema_violation() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        let content = mls_content(
            envelope(EncryptedEnvelopeEncryptionContext::exporter(
                0,
                event_ref(1),
                7,
            )),
            None,
            scope.clone(),
            DEVICE,
        );
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_metadata_routing_context_is_schema_violation() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        let metadata = envelope(EncryptedEnvelopeEncryptionContext::StandardMls {
            epoch: 0,
            group_state_ref: event_ref(1),
            routing_context: Some(EncryptedEnvelopeRoutingContext {
                target_ref: event_ref(9),
                routing_tag: "A".repeat(43),
            }),
        });
        let content = mls_content(
            standard(0, event_ref(1)),
            Some(metadata),
            scope.clone(),
            DEVICE,
        );
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_frozen_scope_mismatch_is_scope_ref_mismatch() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        let content = mls_content(
            standard(0, event_ref(1)),
            None,
            realm_scope(OTHER_REALM),
            DEVICE,
        );
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("scope_ref_mismatch"),
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_foreign_sender_domain_is_capability_denied() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        let content = mls_content(
            standard(0, event_ref(1)),
            None,
            scope.clone(),
            "ak:device:01904100-0000-7000-8000-00000000000e",
        );
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::FORBIDDEN,
            "capability_denied",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_missing_mls_state_is_revision_unavailable() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let content = mls_content(standard(0, event_ref(1)), None, scope.clone(), DEVICE);
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "revision_unavailable",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_uncovered_key_access_revision_is_epoch_update_required() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        state.test_projection().lock().pending_mls_removals.push(
            soland_domain::reducer::MlsRemoveObligation {
                realm_id: REALM.to_owned(),
                circle_id: None,
                mls_group_ref: Some(scope.canonical_mls_group_id().unwrap().to_string()),
                actor_id: LEADER.to_owned(),
                device_id: Some(DEVICE.to_owned()),
                membership_frontier: Vec::new(),
                trigger_membership: "leave".to_owned(),
                triggered_at: chrono::Utc::now(),
            },
        );
        let content = mls_content(standard(0, event_ref(1)), None, scope.clone(), DEVICE);
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("epoch_update_required"),
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_superseded_epoch_is_mls_governance_binding_stale() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let (genesis, commit) = (event_ref(1), event_ref(2));
        accept_genesis(&state, &scope, &genesis).await;
        accept_commit(&state, &scope, &genesis, &commit).await;
        let stale_content = mls_content(standard(0, genesis.clone()), None, scope.clone(), DEVICE);
        assert_problem(
            validate_encryption_context(&state, &stale_content, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("mls_governance_binding_stale"),
        )
        .await;
        let stale_metadata = mls_content(
            standard(1, commit.clone()),
            Some(standard(0, genesis)),
            scope.clone(),
            DEVICE,
        );
        assert_problem(
            validate_encryption_context(&state, &stale_metadata, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("mls_governance_binding_stale"),
        )
        .await;
        let wrong_group_state = mls_content(standard(1, event_ref(3)), None, scope.clone(), DEVICE);
        assert_problem(
            validate_encryption_context(&state, &wrong_group_state, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("mls_governance_binding_stale"),
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_current_mls_context_is_prepared() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let (genesis, commit) = (event_ref(1), event_ref(2));
        accept_genesis(&state, &scope, &genesis).await;
        accept_commit(&state, &scope, &genesis, &commit).await;
        let content = mls_content(
            standard(1, commit.clone()),
            Some(standard(1, commit)),
            scope.clone(),
            DEVICE,
        );
        validate_encryption_context(&state, &content, &scope, DEVICE)
            .await
            .unwrap();
    }
}
