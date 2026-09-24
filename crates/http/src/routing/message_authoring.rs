//! Read-only preparation of one caller-signed ordinary message.
use arkret_models_collaboration::message_authoring::{
    MessageAuthoringContent, MessagePrepareOutcome, MessagePrepareRequestBody,
};
use arkret_models_collaboration::prepared_event_draft::PreparedEventDraft;
use arkret_models_crypto::EncryptedEnvelope;
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

/// Resolve a target only after proving current read visibility for the exact
/// authenticated actor. Keep every target denial opaque before MLS or retry
/// state can disclose the Strand's scope or existence.
async fn visible_target_scope(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    strand_id: &arkret_wire::StrandId,
    actor: &ActorId,
) -> Result<ScopeRef, AppError> {
    let hidden = || AppError::not_found("message target not found");
    if !crate::routing::spaces::space::realm_has_member_by_id(
        state,
        realm_id.as_str(),
        &actor.to_string(),
    )
    .await
    {
        return Err(hidden());
    }
    let projection = state.projections().snapshot();
    let strand = projection
        .strands
        .get(strand_id.as_str())
        .filter(|strand| strand.realm_id == realm_id.as_str() && !strand.state.is_terminal())
        .ok_or_else(hidden)?;
    match strand.scope_circle_id.as_deref() {
        Some(circle_id) => {
            let circle = projection.circles.get(circle_id).filter(|circle| {
                circle.realm_id == realm_id.as_str()
                    && projection.circle_scope_visible_to_actor(circle_id, &actor.to_string())
            });
            if circle.is_none() {
                return Err(hidden());
            }
            Ok(ScopeRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: arkret_wire::CircleId::new(circle_id.to_owned())
                    .map_err(|_| hidden())?,
            })
        }
        None => Ok(ScopeRef::Realm {
            realm_id: realm_id.clone(),
        }),
    }
}

/// Why the current MLS send gate refuses one application body.
///
/// The gate is shared by message prepare and self Event submit so both
/// surfaces answer the same state with the same registered identity
/// (encryption-and-audit §2.5.2, decision 0100).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MlsSendGateRefusal {
    /// Plaintext into a scope with an accepted `ak.mls.genesis`.
    ActivationRequired,
    /// Ciphertext into a scope whose accepted MLS state this Station does not
    /// hold. Nothing was written; the exact request may be retried.
    StateUnavailable,
    /// The scope's membership / policy / key-access checkpoint still awaits a
    /// covering winning Commit: the sender pauses instead of re-encrypting.
    EpochUpdateRequired,
    /// The frozen epoch or `group_state_ref` differs from the ready current
    /// group: the sender refreshes the group and re-encrypts a new request.
    EpochMismatch,
}

/// Failure of the current MLS send gate.
#[derive(Debug)]
pub(crate) enum MlsSendGateError {
    Refused(MlsSendGateRefusal),
    Internal(String),
}

/// Evaluate the current MLS send gate for one application body.
///
/// `envelopes` is `None` for a plaintext body and otherwise every encrypted
/// envelope the body carries (content, then optional metadata). The gate only
/// reads: it never writes or reserves anything, so the same state gives the
/// same answer. Precedence follows §2.5.2: an uncovered key-access checkpoint
/// wins over a stale frozen epoch.
pub(crate) async fn mls_send_gate(
    state: &AppState,
    scope: &ScopeRef,
    envelopes: Option<&[&EncryptedEnvelope]>,
) -> Result<(), MlsSendGateError> {
    let group = scope
        .canonical_mls_group_id()
        .map_err(|error| MlsSendGateError::Internal(error.to_string()))?;
    let current = state
        .mls_commits()
        .commit(scope, &group)
        .await
        .map_err(|error| MlsSendGateError::Internal(error.to_string()))?;
    let Some(envelopes) = envelopes else {
        return match current {
            Some(_) => Err(MlsSendGateError::Refused(
                MlsSendGateRefusal::ActivationRequired,
            )),
            None => Ok(()),
        };
    };
    let current = current.ok_or(MlsSendGateError::Refused(
        MlsSendGateRefusal::StateUnavailable,
    ))?;
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
        return Err(MlsSendGateError::Refused(
            MlsSendGateRefusal::EpochUpdateRequired,
        ));
    }
    let current_ref = current
        .accepted_commit_ref
        .as_deref()
        .unwrap_or(&current.genesis_event_ref);
    if current.effective_scope != *scope
        || current.governance_binding.effective_scope() != scope
        || envelopes.iter().any(|envelope| {
            envelope.encryption_context.epoch() != current.epoch
                || envelope.encryption_context.group_state_ref().as_str() != current_ref
        })
    {
        return Err(MlsSendGateError::Refused(MlsSendGateRefusal::EpochMismatch));
    }
    Ok(())
}

fn send_gate_problem(error: MlsSendGateError) -> AppError {
    match error {
        MlsSendGateError::Internal(detail) => AppError::internal(detail),
        MlsSendGateError::Refused(MlsSendGateRefusal::ActivationRequired) => crate::app_error!(
            FailedPrecondition,
            "plaintext is not allowed after MLS activation",
        )
        .with_reason_code(arkret_wire::ReasonCode::MLS_ACTIVATION_REQUIRED),
        MlsSendGateError::Refused(MlsSendGateRefusal::StateUnavailable) => crate::app_error!(
            RevisionUnavailable,
            "accepted MLS group state is unavailable",
        ),
        MlsSendGateError::Refused(MlsSendGateRefusal::EpochUpdateRequired) => crate::app_error!(
            FailedPrecondition,
            "the scope key-access revision is not yet covered by an accepted MLS Commit",
        )
        .with_reason_code(arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED),
        MlsSendGateError::Refused(MlsSendGateRefusal::EpochMismatch) => crate::app_error!(
            EpochMismatch,
            "frozen message encryption context is no longer applicable",
        ),
    }
}

/// Apply the current MLS send gate to one self-submitted `ak.message.create`.
///
/// Runs before the authority transaction is prepared, so every refusal leaves
/// no Commit, idempotency record or projection behind. The refusal travels as
/// a typed [`soland_storage::ConflictCode`] so the HTTP layer renders its
/// registered identity without reading diagnostic text.
pub(crate) async fn message_create_send_gate(
    state: &AppState,
    event: &Event,
) -> Result<(), soland_services::ServiceError> {
    use soland_services::ServiceError;
    use soland_storage::ConflictCode;
    let envelope = |field: &str| {
        event
            .payload
            .get(field)
            .map(|value| serde_json::from_value::<EncryptedEnvelope>(value.clone()))
            .transpose()
            .map_err(|error| ServiceError::SchemaViolation(format!("message {field}: {error}")))
    };
    let content = envelope("encrypted_content")?;
    let metadata = envelope("encrypted_metadata")?;
    let envelopes: Option<Vec<&EncryptedEnvelope>> = match (&content, &metadata) {
        (Some(content), metadata) => Some(std::iter::once(content).chain(metadata).collect()),
        (None, None) => None,
        (None, Some(_)) => {
            return Err(ServiceError::SchemaViolation(
                "message encrypted_metadata requires encrypted_content".to_owned(),
            ));
        }
    };
    mls_send_gate(state, &event.scope_ref, envelopes.as_deref())
        .await
        .map_err(|error| {
            let (code, detail) = match error {
                MlsSendGateError::Internal(detail) => return ServiceError::Internal(detail),
                MlsSendGateError::Refused(MlsSendGateRefusal::ActivationRequired) => (
                    ConflictCode::MlsActivationRequired,
                    "plaintext is not allowed after MLS activation",
                ),
                MlsSendGateError::Refused(MlsSendGateRefusal::StateUnavailable) => (
                    ConflictCode::TemporarilyUnavailable,
                    "accepted MLS group state is unavailable",
                ),
                MlsSendGateError::Refused(MlsSendGateRefusal::EpochUpdateRequired) => (
                    ConflictCode::EpochUpdateRequired,
                    "the scope key-access revision is not yet covered by an accepted MLS Commit",
                ),
                MlsSendGateError::Refused(MlsSendGateRefusal::EpochMismatch) => (
                    ConflictCode::EpochMismatch,
                    "frozen message encryption context is no longer applicable",
                ),
            };
            ServiceError::Conflict(format!("{code}: {detail}"))
        })
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
/// state the scope has moved past is `epoch_mismatch`.
async fn validate_encryption_context(
    state: &AppState,
    content: &MessageAuthoringContent,
    scope: &ScopeRef,
    device: &str,
) -> Result<(), AppError> {
    let MessageAuthoringContent::Mls {
        encrypted_content,
        encrypted_metadata,
        encryption_context: frozen,
    } = content
    else {
        return mls_send_gate(state, scope, None)
            .await
            .map_err(send_gate_problem);
    };
    if frozen.scheme != EncryptedPayloadScheme::MlsRfc9420 {
        return Err(invalid(
            "message encryption_context.scheme must be mls_rfc9420",
        ));
    }
    let envelopes: Vec<&EncryptedEnvelope> = std::iter::once(encrypted_content)
        .chain(encrypted_metadata)
        .collect();
    for envelope in &envelopes {
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
    mls_send_gate(state, scope, Some(&envelopes))
        .await
        .map_err(send_gate_problem)
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
    let scope = visible_target_scope(state, &body.realm_id, &body.intent.strand_id, &actor).await?;
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
        visible_target_scope(state, &body.realm_id, &body.intent.strand_id, &actor).await?;
        return json_ok(result);
    }
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
    visible_target_scope(state, &body.realm_id, &body.intent.strand_id, &actor).await?;
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
    use arkret_wire::{AccountId, DidCoreId, EventId, RealmId, StrandId};
    use soland_services::events::{AdvanceMlsEpochCommand, InitializeMlsGroupCommand};

    use super::*;

    const REALM: &str = "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT";
    const OTHER_REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000006";
    const LEADER: &str = "ak:did_core:web:alice.example";
    const STRAND: &str = "ak:strand:Ab1XwDyGoarexWM5f2N9k9zOpOIkgMjf0Ky-ngz87YjD";
    const CIRCLE: &str = "ak:circle:AaUAN_rEJJKU7XaSLZMiAC3dbFtb6rKXV-89cGay4X9e";

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

    fn test_actor(state: &AppState) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(LEADER).unwrap(),
            state.service_core_id(),
        ))
    }

    fn seed_target(state: &AppState, actor: &ActorId, circle: bool) {
        let now = chrono::Utc::now();
        let mut projection = state.test_projection().lock();
        projection.members.insert(
            (REALM.to_owned(), actor.to_string()),
            soland_domain::reducer::SolandMembershipState {
                member: actor.to_string(),
                realm_id: REALM.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                membership_event_ref: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
        projection.strands.insert(
            STRAND.to_owned(),
            soland_domain::reducer::StrandProjection {
                strand_id: STRAND.to_owned(),
                realm_id: REALM.to_owned(),
                tracks: Default::default(),
                title: "Target".to_owned(),
                summary: None,
                content: None,
                encrypted_content: None,
                fields: Default::default(),
                state: soland_domain::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                stage: None,
                stage_changed_at: None,
                created_by: actor.to_string(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                scope_circle_id: circle.then(|| CIRCLE.to_owned()),
                schema_refs: Vec::new(),
            },
        );
        if circle {
            projection.circles.insert(
                CIRCLE.to_owned(),
                soland_domain::reducer::CircleProjection {
                    circle_id: CIRCLE.to_owned(),
                    realm_id: REALM.to_owned(),
                    profile_ref: None,
                    title: "Private".to_owned(),
                    summary: None,
                    display: serde_json::json!({}),
                    directory_visibility: "members".to_owned(),
                    join_rule: "invite".to_owned(),
                    history_access: "since_join".to_owned(),
                    mls_group_ref: None,
                    state: soland_domain::reducer::CircleLifecycleState::Active,
                    state_changed_at: None,
                    created_by: actor.to_string(),
                    created_at: now,
                    updated_by: None,
                    updated_at: None,
                    members: Default::default(),
                },
            );
        }
    }

    #[tokio::test]
    async fn message_authoring_hidden_targets_share_not_found() {
        let state = test_state();
        let actor = test_actor(&state);
        let strand = StrandId::new(STRAND).unwrap();
        let realm = RealmId::new(REALM).unwrap();
        assert_problem(
            visible_target_scope(&state, &realm, &strand, &actor)
                .await
                .map(|_| ()),
            StatusCode::NOT_FOUND,
            "not_found",
            None,
        )
        .await;
        seed_target(&state, &actor, true);
        assert_problem(
            visible_target_scope(&state, &realm, &strand, &actor)
                .await
                .map(|_| ()),
            StatusCode::NOT_FOUND,
            "not_found",
            None,
        )
        .await;
        state
            .test_projection()
            .lock()
            .circles
            .get_mut(CIRCLE)
            .unwrap()
            .members
            .insert(actor.to_string());
        assert_eq!(
            visible_target_scope(&state, &realm, &strand, &actor)
                .await
                .unwrap(),
            ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: arkret_wire::CircleId::new(CIRCLE).unwrap(),
            }
        );
        state
            .test_projection()
            .lock()
            .members
            .get_mut(&(REALM.to_owned(), actor.to_string()))
            .unwrap()
            .state = "leave".to_owned();
        assert_problem(
            visible_target_scope(&state, &realm, &strand, &actor)
                .await
                .map(|_| ()),
            StatusCode::NOT_FOUND,
            "not_found",
            None,
        )
        .await;
        {
            let mut projection = state.test_projection().lock();
            projection
                .members
                .get_mut(&(REALM.to_owned(), actor.to_string()))
                .unwrap()
                .state = "join".to_owned();
            projection.strands.get_mut(STRAND).unwrap().state =
                soland_domain::reducer::ObjectLifecycleState::Redacted;
        }
        assert_problem(
            visible_target_scope(&state, &realm, &strand, &actor)
                .await
                .map(|_| ()),
            StatusCode::NOT_FOUND,
            "not_found",
            None,
        )
        .await;
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
        accept_commit(&state, &scope, &event_ref(1), &event_ref(2)).await;
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("epoch_update_required"),
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_superseded_epoch_is_epoch_mismatch() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let (genesis, commit) = (event_ref(1), event_ref(2));
        accept_genesis(&state, &scope, &genesis).await;
        accept_commit(&state, &scope, &genesis, &commit).await;
        let stale_content = mls_content(standard(0, genesis.clone()), None, scope.clone(), DEVICE);
        assert_problem(
            validate_encryption_context(&state, &stale_content, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "epoch_mismatch",
            None,
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
            "epoch_mismatch",
            None,
        )
        .await;
        let wrong_group_state = mls_content(standard(1, event_ref(3)), None, scope.clone(), DEVICE);
        assert_problem(
            validate_encryption_context(&state, &wrong_group_state, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "epoch_mismatch",
            None,
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

    fn message_create_event(scope: &ScopeRef, payload: serde_json::Value) -> Event {
        let serde_json::Value::Object(payload) = payload else {
            unreachable!("message payload is an object")
        };
        Event {
            event_id: event_ref(0x42),
            kind: arkret_wire::EventKind::MessageCreate,
            realm_id: scope.realm_id().clone(),
            scope_ref: scope.clone(),
            actor_id: ActorId::service(DidCoreId::new(LEADER).unwrap()),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: chrono::Utc::now(),
            semantic_refs: Vec::new(),
            payload: payload.into_iter().collect(),
            producer_proof: None,
        }
    }

    fn encrypted_message(
        scope: &ScopeRef,
        content: EncryptedEnvelope,
        metadata: Option<EncryptedEnvelope>,
    ) -> Event {
        let mut payload = serde_json::json!({
            "strand_id": STRAND,
            "track_name": "discussion",
            "encrypted_content": content,
        });
        if let Some(metadata) = metadata {
            payload["encrypted_metadata"] = serde_json::to_value(metadata).unwrap();
        }
        message_create_event(scope, payload)
    }

    async fn accepted_mls_head(state: &AppState, scope: &ScopeRef) -> (u64, Option<String>) {
        let group = scope.canonical_mls_group_id().unwrap();
        let current = state
            .mls_commits()
            .commit(scope, &group)
            .await
            .unwrap()
            .expect("accepted MLS state");
        (current.epoch, current.accepted_commit_ref)
    }

    fn submit_refusal(
        result: Result<(), soland_services::ServiceError>,
    ) -> soland_storage::ConflictCode {
        let error = result.expect_err("the submit gate must refuse");
        error
            .conflict_code()
            .unwrap_or_else(|| panic!("refusal has no typed conflict code: {error}"))
    }

    #[tokio::test]
    async fn message_submit_gate_refuses_plaintext_only_after_activation() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let plaintext = message_create_event(
            &scope,
            serde_json::json!({
                "strand_id": STRAND,
                "track_name": "discussion",
                "content": ContentBlock::text("hello"),
            }),
        );
        message_create_send_gate(&state, &plaintext).await.unwrap();
        accept_genesis(&state, &scope, &event_ref(1)).await;
        assert_eq!(
            submit_refusal(message_create_send_gate(&state, &plaintext).await),
            soland_storage::ConflictCode::MlsActivationRequired
        );
    }

    #[tokio::test]
    async fn message_submit_gate_without_mls_state_is_temporarily_unavailable() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let event = encrypted_message(&scope, standard(0, event_ref(1)), None);
        assert_eq!(
            submit_refusal(message_create_send_gate(&state, &event).await),
            soland_storage::ConflictCode::TemporarilyUnavailable
        );
    }

    #[tokio::test]
    async fn message_submit_gate_metadata_without_content_is_schema_violation() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let event = message_create_event(
            &scope,
            serde_json::json!({
                "strand_id": STRAND,
                "track_name": "discussion",
                "content": ContentBlock::text("hello"),
                "encrypted_metadata": standard(0, event_ref(1)),
            }),
        );
        let error = message_create_send_gate(&state, &event).await.unwrap_err();
        assert!(
            matches!(error, soland_services::ServiceError::SchemaViolation(_)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn message_submit_gate_uncovered_checkpoint_precedes_stale_epoch() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let (genesis, commit) = (event_ref(1), event_ref(2));
        accept_genesis(&state, &scope, &genesis).await;
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
        let current = encrypted_message(&scope, standard(0, genesis.clone()), None);
        assert_eq!(
            submit_refusal(message_create_send_gate(&state, &current).await),
            soland_storage::ConflictCode::EpochUpdateRequired
        );
        accept_commit(&state, &scope, &genesis, &commit).await;
        let before = accepted_mls_head(&state, &scope).await;
        for _ in 0..2 {
            assert_eq!(
                submit_refusal(message_create_send_gate(&state, &current).await),
                soland_storage::ConflictCode::EpochUpdateRequired
            );
        }
        assert_eq!(
            accepted_mls_head(&state, &scope).await,
            before,
            "a refused send must not move accepted MLS state"
        );
    }

    #[tokio::test]
    async fn message_submit_gate_superseded_epoch_is_epoch_mismatch() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let (genesis, commit) = (event_ref(1), event_ref(2));
        accept_genesis(&state, &scope, &genesis).await;
        accept_commit(&state, &scope, &genesis, &commit).await;
        let before = accepted_mls_head(&state, &scope).await;
        for event in [
            encrypted_message(&scope, standard(0, genesis.clone()), None),
            encrypted_message(
                &scope,
                standard(1, commit.clone()),
                Some(standard(0, genesis.clone())),
            ),
            encrypted_message(&scope, standard(1, event_ref(3)), None),
        ] {
            for _ in 0..2 {
                assert_eq!(
                    submit_refusal(message_create_send_gate(&state, &event).await),
                    soland_storage::ConflictCode::EpochMismatch
                );
            }
        }
        assert_eq!(
            accepted_mls_head(&state, &scope).await,
            before,
            "a refused send must not move accepted MLS state"
        );
        let current = encrypted_message(
            &scope,
            standard(1, commit.clone()),
            Some(standard(1, commit)),
        );
        message_create_send_gate(&state, &current).await.unwrap();
    }
}
