use arkret_models_collaboration::events_payloads::{
    MlsGenesisPayload, MlsWelcomePayload, MlsWelcomeRecipient,
};
use arkret_models_crypto::{
    MlsAcceptedArtifactOutcome, MlsAcceptedArtifactRequestBody, MlsCommitPayload, MlsEpochHead,
    MlsGovernanceBindingPayload,
};
use arkret_state::lattice::CellState;

use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.self.seals.read.mls_accepted_artifact",
    tags("seals")
)]
pub(super) async fn read(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<MlsAcceptedArtifactRequestBody>,
) -> JsonResult<MlsAcceptedArtifactOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let query = body.into_inner();
    query.validate().map_err(super::current_query_error)?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SEALS_READ_MLS_ACCEPTED_ARTIFACT_V1,
    )?;
    let realm_id = query
        .effective_scope
        .realm_id_opt()
        .expect("validated scope");
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let own_pcr = durable_account_owns_pcr(state, &actor, realm_id).await?;
    let agent_pcr = if let Some(account) = actor.as_account_id() {
        crate::routing::identity::agent_pcr::agent_record_for_controller_account_pcr(
            state,
            account,
            realm_id.as_str(),
        )
        .await?
        .is_some()
    } else {
        false
    };
    if !(own_pcr
        || agent_pcr
        || crate::routing::spaces::space::realm_id_accessible(
            state,
            realm_id.as_str(),
            Some(&session),
        )
        .await)
        || !super::governance_proof::scope_visible_to_session(
            state,
            &query.effective_scope,
            &session,
        )
    {
        return Err(AppError::not_found("MLS artifact not found"));
    }
    let record = state
        .event_queries()
        .canonical_event(query.artifact_ref.as_str())
        .await
        .map_err(unavailable)?
        .ok_or_else(|| AppError::not_found("MLS artifact not found"))?;
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("MLS artifact not found"));
    }
    let event: Event = serde_json::from_value(record.envelope).map_err(unavailable)?;
    if event.realm_id != *realm_id || event.scope_ref != query.effective_scope {
        return Err(AppError::not_found("MLS artifact not found"));
    }
    if event.kind == arkret_wire::EventKind::MlsWelcome {
        let welcome: MlsWelcomePayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(unavailable)?)
                .map_err(unavailable)?;
        if !welcome_matches_session(&welcome, &session) {
            return Err(AppError::not_found("MLS artifact not found"));
        }
        crate::routing::mls::validate_local_welcome_recipient_authorization(
            state,
            &welcome,
            realm_id.as_str(),
        )
        .await
        .map_err(|_| AppError::not_found("MLS artifact not found"))?;
    }
    let outcome = materialize(state, &query, &event).await?;
    json_ok(outcome)
}

fn welcome_matches_session(welcome: &MlsWelcomePayload, session: &SessionRecord) -> bool {
    match &welcome.recipient {
        MlsWelcomeRecipient::Device {
            recipient_device_id,
        } => {
            session.agent_session.is_none()
                && recipient_device_id.as_str() == session.device_id
                && welcome
                    .recipient_principal_id
                    .as_ref()
                    .is_some_and(|principal| principal.as_str() == session.actor)
        }
        MlsWelcomeRecipient::Agent {
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
        } => {
            session
                .agent_session
                .as_ref()
                .is_some_and(|agent| agent.freshness_state == arkret_wire::FreshnessState::Fresh)
                && session.session_grant.as_ref().is_some_and(|grant| {
                    matches!(&grant.holder_binding,
                    arkret_models_identity::SessionGrantHolderBinding::AgentRuntime {
                        agent_id, device_id, agent_key_authorization_ref, verification_method,
                    } if agent_id == recipient_agent_id && agent_id.as_str() == session.actor
                        && device_id.as_str() == session.device_id
                        && agent_key_authorization_ref == agent_key_authorize_event_id
                        && verification_method == recipient_agent_verification_method)
                })
        }
        MlsWelcomeRecipient::MinimalMetadataPairwise {
            recipient_pairwise_actor_id,
            recipient_pairwise_verification_method,
        } => session.session_grant.as_ref().is_some_and(|grant| {
            matches!(
                &grant.holder_binding,
                arkret_models_identity::SessionGrantHolderBinding::MinimalMetadataPairwise {
                    actor_id,
                    verification_method,
                    ..
                } if actor_id.signing_principal_id() == recipient_pairwise_actor_id
                    && verification_method == recipient_pairwise_verification_method
            )
        }),
    }
}

async fn materialize(
    state: &AppState,
    query: &MlsAcceptedArtifactRequestBody,
    event: &Event,
) -> Result<MlsAcceptedArtifactOutcome, AppError> {
    let realm_id = &event.realm_id;
    let basis = super::endpoints::load_realm_seal_frontier(state, realm_id)
        .await?
        .seal_basis;
    let accepted = state
        .projections()
        .effective_state_at(&basis.leaves, realm_id)
        .await
        .map_err(unavailable)?;
    let cell = arkret_state::mls_cells::mls_epoch_cell_id(
        &query.effective_scope,
        query.mls_group_id.as_str(),
    )
    .map_err(unavailable)?;
    let Some(CellState::Value(value)) = accepted.get(&cell) else {
        return Err(unavailable("MLS epoch has no unique accepted value"));
    };
    let current: MlsEpochHead = serde_json::from_value(value.clone()).map_err(unavailable)?;
    current.validate().map_err(unavailable)?;
    let (target_ref, target_epoch, binding) = match event.kind {
        arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit => {
            let (head, binding, _) = transition(event)?;
            (event.event_id.clone(), head.next_epoch, binding)
        }
        arkret_wire::EventKind::MlsWelcome => {
            let welcome: MlsWelcomePayload =
                serde_json::from_value(serde_json::to_value(&event.payload).map_err(unavailable)?)
                    .map_err(unavailable)?;
            (
                welcome.commit_ref,
                welcome.epoch,
                welcome.governance_binding,
            )
        }
        _ => {
            return Err(AppError::param_invalid(
                "query requires MLS Genesis, Commit or Welcome",
            ));
        }
    };
    if target_epoch > current.next_epoch {
        return Err(crate::app_error!(
            StateMismatch,
            "MLS artifact is ahead of the accepted epoch"
        ));
    }
    // Only exact predecessor point reads are needed; no history Event vector is built.
    let mut head = current.clone();
    let transition_head = loop {
        let record = state
            .event_queries()
            .canonical_event(head.transition_ref.as_str())
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("accepted MLS predecessor is unavailable"))?;
        let ancestor: Event = serde_json::from_value(record.envelope).map_err(unavailable)?;
        let (actual, ancestor_binding, previous) = transition(&ancestor)?;
        if actual != head
            || ancestor.realm_id != *realm_id
            || actual.effective_scope != query.effective_scope
            || actual.mls_group_id != query.mls_group_id
        {
            return Err(crate::app_error!(
                StateMismatch,
                "accepted MLS predecessor binding differs"
            ));
        }
        if head.next_epoch == target_epoch {
            if head.transition_ref != target_ref || ancestor_binding != binding {
                return Err(crate::app_error!(
                    StateMismatch,
                    "MLS artifact is not on the accepted transition chain"
                ));
            }
            break head;
        }
        let previous =
            previous.ok_or_else(|| unavailable("accepted MLS predecessor is missing"))?;
        let record = state
            .event_queries()
            .canonical_event(previous.as_str())
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("accepted MLS predecessor is unavailable"))?;
        let previous_event: Event = serde_json::from_value(record.envelope).map_err(unavailable)?;
        let (previous_head, ..) = transition(&previous_event)?;
        if previous_head.next_epoch != head.previous_epoch
            || previous_head.content_scheme != head.content_scheme
        {
            return Err(crate::app_error!(
                StateMismatch,
                "accepted MLS predecessor epoch differs"
            ));
        }
        head = previous_head;
    };
    require_covered_at_basis(state, event, &basis).await?;
    let leaves = state
        .event_queries()
        .mls_frontier_leaves(target_ref.as_str())
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("accepted MLS transition leaf input is unavailable"))?;
    let outcome = MlsAcceptedArtifactOutcome {
        query_digest: query.query_digest().map_err(unavailable)?,
        seal_basis: basis,
        transition_head,
        governance_binding: binding,
        mls_frontier_leaves: leaves,
        current_epoch_head: current,
    };
    outcome
        .validate_for_request(query)
        .map_err(|error| super::current_result_error(error, ErrorCode::StateMismatch))?;
    Ok(outcome)
}

fn transition(
    event: &Event,
) -> Result<(MlsEpochHead, MlsGovernanceBindingPayload, Option<EventId>), AppError> {
    let (binding, digest, previous) = match event.kind {
        arkret_wire::EventKind::MlsGenesis => {
            let payload: MlsGenesisPayload =
                serde_json::from_value(serde_json::to_value(&event.payload).map_err(unavailable)?)
                    .map_err(unavailable)?;
            let digest = payload.transition_digest().map_err(unavailable)?;
            (payload.governance_binding, digest, None)
        }
        arkret_wire::EventKind::MlsCommit => {
            let payload: MlsCommitPayload =
                serde_json::from_value(serde_json::to_value(&event.payload).map_err(unavailable)?)
                    .map_err(unavailable)?;
            (
                payload.governance_binding().clone(),
                payload.commit_digest().clone(),
                Some(EventId::new(payload.base_epoch_ref().to_owned()).map_err(unavailable)?),
            )
        }
        _ => return Err(unavailable("accepted MLS predecessor is not a transition")),
    };
    let head = MlsEpochHead {
        transition_ref: event.event_id.clone(),
        transition_event_digest: event.event_id.event_digest(),
        mls_transition_digest: digest,
        effective_scope: binding.effective_scope().clone(),
        mls_group_id: arkret_wire::Base64UrlString::new(binding.mls_group_id().to_owned())
            .map_err(unavailable)?,
        previous_epoch: binding.previous_epoch(),
        next_epoch: binding.next_epoch(),
        content_scheme: binding.content_scheme(),
    };
    head.validate().map_err(unavailable)?;
    Ok((head, binding, previous))
}

async fn require_covered_at_basis(
    state: &AppState,
    event: &Event,
    basis: &arkret_wire::SealBasis,
) -> Result<(), AppError> {
    let coverage = state
        .projections()
        .seals_covering_event(&event.event_id.event_digest())
        .await
        .map_err(unavailable)?;
    let mut pending = coverage
        .into_iter()
        .filter(|seal| seal.realm_id == event.realm_id)
        .map(|seal| seal.id)
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        if basis.leaves.contains(&id) {
            return Ok(());
        }
        pending.extend(
            state
                .projections()
                .seal_successors(&event.realm_id, &id)
                .await
                .map_err(unavailable)?,
        );
    }
    Err(unavailable(
        "MLS artifact is not covered by the queried accepted frontier",
    ))
}

fn unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(FrontierUnavailable, error.to_string())
}
