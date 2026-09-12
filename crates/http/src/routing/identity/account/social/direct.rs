use arkret_models_collaboration::agent_operations::AgentLifecycleState;

use super::*;

/// Renew only this Station's attestations, using the accepted directional
/// heads rather than extending a cached proof's lifetime. Foreign expired
/// evidence must be refreshed by its issuer, never signed on its behalf.
pub(crate) async fn fresh_direct_contact_evidence(
    state: &AppState,
    record: &ContactRecord,
) -> Result<
    Option<arkret_models_collaboration::contact_operations::ContactRoundEvidenceBundle>,
    AppError,
> {
    let Some(mut bundle) = record.contact_round_evidence.clone() else {
        return Ok(None);
    };
    if record.status != "accepted"
        || record.contact_round_id.as_ref() != Some(&bundle.contact_round_id)
        || bundle.current_proofs.len() != 2
    {
        return Ok(None);
    }
    let at = now();
    for proof in &mut bundle.current_proofs {
        let peer = proof.peer.contact_actor_id();
        let (holder, head) = if peer == record.target_id {
            (&record.requester_id, record.request_event_ref.as_ref())
        } else if peer == record.requester_id {
            (&record.target_id, record.response_event_ref.as_ref())
        } else {
            return Ok(None);
        };
        if proof.terminal
            || head != Some(&proof.head_event_ref)
            || proof.contact_round_id != bundle.contact_round_id
        {
            return Ok(None);
        }
        if proof.fresh_until > at + chrono::Duration::minutes(1) {
            continue;
        }
        if proof.issuer_id != state.service_core_id()
            || holder
                .as_account_id()
                .is_none_or(|account| account.station_id != state.service_core_id())
        {
            return Ok(None);
        }
        let Some(stored) = state
            .event_queries()
            .canonical_event(proof.head_event_ref.as_str())
            .await
            .map_err(|error| AppError::internal(format!("Contact head lookup: {error}")))?
        else {
            return Ok(None);
        };
        let event: arkret_wire::Event =
            serde_json::from_value(stored.envelope).map_err(|error| {
                AppError::internal(format!("accepted Contact head decode: {error}"))
            })?;
        if event.actor_id != *holder || event.event_id != proof.head_event_ref {
            return Ok(None);
        }
        let digest_suite = event
            .event_id
            .event_digest()
            .digest_suite()
            .map_err(|error| AppError::internal(format!("Contact head digest suite: {error}")))?;
        *proof = super::contact_write::signed_current_proof(
            state,
            bundle.contact_round_id.clone(),
            proof.peer.clone(),
            &event,
            digest_suite,
        )?;
    }
    Ok(Some(bundle))
}

pub(crate) fn direct_pair_key(
    state: &AppState,
    left: &arkret_wire::ActorId,
    right: &arkret_wire::ActorId,
) -> Result<String, AppError> {
    let trust_domain = state.config().trust_domain.clone();
    let left = direct_pair_key_participant(left);
    let right = direct_pair_key_participant(right);
    arkret_models_collaboration::objects::direct_conversation::direct_conversation_pair_key(
        trust_domain,
        left,
        right,
    )
    .map(|pair_key| pair_key.into_string())
    .map_err(|error| AppError::internal(format!("direct pair key construction failed: {error}")))
}

pub(super) fn direct_pair_key_participant(
    identity: &arkret_wire::ActorId,
) -> arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant
{
    arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
        identity.clone(),
    )
}

/// The settled coordinates for a pair.
///
/// `contact-and-direct-conversation.md` §8.3: the binding cell is an or_set and
/// the binding is written once and never retired, so "settled" means every
/// endorsement agrees on one digest. Two distinct digests are a materialization
/// conflict, not a race to resolve — see [`direct_binding_conflict`].
pub(crate) fn active_direct_binding(
    state: &AppState,
    pair_key: &str,
) -> Option<DirectConversationBindingRecord> {
    let binding = state.contacts().direct_binding(pair_key)?;
    direct_binding_matches_projection(state, &binding).then_some(binding)
}

/// `true` when the pair carries two distinct endorsement digests
/// (`direct_conversation_pair_materialization_conflict`, §5.7).
pub(crate) fn direct_binding_conflict(state: &AppState, pair_key: &str) -> bool {
    state.contacts().direct_binding_is_conflicted(pair_key)
}

pub(crate) fn direct_binding_matches_projection(
    state: &AppState,
    binding: &DirectConversationBindingRecord,
) -> bool {
    if binding.participants_unordered.len() != 2 {
        return false;
    }
    let projection = state.projections().snapshot();
    if !projection.realm_is_direct_conversation(&binding.realm_id)
        || projection.realm_is_destroyed(&binding.realm_id)
        || projection.realm_is_tombstoned(&binding.realm_id)
    {
        return false;
    }
    let active_members: BTreeSet<_> = projection
        .members_of_realm(&binding.realm_id)
        .into_iter()
        .map(|membership| membership.member.as_str())
        .collect();
    let participants: BTreeSet<_> = binding
        .participants_unordered
        .iter()
        .map(String::as_str)
        .collect();
    if active_members != participants {
        return false;
    }
    projection
        .strands
        .get(&binding.main_strand_id)
        .is_some_and(|strand| {
            strand.realm_id == binding.realm_id
                && strand.scope_circle_id.is_none()
                && strand.state.as_str() == "active"
                && strand
                    .tracks
                    .get(arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION)
                    .is_some_and(|discussion| {
                        discussion.enabled != Some(false) && discussion.is_primary == Some(true)
                    })
        })
}

pub(crate) async fn direct_group_state_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<Option<arkret_wire::EventId>, AppError> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned()).map_err(|error| {
        AppError::internal(format!("direct conversation Realm id is invalid: {error}"))
    })?;
    let mut matching = state
        .mls_commits()
        .commits()
        .await
        .map_err(|error| AppError::internal(format!("MLS group-state lookup failed: {error}")))?
        .into_iter()
        .filter(|commit| {
            matches!(
                &commit.effective_scope,
                arkret_wire::ScopeRef::Realm { realm_id: commit_realm_id }
                    if commit_realm_id == &realm_id
            )
        });
    let Some(commit) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Ok(None);
    }
    let state_ref = commit
        .accepted_commit_ref
        .as_deref()
        .unwrap_or(commit.genesis_event_ref.as_str());
    let event_ref = arkret_wire::EventId::new(state_ref.to_owned()).map_err(|error| {
        AppError::internal(format!(
            "stored MLS group-state Event ref is invalid: {error}"
        ))
    })?;
    let record = state
        .event_queries()
        .canonical_event(event_ref.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("MLS group-state Event lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "current MLS group-state Event is unavailable",
            )
        })?;
    if record.event_id != event_ref.as_str()
        || record.realm_id.as_deref() != Some(realm_id.as_str())
        || (record.kind != arkret_wire::EventKind::MlsGenesis.as_str()
            && record.kind != arkret_wire::EventKind::MlsCommit.as_str())
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "current MLS group-state Event binding is invalid",
        ));
    }
    Ok(Some(event_ref))
}

/// A registered participant source is proved by accepted binding state and
/// current Contact/MLS authority; it is never an ordinary Realm owner grant.
pub(crate) async fn validate_direct_message_bootstrap(
    state: &AppState,
    realm_id: &str,
    object: &serde_json::Map<String, Value>,
    derived_cells: &[String],
    state_at_ref: &BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::state_model::ResolvedCellState,
    >,
) -> Result<(), &'static str> {
    if object.contains_key("executed_by") || object.contains_key("applet_id") {
        return Err("provisional message requires the direct founder author");
    }
    let realm = arkret_wire::RealmId::new(realm_id.to_owned()).map_err(|_| "invalid Realm")?;
    let create = accepted_direct_realm_create(state, &realm).await?;
    let actor: arkret_wire::ActorId =
        serde_json::from_value(object.get("actor_id").cloned().ok_or("missing founder")?)
            .map_err(|_| "invalid founder")?;
    let projection = state.projections().snapshot();
    if actor != create.actor_id
        || !projection.realm_is_direct_conversation(realm_id)
        || projection.realm_is_in_terminal_state(realm_id)
        || projection.realm_ordinary_writes_blocked(realm_id)
        || state
            .contacts()
            .settled_direct_binding_for_realm(realm_id)
            .is_some()
    {
        return Err("provisional founder authority is not active");
    }
    let members = projection.members_of_realm(realm_id);
    if members.len() != 2
        || !members
            .iter()
            .any(|member| member.member.as_str() == actor.to_string())
    {
        return Err("provisional conversation requires its exact two members");
    }
    let peer: arkret_wire::ActorId = serde_json::from_str(
        members
            .iter()
            .find(|member| member.member.as_str() != actor.to_string())
            .ok_or("missing peer")?
            .member
            .as_str(),
    )
    .map_err(|_| "invalid peer")?;
    let pair_key = direct_pair_key(state, &actor, &peer).map_err(|_| "invalid pair")?;
    if state
        .contacts()
        .direct_bindings_for_pair(&pair_key)
        .is_some_and(|bindings| bindings.digests().next().is_some())
    {
        return Err("existing or conflicting binding closes provisional authority");
    }
    let events = state
        .event_queries()
        .projected_events_for_realm(realm_id)
        .await
        .map_err(|_| "provisional authority dependencies unavailable")?;
    let mut founding = Vec::new();
    for projected in &events {
        if !matches!(
            projected.event_kind,
            arkret_wire::EventKind::RealmCreate
                | arkret_wire::EventKind::MemberState
                | arkret_wire::EventKind::StrandCreate
        ) {
            continue;
        }
        let id = arkret_wire::EventId::new(projected.event_id.clone())
            .map_err(|_| "founding reference")?;
        let event =
            accepted_direct_event(state, &id, &realm, projected.event_kind.as_str()).await?;
        if event.actor_id == actor && event.actor_seq <= 3 {
            founding.push(event);
        }
    }
    founding.sort_by_key(|event| event.actor_seq);
    let exact: [&arkret_wire::Event; 4] = founding
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "founding unit incomplete")?;
    let plan = arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingPlan::from_events(exact)
        .map_err(|_| "invalid founding unit")?;
    if plan.realm_id != realm {
        return Err("founding Realm mismatch");
    }
    let strand_id = plan.main_strand_id;
    let timeline = format!("ak:cell:ak.component.strand.discussion.timeline.v1:{strand_id}");
    if derived_cells != [timeline] {
        return Err("provisional message must target the main Strand");
    }
    let current_ref = direct_group_state_for_realm(state, realm_id)
        .await
        .map_err(|_| "current group state unavailable")?
        .ok_or("current group state is not unique")?;
    let scope = serde_json::to_value(arkret_wire::ScopeRef::Realm {
        realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
            .map_err(|_| "founding Realm mismatch")?,
    })
    .map_err(|_| "founding Realm scope invalid")?;
    if !state_at_ref.iter().any(|(cell, state)| cell.as_str().starts_with("ak:cell:ak.component.mls.epoch.v1:")
        && matches!(state, arkret_state::state_model::ResolvedCellState::Value(value)
            if value.get("transition_ref").and_then(Value::as_str) == Some(current_ref.as_str())
                && value.get("effective_scope") == Some(&scope)
                && value.get("content_scheme").and_then(Value::as_str) == Some("mls_exporter_aead_v1"))) {
        return Err("provisional message Seal does not cover the winning exporter state");
    }
    validate_current_direct_pair_authority(state, &actor, &peer).await?;
    // The other bootstrap phase permits only a binding endorsement. A durable
    // receipt for the winning peer Welcome closes provisional history sends.
    for event in events
        .iter()
        .filter(|event| event.event_kind == arkret_wire::EventKind::MlsWelcome)
    {
        let welcome: arkret_models_collaboration::events_payloads::MlsWelcomePayload =
            serde_json::from_value(event.payload.clone()).map_err(|_| "invalid Welcome")?;
        if welcome.commit_ref != current_ref
            || welcome.recipient_principal_id.as_ref() != Some(peer.signing_principal_id())
        {
            continue;
        }
        let claim = state
            .mls_key_packages()
            .peer_claim(
                welcome.claim_receipt.source_id.as_str(),
                welcome.claim_receipt.claim_request_id.as_str(),
            )
            .await
            .map_err(|_| "Welcome receipt unavailable")?;
        if let Some(claim) = claim.filter(|claim| claim.state == "consumed")
            && let Some(receipt) = claim.consume_receipt
        {
            let receipt: arkret_models_crypto::KeyPackageConsumeReceipt =
                serde_json::from_value(receipt).map_err(|_| "invalid durable receipt")?;
            let durable = &receipt.recipient_durable_receipt;
            if receipt.claim_id == welcome.claim_id
                && durable.welcome_ref.as_str() == event.event_id
                && durable.realm_id == realm
                && durable.mls_group_id.as_str() == welcome.mls_group_id()
                && durable.mls_epoch == welcome.epoch()
                && durable.key_package_ref.as_str() == welcome.keypackage_ref.as_str()
                && durable.recipient_principal_id().as_ref() == Some(peer.signing_principal_id())
            {
                return Err("exact-pair completion requires the binding endorsement");
            }
        }
    }
    Ok(())
}

pub(crate) async fn validate_direct_message_participant(
    state: &AppState,
    realm_id: &str,
    object: &serde_json::Map<String, Value>,
    derived_cells: &[String],
    state_at_ref: &BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::state_model::ResolvedCellState,
    >,
) -> Result<(), &'static str> {
    if object.contains_key("executed_by") || object.contains_key("applet_id") {
        return Err("direct participant source requires a direct author");
    }
    let actor: arkret_wire::ActorId = serde_json::from_value(
        object
            .get("actor_id")
            .cloned()
            .ok_or("missing participant")?,
    )
    .map_err(|_| "invalid participant")?;
    let binding = state
        .contacts()
        .settled_direct_binding_for_realm(realm_id)
        .ok_or("Direct Conversation binding is not settled")?;
    if !direct_binding_matches_projection(state, &binding) {
        return Err("Direct Conversation membership or Strand is not active");
    }
    let projection = state.projections().snapshot();
    if projection.realm_is_in_terminal_state(realm_id)
        || projection.realm_ordinary_writes_blocked(realm_id)
    {
        return Err("Direct Conversation is not writable");
    }
    let refs = object
        .get("refs")
        .and_then(Value::as_array)
        .ok_or("missing Direct Conversation binding reference")?;
    let binding_refs: Vec<_> = refs
        .iter()
        .filter(|r| r.get("role").and_then(Value::as_str) == Some("direct_conversation_binding"))
        .collect();
    if binding_refs.len() != 1
        || binding_refs[0].get("critical").and_then(Value::as_bool) == Some(false)
    {
        return Err("Direct Conversation requires its exact critical binding reference");
    }
    let binding_ref = binding_refs[0]
        .get("id")
        .and_then(Value::as_str)
        .ok_or("invalid Direct Conversation binding reference")?;
    let record = state
        .event_queries()
        .accepted_event(binding_ref)
        .await
        .map_err(|_| "binding lookup failed")?
        .ok_or("binding Event is unavailable")?;
    let event: arkret_wire::Event =
        serde_json::from_value(record.envelope).map_err(|_| "binding Event is invalid")?;
    if event.kind != arkret_wire::EventKind::DirectConversationBound
        || event.realm_id.as_str() != realm_id
        || event.event_id.as_str() != binding_ref
    {
        return Err("binding reference is not an endorsement in this Realm");
    }
    let payload_value =
        serde_json::to_value(&event.payload).map_err(|_| "binding payload encoding")?;
    let payload: arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload =
        serde_json::from_value(payload_value.clone()).map_err(|_| "binding payload is invalid")?;
    if !payload.unordered_participant_ids.contains(&actor) || payload.realm_id.as_str() != realm_id
    {
        return Err("author is not a bound participant");
    }
    let digest = direct_binding_endorsement_digest(&payload)?;
    let bindings = state
        .contacts()
        .direct_bindings_for_pair(payload.pair_key.as_ref())
        .ok_or("current Direct Conversation binding is unavailable")?;
    if bindings.digests().count() != 1
        || !bindings.digests().any(|known| known == digest)
        || payload.main_strand_id.as_str() != binding.main_strand_id
    {
        return Err("binding endorsement differs from the current semantic binding");
    }
    let binding_cell = format!(
        "ak:cell:ak.component.direct_conversation.binding.v1:{}",
        payload.pair_key
    );
    let timeline = format!(
        "ak:cell:ak.component.strand.discussion.timeline.v1:{}",
        binding.main_strand_id
    );
    if !direct_message_seal_covers(
        state_at_ref,
        &binding_cell,
        &payload_value,
        &timeline,
        derived_cells,
    ) {
        return Err("message Seal does not cover the exact binding and main Strand");
    }
    validate_direct_binding_event_refs(state, &payload).await?;
    let create = accepted_direct_realm_create(state, &payload.realm_id).await?;
    let founder_peer = payload
        .unordered_participant_ids
        .iter()
        .find(|id| **id != create.actor_id)
        .ok_or("missing founder peer")?;
    validate_current_direct_pair_authority(state, &create.actor_id, founder_peer).await?;
    if direct_group_state_for_realm(state, realm_id)
        .await
        .map_err(|_| "MLS authority lookup failed")?
        .is_none()
    {
        return Err("Direct Conversation has no unique current MLS state");
    }
    Ok(())
}

/// Both provisional and settled sends require current pair authority. The
/// accepted founder fixes the controller direction even when the Agent sends.
async fn validate_current_direct_pair_authority(
    state: &AppState,
    founder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
) -> Result<(), &'static str> {
    if let Some(basis) = agent_direct_authorization_basis(
        state,
        founder.signing_principal_id().as_str(),
        peer.signing_principal_id().as_str(),
    )
    .await
    .map_err(|_| "current Agent controller authority is unavailable")?
    {
        for event_ref in &basis.event_refs {
            let accepted = state
                .event_queries()
                .accepted_event(event_ref.as_str())
                .await
                .map_err(|_| "Agent authority lookup failed")?
                .ok_or("accepted Agent authority is unavailable")?;
            if accepted.kind == arkret_wire::EventKind::AgentProvision.as_str() {
                let payload: arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload =
                    serde_json::from_value(accepted.envelope.get("payload").cloned().unwrap_or(Value::Null))
                        .map_err(|_| "accepted Agent provision is invalid")?;
                if accepted.actor_id != founder.to_string()
                    || payload.controller_principal_id != *founder.signing_principal_id()
                    || payload.agent_id != *peer.signing_principal_id()
                    || accepted.canonical_digest != event_ref.event_digest().as_str()
                {
                    return Err("Agent authority does not match the exact pair");
                }
                return Ok(());
            }
        }
        return Err("accepted Agent provision is unavailable");
    }
    let contact = accepted_contact_for_pair(state, founder, peer, "direct_message")
        .await
        .map_err(|_| "current Contact lookup failed")?
        .ok_or("current Contact does not permit messages")?;
    if fresh_direct_contact_evidence(state, &contact)
        .await
        .map_err(|_| "Contact head verification failed")?
        .is_none()
    {
        return Err("fresh directional Contact evidence is unavailable");
    }
    Ok(())
}

fn direct_message_seal_covers(
    state_at_ref: &BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::state_model::ResolvedCellState,
    >,
    binding_cell: &str,
    binding_payload: &Value,
    timeline: &str,
    derived_cells: &[String],
) -> bool {
    derived_cells.len() == 1 && derived_cells[0] == timeline
        && state_at_ref.iter().any(|(cell, value)| {
            cell.as_str() == binding_cell && matches!(value,
                arkret_state::state_model::ResolvedCellState::Value(value) if value.as_array().is_some_and(|entries|
                    entries.iter().any(|entry| entry.get("value") == Some(binding_payload))))
        })
}

#[cfg(test)]
mod participant_authority_tests {
    use super::*;

    #[test]
    fn direct_message_seal_rejects_missing_conflicted_foreign_or_widened_authority() {
        use arkret_state::state_model::ResolvedCellState;
        let cell = "ak:cell:ak.component.direct_conversation.binding.v1:pair";
        let timeline = "ak:cell:ak.component.strand.discussion.timeline.v1:main";
        let payload = serde_json::json!({"realm_id": "realm-a", "main_strand_id": "main"});
        let writes = vec![timeline.to_owned()];
        let state = BTreeMap::from([(
            arkret_identifiers::CellRef::new(cell).unwrap(),
            ResolvedCellState::Value(serde_json::json!([{"tag":"endorsement", "value":payload}])),
        )]);
        assert!(direct_message_seal_covers(
            &state, cell, &payload, timeline, &writes
        ));
        assert!(!direct_message_seal_covers(
            &BTreeMap::new(),
            cell,
            &payload,
            timeline,
            &writes
        ));
        let bottom = BTreeMap::from([(
            arkret_identifiers::CellRef::new(cell).unwrap(),
            ResolvedCellState::Bottom(arkret_wire::Bottom::conflict(
                vec![arkret_identifiers::CellRef::new(cell).unwrap()],
                Vec::new(),
            )),
        )]);
        assert!(!direct_message_seal_covers(
            &bottom, cell, &payload, timeline, &writes
        ));
        assert!(!direct_message_seal_covers(
            &state,
            cell,
            &serde_json::json!({"realm_id":"other"}),
            timeline,
            &writes
        ));
        assert!(!direct_message_seal_covers(
            &state,
            cell,
            &payload,
            "other-strand",
            &writes
        ));
        assert!(!direct_message_seal_covers(
            &state,
            cell,
            &payload,
            timeline,
            &[timeline.to_owned(), "other-cell".to_owned()]
        ));
    }
}

fn direct_binding_payload_from_operation(
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<
    arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
    &'static str,
> {
    // The adapter keeps envelope context separate from the closed wire payload.
    let payload = operation.payload.clone();
    serde_json::from_value(payload).map_err(|_| "direct_conversation_binding_invalid")
}

pub(crate) async fn validate_direct_binding_operation(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<(), &'static str> {
    if soland_services::operation_semantics::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::DirectConversationBound)
    {
        return Ok(());
    }
    let payload = direct_binding_payload_from_operation(operation).map_err(|reason| {
        tracing::warn!(
            target: "soland_http::error",
            stage = "payload",
            reason,
            "direct conversation binding validation failed"
        );
        "direct_conversation_binding_invalid"
    })?;
    let issuer = &operation.context.sender;
    if operation
        .context
        .authorization_ref
        .as_ref()
        .map(|reference| reference.as_str())
        != Some(arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_BOOTSTRAP_PARTICIPANT_V1)
    {
        return Err("direct_conversation_bootstrap_authority_required");
    }
    if !payload
        .unordered_participant_ids
        .iter()
        .any(|participant| participant == issuer)
    {
        tracing::warn!(
            target: "soland_http::error",
            stage = "issuer_participant",
            issuer = %issuer,
            participants = ?payload.unordered_participant_ids,
            "direct conversation binding validation failed"
        );
        return Err("direct_conversation_binding_invalid");
    }
    let trust_domain = state.config().trust_domain.clone();
    payload.validate_pair_key(trust_domain).map_err(|_| {
        tracing::warn!(
            target: "soland_http::error",
            stage = "pair_key",
            pair_key = %payload.pair_key,
            participants = ?payload.unordered_participant_ids,
            "direct conversation binding validation failed"
        );
        "direct_conversation_binding_invalid"
    })?;

    // The canonical precursor Events are the admission authority. The MLS
    // activation is also a security-barrier singleton, so its accepted cell
    // projection must be visible before a binding can endorse it. A binding
    // that races projection catches up by exact retry; it must not treat a
    // merely stored activation proposal as final.
    if let Err(stage) = validate_direct_binding_event_refs(state, &payload).await {
        tracing::warn!(
            target: "soland_http::error",
            stage,
            realm_id = %payload.realm_id,
            "direct conversation binding validation failed"
        );
        return Err("direct_conversation_binding_invalid");
    }
    if payload.authorization_basis.kind
        == arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AcceptedContact
    {
        let left = &payload.unordered_participant_ids[0];
        let right = &payload.unordered_participant_ids[1];
        // `unordered_participant_ids` is canonical pair-key order, not contact
        // request direction. Resolve both directions or a random DID ordering
        // can make the same accepted contact intermittently disappear.
        let contact = accepted_contact_for_pair(state, left, right, "direct_message")
            .await
            .map_err(|error| {
                tracing::warn!(
                    target: "soland_http::error",
                    %error,
                    left = %left,
                    right = %right,
                    "direct conversation accepted-contact lookup failed"
                );
                "direct_conversation_binding_invalid"
            })?
            .ok_or("direct_conversation_binding_invalid")?;
        if contact.status != "accepted" {
            tracing::warn!(
                target: "soland_http::error",
                stage = "contact_status",
                status = %contact.status,
                "direct conversation binding validation failed"
            );
            return Err("direct_conversation_binding_invalid");
        }
        let verified_contact_refs = contact_fact_refs(&contact);
        if !accepted_contact_authorization_refs_match(
            &verified_contact_refs,
            &payload.authorization_basis.event_refs,
        ) {
            tracing::warn!(
                target: "soland_http::error",
                stage = "contact_refs",
                verified = ?verified_contact_refs,
                provided = ?payload.authorization_basis.event_refs,
                "direct conversation binding validation failed"
            );
            return Err("direct_conversation_binding_invalid");
        }
    }

    // §8.3 — the or_set element key is `(binding_digest, actor_id)`. A second
    // *distinct* digest for the same pair is a materialization conflict and
    // MUST be refused before projection; §9.3 forbids resolving it by picking a
    // winner. Re-endorsing the same coordinates (either participant, any number
    // of times) stays a compatible add and is admitted here.
    let digest = direct_binding_endorsement_digest(&payload)?;
    if let Some(bindings) = state
        .contacts()
        .direct_bindings_for_pair(payload.pair_key.as_ref())
        && !bindings.is_empty()
        && !bindings.digests().any(|known| known == digest)
    {
        tracing::warn!(
            target: "soland_http::error",
            stage = "pair_materialization_conflict",
            pair_key = %payload.pair_key,
            incoming = %digest,
            known = ?bindings.digests().collect::<Vec<_>>(),
            "direct conversation binding validation failed"
        );
        return Err(arkret_wire::ReasonCode::DIRECT_CONVERSATION_PAIR_MATERIALIZATION_CONFLICT);
    }
    Ok(())
}

async fn accepted_direct_event(
    state: &AppState,
    event_id: &arkret_identifiers::EventId,
    realm_id: &arkret_identifiers::RealmId,
    kind: &str,
) -> Result<arkret_wire::Event, &'static str> {
    let accepted = state
        .event_queries()
        .accepted_event(event_id.as_str())
        .await
        .map_err(|_| "referenced_event_query")?
        .ok_or("referenced_event_missing")?;
    if accepted.realm_id.as_deref() != Some(realm_id.as_str()) || accepted.kind != kind {
        return Err("referenced_event_mismatch");
    }
    serde_json::from_value(accepted.envelope).map_err(|_| "referenced_event_decode")
}

/// Validate a Direct Conversation binding against the accepted founding facts.
///
/// The binding no longer carries member/Strand/MLS refs: uniqueness comes from founder-only
/// admission, so this checks that the endorsed coordinates really are an accepted DM founding unit,
/// that the Realm creator is the founder derived from the pair's root Contact round, and that the
/// main Strand is accepted in the same Realm.
async fn validate_direct_binding_event_refs(
    state: &AppState,
    payload: &arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
) -> Result<(), &'static str> {
    let realm_create = accepted_direct_realm_create(state, &payload.realm_id).await?;
    let genesis = realm_create
        .payload
        .get("object")
        .cloned()
        .and_then(|object| {
            serde_json::from_value::<arkret_models_collaboration::events_payloads::RealmGenesis>(
                object,
            )
            .ok()
        })
        .ok_or("direct_conversation_realm_role_invalid")?;
    arkret_models_collaboration::objects::direct_conversation::DirectConversationRealmRole::validate(
        &genesis,
    )
    .map_err(|_| "direct_conversation_realm_role_invalid")?;

    let creator = &realm_create.actor_id;
    let participants: Vec<&arkret_wire::ActorId> =
        payload.unordered_participant_ids.iter().collect();
    if participants.len() != 2 || !participants.contains(&creator) {
        return Err("creator_participant");
    }

    // founder-only creation: the Realm creator MUST be the participant derived from the pair's root
    // authority. Anything else is not a competing candidate, it is invalid.
    let peer = participants
        .iter()
        .copied()
        .find(|participant| *participant != creator)
        .ok_or("direct_conversation_binding_invalid")?;
    validate_direct_founder(state, payload, creator, peer).await?;

    // Coordinates are derived from the exact accepted four-Event founding unit.
    // StrandCreate has no producer-selected object.id in the current protocol.
    let realm_events = state
        .event_queries()
        .projected_events_for_realm(payload.realm_id.as_str())
        .await
        .map_err(|_| "direct_conversation_binding_invalid")?;
    let mut founding = Vec::new();
    for projected in &realm_events {
        if !matches!(
            projected.event_kind,
            arkret_wire::EventKind::RealmCreate
                | arkret_wire::EventKind::MemberState
                | arkret_wire::EventKind::StrandCreate
        ) {
            continue;
        }
        let id =
            arkret_wire::EventId::new(projected.event_id.clone()).map_err(|_| "founding_ref")?;
        let event =
            accepted_direct_event(state, &id, &payload.realm_id, projected.event_kind.as_str())
                .await?;
        if event.actor_id == *creator && event.actor_seq <= 3 {
            founding.push(event);
        }
    }
    founding.sort_by_key(|event| event.actor_seq);
    let exact: [&arkret_wire::Event; 4] = founding
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "founding_unit_incomplete")?;
    let plan = arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingPlan::from_events(exact)
        .map_err(|_| "founding_unit_invalid")?;
    if plan.realm_id != payload.realm_id
        || plan.main_strand_id != payload.main_strand_id
        || plan.founding_unit_digest != payload.founding_unit_digest
    {
        return Err("founding_coordinates_mismatch");
    }
    let membership: arkret_models_collaboration::governance::membership_invite::MembershipPayload =
        serde_json::from_value(
            serde_json::to_value(&exact[2].payload).map_err(|_| "founding_payload")?,
        )
        .map_err(|_| "founding_membership")?;
    if membership.member_id != *peer {
        return Err("founding_peer_mismatch");
    }
    let initial = accepted_direct_event(
        state,
        &payload.initial_exact_pair_group_state_ref,
        &payload.realm_id,
        arkret_wire::EventKind::MlsCommit.as_str(),
    )
    .await?;
    let commit: arkret_models_crypto::MlsCommitPayload = serde_json::from_value(
        serde_json::to_value(initial.payload).map_err(|_| "initial_group_payload")?,
    )
    .map_err(|_| "initial_group_state_invalid")?;
    if commit.next_epoch() == 0 || commit.next_epoch() != commit.base_epoch().saturating_add(1) {
        return Err("initial_group_state_epoch");
    }
    let current_ref = direct_group_state_for_realm(state, payload.realm_id.as_str())
        .await
        .map_err(|_| "current_group_state_lookup")?
        .ok_or("current_group_state_not_unique")?;
    let current = accepted_direct_event(
        state,
        &current_ref,
        &payload.realm_id,
        arkret_wire::EventKind::MlsCommit.as_str(),
    )
    .await?;
    let current: arkret_models_crypto::MlsCommitPayload = serde_json::from_value(
        serde_json::to_value(current.payload).map_err(|_| "current_group_payload")?,
    )
    .map_err(|_| "current_group_state_invalid")?;
    if current.mls_group_id() != commit.mls_group_id() {
        return Err("group_cross_binding");
    }
    let mut consumed = false;
    for projected in &realm_events {
        if projected.event_kind != arkret_wire::EventKind::MlsWelcome {
            continue;
        }
        let welcome: arkret_models_collaboration::events_payloads::MlsWelcomePayload =
            serde_json::from_value(projected.payload.clone()).map_err(|_| "welcome_payload")?;
        if welcome.commit_ref != payload.initial_exact_pair_group_state_ref
            || welcome.epoch() != commit.next_epoch()
            || welcome.mls_group_id() != commit.mls_group_id()
            || welcome.recipient_principal_id.as_ref() != Some(peer.signing_principal_id())
        {
            continue;
        }
        let ledger = state
            .mls_key_packages()
            .peer_claim(
                welcome.claim_receipt.source_id.as_str(),
                welcome.claim_receipt.claim_request_id.as_str(),
            )
            .await
            .map_err(|_| "welcome_consume_lookup")?;
        if let Some(claim) = ledger.filter(|claim| claim.state == "consumed")
            && let Some(receipt) = claim.consume_receipt
        {
            let receipt: arkret_models_crypto::KeyPackageConsumeReceipt =
                serde_json::from_value(receipt).map_err(|_| "consume_receipt_invalid")?;
            let durable = &receipt.recipient_durable_receipt;
            consumed |= receipt.claim_id == welcome.claim_id
                && durable.welcome_ref.as_str() == projected.event_id
                && durable.realm_id == payload.realm_id
                && durable.mls_group_id.as_str() == welcome.mls_group_id()
                && durable.mls_epoch == welcome.epoch()
                && durable.key_package_ref.as_str() == welcome.keypackage_ref.as_str()
                && durable.recipient_principal_id().as_ref() == Some(peer.signing_principal_id());
        }
    }
    if !consumed {
        return Err("peer_welcome_not_durable");
    }

    match payload.authorization_basis.kind {
        arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AcceptedContact => {
            // Contact facts are principal-scoped projection facts, including facts delivered across
            // federation; the caller validates them against the accepted ContactRecord.
            if payload.authorization_basis.event_refs.len() != 2 {
                return Err("contact_ref_count");
            }
        }
        arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AgentController => {
            let mut authorization_kinds = BTreeSet::new();
            for event_ref in &payload.authorization_basis.event_refs {
                let accepted = state
                    .event_queries()
                    .accepted_event(event_ref.as_str())
                    .await
                    .map_err(|_| "direct_conversation_binding_invalid")?
                    .ok_or("direct_conversation_binding_invalid")?;
                authorization_kinds.insert(accepted.kind);
            }
            let expected = BTreeSet::from([
                arkret_wire::EventKind::AgentProvision.as_str().to_owned(),
                arkret_wire::EventKind::AgentKeyAuthorize.as_str().to_owned(),
            ]);
            if payload.authorization_basis.event_refs.len() != 2 || authorization_kinds != expected
            {
                return Err("agent_authorization_refs");
            }
            let record = state
                .agent_pairings()
                .agent(peer.signing_principal_id().as_str())
                .await
                .map_err(|_| "direct_conversation_binding_invalid")?
                .ok_or("direct_conversation_binding_invalid")?;
            // controller-to-own-Agent fixes the founder to the controller, so the Realm creator is
            // the controller and the Agent is the peer.
            if record.controller_principal_id != creator.signing_principal_id().as_str()
                || record.state != AgentLifecycleState::Active
            {
                return Err("agent_record");
            }
            let provision_refs = record
                .provision_event_refs
                .as_ref()
                .ok_or("direct_conversation_binding_invalid")?;
            let expected_refs = [
                provision_refs
                    .get("provision_event_id")
                    .and_then(Value::as_str),
                record.authorized_event_ref.as_deref(),
            ]
            .into_iter()
            .collect::<Option<BTreeSet<_>>>()
            .ok_or("direct_conversation_binding_invalid")?;
            let provided_refs = payload
                .authorization_basis
                .event_refs
                .iter()
                .map(arkret_identifiers::EventId::as_str)
                .collect::<BTreeSet<_>>();
            if provided_refs != expected_refs {
                return Err("agent_refs");
            }
            crate::routing::identity::agent_pcr::validate_agent_controller_binding(
                state,
                &record,
                payload.created_at.to_owned(),
            )
            .await
            .map_err(|_| "direct_conversation_binding_invalid")?;
        }
    }

    Ok(())
}

/// Locate the accepted `ak.realm.create` for a Direct Conversation Realm.
async fn accepted_direct_realm_create(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
) -> Result<arkret_wire::Event, &'static str> {
    let create_ref = state
        .event_queries()
        .projected_events_for_realm(realm_id.as_str())
        .await
        .map_err(|_| "direct_conversation_binding_invalid")?
        .into_iter()
        .find(|event| event.event_kind == arkret_wire::EventKind::RealmCreate)
        .map(|event| event.event_id)
        .ok_or("direct_conversation_binding_invalid")?;
    let event_id = arkret_identifiers::EventId::new(create_ref)
        .map_err(|_| "direct_conversation_binding_invalid")?;
    accepted_direct_event(
        state,
        &event_id,
        realm_id,
        arkret_wire::EventKind::RealmCreate.as_str(),
    )
    .await
}

/// Enforce founder-only creation.
///
/// The founder is derived from the pair's Contact round and is the sole principal allowed to author
/// the founding unit, which is what removes the cross-server creation race. A Realm created by the
/// other participant is not a competing candidate: it is invalid and MUST NOT be projected.
async fn validate_direct_founder(
    state: &AppState,
    payload: &arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
    creator: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
) -> Result<(), &'static str> {
    use arkret_models_collaboration::objects::direct_conversation::{
        DirectConversationAuthorizationKind, DirectConversationFoundingAuthority,
        direct_conversation_founder,
    };

    let authority = match payload.authorization_basis.kind {
        // controller-to-own-Agent has no Contact round: the founder is fixed to the controller so
        // an Agent runtime key never needs Direct Conversation founding scope.
        DirectConversationAuthorizationKind::AgentController => {
            DirectConversationFoundingAuthority::ControllerOwnedAgent {
                controller_actor_id: creator.clone(),
            }
        }
        DirectConversationAuthorizationKind::AcceptedContact => {
            let record = accepted_contact_for_pair(state, creator, peer, "direct_message")
                .await
                .map_err(|_| "direct_conversation_binding_invalid")?
                .ok_or("direct_conversation_founding_authority_unavailable")?;
            direct_founding_authority_from_contact(&record)?
        }
    };

    let [left, right]: [arkret_wire::ActorId; 2] = payload
        .unordered_participant_ids
        .clone()
        .try_into()
        .map_err(|_| "direct_conversation_binding_invalid")?;
    let founder = direct_conversation_founder([left, right], &authority)
        .map_err(|_| "direct_conversation_founding_authority_unavailable")?;
    if &founder != creator {
        tracing::warn!(
            target: "soland_http::error",
            stage = "founder",
            creator = %creator,
            founder = %founder,
            "direct conversation Realm was not created by the derived founder"
        );
        return Err("direct_conversation_founder_mismatch");
    }
    Ok(())
}

fn accepted_contact_authorization_refs_match(
    verified_contact_refs: &[String],
    provided_refs: &[arkret_identifiers::EventId],
) -> bool {
    let verified = verified_contact_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let provided = provided_refs
        .iter()
        .map(arkret_identifiers::EventId::as_str)
        .collect::<BTreeSet<_>>();
    verified.len() == 2 && provided.len() == 2 && provided == verified
}

/// or_set add for one accepted `ak.direct_conversation.bound` Event.
///
/// `contact-and-direct-conversation.md` §8.3 fixes the element key at
/// `(binding_digest, envelope.actor_id)`: the same participant re-signing the
/// same coordinates counts once, and both participants signing the same
/// coordinates are compatible adds that MUST NOT join to bottom. Nothing here
/// picks a winner between two different endorsements — §9.3 forbids any such
/// selector, and a second distinct digest is refused at admission by
/// [`validate_direct_binding_operation`] and surfaces as `suspended`.
pub(crate) async fn project_canonical_direct_binding(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) {
    if soland_services::operation_semantics::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::DirectConversationBound)
    {
        return;
    }
    let Ok(payload) = direct_binding_payload_from_operation(operation) else {
        return;
    };
    let event_ref = operation.context.event_id.to_string();
    let actor_id = operation.context.sender.to_string();
    let Ok(digest) = direct_binding_endorsement_digest(&payload) else {
        return;
    };
    state.contacts().endorse_direct_binding(
        payload.pair_key.as_ref(),
        digest,
        soland_services::identity::DirectConversationCoordinatesRecord {
            participants_unordered: payload
                .unordered_participant_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            realm_id: payload.realm_id.to_string(),
            main_strand_id: payload.main_strand_id.to_string(),
            created_at: payload.created_at,
        },
        soland_services::identity::DirectConversationEndorsement {
            actor_id,
            binding_event_ref: event_ref,
        },
    );
}

/// Identity of one endorsement inside the or_set.
///
/// §8.3 derives the element key from the registered
/// `ak.direct-conversation.binding-digest.v1` domain and the closed normalized
/// binding object. `created_at` and Event author/proof are excluded, so two
/// participants endorsing the same coordinates at different wall-clock times
/// collapse to the same semantic digest. The digest remains receiver-derived
/// and MUST NOT appear in the payload.
fn direct_binding_endorsement_digest(
    payload: &arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
) -> Result<String, &'static str> {
    payload
        .binding_digest()
        .map(|digest| digest.into_string())
        .map_err(|_| "direct_conversation_binding_invalid")
}

/// Derive the founding authority from an accepted Contact record.
///
/// Normal branch: the founder is the **responder**, i.e. the participant that is not the request
/// issuer. This is normative, not a coin flip. The authority is lit up by the responder's
/// `normal_response_acceptance_receipt`, which proves the responder was online at the moment the
/// authority came into existence; the requester_id may have gone offline days earlier. Base v1
/// defines no fallback, so naming the possibly-absent party would leave the pair unable to ever
/// create the conversation.
pub(crate) fn direct_founding_authority_from_contact(
    record: &ContactRecord,
) -> Result<
    arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthority,
    &'static str,
> {
    if let Some(bundle) = record.contact_round_evidence.as_ref() {
        if record.contact_round_id.as_ref() != Some(&bundle.contact_round_id) {
            return Err("direct_conversation_founding_authority_unavailable");
        }
        arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingAuthorityEvidence::Human {
            contact_round_evidence: bundle.clone(),
            contact_round_continuity_chains: record.contact_round_evidence_history.clone(),
        }
        .participants_and_founder()
        .map_err(|_| "direct_conversation_founding_authority_unavailable")?;
        arkret_models_collaboration::contact_operations::validate_recontact_continuity(
            bundle,
            &record.contact_round_evidence_history,
        )
        .map_err(|_| "direct_conversation_founding_authority_unavailable")?;
        let root = record
            .contact_round_evidence_history
            .last()
            .unwrap_or(bundle);
        root.contact_round
            .validate_canonical_order()
            .map_err(|_| "direct_conversation_founding_authority_unavailable")?;
        if let arkret_models_collaboration::contact_operations::ContactRound::Glare {
            requests,
            ..
        } = &root.contact_round
        {
            let attestations = root
                .glare_concurrency_attestations
                .as_ref()
                .ok_or("direct_conversation_founding_authority_unavailable")?;
            if root.request_receipts.len() != 2
                || attestations.iter().any(|attestation| {
                    attestation.complete_through == 0
                        || requests.iter().any(|request| {
                            !attestation
                                .observed_frontier
                                .contains(&request.request_event_ref)
                        })
                })
            {
                return Err("direct_conversation_founding_authority_unavailable");
            }
            let first = &requests[0];
            let receipt = root
                .request_receipts
                .iter()
                .find(|receipt| receipt.core.request_event_ref == first.request_event_ref)
                .ok_or("direct_conversation_founding_authority_unavailable")?;
            let digest = arkret_identifiers::Hash::new(
                arkret_canonical::canonical_sha256(receipt)
                    .map_err(|_| "direct_conversation_founding_authority_unavailable")?,
            )
            .map_err(|_| "direct_conversation_founding_authority_unavailable")?;
            if digest != first.request_acceptance_receipt_digest {
                return Err("direct_conversation_founding_authority_unavailable");
            }
            return Ok(
                arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthority::Glare {
                    first_request_author_actor_id: receipt.core.holder.contact_actor_id().clone(),
                },
            );
        }
        let arkret_models_collaboration::contact_operations::ContactRound::Normal {
            request_event_ref,
            ..
        } = &root.contact_round
        else {
            unreachable!("glare returned above")
        };
        let request_author_actor_id = root
            .request_receipts
            .iter()
            .find(|receipt| receipt.core.request_event_ref == *request_event_ref)
            .map(|receipt| receipt.core.holder.contact_actor_id().clone())
            .ok_or("direct_conversation_founding_authority_unavailable")?;
        return Ok(
            arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthority::Normal {
                request_author_actor_id,
            },
        );
    }
    Err("direct_conversation_founding_authority_unavailable")
}

/// Which participant may author the founding unit for this pair, if it can be determined now.
///
/// Returns `None` when the authority cannot be verified, so the caller reports
/// `temporarily_unavailable` rather than inventing an answer.
pub(crate) async fn direct_founder_for_pair(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    contact: Option<&ContactRecord>,
    agent: bool,
) -> Result<Option<String>, AppError> {
    use arkret_models_collaboration::objects::direct_conversation::{
        DirectConversationFoundingAuthority, direct_conversation_founder,
    };

    let authority = if agent {
        // controller-to-own-Agent has no Contact round; the founder is fixed to the controller so
        // an Agent runtime key never needs Direct Conversation founding scope.
        let controller = if state
            .agent_pairings()
            .agent(peer.signing_principal_id().as_str())
            .await
            .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?
            .is_some()
        {
            actor
        } else {
            peer
        };
        DirectConversationFoundingAuthority::ControllerOwnedAgent {
            controller_actor_id: controller.clone(),
        }
    } else {
        let Some(record) = contact else {
            return Ok(None);
        };
        match direct_founding_authority_from_contact(record) {
            Ok(authority) => authority,
            Err(_) => return Ok(None),
        }
    };

    Ok(
        direct_conversation_founder([actor.clone(), peer.clone()], &authority)
            .ok()
            .map(|founder| founder.to_string()),
    )
}
