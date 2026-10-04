#[cfg(test)]
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
    super::contact_write::verify_stored_contact_evidence_for_read(state, record, true).await?;
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
        let glare_request_head = head.is_none()
            && proof.complete_through == 1
            && bundle.glare_concurrency_attestations.is_some()
            && bundle.request_receipts.iter().any(|receipt| {
                receipt.core.holder.contact_actor_id() == *holder
                    && receipt.core.request_event_ref == proof.head_event_ref
            });
        if proof.terminal
            || (head != Some(&proof.head_event_ref) && !glare_request_head)
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
        let Some(accepted) = state
            .authority_commits()
            .committed_event(&proof.head_event_ref)
            .await
            .map_err(|error| {
                AppError::internal(format!("Contact head decision lookup: {error}"))
            })?
        else {
            return Ok(None);
        };
        if accepted.commit.event_ref != proof.head_event_ref {
            return Ok(None);
        }
        let event = accepted.event;
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
        )
        .await?;
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
        arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthorityEvidence::Human {
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
                                .observed_commit_event_ids
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
