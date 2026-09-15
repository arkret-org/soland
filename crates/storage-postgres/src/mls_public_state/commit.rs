//! Public transition candidates. None of these rows is membership authority.
use std::collections::{BTreeMap, BTreeSet};

use arkret_mls::{MlsPublicGroupTracker, MlsPublicHandshakeTransition};
use arkret_models_collaboration::events_payloads::{
    MlsDecodedProposalType, MlsProposalMemberBinding, MlsProposalPayload,
    admit_durable_mls_proposal,
};
use diesel::sql_types::{Array, BigInt, Binary, Jsonb};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;
use soland_storage::{PersistenceError, PersistenceResult};

fn fail(message: impl ToString) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {}", message.to_string()))
}

fn fail_with_code(code: arkret_wire::ErrorCode, message: impl ToString) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {}", code.as_str(), message.to_string()))
}

fn fail_mls(error: arkret_mls::MlsError) -> PersistenceError {
    match error {
        arkret_mls::MlsError::UnsupportedFeature(message) => {
            fail_with_code(arkret_wire::ErrorCode::UnsupportedFeature, message)
        }
        error => fail(error),
    }
}

#[derive(diesel::QueryableByName)]
struct Source {
    #[diesel(sql_type=BigInt)]
    pk: i64,
    #[diesel(sql_type=Jsonb)]
    envelope: serde_json::Value,
}
#[derive(diesel::QueryableByName)]
struct State {
    #[diesel(sql_type=Binary)]
    public_state: Vec<u8>,
}
#[derive(diesel::QueryableByName)]
struct Producer {
    #[diesel(sql_type=Jsonb)]
    producer: serde_json::Value,
}

pub(super) fn validate_sender(
    event: &arkret_wire::Event,
    producer: &soland_storage::MlsPublicHandshakeProducer,
    leaf: Option<&arkret_mls::MlsPublicEndpointLeaf>,
) -> PersistenceResult<()> {
    let leaf = leaf.ok_or_else(|| {
        fail("MLS public non-member producer requires an explicit admission authority")
    })?;
    let key = arkret_canonical::decode_ed25519_multibase(
        producer
            .signing_key
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| fail("MLS producer key is not did:key"))?,
    )
    .map_err(fail)?;
    if leaf.signature_key.as_str() != arkret_canonical::base64url_encode(&key) {
        return Err(fail("MLS message signer differs from its Event producer"));
    }
    match &leaf.endpoint_credential {
        arkret_mls::MlsPublicLeafEndpointCredential::HumanDevice { device_id }
            if producer.device_id.as_ref() == Some(device_id) =>
        {
            Ok(())
        }
        arkret_mls::MlsPublicLeafEndpointCredential::Actor { actor_id }
            if actor_id.as_str()
                == event
                    .executed_by
                    .as_ref()
                    .unwrap_or(&event.actor_id)
                    .signing_principal_id()
                    .as_str() =>
        {
            Ok(())
        }
        _ => Err(fail(
            "MLS sender credential differs from its Event producer",
        )),
    }
}

pub(super) async fn commit_handshake(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    event: &arkret_wire::Event,
    producer: Option<&soland_storage::MlsPublicHandshakeProducer>,
) -> PersistenceResult<()> {
    let producer = producer
        .ok_or_else(|| fail("MLS public handshake requires frozen verified producer evidence"))?;
    if event.kind.as_str() == "ak.mls.proposal" {
        // RFC validation is deferred until the Proposal is consumed against an
        // exact base; this row preserves the already-verified Event producer.
        let _: MlsProposalPayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(fail)?)
                .map_err(fail)?;
        let count=sql_query("INSERT INTO mls_public_proposal_sources(event_pk,producer,source_canonical_bytes,source_available) VALUES($1,$2,$3,TRUE) ON CONFLICT(event_pk) DO UPDATE SET source_available=TRUE,producer=EXCLUDED.producer,source_canonical_bytes=EXCLUDED.source_canonical_bytes WHERE mls_public_proposal_sources.source_canonical_bytes<>EXCLUDED.source_canonical_bytes OR mls_public_proposal_sources.producer=EXCLUDED.producer")
            .bind::<BigInt,_>(event_pk).bind::<Jsonb,_>(serde_json::to_value(producer).map_err(fail)?)
            .bind::<Binary,_>(arkret_canonical::canonical_json_bytes(&event.digest_payload().map_err(fail)?).map_err(fail)?).execute(conn).await.map_err(PersistenceError::database)?;
        if count != 1 {
            return Err(fail("MLS Proposal producer changed on exact retry"));
        }
        Ok(())
    } else {
        commit_candidate(conn, event_pk, event, producer).await
    }
}

async fn source(
    conn: &mut AsyncPgConnection,
    id: &arkret_wire::EventId,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<(i64, arkret_wire::Event)> {
    let row = sql_query(
        "SELECT pk,envelope FROM canonical_events WHERE id=$1 AND realm_id=$2 AND state='accepted' FOR SHARE",
    )
    .bind::<Binary, _>(id.token_bytes().to_vec())
    .bind::<diesel::sql_types::Text,_>(realm_id.as_str())
    .get_result::<Source>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| fail("accepted MLS source Event is unavailable"))?;
    let event = serde_json::from_value(row.envelope).map_err(fail)?;
    Ok((row.pk, event))
}

async fn add_membership_sources(
    conn: &mut AsyncPgConnection,
    scope: &arkret_wire::ScopeRef,
    proposal: &MlsProposalPayload,
    dependencies: &mut BTreeSet<i64>,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::history_key::AuthorizationIncarnation;
    let Some(incarnation) = &proposal.target_authorization_incarnation else {
        return Ok(());
    };
    let target = proposal
        .target_actor_id
        .as_ref()
        .ok_or_else(|| fail("Add has no target Actor"))?;
    let (realm_ref, circle_ref) = match incarnation {
        AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref,
        } => (realm_membership_incarnation_ref, None),
        AuthorizationIncarnation::Circle {
            realm_membership_incarnation_ref,
            circle_membership_incarnation_ref,
        } => (
            realm_membership_incarnation_ref,
            Some(circle_membership_incarnation_ref),
        ),
    };
    let realm = match scope {
        arkret_wire::ScopeRef::Realm { realm_id }
        | arkret_wire::ScopeRef::Circle { realm_id, .. } => realm_id,
        _ => return Err(fail("Add membership source requires Realm or Circle scope")),
    };
    let (pk, event) = source(conn, realm_ref, realm).await?;
    let expected_scope = arkret_wire::ScopeRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    if event.kind.as_str() != "ak.member.state"
        || event.scope_ref != expected_scope
        || !matches!(scope, arkret_wire::ScopeRef::Realm { realm_id } | arkret_wire::ScopeRef::Circle { realm_id, .. } if realm_id == &event.realm_id)
    {
        return Err(fail(
            "Add Realm incarnation is not a membership Event in its Realm",
        ));
    }
    let membership: arkret_models_collaboration::governance::membership_invite::MembershipPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).map_err(fail)?).map_err(fail)?;
    if &membership.member_id != target || membership.membership != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join {
        return Err(fail("Add Realm incarnation does not identify the target's join"));
    }
    dependencies.insert(pk);
    if let Some(reference) = circle_ref {
        let (pk, event) = source(conn, reference, realm).await?;
        if event.kind.as_str() != "ak.circle.member.state" || &event.scope_ref != scope {
            return Err(fail(
                "Add Circle incarnation is not a membership Event in its Circle",
            ));
        }
        let membership: arkret_models_collaboration::events_payloads::CircleMemberStatePayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(fail)?)
                .map_err(fail)?;
        if &membership.member_id != target
            || serde_json::to_value(membership.membership).map_err(fail)? != json!("join")
        {
            return Err(fail(
                "Add Circle incarnation does not identify the target's join",
            ));
        }
        dependencies.insert(pk);
    }
    Ok(())
}

/// Exact durable source bytes are processed against one exact public base.
/// A Seal publisher still decides whether this candidate wins; source lineage
/// authorization and original membership readiness are intentionally separate.
async fn commit_candidate(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    event: &arkret_wire::Event,
    producer: &soland_storage::MlsPublicHandshakeProducer,
) -> PersistenceResult<()> {
    let payload: arkret_models_crypto::MlsCommitPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).map_err(fail)?)
            .map_err(fail)?;
    let base_id = payload.base_epoch_ref().parse().map_err(fail)?;
    let (base_pk, base) = source(conn, &base_id, &event.realm_id).await?;
    if base.scope_ref != event.scope_ref || base.realm_id != event.realm_id {
        return Err(fail("MLS base belongs to another security scope"));
    }
    let state=sql_query("SELECT g.public_state FROM mls_public_genesis_states g JOIN canonical_events e ON e.pk=g.event_pk WHERE g.event_pk=$1 AND g.source_available AND g.source_canonical_bytes=e.canonical_bytes UNION ALL SELECT c.public_state FROM mls_public_commit_states c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.event_pk=$1 AND c.source_available AND c.source_canonical_bytes=e.canonical_bytes")
        .bind::<BigInt,_>(base_pk).get_result::<State>(conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||fail("exact verified MLS public base is unavailable"))?;
    let mut tracker = MlsPublicGroupTracker::restore(
        &state.public_state,
        payload.mls_group_id(),
        payload.base_epoch(),
    )
    .map_err(fail)?;
    let base_leaves = tracker
        .leaves()
        .map_err(fail)?
        .into_iter()
        .map(|leaf| (leaf.leaf_index, leaf))
        .collect::<BTreeMap<_, _>>();
    let original_authorizations = super::authority::retained(conn, &event.event_id, false).await?;
    let mut leaf_authorizations = super::authority::read_authorizations(conn, &base_id)
        .await?
        .map(|values| {
            values
                .into_iter()
                .map(|value| (value.leaf_index, value))
                .collect::<BTreeMap<_, _>>()
        });
    if payload.governance_binding().effective_scope() != &event.scope_ref
        || event.scope_ref.canonical_mls_group_id().map_err(fail)? != payload.mls_group_id()
    {
        return Err(fail("MLS Commit group and governance scope mismatch"));
    }
    let mut dependencies = BTreeSet::from([base_pk]);
    let mut proposals = BTreeMap::new();
    for id in payload.proposal_refs() {
        let (pk, proposal) = source(conn, id, &event.realm_id).await?;
        if proposal.kind.as_str() != "ak.mls.proposal"
            || proposal.scope_ref != event.scope_ref
            || proposal.realm_id != event.realm_id
        {
            return Err(fail(
                "MLS Commit source is not a Proposal in its exact scope",
            ));
        }
        let value: MlsProposalPayload =
            serde_json::from_value(serde_json::to_value(&proposal.payload).map_err(fail)?)
                .map_err(fail)?;
        if value.mls_group_id.as_str() != payload.mls_group_id()
            || value.base_epoch != payload.base_epoch()
        {
            return Err(fail("MLS Proposal belongs to another group or epoch"));
        }
        add_membership_sources(conn, &event.scope_ref, &value, &mut dependencies).await?;
        let bytes = arkret_canonical::base64url_decode(&value.proposal_bytes_b64).map_err(fail)?;
        let MlsPublicHandshakeTransition::Proposal {
            proposal_ref,
            proposal_type,
            sender_class,
            sender_leaf,
            ..
        } = tracker.process_public_handshake(&bytes).map_err(fail_mls)?
        else {
            return Err(fail(
                "durable MLS Proposal bytes contain a non-Proposal message",
            ));
        };
        let producer_row =
            sql_query("SELECT p.producer FROM mls_public_proposal_sources p JOIN canonical_events e ON e.pk=p.event_pk WHERE p.event_pk=$1 AND p.source_available AND p.source_canonical_bytes=e.canonical_bytes")
                .bind::<BigInt, _>(pk)
                .get_result::<Producer>(conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?
                .ok_or_else(|| fail("accepted MLS Proposal producer evidence is unavailable"))?;
        let proposal_producer = serde_json::from_value(producer_row.producer).map_err(fail)?;
        let member_binding = MlsProposalMemberBinding {
            leaf_occupied_in_exact_base: sender_leaf.is_some(),
            leaf_binds_verified_producer: sender_leaf.as_ref().is_some_and(|leaf| {
                validate_sender(&proposal, &proposal_producer, Some(leaf)).is_ok()
            }),
        };
        admit_durable_mls_proposal(
            sender_class,
            MlsDecodedProposalType::from_codepoint(proposal_type),
            value.proposal_type,
            member_binding,
        )
        .map_err(|rejection| fail_with_code(rejection.error_code, rejection.reason))?;
        if proposals.insert(proposal_ref, (proposal, value)).is_some() {
            return Err(fail(
                "multiple durable Events identify the same MLS Proposal",
            ));
        }
        dependencies.insert(pk);
    }
    let bytes = arkret_canonical::base64url_decode(payload.commit_bytes_b64()).map_err(fail)?;
    let MlsPublicHandshakeTransition::Commit {
        sender_class,
        sender_leaf,
        epoch,
        referenced_proposal_refs,
        added_leaves,
        added_leaf_proposal_refs,
        removed_leaf_indices,
        updated_leaf_indices,
        ..
    } = tracker.process_public_handshake(&bytes).map_err(fail_mls)?
    else {
        return Err(fail("MLS Commit bytes contain a non-Commit message"));
    };
    if !sender_class.is_supported() {
        return Err(fail_with_code(
            arkret_wire::ErrorCode::UnsupportedFeature,
            "v1 durable Commits accept only a Member sender of the exact base group",
        ));
    }
    validate_sender(event, producer, sender_leaf.as_ref())?;
    let consumed = referenced_proposal_refs
        .into_iter()
        .collect::<BTreeSet<_>>();
    if consumed != proposals.keys().cloned().collect()
        || epoch != payload.next_epoch()
        || tracker.governance_binding().map_err(fail)?.as_ref()
            != Some(payload.governance_binding())
    {
        return Err(fail(
            "MLS actual consumed Proposal set, epoch or governance binding differs from the Event",
        ));
    }
    let added_sources = added_leaf_proposal_refs
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    if let Some(authorizations) = &mut leaf_authorizations {
        for index in &removed_leaf_indices {
            authorizations.remove(index);
        }
    }
    let post_leaves = tracker.leaves().map_err(fail)?;
    for leaf in &post_leaves {
        if !added_sources.contains_key(&leaf.leaf_index) {
            let previous = base_leaves
                .get(&leaf.leaf_index)
                .ok_or_else(|| fail("retained MLS leaf has no base"))?;
            if previous.credential_ref != leaf.credential_ref
                || previous.signature_key != leaf.signature_key
            {
                return Err(fail(
                    "MLS Update cannot replace endpoint credential or signing key",
                ));
            }
        }
    }
    let mut additions = Vec::new();
    let mut used_adds = BTreeSet::new();
    for leaf in added_leaves {
        let reference = added_sources
            .get(&leaf.leaf_index)
            .ok_or_else(|| fail("new MLS leaf has no durable Add source"))?;
        let (proposal, value) = proposals
            .get(reference)
            .ok_or_else(|| fail("inline or unreferenced MLS Add is forbidden"))?;
        if value.proposal_type != arkret_models_collaboration::events_payloads::MlsProposalType::Add
            || !used_adds.insert(reference.clone())
        {
            return Err(fail("MLS Add sources and new leaves are not a bijection"));
        }
        // A target Actor/incarnation and a public key do not carry the exact
        // endpoint authorization. Until verified Add provenance is retained,
        // this candidate cannot supply a complete accepted-artifact result.
        // In particular, never inherit an old origin after Remove+Add.
        leaf_authorizations = None;
        additions.push(json!({"leaf":leaf,"proposal_event_ref":proposal.event_id,
            "declared_target_actor_id":value.target_actor_id,"declared_target_authorization_incarnation":value.target_authorization_incarnation}));
    }
    let expected_adds = proposals
        .iter()
        .filter(|(_, (_, value))| {
            value.proposal_type
                == arkret_models_collaboration::events_payloads::MlsProposalType::Add
        })
        .map(|(reference, _)| reference.clone())
        .collect::<BTreeSet<_>>();
    if used_adds != expected_adds {
        return Err(fail(
            "accepted Add proposals do not exactly explain the new public leaves",
        ));
    }
    let transition = json!({"removed_leaf_indices":removed_leaf_indices,"added":additions,"updated_leaf_indices":updated_leaf_indices});
    let public_state = tracker.export_state().map_err(fail)?;
    // Same immutable Event is deterministic. Reactivation is allowed only
    // after all exact sources have just been locked and revalidated above.
    let count=sql_query("INSERT INTO mls_public_commit_states(event_pk,base_event_pk,public_state,transition,source_available,source_canonical_bytes) VALUES($1,$2,$3,$4,TRUE,$5) ON CONFLICT(event_pk) DO UPDATE SET source_available=TRUE,base_event_pk=EXCLUDED.base_event_pk,public_state=EXCLUDED.public_state,transition=EXCLUDED.transition,source_canonical_bytes=EXCLUDED.source_canonical_bytes WHERE mls_public_commit_states.source_canonical_bytes<>EXCLUDED.source_canonical_bytes OR (mls_public_commit_states.base_event_pk=EXCLUDED.base_event_pk AND mls_public_commit_states.public_state=EXCLUDED.public_state AND mls_public_commit_states.transition=EXCLUDED.transition)")
        .bind::<BigInt,_>(event_pk).bind::<BigInt,_>(base_pk).bind::<Binary,_>(&public_state).bind::<Jsonb,_>(transition)
        .bind::<Binary,_>(arkret_canonical::canonical_json_bytes(&event.digest_payload().map_err(fail)?).map_err(fail)?)
        .execute(conn).await.map_err(PersistenceError::database)?;
    if count != 1 {
        return Err(fail("MLS public Commit candidate changed on exact retry"));
    }
    let leaf_authorizations = original_authorizations
        .unwrap_or_else(|| leaf_authorizations.map(|values| values.into_values().collect()));
    if leaf_authorizations.as_ref().is_some_and(|values| {
        values.len() != post_leaves.len()
            || values
                .iter()
                .zip(&post_leaves)
                .any(|(authorization, leaf)| authorization.leaf_index != leaf.leaf_index)
    }) {
        return Err(fail(
            "retained authority does not cover the exact public tree",
        ));
    }
    sql_query("UPDATE mls_public_commit_states SET leaf_authorizations=$2 WHERE event_pk=$1")
        .bind::<BigInt, _>(event_pk)
        .bind::<diesel::sql_types::Nullable<Jsonb>, _>(
            leaf_authorizations
                .map(serde_json::to_value)
                .transpose()
                .map_err(fail)?,
        )
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    sql_query("DELETE FROM mls_public_transition_dependencies WHERE transition_event_pk=$1")
        .bind::<BigInt, _>(event_pk)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    sql_query("INSERT INTO mls_public_transition_dependencies(transition_event_pk,source_event_pk) SELECT $1,unnest($2::bigint[]) ON CONFLICT DO NOTHING")
        .bind::<BigInt,_>(event_pk).bind::<Array<BigInt>,_>(dependencies.into_iter().collect::<Vec<_>>())
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_sender_and_group_extension_keep_the_registered_conflict_code() {
        let rejection = admit_durable_mls_proposal(
            arkret_models_collaboration::events_payloads::MlsProposalSenderClass::External,
            MlsDecodedProposalType::Remove,
            arkret_models_collaboration::events_payloads::MlsProposalType::Remove,
            MlsProposalMemberBinding {
                leaf_occupied_in_exact_base: false,
                leaf_binds_verified_producer: false,
            },
        )
        .unwrap_err();
        let error = fail_with_code(rejection.error_code, rejection.reason);
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::UnsupportedFeature)
        );

        let error = fail_mls(arkret_mls::MlsError::UnsupportedFeature(
            "external_senders is forbidden".to_owned(),
        ));
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::UnsupportedFeature)
        );
    }

    #[test]
    fn producer_binding_errors_keep_distinct_wire_codes() {
        let missing = admit_durable_mls_proposal(
            arkret_models_collaboration::events_payloads::MlsProposalSenderClass::Member,
            MlsDecodedProposalType::Remove,
            arkret_models_collaboration::events_payloads::MlsProposalType::Remove,
            MlsProposalMemberBinding {
                leaf_occupied_in_exact_base: false,
                leaf_binds_verified_producer: false,
            },
        )
        .unwrap_err();
        assert_eq!(
            fail_with_code(missing.error_code, missing.reason).conflict_code(),
            Some(soland_storage::ConflictCode::FailedPrecondition)
        );

        let wrong_producer = admit_durable_mls_proposal(
            arkret_models_collaboration::events_payloads::MlsProposalSenderClass::Member,
            MlsDecodedProposalType::Remove,
            arkret_models_collaboration::events_payloads::MlsProposalType::Remove,
            MlsProposalMemberBinding {
                leaf_occupied_in_exact_base: true,
                leaf_binds_verified_producer: false,
            },
        )
        .unwrap_err();
        assert_eq!(
            fail_with_code(wrong_producer.error_code, wrong_producer.reason).conflict_code(),
            Some(soland_storage::ConflictCode::SignatureInvalid)
        );
    }
}
