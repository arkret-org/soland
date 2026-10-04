//! Direct resolver MLS facts from the member Station's verified held cut.

use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody;
use arkret_models_crypto::MlsCommitPayload;
use arkret_wire::{
    ActorId, CurrentSelector, EventKind, MlsGroupCurrent, ScopeRef, TypedCurrentResult,
};
use soland_services::{ServiceError, ServiceResult};

use super::AppState;

fn unavailable(detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!(
        "temporarily_unavailable: member Direct MLS current: {detail}"
    ))
}

impl AppState {
    pub(crate) async fn refresh_direct_replica_group(
        &self,
        caller: &ActorId,
        facts: &mut soland_storage::DirectConversationDurableState,
    ) -> ServiceResult<()> {
        let realm = facts.founding_slot.realm_id.parse().map_err(unavailable)?;
        let authority = self
            .authority_commits()
            .current_authority(&realm)
            .await?
            .ok_or_else(|| unavailable("Realm authority is absent"))?;
        if authority.service_id == self.service_core_id() || facts.binding.is_none() {
            return Ok(());
        }
        let account = caller
            .as_account_id()
            .filter(|account| account.station_id == self.service_core_id())
            .ok_or_else(|| unavailable("caller is not a hosted Account"))?;
        // An accepted departure already proves suspension. Do not request
        // public material after the caller's readable interval has closed.
        if facts
            .members
            .iter()
            .any(|member| &member.member_id == caller && member.membership != "join")
        {
            return Ok(());
        }
        let binding = facts.binding.as_ref().unwrap();
        binding.binding_digest().map_err(unavailable)?;
        let payload = &binding
            .endorsements
            .first()
            .ok_or_else(|| unavailable("binding is empty"))?
            .value;
        if payload.realm_id != realm
            || payload.main_strand_id.as_str() != facts.founding_slot.main_strand_id
        {
            return Err(unavailable("binding differs from founding coordinates"));
        }
        let pair = payload
            .unordered_participant_ids
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if pair.len() != 2 || !pair.contains(caller) {
            return Err(unavailable("caller is outside the exact pair"));
        }
        let participants: [ActorId; 2] = pair
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| unavailable("pair cardinality differs"))?;
        let pair_key = facts.founding_slot.pair_key.parse().map_err(unavailable)?;
        let material = self
            .authority_commits()
            .direct_conversation_replica_cut(&realm, account, &pair_key, &participants)
            .await?
            .ok_or_else(|| unavailable("verified bounded current is absent"))?;
        if material.authority != authority {
            return Err(unavailable("Realm authority changed before verification"));
        }
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let selector = CurrentSelector::MlsGroup {
            scope_ref: scope.clone(),
        };
        let group: MlsGroupCurrent = material
            .current_state_entries
            .iter()
            .find_map(|entry| {
                let TypedCurrentResult::Value {
                    selector: found,
                    source_stream_ref,
                    value,
                    ..
                } = entry;
                (found == &selector
                    && source_stream_ref
                        == &arkret_wire::CommitStreamRef::Realm {
                            realm_id: realm.clone(),
                        })
                    .then(|| serde_json::from_value(value.clone()))
            })
            .transpose()
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("signed MLS current is absent"))?;
        if group.effective_scope != scope {
            return Err(unavailable("MLS selector differs"));
        }
        if !material.current_state_entries.iter().any(|entry| {
            let TypedCurrentResult::Value {
                selector,
                source_stream_ref,
                value,
                ..
            } = entry;
            matches!(selector, CurrentSelector::DirectConversationBinding { pair_key: found } if found == &pair_key)
                && source_stream_ref
                    == &arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm.clone(),
                    }
                && serde_json::to_value(binding).is_ok_and(|expected| expected == *value)
        }) {
            return Err(unavailable(
                "binding and MLS current are from different cuts",
            ));
        }
        let head = &material.head;

        // Follow exact accepted base refs, never timestamps or a Realm-wide scan.
        let mut next = group.current_mls_commit_event_ref.clone();
        let mut expected_epoch = group.epoch;
        let mut commits = Vec::new();
        let mut following_position = head
            .stream_position
            .checked_add(1)
            .ok_or_else(|| unavailable("Realm head overflow"))?;
        while next != group.genesis_event_ref {
            let record = self
                .authority_commits()
                .committed_event(&next)
                .await?
                .ok_or_else(|| unavailable("accepted MLS base is unavailable"))?;
            if record.event.realm_id != realm
                || record.event.scope_ref != scope
                || record.event.kind != EventKind::MlsCommit
            {
                return Err(unavailable("MLS base belongs to another scope or kind"));
            }
            if record.commit.stream_ref != head.stream_ref
                || record.commit.event_ref != record.event.event_id
                || record.commit.stream_position >= following_position
            {
                return Err(unavailable("MLS base is outside the accepted Realm prefix"));
            }
            following_position = record.commit.stream_position;
            let body: MlsCommitPayload = serde_json::from_value(
                serde_json::to_value(&record.event.payload).map_err(unavailable)?,
            )
            .map_err(unavailable)?;
            if expected_epoch == 0 || body.next_epoch() != expected_epoch {
                return Err(unavailable("MLS chain does not advance one epoch"));
            }
            next = body.base_group_state_ref().clone();
            expected_epoch -= 1;
            commits.push(record.event);
        }
        if expected_epoch != 0 {
            return Err(unavailable("MLS chain does not reach accepted Genesis"));
        }
        let genesis = self
            .authority_commits()
            .committed_event(&group.genesis_event_ref)
            .await?
            .ok_or_else(|| unavailable("accepted Genesis is absent"))?;
        if genesis.event.realm_id != realm
            || genesis.event.scope_ref != scope
            || genesis.event.kind != EventKind::MlsGenesis
        {
            return Err(unavailable("Genesis belongs to another scope"));
        }
        if genesis.commit.stream_ref != head.stream_ref
            || genesis.commit.event_ref != genesis.event.event_id
            || genesis.commit.stream_position >= following_position
        {
            return Err(unavailable("Genesis is outside the accepted Realm prefix"));
        }
        let genesis_body: MlsGenesisPayload = serde_json::from_value(
            serde_json::to_value(&genesis.event.payload).map_err(unavailable)?,
        )
        .map_err(unavailable)?;
        let request = MlsMemberGroupStateMaterialReadRequestBody {
            realm_id: realm.clone(),
            effective_scope: scope.clone(),
            mls_group_id: scope.canonical_mls_group_id().map_err(unavailable)?,
            epoch: Default::default(),
            group_state_event_id: group.genesis_event_ref.clone(),
            caller_actor_id: caller.clone(),
            target_commit_event_ref: group.current_mls_commit_event_ref.clone(),
            target_epoch: group.epoch,
            group_info_ref: genesis_body.group_info_ref.clone(),
            ratchet_tree_ref: genesis_body.ratchet_tree_ref.clone(),
            max_response_bytes: None,
        };
        let limit = arkret_models_collaboration::mls_group_state_material::MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES as usize;
        let info_row = self
            .deliveries()
            .blob(request.group_info_ref.as_str())
            .await?;
        let tree_row = self
            .deliveries()
            .blob(request.ratchet_tree_ref.as_str())
            .await?;
        if info_row.as_ref().is_some_and(|row| row.redacted)
            || tree_row.as_ref().is_some_and(|row| row.redacted)
        {
            return Err(unavailable("public Genesis material is redacted"));
        }
        let (info, tree) = if info_row.is_some() && tree_row.is_some() {
            let info = crate::routing::mls::load_mls_public_blob(
                self,
                request.group_info_ref.as_str(),
                limit,
            )
            .await
            .map_err(unavailable)?;
            let tree = crate::routing::mls::load_mls_public_blob(
                self,
                request.ratchet_tree_ref.as_str(),
                limit.saturating_sub(info.len()),
            )
            .await
            .map_err(unavailable)?;
            (info, tree)
        } else {
            let outcome = crate::routing::mls::read_member_group_state_material(self, &request)
                .await
                .map_err(unavailable)?;
            let bytes = outcome
                .validate_for_request(&request.as_peer_request())
                .map_err(unavailable)?;
            (bytes.group_info_bytes, bytes.ratchet_tree_bytes)
        };
        for (reference, bytes) in [
            (&request.group_info_ref, &info),
            (&request.ratchet_tree_ref, &tree),
        ] {
            let digest =
                arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(
                    reference,
                )
                .map_err(unavailable)?;
            arkret_canonical::verify_digest(bytes, digest.as_str()).map_err(unavailable)?;
        }
        let mut tracker = arkret_mls::MlsPublicGroupTracker::from_external(
            &info,
            &tree,
            request.mls_group_id.as_str(),
            0,
        )
        .map_err(unavailable)?;
        if tracker.governance_binding().map_err(unavailable)? != genesis_body.governance_binding {
            return Err(unavailable("Genesis RFC binding differs"));
        }
        let mut previous = group.genesis_event_ref.clone();
        for event in commits.iter().rev() {
            let body: MlsCommitPayload =
                serde_json::from_value(serde_json::to_value(&event.payload).map_err(unavailable)?)
                    .map_err(unavailable)?;
            let old_epoch = tracker.epoch();
            let transition = tracker
                .process_public_handshake(
                    &arkret_canonical::base64url_decode(body.commit_bytes_b64())
                        .map_err(unavailable)?,
                )
                .map_err(unavailable)?;
            if !matches!(transition, arkret_mls::MlsPublicHandshakeTransition::Commit { sender_leaf: Some(ref leaf), previous_epoch, epoch, .. }
                if leaf.actor_id == event.actor_id && previous_epoch == old_epoch && epoch == body.next_epoch())
                || body.base_group_state_ref() != &previous
                || tracker.governance_binding().map_err(unavailable)? != *body.governance_binding()
            {
                return Err(unavailable("RFC Commit or accepted base binding differs"));
            }
            previous = event.event_id.clone();
        }
        let tree_bytes = tracker.ratchet_tree_bytes().map_err(unavailable)?;
        arkret_canonical::verify_digest(
            &tree_bytes,
            arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(
                &group.public_tree_ref,
            )
            .map_err(unavailable)?
            .as_str(),
        )
        .map_err(unavailable)?;
        if previous != group.current_mls_commit_event_ref
            || tracker.epoch() != group.epoch
            || tracker.ciphersuite_canonical_id().map_err(unavailable)?
                != group.cipher_suite.as_str()
        {
            return Err(unavailable("RFC group differs from signed current"));
        }
        let occupants = tracker
            .leaves()
            .map_err(unavailable)?
            .into_iter()
            .map(|leaf| leaf.actor_id)
            .collect::<std::collections::BTreeSet<_>>();
        if self
            .authority_commits()
            .direct_conversation_replica_cut(&realm, account, &pair_key, &participants)
            .await?
            .as_ref()
            .is_none_or(|current| !current.retains_resolver_facts(&material))
        {
            return Err(unavailable("held cut changed during verification"));
        }
        // Immutable public material is cached under its existing content address.
        // Future reads recheck the native cut and need no online origin dependency.
        for (reference, bytes) in [
            (&request.group_info_ref, info),
            (&request.ratchet_tree_ref, tree),
        ] {
            if self.deliveries().blob(reference.as_str()).await?.is_some() {
                continue;
            }
            let sha256 = arkret_canonical::sha256_digest(&bytes)
                .trim_start_matches("sha256:")
                .to_owned();
            let key = self.deliveries().object_key_for_sha256(&sha256);
            let size_bytes = bytes.len() as i64;
            self.deliveries()
                .put_object(&key, bytes)
                .await
                .map_err(unavailable)?;
            self.deliveries()
                .store_blob_if_absent(
                    reference.as_str(),
                    soland_storage::BlobRecord {
                        sha256,
                        size_bytes,
                        storage_backend: self.deliveries().object_storage_backend_name(),
                        storage_key: key,
                        media_type: "application/octet-stream".into(),
                        filename: None,
                        realm_id: Some(realm.to_string()),
                        encryption: None,
                        legal_hold: false,
                        redacted: false,
                        visibility:
                            arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
                        uploaded_by: genesis.event.actor_id.signing_principal_id().to_string(),
                        created_at: genesis.commit.committed_at,
                    },
                )
                .await?;
        }
        for reference in [&request.group_info_ref, &request.ratchet_tree_ref] {
            if self
                .deliveries()
                .blob(reference.as_str())
                .await?
                .is_none_or(|row| row.redacted)
            {
                return Err(unavailable(
                    "cached Genesis material disappeared or was redacted",
                ));
            }
        }
        if self
            .authority_commits()
            .direct_conversation_replica_cut(&realm, account, &pair_key, &participants)
            .await?
            .as_ref()
            .is_none_or(|current| !current.retains_resolver_facts(&material))
        {
            return Err(unavailable(
                "held cut changed before resolver classification",
            ));
        }
        facts.group_state_ref = Some(group.current_mls_commit_event_ref);
        facts.group_current_exact_pair = Some(occupants == pair);
        facts.initial_exact_pair_group_state_ref =
            Some(payload.initial_exact_pair_group_state_ref.clone());
        facts.members = material
            .current_state_entries
            .iter()
            .filter_map(|entry| {
                let TypedCurrentResult::Value {
                    selector,
                    source_stream_ref,
                    value,
                    ..
                } = entry;
                match selector {
                    CurrentSelector::MemberState { actor_id }
                        if source_stream_ref == &head.stream_ref =>
                    {
                        Some((actor_id, value))
                    }
                    _ => None,
                }
            })
            .map(|(actor, value)| {
                let member: arkret_wire::MemberStateCurrent =
                    serde_json::from_value(value.clone()).map_err(unavailable)?;
                let membership = serde_json::to_value(member.membership).map_err(unavailable)?;
                Ok(soland_storage::DirectConversationMemberCurrent {
                    member_id: actor.clone(),
                    membership: membership
                        .as_str()
                        .ok_or_else(|| unavailable("membership is not a name"))?
                        .to_owned(),
                })
            })
            .collect::<ServiceResult<Vec<_>>>()?;
        Ok(())
    }
}
