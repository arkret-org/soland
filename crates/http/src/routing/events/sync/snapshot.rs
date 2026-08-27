use super::*;

/// Build one snapshot of the account-aggregate sync response for the next
/// `ak.self.account.stream.subscribe.v1` delta frame.
pub(crate) async fn build_sync_snapshot(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
    after_cursor: &SyncCursor,
) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
    let filter_value = sync_filter_value(body.filter.as_ref());
    // SYNC-MEM-1 + ROST-SOL-1..3 (arkret-spec @ b56cab1) — `members[]` is
    // the per-Realm roster v2 projection from
    // `account-subscribe-frame.schema.json#/$defs/member_roster_entry`. Each
    // row carries `{actor_id, membership, subject_id?, identity_event_ids?,
    // member_display_state_digest?, identity_events?, handle_claim_digests?,
    // handle_claims?, handle_claims_limited?}` — `handle` / display name MUST
    // NOT appear here. Identity is resolved by following
    // `identity_event_ids[]` into the separately delivered
    // `ak.member.identity.update` event log; servers that lack the events for
    // the client SHOULD inline them via `identity_events[]` (gated on
    // `subject_id` disclosure).
    let candidate_realms: Vec<RealmDirectoryEntry> = {
        let realms = state.realm_directory().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let requested_realms = body
        .filter
        .as_ref()
        .map(|filter| {
            filter
                .realms
                .iter()
                .map(|realm_id| realm_id.as_str())
                .collect::<BTreeSet<_>>()
        })
        .filter(|realms| !realms.is_empty());
    let mut visible_realms: Vec<(
        String,
        String,
        Option<String>,
        _,
        Option<String>,
        Option<String>,
        _,
    )> = Vec::new();
    for realm_entry in &candidate_realms {
        if requested_realms
            .as_ref()
            .is_some_and(|realms| !realms.contains(realm_entry.realm_id.as_str()))
        {
            continue;
        }
        if realm_visible_to(state, realm_entry, session).await {
            let members = roster_members_for_realm(state, realm_entry, session, body);
            visible_realms.push((
                realm_entry.realm_id.to_string(),
                realm_entry.title.clone(),
                realm_entry.description.clone(),
                realm_entry.tags.clone(),
                realm_entry.category.clone(),
                realm_entry.default_join_rule.clone(),
                members,
            ));
        }
    }
    let mut visible_actors = BTreeSet::new();
    for (_, _, _, _, _, _, members) in &visible_realms {
        for member in members {
            if let Some(actor) = roster_member_actor_id(member) {
                visible_actors.insert(actor);
            }
        }
    }
    if let Some(session) = session {
        visible_actors.insert(session.actor.clone());
    }
    let (device_lists, device_list_positions) = device_lists_for_actors(
        state,
        session,
        &visible_actors,
        after_cursor,
        body.after.is_some(),
    )
    .await;

    // Clone the projection so the per-Realm loop below can `.await` async
    // visibility/timeline helpers without holding the (non-Send) lock guard
    // across a suspension point.
    let projection = state.projections().snapshot();
    let mut sync_realms = std::collections::BTreeMap::new();
    let mut timeline_positions = BTreeMap::new();
    let mut account_positions = BTreeMap::new();
    let is_incremental = body.after.is_some();
    let (account_notifications, notification_position) =
        account_notification_delta(state, session, after_cursor, is_incremental).await;
    for (realm_id, title, summary, _tags, _category, join_rule, members) in visible_realms {
        let meta = state
            .realms()
            .realm_metadata(&realm_id)
            .await
            .ok()
            .flatten();
        let known_timeline_to_cursor = after_cursor.positions.contains_key(&realm_id);
        let known_account_to_cursor = after_cursor.account_positions.contains_key(&realm_id);
        let after_timeline_position = after_cursor
            .positions
            .get(&realm_id)
            .copied()
            .unwrap_or_default();
        let after_account_position = after_cursor
            .account_positions
            .get(&realm_id)
            .copied()
            .unwrap_or_default();
        let (timeline_events, timeline_siblings, timeline_position) = timeline_events_for_realm(
            state,
            &projection,
            &realm_id,
            after_timeline_position,
            session,
        )
        .await;
        let (state_events, state_position) = state_events_for_realm(
            state,
            &realm_id,
            after_account_position,
            session,
            !is_incremental,
        )
        .await;
        let account_position =
            account_realm_projection_position(meta.as_ref(), &realm_id).max(state_position);
        timeline_positions.insert(realm_id.clone(), timeline_position);
        account_positions.insert(realm_id.clone(), account_position);
        let account_projection_changed = if known_account_to_cursor {
            account_position != after_account_position
        } else {
            account_position > after_timeline_position
        };
        let full_sync = !is_incremental;
        let durable_projection_changed = full_sync
            || !timeline_events.is_empty()
            || !timeline_siblings.is_empty()
            || !state_events.is_empty()
            || account_projection_changed;
        // A Realm entry is a collection of independent stream deltas.
        //
        // Timeline and account projection positions are separate cursor
        // vectors. Visible timeline events drive `positions.realms`; Realm /
        // Strand metadata drives `positions.account_realms`. Keeping them
        // separate prevents a metadata-only position from masking a later
        // visible timeline event, and lets hidden timeline advancement move
        // the cursor without emitting an empty Realm projection.
        //
        // Canonical membership transitions are durable projection changes:
        // `ak.member.state` and the `ak.invite.accept` cascade both touch Realm
        // metadata, while their accepted state Events independently advance the
        // account position. They therefore cannot depend on a later timeline
        // message to surface the updated roster.
        if is_incremental && known_timeline_to_cursor && !durable_projection_changed {
            continue;
        }
        let mut entry =
            arkret_models_collaboration::sync_frames::account_sync::RealmSyncEntry::default();
        if durable_projection_changed {
            let roster = members
                .into_iter()
                .filter_map(|member| serde_json::from_value(member).ok())
                .collect::<Vec<arkret_models_collaboration::sync_frames::account_sync::MemberRosterEntry>>();
            let heroes = roster
                .iter()
                .take(5)
                .map(|member| member.actor_id.clone())
                .collect::<Vec<_>>();
            entry.timeline = Some(
                arkret_models_collaboration::sync_frames::account_sync::Timeline {
                    events: timeline_events,
                    limited: false,
                    prev_cursor: None,
                    preview_only: None,
                    ordered_log_siblings: timeline_siblings,
                    extra: BTreeMap::new(),
                },
            );
            entry.state = Some(
                arkret_models_collaboration::sync_frames::account_sync::EventContainer {
                    events: state_events,
                    extra: BTreeMap::new(),
                },
            );
            // Realm display metadata has a canonical account-sync carrier:
            // `state_at_window_start.realm_metadata`. Do not discard the
            // directory title/summary after visibility filtering and force
            // clients to fall back to the opaque Realm id.
            entry.state_at_window_start = Some(arkret_models_collaboration::sync_frames::account_sync::StateAtWindowStart {
                actor_profiles: BTreeMap::new(),
                realm_metadata: arkret_models_collaboration::sync_frames::account_sync::WindowStartRealmMetadata {
                    title: (!title.trim().is_empty()).then_some(title),
                    summary,
                    join_rule,
                    collaboration_role: projection
                        .realm_is_direct_conversation(&realm_id)
                        .then_some(arkret_models_collaboration::objects::direct_conversation::CollaborationRealmRole::DirectConversation),
                },
                e2ee_epoch: arkret_models_collaboration::sync_frames::account_sync::WindowStartNullableE2eeEpoch::Null(()),
            });
            entry.summary = Some(arkret_models_collaboration::sync_frames::account_sync::AccountSubscribeRealmSummary {
                joined_member_count: Some(roster.len() as u64),
                invited_member_count: None,
                heroes: (!heroes.is_empty()).then_some(heroes),
            });
            entry.members = Some(roster);
            entry.members_limited = Some(false);
            entry.unread_notifications = Some(arkret_models_collaboration::sync_frames::account_sync::AccountSubscribeUnreadCounts {
                notification_count: Some(0),
                highlight_count: Some(0),
            });
        }
        sync_realms.insert(realm_id.clone(), entry);
    }
    drop(projection);
    let mut to_device_position = after_cursor.to_device_position;
    let mut to_device_ack_token = None;
    let mut to_device_limited = false;
    let mut to_device_next_cursor = None;
    let mut to_device_lost = None;
    let to_device = if let Some(session) = session {
        if let Err(error) = prune_device_messages_for_limits(state).await {
            tracing::error!(%error, "failed to prune to-device messages during sync snapshot");
        }
        let lost_watermark = match state
            .deliveries()
            .device_message_lost_watermark(&session.actor, &session.device_id)
            .await
        {
            Ok(watermark) => watermark,
            Err(error) => {
                tracing::error!(%error, "failed to read to-device lost watermark during sync snapshot");
                None
            }
        };
        if lost_watermark.is_some_and(|position| position > after_cursor.to_device_position) {
            to_device_lost = Some(true);
            if let Some(lost_watermark) = lost_watermark {
                to_device_position = to_device_position.max(lost_watermark);
            }
        }
        let queued = state
            .deliveries()
            .device_messages_after(&session.actor, &session.device_id, 0)
            .await
            .unwrap_or_default();
        to_device_limited = queued.len() > TO_DEVICE_PAGE_LIMIT;
        let page = queued
            .into_iter()
            .take(TO_DEVICE_PAGE_LIMIT)
            .collect::<Vec<_>>();
        let events = device_message_envelopes_after(state, &page);
        if let Some(max_position) = page.iter().map(|message| message.position).max() {
            to_device_position = to_device_position.max(max_position);
            to_device_ack_token = state
                .deliveries()
                .issue_device_message_ack_token(&session.actor, &session.device_id, max_position)
                .await
                .ok()
                .flatten();
            if to_device_limited {
                to_device_next_cursor = Some(
                    sync_token_for_client_sync_frontiers(
                        state,
                        Some(session),
                        filter_value.as_ref(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        to_device_position,
                        after_cursor.notification_position,
                    )
                    .await,
                );
            }
        }
        events
    } else {
        Vec::new()
    };

    // Actor-private account data: rebuilt exclusively from canonical
    // `ak.account_data.set` Events authored by (or for) the session actor —
    // NOT from `AccountDataStore` rows. CAS-only cells written directly
    // through `AccountDataStore::compare_and_set` (e.g.
    // `ak.account.invite_delivery` / `ak.account.invite_quarantine`) never
    // appear in this stream; today they are readable only via the
    // `GET /_arkret/self/account_data` list endpoint. Whether the subscribe
    // stream must also carry them is tracked in
    // arkret-work work/active 2026-08-19-2035 (consent-model.md §6.1.1).
    // Spec for the Event-backed part: discovery/client-preferences.md
    // §2 (storage model) / §3.7 (Realm remarks).
    let account_data = account_data_events(state, session).await;
    let agent_signer_evidence_bundle =
        agent_signer_evidence_bundle_for_sync(state, &sync_realms).await;

    let cursor = sync_token_for_client_sync_frontiers(
        state,
        session,
        filter_value.as_ref(),
        timeline_positions,
        account_positions,
        device_list_positions,
        to_device_position,
        notification_position,
    )
    .await;
    arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        kind: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Delta,
        cursor: Some(cursor),
        realms: Some(arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeRealms {
            entries: sync_realms,
        }),
        to_device: Some(arkret_models_collaboration::sync_frames::account_sync::DeviceMessageContainer {
            messages: to_device,
            ack_token: to_device_ack_token,
            lost: to_device_lost,
            limited: to_device_limited.then_some(true),
            next_cursor: to_device_next_cursor,
            extra: BTreeMap::new(),
        }),
        device_lists: Some(device_lists),
        account_data: Some(
            arkret_models_collaboration::sync_frames::account_sync::EventContainer {
                events: account_data,
                extra: BTreeMap::new(),
            },
        ),
        notifications: Some(account_notifications),
        agent_signer_evidence_bundle,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    }
}

async fn agent_signer_evidence_bundle_for_sync(
    state: &AppState,
    realms: &BTreeMap<
        String,
        arkret_models_collaboration::sync_frames::account_sync::RealmSyncEntry,
    >,
) -> Option<arkret_models_identity::agent_signer_evidence::AgentSignerEvidenceBundle> {
    use arkret_models_collaboration::governance_dependencies::{
        GovernanceDependency, GovernanceDependencySelector,
    };
    use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
    use arkret_models_identity::agent_signer_evidence::AgentSignerEvidence;

    const MAX_SYNC_EVIDENCE: usize = 256;

    let receiver_service_id = arkret_wire::DidCoreId::new(state.service_id().clone()).ok()?;
    let store = state.persistence().governance_dependency_store();
    let mut evidence_by_receipt = BTreeMap::new();
    let mut conflicted_receipts = BTreeSet::new();

    for (realm_key, realm) in realms {
        let Ok(realm_id) = arkret_wire::RealmId::new(realm_key.clone()) else {
            continue;
        };
        let event_sets = [
            realm
                .timeline
                .as_ref()
                .map(|timeline| timeline.events.as_slice()),
            realm.state.as_ref().map(|state| state.events.as_slice()),
            realm
                .state_after
                .as_ref()
                .map(|state| state.events.as_slice()),
            realm
                .account_data
                .as_ref()
                .map(|state| state.events.as_slice()),
        ];
        for event in event_sets.into_iter().flatten().flatten() {
            if event.realm_id != realm_id {
                continue;
            }
            let mut producers = event
                .proofs
                .iter()
                .filter_map(arkret_wire::EventProof::as_producer);
            let Some(producer) = producers.next() else {
                continue;
            };
            if producers.next().is_some() {
                continue;
            }
            let (Some(evidence_ref), Some(evidence_digest)) = (
                producer.signer_resolution_evidence_ref.as_ref(),
                producer.signer_resolution_evidence_digest.as_ref(),
            ) else {
                continue;
            };
            let selector = GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: evidence_digest.clone(),
            };
            let dependency = match store.get(&realm_id, &selector).await {
                Ok(Some(dependency)) => dependency,
                Ok(None) => match store.get_unscoped_signer_evidence(&selector).await {
                    Ok(Some(dependency)) => dependency,
                    Ok(None) => continue,
                    Err(error) => {
                        tracing::warn!(
                            realm_id = %realm_id,
                            event_id = %event.event_id,
                            %error,
                            "unscoped Agent signer evidence lookup failed during account sync"
                        );
                        continue;
                    }
                },
                Err(error) => {
                    tracing::warn!(
                        realm_id = %realm_id,
                        event_id = %event.event_id,
                        %error,
                        "Agent signer evidence dependency lookup failed during account sync"
                    );
                    continue;
                }
            };
            let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence,
                ..
            } = dependency
            else {
                continue;
            };
            if authenticated_signer_resolution_evidence
                .validate_attester_binding()
                .is_err()
                || authenticated_signer_resolution_evidence
                    .canonical_sha256_digest()
                    .ok()
                    .as_ref()
                    != Some(evidence_digest)
                || authenticated_signer_resolution_evidence
                    .evidence_ref()
                    .ok()
                    .as_ref()
                    != Some(evidence_ref)
            {
                continue;
            }
            let AuthenticatedSignerResolutionEvidence::NativeAgent {
                signer_id,
                verification_method,
                agent_signer_evidence,
                ..
            } = authenticated_signer_resolution_evidence.as_ref()
            else {
                continue;
            };
            let expected_signer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
            if signer_id != expected_signer || verification_method != &producer.verification_method
            {
                continue;
            }
            let AgentSignerEvidence::HistoricalEvent {
                event_admission_receipt,
                ..
            } = agent_signer_evidence.as_ref()
            else {
                continue;
            };
            if event_admission_receipt.event_id != event.event_id
                || event_admission_receipt.event_digest() != producer.event_digest
                || event_admission_receipt.realm_id != realm_id
                || event_admission_receipt.agent_id != *signer_id
                || event_admission_receipt.verification_method != *verification_method
                || event_admission_receipt.receiver_service_id != receiver_service_id
            {
                continue;
            }
            let receipt_key = (
                event_admission_receipt.event_id.clone(),
                event_admission_receipt.receiver_service_id.clone(),
            );
            if conflicted_receipts.contains(&receipt_key) {
                continue;
            }
            if let Some(previous) = evidence_by_receipt
                .insert(receipt_key.clone(), agent_signer_evidence.as_ref().clone())
                && previous != **agent_signer_evidence
            {
                evidence_by_receipt.remove(&receipt_key);
                conflicted_receipts.insert(receipt_key);
            }
        }
    }

    let evidence = evidence_by_receipt
        .into_values()
        .take(MAX_SYNC_EVIDENCE)
        .collect::<Vec<_>>();
    (!evidence.is_empty()).then_some(
        arkret_models_identity::agent_signer_evidence::AgentSignerEvidenceBundle {
            schema:
                arkret_models_identity::agent_signer_evidence::AgentSignerEvidenceBundle::SCHEMA,
            evidence,
        },
    )
}

async fn account_notification_delta(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    after_cursor: &SyncCursor,
    is_incremental: bool,
) -> (
    arkret_models_collaboration::sync_frames::account_sync::NotificationContainer,
    i64,
) {
    let Some(session) = session else {
        return (
            arkret_models_collaboration::sync_frames::account_sync::NotificationContainer::default(
            ),
            0,
        );
    };
    let Some(account) = state
        .identities()
        .find_account_by_actor(soland_services::identity::FindAccountByActorQuery {
            actor_id: session.actor.clone(),
        })
        .await
        .ok()
        .flatten()
    else {
        return (
            arkret_models_collaboration::sync_frames::account_sync::NotificationContainer::default(
            ),
            after_cursor.notification_position,
        );
    };
    let rows = state
        .deliveries()
        .list_account_deltas(
            soland_services::delivery::ListAccountNotificationDeltasQuery {
                controller_account_id: account.account_id,
                recipient_service_id: state.service_id().clone(),
                after_position: is_incremental.then_some(after_cursor.notification_position),
            },
        )
        .await
        .unwrap_or_default();
    let mut position = after_cursor.notification_position;
    let mut items = Vec::new();
    for row in rows {
        position = position.max(row.projection_position);
        let delta = row.record.delta;
        if !is_incremental
            && delta.action
                == arkret_models_collaboration::sync_frames::account_sync::NotificationDeltaAction::Remove
        {
            continue;
        }
        if is_incremental {
            items.push(delta);
        } else {
            match arkret_models_collaboration::sync_frames::account_sync::NotificationDelta::try_new(
                delta.id,
                arkret_models_collaboration::sync_frames::account_sync::NotificationDeltaAction::Upsert,
                delta.data,
            ) {
                Ok(delta) => items.push(delta),
                Err(error) => {
                    tracing::error!(%error, "ignored invalid persisted account notification")
                }
            }
        }
    }
    (
        arkret_models_collaboration::sync_frames::account_sync::NotificationContainer { items },
        position,
    )
}

/// SYNC-MEM-1..4 + ROST-SOL-1..3 (arkret-spec @ b56cab1) — build the
/// per-Realm `members[]` roster v2 projection from the structured membership
/// FSM, the in-memory `RealmDirectoryEntry`, and the MemberIdentity
/// registry.
///
/// Schema source:
/// `account-subscribe-frame.schema.json#/$defs/member_roster_entry`. Each
/// row carries `{actor_id, membership, subject_id?, identity_event_ids?,
/// member_display_state_digest?, identity_events?, handle_claim_digests?,
/// handle_claims?, handle_claims_limited?}`. The retired R3 shape
/// `{did, handle_uri?}` is gone and the R3.1 roster digest field is renamed
/// to `member_display_state_digest` (R3.2). `handle` / display
/// name MUST NOT appear here; handle strings may only ride inside signed
/// `handle_claims[]`.
///
/// R3.2 dependentRequired (ROST-SOL-2): the disclosure-gated fields
/// (`subject_id` plus its companions `identity_events` / `handle_claim_digests`
/// / `handle_claims` / `handle_claims_limited`) MUST be omitted together
/// unless `subject_id` is disclosed by Realm policy. Clients resolve
/// identity by following `identity_event_ids[]` into the separately
/// delivered `ak.member.identity.update` event log; SYNC-MEM-3 inlines the
/// original envelopes only when `subject_id` is disclosed.
///
/// MIU-SOL-4: the effective set is multi-valued (no last-writer-wins); ALL
/// effective `identity_event_ids[]` are listed.
pub(super) fn roster_members_for_realm(
    state: &AppState,
    realm_entry: &crate::state::RealmDirectoryEntry,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
) -> Vec<Value> {
    let membership_states = roster_membership_states_for_realm(state, realm_entry);
    let context =
        RosterDisclosureContext::new(state, realm_entry, session, body, &membership_states);
    membership_states
        .into_iter()
        .map(|(actor_id, membership)| {
            let actor_id = actor_id.as_str();
            let mut entry = serde_json::Map::new();
            entry.insert("actor_id".to_owned(), json!(actor_id));
            entry.insert("membership".to_owned(), json!(membership));
            if let Some(snapshot) =
                state.member_identity_snapshot(realm_entry.realm_id.as_str(), actor_id)
            {
                if !snapshot.identity_event_ids.is_empty() {
                    entry.insert(
                        "identity_event_ids".to_owned(),
                        json!(snapshot.identity_event_ids),
                    );
                }
                // ROST-SOL-1 — roster digest field rename to
                // `member_display_state_digest`. NOT disclosure-gated.
                if let Some(digest) = snapshot.member_display_state_digest {
                    entry.insert("member_display_state_digest".to_owned(), json!(digest));
                }
                // ROST-SOL-2 — `subject_id` is disclosed only when Realm
                // policy authorizes the caller to learn the principal /
                // holder DID. When disclosed, the gated companion fields MAY
                // be populated; otherwise they MUST all be omitted (the SDK
                // `MemberRosterEntry::validate` dependentRequired rule).
                if subject_disclosed_to_caller(&context, actor_id)
                    && let Some(subject_id) = snapshot.subject_id.as_deref()
                {
                    entry.insert("subject_id".to_owned(), json!(subject_id));
                    // SYNC-MEM-3 — inline original Event envelopes (gated on
                    // subject disclosure per ROST-SOL-2). The reducer stores
                    // the events as received; we do NOT rewrite projection
                    // on egress.
                    if !snapshot.identity_events.is_empty() {
                        entry.insert(
                            "identity_events".to_owned(),
                            json!(snapshot.identity_events),
                        );
                    }
                    let visible_claims: Vec<HandleClaimEvidenceRecord> = state
                        .cached_handle_claims_for_subject(subject_id)
                        .into_iter()
                        .filter(|claim| handle_claim_visible_to_caller(&context, claim))
                        .collect();
                    if !visible_claims.is_empty() {
                        let digest_inputs: Vec<HandleClaimDigestInput> = visible_claims
                            .iter()
                            .map(|claim| HandleClaimDigestInput {
                                claim_digest: claim.digest.clone(),
                                binding_state: claim.binding_state.clone(),
                                expires_at: claim.expires_at.map(|expires_at| {
                                    arkret_canonical::format_timestamp_canonical(expires_at)
                                }),
                            })
                            .collect();
                        if let Some(digest) = crate::state::display_state_digest(
                            realm_entry.realm_id.as_str(),
                            actor_id,
                            &snapshot.effective_entries,
                            &digest_inputs,
                        ) {
                            entry.insert("member_display_state_digest".to_owned(), json!(digest));
                        }
                        entry.insert(
                            "handle_claim_digests".to_owned(),
                            json!(
                                visible_claims
                                    .iter()
                                    .map(|claim| claim.digest.clone())
                                    .collect::<Vec<_>>()
                            ),
                        );
                        let (claims, limited) = inline_handle_claims(&visible_claims);
                        if !claims.is_empty() {
                            entry.insert("handle_claims".to_owned(), json!(claims));
                        }
                        if limited {
                            entry.insert("handle_claims_limited".to_owned(), json!(true));
                        }
                    }
                }
            }
            Value::Object(entry)
        })
        .collect()
}

fn roster_membership_states_for_realm(
    state: &AppState,
    realm_entry: &crate::state::RealmDirectoryEntry,
) -> BTreeMap<String, String> {
    let projected_states = {
        let projection = state.projections().snapshot();
        projection
            .members
            .iter()
            .filter_map(|((realm_id, actor_id), membership)| {
                if realm_id == realm_entry.realm_id.as_str() {
                    Some((actor_id.clone(), membership.state.clone()))
                } else {
                    None
                }
            })
            .collect::<BTreeMap<_, _>>()
    };
    let mut roster_states = projected_states
        .iter()
        .filter(|(_, membership)| roster_membership_is_visible(membership))
        .map(|(actor_id, membership)| (actor_id.clone(), membership.clone()))
        .collect::<BTreeMap<_, _>>();

    for did in &realm_entry.members {
        let actor_id = did.as_str().to_owned();
        if !projected_states.contains_key(&actor_id) {
            roster_states
                .entry(actor_id)
                .or_insert_with(|| "join".to_owned());
        }
    }

    roster_states
}

fn roster_membership_is_visible(membership: &str) -> bool {
    matches!(membership, "join" | "invite" | "knock")
}

struct RosterDisclosureContext<'a> {
    service_id: &'a str,
    realm_public: bool,
    caller: Option<&'a str>,
    caller_is_realm_member: bool,
    audience: String,
    now: DateTime<Utc>,
}

impl<'a> RosterDisclosureContext<'a> {
    fn new(
        state: &'a AppState,
        realm_entry: &'a RealmDirectoryEntry,
        session: Option<&'a SessionIdentityState>,
        body: &SyncRequestBody,
        membership_states: &BTreeMap<String, String>,
    ) -> Self {
        let caller = session.map(|session| session.actor.as_str());
        Self {
            service_id: state.service_id(),
            realm_public: realm_entry.public,
            caller,
            caller_is_realm_member: caller.is_some_and(|actor_id| {
                membership_states
                    .get(actor_id)
                    .is_some_and(|membership| membership == "join")
            }),
            audience: roster_handle_claim_audience(state, session, body),
            now: now(),
        }
    }

    fn caller_is_realm_member(&self) -> bool {
        self.caller_is_realm_member
    }
}

fn roster_handle_claim_audience(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
) -> String {
    let filter_value = sync_filter_value(body.filter.as_ref());
    filter_value
        .as_ref()
        .and_then(|filter| filter.get("handle_claim_audience"))
        .or_else(|| {
            filter_value
                .as_ref()
                .and_then(|filter| filter.get("audience"))
        })
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| session.map(|session| session.audience.clone()))
        .unwrap_or_else(|| state.service_id().clone())
}

/// ROST-SOL-2/3 — subject and companion fields disclose only when the Realm
/// policy admits the caller. Public Realms can reveal public evidence; private
/// Realms require the caller to be a member. A caller may always see their own
/// subject binding.
fn subject_disclosed_to_caller(context: &RosterDisclosureContext<'_>, actor_id: &str) -> bool {
    context.caller == Some(actor_id) || context.realm_public || context.caller_is_realm_member()
}

fn handle_claim_visible_to_caller(
    context: &RosterDisclosureContext<'_>,
    claim: &HandleClaimEvidenceRecord,
) -> bool {
    if !trusted_handle_claim_issuer(context, claim) {
        return false;
    }
    if claim.revoked || claim.binding_state != "verified" {
        return false;
    }
    if claim
        .expires_at
        .is_some_and(|expires_at| expires_at <= context.now)
    {
        return false;
    }
    if claim
        .audience
        .as_deref()
        .is_some_and(|audience| audience != context.audience)
    {
        return false;
    }
    match claim.visibility.as_deref().unwrap_or("restricted") {
        "public" => subject_disclosed_to_caller(context, &claim.subject_id),
        "members" | "restricted" => {
            context.caller == Some(claim.subject_id.as_str()) || context.caller_is_realm_member()
        }
        _ => false,
    }
}

fn trusted_handle_claim_issuer(
    context: &RosterDisclosureContext<'_>,
    claim: &HandleClaimEvidenceRecord,
) -> bool {
    claim.issuer == context.service_id
        || claim.issuer_service_id.as_deref() == Some(context.service_id)
}

fn inline_handle_claims(claims: &[HandleClaimEvidenceRecord]) -> (Vec<Value>, bool) {
    let mut used = 0usize;
    let mut out = Vec::new();
    let mut limited = false;
    for claim in claims {
        let Ok(bytes) = serde_json::to_vec(&claim.envelope) else {
            limited = true;
            continue;
        };
        if used + bytes.len() > HANDLE_CLAIMS_INLINE_MAX_BYTES {
            limited = true;
            continue;
        }
        used += bytes.len();
        out.push(claim.envelope.clone());
    }
    (out, limited)
}

async fn timeline_events_for_realm(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    after_position: i64,
    session: Option<&SessionIdentityState>,
) -> (
    Vec<arkret_wire::Event>,
    Vec<arkret_models_collaboration::sync_frames::account_sync::OrderedLogSiblingDiagnostic>,
    i64,
) {
    let mut seen = BTreeSet::new();
    let mut seen_message_ids = BTreeSet::new();
    let mut newest_position = after_position;
    let mut timeline_entries = Vec::new();

    for message in projection.messages_for_realm_including_redacted(realm_id) {
        let event_received_at =
            timeline_event_received_at(state, &message.event_id, message.created_at).await;
        let position = timestamp_position_with_tie_breaker(event_received_at, &message.event_id);
        newest_position = newest_position.max(position);
        if position <= after_position
            || !seen.insert(message.event_id.clone())
            || !seen_message_ids.insert(message.message_id.clone())
        {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            event_received_at,
            Some(&message.sender),
            session,
        )
        .await
        {
            continue;
        }
        if !circle_scope_visible_to_session(
            projection,
            message_scope_circle_id(&message.content),
            event_received_at,
            session,
            Some(&message.sender),
        ) {
            continue;
        }
        if let Some(mut event) = accepted_event(state, &message.event_id).await {
            if let Some(cell) = projection.redaction_cell_for_message(message) {
                let mut payload =
                    Value::Object(std::mem::take(&mut event.payload).into_iter().collect());
                arkret_models_collaboration::events_payloads::redaction::redaction_tombstone_message_value(
                    &mut payload,
                    cell.redacted_at,
                    cell.redaction_event_id.as_deref(),
                );
                if let Value::Object(payload) = payload {
                    event.payload = payload.into_iter().collect();
                }
                event
                    .payload
                    .entry("message_id".to_owned())
                    .or_insert_with(|| Value::String(message.message_id.clone()));
                event
                    .payload
                    .entry("strand_id".to_owned())
                    .or_insert_with(|| Value::String(message.thread_id.clone()));
                event
                    .payload
                    .entry("thread_id".to_owned())
                    .or_insert_with(|| Value::String(message.thread_id.clone()));
                mark_event_as_projection_only(&mut event);
            }
            timeline_entries.push((position, event));
        }
    }

    for message in state
        .event_queries()
        .messages_for_realm(realm_id, 100)
        .await
        .unwrap_or_default()
    {
        let event_received_at =
            timeline_event_received_at(state, &message.event_id, message.created_at).await;
        let position = timestamp_position_with_tie_breaker(event_received_at, &message.event_id);
        newest_position = newest_position.max(position);
        if position <= after_position
            || !seen.insert(message.event_id.clone())
            || !seen_message_ids.insert(message.message_id.clone())
        {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            event_received_at,
            Some(&message.sender),
            session,
        )
        .await
        {
            continue;
        }
        if !circle_scope_visible_to_session(
            projection,
            message_scope_circle_id(&message.content),
            event_received_at,
            session,
            Some(&message.sender),
        ) {
            continue;
        }
        if let Some(mut event) = accepted_event(state, &message.event_id).await {
            if let Some(projected_message) = projection.messages.get(&message.event_id)
                && let Some(cell) = projection.redaction_cell_for_message(projected_message)
            {
                let mut payload =
                    Value::Object(std::mem::take(&mut event.payload).into_iter().collect());
                arkret_models_collaboration::events_payloads::redaction::redaction_tombstone_message_value(
                    &mut payload,
                    cell.redacted_at,
                    cell.redaction_event_id.as_deref(),
                );
                if let Value::Object(payload) = payload {
                    event.payload = payload.into_iter().collect();
                }
                event
                    .payload
                    .entry("message_id".to_owned())
                    .or_insert_with(|| Value::String(message.message_id.clone()));
                event
                    .payload
                    .entry("strand_id".to_owned())
                    .or_insert_with(|| Value::String(message.thread_id.clone()));
                event
                    .payload
                    .entry("thread_id".to_owned())
                    .or_insert_with(|| Value::String(message.thread_id.clone()));
                mark_event_as_projection_only(&mut event);
            }
            timeline_entries.push((position, event));
        }
    }

    // Reactions are durable data-plane events attached to the discussion
    // timeline. They must remain raw Event envelopes in account sync; clients
    // derive the remove-wins reaction summary locally.
    for record in state
        .event_queries()
        .realm_events_newest_first(realm_id)
        .await
        .unwrap_or_default()
    {
        if !matches!(
            arkret_wire::EventKind::from_wire(&record.kind),
            arkret_wire::EventKind::ReactionAdd | arkret_wire::EventKind::ReactionRemove
        ) || !seen.insert(record.event_id.clone())
        {
            continue;
        }
        let position = timestamp_position_with_tie_breaker(record.received_at, &record.event_id);
        newest_position = newest_position.max(position);
        if position <= after_position
            || !realm_event_visible_to_session_with_projection(
                state,
                projection,
                realm_id,
                record.received_at,
                Some(&record.actor_id),
                session,
            )
            .await
        {
            continue;
        }
        let Some(event) = accepted_event(state, &record.event_id).await else {
            continue;
        };
        // Message-scoped kinds carry the target as `message_id`; cross-object
        // kinds (pins, reactions, redaction) carry it as `target_ref`. The two
        // member names are disjoint, so this is a per-kind lookup rather than a
        // fallback chain over alternative spellings of one target.
        let target_ref = event
            .payload
            .get("message_id")
            .or_else(|| event.payload.get("target_ref"))
            .and_then(Value::as_str);
        let circle_scope = target_ref.and_then(|target| projection.message_circle_scope(target));
        if !circle_scope_visible_to_session(
            projection,
            circle_scope.as_deref(),
            record.received_at,
            session,
            Some(&record.actor_id),
        ) {
            continue;
        }
        timeline_entries.push((position, event));
    }

    let (mut timeline_entries, siblings) = annotate_message_ordered_log_siblings(timeline_entries);
    timeline_entries.sort_by_key(|left| left.0);
    (
        timeline_entries
            .into_iter()
            .map(|(_, event)| event)
            .collect(),
        siblings,
        newest_position,
    )
}

pub(crate) fn annotate_message_ordered_log_siblings(
    entries: Vec<(i64, arkret_wire::Event)>,
) -> (
    Vec<(i64, arkret_wire::Event)>,
    Vec<arkret_models_collaboration::sync_frames::account_sync::OrderedLogSiblingDiagnostic>,
) {
    let mut slots = BTreeMap::<(String, String, u64), Vec<usize>>::new();
    for (index, (_, event)) in entries.iter().enumerate() {
        if event.kind != arkret_wire::EventKind::MessageCreate {
            continue;
        }
        let Some(strand_id) = event.payload.get("strand_id").and_then(Value::as_str) else {
            continue;
        };
        slots
            .entry((
                strand_id.to_owned(),
                event.actor_id.as_str().to_owned(),
                event.actor_seq,
            ))
            .or_default()
            .push(index);
    }

    let mut siblings = Vec::new();
    for ((strand_id, issuer, issuer_seq), candidates) in slots {
        if candidates.len() < 2 {
            continue;
        }
        let mut resolved = Vec::with_capacity(candidates.len());
        for index in candidates {
            let event = &entries[index].1;
            if let Ok(digest_suite) = arkret::signed_event_digest_claim(event)
                .and_then(|digest| digest.digest_suite().map_err(Into::into))
                && let Ok(digest) = event.event_digest_with_digest_suite(digest_suite)
            {
                resolved.push((event.event_id.clone(), digest));
            }
        }
        if resolved.len() < 2 {
            continue;
        }
        resolved.sort_by(|left, right| {
            arkret_state::lattice::ordered_log::compare_canonical_digests(&left.1, &right.1)
                .unwrap_or_else(|| left.1.cmp(&right.1))
        });
        siblings.push(
            arkret_models_collaboration::sync_frames::account_sync::OrderedLogSiblingDiagnostic {
                cell: format!("ak:cell:ak.component.strand.discussion.timeline.v1:{strand_id}"),
                issuer: arkret_wire::DidCoreId::new(issuer)
                    .expect("accepted Event actor_id is a valid core DID"),
                issuer_seq,
                reason: "actor_seq_siblings".to_owned(),
                event_ids: resolved.iter().map(|entry| entry.0.clone()).collect(),
                event_digests: resolved.into_iter().map(|entry| entry.1).collect(),
            },
        );
    }
    (entries, siblings)
}

fn mark_event_as_projection_only(event: &mut arkret_wire::Event) {
    event
        .unsigned
        .insert("projection_only".to_owned(), Value::Bool(true));
    event.proofs.clear();
}

async fn state_events_for_realm(
    state: &AppState,
    realm_id: &str,
    after_position: i64,
    session: Option<&SessionIdentityState>,
    include_current_security_baseline: bool,
) -> (Vec<arkret_wire::Event>, i64) {
    let events = state
        .event_queries()
        .projected_events_for_realm(realm_id)
        .await
        .unwrap_or_else(|error| {
            tracing::error!(%error, realm_id, "failed to load Realm projection events for sync");
            Vec::new()
        });
    // `history_access=since_join` limits historical data-plane Events, but it
    // must not hide the current object/control baseline from an active member.
    // Initial account sync therefore carries the newest accepted Event for
    // each required singleton plus the exact Strand named by the current
    // default-Strand pointer. Other pre-join Strand objects remain hidden.
    let member_may_receive_current_baseline = if include_current_security_baseline {
        match session {
            Some(session) => realm_has_member(state, realm_id, &session.actor).await,
            None => false,
        }
    } else {
        false
    };
    let projection = state.projections().snapshot();
    let default_strand_id = projection
        .realm_states
        .get(realm_id)
        .and_then(|realm| realm.default_strand_id.as_deref());
    let newest_current_baseline = events
        .iter()
        .filter(|event| {
            required_current_baseline_kind(&event.event_kind)
                && (event.event_kind != arkret_wire::EventKind::StrandCreate
                    || event.payload.get("strand_id").and_then(Value::as_str) == default_strand_id)
        })
        .fold(
            std::collections::HashMap::<arkret_wire::EventKind, (i64, String)>::new(),
            |mut newest, event| {
                let position = projection_event_position(event);
                let key = event.event_kind.clone();
                if newest
                    .get(&key)
                    .is_none_or(|(current, _)| position > *current)
                {
                    newest.insert(key, (position, event.event_id.clone()));
                }
                newest
            },
        );
    let mut seen = BTreeSet::new();
    let mut newest_position = after_position;
    let mut state_entries = Vec::new();
    for event in events {
        if event.event_kind == arkret_wire::EventKind::MessageCreate {
            continue;
        }
        let position = projection_event_position(&event);
        newest_position = newest_position.max(position);
        if position <= after_position || !seen.insert(event.event_id.clone()) {
            continue;
        }
        let visible_by_history = projection_record_visible_to_session(state, &event, session).await;
        let visible_as_current_baseline = member_may_receive_current_baseline
            && newest_current_baseline
                .get(&event.event_kind)
                .is_some_and(|(_, event_id)| event_id == &event.event_id);
        if !visible_by_history && !visible_as_current_baseline {
            continue;
        }
        if let Some(event) = accepted_event(state, &event.event_id).await {
            state_entries.push((position, event));
        }
    }
    state_entries.sort_by_key(|left| left.0);
    (
        state_entries.into_iter().map(|(_, event)| event).collect(),
        newest_position,
    )
}

pub(crate) fn required_current_baseline_kind(kind: &arkret_wire::EventKind) -> bool {
    matches!(
        kind,
        arkret_wire::EventKind::RealmCreate
            | arkret_wire::EventKind::RealmProfile
            | arkret_wire::EventKind::RealmPolicyBundle
            | arkret_wire::EventKind::RealmJoinRule
            | arkret_wire::EventKind::RealmHistoryAccess
            | arkret_wire::EventKind::RealmDiscovery
            | arkret_wire::EventKind::RealmAlias
            | arkret_wire::EventKind::RealmPlaintextVisibleServices
            | arkret_wire::EventKind::RealmDeliveryBindingPolicy
            | arkret_wire::EventKind::RealmSetDefaultStrand
            | arkret_wire::EventKind::StrandCreate
    )
}

fn projection_event_position(event: &soland_services::events::ProjectedEvent) -> i64 {
    timestamp_position_with_tie_breaker(event.received_at, &event.event_id)
}

fn account_realm_projection_position(meta: Option<&RealmMetadata>, realm_id: &str) -> i64 {
    meta.map(|record| timestamp_position_with_tie_breaker(record.updated_at, realm_id))
        .unwrap_or_default()
}

async fn device_lists_for_actors(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    visible_actors: &BTreeSet<String>,
    after_cursor: &SyncCursor,
    is_incremental: bool,
) -> (
    arkret_models_collaboration::sync_frames::account_sync::AccountSubscribeDeviceListChanges,
    BTreeMap<String, i64>,
) {
    if session.is_none() {
        return (
            arkret_models_collaboration::sync_frames::account_sync::AccountSubscribeDeviceListChanges {
                changed: Vec::new(),
                left: Vec::new(),
            },
            BTreeMap::new(),
        );
    }

    let mut positions = BTreeMap::new();
    let mut changed = BTreeSet::new();
    let mut left = BTreeSet::new();
    for actor in visible_actors {
        let records = match state.identities().devices_for_actor(actor).await {
            Ok(records) => records,
            Err(error) => {
                tracing::error!(%error, actor, "failed to load device list for sync snapshot");
                changed.insert(actor.clone());
                continue;
            }
        };
        let position = records
            .iter()
            .map(device_inventory_position)
            .max()
            .unwrap_or_default();
        positions.insert(actor.clone(), position);

        if !is_incremental {
            changed.insert(actor.clone());
            continue;
        }

        match after_cursor.device_list_positions.get(actor).copied() {
            Some(previous_position) if position <= previous_position => {}
            _ => {
                changed.insert(actor.clone());
            }
        }
    }

    if is_incremental {
        for actor in after_cursor.device_list_positions.keys() {
            if !visible_actors.contains(actor) {
                left.insert(actor.clone());
            }
        }
    }

    let changed = changed
        .into_iter()
        .filter_map(|actor| arkret_identifiers::DidCoreId::new(actor).ok())
        .collect();
    let left = left
        .into_iter()
        .filter_map(|actor| arkret_identifiers::DidCoreId::new(actor).ok())
        .collect();
    (
        arkret_models_collaboration::sync_frames::account_sync::AccountSubscribeDeviceListChanges {
            changed,
            left,
        },
        positions,
    )
}

fn device_inventory_position(record: &soland_services::identity::DeviceIdentity) -> i64 {
    let key = format!("{}\0{}", record.actor_id, record.device_id);
    record
        .updated_at
        .timestamp_micros()
        .saturating_mul(TIMELINE_POSITION_SUBTICKS)
        .saturating_add(stable_position_tie_breaker(&key))
}

fn stable_position_tie_breaker(key: &str) -> i64 {
    let digest = sha256_hex(key.as_bytes());
    i64::from_str_radix(&digest[..3], 16).unwrap_or_default() & 0x03ff
}

async fn accepted_event(state: &AppState, event_id: &str) -> Option<arkret_wire::Event> {
    let record = state
        .event_queries()
        .canonical_event(event_id)
        .await
        .ok()
        .flatten()?;
    match super::super::event_log::sdk_event_for_state(state, &record) {
        Ok(event) => Some(event),
        Err(error) => {
            tracing::warn!(%error, event_id, "canonical event record failed SDK projection");
            None
        }
    }
}

async fn account_data_events(
    state: &AppState,
    session: Option<&SessionIdentityState>,
) -> Vec<arkret_wire::Event> {
    let Some(session) = session else {
        return Vec::new();
    };
    let mut latest = BTreeMap::<String, (DateTime<Utc>, arkret_wire::Event)>::new();
    for record in state
        .event_queries()
        .canonical_events()
        .await
        .unwrap_or_default()
    {
        if record.kind != arkret_wire::EventKind::AccountDataSet.as_str() {
            continue;
        }
        let Ok(event) = super::super::event_log::sdk_event_for_state(state, &record) else {
            continue;
        };
        let holder_id = event.payload.get("holder_id").and_then(Value::as_str);
        let holder_authored = record.actor_id == session.actor
            && holder_id.is_none_or(|holder_id| holder_id == session.actor);
        let local_service_authored =
            record.actor_id == *state.service_id() && holder_id == Some(session.actor.as_str());
        if !holder_authored && !local_service_authored {
            continue;
        }
        let Some(key) = event.payload.get("key").and_then(Value::as_str) else {
            continue;
        };
        // Service-internal CAS state is deliberately persisted through the
        // AccountData storage port, but is never a holder-visible account-data
        // Event. Keep this guard even though current internal writers do not
        // append Events, so a future writer cannot expose frozen challenges or
        // binding history accidentally.
        if crate::routing::identity::account_data::is_service_internal_account_data_key(key) {
            continue;
        }
        // Agent runtime sessions never receive controller-private account
        // data over the account stream, even when their session presents the
        // controller as actor (fail closed; private-objects.md §4.2).
        if session.agent_session.is_some()
            && crate::routing::identity::account_data::is_controller_private_account_data_key(key)
        {
            continue;
        }
        let replace = latest
            .get(key)
            .is_none_or(|(received_at, _)| record.received_at > *received_at);
        if replace {
            latest.insert(key.to_owned(), (record.received_at, event));
        }
    }
    let mut events = latest
        .into_values()
        .filter_map(|(_, event)| {
            (!event
                .payload
                .get("tombstone")
                .and_then(Value::as_bool)
                .unwrap_or(false))
            .then_some(event)
        })
        .collect::<Vec<_>>();
    events.extend(notification_account_data_events(state, session).await);
    events
}

/// Ordinary notification projections use the closed
/// `ak.schema.notification.v1` object shape. The typed `notifications` sync
/// container is reserved for account-level Agent approval deltas, so Realm
/// Event notifications ride as derived account-data payloads. This keeps the
/// durable source Event authoritative while making the rebuildable projection
/// available to every device of the recipient principal.
async fn notification_account_data_events(
    state: &AppState,
    session: &SessionIdentityState,
) -> Vec<arkret_wire::Event> {
    let rows = state
        .deliveries()
        .list_recipient_notifications(soland_services::delivery::ListRecipientNotificationsQuery {
            recipient_id: session.actor.clone(),
        })
        .await
        .unwrap_or_default();
    let mut events = Vec::new();
    for row in rows {
        let arkret_models_collaboration::objects::read_receipts::NotificationSource::Event(source) =
            &row.notification.source
        else {
            continue;
        };
        let Some(mut event) = accepted_event(state, source.source_event_id.as_str()).await else {
            continue;
        };
        let Ok(Value::Object(payload)) = serde_json::to_value(row.notification) else {
            continue;
        };
        event.actor_id = match arkret_wire::DidCoreId::new(session.actor.clone()) {
            Ok(actor_id) => actor_id,
            Err(_) => continue,
        };
        event.payload = payload.into_iter().collect();
        events.push(event);
    }
    events
}

async fn timeline_event_received_at(
    state: &AppState,
    event_id: &str,
    created_at: DateTime<Utc>,
) -> DateTime<Utc> {
    state
        .event_queries()
        .canonical_event(event_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.received_at)
        .unwrap_or(created_at)
}

pub(super) fn timestamp_position_with_tie_breaker(timestamp: DateTime<Utc>, event_id: &str) -> i64 {
    timestamp
        .timestamp_micros()
        .saturating_mul(TIMELINE_POSITION_SUBTICKS)
        .saturating_add(timeline_event_tie_breaker(event_id))
}

/// Deterministic subtick so two Events sharing a timestamp keep one stable
/// order on every receiver. It is drawn from the content digest carried in the
/// Event ID, which says nothing about time — the Event ID no longer encodes
/// any — and only has to be a stable function of the identity.
fn timeline_event_tie_breaker(event_id: &str) -> i64 {
    arkret_identifiers::EventId::new(event_id.to_owned())
        .map(|event_id| {
            let token = event_id.token_bytes();
            (i64::from(token[1]) << 2 | i64::from(token[2] >> 6)) & 0x03ff
        })
        .unwrap_or_default()
}

async fn realm_event_visible_to_session_with_projection(
    state: &AppState,
    _projection: &ProjectionState,
    realm_id: &str,
    event_created_at: DateTime<Utc>,
    sender: Option<&str>,
    session: Option<&SessionIdentityState>,
) -> bool {
    realm_event_visible_to_session(state, realm_id, event_created_at, sender, session).await
}

pub(crate) async fn projection_record_visible_to_session(
    state: &AppState,
    event: &ProjectedEvent,
    session: Option<&SessionIdentityState>,
) -> bool {
    if !realm_event_visible_to_session(
        state,
        &event.realm_id,
        event.received_at,
        event.sender.as_deref(),
        session,
    )
    .await
    {
        return false;
    }
    let projection = state.projections().snapshot();
    let sidecar_id = match &event.event_kind {
        arkret_wire::EventKind::SidecarCreate => event
            .event_id
            .strip_prefix("ak:event:")
            .map(|event_token| format!("ak:sidecar:{event_token}")),
        arkret_wire::EventKind::SidecarContextAttach
        | arkret_wire::EventKind::AgentSidecarExchangeControl => event
            .payload
            .get("sidecar_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        // Remaining sidecar-bearing kinds are the MLS events, whose payloads
        // name the binding `governance_binding` (`mls_governance_binding` is a
        // profile / reason-code prefix, never a payload field).
        _ => crate::routing::mls::payload_fields::governance_binding(&event.payload)
            .and_then(|binding| binding.get("sidecar_id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    };
    if let Some(sidecar_id) = sidecar_id {
        return session.is_some_and(|session| {
            projection
                .sidecars
                .get(&sidecar_id)
                .is_some_and(|sidecar| sidecar.controller_id == session.actor)
        });
    }
    let scope_circle_id = projection_event_scope_circle_id(&projection, event);
    circle_scope_visible_to_session(
        &projection,
        scope_circle_id.as_deref(),
        event.received_at,
        session,
        event.sender.as_deref(),
    )
}

pub(crate) async fn projection_event_value_visible_to_session(
    state: &AppState,
    event: &Value,
    session: Option<&SessionIdentityState>,
) -> bool {
    let Some(realm_id) = event.get("realm_id").and_then(Value::as_str) else {
        return false;
    };
    let Some(created_at) = event
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
    else {
        return false;
    };
    let sender = event.get("sender").and_then(Value::as_str);
    realm_event_visible_to_session(state, realm_id, created_at, sender, session).await
}

fn message_scope_circle_id(content: &Value) -> Option<&str> {
    content
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:circle:"))
}

fn projection_event_scope_circle_id(
    projection: &ProjectionState,
    event: &ProjectedEvent,
) -> Option<String> {
    if event.event_kind == arkret_wire::EventKind::MessageCreate {
        return event
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .or_else(|| {
                event
                    .payload
                    .get("thread_id")
                    .and_then(Value::as_str)
                    .filter(|value| value.starts_with("ak:strand:"))
            })
            .and_then(|strand_id| projection.strand_scope_circle_id(strand_id));
    }
    let explicit_scope = event
        .payload
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .or_else(|| {
            event
                .payload
                .get("object")
                .and_then(Value::as_object)
                .and_then(|object| object.get("scope_circle_id"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            event
                .payload
                .get("relation")
                .and_then(Value::as_object)
                .and_then(|relation| relation.get("scope_circle_id"))
                .and_then(Value::as_str)
        })
        .filter(|value| value.starts_with("ak:circle:"))
        .map(ToOwned::to_owned);
    if explicit_scope.is_some() {
        return explicit_scope;
    }
    if event.event_kind == arkret_wire::EventKind::RelationCreate {
        let relation = event.payload.get("relation").and_then(Value::as_object);
        return relation
            .and_then(|value| value.get("from_ref"))
            .and_then(Value::as_str)
            .or_else(|| {
                relation
                    .and_then(|value| value.get("to_ref"))
                    .and_then(Value::as_str)
            })
            .and_then(|object_ref| {
                projection
                    .strand_scope_circle_id(object_ref)
                    .or_else(|| projection.relation_scope_circle_id(object_ref))
                    .or_else(|| projection.morph_scope_circle_id(object_ref))
                    .or_else(|| projection.space_container_scope_circle_id(object_ref))
            });
    }
    None
}

fn circle_scope_visible_to_session(
    projection: &ProjectionState,
    scope_circle_id: Option<&str>,
    event_created_at: chrono::DateTime<chrono::Utc>,
    session: Option<&SessionIdentityState>,
    sender: Option<&str>,
) -> bool {
    let Some(scope_circle_id) = scope_circle_id else {
        return true;
    };
    if sender.is_some_and(|sender| session.is_some_and(|session| session.actor == sender)) {
        return true;
    }
    let Some(session) = session else {
        return false;
    };
    projection.circle_scope_visible_to_actor_at(scope_circle_id, &session.actor, event_created_at)
}

#[cfg(test)]
mod account_notification_tests {
    use super::*;

    #[test]
    fn typed_agent_approval_uses_discriminator_free_notification_delta() {
        let delta =
            arkret_models_collaboration::sync_frames::account_sync::NotificationDelta::try_new(
                arkret_wire::NotificationId::new(
                    "ak:notification:019fa1ef-00ee-77e0-9f06-2f2d36bf2475".to_owned(),
                )
                .expect("test notification id"),
                arkret_models_collaboration::sync_frames::account_sync::NotificationDeltaAction::Upsert,
                Some(
                    arkret_models_collaboration::sync_frames::account_sync::NotificationData::AgentRuntimeApproval(
                        arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalNotificationData {
                            approval_request_id: arkret_wire::OpaqueLocalId::new(
                                "agent_runtime_approval:019fa1ef-00ee-77e0-9f06-2f1d9ed5e3fa",
                            )
                            .unwrap(),
                            agent_id: arkret_wire::DidCoreId::new(
                                "ak:did_core:web:agent.example".to_owned(),
                            )
                            .expect("test Agent core id"),
                            requested_at: "2026-07-27T04:57:02.959Z"
                                .parse()
                                .expect("test requested_at"),
                            expires_at: "2026-07-27T05:07:02.959Z"
                                .parse()
                                .expect("test expires_at"),
                        },
                    ),
                ),
            )
            .expect("typed Agent approval must be valid");
        let wire = serde_json::to_value(delta).expect("NotificationDelta must serialize");

        assert!(wire.get("notification_kind").is_none());
        assert!(wire["data"].get("kind").is_none());
        assert_eq!(wire.get("action").and_then(Value::as_str), Some("upsert"));
    }
}
